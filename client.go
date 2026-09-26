//go:build linux

package main

import (
	"log"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"
)

// startClientAFPacket runs the client side of the tunnel: it accepts local
// application UDP traffic, NATs each flow to a virtual port, wraps it in a
// raw Ethernet+IP+fake-transport frame under a custom IP protocol number, and
// sends it via AF_PACKET. The reverse direction unwraps server replies and
// delivers them back to the originating application socket.
func startClientAFPacket(localAddr string, serverIP net.IP, dstPort uint16, upProto, dnProto uint8, iface string) {
	// Get interface info
	srcMAC, ifaceIP, err := getInterfaceInfo(iface)
	if err != nil {
		log.Fatalf("Failed to get interface info: %v", err)
	}

	// Determine source IP
	var srcIP net.IP
	if *customSrc != "" {
		srcIP = net.ParseIP(*customSrc)
		if srcIP == nil {
			log.Fatal("Invalid source IP format")
		}
		log.Printf("Using Custom Source IP: %s (spoofing)", srcIP)
	} else {
		srcIP = ifaceIP
		log.Printf("Using Interface IP: %s", srcIP)
	}

	// Get destination MAC (gateway or direct neighbor)
	dstMAC, err := getNeighborMAC(iface, serverIP)
	if err != nil {
		log.Fatalf("Failed to get destination MAC: %v", err)
	}
	log.Printf("Destination MAC: %s", dstMAC)

	// Create AF_PACKET socket with TPACKET_V3 for high-performance mmap'd ring buffer
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(afBlockSize),
		afpacket.OptNumBlocks(afNumBlocks),
		afpacket.OptFrameSize(afFrameSize),
		afpacket.OptBlockTimeout(afBlockTimeout),
	)
	if err != nil {
		log.Fatalf("Failed to create AF_PACKET socket: %v", err)
	}
	defer tpacket.Close()

	// BPF: reject our own outgoing packets + only accept our custom IP protocol
	// This filters in-kernel, before packets ever reach the mmap ring buffer.
	// For TCP/UDP modes we also narrow by tunnel peer IPs and target port.
	filterDst := resolveFilterDstIP(srcIP)
	// Client receives downlink (server→client) traffic, so the BPF filters dnProto.
	filter := createBPFFilter(dnProto, srcMAC, *fakeFrag, filterDst, dstPort, true)
	if err := tpacket.SetBPF(filter); err != nil {
		log.Fatalf("Failed to set BPF filter: %v", err)
	}

	// Local UDP socket for application traffic
	udpAddr, err := net.ResolveUDPAddr("udp4", localAddr)
	if err != nil {
		log.Fatalf("Failed to resolve UDP listen address %q: %v", localAddr, err)
	}
	appConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer appConn.Close()

	appConn.SetReadBuffer(socketBufSize)
	appConn.SetWriteBuffer(socketBufSize)

	// Probe for GSO/GRO support on the app-facing UDP socket
	// txOffload, rxOffload := supportsUDPOffload(appConn)
	txOffload := false
	rxOffload := false
	if rxOffload {
		if err := enableUDPGRO(appConn); err != nil {
			log.Printf("Warning: Failed to enable UDP_GRO: %v", err)
			rxOffload = false
		} else {
			log.Printf("UDP GRO enabled on app socket")
		}
	}
	if txOffload {
		log.Printf("UDP GSO available on app socket")
	}

	nat := newNatTable()
	go nat.Cleanup()

	// Downlink (AF_PACKET -> App)
	// Reads raw Ethernet frames, strips headers, translates VirtualPort -> ClientPort
	go func() {
		// Reusable UDPAddr to avoid per-packet heap allocation.
		// IP is assigned from sess.clientIP per packet, so no preallocation needed.
		writeAddr := &net.UDPAddr{}

		for {
			// Zero-copy read from AF_PACKET mmap'd ring buffer
			data, _, err := tpacket.ZeroCopyReadPacketData()
			if err != nil {
				continue
			}

			// Parse Ethernet + IPv4 header (fixed-offset, no gopacket dispatch).
			pkt, ok := parseEthIPv4(data)
			if !ok {
				continue
			}

			// Userspace protocol filter (defense-in-depth: BPF may fail to attach).
			// Incoming on the client is server→client traffic → dnProto.
			if pkt.proto != dnProto || pkt.fragOffset != 0 {
				continue
			}

			// Parse transport header (UDP or TCP) from IP payload
			_, dstPortRecv, payload, ok := parseFakeTransport(pkt.payload, *fakeTCP)
			if !ok {
				continue
			}

			// Reverse NAT: VirtualPort (transport.DstPort) -> Client Session
			sess := nat.GetSession(dstPortRecv)
			if sess == nil {
				continue
			}

			writeAddr.IP = sess.clientIP
			writeAddr.Port = sess.clientPort
			if _, err := appConn.WriteToUDP(payload, writeAddr); err != nil {
				log.Printf("WriteToUDP error in downlink (no coalesce): %v", err)
			}
		}
	}()

	// Uplink (App -> AF_PACKET)
	// Reads UDP from App, translates ClientPort -> VirtualPort, wraps in Ethernet + IP + Proto, sends raw
	// Uses GRO to receive coalesced datagrams from the kernel
	ipv4AppConn := ipv4.NewPacketConn(appConn)
	msgs := prepareMsgsUDP(rxOffload)

	// Reusable serialize buffer
	serializeBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Pre-build headers (will modify SrcPort for each packet)
	var ipId uint16 = 1

	ipFlags := layers.IPv4DontFragment
	if *fakeFrag {
		ipFlags = layers.IPv4MoreFragments
	}

	ethHeader := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipHeader := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Id:         ipId,
		TTL:        64,
		Protocol:   layers.IPProtocol(upProto),
		SrcIP:      srcIP,
		DstIP:      serverIP,
		Flags:      ipFlags,
		FragOffset: 0,
	}
	// Transport header — either UDP or TCP based on -fake-tcp. Both share the
	// same first 4 bytes (src/dst port), so the rest of the tunnel logic is
	// identical.
	var udpHeader *layers.UDP
	var tcpHeader *layers.TCP
	if *fakeTCP {
		tcpHeader = newFakeTCPHeader(dstPort, tcpFlagByte)
		tcpHeader.SetNetworkLayerForChecksum(ipHeader)
	} else {
		udpHeader = &layers.UDP{DstPort: layers.UDPPort(dstPort)}
		udpHeader.SetNetworkLayerForChecksum(ipHeader)
	}
	hdrLen := transportHeaderLen()

	// Fake frag IP header
	ipHeaderFrag := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Id:         ipId,
		TTL:        64,
		Protocol:   layers.IPProtocol(upProto),
		SrcIP:      srcIP,
		DstIP:      serverIP,
		Flags:      0,
		FragOffset: 0,
	}

	n := 0
	readPos := 0
	for {
		if readPos >= n {
			if rxOffload {
				// With GRO: read into fewer slots, then split coalesced messages
				readAt := len(msgs) - (batchSize / udpSegmentMaxDatagrams)
				if readAt < 0 {
					readAt = 0
				}
				resetOOB(msgs[readAt:])
				n, err = ipv4AppConn.ReadBatch(msgs[readAt:], 0)
				if n == 0 || err != nil {
					log.Printf("Read UDP error: %v", err)
					continue
				}
				n, err = splitCoalescedMessages(msgs, readAt)
				if err != nil {
					log.Printf("GRO split error: %v", err)
					continue
				}
			} else {
				n, err = ipv4AppConn.ReadBatch(msgs, 0)
				if n == 0 || err != nil {
					log.Printf("Read UDP error: %v", err)
					continue
				}
			}
			readPos = 0
		}
		msg := &msgs[readPos]
		readPos++
		data := msg.Buffers[0][:msg.N]
		cAddr := msg.Addr.(*net.UDPAddr)

		// NAT: Client -> VirtualPort
		vPort := nat.GetOrCreateVirtualPort(cAddr.IP, cAddr.Port)

		// Build packet with Ethernet header
		ipHeader.Id = ipId
		var transport gopacket.SerializableLayer
		if *fakeTCP {
			tcpHeader.SrcPort = layers.TCPPort(vPort)
			transport = tcpHeader
		} else {
			udpHeader.SrcPort = layers.UDPPort(vPort)
			transport = udpHeader
		}

		if *fakeFrag {
			data = padData(data, 8, hdrLen)
		}

		if err := gopacket.SerializeLayers(serializeBuf, opts, ethHeader, ipHeader, transport, gopacket.Payload(data)); err != nil {
			log.Printf("Serialize error: %v", err)
			continue
		}

		// Send via AF_PACKET (bypasses kernel IP stack)
		if err := tpacket.WritePacketData(serializeBuf.Bytes()); err != nil {
			log.Printf("AF_PACKET write error: %v", err)
		}

		// fake frag
		if *fakeFrag {
			ipHeaderFrag.Id = ipId
			// Offset of the fake fragment in 8-byte units: after the real
			// transport header + padded data.
			ipHeaderFrag.FragOffset = uint16((len(data) + hdrLen) / 8)

			if err := gopacket.SerializeLayers(serializeBuf, opts, ethHeader, ipHeaderFrag, gopacket.Payload([]byte("0"))); err != nil {
				log.Printf("Serialize error: %v", err)
				continue
			}

			// Send via AF_PACKET (bypasses kernel IP stack)
			if err := tpacket.WritePacketData(serializeBuf.Bytes()); err != nil {
				log.Printf("AF_PACKET write error: %v", err)
			}
		}

		ipId = (ipId + 1) % 65000
	}
}
