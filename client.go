//go:build linux

package main

import (
	"log"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// startClientAFPacket runs the client side of the tunnel: it accepts local
// application UDP traffic, NATs each flow to a virtual port, wraps it in a
// raw Ethernet+IP+fake-transport frame under a custom IP protocol number, and
// sends it through the selected AF_PACKET or AF_XDP backend. The reverse direction unwraps server replies and
// delivers them back to the originating application socket.
func startClientAFPacket(localAddr string, serverIP net.IP, dstPort uint16, upProto, dnProto uint8, iface string) {
	mtu, err := effectiveMTU(iface)
	if err != nil {
		log.Fatal(err)
	}
	maxPayload := payloadLimit(mtu, *fakeTCP, *fakeFrag)
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

	filterDst := resolveFilterDstIP(srcIP)
	receiver, txSender, err := newTunnelIO(iface, dnProto, srcMAC, filterDst, dstPort, true)
	if err != nil {
		log.Fatalf("Initialize packet backend: %v", err)
	}
	defer receiver.Close()
	defer txSender.Close()

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

	configureLocalUDP(appConn, "client app")

	nat := newNatTable()
	go nat.Cleanup()

	// Downlink (packet backend -> App)
	// Reads raw Ethernet frames, strips headers, translates VirtualPort -> ClientPort
	go func() {
		forwarder := newLocalUDPDelivery(receiver, mtu)
		defer forwarder.Close()

		for {
			// Read a borrowed frame; its bytes remain valid until the next read.
			data, err := forwarder.ReadPacket()
			if err != nil {
				log.Fatalf("Packet receive failed: %v", err)
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

			if addr, ok := netip.AddrFromSlice(sess.clientIP); ok {
				forwarder.Send(appConn, netip.AddrPortFrom(addr.Unmap(), uint16(sess.clientPort)), payload)
			}
		}
	}()

	// Uplink (App -> AF_PACKET)
	// Reads UDP from App, translates ClientPort -> VirtualPort, wraps in Ethernet + IP + Proto, sends raw
	// recvmmsg batches application datagrams; GRO remains disabled.
	ipv4AppConn := ipv4.NewPacketConn(appConn)
	msgs := prepareMsgsUDP()

	txBuffers := make([][]byte, batchSize*2)
	for i := range txBuffers {
		txBuffers[i] = make([]byte, max(60, mtu+14))
	}
	encoder, err := newTunnelEncoder(srcMAC, dstMAC, srcIP, serverIP, upProto, *fakeTCP, tcpFlagByte)
	if err != nil {
		log.Fatal(err)
	}
	frames := make([][]byte, 0, batchSize*2)
	flush := func() {
		if len(frames) > 0 {
			if _, err := txSender.WriteBatch(frames); err != nil {
				log.Printf("TX batch: %v", err)
			}
			frames = frames[:0]
		}
	}
	defer flush()
	ipId := uint16(1)
	ipFlags := uint16(0x4000) // Don't Fragment.
	if *fakeFrag {
		ipFlags = 0x2000 // More Fragments.
	}
	hdrLen := transportHeaderLen()
	fakeTail := [1]byte{'0'}

	n := 0
	readPos := 0
	for {
		if readPos >= n {
			flush()
			n, err = ipv4AppConn.ReadBatch(msgs, 0)
			if n == 0 || err != nil {
				log.Printf("Read UDP error: %v", err)
				continue
			}
			readPos = 0
		}
		msg := &msgs[readPos]
		readPos++
		if msg.Flags&unix.MSG_TRUNC != 0 || msg.N > maxPayload {
			continue
		}
		data := msg.Buffers[0][:msg.N]
		cAddr := msg.Addr.(*net.UDPAddr)

		// NAT: Client -> VirtualPort
		vPort, natErr := nat.GetOrCreateVirtualPort(cAddr.IP, cAddr.Port)
		if natErr != nil {
			continue
		}

		if *fakeFrag {
			data = padData(data, 8, hdrLen)
		}
		frame, err := encoder.Encode(txBuffers[len(frames)], data, vPort, dstPort, ipId, ipFlags, 0, true)
		if err != nil {
			log.Printf("Encode error: %v", err)
			continue
		}
		frames = append(frames, frame)
		if *fakeFrag {
			offset := uint16((len(data) + hdrLen) / 8)
			frame, err = encoder.Encode(txBuffers[len(frames)], fakeTail[:], 0, 0, ipId, 0, offset, false)
			if err != nil {
				log.Printf("Encode error: %v", err)
				continue
			}
			frames = append(frames, frame)
		}

		ipId = (ipId + 1) % 65000
	}
}
