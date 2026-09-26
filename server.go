//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"
)

// startServerAFPacket runs the server side of the tunnel: it captures uplink
// frames (client→server) under the custom IP protocol number, forwards the
// inner payload to a local target port, and spawns a per-flow reply goroutine
// that wraps target responses back into tunnel frames on a shared TX socket.
func startServerAFPacket(upProto, dnProto uint8, iface string) {
	// Get interface info
	srcMAC, ifaceIP, err := getInterfaceInfo(iface)
	if err != nil {
		log.Fatalf("Failed to get interface info: %v", err)
	}

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

	// Create Inbound AF_PACKET socket (RX)
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(afBlockSize),
		afpacket.OptNumBlocks(afNumBlocks),
		afpacket.OptFrameSize(afFrameSize),
		afpacket.OptBlockTimeout(afBlockTimeout),
	)
	if err != nil {
		log.Fatalf("Failed to create RX AF_PACKET socket: %v", err)
	}
	defer tpacket.Close()

	// Create Outbound Shared AF_PACKET socket (TX)
	// We use a separate socket/ring for TX to separate limits and potential locks,
	// though we could share if careful. A separate TX ring is cleaner.
	txTPacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(1<<19), // 512KB blocks for TX
		afpacket.OptNumBlocks(16),
		afpacket.OptFrameSize(afFrameSize),
	)
	if err != nil {
		log.Fatalf("Failed to create TX AF_PACKET socket: %v", err)
	}
	defer txTPacket.Close()

	// No mutex around TX: WritePacketData is a single write(2) per packet, which
	// the kernel emits atomically for a packet socket, so reply goroutines can
	// write concurrently to the shared TX socket without interleaving.

	// BPF: reject our own outgoing packets + only accept our custom IP protocol.
	// For TCP/UDP modes we also narrow by our IP and the target port.
	filterDst := resolveFilterDstIP(srcIP)
	// Server receives uplink (client→server) traffic, so the BPF filters upProto.
	filter := createBPFFilter(upProto, srcMAC, *fakeFrag, filterDst, uint16(*targetPort), false)
	if err := tpacket.SetBPF(filter); err != nil {
		log.Fatalf("Failed to set BPF filter: %v", err)
	}

	sessions := sync.Map{}

	autoDst := false
	if *tunnelIP == "" {
		autoDst = true
		log.Printf("Auto-detecting Remote IP from incoming packets for each session")
	}

	for {
		// Zero-copy read from ring buffer
		data, _, err := tpacket.ZeroCopyReadPacketData()
		if err != nil {
			// Timeout is expected when no packets arrive — silently retry
			continue
		}

		// Parse Ethernet + IPv4 (fixed-offset, no gopacket dispatch).
		pkt, ok := parseEthIPv4(data)
		if !ok {
			continue
		}

		// Userspace protocol filter (defense-in-depth: BPF may fail to attach).
		// Incoming on the server is client→server traffic → upProto.
		if pkt.proto != upProto || pkt.fragOffset != 0 {
			continue
		}

		// Parse transport header (UDP or TCP) from IPv4 payload
		clientSrcPort, clientDstPort, innerPayload, ok := parseFakeTransport(pkt.payload, *fakeTCP)
		if !ok {
			continue
		}

		// Session key: ClientRealIP + VirtualSrcPort
		clientKey := makeNatKey(pkt.srcIP, int(clientSrcPort))

		var conn *net.UDPConn
		val, sessOk := sessions.Load(clientKey)

		if sessOk {
			conn = val.(*net.UDPConn)
		} else {
			// NEW SESSION
			targetAddr := fmt.Sprintf("127.0.0.1:%d", clientDstPort)
			rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				log.Printf("Resolve error: %v", err)
				continue
			}

			conn, err = net.DialUDP("udp", nil, rAddr)
			if err != nil {
				log.Printf("Dial error: %v", err)
				continue
			}

			conn.SetReadBuffer(socketBufSize)
			conn.SetWriteBuffer(socketBufSize)

			// Probe for GSO/GRO support on this session socket
			// sessTxOffload, sessRxOffload := supportsUDPOffload(conn)
			sessTxOffload := false
			sessRxOffload := false
			if sessRxOffload {
				if err := enableUDPGRO(conn); err != nil {
					log.Printf("Warning: Failed to enable UDP_GRO on session socket: %v", err)
					sessRxOffload = false
				}
			}

			sessions.Store(clientKey, conn)
			log.Printf("New Session: %s -> Target :%d (GSO=%v GRO=%v)", clientKey.String(), clientDstPort, sessTxOffload, sessRxOffload)

			// Create safe copies of the slices backed by the mmap ring
			safeClientIP := make(net.IP, len(pkt.srcIP))
			copy(safeClientIP, pkt.srcIP)

			safeClientMAC := make(net.HardwareAddr, len(pkt.srcMAC))
			copy(safeClientMAC, pkt.srcMAC)

			// Reply handler goroutine
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, clientMAC net.HardwareAddr,
				srcServerIP net.IP, targetRAddr *net.UDPAddr, sessionKey natKey,
				txOff, rxOff bool) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgsUDP(rxOff)
				defer c.Close()
				defer sessions.Delete(sessionKey)

				// Use shared txTPacket from outer scope (concurrent writes are safe)

				sBuf := gopacket.NewSerializeBuffer()
				sOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

				dstClientIP := net.ParseIP(*tunnelIP)
				if autoDst {
					dstClientIP = clientIP
				}

				// Reply headers
				rEthHeader := &layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       clientMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
				rIpFlags := layers.IPv4DontFragment
				// if *fakeFrag {
				// 	rIpFlags = layers.IPv4MoreFragments
				// }
				rIpHeader := &layers.IPv4{
					Version:  4,
					IHL:      5,
					TTL:      64,
					Protocol: layers.IPProtocol(dnProto),
					SrcIP:    srcServerIP,
					DstIP:    dstClientIP,
					Flags:    rIpFlags,
				}
				// Reply transport header (UDP or TCP), src port set per-packet.
				var rUdpHeader *layers.UDP
				var rTcpHeader *layers.TCP
				if *fakeTCP {
					rTcpHeader = newFakeTCPHeader(clientPort, tcpFlagByte)
					rTcpHeader.SetNetworkLayerForChecksum(rIpHeader)
				} else {
					rUdpHeader = &layers.UDP{DstPort: layers.UDPPort(clientPort)}
					rUdpHeader.SetNetworkLayerForChecksum(rIpHeader)
				}

				var errRead error
				n := 0
				readPos := 0
				for {
					if readPos >= n {
						// Arm the idle timeout only before an actual read, not on
						// every drained packet — one syscall per batch, not per packet.
						ipv4AppConn.SetReadDeadline(time.Now().Add(30 * time.Second))
						if rxOff {
							// With GRO: read into fewer slots, then split
							readAt := len(msgs) - (batchSize / udpSegmentMaxDatagrams)
							if readAt < 0 {
								readAt = 0
							}
							resetOOB(msgs[readAt:])
							n, errRead = ipv4AppConn.ReadBatch(msgs[readAt:], 0)
							if n == 0 || errRead != nil {
								// Normal EOF or timeout removal
								return
							}
							n, errRead = splitCoalescedMessages(msgs, readAt)
							if errRead != nil {
								log.Printf("GRO split error in session %s: %v", sessionKey.String(), errRead)
								return
							}
						} else {
							n, errRead = ipv4AppConn.ReadBatch(msgs, 0)
							if n == 0 || errRead != nil {
								return
							}
						}
						readPos = 0
					}
					msg := &msgs[readPos]
					readPos++
					payload := msg.Buffers[0][:msg.N]

					var transport gopacket.SerializableLayer
					if *fakeTCP {
						rTcpHeader.SrcPort = layers.TCPPort(targetRAddr.Port)
						transport = rTcpHeader
					} else {
						rUdpHeader.SrcPort = layers.UDPPort(targetRAddr.Port)
						transport = rUdpHeader
					}

					if err := gopacket.SerializeLayers(sBuf, sOpts, rEthHeader, rIpHeader, transport, gopacket.Payload(payload)); err != nil {
						log.Printf("Serialize error: %v", err)
						continue
					}

					err := txTPacket.WritePacketData(sBuf.Bytes())
					if err != nil {
						log.Printf("TX error: %v", err)
					}
				}
			}(conn, safeClientIP, clientSrcPort, safeClientMAC, srcIP, rAddr, clientKey,
				sessTxOffload, sessRxOffload)
		}

		payload := innerPayload
		if *fakeFrag {
			payload = unpadData(payload)
		}
		if _, err := conn.Write(payload); err != nil {
			log.Printf("conn.Write error in Server AF_PACKET downlink: %v", err)
		}
	}
}
