//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// startServerAFPacket runs the server side of the tunnel: it captures uplink
// frames (client→server) under the custom IP protocol number, forwards the
// inner payload to a local target port, and spawns a per-flow reply goroutine
// that wraps target responses back into tunnel frames on the selected backend.
type serverSession struct {
	conn     *net.UDPConn
	lastSeen atomic.Int64
}

// Use the coarse clock's upper bound so timestamp quantization cannot expire
// a session before its idle timeout. Short timeouts retain full precision.
func sessionActivityTime() int64 {
	if *sessionTimeout < time.Second {
		return time.Now().UnixNano()
	}
	return atomic.LoadInt64(&coarseTime) + int64(coarseTimeInterval)
}

func (s *serverSession) refresh(now int64) bool {
	for {
		last := s.lastSeen.Load()
		if last == retiredSessionTime {
			return false
		}
		if s.lastSeen.CompareAndSwap(last, max(last, now)) {
			return true
		}
	}
}

func (s *serverSession) expireIdle(now int64, timeout time.Duration) bool {
	for {
		last := s.lastSeen.Load()
		if last == retiredSessionTime {
			return true
		}
		if now-last < int64(timeout) {
			return false
		}
		if s.lastSeen.CompareAndSwap(last, retiredSessionTime) {
			return true
		}
	}
}

func (s *serverSession) idleDeadline(timeout time.Duration) time.Time {
	return time.Unix(0, s.lastSeen.Load()).Add(timeout)
}

func startServerAFPacket(upProto, dnProto uint8, iface string) {
	mtu, err := effectiveMTU(iface)
	if err != nil {
		log.Fatal(err)
	}
	maxReply := payloadLimit(mtu, *fakeTCP, false)
	maxUplink := payloadLimit(mtu, *fakeTCP, *fakeFrag)
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

	filterDst := resolveFilterDstIP(srcIP)
	receiver, txSender, err := newTunnelIO(iface, upProto, srcMAC, filterDst, uint16(*targetPort), false)
	if err != nil {
		log.Fatalf("Initialize packet backend: %v", err)
	}
	defer receiver.Close()
	defer txSender.Close()

	sessions := sync.Map{}

	autoDst := false
	if *tunnelIP == "" {
		autoDst = true
		log.Printf("Auto-detecting Remote IP from incoming packets for each session")
	}

	for {
		// Read a borrowed frame from the selected packet backend.
		data, err := receiver.ReadPacket()
		if err != nil {
			log.Fatalf("Packet receive failed: %v", err)
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

		payload := innerPayload
		if *fakeFrag {
			payload = unpadData(payload)
			if payload == nil {
				continue
			}
		}
		if len(payload) > maxUplink {
			continue
		}
		// Session key: ClientRealIP + VirtualSrcPort
		clientKey := makeNatKey(pkt.srcIP, int(clientSrcPort))

		var conn *net.UDPConn
		var state *serverSession
		val, sessOk := sessions.Load(clientKey)
		if sessOk && !val.(*serverSession).refresh(sessionActivityTime()) {
			sessions.CompareAndDelete(clientKey, val)
			sessOk = false
		}

		if sessOk {
			state = val.(*serverSession)
			conn = state.conn
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

			state = &serverSession{conn: conn}
			state.lastSeen.Store(sessionActivityTime())
			sessions.Store(clientKey, state)
			log.Printf("New Session: %s -> Target :%d (GSO=%v GRO=%v)", clientKey.String(), clientDstPort, sessTxOffload, sessRxOffload)

			// Create safe copies of the slices backed by the mmap ring
			safeClientIP := make(net.IP, len(pkt.srcIP))
			copy(safeClientIP, pkt.srcIP)

			safeClientMAC := make(net.HardwareAddr, len(pkt.srcMAC))
			copy(safeClientMAC, pkt.srcMAC)

			// Reply handler goroutine
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, clientMAC net.HardwareAddr,
				srcServerIP net.IP, targetRAddr *net.UDPAddr, sessionKey natKey,
				txOff, rxOff bool, state *serverSession) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgsUDP(rxOff)
				defer c.Close()
				defer sessions.CompareAndDelete(sessionKey, state)
				defer state.lastSeen.Store(retiredSessionTime)

				// Use shared txSender from outer scope (concurrent writes are safe)

				var sBuf gopacket.SerializeBuffer
				txBuffers := make([]gopacket.SerializeBuffer, batchSize)
				for i := range txBuffers {
					txBuffers[i] = gopacket.NewSerializeBufferExpectedSize(64, mtu)
				}
				frames := make([][]byte, 0, batchSize)
				flush := func() {
					if len(frames) > 0 {
						if _, err := txSender.WriteBatch(frames); err != nil {
							log.Printf("TX batch: %v", err)
						}
						frames = frames[:0]
					}
				}
				defer flush()
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
				// Packet activity advances lastSeen without resetting Go's socket
				// timer. Renew the deadline only when the previous one fires.
				if err := ipv4AppConn.SetReadDeadline(state.idleDeadline(*sessionTimeout)); err != nil {
					return
				}
				for {
					if readPos >= n {
						flush()
						readAt := 0
						if rxOff {
							// With GRO: read into fewer slots, then split
							readAt = len(msgs) - ((batchSize + udpSegmentMaxDatagrams - 1) / udpSegmentMaxDatagrams)
							if readAt < 0 {
								readAt = 0
							}
							resetOOB(msgs[readAt:])
						}
						n, errRead = ipv4AppConn.ReadBatch(msgs[readAt:], 0)
						if n == 0 || errRead != nil {
							if ne, ok := errRead.(net.Error); ok && ne.Timeout() && !state.expireIdle(time.Now().UnixNano(), *sessionTimeout) {
								if err := ipv4AppConn.SetReadDeadline(state.idleDeadline(*sessionTimeout)); err != nil {
									return
								}
								continue
							}
							return
						}
						if rxOff {
							n, errRead = splitCoalescedMessages(msgs, readAt, n)
							if errRead != nil {
								log.Printf("GRO split error in session %s: %v", sessionKey.String(), errRead)
								return
							}
						}
						readPos = 0
					}
					msg := &msgs[readPos]
					readPos++
					if msg.Flags&unix.MSG_TRUNC != 0 || msg.N > maxReply {
						continue
					}
					state.refresh(sessionActivityTime())
					payload := msg.Buffers[0][:msg.N]

					sBuf = txBuffers[len(frames)]
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

					frames = append(frames, sBuf.Bytes())
				}
			}(conn, safeClientIP, clientSrcPort, safeClientMAC, srcIP, rAddr, clientKey,
				sessTxOffload, sessRxOffload, state)
		}

		if _, err := conn.Write(payload); err != nil {
			log.Printf("conn.Write error in Server AF_PACKET downlink: %v", err)
		}
	}
}
