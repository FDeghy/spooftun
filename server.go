//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

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
	forwarder := newLocalUDPForwarder(mtu)
	defer forwarder.Close()

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

			configureLocalUDP(conn, "server target")

			state = &serverSession{conn: conn}
			state.lastSeen.Store(sessionActivityTime())
			sessions.Store(clientKey, state)
			log.Printf("New Session: %s -> Target :%d", clientKey.String(), clientDstPort)

			// Create safe copies of the slices backed by the mmap ring
			safeClientIP := make(net.IP, len(pkt.srcIP))
			copy(safeClientIP, pkt.srcIP)

			safeClientMAC := make(net.HardwareAddr, len(pkt.srcMAC))
			copy(safeClientMAC, pkt.srcMAC)

			// Reply handler goroutine
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, clientMAC net.HardwareAddr,
				srcServerIP net.IP, targetRAddr *net.UDPAddr, sessionKey natKey,
				state *serverSession) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgsUDP()
				defer c.Close()
				defer sessions.CompareAndDelete(sessionKey, state)
				defer state.lastSeen.Store(retiredSessionTime)

				// Use shared txSender from outer scope (concurrent writes are safe)

				txBuffers := make([][]byte, batchSize)
				for i := range txBuffers {
					txBuffers[i] = make([]byte, max(60, mtu+14))
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

				dstClientIP := net.ParseIP(*tunnelIP)
				if autoDst {
					dstClientIP = clientIP
				}

				encoder, err := newTunnelEncoder(srcMAC, clientMAC, srcServerIP, dstClientIP, dnProto, *fakeTCP, tcpFlagByte)
				if err != nil {
					log.Printf("Create reply encoder: %v", err)
					return
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
						n, errRead = ipv4AppConn.ReadBatch(msgs, 0)
						if n == 0 || errRead != nil {
							if ne, ok := errRead.(net.Error); ok && ne.Timeout() && !state.expireIdle(time.Now().UnixNano(), *sessionTimeout) {
								if err := ipv4AppConn.SetReadDeadline(state.idleDeadline(*sessionTimeout)); err != nil {
									return
								}
								continue
							}
							return
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

					frame, err := encoder.Encode(txBuffers[len(frames)], payload, uint16(targetRAddr.Port), clientPort, 0, 0x4000, 0, true)
					if err != nil {
						log.Printf("Encode error: %v", err)
						continue
					}
					frames = append(frames, frame)
				}
			}(conn, safeClientIP, clientSrcPort, safeClientMAC, srcIP, rAddr, clientKey,
				state)
		}

		forwarder.Send(conn, netip.AddrPort{}, payload)
	}
}
