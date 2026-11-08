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
)

// startServerAFPacket runs the server side of the tunnel: it captures uplink
// frames (client→server) under the custom IP protocol number, forwards the
// inner payload to a local target port, and spawns a per-flow reply goroutine
// that wraps target responses back into tunnel frames on the selected backend.
func startServerAFPacket(upProto, dnProto uint8, iface string) {
	mtu, err := effectiveMTU(iface)
	if err != nil {
		log.Fatal(err)
	}
	maxReply := payloadLimit(mtu, *fakeTCP, false)
	maxUplink := payloadLimit(mtu, *fakeTCP, *fakeFrag)
	if *noise {
		if err := validateNoisePayload(noiseContent, mtu); err != nil {
			log.Fatal(err)
		}
	}
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
	filter := newTunnelPacketFilter(upProto, srcMAC, filterDst, uint16(*targetPort), false)
	workers, err := newTunnelWorkers(iface, upProto, srcMAC, filterDst, uint16(*targetPort), false)
	if err != nil {
		log.Fatalf("Initialize packet backend: %v", err)
	}
	defer closeTunnelWorkers(workers)

	sessions := sync.Map{}
	var sessionCreateMu sync.Mutex
	var admission serverSessionAdmission
	var activeSessions atomic.Int32
	sessionLimit := serverSessionLimit(mtu, maxReply, *udpGRO, *noise)
	log.Printf("server session limit=%d reserved-payload-budget=%d MiB", sessionLimit, serverSessionBufferBudget>>20)
	expectedDstPort := uint16(*targetPort)
	if *outboundPort != 0 {
		log.Printf("Server local UDP destination: 127.0.0.1:%d (tunnel port unchanged)", *outboundPort)
	}

	autoDst := false
	if *tunnelIP == "" {
		autoDst = true
		log.Printf("Auto-detecting Remote IP from incoming packets for each session")
	}

	var overrideMAC net.HardwareAddr
	if !autoDst {
		overrideMAC, err = getNeighborMAC(iface, net.ParseIP(*tunnelIP))
		if err != nil {
			log.Fatalf("Resolve return endpoint: %v", err)
		}
	}

	runWorker := func(receiver packetReceiver, txSender packetTransmitter) {
		nextSessionError := int64(0)
		forwarder := newLocalUDPDelivery(receiver, maxUplink)
		defer forwarder.Close()
		for {
			// Read a borrowed frame from the selected packet backend.
			data, err := forwarder.ReadPacket()
			if err != nil {
				log.Fatalf("Packet receive failed: %v", err)
			}

			// Parse Ethernet + IPv4 (fixed-offset, no gopacket dispatch).
			pkt, ok := parseEthIPv4(data)
			if !ok || isNoisePacket(pkt, *fakeTCP) {
				continue
			}

			// Userspace protocol filter (defense-in-depth: BPF may fail to attach).
			// Incoming on the server is client→server traffic → upProto.
			if pkt.proto != upProto || pkt.fragOffset != 0 {
				continue
			}

			// Parse transport header (UDP or TCP) from IPv4 payload
			clientSrcPort, clientDstPort, innerPayload, ok := parseTunnelTransport(pkt, *fakeTCP)
			if !ok || clientDstPort != expectedDstPort || !filter.matches(pkt, clientSrcPort, clientDstPort) {
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

			state, created, err := acquireServerSession(&sessions, &sessionCreateMu, clientKey, func() (*serverSession, error) {
				if activeSessions.Load() >= sessionLimit {
					return nil, fmt.Errorf("maximum active server sessions (%d) reached", sessionLimit)
				}
				if !admission.allow(monotonicNow()) {
					return nil, fmt.Errorf("server session creation rate exceeded")
				}
				localPort := expectedDstPort
				if *outboundPort != 0 {
					localPort = uint16(*outboundPort)
				}
				targetAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
				rAddr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					return nil, err
				}
				conn, err := net.DialUDP("udp", nil, rAddr)
				if err != nil {
					return nil, err
				}
				configureLocalUDP(conn, "server target")
				state := &serverSession{conn: conn}
				state.lastSeen.Store(sessionActivityTime())
				activeSessions.Add(1)
				log.Printf("New Session: %s -> Target :%d (tunnel port %d)", clientKey.String(), localPort, clientDstPort)
				return state, nil
			})
			if err != nil {
				if now := monotonicNow(); now >= nextSessionError {
					log.Printf("Create session: %v (further errors suppressed for one second)", err)
					nextSessionError = now + int64(time.Second)
				}
				continue
			}
			conn := state.conn
			if autoDst {
				mac := [6]byte(pkt.srcMAC)
				previous := state.replyMAC.Load()
				if previous == nil || *previous != mac {
					replacement := mac
					state.replyMAC.Store(&replacement)
				}
			}
			if created {
				// Create safe copies of the slices backed by the mmap ring
				safeClientIP := make(net.IP, len(pkt.srcIP))
				copy(safeClientIP, pkt.srcIP)

				safeClientMAC := make(net.HardwareAddr, len(pkt.srcMAC))
				copy(safeClientMAC, pkt.srcMAC)
				if overrideMAC != nil {
					copy(safeClientMAC, overrideMAC)
				}

				// Reply handler goroutine
				go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, clientMAC net.HardwareAddr,
					srcServerIP net.IP, tunnelPort uint16, sessionKey natKey,
					state *serverSession) {
					defer c.Close()
					defer activeSessions.Add(-1)
					defer sessions.CompareAndDelete(sessionKey, state)
					defer state.lastSeen.Store(retiredSessionTime)
					udpReader, err := newLocalUDPReader(c, maxReply, *udpGRO)
					if err != nil {
						log.Printf("Initialize reply UDP reader: %v", err)
						return
					}
					log.Printf("server UDP receive: recvmmsg GRO=%t", udpReader.gro)
					msgs := make([]localUDPDatagram, batchSize)

					// Use shared txSender from outer scope (concurrent writes are safe)

					noiseSender, err := newPacketNoise(*noise, noiseContent)
					if err != nil {
						log.Printf("Initialize reply noise: %v", err)
						return
					}
					framesPerDatagram := 1
					if noiseSender != nil {
						framesPerDatagram++
					}
					noiseSent := false
					txBuffers := make([][]byte, batchSize*framesPerDatagram)
					frames := make([][]byte, 0, len(txBuffers))
					var pendingNoise noiseBatch
					flush := func() {
						if len(frames) > 0 {
							if _, err := pendingNoise.WriteBatch(txSender, frames); err != nil {
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

					neighbor := neighborRefresh{iface: iface, peer: dstClientIP}
					var errRead error
					n := 0
					readPos := 0
					replyID := uint16(1)
					// Packet activity advances lastSeen without resetting Go's socket
					// timer. Renew the deadline only when the previous one fires.
					if err := c.SetReadDeadline(state.idleDeadline(*sessionTimeout)); err != nil {
						return
					}
					for {
						if readPos >= n {
							flush()
							n, errRead = udpReader.ReadBatch(msgs)
							if n == 0 || errRead != nil {
								if ne, ok := errRead.(net.Error); ok && ne.Timeout() && !state.expireIdle(monotonicNow(), *sessionTimeout) {
									if err := c.SetReadDeadline(state.idleDeadline(*sessionTimeout)); err != nil {
										return
									}
									continue
								}
								return
							}

							if autoDst {
								if mac := state.replyMAC.Load(); mac != nil {
									copy(encoder.template[:6], mac[:])
								}
							} else {
								neighbor.refresh(encoder)
							}
							readPos = 0
						}
						if txBuffers[0] == nil {
							storage := make([]byte, len(txBuffers)*max(60, mtu+14))
							size := max(60, mtu+14)
							for i := range txBuffers {
								txBuffers[i] = storage[i*size : (i+1)*size : (i+1)*size]
							}
						}
						msg := &msgs[readPos]
						readPos++
						state.refresh(sessionActivityTime())
						payload := msg.payload
						base := len(frames)
						dataIdx := base
						var noiseFrame []byte
						if noiseSender != nil && !noiseSent {
							noiseFrame, err = noiseSender.Encode(encoder, txBuffers[base], tunnelPort, clientPort)
							if err != nil {
								log.Printf("Noise encode error: %v", err)
								continue
							}
							dataIdx++
						}

						// Client filters match the original tunnel port, not the
						// possibly remapped local application's port.
						frame, err := encoder.Encode(txBuffers[dataIdx], payload, tunnelPort, clientPort, replyID, 0x4000, 0, true)
						if err != nil {
							log.Printf("Encode error: %v", err)
							continue
						}
						if noiseFrame != nil {
							pendingNoise.queued(base, &noiseSent)
							frames = append(frames, noiseFrame)
						}
						frames = append(frames, frame)
						replyID++
						if replyID == 0 {
							replyID = 1
						}
					}
				}(conn, safeClientIP, clientSrcPort, safeClientMAC, srcIP, clientDstPort, clientKey,
					state)
			}

			forwarder.Send(conn, netip.AddrPort{}, payload)
		}
	}
	for _, worker := range workers[1:] {
		go runWorker(worker.receiver, worker.sender)
	}
	runWorker(workers[0].receiver, workers[0].sender)
}

// Established sessions need no creation lock. Only misses/retirement enter the
// slow path; rechecking under the lock prevents spread workers opening multiple
// target sockets (and reply goroutines) for the same newly observed flow.
func acquireServerSession(sessions *sync.Map, createMu *sync.Mutex, key natKey, create func() (*serverSession, error)) (*serverSession, bool, error) {
	load := func() *serverSession {
		if value, ok := sessions.Load(key); ok {
			state := value.(*serverSession)
			if state.refresh(sessionActivityTime()) {
				return state
			}
			sessions.CompareAndDelete(key, state)
		}
		return nil
	}
	if state := load(); state != nil {
		return state, false, nil
	}
	createMu.Lock()
	defer createMu.Unlock()
	if state := load(); state != nil {
		return state, false, nil
	}
	state, err := create()
	if err != nil {
		return nil, false, err
	}
	sessions.Store(key, state)
	return state, true, nil
}
