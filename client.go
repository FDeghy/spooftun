//go:build linux

package main

import (
	"log"
	"net"
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
	maxReply := payloadLimit(mtu, *fakeTCP, false)
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
	filter := newTunnelPacketFilter(dnProto, srcMAC, filterDst, dstPort, true)
	workers, err := newTunnelWorkers(iface, dnProto, srcMAC, filterDst, dstPort, true)
	if err != nil {
		log.Fatalf("Initialize packet backend: %v", err)
	}
	defer closeTunnelWorkers(workers)
	txSender := workers[0].sender

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
	for _, worker := range workers {
		go func(receiver packetReceiver) {
			forwarder := newLocalUDPDelivery(receiver, maxReply)
			defer forwarder.Close()

			for {
				// Read a borrowed frame; its bytes remain valid until the next read.
				data, err := forwarder.ReadPacket()
				if err != nil {
					log.Fatalf("Packet receive failed: %v", err)
				}

				// Parse Ethernet + IPv4 header (fixed-offset, no gopacket dispatch).
				pkt, ok := parseEthIPv4(data)
				if !ok || isNoisePacket(pkt, *fakeTCP) {
					continue
				}

				// Userspace protocol filter (defense-in-depth: BPF may fail to attach).
				// Incoming on the client is server→client traffic → dnProto.
				if pkt.proto != dnProto || pkt.fragOffset != 0 {
					continue
				}

				// Parse transport header (UDP or TCP) from IP payload
				srcPortRecv, dstPortRecv, payload, ok := parseTunnelTransport(pkt, *fakeTCP)
				if !ok || srcPortRecv != dstPort || len(payload) > maxReply || !filter.matches(pkt, srcPortRecv, dstPortRecv) {
					continue
				}

				// Reverse NAT: VirtualPort (transport.DstPort) -> Client Session
				sess := nat.GetSession(dstPortRecv)
				if sess == nil {
					continue
				}

				if sess.clientAddr.IsValid() {
					forwarder.Send(appConn, sess.clientAddr, payload)
				}
			}
		}(worker.receiver)
	}

	// Uplink (App -> AF_PACKET)
	// Reads UDP from App, translates ClientPort -> VirtualPort, wraps in Ethernet + IP + Proto, sends raw
	udpReader, err := newLocalUDPReader(appConn, maxPayload, *udpGRO)
	if err != nil {
		log.Fatalf("Initialize UDP reader: %v", err)
	}
	log.Printf("client UDP receive: recvmmsg GRO=%t", udpReader.gro)
	msgs := make([]localUDPDatagram, batchSize)

	noiseSender, err := newPacketNoise(*noise, noiseContent)
	if err != nil {
		log.Fatalf("Initialize noise: %v", err)
	}
	framesPerDatagram := 1
	if *fakeFrag {
		framesPerDatagram++
	}
	if noiseSender != nil {
		framesPerDatagram++
	}
	txBuffers := make([][]byte, batchSize*framesPerDatagram)
	for i := range txBuffers {
		txBuffers[i] = make([]byte, max(60, mtu+14))
	}
	encoder, err := newTunnelEncoder(srcMAC, dstMAC, srcIP, serverIP, upProto, *fakeTCP, tcpFlagByte)
	if err != nil {
		log.Fatal(err)
	}
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
			n, err = udpReader.ReadBatch(msgs)
			if n == 0 || err != nil {
				log.Printf("Read UDP error: %v", err)
				continue
			}
			readPos = 0
		}
		msg := &msgs[readPos]
		readPos++
		data := msg.payload

		// NAT: Client -> VirtualPort
		vPort, natErr := nat.GetOrCreateVirtualPort4(msg.addr.Addr().As4(), msg.addr.Port())
		if natErr != nil {
			continue
		}

		var noiseSession *natSession
		if noiseSender != nil {
			noiseSession = nat.reverse[vPort].Load()
		}
		base := len(frames)
		dataIdx := base
		var noiseFrame []byte
		if noiseSession != nil && !noiseSession.noiseSent {
			noiseFrame, err = noiseSender.Encode(encoder, txBuffers[base], vPort, dstPort)
			if err != nil {
				log.Printf("Noise encode error: %v", err)
				continue
			}
			dataIdx++
		}
		if *fakeFrag {
			// Stage and pad directly in the target TX frame's payload region so
			// GRO segments are not overwritten and no scratch copy is needed.
			buf := txBuffers[dataIdx][34+hdrLen : 34+hdrLen+len(data)]
			copy(buf, data)
			data = padData(buf, 8, hdrLen)
		}
		frame, err := encoder.Encode(txBuffers[dataIdx], data, vPort, dstPort, ipId, ipFlags, 0, true)
		if err != nil {
			log.Printf("Encode error: %v", err)
			continue
		}
		var fragFrame []byte
		if *fakeFrag {
			offset := uint16((len(data) + hdrLen) / 8)
			fragFrame, err = encoder.Encode(txBuffers[dataIdx+1], fakeTail[:], 0, 0, ipId, 0, offset, false)
			if err != nil {
				log.Printf("Encode error: %v", err)
				continue
			}
		}
		if noiseFrame != nil {
			pendingNoise.queued(base, &noiseSession.noiseSent)
			frames = append(frames, noiseFrame)
		}
		frames = append(frames, frame)
		if fragFrame != nil {
			frames = append(frames, fragFrame)
		}

		ipId++
		if ipId == 0 {
			ipId = 1
		}
	}
}
