//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// High-throughput tuning constants
const (
	batchSize      = 32                     // Messages per batch read/write (recvmmsg/sendmmsg)
	socketBufSize  = 1 << 24                // 16MB socket buffer
	packetBufSize  = 1500                   // MTU size for raw socket reads
	udpPayloadSize = packetBufSize - 20 - 8 // 1472 bytes: fits in raw socket after IP+UDP headers
)

// Coarse timestamp to avoid time.Now() per packet
var coarseTime int64

func init() {
	atomic.StoreInt64(&coarseTime, time.Now().UnixNano())
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			atomic.StoreInt64(&coarseTime, time.Now().UnixNano())
		}
	}()
}

// Configuration
var (
	mode       = flag.String("mode", "client", "Mode: 'client' or 'server'")
	customSrc  = flag.String("src-ip", "", "Force a specific Source IP (Spoofing). Leave empty to auto-detect.")
	listenAddr = flag.String("listen", "127.0.0.1:1001", "Client: Local UDP port to bind. Server: Not used")
	tunnelIP   = flag.String("remote-ip", "", "IP of the remote tunnel endpoint")
	targetPort = flag.Int("target-port", 8080, "Client: Port to forward traffic to on the Server side")
	protoNum   = flag.Int("proto", 200, "Custom IP Protocol Number (0-255)")
)

func main() {
	flag.Parse()

	if *mode == "client" {
		log.Printf("[Client] Forwarding %s -> Tunnel(%s) -> :%d (Proto %d)", *listenAddr, *tunnelIP, *targetPort, *protoNum)
		startClient(*listenAddr, *tunnelIP, uint16(*targetPort), uint8(*protoNum))
	} else {
		log.Printf("[Server] Listening on Proto %d", *protoNum)
		startServer(uint8(*protoNum))
	}
}

// getOutboundIP determines the preferred local IP of this machine
func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

// --- Client Logic ---

// natKey is a fixed-size key to avoid string allocations (4 bytes IP + 2 bytes port)
type natKey [6]byte

func (k natKey) String() string {
	ip := net.IPv4(k[0], k[1], k[2], k[3])
	port := (uint16(k[4]) << 8) | uint16(k[5])
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

func makeNatKey(ip net.IP, port int) natKey {
	var k natKey
	ip4 := ip.To4()
	if ip4 != nil {
		copy(k[:4], ip4)
	}
	k[4] = byte(port >> 8)
	k[5] = byte(port)
	return k
}

type natSession struct {
	clientIP   net.IP
	clientPort int
	lastSeen   int64 // Unix nano timestamp - atomic access friendly
	forwardKey natKey
}

type NatTable struct {
	// key: natKey -> value: VirtualPort (uint16)
	forward sync.Map
	// key: VirtualPort (uint16) -> value: *natSession
	reverse sync.Map
}

func (n *NatTable) GetOrCreateVirtualPort(clientIP net.IP, clientPort int) uint16 {
	key := makeNatKey(clientIP, clientPort)

	// 1. Check existing - fast path
	if val, ok := n.forward.Load(key); ok {
		vPort := val.(uint16)
		if s, ok := n.reverse.Load(vPort); ok {
			// Use atomic store for lastSeen to avoid race detector complaints
			sess := s.(*natSession)
			sess.lastSeen = atomic.LoadInt64(&coarseTime)
		}
		return vPort
	}

	// 2. Allocation Logic - try original port first (slow path, acceptable)
	proposed := uint16(clientPort)
	for {
		session := &natSession{
			clientIP:   clientIP,
			clientPort: clientPort,
			lastSeen:   atomic.LoadInt64(&coarseTime),
			forwardKey: key,
		}
		// Try to store atomically
		if _, loaded := n.reverse.LoadOrStore(proposed, session); !loaded {
			n.forward.Store(key, proposed)
			return proposed
		}
		// Collision: pick random
		proposed = uint16(rand.Intn(65535-1024) + 1024)
	}
}

func (n *NatTable) GetSession(virtualPort uint16) *natSession {
	if val, ok := n.reverse.Load(virtualPort); ok {
		sess := val.(*natSession)
		sess.lastSeen = atomic.LoadInt64(&coarseTime)
		return sess
	}
	return nil
}

func (n *NatTable) Cleanup() {
	for {
		time.Sleep(30 * time.Second)
		threshold := time.Now().Add(-60 * time.Second).UnixNano()
		n.reverse.Range(func(key, value interface{}) bool {
			vPort := key.(uint16)
			sess := value.(*natSession)
			if sess.lastSeen < threshold {
				n.reverse.Delete(vPort)
				n.forward.Delete(sess.forwardKey)
			}
			return true
		})
	}
}

func startClient(localAddr, serverIPStr string, dstPort uint16, proto uint8) {
	ipv4RawConn, err := setupRawConn(int(proto))
	if err != nil {
		log.Fatalf("Raw setup failed: %v", err)
	}
	defer ipv4RawConn.Close()

	udpAddr, _ := net.ResolveUDPAddr("udp4", localAddr)
	appConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer appConn.Close()

	var errDFIPv4 error
	appRaw, _ := appConn.SyscallConn()
	appRaw.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
	})
	if errDFIPv4 != nil {
		log.Printf("failed to set IP_MTU_DISCOVER: %v", errDFIPv4)
	}
	appConn.SetReadBuffer(socketBufSize)
	appConn.SetWriteBuffer(socketBufSize)

	var srcIP net.IP
	if *customSrc != "" {
		srcIP = net.ParseIP(*customSrc) // User defined (SET)
		if srcIP == nil {
			log.Fatal("Invalid source IP format")
		}
		log.Printf("Using Custom Source IP: %s", srcIP)
	} else {
		srcIP = getOutboundIP() // Auto-detected (GET)
		log.Printf("Using Interface IP: %s", srcIP)
	}

	serverIP := net.ParseIP(serverIPStr)
	nat := &NatTable{}
	go nat.Cleanup()

	// Reusable Objects for Downlink
	// Separate parsers because custom IP protocol won't chain to UDP
	var ipLayer layers.IPv4
	var udpLayer layers.UDP
	ipParser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipLayer)
	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udpLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 2)

	// Downlink (Tunnel -> App)
	// Reads Raw Packets from Server, strips headers, translates VirtualPort -> ClientPort, writes to App
	go func() {
		msgs := prepareMsgs()

		n := 0
		readPos := 0
		for {
			if readPos >= n {
				n, err = ipv4RawConn.ReadBatch(msgs, 0)
				if n == 0 || err != nil {
					log.Printf("Read raw error: %v", err)
					continue
				}
				readPos = 0
			}
			msg := msgs[readPos]
			readPos++
			data := msg.Buffers[0][:msg.N]

			// Parse IPv4 header (ignore error - it complains about custom protocol but still decodes IPv4)
			ipParser.DecodeLayers(data, &decodedLayers)
			if len(decodedLayers) == 0 || decodedLayers[0] != layers.LayerTypeIPv4 {
				continue
			}

			if !ipLayer.SrcIP.Equal(serverIP) {
				// accept ip spoof?
				// continue
			}

			// Parse UDP from IPv4 payload (ignore error - complains about Payload layer)
			udpParser.DecodeLayers(ipLayer.Payload, &decodedLayers)
			if len(decodedLayers) == 0 || decodedLayers[0] != layers.LayerTypeUDP {
				continue
			}

			// Reverse NAT: VirtualPort (udp.DstPort) -> Client Session
			sess := nat.GetSession(uint16(udpLayer.DstPort))
			if sess == nil {
				continue
			}

			clientAppAddr := &net.UDPAddr{IP: sess.clientIP, Port: int(sess.clientPort)}
			appConn.WriteToUDP(udpLayer.Payload, clientAppAddr)
		}
	}()

	// Main Loop: Uplink (App -> Tunnel)
	// Reads UDP from App, Translate ClientPort -> VirtualPort, Wraps in Proto 200, Sends Raw
	ipv4AppConn := ipv4.NewPacketConn(appConn)
	msgs := prepareMsgsUDP()

	serializeBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ipHeader := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocol(proto),
		SrcIP:    srcIP,
		DstIP:    serverIP,
		Flags:    layers.IPv4DontFragment,
	}
	udpHeader := &layers.UDP{
		DstPort: layers.UDPPort(dstPort),
	}
	serverIPAddr := &net.IPAddr{IP: serverIP}

	n := 0
	readPos := 0
	for {
		if readPos >= n {
			n, err = ipv4AppConn.ReadBatch(msgs, 0)
			if n == 0 || err != nil {
				log.Printf("Read UDP error: %v", err)
				continue
			}
			readPos = 0
		}
		msg := msgs[readPos]
		readPos++
		data := msg.Buffers[0][:msg.N]
		cAddr := msg.Addr.(*net.UDPAddr)

		// NAT: Client -> VirtualPort
		// We use cAddr.Port as the unique identifier for the local client app
		vPort := nat.GetOrCreateVirtualPort(cAddr.IP, cAddr.Port)

		// Construct Packet
		udpHeader.SrcPort = layers.UDPPort(vPort)
		udpHeader.SetNetworkLayerForChecksum(ipHeader)

		gopacket.SerializeLayers(serializeBuf, opts, ipHeader, udpHeader, gopacket.Payload(data))

		// Send the packet buffer
		_, err = ipv4RawConn.WriteToIP(serializeBuf.Bytes(), serverIPAddr)
		if err != nil {
			log.Printf("Sendto error: %v", err)
		}
	}
}

// --- Server Logic ---

func startServer(proto uint8) {
	ipv4RawConn, err := setupRawConn(int(proto))
	if err != nil {
		log.Fatalf("Raw setup failed: %v", err)
	}
	defer ipv4RawConn.Close()

	sessions := sync.Map{}

	// Separate parsers because custom IP protocol won't chain to UDP
	var ipLayer layers.IPv4
	var udpLayer layers.UDP
	ipParser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipLayer)
	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udpLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 2)

	var srcIP net.IP
	if *customSrc != "" {
		srcIP = net.ParseIP(*customSrc) // User defined (SET)
		if srcIP == nil {
			log.Fatal("Invalid source IP format")
		}
		log.Printf("Using Custom Source IP: %s", srcIP)
	} else {
		srcIP = getOutboundIP() // Auto-detected (GET)
		log.Printf("Using Interface IP: %s", srcIP)
	}

	autoDst := false
	if *tunnelIP == "" {
		autoDst = true
		log.Printf("Auto-detecting Remote IP from incoming packets for each session")
	}

	msgs := prepareMsgs()

	n := 0
	readPos := 0
	for {
		if readPos >= n {
			n, err = ipv4RawConn.ReadBatch(msgs, 0)
			if n == 0 || err != nil {
				log.Printf("Read raw error: %v", err)
				continue
			}
			readPos = 0
		}
		msg := msgs[readPos]
		readPos++
		data := msg.Buffers[0][:msg.N]

		// Parse IPv4 header (ignore error - it complains about custom protocol but still decodes IPv4)
		err = ipParser.DecodeLayers(data, &decodedLayers)
		if len(decodedLayers) == 0 || decodedLayers[0] != layers.LayerTypeIPv4 {
			log.Printf("Failed to decode IPv4 layer, err %v", err)
			continue
		}

		// Parse UDP from IPv4 payload (ignore error - complains about Payload layer)
		err = udpParser.DecodeLayers(ipLayer.Payload, &decodedLayers)
		if len(decodedLayers) == 0 || decodedLayers[0] != layers.LayerTypeUDP {
			log.Printf("Failed to decode UDP layer, err %v", err)
			continue
		}

		// Identify Session Key (ClientRealIP + VirtualSrcPort) - use fixed-size key to avoid allocs
		clientKey := makeNatKey(ipLayer.SrcIP, int(udpLayer.SrcPort))

		var conn *net.UDPConn
		val, ok := sessions.Load(clientKey)

		if ok {
			conn = val.(*net.UDPConn)
		} else {
			// NEW SESSION
			targetAddr := fmt.Sprintf("127.0.0.1:%d", udpLayer.DstPort)
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

			var errDFIPv4 error
			appRaw, _ := conn.SyscallConn()
			appRaw.Control(func(fd uintptr) {
				errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
			})
			if errDFIPv4 != nil {
				log.Printf("failed to set IP_MTU_DISCOVER: %v", errDFIPv4)
			}
			conn.SetReadBuffer(socketBufSize)
			conn.SetWriteBuffer(socketBufSize)

			sessions.Store(clientKey, conn)
			log.Printf("New Session: %s -> Target", clientKey.String())

			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, srcServerIP net.IP) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgsUDP()
				defer c.Close()
				defer sessions.Delete(clientKey)

				// Serialize reuse variables
				sBuf := gopacket.NewSerializeBuffer()
				sOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

				dstClientIP := net.ParseIP(*tunnelIP)
				if autoDst {
					dstClientIP = clientIP
				}
				// Reply Headers
				rIpHeader := &layers.IPv4{
					Version:  4,
					IHL:      5,
					TTL:      64,
					Protocol: layers.IPProtocol(proto),
					SrcIP:    srcServerIP,
					DstIP:    dstClientIP,
					Flags:    layers.IPv4DontFragment,
				}
				rUdpHeader := &layers.UDP{
					DstPort: layers.UDPPort(clientPort),
				}
				// Cache destination IPAddr outside loop to avoid per-packet allocation
				dstIPAddr := &net.IPAddr{IP: dstClientIP}

				var err error
				n := 0
				readPos := 0
				for {
					ipv4AppConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					if readPos >= n {
						n, err = ipv4AppConn.ReadBatch(msgs, 0)
						if n == 0 || err != nil {
							log.Printf("Read UDP error: %v", err)
							return
						}
						readPos = 0
					}
					msg := msgs[readPos]
					readPos++
					data := msg.Buffers[0][:msg.N]

					// Send Reply: [IPv4 (Dst=Client)] [UDP (Dst=ClientPort)] [Payload]
					// We need to use the original DstPort (from request) as SrcPort (for reply)
					// But we don't track original DstPort in scope easily unless we pass it or reuse conn's remote?
					// Actually, the tunnel logic usually mirrors ports.
					// In the request: Src=VirtualPort, Dst=TargetPort
					// In the reply: Src=TargetPort, Dst=VirtualPort
					// Wait, the client expects reply DstPort=VirtualPort.
					// The simple logic uses the TargetPort as Src?
					// Let's capture the TargetPort from the session creation context.
					// Or just use the RemoteAddr of the dial?
					// rAddr was resolved above.

					rUdpHeader.SrcPort = layers.UDPPort(rAddr.Port)
					rUdpHeader.SetNetworkLayerForChecksum(rIpHeader)

					gopacket.SerializeLayers(sBuf, sOpts, rIpHeader, rUdpHeader, gopacket.Payload(data))

					// Use cached clientIPAddr to avoid allocation per packet
					ipv4RawConn.WriteToIP(sBuf.Bytes(), dstIPAddr)
				}
			}(conn, ipLayer.SrcIP, uint16(udpLayer.SrcPort), srcIP)
		}

		conn.Write(udpLayer.Payload)
	}
}

// --- Shared Helpers ---

func setupRawConn(proto int) (*ipv4.RawConn, error) {
	// Use Go's standard net package to open the raw socket (binds to 0.0.0.0)
	conn, err := net.ListenPacket(fmt.Sprintf("ip4:%d", proto), "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("net.ListenPacket failed: %v", err)
	}

	// Apply socket options (IP_HDRINCL) directly to the underlying FD
	if sc, ok := conn.(syscall.Conn); ok {
		raw, err := sc.SyscallConn()
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("SyscallConn failed: %v", err)
		}
		var sockErr error
		err = raw.Control(func(fd uintptr) {
			// IP_HDRINCL is mandatory for spoofing
			if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
				sockErr = fmt.Errorf("failed to set IP_HDRINCL: %v", err)
				return
			}
			// Optimization: PMTU Discovery (Best effort)
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
		})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("control failed: %v", err)
		}
		if sockErr != nil {
			conn.Close()
			return nil, sockErr
		}
	}

	return ipv4.NewRawConn(conn)
}

func prepareMsgs() []ipv4.Message {
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, packetBufSize)
	}
	return msgs
}

// prepareMsgsUDP creates message buffers for UDP reads (payload only, fits in raw socket)
func prepareMsgsUDP() []ipv4.Message {
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, udpPayloadSize)
	}
	return msgs
}
