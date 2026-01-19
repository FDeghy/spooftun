//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Configuration
var (
	mode       = flag.String("mode", "client", "Mode: 'client' or 'server'")
	customSrc  = flag.String("src-ip", "", "Force a specific Source IP (Spoofing). Leave empty to auto-detect.")
	listenAddr = flag.String("listen", "127.0.0.1:1001", "Client: Local UDP port to bind. Server: Not used")
	tunnelIP   = flag.String("remote-ip", "127.0.0.1", "IP of the remote tunnel endpoint")
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

type natSession struct {
	clientIP   net.IP
	clientPort int
	lastSeen   time.Time
	forwardKey string // Cached key to avoid allocation in cleanup
}

type NatTable struct {
	// key: "ClientIP:ClientPort" -> value: VirtualPort (uint16)
	forward sync.Map
	// key: VirtualPort (uint16) -> value: *natSession
	reverse sync.Map
}

func (n *NatTable) GetOrCreateVirtualPort(clientIP net.IP, clientPort int) uint16 {
	key := fmt.Sprintf("%s:%d", clientIP.String(), clientPort)

	// 1. Check existing
	if val, ok := n.forward.Load(key); ok {
		vPort := val.(uint16)
		if s, ok := n.reverse.Load(vPort); ok {
			s.(*natSession).lastSeen = time.Now()
		}
		return vPort
	}

	// 2. Allocation Logic - try original port first
	proposed := uint16(clientPort)
	for {
		session := &natSession{
			clientIP:   clientIP,
			clientPort: clientPort,
			lastSeen:   time.Now(),
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
		sess.lastSeen = time.Now()
		return sess
	}
	return nil
}

func (n *NatTable) Cleanup() {
	for {
		time.Sleep(30 * time.Second)
		now := time.Now()
		n.reverse.Range(func(key, value interface{}) bool {
			vPort := key.(uint16)
			sess := value.(*natSession)
			if now.Sub(sess.lastSeen) > 60*time.Second {
				n.reverse.Delete(vPort)
				n.forward.Delete(sess.forwardKey)
			}
			return true
		})
	}
}

func startClient(localAddr, serverIPStr string, dstPort uint16, proto uint8) {
	rawFd := createRawSocket(proto)
	defer syscall.Close(rawFd)

	udpAddr, _ := net.ResolveUDPAddr("udp", localAddr)
	appConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer appConn.Close()

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
	// Packet Parsing
	var (
		ipLayer  layers.IPv4
		udpLayer layers.UDP
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipLayer, &udpLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// Downlink (Tunnel -> App)
	// Reads Raw Packets from Server, strips headers, translates VirtualPort -> ClientPort, writes to App
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := syscall.Recvfrom(rawFd, buf, 0)
			if err != nil {
				log.Printf("error syscall.Recvfrom: %v", err)
				continue
			}

			// Zero-alloc parse
			err = parser.DecodeLayers(buf[:n], &decodedLayers)
			if err != nil {
				// gopacket might error if payload is not fully parsed or strict check fails,
				// but we usually care if we got at least IPv4 and UDP
				// Check if we got the layers we need
			}

			// Validate layers
			hasIP := false
			hasUDP := false
			for _, typ := range decodedLayers {
				if typ == layers.LayerTypeIPv4 {
					hasIP = true
				} else if typ == layers.LayerTypeUDP {
					hasUDP = true
				}
			}

			if !hasIP || !hasUDP {
				continue
			}

			if !ipLayer.SrcIP.Equal(serverIP) {
				continue
			}

			// Reverse NAT: VirtualPort (udp.DstPort) -> Client Session
			// Note: udpLayer.DstPort is layers.UDPPort (uint16)
			sess := nat.GetSession(uint16(udpLayer.DstPort))
			if sess == nil {
				continue
			}

			clientAppAddr := &net.UDPAddr{IP: sess.clientIP, Port: sess.clientPort}
			appConn.WriteToUDP(udpLayer.Payload, clientAppAddr)
		}
	}()

	// Main Loop: Uplink (App -> Tunnel)
	// Reads UDP from App, Translate ClientPort -> VirtualPort, Wraps in Proto 200, Sends Raw
	buf := make([]byte, 1500)
	serializeBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ipHeader := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocol(proto),
		SrcIP:    srcIP,
		DstIP:    serverIP,
	}
	udpHeader := &layers.UDP{
		DstPort: layers.UDPPort(dstPort),
	}

	for {
		n, cAddr, err := appConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read UDP error: %v", err)
			continue
		}

		// NAT: Client -> VirtualPort
		// We use cAddr.Port as the unique identifier for the local client app
		vPort := nat.GetOrCreateVirtualPort(cAddr.IP, cAddr.Port)

		// Construct Packet
		udpHeader.SrcPort = layers.UDPPort(vPort)
		// IP header src/dst are constant for tunnel link
		ipHeader.SrcIP = srcIP // Might need refreshing if dynamic, but usually constant
		ipHeader.DstIP = serverIP

		udpHeader.SetNetworkLayerForChecksum(ipHeader)

		gopacket.SerializeLayers(serializeBuf, opts, ipHeader, udpHeader, gopacket.Payload(buf[:n]))

		// Send
		dstAddr := &syscall.SockaddrInet4{}
		copy(dstAddr.Addr[:], serverIP.To4())
		// Send the packet buffer
		err = syscall.Sendto(rawFd, serializeBuf.Bytes(), 0, dstAddr)
		if err != nil {
			log.Printf("Sendto error: %v", err)
		}
	}
}

// --- Server Logic ---

func startServer(proto uint8) {
	rawFd := createRawSocket(proto)
	defer syscall.Close(rawFd)

	sessions := sync.Map{}

	// Reusable Parsing Objects
	var (
		ipLayer  layers.IPv4
		udpLayer layers.UDP
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ipLayer, &udpLayer)
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// Buffer for reading raw packets
	buf := make([]byte, 1500)

	for {
		n, _, err := syscall.Recvfrom(rawFd, buf, 0)
		if err != nil {
			continue
		}

		// Zero-alloc parse
		err = parser.DecodeLayers(buf[:n], &decodedLayers)

		hasIP := false
		hasUDP := false
		for _, typ := range decodedLayers {
			if typ == layers.LayerTypeIPv4 {
				hasIP = true
			} else if typ == layers.LayerTypeUDP {
				hasUDP = true
			}
		}

		if !hasIP || !hasUDP {
			continue
		}

		// Identify Session Key (ClientRealIP + VirtualSrcPort)
		clientKey := fmt.Sprintf("%s:%d", ipLayer.SrcIP.String(), udpLayer.SrcPort)

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

			sessions.Store(clientKey, conn)
			log.Printf("New Session: %s -> Target", clientKey)

			// Helper to handle replies
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, serverIP net.IP) {
				defer c.Close()
				defer sessions.Delete(clientKey)
				rBuf := make([]byte, 1500)

				// Serialize reuse variables
				sBuf := gopacket.NewSerializeBuffer()
				sOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

				// Reply Headers
				rIpHeader := &layers.IPv4{
					Version:  4,
					IHL:      5,
					TTL:      64,
					Protocol: layers.IPProtocol(proto),
					SrcIP:    serverIP,
					DstIP:    clientIP,
				}
				rUdpHeader := &layers.UDP{
					DstPort: layers.UDPPort(clientPort),
				}

				for {
					c.SetReadDeadline(time.Now().Add(30 * time.Second))
					rn, _, rerr := c.ReadFromUDP(rBuf)
					if rerr != nil {
						return
					}

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

					gopacket.SerializeLayers(sBuf, sOpts, rIpHeader, rUdpHeader, gopacket.Payload(rBuf[:rn]))

					dstAddr := &syscall.SockaddrInet4{}
					copy(dstAddr.Addr[:], clientIP.To4())
					syscall.Sendto(rawFd, sBuf.Bytes(), 0, dstAddr)
				}
			}(conn, ipLayer.SrcIP, uint16(udpLayer.SrcPort), ipLayer.DstIP)
		}

		conn.Write(udpLayer.Payload)
	}
}

// --- Shared Helpers ---

func createRawSocket(proto uint8) int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		log.Fatalf("Socket creation failed (ROOT REQUIRED): %v", err)
	}
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		log.Fatalf("SetsockoptInt failed: %v", err)
	}
	return fd
}
