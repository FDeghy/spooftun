//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
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
	ipv4RawConn := getRawConn(rawFd)
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
	appConn.SetReadBuffer((1 << 20) * 7)
	appConn.SetWriteBuffer((1 << 20) * 7)

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
					log.Printf("Read UDP error: %v", err)
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

			clientAppAddr := &net.UDPAddr{IP: sess.clientIP, Port: sess.clientPort}
			appConn.WriteToUDP(udpLayer.Payload, clientAppAddr)
		}
	}()

	// Main Loop: Uplink (App -> Tunnel)
	// Reads UDP from App, Translate ClientPort -> VirtualPort, Wraps in Proto 200, Sends Raw
	ipv4AppConn := ipv4.NewPacketConn(appConn)
	msgs := prepareMsgs()

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
		// IP header src/dst are constant for tunnel link
		ipHeader.SrcIP = srcIP // Might need refreshing if dynamic, but usually constant
		ipHeader.DstIP = serverIP

		udpHeader.SetNetworkLayerForChecksum(ipHeader)

		gopacket.SerializeLayers(serializeBuf, opts, ipHeader, udpHeader, gopacket.Payload(data))

		// Send the packet buffer
		_, err = ipv4RawConn.WriteToIP(serializeBuf.Bytes(), &net.IPAddr{IP: serverIP})
		if err != nil {
			log.Printf("Sendto error: %v", err)
		}
	}
}

// --- Server Logic ---

func startServer(proto uint8) {
	rawFd := createRawSocket(proto)
	ipv4RawConn := getRawConn(rawFd)
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

	msgs := prepareMsgs()

	var err error
	n := 0
	readPos := 0
	for {
		if readPos >= n {
			n, err = ipv4RawConn.ReadBatch(msgs, 0)
			if n == 0 || err != nil {
				log.Printf("Read UDP error: %v", err)
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

			var errDFIPv4 error
			appRaw, _ := conn.SyscallConn()
			appRaw.Control(func(fd uintptr) {
				errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_PROBE)
			})
			if errDFIPv4 != nil {
				log.Printf("failed to set IP_MTU_DISCOVER: %v", errDFIPv4)
			}
			conn.SetReadBuffer((1 << 20) * 7)
			conn.SetWriteBuffer((1 << 20) * 7)

			sessions.Store(clientKey, conn)
			log.Printf("New Session: %s -> Target", clientKey)

			// Helper to handle replies
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, serverIP net.IP) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgs()
				defer c.Close()
				defer sessions.Delete(clientKey)

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

					ipv4RawConn.WriteToIP(sBuf.Bytes(), &net.IPAddr{IP: clientIP})
				}
			}(conn, ipLayer.SrcIP, uint16(udpLayer.SrcPort), srcIP)
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
	err = syscall.SetNonblock(fd, true)
	if err != nil {
		log.Fatalf("SetNonblock failed: %v", err)
	}
	return fd
}

func getRawConn(fd int) *ipv4.RawConn {
	f := os.NewFile(uintptr(fd), "")
	conn, err := net.FilePacketConn(f)
	if err != nil {
		log.Fatalf("FilePacketConn failed: %v", err)
	}
	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		log.Fatalf("NewRawConn failed: %v", err)
	}
	return rawConn
}

func prepareMsgs() []ipv4.Message {
	msgs := make([]ipv4.Message, 8)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		msgs[i].Buffers[0] = make([]byte, 1500)
	}
	return msgs
}
