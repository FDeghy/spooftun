//go:build linux

package main

import (
	"flag"
	"fmt"
	"log"
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
// by dialing a dummy connection (does not actually send data).
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

type sess struct {
	ip       net.IP
	lastSeen time.Time
}

func startClient(localAddr, serverIPStr string, dstPort uint16, proto uint8) {
	// 1. Setup Raw Socket (For sending/receiving Tunnel Traffic)
	rawFd := createRawSocket(proto)
	defer syscall.Close(rawFd)

	// 2. Setup Local UDP Listener (For Application Traffic)
	udpAddr, _ := net.ResolveUDPAddr("udp", localAddr)
	appConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer appConn.Close()

	// 3. Determine Source IP
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

	// Session Map: "DstPort" -> "ClientIP:DstPort"
	sessions := sync.Map{}

	// Goroutine: Downlink (Tunnel -> App)
	// Reads Raw Packets from Server, strips headers, writes to App
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := syscall.Recvfrom(rawFd, buf, 0)
			if err != nil {
				log.Printf("error syscall.Recvfrom: %w", err)
				continue
			}

			// Parse Outer IP (Proto 200)
			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer == nil {
				log.Printf("Downlink (Tunnel -> App): ipLayer == nil")
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)

			// Validate it came from our Server
			if !ip.SrcIP.Equal(serverIP) {
				log.Printf("ip.SrcIP != serverIP)")
				continue
			}

			// Parse Inner UDP
			udpPacket := gopacket.NewPacket(ip.Payload, layers.LayerTypeUDP, gopacket.Default)
			udpLayer := udpPacket.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				log.Printf("Downlink (Tunnel -> App): udpLayer == nil")
				continue
			}
			udp, _ := udpLayer.(*layers.UDP)

			// Forward payload back to the specific App Instance (Localhost:SrcPort)
			// We use the Inner UDP DstPort because that matches the App's original SrcPort
			//log.Printf("udp.DstPort: %v", udp.DstPort)
			s, ok := sessions.Load(int(udp.DstPort))
			session, ok2 := s.(*sess)
			if !ok || !ok2 {
				continue
			}
			if time.Since(session.lastSeen) > 1*time.Minute {
				sessions.Delete(udp.DstPort)
				continue
			}
			clientAppAddr := &net.UDPAddr{IP: session.ip, Port: int(udp.DstPort)}
			//log.Printf("session.ip2: %v", session.ip)
			appConn.WriteToUDP(udp.Payload, clientAppAddr)
		}
	}()

	// Main Loop: Uplink (App -> Tunnel)
	// Reads UDP from App, Wraps in Proto 200, Sends Raw to Server
	buf := make([]byte, 1500)
	for {
		n, cAddr, err := appConn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Read UDP error: %v", err)
			continue
		}

		// Save ClientIP in the sessions
		sessions.Store(cAddr.Port, &sess{ip: cAddr.IP, lastSeen: time.Now()})

		// Construct Packet: [IPv4] [UDP] [Payload]
		// Inner UDP SrcPort is the App's actual port (so Server knows how to reply)
		payload := buf[:n]
		sendRawPacket(rawFd, serverIP, srcIP, uint16(cAddr.Port), dstPort, proto, payload)
	}
}

// --- Server Logic ---

func startServer(proto uint8) {
	// 1. Setup Raw Socket
	rawFd := createRawSocket(proto)
	defer syscall.Close(rawFd)

	// Session Map: "ClientIP:ClientPort" -> UDP Connection to Target
	sessions := sync.Map{}

	buf := make([]byte, 1500)
	for {
		// Read Raw Packet from Client
		n, _, err := syscall.Recvfrom(rawFd, buf, 0)
		if err != nil {
			continue
		}

		// Parse Outer IP
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		// Parse Inner UDP
		udpPacket := gopacket.NewPacket(ip.Payload, layers.LayerTypeUDP, gopacket.Default)
		udpLayer := udpPacket.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)

		// Identify Session Key (ClientRealIP + InnerSrcPort)
		clientKey := fmt.Sprintf("%s:%d", ip.SrcIP.String(), udp.SrcPort)

		// Check if we already have a connection for this client flow
		var conn *net.UDPConn
		val, ok := sessions.Load(clientKey)

		if ok {
			conn = val.(*net.UDPConn)
		} else {
			// NEW SESSION: Create a new UDP socket to talk to the Target
			targetAddr := fmt.Sprintf("127.0.0.1:%d", udp.DstPort) // Forward to local target
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

			// Goroutine: Handle Replies (Target -> Server -> Tunnel -> Client)
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, serverIP net.IP) {
				defer c.Close()
				defer sessions.Delete(clientKey)
				rBuf := make([]byte, 1500)

				// Set a timeout to clean up idle sessions
				for {
					c.SetReadDeadline(time.Now().Add(30 * time.Second))
					rn, _, rerr := c.ReadFromUDP(rBuf)
					if rerr != nil {
						return // Close on error/timeout
					}

					// Encapsulate Reply: [IPv4 (Dst=ClientIP)] [UDP (Dst=ClientPort)] [Payload]
					// Note: We swap ports for the reply (Src=Target, Dst=Client)
					sendRawPacket(rawFd, clientIP, serverIP, uint16(udp.DstPort), clientPort, proto, rBuf[:rn])
				}
			}(conn, ip.SrcIP, uint16(udp.SrcPort), ip.DstIP)
		}

		// Forward the actual payload to the target
		conn.Write(udp.Payload)
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

func sendRawPacket(fd int, dstIP, srcIP net.IP, srcPort, dstPort uint16, proto uint8, payload []byte) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocol(proto),
		SrcIP:    srcIP, // In a real tunnel, this should be the interface IP
		DstIP:    dstIP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload(payload))

	dstAddr := &syscall.SockaddrInet4{}
	copy(dstAddr.Addr[:], dstIP.To4())
	syscall.Sendto(fd, buf.Bytes(), 0, dstAddr)
}
