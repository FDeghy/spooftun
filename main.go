//go:build linux

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// High-throughput tuning constants for AF_PACKET
const (
	// AF_PACKET ring buffer configuration (TPACKET_V3)
	afBlockSize    = 1 << 20               // 1MB blocks
	afNumBlocks    = 64                    // 64 blocks = 64MB ring buffer
	afFrameSize    = 2048                  // Frame size for each packet slot
	afBlockTimeout = 64 * time.Millisecond // Block retire timeout. Low value needed for low latency.

	batchSize      = 64                     // Messages per batch read/write (for UDP side)
	socketBufSize  = 1 << 24                // 16MB socket buffer
	packetBufSize  = 1500                   // MTU size
	udpPayloadSize = packetBufSize - 20 - 8 // 1472 bytes: fits after IP+UDP headers

	// GSO/GRO constants
	sizeOfGSOData          = 2     // uint16 size for UDP_SEGMENT value
	udpSegmentMaxDatagrams = 64    // kernel hard limit
	maxUDPGSOPayload       = 65535 // max payload size for a single GSO sendmsg
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
	ifaceName  = flag.String("iface", "", "Network interface to use for AF_PACKET (auto-detect if empty)")
)

// --- GSO/GRO Helpers ---

// gsoControlSize is the cmsg space needed for UDP_SEGMENT
var gsoControlSize = unix.CmsgSpace(sizeOfGSOData)

// supportsUDPOffload probes the socket for GSO (UDP_SEGMENT) and GRO (UDP_GRO) support
func supportsUDPOffload(conn *net.UDPConn) (txOffload, rxOffload bool) {
	rc, err := conn.SyscallConn()
	if err != nil {
		return
	}
	err = rc.Control(func(fd uintptr) {
		_, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_SEGMENT)
		txOffload = errSyscall == nil
		opt, errSyscall := unix.GetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO)
		rxOffload = errSyscall == nil && opt == 1
	})
	if err != nil {
		return false, false
	}
	return txOffload, rxOffload
}

// enableUDPGRO enables UDP_GRO on the socket
func enableUDPGRO(conn *net.UDPConn) error {
	rc, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sysErr error
	err = rc.Control(func(fd uintptr) {
		sysErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
	})
	if err != nil {
		return err
	}
	return sysErr
}

// getGSOSize parses control message for UDP_GRO and returns the GSO segment size
func getGSOSize(control []byte) (int, error) {
	var (
		hdr  unix.Cmsghdr
		data []byte
		rem  = control
		err  error
	)
	for len(rem) > unix.SizeofCmsghdr {
		hdr, data, rem, err = unix.ParseOneSocketControlMessage(rem)
		if err != nil {
			return 0, fmt.Errorf("error parsing socket control message: %w", err)
		}
		if hdr.Level == unix.SOL_UDP && hdr.Type == unix.UDP_GRO && len(data) >= sizeOfGSOData {
			var gso uint16
			copy(unsafe.Slice((*byte)(unsafe.Pointer(&gso)), sizeOfGSOData), data[:sizeOfGSOData])
			return int(gso), nil
		}
	}
	return 0, nil
}

// setGSOSize sets a UDP_SEGMENT in control based on gsoSize
func setGSOSize(control *[]byte, gsoSize uint16) {
	existingLen := len(*control)
	avail := cap(*control) - existingLen
	space := unix.CmsgSpace(sizeOfGSOData)
	if avail < space {
		return
	}
	*control = (*control)[:cap(*control)]
	gsoControl := (*control)[existingLen:]
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&(gsoControl)[0]))
	hdr.Level = unix.SOL_UDP
	hdr.Type = unix.UDP_SEGMENT
	hdr.SetLen(unix.CmsgLen(sizeOfGSOData))
	copy((gsoControl)[unix.CmsgLen(0):], unsafe.Slice((*byte)(unsafe.Pointer(&gsoSize)), sizeOfGSOData))
	*control = (*control)[:existingLen+space]
}

// errShouldDisableUDPGSO checks if GSO should be disabled due to EIO (missing tx checksum offload)
func errShouldDisableUDPGSO(err error) bool {
	var serr *os.SyscallError
	if errors.As(err, &serr) {
		return serr.Err == unix.EIO
	}
	return false
}

// splitCoalescedMessages splits GRO-coalesced messages into individual datagrams
func splitCoalescedMessages(msgs []ipv4.Message, firstMsgAt int) (int, error) {
	n := 0
	for i := firstMsgAt; i < len(msgs); i++ {
		msg := &msgs[i]
		if msg.N == 0 {
			return n, nil
		}
		var (
			gsoSize    int
			start      int
			end        = msg.N
			numToSplit = 1
		)
		var err error
		gsoSize, err = getGSOSize(msg.OOB[:msg.NN])
		if err != nil {
			return n, err
		}
		if gsoSize > 0 {
			numToSplit = (msg.N + gsoSize - 1) / gsoSize
			end = gsoSize
		}
		for j := 0; j < numToSplit; j++ {
			if n > i {
				return n, errors.New("splitting coalesced packet resulted in overflow")
			}
			copied := copy(msgs[n].Buffers[0], msg.Buffers[0][start:end])
			msgs[n].N = copied
			msgs[n].Addr = msg.Addr
			start = end
			end += gsoSize
			if end > msg.N {
				end = msg.N
			}
			n++
		}
		if i != n-1 {
			msg.N = 0
		}
	}
	return n, nil
}

// resetOOB resets OOB slices to full capacity before ReadBatch so the kernel
// can write GRO control messages into them. Without this, GRO silently fails
// after the first batch because msg.NN truncates the OOB length.
func resetOOB(msgs []ipv4.Message) {
	for i := range msgs {
		if msgs[i].OOB != nil {
			msgs[i].OOB = msgs[i].OOB[:cap(msgs[i].OOB)]
		}
	}
}

// --- Ethernet/ARP Helpers ---

// getInterfaceInfo returns the MAC address and IP of the specified interface
func getInterfaceInfo(name string) (mac net.HardwareAddr, ip net.IP, err error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, nil, fmt.Errorf("interface %s not found: %v", name, err)
	}
	mac = iface.HardwareAddr
	if mac == nil {
		return nil, nil, fmt.Errorf("interface %s has no MAC address", name)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get addresses for %s: %v", name, err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipv4 := ipNet.IP.To4(); ipv4 != nil {
				ip = ipv4
				break
			}
		}
	}

	if ip == nil {
		return nil, nil, fmt.Errorf("interface %s has no IPv4 address", name)
	}

	return mac, ip, nil
}

// findDefaultInterface finds the interface used for routing to the given destination
func findDefaultInterface(dstIP net.IP) (string, error) {
	if dstIP == nil {
		dstIP = net.ParseIP("8.8.8.8")
	}

	conn, err := net.DialTimeout("udp4", dstIP.String()+":80", time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to determine route: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localAddr.IP) {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not find interface for %s", localAddr.IP)
}

// lookupARPCache reads /proc/net/arp to find MAC for an IP
func lookupARPCache(ip net.IP) net.HardwareAddr {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header line

	ipStr := ip.String()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ipStr {
			mac, err := net.ParseMAC(fields[3])
			if err == nil && fields[2] != "0x0" { // 0x0 means incomplete
				return mac
			}
		}
	}
	return nil
}

// getNeighborMAC gets the MAC address for a destination IP (via ARP cache or probe)
func getNeighborMAC(iface string, dstIP net.IP) (net.HardwareAddr, error) {
	// First check ARP cache
	if mac := lookupARPCache(dstIP); mac != nil {
		return mac, nil
	}

	// Trigger ARP by sending a probe packet
	conn, err := net.DialTimeout("udp4", dstIP.String()+":1", 500*time.Millisecond)
	if err == nil {
		conn.Close()
	}

	// Wait for ARP to populate
	time.Sleep(200 * time.Millisecond)

	if mac := lookupARPCache(dstIP); mac != nil {
		return mac, nil
	}

	// Try default gateway
	return getDefaultGatewayMAC(iface)
}

// getDefaultGatewayMAC finds the default gateway and gets its MAC
func getDefaultGatewayMAC(iface string) (net.HardwareAddr, error) {
	// Read /proc/net/route to find default gateway
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		// Look for default route (Destination = 00000000)
		if fields[1] == "00000000" {
			// Gateway is in hex, little-endian (Linux)
			var gw uint32
			fmt.Sscanf(fields[2], "%x", &gw)

			gwIP := net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24))

			// Now get MAC for gateway
			if mac := lookupARPCache(gwIP); mac != nil {
				return mac, nil
			}

			// Trigger ARP for gateway
			conn, err := net.DialTimeout("udp4", gwIP.String()+":1", 500*time.Millisecond)
			if err == nil {
				conn.Close()
			}
			time.Sleep(200 * time.Millisecond)

			if mac := lookupARPCache(gwIP); mac != nil {
				return mac, nil
			}
		}
	}

	return nil, fmt.Errorf("could not find gateway MAC")
}

// ARPCache caches IP -> MAC mappings discovered via incoming packets
type ARPCache struct {
	cache sync.Map // net.IP string -> net.HardwareAddr
}

func (a *ARPCache) Get(ip net.IP) net.HardwareAddr {
	if v, ok := a.cache.Load(ip.String()); ok {
		return v.(net.HardwareAddr)
	}
	return nil
}

func (a *ARPCache) Set(ip net.IP, mac net.HardwareAddr) {
	a.cache.Store(ip.String(), mac)
}

func main() {
	flag.Parse()

	serverIP := net.ParseIP(*tunnelIP)

	// Auto-detect interface if not specified
	iface := *ifaceName
	if iface == "" {
		var err error
		iface, err = findDefaultInterface(serverIP)
		if err != nil {
			log.Fatalf("Failed to auto-detect interface: %v", err)
		}
		log.Printf("Auto-detected interface: %s", iface)
	}

	if *mode == "client" {
		if serverIP == nil {
			log.Fatal("Remote IP is required for client mode. Use -remote-ip <IP>")
		}
		log.Printf("[Client-AF_PACKET] Forwarding %s -> Tunnel(%s) -> :%d (Proto %d) via %s",
			*listenAddr, *tunnelIP, *targetPort, *protoNum, iface)
		startClientAFPacket(*listenAddr, serverIP, uint16(*targetPort), uint8(*protoNum), iface)
	} else {
		log.Printf("[Server-AF_PACKET] Listening on Proto %d via %s", *protoNum, iface)
		startServerAFPacket(uint8(*protoNum), iface)
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

// --- NAT Types ---

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

// --- AF_PACKET Client ---

func startClientAFPacket(localAddr string, serverIP net.IP, dstPort uint16, proto uint8, iface string) {
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

	// Create AF_PACKET socket with TPACKET_V3 for high-performance mmap'd ring buffer
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(afBlockSize),
		afpacket.OptNumBlocks(afNumBlocks),
		afpacket.OptFrameSize(afFrameSize),
		afpacket.OptBlockTimeout(afBlockTimeout),
	)
	if err != nil {
		log.Fatalf("Failed to create AF_PACKET socket: %v", err)
	}
	defer tpacket.Close()

	// BPF: reject our own outgoing packets + only accept our custom IP protocol
	// This filters in-kernel, before packets ever reach the mmap ring buffer
	filter := createBPFFilter(proto, srcMAC)
	if err := tpacket.SetBPF(filter); err != nil {
		log.Printf("Warning: Failed to set BPF filter: %v", err)
	}

	// Local UDP socket for application traffic
	udpAddr, _ := net.ResolveUDPAddr("udp4", localAddr)
	appConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Fatalf("Failed to listen on UDP: %v", err)
	}
	defer appConn.Close()

	appConn.SetReadBuffer(socketBufSize)
	appConn.SetWriteBuffer(socketBufSize)

	// Probe for GSO/GRO support on the app-facing UDP socket
	txOffload, rxOffload := supportsUDPOffload(appConn)
	if rxOffload {
		if err := enableUDPGRO(appConn); err != nil {
			log.Printf("Warning: Failed to enable UDP_GRO: %v", err)
			rxOffload = false
		} else {
			log.Printf("UDP GRO enabled on app socket")
		}
	}
	if txOffload {
		log.Printf("UDP GSO available on app socket")
	}

	nat := &NatTable{}
	go nat.Cleanup()

	// Reusable layer parsers for Downlink
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	var udpLayer layers.UDP

	// Parser for full Ethernet frames
	ethParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer)
	ethParser.IgnoreUnsupported = true
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// Custom protocol layer parser (since gopacket won't auto-chain to UDP for unknown protocols)
	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udpLayer)
	udpParser.IgnoreUnsupported = true

	// Downlink (AF_PACKET -> App)
	// Reads raw Ethernet frames, strips headers, translates VirtualPort -> ClientPort
	// Uses GSO to batch multiple payloads into one sendmsg call when possible
	go func() {
		// GSO write batching state for downlink
		var gsoTxEnabled atomic.Bool
		gsoTxEnabled.Store(txOffload)

		// Accumulation buffer for GSO writes
		gsoBuf := make([]byte, 0, maxUDPGSOPayload)
		var gsoSegSize int
		var gsoDgramCnt int

		// Pre-allocated OOB buffer for GSO control messages (reused across flushes)
		gsoOOB := make([]byte, 0, gsoControlSize)

		// Reusable UDPAddr to avoid per-packet heap allocation
		writeAddr := &net.UDPAddr{IP: make(net.IP, 4)}
		// Track current GSO batch destination as natKey for fast comparison (no IP.Equal)
		var gsoDstKey natKey

		flushGSO := func() {
			if gsoDgramCnt == 0 {
				return
			}
			if gsoDgramCnt == 1 || !gsoTxEnabled.Load() {
				// Single datagram or GSO disabled: just write normally
				appConn.WriteToUDP(gsoBuf, writeAddr)
			} else {
				// Build OOB with UDP_SEGMENT (reuse pre-allocated buffer)
				gsoOOB = gsoOOB[:0]
				setGSOSize(&gsoOOB, uint16(gsoSegSize))
				appConn.WriteMsgUDP(gsoBuf, gsoOOB, writeAddr)
			}
			gsoBuf = gsoBuf[:0]
			gsoDgramCnt = 0
			gsoSegSize = 0
		}

		for {
			// Zero-copy read from AF_PACKET mmap'd ring buffer
			data, _, err := tpacket.ZeroCopyReadPacketData()
			if err != nil {
				flushGSO()
				continue
			}

			// Parse Ethernet + IPv4 header
			err = ethParser.DecodeLayers(data, &decodedLayers)
			if len(decodedLayers) < 2 {
				continue
			}

			// Userspace protocol filter (defense-in-depth: BPF may fail to attach)
			if ipLayer.Protocol != layers.IPProtocol(proto) {
				continue
			}

			// Parse UDP from IPv4 payload (custom proto won't auto-chain)
			udpParser.DecodeLayers(ipLayer.Payload, &decodedLayers)
			if len(decodedLayers) == 0 || decodedLayers[0] != layers.LayerTypeUDP {
				continue
			}

			// Reverse NAT: VirtualPort (udp.DstPort) -> Client Session
			sess := nat.GetSession(uint16(udpLayer.DstPort))
			if sess == nil {
				continue
			}

			payload := udpLayer.Payload

			// Build natKey for destination (6-byte value compare, no alloc)
			dstKey := makeNatKey(sess.clientIP, sess.clientPort)

			// Try to coalesce into GSO batch
			if gsoTxEnabled.Load() && len(payload) > 0 {
				canCoalesce := gsoDgramCnt > 0 &&
					gsoDstKey == dstKey &&
					len(payload) == gsoSegSize &&
					gsoDgramCnt < udpSegmentMaxDatagrams &&
					len(gsoBuf)+len(payload) <= maxUDPGSOPayload

				if canCoalesce {
					gsoBuf = append(gsoBuf, payload...)
					gsoDgramCnt++
					continue
				}
				// Flush previous batch if any
				flushGSO()
				// Start new batch — update the reusable writeAddr
				copy(writeAddr.IP, sess.clientIP.To4())
				writeAddr.Port = sess.clientPort
				gsoDstKey = dstKey
				gsoBuf = append(gsoBuf, payload...)
				gsoSegSize = len(payload)
				gsoDgramCnt = 1
			} else {
				flushGSO()
				copy(writeAddr.IP, sess.clientIP.To4())
				writeAddr.Port = sess.clientPort
				appConn.WriteToUDP(payload, writeAddr)
			}
		}
	}()

	// Uplink (App -> AF_PACKET)
	// Reads UDP from App, translates ClientPort -> VirtualPort, wraps in Ethernet + IP + Proto, sends raw
	// Uses GRO to receive coalesced datagrams from the kernel
	ipv4AppConn := ipv4.NewPacketConn(appConn)
	msgs := prepareMsgsUDP(rxOffload)

	// Reusable serialize buffer
	serializeBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Pre-build headers (will modify SrcPort for each packet)
	ethHeader := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
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

	n := 0
	readPos := 0
	for {
		if readPos >= n {
			if rxOffload {
				// With GRO: read into fewer slots, then split coalesced messages
				readAt := len(msgs) - (batchSize / udpSegmentMaxDatagrams)
				if readAt < 0 {
					readAt = 0
				}
				resetOOB(msgs[readAt:])
				n, err = ipv4AppConn.ReadBatch(msgs[readAt:], 0)
				if n == 0 || err != nil {
					log.Printf("Read UDP error: %v", err)
					continue
				}
				n, err = splitCoalescedMessages(msgs, readAt)
				if err != nil {
					log.Printf("GRO split error: %v", err)
					continue
				}
			} else {
				n, err = ipv4AppConn.ReadBatch(msgs, 0)
				if n == 0 || err != nil {
					log.Printf("Read UDP error: %v", err)
					continue
				}
			}
			readPos = 0
		}
		msg := msgs[readPos]
		readPos++
		data := msg.Buffers[0][:msg.N]
		cAddr := msg.Addr.(*net.UDPAddr)

		// NAT: Client -> VirtualPort
		vPort := nat.GetOrCreateVirtualPort(cAddr.IP, cAddr.Port)

		// Build packet with Ethernet header
		udpHeader.SrcPort = layers.UDPPort(vPort)
		udpHeader.SetNetworkLayerForChecksum(ipHeader)

		if err := gopacket.SerializeLayers(serializeBuf, opts, ethHeader, ipHeader, udpHeader, gopacket.Payload(data)); err != nil {
			log.Printf("Serialize error: %v", err)
			continue
		}

		// Send via AF_PACKET (bypasses kernel IP stack)
		if err := tpacket.WritePacketData(serializeBuf.Bytes()); err != nil {
			log.Printf("AF_PACKET write error: %v", err)
		}
	}
}

// --- AF_PACKET Server ---

func startServerAFPacket(proto uint8, iface string) {
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

	// Create AF_PACKET socket with TPACKET_V3
	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(iface),
		afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		afpacket.OptBlockSize(afBlockSize),
		afpacket.OptNumBlocks(afNumBlocks),
		afpacket.OptFrameSize(afFrameSize),
		afpacket.OptBlockTimeout(afBlockTimeout),
	)
	if err != nil {
		log.Fatalf("Failed to create AF_PACKET socket: %v", err)
	}
	defer tpacket.Close()

	// BPF: reject our own outgoing packets + only accept our custom IP protocol
	filter := createBPFFilter(proto, srcMAC)
	if err := tpacket.SetBPF(filter); err != nil {
		log.Printf("Warning: Failed to set BPF filter: %v", err)
	}

	sessions := sync.Map{}
	arpCache := &ARPCache{}

	autoDst := false
	if *tunnelIP == "" {
		autoDst = true
		log.Printf("Auto-detecting Remote IP from incoming packets for each session")
	}

	// Parsers
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	var udpLayer layers.UDP
	ethParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer, &udpLayer)
	ethParser.IgnoreUnsupported = true
	udpParser := gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udpLayer)
	udpParser.IgnoreUnsupported = true
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	for {
		// Zero-copy read from ring buffer
		data, _, err := tpacket.ZeroCopyReadPacketData()
		if err != nil {
			// Timeout is expected when no packets arrive — silently retry
			continue
		}

		// Parse Ethernet + IPv4
		err = ethParser.DecodeLayers(data, &decodedLayers)
		if len(decodedLayers) < 2 {
			continue
		}

		// Userspace protocol filter (defense-in-depth: BPF may fail to attach)
		if ipLayer.Protocol != layers.IPProtocol(proto) {
			continue
		}

		// Cache the source MAC for this IP (for replies)
		arpCache.Set(ipLayer.SrcIP, ethLayer.SrcMAC)

		// Parse UDP from IPv4 payload
		err = udpParser.DecodeLayers(ipLayer.Payload, &decodedLayers)
		if len(decodedLayers) == 0 || decodedLayers[0] != layers.LayerTypeUDP {
			continue
		}

		// Session key: ClientRealIP + VirtualSrcPort
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

			conn.SetReadBuffer(socketBufSize)
			conn.SetWriteBuffer(socketBufSize)

			// Probe for GSO/GRO support on this session socket
			sessTxOffload, sessRxOffload := supportsUDPOffload(conn)
			if sessRxOffload {
				if err := enableUDPGRO(conn); err != nil {
					log.Printf("Warning: Failed to enable UDP_GRO on session socket: %v", err)
					sessRxOffload = false
				}
			}

			sessions.Store(clientKey, conn)
			log.Printf("New Session: %s -> Target :%d (GSO=%v GRO=%v)", clientKey.String(), udpLayer.DstPort, sessTxOffload, sessRxOffload)

			// Reply handler goroutine
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, clientMAC net.HardwareAddr,
				srcServerIP net.IP, targetRAddr *net.UDPAddr, sessionKey natKey,
				txOff, rxOff bool) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgsUDP(rxOff)
				defer c.Close()
				defer sessions.Delete(sessionKey)

				// Create a separate TPacket for replies (thread safety)
				replyTPacket, err := afpacket.NewTPacket(
					afpacket.OptInterface(iface),
					afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
					afpacket.OptBlockSize(1<<18), // 256KB blocks for TX
					afpacket.OptNumBlocks(16),
					afpacket.OptFrameSize(afFrameSize),
				)
				if err != nil {
					log.Printf("Failed to create reply TPacket: %v", err)
					return
				}
				defer replyTPacket.Close()

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

				var errRead error
				n := 0
				readPos := 0
				for {
					ipv4AppConn.SetReadDeadline(time.Now().Add(30 * time.Second))
					if readPos >= n {
						if rxOff {
							// With GRO: read into fewer slots, then split
							readAt := len(msgs) - (batchSize / udpSegmentMaxDatagrams)
							if readAt < 0 {
								readAt = 0
							}
							resetOOB(msgs[readAt:])
							n, errRead = ipv4AppConn.ReadBatch(msgs[readAt:], 0)
							if n == 0 || errRead != nil {
								log.Printf("Session %s ended: %v", sessionKey.String(), errRead)
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
								log.Printf("Session %s ended: %v", sessionKey.String(), errRead)
								return
							}
						}
						readPos = 0
					}
					msg := msgs[readPos]
					readPos++
					payload := msg.Buffers[0][:msg.N]

					rUdpHeader.SrcPort = layers.UDPPort(targetRAddr.Port)
					rUdpHeader.SetNetworkLayerForChecksum(rIpHeader)

					if err := gopacket.SerializeLayers(sBuf, sOpts, rEthHeader, rIpHeader, rUdpHeader, gopacket.Payload(payload)); err != nil {
						log.Printf("Serialize error: %v", err)
						continue
					}

					replyTPacket.WritePacketData(sBuf.Bytes())
				}
			}(conn, ipLayer.SrcIP, uint16(udpLayer.SrcPort), ethLayer.SrcMAC, srcIP, rAddr, clientKey,
				sessTxOffload, sessRxOffload)
		}

		conn.Write(udpLayer.Payload)
	}
}

// --- BPF Filter ---

// createBPFFilter builds a kernel-level BPF program that:
//  1. Rejects packets where src MAC == our own MAC (outgoing loopback)
//  2. Accepts only IPv4 (EtherType 0x0800)
//  3. Accepts only our custom IP protocol number
//
// All filtering happens in-kernel before packets reach the mmap ring buffer,
// eliminating unnecessary copies and userspace processing.
func createBPFFilter(proto uint8, srcMAC net.HardwareAddr) []bpf.RawInstruction {
	// Split 6-byte MAC into a 4-byte and 2-byte comparison
	macHi := uint32(srcMAC[0])<<24 | uint32(srcMAC[1])<<16 | uint32(srcMAC[2])<<8 | uint32(srcMAC[3])
	macLo := uint32(srcMAC[4])<<8 | uint32(srcMAC[5])

	return []bpf.RawInstruction{
		// --- Check 1: Reject our own outgoing packets (src MAC filter) ---
		//  0: ld [6]            Load src MAC bytes 0-3
		{Op: 0x20, Jt: 0, Jf: 0, K: 6},
		//  1: jeq macHi          Match? -> check rest (2). No match? -> protocol check (4)
		{Op: 0x15, Jt: 0, Jf: 2, K: macHi},
		//  2: ldh [10]           Load src MAC bytes 4-5
		{Op: 0x28, Jt: 0, Jf: 0, K: 10},
		//  3: jeq macLo          Full MAC match? -> reject (9). No? -> protocol check (4)
		{Op: 0x15, Jt: 5, Jf: 0, K: macLo},

		// --- Check 2: EtherType must be IPv4 ---
		//  4: ldh [12]           Load EtherType
		{Op: 0x28, Jt: 0, Jf: 0, K: 12},
		//  5: jeq 0x0800         IPv4? -> check proto (6). Else -> reject (9)
		{Op: 0x15, Jt: 0, Jf: 3, K: 0x0800},

		// --- Check 3: IP protocol must match ---
		//  6: ldb [23]           Load IP protocol (eth:14 + ip:9 = offset 23)
		{Op: 0x30, Jt: 0, Jf: 0, K: 23},
		//  7: jeq proto          Match? -> accept (8). Else -> reject (9)
		{Op: 0x15, Jt: 0, Jf: 1, K: uint32(proto)},

		// --- Verdicts ---
		//  8: ret #262144        ACCEPT
		{Op: 0x06, Jt: 0, Jf: 0, K: 262144},
		//  9: ret #0             REJECT
		{Op: 0x06, Jt: 0, Jf: 0, K: 0},
	}
}

// --- Shared Helpers ---

// prepareMsgsUDP creates message buffers for UDP batch reads
// When groEnabled is true, OOB buffers are allocated for control message parsing (UDP_GRO)
// and a larger data buffer is used to accommodate GRO-coalesced payloads
func prepareMsgsUDP(groEnabled bool) []ipv4.Message {
	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		msgs[i].Buffers = make([][]byte, 1)
		if groEnabled {
			// GRO can coalesce up to udpSegmentMaxDatagrams into one buffer
			msgs[i].Buffers[0] = make([]byte, udpPayloadSize*udpSegmentMaxDatagrams)
			msgs[i].OOB = make([]byte, gsoControlSize)
		} else {
			msgs[i].Buffers[0] = make([]byte, udpPayloadSize)
		}
	}
	return msgs
}
