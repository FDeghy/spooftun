//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// High-throughput tuning constants for AF_PACKET
const (
	batchSize      = 64                         // Messages per batch read/write (for UDP side)
	socketBufSize  = 1 << 24                    // 16MB socket buffer
	packetBufSize  = 1500                       // MTU size
	udpPayloadSize = packetBufSize - 20 - 8 - 8 // 1472 bytes: fits after IP+UDP headers + padding

	// GSO/GRO constants
	sizeOfGSOData          = 2     // uint16 size for UDP_SEGMENT value
	udpSegmentMaxDatagrams = 64    // kernel hard limit
	maxUDPGSOPayload       = 65535 // max payload size for a single GSO sendmsg
)

var (
	// will be changed at runtime
	// AF_PACKET ring buffer configuration (TPACKET_V3)
	afBlockSize    = 1 << 20               // 1MB blocks
	afNumBlocks    = 64                    // 64 blocks = 64MB ring buffer
	afFrameSize    = 2048                  // Frame size for each packet slot
	afBlockTimeout = 64 * time.Millisecond // Block retire timeout. Low value needed for low latency.
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
	mode        = flag.String("mode", "client", "Mode: 'client' or 'server'")
	customSrc   = flag.String("src-ip", "", "Force a specific Source IP (Spoofing). Leave empty to auto-detect.")
	listenAddr  = flag.String("listen", "127.0.0.1:1001", "Client: Local UDP port to bind. Server: Not used")
	tunnelIP    = flag.String("remote-ip", "", "IP of the remote tunnel endpoint")
	targetPort  = flag.Int("target-port", 8080, "Client: Port to forward traffic to on the Server side")
	protoNum    = flag.Int("proto", 200, "Custom IP Protocol Number (0-255). Default for both directions.")
	uplinkProto = flag.Int("uplink-proto", -1, "IP protocol for client→server packets. Overrides -proto for that direction; -1 means inherit -proto.")
	downProto   = flag.Int("downlink-proto", -1, "IP protocol for server→client packets. Overrides -proto for that direction; -1 means inherit -proto.")
	ifaceName   = flag.String("iface", "", "Network interface to use for AF_PACKET (auto-detect if empty)")
	fakeFrag    = flag.Bool("fake-frag", false, "Use fake frag only for *client uplink, must be enabled in *server to receiving fake frag packets")
	filterDstIP = flag.String("filter-dst-ip", "", "Destination IP for BPF capture filter (TCP/UDP proto). Use when -src-ip is spoofed and the on-wire dst IP differs. Defaults to -src-ip.")
	fakeTCP     = flag.Bool("fake-tcp", false, "Use a TCP-shaped header instead of UDP for tunnel framing. Must match on both ends.")
	tcpFlags    = flag.String("tcp-flags", "0x18", "TCP flag byte (hex or decimal) used with -fake-tcp. Examples: 0x18=PSH+ACK, 0x10=ACK, 0x02=SYN.")
)

// tcpFlagByte is parsed from -tcp-flags at startup.
var tcpFlagByte uint8

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

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

func main() {
	flag.Parse()

	if *fakeTCP {
		v, err := strconv.ParseUint(*tcpFlags, 0, 8)
		if err != nil {
			log.Fatalf("Invalid -tcp-flags %q: %v", *tcpFlags, err)
		}
		tcpFlagByte = uint8(v)
	}

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

	// Calculate AF_PACKET buffer size
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(8, 65535, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}
	afFrameSize = szFrame
	afBlockSize = szBlock
	afNumBlocks = numBlocks

	upProto := uint8(*protoNum)
	if *uplinkProto >= 0 {
		upProto = uint8(*uplinkProto)
	}
	dnProto := uint8(*protoNum)
	if *downProto >= 0 {
		dnProto = uint8(*downProto)
	}

	if *mode == "client" {
		if serverIP == nil {
			log.Fatal("Remote IP is required for client mode. Use -remote-ip <IP>")
		}
		log.Printf("[Client-AF_PACKET] Forwarding %s -> Tunnel(%s) -> :%d (Up=Proto %d, Down=Proto %d) via %s",
			*listenAddr, *tunnelIP, *targetPort, upProto, dnProto, iface)
		startClientAFPacket(*listenAddr, serverIP, uint16(*targetPort), upProto, dnProto, iface)
	} else {
		log.Printf("[Server-AF_PACKET] Listening on Up=Proto %d, replying Down=Proto %d via %s", upProto, dnProto, iface)
		startServerAFPacket(upProto, dnProto, iface)
	}
}

// resolveFilterDstIP returns the dst-host IP for the BPF capture filter.
// Falls back to the supplied IP (typically srcIP) if -filter-dst-ip is unset.
// The CLI override exists because srcIP may be a spoofed/customSrc value
// that doesn't match what packets actually carry on the wire.
func resolveFilterDstIP(fallback net.IP) net.IP {
	if *filterDstIP == "" {
		return fallback
	}
	ip := net.ParseIP(*filterDstIP)
	if ip == nil {
		log.Fatalf("Invalid -filter-dst-ip: %q", *filterDstIP)
	}
	return ip
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
	// Local RNG to avoid global lock contention in rand.Intn
	// Only accessed by the single Uplink goroutine
	rng *rand.Rand
}

func (n *NatTable) GetOrCreateVirtualPort(clientIP net.IP, clientPort int) uint16 {
	key := makeNatKey(clientIP, clientPort)
	now := atomic.LoadInt64(&coarseTime)

	// 1. Check existing - fast path
	if val, ok := n.forward.Load(key); ok {
		vPort := val.(uint16)
		if s, ok := n.reverse.Load(vPort); ok {
			atomic.StoreInt64(&s.(*natSession).lastSeen, now)
		}
		return vPort
	}

	// 2. Allocation Logic - try original port first (slow path, acceptable).
	// Session is allocated once and reused across collision retries because
	// LoadOrStore only retains it on a successful store.
	session := &natSession{
		clientIP:   clientIP,
		clientPort: clientPort,
		lastSeen:   now,
		forwardKey: key,
	}
	proposed := uint16(clientPort)
	for {
		if _, loaded := n.reverse.LoadOrStore(proposed, session); !loaded {
			n.forward.Store(key, proposed)
			return proposed
		}
		// Collision: pick random in [1024, 65535)
		proposed = uint16(n.rng.Intn(64511) + 1024)
	}
}

func (n *NatTable) GetSession(virtualPort uint16) *natSession {
	if val, ok := n.reverse.Load(virtualPort); ok {
		sess := val.(*natSession)
		atomic.StoreInt64(&sess.lastSeen, atomic.LoadInt64(&coarseTime))
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
			if atomic.LoadInt64(&sess.lastSeen) < threshold {
				n.reverse.Delete(vPort)
				n.forward.Delete(sess.forwardKey)
			}
			return true
		})
	}
}

// --- AF_PACKET Client ---

func startClientAFPacket(localAddr string, serverIP net.IP, dstPort uint16, upProto, dnProto uint8, iface string) {
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
	// This filters in-kernel, before packets ever reach the mmap ring buffer.
	// For TCP/UDP modes we also narrow by tunnel peer IPs and target port.
	filterDst := resolveFilterDstIP(srcIP)
	// Client receives downlink (server→client) traffic, so the BPF filters dnProto.
	filter := createBPFFilter(dnProto, srcMAC, *fakeFrag, serverIP, filterDst, dstPort, true)
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
	// txOffload, rxOffload := supportsUDPOffload(appConn)
	txOffload := false
	rxOffload := false
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

	nat := &NatTable{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	go nat.Cleanup()

	// Reusable layer parsers for Downlink. We only need Ethernet + IPv4 here;
	// the inner transport (UDP or TCP) is parsed by parseFakeTransport since
	// gopacket won't auto-chain to either for a custom IP protocol number.
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	ethParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer)
	ethParser.IgnoreUnsupported = true
	decodedLayers := make([]gopacket.LayerType, 0, 4)

	// Downlink (AF_PACKET -> App)
	// Reads raw Ethernet frames, strips headers, translates VirtualPort -> ClientPort
	go func() {
		// Reusable UDPAddr to avoid per-packet heap allocation.
		// IP is assigned from sess.clientIP per packet, so no preallocation needed.
		writeAddr := &net.UDPAddr{}

		for {
			// Zero-copy read from AF_PACKET mmap'd ring buffer
			data, _, err := tpacket.ZeroCopyReadPacketData()
			if err != nil {
				continue
			}

			// Parse Ethernet + IPv4 header
			err = ethParser.DecodeLayers(data, &decodedLayers)
			if len(decodedLayers) < 2 {
				continue
			}

			// Userspace protocol filter (defense-in-depth: BPF may fail to attach).
			// Incoming on the client is server→client traffic → dnProto.
			if ipLayer.Protocol != layers.IPProtocol(dnProto) || ipLayer.FragOffset != 0 {
				continue
			}

			// Parse transport header (UDP or TCP) from IP payload
			_, dstPortRecv, payload, ok := parseFakeTransport(ipLayer.Payload, *fakeTCP)
			if !ok {
				continue
			}

			// Reverse NAT: VirtualPort (transport.DstPort) -> Client Session
			sess := nat.GetSession(dstPortRecv)
			if sess == nil {
				continue
			}

			writeAddr.IP = sess.clientIP
			writeAddr.Port = sess.clientPort
			if _, err := appConn.WriteToUDP(payload, writeAddr); err != nil {
				log.Printf("WriteToUDP error in downlink (no coalesce): %v", err)
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
	var ipId uint16 = 1

	ipFlags := layers.IPv4DontFragment
	if *fakeFrag {
		ipFlags = layers.IPv4MoreFragments
	}

	ethHeader := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipHeader := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Id:         ipId,
		TTL:        64,
		Protocol:   layers.IPProtocol(upProto),
		SrcIP:      srcIP,
		DstIP:      serverIP,
		Flags:      ipFlags,
		FragOffset: 0,
	}
	// Transport header — either UDP or TCP based on -fake-tcp. Both share the
	// same first 4 bytes (src/dst port), so the rest of the tunnel logic is
	// identical.
	var udpHeader *layers.UDP
	var tcpHeader *layers.TCP
	if *fakeTCP {
		tcpHeader = newFakeTCPHeader(dstPort, tcpFlagByte)
		tcpHeader.SetNetworkLayerForChecksum(ipHeader)
	} else {
		udpHeader = &layers.UDP{DstPort: layers.UDPPort(dstPort)}
		udpHeader.SetNetworkLayerForChecksum(ipHeader)
	}
	hdrLen := transportHeaderLen()

	// Fake frag IP header
	ipHeaderFrag := &layers.IPv4{
		Version:    4,
		IHL:        5,
		Id:         ipId,
		TTL:        64,
		Protocol:   layers.IPProtocol(upProto),
		SrcIP:      srcIP,
		DstIP:      serverIP,
		Flags:      0,
		FragOffset: 0,
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
		ipHeader.Id = ipId
		var transport gopacket.SerializableLayer
		if *fakeTCP {
			tcpHeader.SrcPort = layers.TCPPort(vPort)
			transport = tcpHeader
		} else {
			udpHeader.SrcPort = layers.UDPPort(vPort)
			transport = udpHeader
		}

		if *fakeFrag {
			data = padData(data, 8, hdrLen)
		}

		if err := gopacket.SerializeLayers(serializeBuf, opts, ethHeader, ipHeader, transport, gopacket.Payload(data)); err != nil {
			log.Printf("Serialize error: %v", err)
			continue
		}

		// Send via AF_PACKET (bypasses kernel IP stack)
		if err := tpacket.WritePacketData(serializeBuf.Bytes()); err != nil {
			log.Printf("AF_PACKET write error: %v", err)
		}

		// fake frag
		if *fakeFrag {
			ipHeaderFrag.Id = ipId
			// Offset of the fake fragment in 8-byte units: after the real
			// transport header + padded data.
			ipHeaderFrag.FragOffset = uint16((len(data) + hdrLen) / 8)

			if err := gopacket.SerializeLayers(serializeBuf, opts, ethHeader, ipHeaderFrag, gopacket.Payload([]byte("0"))); err != nil {
				log.Printf("Serialize error: %v", err)
				continue
			}

			// Send via AF_PACKET (bypasses kernel IP stack)
			if err := tpacket.WritePacketData(serializeBuf.Bytes()); err != nil {
				log.Printf("AF_PACKET write error: %v", err)
			}
		}

		ipId = (ipId + 1) % 65000
	}
}

// --- AF_PACKET Server ---

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

	// Mutex to protect simultaneous writes to the shared TX ring
	var txMutex sync.Mutex

	// BPF: reject our own outgoing packets + only accept our custom IP protocol.
	// For TCP/UDP modes we also narrow by our IP and the target port.
	filterDst := resolveFilterDstIP(srcIP)
	// Server receives uplink (client→server) traffic, so the BPF filters upProto.
	filter := createBPFFilter(upProto, srcMAC, *fakeFrag, nil, filterDst, uint16(*targetPort), false)
	if err := tpacket.SetBPF(filter); err != nil {
		log.Printf("Warning: Failed to set BPF filter: %v", err)
	}

	sessions := sync.Map{}

	autoDst := false
	if *tunnelIP == "" {
		autoDst = true
		log.Printf("Auto-detecting Remote IP from incoming packets for each session")
	}

	// Parsers — only Ethernet+IPv4; transport (UDP/TCP) is parsed manually
	// since gopacket can't auto-chain through a custom IP proto number.
	var ethLayer layers.Ethernet
	var ipLayer layers.IPv4
	ethParser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ethLayer, &ipLayer)
	ethParser.IgnoreUnsupported = true
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

		// Userspace protocol filter (defense-in-depth: BPF may fail to attach).
		// Incoming on the server is client→server traffic → upProto.
		if ipLayer.Protocol != layers.IPProtocol(upProto) || ipLayer.FragOffset != 0 {
			continue
		}

		// Parse transport header (UDP or TCP) from IPv4 payload
		clientSrcPort, clientDstPort, innerPayload, ok := parseFakeTransport(ipLayer.Payload, *fakeTCP)
		if !ok {
			continue
		}

		// Session key: ClientRealIP + VirtualSrcPort
		clientKey := makeNatKey(ipLayer.SrcIP, int(clientSrcPort))

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
			safeClientIP := make(net.IP, len(ipLayer.SrcIP))
			copy(safeClientIP, ipLayer.SrcIP)

			safeClientMAC := make(net.HardwareAddr, len(ethLayer.SrcMAC))
			copy(safeClientMAC, ethLayer.SrcMAC)

			// Reply handler goroutine
			go func(c *net.UDPConn, clientIP net.IP, clientPort uint16, clientMAC net.HardwareAddr,
				srcServerIP net.IP, targetRAddr *net.UDPAddr, sessionKey natKey,
				txOff, rxOff bool) {
				ipv4AppConn := ipv4.NewPacketConn(c)
				msgs := prepareMsgsUDP(rxOff)
				defer c.Close()
				defer sessions.Delete(sessionKey)

				// Use shared txTPacket and txMutex from outer scope

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
					msg := msgs[readPos]
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

					// Shared Mutex Write - Bottleneck potential but memory safe
					txMutex.Lock()
					err := txTPacket.WritePacketData(sBuf.Bytes())
					txMutex.Unlock()

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

// Data utils

// padding

// padData appends PKCS#7-style padding so that headerLen+len(data) becomes
// a multiple of blockSize. headerLen accounts for the transport header that
// will precede the data on the wire — needed because the IP fragment offset
// (used by fake-frag) is expressed in 8-byte units relative to the IP body.
func padData(data []byte, blockSize, headerLen int) []byte {
	p := blockSize - ((headerLen + len(data)) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(p)}, p)...)
}

func unpadData(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	p := int(data[len(data)-1])
	if p == 0 || p > len(data) {
		// malformed pad byte — leave data untouched
		return data
	}
	return data[:len(data)-p]
}

// --- Fake transport (UDP/TCP) helpers ---

// transportHeaderLen returns the wire size of the chosen transport header.
// UDP=8, TCP (minimum, no options) = 20. Used for fake-frag offset math.
func transportHeaderLen() int {
	if *fakeTCP {
		return 20
	}
	return 8
}

// newFakeTCPHeader builds a TCP header with the user-configured flag byte.
// Seq/Ack are constants; the goal is to mimic a mid-flow segment shape, not
// to participate in a real TCP handshake (the kernel never sees these packets
// — both ends use AF_PACKET).
func newFakeTCPHeader(dstPort uint16, flagsByte uint8) *layers.TCP {
	return &layers.TCP{
		DstPort:    layers.TCPPort(dstPort),
		Seq:        1,
		Ack:        0,
		DataOffset: 5, // 20-byte header, no options
		Window:     65535,
		FIN:        flagsByte&0x01 != 0,
		SYN:        flagsByte&0x02 != 0,
		RST:        flagsByte&0x04 != 0,
		PSH:        flagsByte&0x08 != 0,
		ACK:        flagsByte&0x10 != 0,
		URG:        flagsByte&0x20 != 0,
		ECE:        flagsByte&0x40 != 0,
		CWR:        flagsByte&0x80 != 0,
	}
}

// parseFakeTransport reads src/dst port and inner payload from an IP body
// shaped as either UDP (8-byte header) or TCP (variable-length header).
// Both protocols place srcPort at bytes 0-1 and dstPort at bytes 2-3.
func parseFakeTransport(ipPayload []byte, useTCP bool) (srcPort, dstPort uint16, payload []byte, ok bool) {
	if useTCP {
		if len(ipPayload) < 20 {
			return 0, 0, nil, false
		}
		srcPort = binary.BigEndian.Uint16(ipPayload[0:2])
		dstPort = binary.BigEndian.Uint16(ipPayload[2:4])
		dataOff := int(ipPayload[12]>>4) * 4
		if dataOff < 20 || dataOff > len(ipPayload) {
			return 0, 0, nil, false
		}
		return srcPort, dstPort, ipPayload[dataOff:], true
	}
	if len(ipPayload) < 8 {
		return 0, 0, nil, false
	}
	srcPort = binary.BigEndian.Uint16(ipPayload[0:2])
	dstPort = binary.BigEndian.Uint16(ipPayload[2:4])
	return srcPort, dstPort, ipPayload[8:], true
}

// --- BPF Filter ---

// createBPFFilter builds a kernel-level BPF program that:
//  1. Rejects packets where src MAC == our own MAC (outgoing loopback)
//  2. Accepts only IPv4 (EtherType 0x0800)
//  3. Accepts only our custom IP protocol number
//  4. For TCP (6) / UDP (17): narrows by tunnel IPs and port so we don't
//     accidentally siphon unrelated TCP/UDP traffic on the interface.
//
// Port matching uses raw IP-body byte reads (ip[20:2] / ip[22:2]) rather
// than the `tcp/udp port X` shorthand. The src/dst port fields share the
// same layout for TCP and UDP, and the IP-proto check already discriminates
// the two — so the byte reads remain correct for either protocol.
//
// All filtering happens in-kernel before packets reach the mmap ring buffer,
// eliminating unnecessary copies and userspace processing.
func createBPFFilter(proto uint8, srcMAC net.HardwareAddr, fakeFrag bool, remoteIP, localIP net.IP, port uint16, isClient bool) []bpf.RawInstruction {
	parts := []string{
		fmt.Sprintf("not ether src %s", srcMAC.String()),
		fmt.Sprintf("ip proto %d", proto),
	}

	// TCP/UDP need IP+port narrowing — otherwise we'd capture every packet
	// of those well-known protocols on the interface.
	if proto == 6 || proto == 17 {
		if isClient {
			// Replies arrive from the server endpoint with src port == target port.
			if remoteIP != nil {
				parts = append(parts, fmt.Sprintf("src host %s", remoteIP.String()))
			}
			if localIP != nil {
				parts = append(parts, fmt.Sprintf("dst host %s", localIP.String()))
			}
			if port != 0 {
				// dst port = first 2 bytes of IP body (offset 20 assumes IHL=5,
				// which our tunnel always emits)
				parts = append(parts, fmt.Sprintf("ip[22:2] == %d", port))
			}
		} else {
			// Incoming tunnel traffic lands on the server's IP and target port.
			if localIP != nil {
				parts = append(parts, fmt.Sprintf("dst host %s", localIP.String()))
			}
			if port != 0 {
				// dst port = bytes 2-3 of IP body (offset 22 from IP header start)
				parts = append(parts, fmt.Sprintf("ip[22:2] == %d", port))
			}
		}
	}

	if fakeFrag {
		// frag offset == 0
		parts = append(parts, "ip[6:2] & 0x1FFF == 0")
	}

	filter := strings.Join(parts, " and ")

	pcapBPF, err := pcap.CompileBPFFilter(
		layers.LinkTypeEthernet,
		65535,
		filter,
	)
	if err != nil {
		log.Fatalf("Failed to compile BPF filter %q: %v", filter, err)
	}

	bpfIns := make([]bpf.RawInstruction, 0, len(pcapBPF))
	for _, ins := range pcapBPF {
		bpfIns = append(bpfIns, bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		})
	}

	return bpfIns

	/*
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
	*/
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
