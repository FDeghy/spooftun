//go:build linux

package main

import (
	"flag"
	"sync/atomic"
	"time"
)

// High-throughput tuning constants for AF_PACKET
const (
	batchSize     = 16      // Messages per batch read/write (for UDP side)
	socketBufSize = 1 << 24 // 16MB socket buffer

	// GSO/GRO constants
	udpSegmentMaxDatagrams = 64 // kernel hard limit
	coarseTimeInterval     = 100 * time.Millisecond
)

var (
	// will be changed at runtime
	// AF_PACKET ring buffer configuration (TPACKET_V3)
	afBlockSize = 1 << 20 // 1MB blocks
	afNumBlocks = 64      // 64 blocks = 64MB ring buffer
	afFrameSize = 2048    // Frame size for each packet slot
	// V3 exposes packets only after their block fills or retires. Keep the
	// retire wait short so sparse traffic does not sit in an RX block.
	afBlockTimeout = time.Millisecond
)

// Coarse timestamp to avoid time.Now() per packet
var coarseTime int64

func init() {
	atomic.StoreInt64(&coarseTime, time.Now().UnixNano())
	go func() {
		for {
			time.Sleep(coarseTimeInterval)
			atomic.StoreInt64(&coarseTime, time.Now().UnixNano())
		}
	}()
}

// Configuration
var (
	backend        = flag.String("backend", "afpacket", "Packet backend: afpacket, xdp (AF_XDP), or tc (kernel rewrite)")
	tcLocalPort    = flag.Int("tc-local-port", 0, "TC: local application's fixed UDP port (required)")
	tcPeerPort     = flag.Int("tc-peer-port", 0, "TC server: remote client's fixed UDP port (required)")
	tcAddress      = flag.String("tc-address", "198.18.0.1/30", "TC: unused private /30, with local address at network+1; peer is network+2")
	tcPeerSrc      = flag.String("tc-peer-src-ip", "", "TC: expected incoming source IP, defaults to remote-ip; set for a spoofing peer")
	udpGRO         = flag.Bool("udp-gro", false, "Enable local UDP receive coalescing (GRO), using larger per-flow receive buffers")
	afpacketTX     = flag.String("afpacket-tx", "sendmmsg", "AF_PACKET transmitter: sendmmsg or ring")
	ringMB         = flag.Int("ring-mb", 16, "AF_PACKET RX ring size in MiB")
	blockTimeout   = flag.Duration("block-timeout", time.Millisecond, "TPACKET_V3 block retirement latency")
	tunnelMTU      = flag.Int("mtu", 1500, "Maximum tunnel IPv4 packet size (capped to interface MTU)")
	sessionTimeout = flag.Duration("session-timeout", 60*time.Second, "Server session idle timeout in either direction")
	mode           = flag.String("mode", "client", "Mode: 'client' or 'server'")
	customSrc      = flag.String("src-ip", "", "Force a specific Source IP (Spoofing). Leave empty to auto-detect.")
	listenAddr     = flag.String("listen", "127.0.0.1:1001", "Client: Local UDP port to bind. Server: Not used")
	tunnelIP       = flag.String("remote-ip", "", "IP of the remote tunnel endpoint")
	targetPort     = flag.Int("target-port", 8080, "Tunnel destination port; server capture port for protocols 6/17")
	outboundPort   = flag.Int("outbound-port", 0, "Server: local UDP destination port (0 uses the incoming tunnel destination port)")
	protoNum       = flag.Int("proto", 200, "Custom IP Protocol Number (0-255). Default for both directions.")
	uplinkProto    = flag.Int("uplink-proto", -1, "IP protocol for client→server packets. Overrides -proto for that direction; -1 means inherit -proto.")
	downProto      = flag.Int("downlink-proto", -1, "IP protocol for server→client packets. Overrides -proto for that direction; -1 means inherit -proto.")
	ifaceName      = flag.String("iface", "", "Network interface to use for AF_PACKET (auto-detect if empty)")
	fakeFrag       = flag.Bool("fake-frag", false, "Use fake frag only for *client uplink, must be enabled in *server to receiving fake frag packets")
	filterDstIP    = flag.String("filter-dst-ip", "", "Destination IP for BPF capture filter (TCP/UDP proto). Use when -src-ip is spoofed and the on-wire dst IP differs. Defaults to -src-ip.")
	fakeTCP        = flag.Bool("fake-tcp", false, "Use a TCP-shaped header instead of UDP for tunnel framing. Must match on both ends.")
	noise          = flag.Bool("noise", false, "Send noise once per flow before its first datagram (UDP framing, outgoing protocol 17 only)")
	noisePayload   = flag.String("noise-payload", "", "Base64 noise content after the internal marker (empty uses random content; requires -noise)")
	tcpFlags       = flag.String("tcp-flags", "0x18", "TCP flag byte (hex or decimal) used with -fake-tcp. Examples: 0x18=PSH+ACK, 0x10=ACK, 0x02=SYN.")
)

// tcpFlagByte is parsed from -tcp-flags at startup.
var tcpFlagByte uint8

// Decoded once at startup and read-only for all flow senders. Nil selects random.
var noiseContent []byte
