//go:build linux

package main

import (
	"flag"
	"sync/atomic"
	"time"
)

// High-throughput tuning constants for AF_PACKET
const (
	batchSize      = 64                         // Messages per batch read/write (for UDP side)
	socketBufSize  = 1 << 24                    // 16MB socket buffer
	packetBufSize  = 1500                       // MTU size
	udpPayloadSize = packetBufSize - 20 - 8 - 8 // 1464 bytes: fits after IP+UDP headers + fake-frag padding

	// GSO/GRO constants
	sizeOfGSOData          = 2     // uint16 size for UDP_SEGMENT value
	udpSegmentMaxDatagrams = 64    // kernel hard limit
	maxUDPGSOPayload       = 65535 // max payload size for a single GSO sendmsg
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
