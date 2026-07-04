//go:build linux

// Command spooftun is a high-throughput Linux UDP tunnel that carries traffic
// under a configurable custom IP protocol number using AF_PACKET (TPACKET_V3)
// for both RX and TX, bypassing the kernel IP stack. It supports source-IP
// spoofing, a per-flow NAT layer, and optional obfuscation via fake TCP-shaped
// framing and fake IP fragmentation.
//
// The code is split across files by concern:
//
//	config.go   flags, tuning constants, runtime ring config, coarse clock
//	nat.go      client-side NAT table (client:port <-> virtual port)
//	netutil.go  interface / ARP / route discovery and ring sizing
//	framing.go  Ethernet/IPv4 parsing and fake UDP/TCP + fragmentation framing
//	bpf.go      in-kernel BPF capture filter
//	client.go   client data path (app -> tunnel -> app)
//	server.go   server data path (tunnel -> target -> tunnel)
//	offload.go  UDP GSO/GRO helpers (scaffolding, currently disabled)
package main

import (
	"flag"
	"log"
	"net"
	"os"
	"strconv"
)

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

	// Calculate AF_PACKET buffer size.
	// snaplen is sized to one Ethernet MTU frame (header + IP MTU, rounded up)
	// rather than 65535: our tunnel frames never exceed the MTU, and a 64KB
	// snaplen would pad every ring slot to 64KB, shrinking the ring to a
	// handful of frames and causing drops under load.
	const afSnaplen = 2048 // >= 14 (eth) + packetBufSize, next power of two
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(16, afSnaplen, os.Getpagesize())
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
