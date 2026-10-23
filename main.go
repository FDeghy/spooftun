//go:build linux

// Command spooftun is a high-throughput Linux UDP tunnel that carries traffic
// under a configurable custom IP protocol number using AF_PACKET (TPACKET_V3
// RX with sendmmsg/TX ring) or AF_XDP (automatic zero-copy/copy fallback). It
// supports source-IP spoofing, a per-flow NAT layer, and optional fake TCP-shaped
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
	"time"
)

func main() {
	flag.Parse()
	if *backend != "afpacket" && *backend != "xdp" {
		log.Fatal("Invalid -backend: use afpacket or xdp")
	}
	if *afpacketTX != "sendmmsg" && *afpacketTX != "ring" {
		log.Fatal("Invalid -afpacket-tx: use sendmmsg or ring")
	}
	if *mode != "client" && *mode != "server" {
		log.Fatal("Invalid -mode: use client or server")
	}
	if *protoNum < 0 || *protoNum > 255 || *uplinkProto < -1 || *uplinkProto > 255 || *downProto < -1 || *downProto > 255 {
		log.Fatal("Protocol numbers must be 0..255 (-1 inherits for directional overrides)")
	}
	if *targetPort < 1 || *targetPort > 65535 {
		log.Fatal("Target port must be 1..65535")
	}
	if *ringMB < 1 || *ringMB > 1024 || *blockTimeout < time.Millisecond || *sessionTimeout <= 0 || *tunnelMTU < 68 || *tunnelMTU > 65535 {
		log.Fatal("Invalid ring size, timeout, or MTU")
	}
	for _, value := range []string{*customSrc, *tunnelIP, *filterDstIP} {
		if value != "" && net.ParseIP(value).To4() == nil {
			log.Fatalf("Expected IPv4 address: %q", value)
		}
	}
	afBlockTimeout = *blockTimeout

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
	// Size the ring for the configured MTU and packet metadata rather than
	// a fixed 64 KiB capture size.
	afSnaplen := *tunnelMTU + 14 + 128 // account for packet-ring metadata
	szFrame, szBlock, numBlocks, err := afpacketComputeSize(*ringMB, afSnaplen, os.Getpagesize())
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
		log.Printf("[Client] Forwarding %s -> Tunnel(%s) -> :%d (Up=Proto %d, Down=Proto %d) via %s",
			*listenAddr, *tunnelIP, *targetPort, upProto, dnProto, iface)
		startClientAFPacket(*listenAddr, serverIP, uint16(*targetPort), upProto, dnProto, iface)
	} else {
		log.Printf("[Server] Listening on Up=Proto %d, replying Down=Proto %d via %s", upProto, dnProto, iface)
		startServerAFPacket(upProto, dnProto, iface)
	}
}
