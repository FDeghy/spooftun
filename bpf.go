//go:build linux

package main

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
)

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
func createBPFFilter(proto uint8, srcMAC net.HardwareAddr, fakeFrag bool, localIP net.IP, port uint16, isClient bool) []bpf.RawInstruction {
	parts := []string{
		fmt.Sprintf("not ether src %s", srcMAC.String()),
		fmt.Sprintf("ip proto %d", proto),
	}

	// TCP/UDP need IP+port narrowing — otherwise we'd capture every packet
	// of those well-known protocols on the interface.
	if proto == 6 || proto == 17 {
		if isClient {
			// src IP may be spoofed — don't filter on it.
			// Match on dst host (our real IP) and src port (server's target port).
			if localIP != nil {
				parts = append(parts, fmt.Sprintf("dst host %s", localIP.String()))
			}
			if port != 0 {
				// src port in server→client reply = the server's target port.
				// ip[20:2] is the src port field (IHL=5 assumed).
				parts = append(parts, fmt.Sprintf("ip[20:2] == %d", port))
			}
		} else {
			// src IP may be spoofed — don't filter on it.
			// Match on dst host (our real IP) and dst port (target port).
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
