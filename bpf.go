//go:build linux

package main

import (
	"encoding/binary"
	"log"
	"net"

	"golang.org/x/net/bpf"
)

// resolveFilterDstIP returns the dst-host IP for the capture filter.
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

// createBPFFilter assembles classic BPF directly: no libpcap or cgo is needed.
// Source MAC, IPv4 protocol, and fragment offset are checked for every mode.
// TCP/UDP also match destination IP and the directional tunnel port. The port
// offset follows IPv4 IHL so packets with IP options are filtered correctly.
func createBPFFilter(proto uint8, srcMAC net.HardwareAddr, fakeFrag bool, localIP net.IP, port uint16, isClient bool) []bpf.RawInstruction {
	// fakeFrag changes framing, but a non-initial fragment never contains the
	// transport header/NAT key and must be rejected even with that mode disabled.
	_ = fakeFrag
	if len(srcMAC) != 6 || (localIP != nil && localIP.To4() == nil) {
		raw, _ := bpf.Assemble([]bpf.Instruction{bpf.RetConstant{Val: 0}})
		return raw
	}
	var ins []bpf.Instruction
	var rejectTrue, rejectFalse []int
	rejectUnless := func(cond bpf.JumpTest, value uint32) {
		rejectFalse = append(rejectFalse, len(ins))
		ins = append(ins, bpf.JumpIf{Cond: cond, Val: value})
	}
	ins = append(ins,
		bpf.LoadAbsolute{Off: 6, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: binary.BigEndian.Uint32(srcMAC[:4]), SkipFalse: 2},
		bpf.LoadAbsolute{Off: 10, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(binary.BigEndian.Uint16(srcMAC[4:]))},
	)
	rejectTrue = append(rejectTrue, len(ins)-1)
	ins = append(ins, bpf.LoadAbsolute{Off: 12, Size: 2})
	rejectUnless(bpf.JumpEqual, 0x0800)
	ins = append(ins, bpf.LoadAbsolute{Off: 14, Size: 1}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0xf0})
	rejectUnless(bpf.JumpEqual, 0x40)
	ins = append(ins, bpf.LoadAbsolute{Off: 14, Size: 1}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x0f})
	rejectUnless(bpf.JumpGreaterOrEqual, 5)
	ins = append(ins, bpf.LoadAbsolute{Off: 23, Size: 1})
	rejectUnless(bpf.JumpEqual, uint32(proto))
	ins = append(ins, bpf.LoadAbsolute{Off: 20, Size: 2}, bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: 0x1fff})
	rejectUnless(bpf.JumpEqual, 0)
	if proto == 6 || proto == 17 {
		if localIP != nil {
			ins = append(ins, bpf.LoadAbsolute{Off: 30, Size: 4})
			rejectUnless(bpf.JumpEqual, binary.BigEndian.Uint32(localIP.To4()))
		}
		if port != 0 {
			offset := uint32(14)
			if !isClient {
				offset += 2
			}
			ins = append(ins, bpf.LoadMemShift{Off: 14}, bpf.LoadIndirect{Off: offset, Size: 2})
			rejectUnless(bpf.JumpEqual, uint32(port))
		}
	}
	ins = append(ins, bpf.RetConstant{Val: 65535})
	reject := len(ins)
	ins = append(ins, bpf.RetConstant{Val: 0})
	for _, i := range rejectTrue {
		jump := ins[i].(bpf.JumpIf)
		jump.SkipTrue = uint8(reject - i - 1)
		ins[i] = jump
	}
	for _, i := range rejectFalse {
		jump := ins[i].(bpf.JumpIf)
		jump.SkipFalse = uint8(reject - i - 1)
		ins[i] = jump
	}
	raw, err := bpf.Assemble(ins)
	if err != nil {
		log.Fatalf("assemble capture filter: %v", err)
	}
	return raw
}
