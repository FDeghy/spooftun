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

// AF_PACKET can queue frames before its capture filter is attached. Keep the
// same selection rules in userspace so those startup frames cannot bypass it.
type tunnelPacketFilter struct {
	proto                    uint8
	srcMAC                   [6]byte
	localIP                  [4]byte
	port                     uint16
	isClient, checkIP, valid bool
}

func newTunnelPacketFilter(proto uint8, srcMAC net.HardwareAddr, localIP net.IP, port uint16, isClient bool) tunnelPacketFilter {
	f := tunnelPacketFilter{proto: proto, port: port, isClient: isClient, checkIP: localIP != nil}
	if len(srcMAC) != 6 || localIP != nil && localIP.To4() == nil {
		return f
	}
	copy(f.srcMAC[:], srcMAC)
	copy(f.localIP[:], localIP.To4())
	f.valid = true
	return f
}

func (f tunnelPacketFilter) matches(p ethIPv4, srcPort, dstPort uint16) bool {
	if !f.valid || p.proto != f.proto || p.fragOffset != 0 || len(p.srcMAC) != 6 || [6]byte(p.srcMAC) == f.srcMAC {
		return false
	}
	if f.proto != 6 && f.proto != 17 {
		return true
	}
	if f.checkIP && (len(p.dstIP) != 4 || [4]byte(p.dstIP) != f.localIP) {
		return false
	}
	if f.port == 0 {
		return true
	}
	if f.isClient {
		return srcPort == f.port
	}
	return dstPort == f.port
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
	// Capture lengths include Ethernet, while the supported 65535-byte MTU
	// limits only IPv4. Returning 65535 truncates the largest valid frames.
	ins = append(ins, bpf.RetConstant{Val: 14 + 65535})
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
