//go:build linux

package main

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf/asm"
)

// xdpInstructions is intentionally a narrow redirector. Anything not matching
// the existing AF_PACKET filter, including ARP and management traffic, passes
// to the network stack. Bounds checks cover both fixed and variable IP headers.
func xdpInstructions(mapFD int, proto uint8, mac net.HardwareAddr, ip net.IP, port uint16, client bool) asm.Instructions {
	i := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R8, asm.R6, 4, asm.Word),
		asm.Mov.Reg(asm.R0, asm.R7),
		asm.Add.Imm(asm.R0, 34),
		asm.JGT.Reg(asm.R0, asm.R8, "pass"),
		asm.LoadMem(asm.R0, asm.R7, 6, asm.Word),
		asm.HostTo(asm.BE, asm.R0, asm.Word),
		asm.JNE.Imm32(asm.R0, int32(binary.BigEndian.Uint32(mac[:4])), "ether"),
		asm.LoadMem(asm.R0, asm.R7, 10, asm.Half),
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.JEq.Imm(asm.R0, int32(binary.BigEndian.Uint16(mac[4:])), "pass"),
		asm.LoadMem(asm.R0, asm.R7, 12, asm.Half).WithSymbol("ether"),
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.JNE.Imm(asm.R0, 0x0800, "pass"),
		asm.LoadMem(asm.R0, asm.R7, 14, asm.Byte),
		asm.Mov.Reg(asm.R9, asm.R0),
		asm.And.Imm(asm.R0, 0xf0),
		asm.JNE.Imm(asm.R0, 0x40, "pass"),
		asm.And.Imm(asm.R9, 0xf),
		asm.JLT.Imm(asm.R9, 5, "pass"),
		asm.LoadMem(asm.R0, asm.R7, 23, asm.Byte),
		asm.JNE.Imm(asm.R0, int32(proto), "pass"),
		asm.LoadMem(asm.R0, asm.R7, 20, asm.Half),
		asm.HostTo(asm.BE, asm.R0, asm.Half),
		asm.And.Imm(asm.R0, 0x1fff),
		asm.JNE.Imm(asm.R0, 0, "pass"),
	}
	if proto == 6 || proto == 17 {
		if ip != nil {
			i = append(i, asm.LoadMem(asm.R0, asm.R7, 30, asm.Word), asm.HostTo(asm.BE, asm.R0, asm.Word), asm.JNE.Imm32(asm.R0, int32(binary.BigEndian.Uint32(ip.To4())), "pass"))
		}
		if port != 0 {
			offset := int16(0)
			if !client {
				offset = 2
			}
			i = append(i,
				asm.LSh.Imm(asm.R9, 2), asm.Add.Imm(asm.R9, 14), asm.Add.Reg(asm.R9, asm.R7),
				asm.Mov.Reg(asm.R0, asm.R9), asm.Add.Imm(asm.R0, 4), asm.JGT.Reg(asm.R0, asm.R8, "pass"),
				asm.LoadMem(asm.R0, asm.R9, offset, asm.Half), asm.HostTo(asm.BE, asm.R0, asm.Half), asm.JNE.Imm(asm.R0, int32(port), "pass"),
			)
		}
	}
	i = append(i,
		asm.LoadMem(asm.R2, asm.R6, 16, asm.Word), // rx_queue_index
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Imm(asm.R3, 2), // XDP_PASS when a queue has no map entry
		asm.FnRedirectMap.Call(), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("pass"), asm.Return(),
	)
	return i
}
