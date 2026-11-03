//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

func filterPacket(proto byte, ihl int, source, destination uint16) []byte {
	p := make([]byte, 14+ihl*4+8)
	copy(p[6:12], []byte{2, 3, 4, 5, 6, 7})
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14] = 0x40 | byte(ihl)
	p[23] = proto
	copy(p[30:34], net.ParseIP("192.0.2.1").To4())
	binary.BigEndian.PutUint16(p[14+ihl*4:], source)
	binary.BigEndian.PutUint16(p[16+ihl*4:], destination)
	return p
}

func TestCaptureFilter(t *testing.T) {
	own := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	for _, proto := range []byte{6, 17, 253} {
		for _, client := range []bool{false, true} {
			for _, fake := range []bool{false, true} {
				t.Run(fmt.Sprintf("proto=%d/client=%v/frag=%v", proto, client, fake), func(t *testing.T) {
					raw := createBPFFilter(proto, own, fake, net.ParseIP("192.0.2.1"), 443, client)
					ins, ok := bpf.Disassemble(raw)
					if !ok {
						t.Fatal("cannot disassemble")
					}
					vm, err := bpf.NewVM(ins)
					if err != nil {
						t.Fatal(err)
					}
					check := func(name string, p []byte, want bool) {
						t.Helper()
						got, err := vm.Run(p)
						if err != nil {
							t.Fatal(err)
						}
						if (got > 0) != want {
							t.Errorf("%s: accepted=%v want=%v", name, got > 0, want)
						}
					}
					source, dest := uint16(12000), uint16(443)
					if client {
						source, dest = dest, source
					}
					for _, ihl := range []int{5, 6, 15} {
						check(fmt.Sprintf("valid IHL %d", ihl), filterPacket(proto, ihl, source, dest), true)
						// MF is allowed for the intentional first-fragment framing.
						p := filterPacket(proto, ihl, source, dest)
						p[20] = 0x20
						check("first fragment", p, true)
					}
					cases := []struct {
						name   string
						edit   func([]byte)
						accept bool
					}{
						{"own MAC", func(p []byte) { copy(p[6:12], own) }, false},
						{"same MAC prefix", func(p []byte) { copy(p[6:10], own[:4]) }, true},
						{"same MAC suffix", func(p []byte) { copy(p[10:12], own[4:]) }, true},
						{"EtherType", func(p []byte) { p[12] = 0x86; p[13] = 0xdd }, false},
						{"version", func(p []byte) { p[14] = 0x65 }, false},
						{"invalid IHL", func(p []byte) { p[14] = 0x44 }, false},
						{"wrong protocol", func(p []byte) { p[23]++ }, false},
						{"fragment", func(p []byte) { p[21] = 1 }, false},
						{"fragment high bits", func(p []byte) { p[20] = 1 }, false},
						{"wrong IP", func(p []byte) { p[33]++ }, proto != 6 && proto != 17},
						{"wrong source port", func(p []byte) { p[34]++ }, !client || proto == 253},
						{"wrong dest port", func(p []byte) { p[36]++ }, client || proto == 253},
					}
					for _, tc := range cases {
						p := filterPacket(proto, 5, source, dest)
						tc.edit(p)
						check(tc.name, p, tc.accept)
					}
					check("truncated ethernet", []byte{1, 2}, false)
					p := filterPacket(proto, 5, source, dest)
					check("truncated IP", p[:23], false)
					if proto == 6 || proto == 17 {
						check("truncated port", p[:34], false)
					}
				})
			}
		}
	}
}

func TestCaptureFilterUnrestrictedPort(t *testing.T) {
	raw := createBPFFilter(17, net.HardwareAddr{0, 1, 2, 3, 4, 5}, false, nil, 0, false)
	ins, _ := bpf.Disassemble(raw)
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	n, err := vm.Run(filterPacket(17, 5, 123, 456))
	if err != nil || n == 0 {
		t.Fatalf("wildcard rejected: %d %v", n, err)
	}
}

func TestCaptureFilterFullIPv4Frame(t *testing.T) {
	own := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	raw := createBPFFilter(17, own, false, net.ParseIP("192.0.2.1"), 443, false)
	ins, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("cannot disassemble capture filter")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 14+65535)
	copy(frame, filterPacket(17, 5, 12000, 443))
	binary.BigEndian.PutUint16(frame[16:18], 65535)
	binary.BigEndian.PutUint16(frame[38:40], 65535-20)
	// Socket-filter return values are capture lengths including Ethernet,
	// whereas -mtu is an IPv4 length. The largest supported packet must fit.
	n, err := vm.Run(frame)
	if err != nil || n < len(frame) {
		t.Fatalf("full IPv4 frame truncated: capture=%d frame=%d err=%v", n, len(frame), err)
	}
}

func TestTunnelPacketFilterMatchesCaptureFilter(t *testing.T) {
	own := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	ip := net.ParseIP("192.0.2.1")
	for _, proto := range []byte{6, 17, 253} {
		for _, client := range []bool{false, true} {
			for _, wildcard := range []bool{false, true} {
				t.Run(fmt.Sprintf("proto=%d/client=%t/wildcard=%t", proto, client, wildcard), func(t *testing.T) {
					localIP, port := ip, uint16(443)
					if wildcard {
						localIP, port = nil, 0
					}
					filter := newTunnelPacketFilter(proto, own, localIP, port, client)
					ins, _ := bpf.Disassemble(createBPFFilter(proto, own, false, localIP, port, client))
					vm, err := bpf.NewVM(ins)
					if err != nil {
						t.Fatal(err)
					}
					cases := []struct {
						name string
						edit func([]byte)
					}{
						{"match", func([]byte) {}},
						{"own MAC", func(p []byte) { copy(p[6:12], own) }},
						{"own MAC prefix", func(p []byte) { copy(p[6:10], own[:4]) }},
						{"other protocol", func(p []byte) { p[23]++ }},
						{"noninitial fragment", func(p []byte) { p[21] = 1 }},
						{"first fragment", func(p []byte) { p[20] = 0x20 }},
						{"other destination", func(p []byte) { p[33]++ }},
						{"other source port", func(p []byte) { p[34]++ }},
						{"other destination port", func(p []byte) { p[36]++ }},
					}
					for _, tc := range cases {
						t.Run(tc.name, func(t *testing.T) {
							source, destination := uint16(12000), uint16(443)
							if client {
								source, destination = destination, source
							}
							frame := filterPacket(proto, 5, source, destination)
							tc.edit(frame)
							captured, err := vm.Run(frame)
							if err != nil {
								t.Fatal(err)
							}
							// Model the fields produced by the IPv4/transport parsers;
							// checksum and length validation belongs to those parsers.
							packet := ethIPv4{srcMAC: frame[6:12], proto: frame[23],
								fragOffset: binary.BigEndian.Uint16(frame[20:22]) & 0x1fff,
								dstIP:      frame[30:34]}
							source = binary.BigEndian.Uint16(frame[34:36])
							destination = binary.BigEndian.Uint16(frame[36:38])
							if got := filter.matches(packet, source, destination); got != (captured > 0) {
								t.Fatalf("userspace selected=%t, capture selected=%t", got, captured > 0)
							}
						})
					}
				})
			}
		}
	}
}

// Exercise the actual Linux verifier and socket filter without CAP_NET_RAW.
func TestCaptureFilterKernel(t *testing.T) {
	sender, receiver := packetSenderPair(t, unix.SOCK_NONBLOCK)
	raw := createBPFFilter(17, net.HardwareAddr{0, 1, 2, 3, 4, 5}, false, net.ParseIP("192.0.2.1"), 443, false)
	filters := make([]unix.SockFilter, len(raw))
	for i, ins := range raw {
		filters[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	program := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if err := unix.SetsockoptSockFprog(receiver, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program); err != nil {
		t.Fatal(err)
	}
	rejected := filterPacket(17, 6, 12000, 444)
	accepted := filterPacket(17, 6, 12000, 443)
	if _, err := sender.WriteBatch([][]byte{rejected, accepted}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := unix.Read(receiver, buf)
	if err != nil || n != len(accepted) {
		t.Fatalf("accepted frame: n=%d err=%v", n, err)
	}
	if _, err := unix.Read(receiver, buf); err != unix.EAGAIN {
		t.Fatalf("filter passed rejected frame: %v", err)
	}
	// The BPF return value limits the entire captured Ethernet frame, not
	// just IPv4. Verify the kernel preserves the largest supported frame.
	large := make([]byte, 14+65535)
	copy(large, accepted)
	binary.BigEndian.PutUint16(large[16:18], 65535)
	binary.BigEndian.PutUint16(large[42:44], 65535-24)
	if _, err := sender.WriteBatch([][]byte{large}); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len(large))
	if n, err := unix.Read(receiver, buf); err != nil || n != len(large) {
		t.Fatalf("maximum frame truncated: n=%d want=%d err=%v", n, len(large), err)
	}
}
