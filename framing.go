//go:build linux

package main

import (
	"encoding/binary"
	"net"

	"github.com/gopacket/gopacket/layers"
)

// --- Ethernet/IPv4 fixed-offset parse ---

// ethIPv4 holds the fields we need from a captured Ethernet+IPv4 frame.
// All slice fields alias the input frame buffer (no copies).
type ethIPv4 struct {
	srcMAC     net.HardwareAddr
	proto      uint8
	fragOffset uint16 // 13-bit fragment offset (flags masked out)
	srcIP      net.IP
	dstIP      net.IP
	payload    []byte // IP payload (after the IPv4 header)
}

// parseEthIPv4 decodes a raw Ethernet+IPv4 frame using fixed offsets, avoiding
// gopacket's per-layer dispatch on the RX hot path. Only untagged IPv4 frames
// are accepted — which is all our tunnel ever produces, and BPF already narrows
// to EtherType IPv4. Returns ok=false for anything malformed or non-IPv4.
func parseEthIPv4(frame []byte) (ethIPv4, bool) {
	var p ethIPv4
	// 14 (Ethernet) + 20 (minimum IPv4 header)
	if len(frame) < 34 {
		return p, false
	}
	// EtherType (bytes 12-13) must be IPv4 (0x0800).
	if frame[12] != 0x08 || frame[13] != 0x00 {
		return p, false
	}
	ip := frame[14:]
	if ip[0]>>4 != 4 { // IP version
		return p, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return p, false
	}
	// Trust the IP total-length field, but clamp to the captured bytes in case
	// of truncation so payload never runs past the buffer.
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl || totalLen > len(ip) {
		totalLen = len(ip)
	}
	p.srcMAC = frame[6:12]
	p.proto = ip[9]
	p.fragOffset = binary.BigEndian.Uint16(ip[6:8]) & 0x1fff
	p.srcIP = ip[12:16]
	p.dstIP = ip[16:20]
	p.payload = ip[ihl:totalLen]
	return p, true
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

// --- Fake-frag padding ---

// padData appends PKCS#7-style padding so that headerLen+len(data) becomes
// a multiple of blockSize. headerLen accounts for the transport header that
// will precede the data on the wire — needed because the IP fragment offset
// (used by fake-frag) is expressed in 8-byte units relative to the IP body.
func padData(data []byte, blockSize, headerLen int) []byte {
	p := blockSize - ((headerLen + len(data)) % blockSize)
	// Append p copies of the pad byte. The uplink read buffer has spare
	// capacity (udpPayloadSize), so this reuses the backing array — no alloc.
	for i := 0; i < p; i++ {
		data = append(data, byte(p))
	}
	return data
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
