//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"net"
)

var (
	errEncoderAddress = errors.New("tunnel encoder requires Ethernet MACs and IPv4 addresses")
	errEncoderPacket  = errors.New("invalid tunnel packet length or fragment fields")
	errEncoderBuffer  = errors.New("tunnel encoder output buffer too small")
)

// tunnelEncoder holds the immutable fields and checksum sums for one direction.
// It emits the same fixed headers as the previous gopacket serialization path.
// Encode does not retain dst or payload, and concurrent calls with separate
// output buffers are safe.
type tunnelEncoder struct {
	template     [54]byte
	transportLen int
	ipSum, l4Sum uint32
}

func newTunnelEncoder(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, proto uint8, tcp bool, flags uint8) (*tunnelEncoder, error) {
	src4, dst4 := srcIP.To4(), dstIP.To4()
	if len(srcMAC) != 6 || len(dstMAC) != 6 || src4 == nil || dst4 == nil {
		return nil, errEncoderAddress
	}
	e := &tunnelEncoder{transportLen: 8}
	h := e.template[:]
	copy(h[:6], dstMAC)
	copy(h[6:12], srcMAC)
	binary.BigEndian.PutUint16(h[12:14], 0x0800)
	h[14], h[22], h[23] = 0x45, 64, proto
	copy(h[26:30], src4)
	copy(h[30:34], dst4)
	e.ipSum = encoderChecksumSum(h[14:34], 0)
	// The transport checksum pseudoheader uses its actual header protocol,
	// including when the enclosing IPv4 protocol is a custom tunnel number.
	headerProto := uint32(17)
	if tcp {
		e.transportLen = 20
		headerProto = 6
		binary.BigEndian.PutUint32(h[38:42], 1) // TCP sequence number
		h[46], h[47] = 0x50, flags
		binary.BigEndian.PutUint16(h[48:50], 65535)
	}
	e.l4Sum = encoderChecksumSum(h[26:34], headerProto)
	e.l4Sum = encoderChecksumSum(h[34:34+e.transportLen], e.l4Sum)
	return e, nil
}

// Encode writes into dst's capacity; payload must not overlap that storage.
// ipFlags contains the wire flag bits (DF=0x4000, MF=0x2000). When transport is
// false, payload is the complete IP body, used by the final fake fragment.
func (e *tunnelEncoder) Encode(dst, payload []byte, srcPort, dstPort, ipID, ipFlags, fragOffset uint16, transport bool) ([]byte, error) {
	l4Len := 0
	if transport {
		l4Len = e.transportLen
	}
	if len(payload) > 65535-20-l4Len || ipFlags&0x1fff != 0 || fragOffset > 0x1fff {
		return nil, errEncoderPacket
	}
	ipLen := 20 + l4Len + len(payload)
	frameLen := 14 + ipLen
	wireLen := max(60, frameLen)
	if cap(dst) < wireLen {
		return nil, errEncoderBuffer
	}
	dst = dst[:wireLen]
	copy(dst[:34+l4Len], e.template[:34+l4Len])
	copy(dst[34+l4Len:frameLen], payload)
	clear(dst[frameLen:]) // A reused larger frame must not leak into Ethernet padding.
	binary.BigEndian.PutUint16(dst[16:18], uint16(ipLen))
	binary.BigEndian.PutUint16(dst[18:20], ipID)
	frag := ipFlags | fragOffset
	binary.BigEndian.PutUint16(dst[20:22], frag)
	binary.BigEndian.PutUint16(dst[24:26], encoderFoldChecksum(e.ipSum+uint32(ipLen)+uint32(ipID)+uint32(frag)))
	if transport {
		binary.BigEndian.PutUint16(dst[34:36], srcPort)
		binary.BigEndian.PutUint16(dst[36:38], dstPort)
		length := uint32(l4Len + len(payload))
		sum := e.l4Sum + uint32(srcPort) + uint32(dstPort) + length
		checksumAt := 50
		if l4Len == 8 {
			binary.BigEndian.PutUint16(dst[38:40], uint16(length))
			sum += length // UDP length is present in both header and pseudoheader.
			checksumAt = 40
		}
		checksum := encoderFoldChecksum(encoderChecksumSum(payload, sum))
		if l4Len == 8 && checksum == 0 {
			checksum = 0xffff // RFC 768: zero on the wire means no UDP checksum.
		}
		binary.BigEndian.PutUint16(dst[checksumAt:checksumAt+2], checksum)
	}
	return dst, nil
}

// The bounded IPv4 packet length keeps this unfolded sum below uint32 overflow.
// Unroll the payload loop to amortize bounds checks and loop bookkeeping.
func encoderChecksumSum(data []byte, sum uint32) uint32 {
	for len(data) >= 8 {
		sum += uint32(binary.BigEndian.Uint16(data[:2])) + uint32(binary.BigEndian.Uint16(data[2:4])) +
			uint32(binary.BigEndian.Uint16(data[4:6])) + uint32(binary.BigEndian.Uint16(data[6:8]))
		data = data[8:]
	}
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	return sum
}

func encoderFoldChecksum(sum uint32) uint16 {
	sum = sum>>16 + sum&0xffff
	sum = sum>>16 + sum&0xffff
	return ^uint16(sum)
}
