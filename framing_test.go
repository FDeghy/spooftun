//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// Exercise the on-wire modes through the upgraded serializer and the tunnel's
// own parser. These modes intentionally use a custom IP protocol number and
// transport-shaped headers rather than ordinary UDP/TCP packets.
func TestFakeFramingRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		tcp  bool
		frag bool
	}{
		{name: "udp"},
		{name: "tcp", tcp: true},
		{name: "fragmented_udp", frag: true},
		{name: "fragmented_tcp", tcp: true, frag: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte("arbitrary tunnel data")
			wirePayload := append([]byte(nil), payload...)
			headerLen := 8
			if tc.tcp {
				headerLen = 20
			}
			if tc.frag {
				wirePayload = padData(wirePayload, 8, headerLen)
			}

			eth := &layers.Ethernet{
				SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
				DstMAC:       net.HardwareAddr{6, 7, 8, 9, 10, 11},
				EthernetType: layers.EthernetTypeIPv4,
			}
			ip := &layers.IPv4{
				Version: 4, IHL: 5, TTL: 64,
				Protocol: layers.IPProtocol(200),
				SrcIP:    net.IPv4(192, 0, 2, 1),
				DstIP:    net.IPv4(198, 51, 100, 2),
			}
			if tc.frag {
				ip.Flags = layers.IPv4MoreFragments
			}
			var transport gopacket.SerializableLayer
			if tc.tcp {
				tcp := newFakeTCPHeader(8080, 0x18)
				tcp.SrcPort = 1234
				tcp.SetNetworkLayerForChecksum(ip)
				transport = tcp
			} else {
				udp := &layers.UDP{SrcPort: 1234, DstPort: 8080}
				udp.SetNetworkLayerForChecksum(ip)
				transport = udp
			}
			buf := gopacket.NewSerializeBuffer()
			if err := gopacket.SerializeLayers(buf,
				gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
				eth, ip, transport, gopacket.Payload(wirePayload)); err != nil {
				t.Fatal(err)
			}
			frame := buf.Bytes()
			parsed, ok := parseEthIPv4(frame)
			if !ok || parsed.proto != 200 {
				t.Fatalf("custom-protocol frame not parsed: ok=%v proto=%d", ok, parsed.proto)
			}
			if tc.frag && binary.BigEndian.Uint16(frame[20:22])&0x2000 == 0 {
				t.Fatal("fake fragment flag was lost")
			}
			if tc.tcp && frame[14+20+13] != 0x18 {
				t.Fatalf("fake TCP flags changed: got %#x", frame[14+20+13])
			}
			src, dst, got, ok := parseTunnelTransport(parsed, tc.tcp)
			if !ok || src != 1234 || dst != 8080 {
				t.Fatalf("fake transport changed: ok=%v src=%d dst=%d", ok, src, dst)
			}
			if tc.frag {
				got = unpadData(got)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("payload changed: got %x, want %x", got, payload)
			}
		})
	}
}

func TestTunnelTransportChecksumValidation(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, proto := range []uint8{17, 200} {
			for _, frag := range []bool{false, true} {
				for _, tc := range []struct {
					name string
					edit func([]byte, int)
					ok   bool
				}{
					{name: "valid", edit: func([]byte, int) {}, ok: true},
					{name: "payload", edit: func(frame []byte, _ int) { frame[54] ^= 1 }},
					{name: "checksum", edit: func(frame []byte, at int) { frame[at] ^= 1 }},
					{name: "pseudoheader", edit: func(frame []byte, _ int) {
						frame[26] ^= 1
						frame[24], frame[25] = 0, 0
						binary.BigEndian.PutUint16(frame[24:26], encoderFoldChecksum(encoderChecksumSum(frame[14:34], 0)))
					}},
				} {
					name := fmt.Sprintf("tcp=%t/proto=%d/frag=%t/%s", tcp, proto, frag, tc.name)
					t.Run(name, func(t *testing.T) {
						e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, proto, tcp, 0x18)
						if err != nil {
							t.Fatal(err)
						}
						payload := bytes.Repeat([]byte{0xa5}, 24)
						flags := uint16(0x4000)
						if frag {
							payload = padData(payload, 8, e.transportLen)
							flags = 0x2000
						}
						frame, err := e.Encode(make([]byte, 128), payload, 1234, 8080, 0, flags, 0, true)
						if err != nil {
							t.Fatal(err)
						}
						checksumAt := 40
						if tcp {
							checksumAt = 50
						}
						tc.edit(frame, checksumAt)
						p, ok := parseEthIPv4(frame)
						if !ok {
							t.Fatal("test requires a valid IPv4 header")
						}
						src, dst, got, ok := parseTunnelTransport(p, tcp)
						if ok != tc.ok {
							t.Fatalf("transport accepted=%t, want %t", ok, tc.ok)
						}
						if ok && (src != 1234 || dst != 8080 || !bytes.Equal(got, payload)) {
							t.Fatal("valid datagram changed")
						}
						if !tcp {
							// RFC 768 permits an omitted checksum, also used by noise.
							frame[40], frame[41] = 0, 0
							if _, _, _, ok := parseTunnelTransport(p, false); !ok {
								t.Fatal("legal omitted UDP checksum rejected")
							}
						}
					})
				}
			}
		}
	}
}

func TestFakeUDPLengthValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length uint16
		ok     bool
		want   []byte
	}{
		{name: "zero", length: 0},
		{name: "below_header", length: 7},
		{name: "truncated", length: 12},
		{name: "empty", length: 8, ok: true, want: []byte{}},
		{name: "payload", length: 11, ok: true, want: []byte{1, 2, 3}},
		{name: "trailing_ip_bytes", length: 9, ok: true, want: []byte{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte{0x12, 0x34, 0x1f, 0x90, 0, 0, 0, 0, 1, 2, 3}
			binary.BigEndian.PutUint16(body[4:6], tc.length)
			src, dst, payload, ok := parseFakeTransport(body, false)
			if ok != tc.ok {
				t.Fatalf("UDP length %d: parsed=%v, want %v", tc.length, ok, tc.ok)
			}
			if ok && (src != 0x1234 || dst != 8080 || !bytes.Equal(payload, tc.want)) {
				t.Fatalf("UDP datagram changed: src=%d dst=%d payload=%x; want %x", src, dst, payload, tc.want)
			}
		})
	}
}

func TestIPv4TotalLengthValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		total uint16
		ok    bool
	}{
		{"zero", 0, false},
		{"below_header", 19, false},
		{"truncated", 40, false},
		{"empty_payload", 20, true},
		{"with_payload", 24, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame := make([]byte, 14+24)
			frame[12], frame[13], frame[14] = 8, 0, 0x45
			binary.BigEndian.PutUint16(frame[16:18], tc.total)
			binary.BigEndian.PutUint16(frame[24:26], encoderFoldChecksum(encoderChecksumSum(frame[14:34], 0)))
			pkt, ok := parseEthIPv4(frame)
			if ok != tc.ok {
				t.Fatalf("total length %d: parsed=%v, want %v", tc.total, ok, tc.ok)
			}
			if ok && len(pkt.payload) != int(tc.total)-20 {
				t.Fatal("Ethernet padding leaked into the IPv4 payload")
			}
		})
	}
}

func TestIPv4ChecksumValidation(t *testing.T) {
	encoder, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 200, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := encoder.Encode(make([]byte, 128), []byte("payload"), 1234, 8080, 0, 0x4000, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseEthIPv4(frame); !ok {
		t.Fatal("valid IPv4 checksum rejected")
	}
	frame[26] ^= 1 // Corrupt source IP without changing its header checksum.
	if _, ok := parseEthIPv4(frame); ok {
		t.Fatal("corrupted IPv4 header accepted")
	}
	frame[26] ^= 1
	withOptions := append([]byte(nil), frame[:34]...)
	withOptions = append(withOptions, 1, 1, 1, 0)
	withOptions = append(withOptions, frame[34:]...)
	withOptions[14] = 0x46
	binary.BigEndian.PutUint16(withOptions[16:18], binary.BigEndian.Uint16(frame[16:18])+4)
	withOptions[24], withOptions[25] = 0, 0
	binary.BigEndian.PutUint16(withOptions[24:26], encoderFoldChecksum(encoderChecksumSum(withOptions[14:38], 0)))
	if _, ok := parseEthIPv4(withOptions); !ok {
		t.Fatal("valid IPv4 options rejected")
	}
	withOptions[34] ^= 1
	if _, ok := parseEthIPv4(withOptions); ok {
		t.Fatal("corrupted IPv4 options accepted")
	}
}

func TestTunnelTransportChecksumBoundaries(t *testing.T) {
	t.Run("UDP ignores bytes beyond declared length", func(t *testing.T) {
		e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 200, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := e.Encode(make([]byte, 128), []byte{1, 2}, 1234, 8080, 0, 0x4000, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		frame[44] = 0xee // Append within the Ethernet padding, then extend IPv4 only.
		binary.BigEndian.PutUint16(frame[16:18], 31)
		frame[24], frame[25] = 0, 0
		binary.BigEndian.PutUint16(frame[24:26], encoderFoldChecksum(encoderChecksumSum(frame[14:34], 0)))
		p, ok := parseEthIPv4(frame)
		if !ok {
			t.Fatal("invalid IPv4 fixture")
		}
		if _, _, payload, ok := parseTunnelTransport(p, false); !ok || !bytes.Equal(payload, []byte{1, 2}) {
			t.Fatal("UDP checksum included trailing IPv4 bytes")
		}
	})
	t.Run("TCP checksum field may be zero", func(t *testing.T) {
		e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 6, true, 0x18)
		if err != nil {
			t.Fatal(err)
		}
		word := encoderFoldChecksum(e.l4Sum + 1234 + 8080 + 22)
		frame, err := e.Encode(make([]byte, 128), []byte{byte(word >> 8), byte(word)}, 1234, 8080, 0, 0x4000, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint16(frame[50:52]) != 0 {
			t.Fatal("fixture needs a computed zero TCP checksum")
		}
		p, ok := parseEthIPv4(frame)
		if !ok {
			t.Fatal("invalid IPv4 fixture")
		}
		if _, _, _, ok := parseTunnelTransport(p, true); !ok {
			t.Fatal("valid zero TCP checksum rejected")
		}
	})
}

func TestModePayloadLimits(t *testing.T) {
	for _, mtu := range []int{68, 576, 1280, 1499, 1500, 9000, 65535} {
		for _, tcp := range []bool{false, true} {
			for _, frag := range []bool{false, true} {
				header := 8
				if tcp {
					header = 20
				}
				limit := payloadLimit(mtu, tcp, frag)
				for _, size := range []int{limit, limit + 1} {
					payload := make([]byte, size)
					if frag {
						payload = padData(payload, 8, header)
						if (header+len(payload))%8 != 0 {
							t.Fatal("fake fragment body is not aligned")
						}
					}
					fits := 20+header+len(payload) <= mtu
					if fits != (size == limit) {
						t.Fatalf("mtu=%d tcp=%v frag=%v payload=%d: fits=%v", mtu, tcp, frag, size, fits)
					}
				}
			}
		}
	}
}

func TestFakeFragmentPaddingValidation(t *testing.T) {
	for _, malformed := range [][]byte{nil, {}, {0}, {9}, {1, 2}, {1, 2, 3, 3}, {2}} {
		if unpadData(malformed) != nil {
			t.Fatalf("accepted malformed padding %x", malformed)
		}
	}
	for _, header := range []int{8, 20} {
		for size := 0; size <= 16; size++ {
			original := bytes.Repeat([]byte{0xa5}, size)
			padded := padData(append([]byte(nil), original...), 8, header)
			got := unpadData(padded)
			if got == nil || !bytes.Equal(got, original) {
				t.Fatalf("header=%d size=%d: padding round trip failed", header, size)
			}
		}
	}
}
