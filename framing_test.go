//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
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
			src, dst, got, ok := parseFakeTransport(parsed.payload, tc.tcp)
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
