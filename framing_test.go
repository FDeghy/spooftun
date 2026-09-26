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
