//go:build linux

package main

import (
	"net"
	"testing"
)

func BenchmarkTUNFlowPort(b *testing.B) {
	p := testTUNIPv4(1472)
	b.ReportAllocs()
	for b.Loop() {
		tunFlowPort(p)
	}
}

func BenchmarkTUNFraming(b *testing.B) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	enc, err := newTunnelEncoder(mac, mac, net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2), 200, false, 0)
	if err != nil {
		b.Fatal(err)
	}
	p, dst := testTUNIPv4(1472), make([]byte, 1514)
	b.SetBytes(int64(len(p)))
	b.ReportAllocs()
	for b.Loop() {
		frame, err := enc.Encode(dst, p, tunFlowPort(p), 8080, 1, 0x4000, 0, true)
		if err != nil {
			b.Fatal(err)
		}
		parsed, ok := parseEthIPv4(frame)
		_, _, payload, transportOK := parseTunnelTransport(parsed, false)
		if !ok || !transportOK || !validTUNPacket(payload, 1472) {
			b.Fatal("invalid round trip")
		}
	}
}
