//go:build linux

package main

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestAFPacketRingSizing(t *testing.T) {
	for _, mtu := range []int{68, 1000, 1280, 1500, 9000} {
		for _, page := range []int{4096, 65536} {
			for _, budget := range []int{1, 16} {
				t.Run(fmt.Sprintf("MTU%d/page%d/MiB%d", mtu, page, budget), func(t *testing.T) {
					snaplen := mtu + 14 + 128
					frame, block, count, err := afpacketComputeSize(budget, snaplen, page)
					if err != nil {
						t.Fatal(err)
					}
					if frame < snaplen || frame%16 != 0 || block%frame != 0 || block%page != 0 || count < 1 {
						t.Fatalf("invalid ring: frame=%d block=%d count=%d", frame, block, count)
					}
					if block*count > budget*1024*1024 {
						t.Fatal("ring exceeds budget")
					}
				})
			}
		}
	}
}

func TestAFPacketRingInvalidSizes(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, args := range [][3]int{
		{0, 2048, 4096}, {-1, 2048, 4096}, {maxInt, 2048, 4096},
		{1, 0, 4096}, {1, -1, 4096}, {1, maxInt, 4096},
		{1, 2048, 0}, {1, 2048, -1}, {1, 2048, 3}, {1, 2048, 6000},
		{1, 2 * 1024 * 1024, 4096}, {1, 2048, 2 * 1024 * 1024},
	} {
		if _, _, _, err := afpacketComputeSize(args[0], args[1], args[2]); err == nil {
			t.Errorf("expected error for %v", args)
		}
	}
}

func TestRouteNextHop(t *testing.T) {
	// /proc/net/route stores IPv4 addresses and masks in little-endian hex.
	const routes = `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth1 00000000 0100000A 0003 0 0 0 00000000 0 0 0
eth0 00000000 010200C0 0003 0 0 100 00000000 0 0 0
eth0 00000000 020200C0 0003 0 0 200 00000000 0 0 0
eth0 000200C0 00000000 0001 0 0 100 00FFFFFF 0 0 0
eth0 006433C6 030200C0 0003 0 0 999 00FFFFFF 0 0 0
eth0 000000CB 00000000 0201 0 0 0 00FFFFFF 0 0 0
eth0 003355CB 040200C0 0002 0 0 0 00FFFFFF 0 0 0
`
	for _, tc := range []struct{ name, iface, destination, want string }{
		{"selected interface default", "eth0", "8.8.8.8", "192.0.2.1"},
		{"other interface default", "eth1", "8.8.8.8", "10.0.0.1"},
		{"direct neighbor", "eth0", "192.0.2.99", "192.0.2.99"},
		{"specific gateway beats default", "eth0", "198.51.100.99", "192.0.2.3"},
		{"reject beats default", "eth0", "203.0.0.7", ""},
		{"down route ignored", "eth0", "203.85.51.7", "192.0.2.1"},
		{"no interface route", "eth2", "8.8.8.8", ""},
		{"IPv6 rejected", "eth0", "2001:db8::1", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := routeNextHop(strings.NewReader(routes), tc.iface, net.ParseIP(tc.destination))
			if tc.want == "" {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil || !got.Equal(net.ParseIP(tc.want)) {
				t.Fatalf("got %v, %v; want %s", got, err, tc.want)
			}
		})
	}
}

func TestParseARPCache(t *testing.T) {
	const header = "IP address HW type Flags HW address Mask Device\n"
	for _, tc := range []struct{ name, rows, want string }{
		{"interface scoped", "192.0.2.1 0x1 0x2 02:00:00:00:00:01 * eth1\n192.0.2.1 0x1 0x6 02:00:00:00:00:02 * eth0\n", "02:00:00:00:00:02"},
		{"incomplete", "192.0.2.1 0x1 0x0 02:00:00:00:00:01 * eth0\n", ""},
		{"permanent without complete flag", "192.0.2.1 0x1 0x4 02:00:00:00:00:01 * eth0\n", ""},
		{"all zero", "192.0.2.1 0x1 0x2 00:00:00:00:00:00 * eth0\n", ""},
		{"broadcast", "192.0.2.1 0x1 0x2 ff:ff:ff:ff:ff:ff * eth0\n", ""},
		{"multicast", "192.0.2.1 0x1 0x2 01:00:5e:00:00:01 * eth0\n", ""},
		{"other IP", "192.0.2.2 0x1 0x2 02:00:00:00:00:01 * eth0\n", ""},
		{"malformed", "192.0.2.1 0x1 bogus invalid * eth0\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parseARPCache(strings.NewReader(header+tc.rows), "eth0", net.ParseIP("192.0.2.1"))
			if got.String() != tc.want {
				t.Fatalf("got %q; want %q", got, tc.want)
			}
		})
	}
}
