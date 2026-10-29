//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestTCEmbeddedObjectMatchesSource(t *testing.T) {
	const regenerate = "regenerate with CLANG=clang-18 sh scripts/build-tc-bpf.sh"
	manifest, err := os.ReadFile("bpf/tc.sha256")
	if err != nil {
		t.Fatalf("read TC build manifest: %v; %s", err, regenerate)
	}
	source, err := os.ReadFile("bpf/tc.c")
	if err != nil {
		t.Fatalf("read TC source: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	if len(lines) != 2 {
		t.Fatalf("TC build manifest must contain exactly two hashes; %s", regenerate)
	}
	for i, item := range []struct {
		name string
		data []byte
	}{{"bpf/tc.c", source}, {"bpf/tc_bpfel.o", tcObject}} {
		fields := strings.Fields(lines[i])
		if len(fields) != 2 || fields[1] != item.name {
			t.Fatalf("invalid TC manifest entry %d; %s", i+1, regenerate)
		}
		got := fmt.Sprintf("%x", sha256.Sum256(item.data))
		if got != fields[0] {
			t.Fatalf("stale TC source/object: %s SHA256=%s, manifest=%s; %s", item.name, got, fields[0], regenerate)
		}
	}
}

func TestTCConfigABI(t *testing.T) {
	if size := binary.Size(tcConfig{}); size != 72 {
		t.Fatalf("TC config size = %d, want 72", size)
	}
	c := tcTestConfig()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, c); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	if !bytes.Equal(b[:4], c.LocalIP[:]) || !bytes.Equal(b[20:24], c.WirePeerSrc[:]) ||
		binary.LittleEndian.Uint32(b[24:28]) != c.PhysicalIfindex ||
		binary.LittleEndian.Uint32(b[32:36]) != c.MTU ||
		binary.LittleEndian.Uint32(b[36:40]) != c.TXFlags ||
		!bytes.Equal(b[40:42], c.LocalPort[:]) || !bytes.Equal(b[46:48], c.WireRemotePort[:]) ||
		!bytes.Equal(b[48:54], c.WireDstMAC[:]) || !bytes.Equal(b[66:72], c.LocalSrcMAC[:]) {
		t.Fatal("TC config field offsets differ from C ABI")
	}
}

func TestTCOptionsValidation(t *testing.T) {
	base := tcOptions{Mode: "client", Address: "198.18.0.1/30", RemoteIP: "192.0.2.2", LocalPort: 51820, TargetPort: 40000, MTU: 1500, Flags: 0x06}
	for _, tc := range []struct {
		name  string
		edit  func(*tcOptions)
		valid bool
	}{
		{"client", func(o *tcOptions) {}, true},
		{"server", func(o *tcOptions) { o.Mode, o.PeerPort, o.OutboundPort = "server", 51820, 51820 }, true},
		{"port-boundaries", func(o *tcOptions) { o.LocalPort, o.TargetPort = 1, 65535 }, true},
		{"minimum-mtu", func(o *tcOptions) { o.MTU = 80 }, true},
		{"mtu-too-small", func(o *tcOptions) { o.MTU = 79 }, false},
		{"mtu-too-large", func(o *tcOptions) { o.MTU = 1501 }, false},
		{"spoof", func(o *tcOptions) { o.SourceIP, o.FilterIP, o.PeerSource = "198.51.100.1", "192.0.2.1", "203.0.113.1" }, true},
		{"mode", func(o *tcOptions) { o.Mode = "invalid" }, false},
		{"missing-remote", func(o *tcOptions) { o.RemoteIP = "" }, false},
		{"ipv6-remote", func(o *tcOptions) { o.RemoteIP = "2001:db8::1" }, false},
		{"loopback-remote", func(o *tcOptions) { o.RemoteIP = "127.0.0.1" }, false},
		{"multicast-source", func(o *tcOptions) { o.SourceIP = "224.0.0.1" }, false},
		{"unspecified-filter", func(o *tcOptions) { o.FilterIP = "0.0.0.0" }, false},
		{"bad-peer-source", func(o *tcOptions) { o.PeerSource = "invalid" }, false},
		{"local-port-zero", func(o *tcOptions) { o.LocalPort = 0 }, false},
		{"local-port-overflow", func(o *tcOptions) { o.LocalPort = 65536 }, false},
		{"target-port-negative", func(o *tcOptions) { o.TargetPort = -1 }, false},
		{"target-port-overflow", func(o *tcOptions) { o.TargetPort = 65536 }, false},
		{"server-missing-peer", func(o *tcOptions) { o.Mode = "server" }, false},
		{"server-peer-overflow", func(o *tcOptions) { o.Mode, o.PeerPort = "server", 65536 }, false},
		{"client-peer-port", func(o *tcOptions) { o.PeerPort = 51820 }, false},
		{"client-outbound-port", func(o *tcOptions) { o.OutboundPort = 51820 }, false},
		{"server-outbound-mismatch", func(o *tcOptions) { o.Mode, o.PeerPort, o.OutboundPort = "server", 51820, 51821 }, false},
		{"bad-prefix", func(o *tcOptions) { o.Address = "invalid" }, false},
		{"ipv6-prefix", func(o *tcOptions) { o.Address = "2001:db8::1/126" }, false},
		{"wrong-prefix-size", func(o *tcOptions) { o.Address = "198.18.0.1/24" }, false},
		{"network-address", func(o *tcOptions) { o.Address = "198.18.0.0/30" }, false},
		{"peer-address", func(o *tcOptions) { o.Address = "198.18.0.2/30" }, false},
		{"broadcast-address", func(o *tcOptions) { o.Address = "198.18.0.3/30" }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base
			tc.edit(&o)
			prefix, err := o.validate()
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t, got %v", tc.valid, err)
			}
			if err == nil && prefix.String() != o.Address {
				t.Fatalf("prefix changed: %s", prefix)
			}
		})
	}
}

func tcTestConfig() tcConfig {
	c := tcConfig{
		LocalIP: [4]byte{198, 18, 0, 1}, PeerIP: [4]byte{198, 18, 0, 2},
		WireLocalIP: [4]byte{192, 0, 2, 1}, WireSrcIP: [4]byte{198, 51, 100, 1},
		WirePeerIP: [4]byte{192, 0, 2, 2}, WirePeerSrc: [4]byte{192, 0, 2, 2},
		PhysicalIfindex: 1, VethIfindex: 1, MTU: 1500, TXFlags: 0x06,
		WireDstMAC: [6]byte{2, 0, 0, 0, 0, 2}, WireSrcMAC: [6]byte{2, 0, 0, 0, 0, 1},
		LocalDstMAC: [6]byte{2, 0, 0, 0, 1, 1}, LocalSrcMAC: [6]byte{2, 0, 0, 0, 1, 2},
	}
	binary.BigEndian.PutUint16(c.LocalPort[:], 51820)
	binary.BigEndian.PutUint16(c.RemotePort[:], 40000)
	binary.BigEndian.PutUint16(c.WireLocalPort[:], 51820)
	binary.BigEndian.PutUint16(c.WireRemotePort[:], 40000)
	return c
}

func tcFixture(t *testing.T, tcp bool, src, dst [4]byte, sport, dport [2]byte, payload []byte) []byte {
	t.Helper()
	proto := uint8(17)
	if tcp {
		proto = 6
	}
	e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, net.IP(src[:]), net.IP(dst[:]), proto, tcp, 0x06)
	if err != nil {
		t.Fatal(err)
	}
	p, err := e.Encode(make([]byte, 1600), payload, binary.BigEndian.Uint16(sport[:]), binary.BigEndian.Uint16(dport[:]), 0, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func tcCheckPacket(t *testing.T, packet, payload []byte, tcp bool, src, dst [4]byte, sport, dport [2]byte) {
	t.Helper()
	hdr, proto := 8, byte(17)
	if tcp {
		hdr, proto = 20, 6
	}
	ipLen := 20 + hdr + len(payload)
	if len(packet) < 14+ipLen || packet[23] != proto || int(binary.BigEndian.Uint16(packet[16:18])) != ipLen ||
		!bytes.Equal(packet[26:30], src[:]) || !bytes.Equal(packet[30:34], dst[:]) ||
		!bytes.Equal(packet[34:36], sport[:]) || !bytes.Equal(packet[36:38], dport[:]) ||
		!bytes.Equal(packet[34+hdr:14+ipLen], payload) {
		t.Fatalf("rewritten packet/header/payload differs: %x", packet)
	}
	if encoderFoldChecksum(encoderChecksumSum(packet[14:34], 0)) != 0 {
		t.Fatal("bad rewritten IPv4 checksum")
	}
	pseudo := encoderChecksumSum(packet[26:34], uint32(proto)+uint32(ipLen-20))
	if encoderFoldChecksum(encoderChecksumSum(packet[34:14+ipLen], pseudo)) != 0 {
		t.Fatal("bad rewritten transport checksum")
	}
}

// BPF_PROG_TEST_RUN executes the real kernel verifier/helpers without attaching
// to any interface. The redirect action is returned, not transmitted.
func TestTCKernelRewrite(t *testing.T) {
	if os.Getenv("SPOOFTUN_TC_TEST") != "1" {
		t.Skip("set SPOOFTUN_TC_TEST=1 for kernel TC tests")
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(tcObject))
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load TC: %+v", err)
	}
	defer collection.Close()
	c := tcTestConfig()
	if err := collection.Maps["config"].Update(uint32(0), c, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	execute := func(t *testing.T, name string, packet []byte, want uint32) []byte {
		t.Helper()
		ret, out, err := collection.Programs[name].Test(packet)
		if err != nil {
			t.Fatalf("%s run: %v", name, err)
		}
		if ret != want {
			t.Fatalf("%s action=%d, want %d", name, ret, want)
		}
		return out
	}
	for _, size := range []int{0, 1, 3, 1200, 1460} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i*31 + size)
			}
			udp := tcFixture(t, false, c.LocalIP, c.PeerIP, c.LocalPort, c.RemotePort, payload)
			out := execute(t, "tc_out", udp, 7)
			tcCheckPacket(t, out, payload, true, c.WireSrcIP, c.WirePeerIP, c.WireLocalPort, c.WireRemotePort)
			if !bytes.Equal(out[:6], c.WireDstMAC[:]) || !bytes.Equal(out[6:12], c.WireSrcMAC[:]) ||
				binary.BigEndian.Uint32(out[38:42]) != 1 || binary.BigEndian.Uint32(out[42:46]) != 0 ||
				out[46] != 0x50 || out[47] != 0x06 || binary.BigEndian.Uint16(out[48:50]) != 65535 {
				t.Fatal("fake TCP framing or wire Ethernet addresses differ")
			}
			// Legal IPv4 UDP zero-checksum input takes the bounded fallback.
			udp[40], udp[41] = 0, 0
			out = execute(t, "tc_out", udp, 7)
			tcCheckPacket(t, out, payload, true, c.WireSrcIP, c.WirePeerIP, c.WireLocalPort, c.WireRemotePort)
			incoming := tcFixture(t, true, c.WirePeerSrc, c.WireLocalIP, c.WireRemotePort, c.WireLocalPort, payload)
			out = execute(t, "tc_in", incoming, 7)
			tcCheckPacket(t, out, payload, false, c.PeerIP, c.LocalIP, c.RemotePort, c.LocalPort)
			if !bytes.Equal(out[:6], c.LocalDstMAC[:]) || !bytes.Equal(out[6:12], c.LocalSrcMAC[:]) {
				t.Fatal("local Ethernet addresses differ")
			}
		})
	}
	for _, incoming := range []bool{false, true} {
		name := "tc_out"
		src, dst, sport, dport := c.LocalIP, c.PeerIP, c.LocalPort, c.RemotePort
		if incoming {
			name, src, dst, sport, dport = "tc_in", c.WirePeerSrc, c.WireLocalIP, c.WireRemotePort, c.WireLocalPort
		}
		for _, check := range []struct {
			name   string
			edit   func([]byte) []byte
			action uint32
		}{
			{"unrelated-port", func(p []byte) []byte { p[35] ^= 1; return p }, ^uint32(0)},
			{"unrelated-address", func(p []byte) []byte { p[29] ^= 1; return p }, ^uint32(0)},
			{"fragment", func(p []byte) []byte { p[20] = 0x20; return p }, 2},
			{"noninitial-fragment", func(p []byte) []byte { p[21] = 1; return p }, ^uint32(0)},
			{"unrelated-first-fragment", func(p []byte) []byte { p[20] = 0x20; p[34] ^= 1; return p }, ^uint32(0)},
			{"short-ihl", func(p []byte) []byte { p[14] = 0x44; return p }, 2},
			{"truncated", func(p []byte) []byte { return p[:len(p)-1] }, 2},
			{"invalid-ip-checksum", func(p []byte) []byte { p[24] ^= 1; return p }, 2},
		} {
			t.Run(name+"/"+check.name, func(t *testing.T) {
				packet := tcFixture(t, incoming, src, dst, sport, dport, bytes.Repeat([]byte{0x7b}, 1200))
				execute(t, name, check.edit(packet), check.action)
			})
		}
		t.Run(name+"/oversize", func(t *testing.T) {
			execute(t, name, tcFixture(t, incoming, src, dst, sport, dport, make([]byte, 1461)), 2)
		})
	}
	t.Run("invalid-tcp-header", func(t *testing.T) {
		p := tcFixture(t, true, c.WirePeerSrc, c.WireLocalIP, c.WireRemotePort, c.WireLocalPort, []byte("data"))
		p[46] = 0x60
		execute(t, "tc_in", p, 2)
	})
	t.Run("invalid-tcp-checksum", func(t *testing.T) {
		p := tcFixture(t, true, c.WirePeerSrc, c.WireLocalIP, c.WireRemotePort, c.WireLocalPort, []byte("data"))
		p[54] ^= 1
		out := execute(t, "tc_in", p, 7)
		// Incremental conversion must preserve corruption as a bad, nonzero
		// UDP checksum, allowing the normal UDP stack to reject it. It must
		// never repair corruption or emit IPv4's checksum-disabled zero.
		ipLen := int(binary.BigEndian.Uint16(out[16:18]))
		pseudo := encoderChecksumSum(out[26:34], 17+uint32(ipLen-20))
		if binary.BigEndian.Uint16(out[40:42]) == 0 || encoderFoldChecksum(encoderChecksumSum(out[34:14+ipLen], pseudo)) == 0 {
			t.Fatal("TCP payload corruption became valid or unchecked UDP")
		}
	})
	t.Run("invalid-udp-length", func(t *testing.T) {
		p := tcFixture(t, false, c.LocalIP, c.PeerIP, c.LocalPort, c.RemotePort, []byte("data"))
		p[39] ^= 1
		execute(t, "tc_out", p, 2)
	})
}
