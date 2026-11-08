//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type tunTestReceiver struct{ frames [][]byte }

func (r *tunTestReceiver) ReadPacket() ([]byte, error) {
	if len(r.frames) == 0 {
		return nil, io.EOF
	}
	f := r.frames[0]
	r.frames = r.frames[1:]
	return f, nil
}
func (r *tunTestReceiver) Close() error { return nil }

type tunBatchTestSender struct {
	t       *testing.T
	count   int
	batches []int
}

var errTUNBatchTestDone = errors.New("TUN batch test complete")

func (s *tunBatchTestSender) WriteBatch(frames [][]byte) (int, error) {
	s.batches = append(s.batches, len(frames))
	for _, frame := range frames {
		p, ok := parseEthIPv4(frame)
		_, _, inner, transportOK := parseTunnelTransport(p, false)
		if !ok || !transportOK || !validTUNPacket(inner, 1472) || inner[50] != byte(s.count) {
			s.t.Fatal("TUN batch dropped, reordered or corrupted a packet")
		}
		s.count++
	}
	if s.count == 70 {
		return len(frames), errTUNBatchTestDone
	}
	return len(frames), nil
}
func (s *tunBatchTestSender) Close() error { return nil }

func TestTUNTransmitBatchBoundaries(t *testing.T) {
	t.Run("single-worker", func(t *testing.T) { testTUNTransmitBatch(t, 1, 64) })
	t.Run("multiple-workers", func(t *testing.T) { testTUNTransmitBatch(t, 2, 16) })
}

func testTUNTransmitBatch(t *testing.T, workers, limit int) {
	t.Helper()
	oldWorkers := *packetWorkers
	*packetWorkers = workers
	t.Cleanup(func() { *packetWorkers = oldWorkers })
	oldFrag := *fakeFrag
	*fakeFrag = false
	t.Cleanup(func() { *fakeFrag = oldFrag })
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	q := os.NewFile(uintptr(fds[0]), "tun-batch-test")
	defer q.Close()
	defer unix.Close(fds[1])
	if err := q.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 70; i++ {
		p := testTUNIPv4(100)
		p[50] = byte(i)
		if _, err := unix.Write(fds[1], p); err != nil {
			t.Fatal(err)
		}
	}
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	enc, err := newTunnelEncoder(mac, mac, net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2), 200, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	sender := &tunBatchTestSender{t: t}
	if err := tunTransmit(q, sender, enc, 1500, 1472, true); !errors.Is(err, errTUNBatchTestDone) {
		t.Fatal(err)
	}
	if len(sender.batches) != (70+limit-1)/limit {
		t.Fatalf("unexpected batches: %v", sender.batches)
	}
	for i, n := range sender.batches {
		if n != min(limit, 70-i*limit) {
			t.Fatalf("unexpected batches: %v", sender.batches)
		}
	}
}

func TestTUNReceivePeerAndPacketValidation(t *testing.T) {
	oldTCP, oldFrag := *fakeTCP, *fakeFrag
	*fakeTCP, *fakeFrag = false, false
	t.Cleanup(func() { *fakeTCP, *fakeFrag = oldTCP, oldFrag })
	localMAC := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	peerMAC := net.HardwareAddr{2, 0, 0, 0, 0, 2}
	local, peer := net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2)
	encode := func(src, dst net.IP, payload []byte) []byte {
		enc, err := newTunnelEncoder(peerMAC, localMAC, src, dst, 200, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		frame, err := enc.Encode(make([]byte, 1600), payload, 8080, 12000, 1, 0x4000, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		return frame
	}
	payload := testTUNIPv4(100)
	corrupt := encode(peer, local, payload)
	corrupt[len(corrupt)-1] ^= 1
	r := &tunTestReceiver{frames: [][]byte{
		encode(net.IPv4(192, 0, 2, 3), local, payload),
		encode(peer, net.IPv4(192, 0, 2, 3), payload),
		corrupt,
		encode(peer, local, []byte{0x45}),
		encode(peer, local, testTUNIPv4(1473)),
		encode(peer, local, payload),
	}}
	path := filepath.Join(t.TempDir(), "injected")
	q, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	filter := newTunnelPacketFilter(200, localMAC, local, 8080, true)
	if err := tunReceive(q, r, filter, peer, local, 1472, true); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("injected unvalidated traffic: len=%d err=%v", len(got), err)
	}
}

func testTUNIPv4(size int) []byte {
	p := make([]byte, size)
	p[0], p[8], p[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	copy(p[12:20], []byte{198, 18, 0, 1, 198, 18, 0, 2})
	binary.BigEndian.PutUint16(p[10:12], encoderFoldChecksum(encoderChecksumSum(p[:20], 0)))
	return p
}

func TestTUNPacketValidation(t *testing.T) {
	p := testTUNIPv4(1472)
	if !validTUNPacket(p, 1472) || validTUNPacket(p, 1471) {
		t.Fatal("IPv4 MTU boundary")
	}
	for _, bad := range [][]byte{nil, {0x40}, append(append([]byte{}, p...), 0), p[:len(p)-1]} {
		if validTUNPacket(bad, 1500) {
			t.Fatal("accepted malformed packet")
		}
	}
	p[8] ^= 1
	if validTUNPacket(p, 1500) {
		t.Fatal("accepted corrupt IPv4 header")
	}
	v6 := make([]byte, 1280)
	v6[0] = 0x60
	binary.BigEndian.PutUint16(v6[4:6], 1240)
	if !validTUNPacket(v6, 1280) || validTUNPacket(v6, 1279) || validTUNPacket(v6[:1279], 1500) {
		t.Fatal("IPv6 boundary")
	}
}

func TestTUNMTUFraming(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, tcp := range []bool{false, true} {
		for _, frag := range []bool{false, true} {
			enc, err := newTunnelEncoder(mac, mac, net.IPv4(192, 0, 2, 1), net.IPv4(192, 0, 2, 2), 200, tcp, 0x18)
			if err != nil {
				t.Fatal(err)
			}
			for outer := 1280; outer <= 1520; outer++ {
				inner := payloadLimit(outer, tcp, frag)
				p := testTUNIPv4(inner)
				if frag {
					p = padData(p, 8, enc.transportLen)
				}
				frame, err := enc.Encode(make([]byte, outer+14), p, 12000, 8080, 1, 0, 0, true)
				if err != nil || len(frame)-14 > outer {
					t.Fatalf("outer=%d tcp=%t frag=%t: %v", outer, tcp, frag, err)
				}
				parsed, ok := parseEthIPv4(frame)
				if !ok {
					t.Fatal("outer parse")
				}
				_, _, got, ok := parseTunnelTransport(parsed, tcp)
				if frag {
					got = unpadData(got)
				}
				if !ok || !validTUNPacket(got, inner) {
					t.Fatal("inner round trip")
				}
				// One more inner byte cannot fit, including mandatory padding.
				tooBig := testTUNIPv4(inner + 1)
				if frag {
					tooBig = padData(tooBig, 8, enc.transportLen)
				}
				if 20+enc.transportLen+len(tooBig) <= outer {
					t.Fatal("MTU is unnecessarily small")
				}
			}
		}
	}
}

func TestTUNFlowSteering(t *testing.T) {
	p := testTUNIPv4(100)
	seen := map[uint16]bool{}
	for port := 10000; port < 10100; port++ {
		binary.BigEndian.PutUint16(p[20:22], uint16(port))
		key := tunFlowPort(p)
		p[50]++
		if key != tunFlowPort(p) || key < 1024 {
			t.Fatal("flow hash depends on payload")
		}
		seen[key] = true
	}
	if len(seen) < 90 {
		t.Fatal("poor flow distribution")
	}
	binary.BigEndian.PutUint16(p[6:8], 0x2000)
	first := tunFlowPort(p)
	binary.BigEndian.PutUint16(p[6:8], 1)
	clear(p[20:24])
	if first != tunFlowPort(p) {
		t.Fatal("fragments changed worker")
	}
}
