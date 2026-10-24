//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestNoiseFramingAndPayloadCollision(t *testing.T) {
	n, err := newPacketNoise(true)
	if err != nil {
		t.Fatal(err)
	}
	e, err := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 17, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	storage := make([]byte, 1514)
	frame, err := n.Encode(e, storage, 12345, 40000)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := parseEthIPv4(frame)
	if !ok || !isNoisePacket(p, false) || isNoisePacket(p, true) {
		t.Fatal("noise classification failed")
	}
	src, dst, payload, ok := parseFakeTransport(p.payload, false)
	if !ok || src != 12345 || dst != 40000 || len(payload) != noisePayloadSize {
		t.Fatal("noise changed the tunnel flow")
	}
	if encoderFoldChecksum(encoderChecksumSum(frame[14:34], 0)) != 0 || binary.BigEndian.Uint16(p.payload[4:6]) != 8+noisePayloadSize {
		t.Fatal("invalid noise IP checksum or UDP length")
	}
	previous := bytes.Clone(frame)
	other, err := n.Encode(e, make([]byte, 1514), 12345, 40000)
	if err != nil || bytes.Equal(previous[42:], other[42:]) || !bytes.Equal(frame, previous) {
		t.Fatal("noise randomization or buffer ownership failed")
	}
	// An application is allowed to send the exact noise payload. Its real UDP
	// checksum is nonzero, so it must still reach the peer unchanged.
	for _, frag := range []bool{false, true} {
		data := bytes.Clone(previous[42:])
		flags := uint16(0x4000)
		if frag {
			data = padData(data, 8, 8)
			flags = 0x2000
		}
		real, err := e.Encode(storage, data, 12345, 40000, 1, flags, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		p, ok := parseEthIPv4(real)
		if !ok || isNoisePacket(p, false) {
			t.Fatal("real application data misclassified as noise")
		}
		_, _, got, _ := parseFakeTransport(p.payload, false)
		if frag {
			got = unpadData(got)
		}
		if !bytes.Equal(got, previous[42:]) {
			t.Fatal("real marker-like payload changed")
		}
	}
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := n.Encode(e, storage, 12345, 40000); err != nil {
			panic(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("noise allocated %g objects per packet", allocs)
	}
}

func TestNoiseModeAndTruncation(t *testing.T) {
	n, err := newPacketNoise(false)
	if err != nil || n != nil {
		t.Fatal("disabled noise initialized")
	}
	n, err = newPacketNoise(true)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		proto uint8
		tcp   bool
	}{{200, false}, {17, true}, {6, true}} {
		e, _ := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, tc.proto, tc.tcp, 0x18)
		if _, err := n.Encode(e, make([]byte, 1514), 1, 2); !errors.Is(err, errNoiseMode) {
			t.Fatalf("unsupported noise mode: %v", err)
		}
	}
	e, _ := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 17, false, 0)
	frame, _ := n.Encode(e, make([]byte, 1514), 1, 2)
	for i := 0; i < len(frame); i++ {
		p, ok := parseEthIPv4(frame[:i])
		if ok && isNoisePacket(p, false) {
			t.Fatalf("truncated noise accepted at %d", i)
		}
	}
}

type noiseResultSender struct {
	n   int
	err error
}

func (s noiseResultSender) WriteBatch([][]byte) (int, error) { return s.n, s.err }
func (s noiseResultSender) Close() error                     { return nil }

func TestNoiseOnceStateTracksAcceptedFrames(t *testing.T) {
	for _, accepted := range []int{0, 1, 3, 4, 6} {
		var pending noiseBatch
		var sent [3]bool
		for i, index := range []int{0, 3, 5} {
			pending.queued(index, &sent[i])
			if !sent[i] {
				t.Fatal("queued noise could be repeated in the same batch")
			}
		}
		failure := errors.New("partial first batch")
		if n, err := pending.WriteBatch(noiseResultSender{accepted, failure}, make([][]byte, 6)); n != accepted || !errors.Is(err, failure) {
			t.Fatal("send result changed")
		}
		for i, index := range []int{0, 3, 5} {
			if sent[i] != (index < accepted) {
				t.Fatalf("accepted=%d noise at %d: sent=%t", accepted, index, sent[i])
			}
		}
		if pending.n != 0 {
			t.Fatal("noise marks retained after submission")
		}
		for _, mark := range pending.marks {
			if mark.sent != nil {
				t.Fatal("noise batch retained a session")
			}
		}
	}
}
