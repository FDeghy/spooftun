//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
)

func TestNoiseFramingAndPayloadCollision(t *testing.T) {
	n, err := newPacketNoise(true, nil)
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
	n, err := newPacketNoise(false, nil)
	if err != nil || n != nil {
		t.Fatal("disabled noise initialized")
	}
	n, err = newPacketNoise(true, nil)
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

func TestNoiseBase64Content(t *testing.T) {
	want := []byte{0, 255, 'h', 'e', 'l', 'l', 'o'}
	for _, encoded := range []string{base64.StdEncoding.EncodeToString(want), base64.RawStdEncoding.EncodeToString(want)} {
		content, err := decodeNoisePayload(" \n" + encoded + "\t")
		if err != nil || !bytes.Equal(content, want) {
			t.Fatalf("Base64 decode: %x %v", content, err)
		}
	}
	for _, encoded := range []string{"%%%", "a", "AA===", "-_8="} {
		if _, err := decodeNoisePayload(encoded); err == nil {
			t.Fatalf("invalid standard Base64 accepted: %q", encoded)
		}
	}
	if content, err := decodeNoisePayload(""); err != nil || content != nil {
		t.Fatal("empty setting must select random noise")
	}
	if _, err := decodeNoisePayload(base64.StdEncoding.EncodeToString(make([]byte, 65500))); err == nil {
		t.Fatal("oversized Base64 content accepted")
	}
}

func TestNoiseCustomContentWireAndMTU(t *testing.T) {
	e, _ := newTunnelEncoder(encoderSrcMAC, encoderDstMAC, encoderSrcIP, encoderDstIP, 17, false, 0)
	for _, size := range []int{0, 1, 24, 1464} {
		content := bytes.Repeat([]byte{0xff}, size)
		if size == 0 {
			content = make([]byte, 0)
		}
		want := bytes.Clone(content)
		if err := validateNoisePayload(content, 1500); err != nil {
			t.Fatal(err)
		}
		n, err := newPacketNoise(true, content)
		if err != nil {
			t.Fatal(err)
		}
		clear(content) // Sender must own its configured content.
		storage := make([]byte, 1514)
		frame, err := n.Encode(e, storage, 12345, 40000)
		if err != nil {
			t.Fatal(err)
		}
		p, ok := parseEthIPv4(frame)
		if !ok || !isNoisePacket(p, false) {
			t.Fatalf("custom noise not recognized at size %d", size)
		}
		_, _, payload, ok := parseFakeTransport(p.payload, false)
		if !ok || !bytes.Equal(payload[len(noiseMagic):], want) || len(payload) != len(noiseMagic)+size {
			t.Fatalf("custom content changed at size %d", size)
		}
		if encoderFoldChecksum(encoderChecksumSum(frame[14:34], 0)) != 0 {
			t.Fatal("invalid custom noise IP checksum")
		}
		real, err := e.Encode(make([]byte, 1514), payload, 12345, 40000, 0, 0x4000, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		realPacket, _ := parseEthIPv4(real)
		if isNoisePacket(realPacket, false) {
			t.Fatal("identical real app content was classified as noise")
		}
		if allocs := testing.AllocsPerRun(100, func() {
			if _, err := n.Encode(e, storage, 12345, 40000); err != nil {
				panic(err)
			}
		}); allocs != 0 {
			t.Fatalf("custom encoding allocated %g objects", allocs)
		}
	}
	for _, tc := range []struct{ size, mtu int }{{1465, 1500}, {33, 68}} {
		if err := validateNoisePayload(make([]byte, tc.size), tc.mtu); err == nil {
			t.Fatalf("oversized noise accepted: %v", tc)
		}
	}
}
