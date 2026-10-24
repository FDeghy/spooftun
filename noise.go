//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	randv2 "math/rand/v2"
	"strings"
)

const noisePayloadSize = 32

var noiseMagic = [8]byte{'S', 'T', 'N', 'O', 'I', 'S', 'E', 1}
var errNoiseMode = errors.New("noise requires protocol-17 UDP encoding")

// Each sender owns its generator. Seeding happens once, not on the packet hot
// path. Real tunnel UDP checksums are always nonzero; noise uses IPv4 UDP's
// legal zero-checksum form plus a versioned marker, without reserving app data.
type packetNoise struct {
	random  *randv2.ChaCha8
	payload []byte
}

// Mark queued first-packet noise immediately so later data in the same batch
// does not queue it again. Restore unsent attempts after a partial/failed send.
type noiseBatch struct {
	marks [batchSize]struct {
		index int
		sent  *bool
	}
	n int
}

func (b *noiseBatch) queued(index int, sent *bool) {
	*sent = true
	b.marks[b.n].index, b.marks[b.n].sent = index, sent
	b.n++
}

func (b *noiseBatch) WriteBatch(tx packetTransmitter, frames [][]byte) (int, error) {
	n, err := tx.WriteBatch(frames)
	for i := 0; i < b.n; i++ {
		if b.marks[i].index >= n {
			*b.marks[i].sent = false
		}
	}
	clear(b.marks[:b.n])
	b.n = 0
	return n, err
}

func decodeNoisePayload(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	// Bound allocation before decoding. IPv4 UDP has at most 65507 payload bytes.
	if len(encoded) > base64.StdEncoding.EncodedLen(65507-len(noiseMagic)) {
		return nil, fmt.Errorf("encoded payload is too large")
	}
	content, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		content, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("expected standard Base64, padded or unpadded: %w", err)
	}
	return content, nil
}

func validateNoisePayload(content []byte, mtu int) error {
	size := noisePayloadSize
	if content != nil {
		size = len(noiseMagic) + len(content)
	}
	limit := payloadLimit(mtu, false, false)
	if size > limit {
		return fmt.Errorf("noise content plus %d-byte marker is %d bytes; maximum is %d at MTU %d", len(noiseMagic), size, limit, mtu)
	}
	return nil
}

func newPacketNoise(enabled bool, content []byte) (*packetNoise, error) {
	if !enabled {
		return nil, nil
	}
	if content != nil {
		n := &packetNoise{payload: make([]byte, len(noiseMagic)+len(content))}
		copy(n.payload, noiseMagic[:])
		copy(n.payload[len(noiseMagic):], content)
		return n, nil
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	n := &packetNoise{random: randv2.NewChaCha8(seed), payload: make([]byte, noisePayloadSize)}
	copy(n.payload[:], noiseMagic[:])
	return n, nil
}

func (n *packetNoise) Encode(e *tunnelEncoder, dst []byte, srcPort, dstPort uint16) ([]byte, error) {
	if e.transportLen != 8 || e.template[23] != 17 {
		return nil, errNoiseMode
	}
	var id uint16
	if n.random != nil {
		_, _ = n.random.Read(n.payload[len(noiseMagic):])
		id = binary.BigEndian.Uint16(n.payload[len(noiseMagic):])
	}
	frame, err := e.Encode(dst, n.payload[:], srcPort, dstPort, id, 0x4000, 0, true)
	if err != nil {
		return nil, err
	}
	// IPv4 UDP checksum zero means omitted, not an invalid checksum. The IP
	// checksum and UDP length remain valid. Receivers distinguish this marker
	// from a real application's identical payload, whose checksum is nonzero.
	frame[40], frame[41] = 0, 0
	return frame, nil
}

func isNoisePacket(p ethIPv4, tcp bool) bool {
	return !tcp && p.proto == 17 && len(p.payload) >= 8+len(noiseMagic) &&
		int(binary.BigEndian.Uint16(p.payload[4:6])) == len(p.payload) &&
		binary.BigEndian.Uint16(p.payload[6:8]) == 0 &&
		bytes.Equal(p.payload[8:8+len(noiseMagic)], noiseMagic[:])
}
