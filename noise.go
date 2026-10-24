//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	randv2 "math/rand/v2"
)

const noisePayloadSize = 32

var noiseMagic = [8]byte{'S', 'T', 'N', 'O', 'I', 'S', 'E', 1}
var errNoiseMode = errors.New("noise requires protocol-17 UDP encoding")

// Each sender owns its generator. Seeding happens once, not on the packet hot
// path. Real tunnel UDP checksums are always nonzero; noise uses IPv4 UDP's
// legal zero-checksum form plus a versioned marker, without reserving app data.
type packetNoise struct {
	random  *randv2.ChaCha8
	payload [noisePayloadSize]byte
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

func newPacketNoise(enabled bool) (*packetNoise, error) {
	if !enabled {
		return nil, nil
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	n := &packetNoise{random: randv2.NewChaCha8(seed)}
	copy(n.payload[:], noiseMagic[:])
	return n, nil
}

func (n *packetNoise) Encode(e *tunnelEncoder, dst []byte, srcPort, dstPort uint16) ([]byte, error) {
	if e.transportLen != 8 || e.template[23] != 17 {
		return nil, errNoiseMode
	}
	_, _ = n.random.Read(n.payload[len(noiseMagic):])
	id := binary.BigEndian.Uint16(n.payload[len(noiseMagic):])
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
	return !tcp && p.proto == 17 && len(p.payload) == 8+noisePayloadSize &&
		binary.BigEndian.Uint16(p.payload[4:6]) == 8+noisePayloadSize &&
		binary.BigEndian.Uint16(p.payload[6:8]) == 0 &&
		bytes.Equal(p.payload[8:8+len(noiseMagic)], noiseMagic[:])
}
