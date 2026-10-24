//go:build linux

package main

import (
	"bytes"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func batchTestQueue(count int, start uint32) *xdpQueue {
	q := &xdpQueue{rx: fakeXDPRing(16), fill: fakeXDPRing(8), umem: make([]byte, 2*xdpRingSize*xdpFrameSize)}
	*q.rx.consumer, *q.rx.producer = start, start+uint32(count)
	for i := 0; i < count; i++ {
		addr := uint64(i*xdpFrameSize + 256)
		q.umem[addr] = byte(i + 1)
		*q.rx.packet(start + uint32(i)) = unix.XDPDesc{Addr: addr, Len: 1}
	}
	return q
}

func TestXDPBatchOwnershipWrapAndFairness(t *testing.T) {
	q0 := batchTestQueue(batchSize+1, ^uint32(0)-7)
	q1 := batchTestQueue(1, 0)
	x := &xdpIO{queues: []*xdpQueue{q0, q1}}
	reader := newPacketReader(x)
	for i := 0; i < batchSize; i++ {
		got, err := reader.ReadPacket()
		if err != nil || !bytes.Equal(got, []byte{byte(i + 1)}) {
			t.Fatalf("packet %d: %x %v", i, got, err)
		}
		if *q0.fill.producer != 0 {
			t.Fatal("borrowed batch recycled before the reader drained it")
		}
	}
	if *q0.rx.consumer != 8 {
		t.Fatalf("RX counter did not wrap: %d", *q0.rx.consumer)
	}
	// A different ready queue gets a turn after at most one batch.
	if got, err := reader.ReadPacket(); err != nil || !bytes.Equal(got, []byte{1}) || x.held != q1 {
		t.Fatalf("next queue: %x %v", got, err)
	}
	if *q0.fill.producer != batchSize {
		t.Fatalf("batch not returned: %d", *q0.fill.producer)
	}
	for i := uint32(0); i < batchSize; i++ {
		if *q0.fill.address(i) != uint64(i)*xdpFrameSize {
			t.Fatalf("wrong frame returned at %d", i)
		}
	}
	// A sparse tail returns immediately; no timer or full batch is required.
	if got, err := reader.ReadPacket(); err != nil || !bytes.Equal(got, []byte{17}) {
		t.Fatalf("sparse tail: %x %v", got, err)
	}
}

func TestXDPBatchPartialFillPublication(t *testing.T) {
	wake, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(wake)
	q := batchTestQueue(batchSize+1, 0)
	p := ^uint32(0) - 3
	*q.fill.producer, *q.fill.consumer = p, p-xdpRingSize+3
	x := &xdpIO{wake: wake, queues: []*xdpQueue{q}}
	var packets [batchSize][]byte
	if n, err := x.ReadPacketBatch(packets[:]); err != nil || n != batchSize {
		t.Fatalf("first batch: %d %v", n, err)
	}
	done := make(chan error, 1)
	go func() {
		var next [batchSize][]byte
		n, err := x.ReadPacketBatch(next[:])
		if err == nil && (n != 1 || !bytes.Equal(next[0], []byte{17})) {
			err = fmt.Errorf("tail batch: %d %x", n, next[0])
		}
		done <- err
	}()
	defer func() { atomic.StoreUint32(q.fill.consumer, p) }()
	deadline := time.Now().Add(time.Second)
	for atomic.LoadUint32(q.fill.producer) != p+3 {
		if time.Now().After(deadline) {
			t.Fatal("available FILL slots were not published")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-done:
		t.Fatalf("recycled into a full ring: %v", err)
	default:
	}
	atomic.StoreUint32(q.fill.consumer, p)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("batch recycling did not resume")
	}
	if *q.fill.producer != p+batchSize {
		t.Fatal("wrong number of returned frames")
	}
	for i := uint32(0); i < batchSize; i++ {
		if *q.fill.address(p + i) != uint64(i)*xdpFrameSize {
			t.Fatalf("frame %d lost or duplicated", i)
		}
	}
}

func TestXDPInvalidBatchPreservesOwnership(t *testing.T) {
	q := batchTestQueue(2, 0)
	q.rx.packet(1).Len = xdpFrameSize // Overflows the frame after headroom.
	x := &xdpIO{queues: []*xdpQueue{q}}
	var packets [batchSize][]byte
	n, err := x.ReadPacketBatch(packets[:])
	if err == nil || n != 0 || x.held != nil || *q.rx.consumer != 0 || *q.fill.producer != 0 || packets[0] != nil {
		t.Fatalf("invalid batch changed ownership: n=%d err=%v", n, err)
	}
}

type singlePacketTestReceiver struct{ calls int }

func (r *singlePacketTestReceiver) ReadPacket() ([]byte, error) {
	r.calls++
	return []byte{byte(r.calls)}, nil
}
func (r *singlePacketTestReceiver) Close() error { return nil }

func TestPacketReaderSinglePacketFallback(t *testing.T) {
	r := &singlePacketTestReceiver{}
	reader := newPacketReader(r)
	for i := 1; i <= 3; i++ {
		got, err := reader.ReadPacket()
		if err != nil || !bytes.Equal(got, []byte{byte(i)}) || r.calls != i {
			t.Fatalf("fallback receive %d: %x %v", i, got, err)
		}
	}
}

// Synthetic ring bookkeeping only: no NIC, kernel wakeups, UDP or WireGuard.
// Each operation consumes 16 frames; compare the same current implementation
// through its single-packet API versus the production batched reader.
func BenchmarkXDPReceiveBookkeeping(b *testing.B) {
	for _, batch := range []bool{false, true} {
		b.Run(fmt.Sprintf("batch=%t", batch), func(b *testing.B) {
			q := batchTestQueue(xdpRingSize, 0)
			*q.rx.producer = 0
			x := &xdpIO{queues: []*xdpQueue{q}}
			var receiver interface{ ReadPacket() ([]byte, error) } = x
			if batch {
				receiver = newPacketReader(x)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				atomic.StoreUint32(q.fill.consumer, atomic.LoadUint32(q.fill.producer))
				atomic.AddUint32(q.rx.producer, batchSize)
				for j := 0; j < batchSize; j++ {
					if _, err := receiver.ReadPacket(); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
