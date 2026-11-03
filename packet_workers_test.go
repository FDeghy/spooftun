//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/net/bpf"
)

func TestPacketWorkerValidation(t *testing.T) {
	for _, tc := range []struct {
		backend, distribution string
		count                 int
		valid                 bool
	}{
		{"afpacket", "flow", 1, true}, {"afpacket", "flow", 2, true}, {"afpacket", "spread", 2, true},
		{"xdp", "flow", 1, true}, {"tc", "flow", 1, true},
		{"afpacket", "flow", 0, false}, {"afpacket", "flow", 65, false}, {"afpacket", "random", 2, false},
		{"xdp", "flow", 2, false}, {"tc", "spread", 1, false},
	} {
		if err := validatePacketWorkers(tc.backend, tc.count, tc.distribution); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

func TestPacketFlowSteering(t *testing.T) {
	vm, err := bpf.NewVM(packetFlowSteering())
	if err != nil {
		t.Fatal(err)
	}
	for _, proto := range []byte{6, 17, 200} {
		for _, ihl := range []int{20, 24, 60} {
			counts := [4]int{}
			for port := 10000; port < 10256; port++ {
				frame := make([]byte, ihl+20+8)
				frame[0] = 0x40 | byte(ihl/4)
				binary.BigEndian.PutUint16(frame[2:4], uint16(len(frame)))
				frame[9] = proto
				copy(frame[12:20], []byte{192, 0, 2, 1, 192, 0, 2, 2})
				binary.BigEndian.PutUint16(frame[ihl:], uint16(port))
				binary.BigEndian.PutUint16(frame[2+ihl:], 51820)
				first, e := vm.Run(frame)
				if e != nil {
					t.Fatal(e)
				}
				counts[uint32(first)%4]++
				// Payload/checksum/IP-ID changes must not move a visible flow.
				frame[len(frame)-1] = 99
				frame[4] = 17
				frame[10] = 42
				second, e := vm.Run(frame)
				if e != nil || first != second {
					t.Fatal("unstable flow steering")
				}
			}
			for lane, n := range counts {
				if n < 32 {
					t.Fatalf("proto=%d IHL=%d lane=%d count=%d", proto, ihl, lane, n)
				}
			}
		}
	}
	for size := 0; size < 34; size++ {
		if _, err := vm.Run(make([]byte, size)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestServerSessionConcurrentCreation(t *testing.T) {
	var sessions sync.Map
	var mu sync.Mutex
	var calls atomic.Int32
	key := makeNatKey([]byte{192, 0, 2, 1}, 1234)
	create := func() (*serverSession, error) {
		calls.Add(1)
		s := new(serverSession)
		s.lastSeen.Store(sessionActivityTime())
		return s, nil
	}
	var wg sync.WaitGroup
	results := make(chan *serverSession, 64)
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			s, _, err := acquireServerSession(&sessions, &mu, key, create)
			if err != nil {
				t.Error(err)
			}
			results <- s
		})
	}
	wg.Wait()
	close(results)
	var first *serverSession
	for s := range results {
		if first == nil {
			first = s
		}
		if s != first {
			t.Fatal("duplicate session published")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("created %d sessions", calls.Load())
	}
	first.lastSeen.Store(retiredSessionTime)
	second, created, err := acquireServerSession(&sessions, &mu, key, create)
	if err != nil || !created || second == first || calls.Load() != 2 {
		t.Fatal("retired session not replaced")
	}
	failedKey := makeNatKey([]byte{192, 0, 2, 1}, 4321)
	want := errors.New("dial failed")
	if _, _, err := acquireServerSession(&sessions, &mu, failedKey, func() (*serverSession, error) { return nil, want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if _, ok := sessions.Load(failedKey); ok {
		t.Fatal("failed creation published")
	}
}
