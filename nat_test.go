//go:build linux

package main

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNATExhaustionAndReuse(t *testing.T) {
	n := newNatTable()
	ip := net.IPv4(192, 0, 2, 1)
	for port := range len(n.reverse) {
		got, err := n.GetOrCreateVirtualPort(ip, port)
		if err != nil || got != uint16(port) {
			t.Fatalf("allocate %d: got %d, %v", port, got, err)
		}
	}
	if _, err := n.GetOrCreateVirtualPort(net.IPv4(192, 0, 2, 2), 1234); !errors.Is(err, errNATExhausted) {
		t.Fatalf("full table: got %v, want errNATExhausted", err)
	}
	// The fallback search must find both the low range and port 65535.
	for i, freed := range []uint16{1, 65535} {
		s := n.reverse[freed].Load()
		n.expireSession(freed, s, atomic.LoadInt64(&s.lastSeen))
		got, err := n.GetOrCreateVirtualPort(net.IPv4(192, 0, 2, byte(i+2)), 1234)
		if err != nil || got != freed {
			t.Fatalf("reuse %d: got %d, %v", freed, got, err)
		}
	}
}

func TestNATRefreshWinsOverStaleCleanup(t *testing.T) {
	n := newNatTable()
	ip := net.IPv4(192, 0, 2, 1)
	port, err := n.GetOrCreateVirtualPort(ip, 1234)
	if err != nil {
		t.Fatal(err)
	}
	s := n.reverse[port].Load()
	observed := time.Now().Add(-2 * time.Minute).UnixNano()
	atomic.StoreInt64(&s.lastSeen, observed)
	if n.GetSession(port) != s {
		t.Fatal("downlink refresh lost session")
	}
	// Simulate cleanup having already observed the old timestamp before
	// a packet refreshed it, then resuming to remove that session.
	n.expireSession(port, s, observed)
	if n.GetSession(port) != s {
		t.Fatal("cleanup deleted a freshly refreshed mapping")
	}
	n.cleanupOnce(time.Now())
	if n.reverse[port].Load() != s {
		t.Fatal("cleanup deleted an active mapping")
	}
	n.cleanupOnce(time.Now().Add(2 * time.Minute))
	if n.GetSession(port) != nil || len(n.forward) != 0 {
		t.Fatal("idle session was not removed from both directions")
	}
	if s.refresh(time.Now().UnixNano()) {
		t.Fatal("retired session was revived")
	}
	if _, err := n.GetOrCreateVirtualPort(ip, 1234); err != nil {
		t.Fatal(err)
	}
	n.expireSession(port, s, retiredSessionTime)
	if replacement := n.GetSession(port); replacement == nil || replacement == s {
		t.Fatal("stale cleanup removed a replacement session")
	}
}

func TestNATConcurrentAllocation(t *testing.T) {
	n := newNatTable()
	ip := net.IPv4(192, 0, 2, 1)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := 1024; port < 1088; port++ {
				v, err := n.GetOrCreateVirtualPort(ip, port)
				if err != nil {
					t.Error(err)
					return
				}
				if s := n.GetSession(v); s == nil || s.clientPort != port {
					t.Errorf("missing or mismatched session for %d", port)
				}
			}
		}()
	}
	wg.Wait()
	if len(n.forward) != 64 {
		t.Fatalf("got %d forward entries, want 64", len(n.forward))
	}
	live := 0
	for i := range n.reverse {
		if n.reverse[i].Load() != nil {
			live++
		}
	}
	if live != 64 {
		t.Fatalf("got %d reverse entries, want 64", live)
	}
}

func BenchmarkNATGetSession(b *testing.B) {
	n := newNatTable()
	port, _ := n.GetOrCreateVirtualPort(net.IPv4(192, 0, 2, 1), 1234)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if n.GetSession(port) == nil {
			b.Fatal("session missing")
		}
	}
}

func BenchmarkNATExistingFlow(b *testing.B) {
	n := newNatTable()
	ip := net.IPv4(192, 0, 2, 1)
	n.GetOrCreateVirtualPort(ip, 1234)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := n.GetOrCreateVirtualPort(ip, 1234); err != nil {
			b.Fatal(err)
		}
	}
}
