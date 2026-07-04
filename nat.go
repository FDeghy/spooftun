//go:build linux

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// natKey is a fixed-size key to avoid string allocations (4 bytes IP + 2 bytes port)
type natKey [6]byte

func (k natKey) String() string {
	ip := net.IPv4(k[0], k[1], k[2], k[3])
	port := (uint16(k[4]) << 8) | uint16(k[5])
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

func makeNatKey(ip net.IP, port int) natKey {
	var k natKey
	ip4 := ip.To4()
	if ip4 != nil {
		copy(k[:4], ip4)
	}
	k[4] = byte(port >> 8)
	k[5] = byte(port)
	return k
}

type natSession struct {
	clientIP   net.IP
	clientPort int
	lastSeen   int64 // Unix nano timestamp - atomic access friendly
	forwardKey natKey
}

// NatTable maps client (IP:port) <-> a 16-bit virtual port used on the wire.
//
// The reverse direction (virtual port -> session) is the per-packet hot path
// for both uplink refresh and downlink lookup, so it is a directly indexed
// array of atomic pointers: O(1), lock-free, and allocation-free (a plain
// sync.Map would box the uint16 key into an interface{} on every packet).
//
// The forward direction (client key -> virtual port) is touched once per new
// flow on the uplink and by the cleanup goroutine, so a mutex-guarded map is
// cheap enough there.
type NatTable struct {
	reverse [65536]atomic.Pointer[natSession]

	mu      sync.RWMutex
	forward map[natKey]uint16

	// Local RNG to avoid global lock contention in rand.Intn.
	// Only accessed by the single Uplink goroutine.
	rng *rand.Rand
}

func newNatTable() *NatTable {
	return &NatTable{
		forward: make(map[natKey]uint16),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (n *NatTable) GetOrCreateVirtualPort(clientIP net.IP, clientPort int) uint16 {
	key := makeNatKey(clientIP, clientPort)
	now := atomic.LoadInt64(&coarseTime)

	// Fast path: an existing mapping whose session is still live.
	n.mu.RLock()
	vPort, ok := n.forward[key]
	n.mu.RUnlock()
	if ok {
		if s := n.reverse[vPort].Load(); s != nil {
			atomic.StoreInt64(&s.lastSeen, now)
			return vPort
		}
		// Stale forward entry (session was reaped): fall through to reallocate.
	}

	// Slow path: allocate a virtual port. Try the client's real port first,
	// then random ports in [1024, 65535). The clientIP slice may alias a
	// reusable read buffer, so copy it into the retained session.
	ip4 := clientIP.To4()
	ipCopy := make(net.IP, len(ip4))
	copy(ipCopy, ip4)
	session := &natSession{
		clientIP:   ipCopy,
		clientPort: clientPort,
		lastSeen:   now,
		forwardKey: key,
	}
	proposed := uint16(clientPort)
	for {
		if n.reverse[proposed].CompareAndSwap(nil, session) {
			n.mu.Lock()
			n.forward[key] = proposed
			n.mu.Unlock()
			return proposed
		}
		// Collision: pick random in [1024, 65534].
		proposed = uint16(n.rng.Intn(64511) + 1024)
	}
}

func (n *NatTable) GetSession(virtualPort uint16) *natSession {
	sess := n.reverse[virtualPort].Load()
	if sess != nil {
		atomic.StoreInt64(&sess.lastSeen, atomic.LoadInt64(&coarseTime))
	}
	return sess
}

func (n *NatTable) Cleanup() {
	for {
		time.Sleep(30 * time.Second)
		threshold := time.Now().Add(-60 * time.Second).UnixNano()
		for i := range n.reverse {
			sess := n.reverse[i].Load()
			if sess == nil || atomic.LoadInt64(&sess.lastSeen) >= threshold {
				continue
			}
			// Delete the forward entry first so a concurrent uplink misses and
			// reallocates cleanly; guard against clobbering a fresh remapping.
			n.mu.Lock()
			if v, ok := n.forward[sess.forwardKey]; ok && v == uint16(i) {
				delete(n.forward, sess.forwardKey)
			}
			n.mu.Unlock()
			n.reverse[i].Store(nil)
		}
	}
}
