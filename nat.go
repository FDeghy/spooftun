//go:build linux

package main

import (
	"errors"
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

var errNATExhausted = errors.New("NAT virtual port space exhausted")

// A retired session must never be refreshed or returned by a later lookup.
const retiredSessionTime int64 = -1

func (s *natSession) refresh(now int64) bool {
	for {
		last := atomic.LoadInt64(&s.lastSeen)
		if last == retiredSessionTime {
			return false
		}
		// Concurrent readers can have slightly different timestamps. Do not
		// move the activity clock backwards, but still synchronize retirement.
		if now < last {
			now = last
		}
		if atomic.CompareAndSwapInt64(&s.lastSeen, last, now) {
			return true
		}
	}
}

// NatTable maps client (IP:port) <-> a 16-bit virtual port used on the wire.
//
// The reverse direction (virtual port -> session) is the per-packet hot path
// for both uplink refresh and downlink lookup, so it is a directly indexed
// array of atomic pointers: O(1), lock-free, and allocation-free (a plain
// sync.Map would box the uint16 key into an interface{} on every packet).
//
// The forward direction (client key -> virtual port) uses a shared read lock
// for existing uplink flows. Allocation and cleanup serialize mutations of
// both directions under the write lock.
type NatTable struct {
	reverse [65536]atomic.Pointer[natSession]

	mu      sync.RWMutex
	forward map[natKey]uint16

	// Local RNG to avoid global lock contention in rand.Intn.
	// Accessed under mu on the allocation path.
	rng *rand.Rand
}

func newNatTable() *NatTable {
	return &NatTable{
		forward: make(map[natKey]uint16),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (n *NatTable) GetOrCreateVirtualPort(clientIP net.IP, clientPort int) (uint16, error) {
	key := makeNatKey(clientIP, clientPort)
	now := atomic.LoadInt64(&coarseTime)

	// Fast path: an existing mapping whose session is still live.
	n.mu.RLock()
	vPort, ok := n.forward[key]
	if ok {
		if s := n.reverse[vPort].Load(); s != nil && s.refresh(now) {
			n.mu.RUnlock()
			return vPort, nil
		}
	}
	n.mu.RUnlock()

	n.mu.Lock()
	defer n.mu.Unlock()
	// Another uplink may have allocated this flow while we waited.
	if v, exists := n.forward[key]; exists {
		if s := n.reverse[v].Load(); s != nil && s.refresh(now) {
			return v, nil
		}
	}
	if len(n.forward) == len(n.reverse) {
		return 0, errNATExhausted
	}

	// Slow path: allocate a virtual port. Try the client's real port first,
	// then scan from a random offset over the entire virtual-port space.
	// These ports are wire identifiers, not local bind ports; low ports and
	// 65535 are valid too. The clientIP slice may alias a
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
	if n.reverse[proposed].Load() != nil {
		start := n.rng.Intn(len(n.reverse))
		found := false
		for offset := range len(n.reverse) {
			candidate := uint16(start + offset)
			if n.reverse[candidate].Load() == nil {
				proposed = candidate
				found = true
				break
			}
		}
		if !found {
			return 0, errNATExhausted
		}
	}
	n.reverse[proposed].Store(session)
	n.forward[key] = proposed
	return proposed, nil
}

func (n *NatTable) GetSession(virtualPort uint16) *natSession {
	sess := n.reverse[virtualPort].Load()
	if sess != nil && sess.refresh(atomic.LoadInt64(&coarseTime)) {
		return sess
	}
	return nil
}

func (n *NatTable) Cleanup() {
	for {
		time.Sleep(30 * time.Second)
		n.cleanupOnce(time.Now())
	}
}

func (n *NatTable) cleanupOnce(now time.Time) {
	threshold := now.Add(-60 * time.Second).UnixNano()
	for i := range n.reverse {
		sess := n.reverse[i].Load()
		if sess == nil {
			continue
		}
		last := atomic.LoadInt64(&sess.lastSeen)
		if last >= threshold {
			continue
		}
		n.expireSession(uint16(i), sess, last)
	}
}

func (n *NatTable) expireSession(port uint16, sess *natSession, last int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	// Retirement and refresh compete on the same timestamp. If a packet
	// refreshed since our stale check, leave the mapping live. Also verify
	// identity before touching a slot that may have been reused.
	if n.reverse[port].Load() == sess && atomic.CompareAndSwapInt64(&sess.lastSeen, last, retiredSessionTime) {
		if v, ok := n.forward[sess.forwardKey]; ok && v == port {
			delete(n.forward, sess.forwardKey)
		}
		n.reverse[port].Store(nil)
	}
}
