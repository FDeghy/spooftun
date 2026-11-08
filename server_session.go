//go:build linux

package main

import (
	"net"
	"sync/atomic"
	"time"
)

const (
	maxServerSessions = 1024
	// Bound reserved payload storage, including GRO and eventual reply batches.
	// Kernel socket queues and Go metadata are additional memory.
	serverSessionBufferBudget = 64 << 20
)

func serverSessionBufferBytes(mtu, maxReply int, gro, noise bool) int {
	receiveSize := maxReply + 1
	if gro {
		receiveSize = 65535
	}
	frames := 1
	if noise {
		frames++
	}
	return batchSize * (receiveSize + frames*max(60, mtu+14))
}

func serverSessionLimit(mtu, maxReply int, gro, noise bool) int32 {
	return int32(min(maxServerSessions, serverSessionBufferBudget/serverSessionBufferBytes(mtu, maxReply, gro, noise)))
}

// Called only under the server creation mutex. Existing flows bypass this gate.
// A fixed window bounds socket/buffer churn without per-source allocations.
type serverSessionAdmission struct {
	window  int64
	created int
}

func (a *serverSessionAdmission) allow(now int64) bool {
	if now-a.window >= int64(time.Second) {
		a.window, a.created = now, 0
	}
	if a.created >= 128 {
		return false
	}
	a.created++
	return true
}

type serverSession struct {
	conn     *net.UDPConn
	lastSeen atomic.Int64
	replyMAC atomic.Pointer[[6]byte]
}

func (s *serverSession) refresh(now int64) bool {
	for {
		last := s.lastSeen.Load()
		if last == retiredSessionTime {
			return false
		}
		if s.lastSeen.CompareAndSwap(last, max(last, now)) {
			return true
		}
	}
}

func (s *serverSession) expireIdle(now int64, timeout time.Duration) bool {
	for {
		last := s.lastSeen.Load()
		if last == retiredSessionTime {
			return true
		}
		if now-last < int64(timeout) {
			return false
		}
		if s.lastSeen.CompareAndSwap(last, retiredSessionTime) {
			return true
		}
	}
}

func (s *serverSession) idleDeadline(timeout time.Duration) time.Time {
	return coarseBaseTime.Add(time.Duration(s.lastSeen.Load() - coarseBaseNano)).Add(timeout)
}
