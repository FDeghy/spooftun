//go:build linux

package main

import (
	"testing"
	"time"
)

func TestServerSessionIdleActivity(t *testing.T) {
	var session serverSession
	now := time.Now().UnixNano()
	session.lastSeen.Store(now)
	if got := session.idleDeadline(2 * time.Second); got.UnixNano() != now+int64(2*time.Second) {
		t.Fatalf("initial deadline: %v", got)
	}
	if session.expireIdle(now+int64(time.Second), 2*time.Second) {
		t.Fatal("expired active session")
	}
	if !session.refresh(now + int64(2*time.Second)) {
		t.Fatal("could not refresh live session")
	}
	if session.expireIdle(now+int64(3*time.Second), 2*time.Second) {
		t.Fatal("uplink activity did not extend the session lifetime")
	}
	if got := session.idleDeadline(2 * time.Second); got.UnixNano() != now+int64(4*time.Second) {
		t.Fatalf("renewed deadline did not follow the latest activity: %v", got)
	}
	if !session.expireIdle(now+int64(5*time.Second), 2*time.Second) {
		t.Fatal("idle session did not expire")
	}
	if session.refresh(now + int64(6*time.Second)) {
		t.Fatal("late packet revived a retired session")
	}
}

func TestServerDeadlineRetainsMonotonicClock(t *testing.T) {
	var s serverSession
	s.lastSeen.Store(coarseBaseNano + int64(3*time.Second))
	deadline := s.idleDeadline(2 * time.Second)
	if deadline == deadline.Round(0) {
		t.Fatal("socket deadline lost its monotonic clock")
	}
	if deadline.Sub(coarseBaseTime) != 5*time.Second {
		t.Fatal("deadline does not follow monotonic session activity")
	}
}

func TestServerSessionResourceLimits(t *testing.T) {
	for _, mtu := range []int{68, 1500, 65535} {
		for _, gro := range []bool{false, true} {
			for _, noise := range []bool{false, true} {
				size := serverSessionBufferBytes(mtu, payloadLimit(mtu, false, false), gro, noise)
				limit := serverSessionLimit(mtu, payloadLimit(mtu, false, false), gro, noise)
				if limit < 1 || limit > maxServerSessions || int(limit)*size > serverSessionBufferBudget {
					t.Fatalf("unsafe admission: mtu=%d gro=%t noise=%t count=%d bytes=%d", mtu, gro, noise, limit, size)
				}
			}
		}
	}
	var a serverSessionAdmission
	now := int64(time.Second)
	for i := 0; i < 128; i++ {
		if !a.allow(now) {
			t.Fatal("rejected admission before burst limit")
		}
	}
	if a.allow(now + int64(time.Second) - 1) {
		t.Fatal("admitted excess session churn")
	}
	if !a.allow(now + int64(time.Second)) {
		t.Fatal("admission did not recover")
	}
}
