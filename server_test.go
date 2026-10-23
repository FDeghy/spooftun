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
