package scanner

import (
	"testing"
	"time"
)

func TestScanGuardBasicAcquireRelease(t *testing.T) {
	g := NewScanGuard(time.Minute)
	if !g.TryAcquire() {
		t.Fatal("first TryAcquire should succeed")
	}
	if g.TryAcquire() {
		t.Fatal("second TryAcquire should fail while held")
	}
	g.Release()
	if !g.TryAcquire() {
		t.Fatal("TryAcquire after Release should succeed")
	}
}

func TestScanGuardDeadlineExpiry(t *testing.T) {
	g := NewScanGuard(10 * time.Millisecond)
	if !g.TryAcquire() {
		t.Fatal("first TryAcquire should succeed")
	}
	if g.TryAcquire() {
		t.Fatal("TryAcquire should fail before deadline")
	}
	time.Sleep(15 * time.Millisecond)
	if !g.TryAcquire() {
		t.Fatal("TryAcquire should succeed after deadline expires (stale claim recovered)")
	}
}
