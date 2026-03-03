package scanner

import (
	"log/slog"
	"sync/atomic"
	"time"
)

// ScanGuard provides mutual exclusion for scan jobs with a maximum hold
// duration. Unlike a plain sync.Mutex, a stuck goroutine cannot permanently
// block subsequent scans — once the deadline expires, TryAcquire succeeds
// even if Release was never called (e.g. goroutine leak, panic).
type ScanGuard struct {
	maxHold     time.Duration
	busyUntilNS atomic.Int64 // unix nanos; 0 = idle
}

// NewScanGuard returns a ScanGuard. maxHold is the longest a single scan job
// is allowed to keep the guard claimed before another caller can take it.
func NewScanGuard(maxHold time.Duration) *ScanGuard {
	return &ScanGuard{maxHold: maxHold}
}

// TryAcquire claims the guard if it is idle or its previous claim has expired.
// Returns true on success.
func (g *ScanGuard) TryAcquire() bool {
	now := time.Now().UnixNano()
	prev := g.busyUntilNS.Load()
	if prev > now {
		return false
	}
	if prev != 0 {
		slog.Warn("previous scan claim expired, allowing new scan", "elapsed", time.Duration(now-prev+int64(g.maxHold)))
	}
	deadline := now + int64(g.maxHold)
	return g.busyUntilNS.CompareAndSwap(prev, deadline)
}

// Release marks the guard as idle.
func (g *ScanGuard) Release() {
	g.busyUntilNS.Store(0)
}
