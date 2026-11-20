package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

// Run state changes (read, mutate, store, publish) are serialized per run:
// two changes to the same run never interleave, while different runs change
// in parallel. Runs share no in-memory state that these sections guard;
// cross-run work (cancelling children, resuming a parent, admission) goes
// through its own run's lock or through database transactions.
//
// The lock records how often it was taken, how long callers waited and how
// long it was held, summed over all runs.

type runLock struct {
	mu       sync.Mutex
	acquired time.Time // guarded by mu
	refs     int       // guarded by runLocks.mu
}

type runLocks struct {
	mu    sync.Mutex
	locks map[string]*runLock

	count, waitNs, holdNs, maxWaitNs, maxHoldNs atomic.Int64
}

// lock takes runID's lock and returns its release. Typical use:
//
//	defer e.stateLocks.lock(runID)()
func (l *runLocks) lock(runID string) func() {
	start := time.Now()
	l.mu.Lock()
	if l.locks == nil {
		l.locks = map[string]*runLock{}
	}
	rl := l.locks[runID]
	if rl == nil {
		rl = &runLock{}
		l.locks[runID] = rl
	}
	rl.refs++
	l.mu.Unlock()

	rl.mu.Lock()
	now := time.Now()
	wait := now.Sub(start).Nanoseconds()
	rl.acquired = now
	l.count.Add(1)
	l.waitNs.Add(wait)
	storeMax(&l.maxWaitNs, wait)
	return func() {
		hold := time.Since(rl.acquired).Nanoseconds()
		l.holdNs.Add(hold)
		storeMax(&l.maxHoldNs, hold)
		rl.mu.Unlock()
		l.mu.Lock()
		rl.refs--
		if rl.refs == 0 {
			delete(l.locks, runID)
		}
		l.mu.Unlock()
	}
}

func storeMax(v *atomic.Int64, n int64) {
	for {
		old := v.Load()
		if n <= old || v.CompareAndSwap(old, n) {
			return
		}
	}
}

// StateLockStats is a snapshot of the run state locks' counters since start,
// summed over all runs. Hold can exceed wall time because runs hold their
// locks in parallel.
type StateLockStats struct {
	Acquisitions int64
	Wait, Hold   time.Duration
	MaxWait      time.Duration
	MaxHold      time.Duration
}

// StateLockStats reports the run state locks' counters.
func (e *Engine) StateLockStats() StateLockStats {
	l := &e.stateLocks
	return StateLockStats{
		Acquisitions: l.count.Load(),
		Wait:         time.Duration(l.waitNs.Load()),
		Hold:         time.Duration(l.holdNs.Load()),
		MaxWait:      time.Duration(l.maxWaitNs.Load()),
		MaxHold:      time.Duration(l.maxHoldNs.Load()),
	}
}
