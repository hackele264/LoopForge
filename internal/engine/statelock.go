package engine

import (
	"sync"
	"sync/atomic"
	"time"
)

// timedMutex is the engine's global state lock with counters: how often it
// was taken, how long callers waited for it and how long it was held. Every
// run state change (read, mutate, store, publish) happens under it, so its
// hold time bounds how many state changes per second one engine instance can
// make, whatever the number of runs.
type timedMutex struct {
	mu       sync.Mutex
	acquired time.Time // guarded by mu

	count, waitNs, holdNs, maxWaitNs, maxHoldNs atomic.Int64
}

func (m *timedMutex) Lock() {
	start := time.Now()
	m.mu.Lock()
	now := time.Now()
	wait := now.Sub(start).Nanoseconds()
	m.acquired = now
	m.count.Add(1)
	m.waitNs.Add(wait)
	storeMax(&m.maxWaitNs, wait)
}

func (m *timedMutex) Unlock() {
	hold := time.Since(m.acquired).Nanoseconds()
	m.holdNs.Add(hold)
	storeMax(&m.maxHoldNs, hold)
	m.mu.Unlock()
}

func storeMax(v *atomic.Int64, n int64) {
	for {
		old := v.Load()
		if n <= old || v.CompareAndSwap(old, n) {
			return
		}
	}
}

// StateLockStats is a snapshot of the state lock's counters since start.
type StateLockStats struct {
	Acquisitions int64
	Wait, Hold   time.Duration
	MaxWait      time.Duration
	MaxHold      time.Duration
}

// StateLockStats reports the global state lock's counters.
func (e *Engine) StateLockStats() StateLockStats {
	m := &e.stateMu
	return StateLockStats{
		Acquisitions: m.count.Load(),
		Wait:         time.Duration(m.waitNs.Load()),
		Hold:         time.Duration(m.holdNs.Load()),
		MaxWait:      time.Duration(m.maxWaitNs.Load()),
		MaxHold:      time.Duration(m.maxHoldNs.Load()),
	}
}
