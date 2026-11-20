// Package ratelimit holds the in-process token buckets behind per-webhook
// alert limits and per-connection request limits. Buckets live in the
// memory of one platform process: several processes each apply the full
// limit.
package ratelimit

import (
	"context"
	"math"
	"sync"
	"time"
)

// Bucket is a token bucket refilled at rate tokens per second up to burst.
// It starts full.
type Bucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

// NewBucket returns a full bucket. A burst below 1 is raised to 1.
func NewBucket(rate float64, burst int, now time.Time) *Bucket {
	b := float64(burst)
	if b < 1 {
		b = 1
	}
	return &Bucket{rate: rate, burst: b, tokens: b, last: now}
}

func (b *Bucket) refill(now time.Time) {
	if now.After(b.last) {
		b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
}

// Take removes one token when one is available. Otherwise it reports how
// long until one will be.
func (b *Bucket) Take(now time.Time) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	if b.rate <= 0 {
		return false, time.Hour
	}
	wait := time.Duration(math.Round((1-b.tokens)/b.rate*1000)) * time.Millisecond
	if wait <= 0 {
		wait = time.Millisecond
	}
	return false, wait
}

// Refund gives back a token taken for work that did not happen.
func (b *Bucket) Refund() {
	b.mu.Lock()
	b.tokens = math.Min(b.burst, b.tokens+1)
	b.mu.Unlock()
}

// Wait blocks until it takes a token or ctx ends.
func (b *Bucket) Wait(ctx context.Context) error {
	for {
		ok, wait := b.Take(time.Now())
		if ok {
			return nil
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// Registry keeps one bucket per key (a webhook or connection ID). A key whose
// settings change gets a fresh, full bucket.
type Registry struct {
	mu      sync.Mutex
	buckets map[string]registryEntry
}

type registryEntry struct {
	rate   float64
	burst  int
	bucket *Bucket
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{buckets: map[string]registryEntry{}} }

// Bucket returns key's bucket for rate tokens per second and burst, or nil
// when rate is not positive (unlimited).
func (r *Registry) Bucket(key string, rate float64, burst int) *Bucket {
	if r == nil || rate <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.buckets[key]; ok && e.rate == rate && e.burst == burst {
		return e.bucket
	}
	b := NewBucket(rate, burst, time.Now())
	r.buckets[key] = registryEntry{rate: rate, burst: burst, bucket: b}
	return b
}

// Forget drops key's bucket.
func (r *Registry) Forget(key string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	delete(r.buckets, key)
	r.mu.Unlock()
}
