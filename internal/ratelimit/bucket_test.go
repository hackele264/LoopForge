package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestBucketBurstThenRefill(t *testing.T) {
	start := time.Unix(1000, 0)
	b := NewBucket(1, 3, start) // one token per second, burst 3
	for i := 0; i < 3; i++ {
		if ok, _ := b.Take(start); !ok {
			t.Fatalf("take %d within burst refused", i)
		}
	}
	ok, wait := b.Take(start)
	if ok || wait != time.Second {
		t.Fatalf("fourth take = %v, wait %v; want refused, 1s", ok, wait)
	}
	if ok, _ := b.Take(start.Add(500 * time.Millisecond)); ok {
		t.Fatal("half a token should not be enough")
	}
	if ok, _ := b.Take(start.Add(time.Second)); !ok {
		t.Fatal("refilled token refused")
	}
	// Refill never exceeds the burst.
	later := start.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := b.Take(later); !ok {
			t.Fatalf("take %d after an idle hour refused", i)
		}
	}
	if ok, _ := b.Take(later); ok {
		t.Fatal("burst exceeded after idle period")
	}
	b.Refund()
	if ok, _ := b.Take(later); !ok {
		t.Fatal("refunded token refused")
	}
}

func TestBucketMinimumBurstAndPerMinuteRate(t *testing.T) {
	start := time.Unix(0, 0)
	b := NewBucket(2.0/60, 0, start) // 2 per minute, burst raised to 1
	if ok, _ := b.Take(start); !ok {
		t.Fatal("first take refused")
	}
	ok, wait := b.Take(start)
	if ok || wait != 30*time.Second {
		t.Fatalf("second take = %v, wait %v; want refused, 30s", ok, wait)
	}
}

func TestBucketWaitHonoursContext(t *testing.T) {
	b := NewBucket(0.001, 1, time.Now())
	if err := b.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := b.Wait(ctx); err == nil {
		t.Fatal("wait on an empty bucket should end with the context")
	}
	if time.Since(started) > time.Second {
		t.Fatal("wait ignored the context deadline")
	}
	fast := NewBucket(100, 1, time.Now())
	_ = fast.Wait(context.Background())
	if err := fast.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryResetsOnChangedSettings(t *testing.T) {
	r := NewRegistry()
	if r.Bucket("a", 0, 5) != nil {
		t.Fatal("zero rate must mean unlimited")
	}
	a := r.Bucket("a", 1, 1)
	if r.Bucket("a", 1, 1) != a {
		t.Fatal("same settings must reuse the bucket")
	}
	if r.Bucket("a", 2, 1) == a {
		t.Fatal("changed settings must start a new bucket")
	}
	r.Forget("a")
	var nilRegistry *Registry
	if nilRegistry.Bucket("a", 1, 1) != nil {
		t.Fatal("nil registry must be unlimited")
	}
}
