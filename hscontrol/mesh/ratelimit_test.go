// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

package mesh

import (
	"testing"
	"time"
)

// TestJoinLimiterBurstAndRefill: a source may burst up to joinBurst
// requests then is blocked; after one refill interval it can send again.
func TestJoinLimiterBurstAndRefill(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fake := base
	l := &joinLimiter{
		buckets: make(map[string]*joinBucket),
		nowFn:   func() time.Time { return fake },
	}
	for i := 0; i < joinBurst; i++ {
		if !l.allow("1.2.3.4") {
			t.Fatalf("burst request %d denied", i)
		}
	}
	if l.allow("1.2.3.4") {
		t.Fatal("allowed request past burst")
	}

	// Advance by enough time to refill ≥1 token.
	needed := time.Duration(float64(time.Second) / joinRefillPerSec)
	fake = fake.Add(needed + time.Millisecond)
	if !l.allow("1.2.3.4") {
		t.Fatal("still denied after refill interval")
	}
}

// TestJoinLimiterPerIP: two different IPs get independent buckets.
func TestJoinLimiterPerIP(t *testing.T) {
	fake := time.Now()
	l := &joinLimiter{
		buckets: make(map[string]*joinBucket),
		nowFn:   func() time.Time { return fake },
	}
	for i := 0; i < joinBurst; i++ {
		l.allow("1.2.3.4")
	}
	if l.allow("1.2.3.4") {
		t.Fatal("ip1 allowed past burst")
	}
	if !l.allow("5.6.7.8") {
		t.Fatal("ip2 denied despite fresh bucket")
	}
}

// TestJoinLimiterGC: stale buckets are swept after joinBucketTTL so
// spray-and-rotate attackers can't grow the map unboundedly.
func TestJoinLimiterGC(t *testing.T) {
	fake := time.Now()
	l := &joinLimiter{
		buckets: make(map[string]*joinBucket),
		nowFn:   func() time.Time { return fake },
	}
	l.allow("1.1.1.1")
	if _, ok := l.buckets["1.1.1.1"]; !ok {
		t.Fatal("bucket not created")
	}
	// Advance past TTL + GC interval and trigger sweep via any allow.
	fake = fake.Add(joinBucketGC + joinBucketTTL + time.Second)
	l.allow("9.9.9.9")
	if _, ok := l.buckets["1.1.1.1"]; ok {
		t.Fatal("stale bucket not reaped")
	}
}
