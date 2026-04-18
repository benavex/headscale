// Copyright (c) benavex
// SPDX-License-Identifier: BSD-3-Clause

// Per-source-IP token bucket guarding /mesh/join. The join handler
// already rejects unsigned callers, but HMAC verification is a
// sha256 — cheap but non-trivial to spray at scale. The bucket caps
// each source IP to a few requests per minute so a hostile scanner
// can't turn the endpoint into a CPU-burn gadget, and bounds the
// operator's log volume when a misconfigured node is in a retry
// loop.

package mesh

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// joinBucket is the per-IP state. Tokens refill linearly at rate
// joinRefillPerSec up to joinBurst; each accepted request costs 1.
type joinBucket struct {
	tokens   float64
	lastSeen time.Time
}

const (
	// joinBurst is the number of back-to-back joins we allow before
	// a source IP must wait for the refill. Three is enough for a
	// fresh node to retry through a brief network blip without
	// getting rate-limited.
	joinBurst = 3

	// joinRefillPerSec is the steady-state token grant rate. At
	// 0.2 tokens/sec a single source gets roughly 12 joins/minute
	// after its burst is exhausted — comfortably above any
	// legitimate retry cadence, well below what a CPU-burn attack
	// needs.
	joinRefillPerSec = 0.2

	// joinBucketGC is how often stale buckets are swept out so the
	// map can't be grown unboundedly by spray-and-rotate attackers.
	// Entries older than joinBucketTTL are discarded.
	joinBucketGC  = 5 * time.Minute
	joinBucketTTL = 10 * time.Minute
)

// joinLimiter is a tiny token bucket keyed by source IP. Package-global
// so all join handler invocations share state. Allocated lazily on
// first use so tests that import the package without starting an HTTP
// server don't pay for it.
type joinLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*joinBucket
	lastGC   time.Time
	nowFn    func() time.Time // overridable for tests
}

var defaultJoinLimiter = &joinLimiter{
	buckets: make(map[string]*joinBucket),
	nowFn:   time.Now,
}

// allow reports whether a request from ip may proceed. Mutates the
// bucket in place: decrements on allow, refills based on elapsed time,
// and periodically reaps stale entries.
func (l *joinLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFn()

	if now.Sub(l.lastGC) > joinBucketGC {
		for k, b := range l.buckets {
			if now.Sub(b.lastSeen) > joinBucketTTL {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[ip]
	if !ok {
		b = &joinBucket{tokens: joinBurst, lastSeen: now}
		l.buckets[ip] = b
	} else {
		elapsed := now.Sub(b.lastSeen).Seconds()
		b.tokens += elapsed * joinRefillPerSec
		if b.tokens > joinBurst {
			b.tokens = joinBurst
		}
		b.lastSeen = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP extracts the source IP from an http.Request, stripping the
// port. Honours a preceding RealIP middleware: r.RemoteAddr at that
// point is already the client's external IP, not the proxy's.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
