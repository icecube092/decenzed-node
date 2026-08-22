// Package throttle implements a token-bucket rate limiter used to cap the
// node's TOTAL bandwidth (the operator's `config bandwidth`). xray-core has no
// fully-native per-node bandwidth cap, so the data path is wrapped with this.
package throttle

import (
	"sync"
	"time"
)

// Bucket is a token bucket where tokens represent bytes. It refills at `rate`
// bytes/sec up to `burst` bytes. rate == 0 means UNLIMITED.
//
// The clock is injectable (now) so the refill logic is deterministically
// testable without sleeping.
type Bucket struct {
	mu     sync.Mutex
	rate   float64 // bytes per second; 0 = unlimited
	burst  float64 // max tokens (bytes)
	tokens float64
	last   time.Time
	now    func() time.Time
}

// New creates a bucket that starts full (a full burst is available immediately).
func New(rate, burst float64) *Bucket {
	return newWithClock(rate, burst, time.Now)
}

func newWithClock(rate, burst float64, now func() time.Time) *Bucket {
	return &Bucket{rate: rate, burst: burst, tokens: burst, last: now(), now: now}
}

// AllowN reports whether n bytes may be sent now, consuming tokens if so.
// Non-blocking: returns false when there are not enough tokens; the caller can
// delay/retry. Refills lazily based on elapsed wall-clock time since last call.
func (b *Bucket) AllowN(n float64) bool {
	if b.rate == 0 {
		return true // unlimited
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst // cap at burst; never accrue unbounded credit
		}
		b.last = now
	}
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

// Rate returns the bucket's byte/sec rate (0 = unlimited).
func (b *Bucket) Rate() float64 { return b.rate }

// WaitN blocks until n bytes may be sent (or unlimited). n must be <= burst or
// it would never be satisfiable — callers copy in chunks <= burst.
func (b *Bucket) WaitN(n float64) {
	if b.rate == 0 {
		return
	}
	for !b.AllowN(n) {
		time.Sleep(2 * time.Millisecond)
	}
}
