package auth

import (
	"sync"
	"time"
)

// RateLimiter is a fixed-window-free sliding counter used for login attempts.
// It keeps the timestamps of recent attempts per key and drops the ones that
// have aged out, which avoids the burst-at-the-window-boundary behaviour of a
// naive fixed window.
type RateLimiter struct {
	mu        sync.Mutex
	hits      map[string][]time.Time
	lastSweep time.Time
	now       func() time.Time // injectable for tests
}

// NewRateLimiter returns an empty limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{hits: map[string][]time.Time{}, now: time.Now}
}

// Allow records an attempt against key and reports whether it is within limit
// over the trailing window. A non-positive limit disables the check.
func (r *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	if limit <= 0 || window <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	cutoff := now.Add(-window)
	kept := r.hits[key][:0]
	for _, t := range r.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}

	allowed := len(kept) < limit
	// The attempt is recorded whether or not it is allowed, so hammering the
	// endpoint keeps the window full rather than resetting it.
	kept = append(kept, now)
	r.hits[key] = kept

	r.sweepLocked(now, window)
	return allowed
}

// Reset clears the history for a key, called after a successful login so a user
// who mistyped a few times is not throttled once they get it right.
func (r *RateLimiter) Reset(key string) {
	r.mu.Lock()
	delete(r.hits, key)
	r.mu.Unlock()
}

// sweepLocked drops keys whose entries have all aged out. Without it, a stream
// of distinct usernames or client addresses would grow the map without bound.
func (r *RateLimiter) sweepLocked(now time.Time, window time.Duration) {
	if now.Sub(r.lastSweep) < window {
		return
	}
	r.lastSweep = now
	cutoff := now.Add(-window)
	for key, times := range r.hits {
		newest := time.Time{}
		if len(times) > 0 {
			newest = times[len(times)-1]
		}
		if !newest.After(cutoff) {
			delete(r.hits, key)
		}
	}
}
