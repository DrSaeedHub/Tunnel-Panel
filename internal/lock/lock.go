// Package lock holds the panel's global mutation lock (§16).
//
// One lock serialises every change to kernel state, whatever subsystem is
// making it: a tunnel apply and a forwarding rule apply must never interleave,
// because both reconfigure the same kernel and the second would be planning
// against a picture the first is in the middle of changing.
//
// It is a channel rather than a mutex so that acquiring it respects context
// cancellation: a request abandoned while queued stops waiting instead of tying
// up a goroutine until the operation ahead of it finishes.
package lock

import (
	"context"
	"fmt"
)

// Mutation is the global mutation lock. The zero value is not usable; call New.
type Mutation struct {
	ch chan struct{}
}

// New returns an unheld lock.
func New() *Mutation { return &Mutation{ch: make(chan struct{}, 1)} }

// Acquire takes the lock, returning the function that releases it.
//
// A nil receiver acquires nothing and releases nothing, so a service built
// without a lock in a test still runs.
func (m *Mutation) Acquire(ctx context.Context) (func(), error) {
	if m == nil || m.ch == nil {
		return func() {}, nil
	}
	select {
	case m.ch <- struct{}{}:
		return func() { <-m.ch }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("another change is in progress and this request was abandoned: %w", ctx.Err())
	}
}

// Held reports whether the lock is currently taken, which the health endpoint
// shows so a queued request has an explanation.
func (m *Mutation) Held() bool {
	if m == nil || m.ch == nil {
		return false
	}
	return len(m.ch) > 0
}
