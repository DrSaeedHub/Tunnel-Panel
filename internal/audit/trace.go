package audit

import (
	"context"
	"sync"
)

// Operation kinds. They name the mechanism that performed the step, so an
// operator reading the audit trail can tell a netlink call from a command.
const (
	KindNetlink = "netlink"
	KindCommand = "command"
	KindFile    = "file"
)

// Trace collects the operations performed while serving one request, in the
// order they happened. The apply pipeline attaches one to the request context
// and every layer below appends to it, so the audit record shows exactly what
// was done to the system rather than only what was asked for (§8.2, §18).
//
// Every method is safe on a nil receiver, so code that runs both inside and
// outside a traced request needs no branch.
type Trace struct {
	mu  sync.Mutex
	ops []Operation
}

// NewTrace returns an empty trace.
func NewTrace() *Trace { return &Trace{} }

// Add appends one operation.
func (t *Trace) Add(op Operation) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.ops = append(t.ops, op)
	t.mu.Unlock()
}

// Operations returns a copy of everything recorded so far.
func (t *Trace) Operations() []Operation {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Operation, len(t.ops))
	copy(out, t.ops)
	return out
}

// Len reports how many operations have been recorded.
func (t *Trace) Len() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ops)
}

type traceKey struct{}

// WithTrace attaches a trace to a context.
func WithTrace(ctx context.Context, t *Trace) context.Context {
	return context.WithValue(ctx, traceKey{}, t)
}

// TraceFrom returns the trace attached to a context, or nil when there is none.
// A nil trace is usable, so callers never have to check.
func TraceFrom(ctx context.Context) *Trace {
	t, _ := ctx.Value(traceKey{}).(*Trace)
	return t
}
