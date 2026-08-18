package rules

import (
	"context"
	"sync"

	"github.com/drs/gre-panel/internal/audit"
)

// Fake is an in-memory Backend. It renders exactly what the real backends
// render — it delegates to one of them, so the preview can never drift from
// what would actually be applied — and then changes nothing on the host.
//
// It is the implementation behind the preview endpoint and behind every
// hermetic test.
type Fake struct {
	// Render delegates to this backend, so the fake's output is the real
	// output. It defaults to the nftables renderer.
	Renderer Backend

	mu       sync.Mutex
	applied  []Payload
	live     Live
	counters map[int64]Counter
	foreign  ForeignView

	// FailOn, when set, is returned by Apply. This is how a test makes an apply
	// fail and asserts the rollback.
	FailOn error
}

// NewFake returns a fake rendering the way the nftables backend does.
func NewFake() *Fake {
	return &Fake{Renderer: NewNftables(DefaultNftBin, DefaultDir, nil)}
}

// NewFakeFor returns a fake rendering the way the given backend does, which is
// what the preview endpoint uses so an operator previews the payload their host
// will actually receive.
func NewFakeFor(backend Backend) *Fake {
	if backend == nil {
		return NewFake()
	}
	return &Fake{Renderer: backend}
}

// Name identifies the implementation.
func (f *Fake) Name() string { return BackendFake }

// Capabilities reports the fake as able to serve everything the backend it
// renders for can, marked plainly as a simulation.
func (f *Fake) Capabilities() Capabilities {
	caps := f.Renderer.Capabilities()
	rendersLike := f.Renderer.Name()
	caps.Name = BackendFake
	caps.Available = true
	caps.Detail = "in-memory backend used for preview and tests; it renders exactly what " +
		rendersLike + " would apply and then changes nothing on this host"
	return caps
}

// Render delegates, so the fake and the real backend can never disagree.
func (f *Fake) Render(rs Ruleset) (Payload, error) {
	payload, err := f.Renderer.Render(rs)
	if err != nil {
		return payload, err
	}
	payload.Backend = BackendFake + ":" + f.Renderer.Name()
	return payload, nil
}

// Apply records the payload and touches nothing.
func (f *Fake) Apply(ctx context.Context, payload Payload) error {
	f.mu.Lock()
	f.applied = append(f.applied, payload)
	failure := f.FailOn
	f.mu.Unlock()

	for _, part := range payload.Parts {
		audit.TraceFrom(ctx).Add(audit.Operation{
			Kind: audit.KindCommand, Argv: part.Argv,
			Detail: "simulated: " + part.Path,
		})
	}
	if failure != nil {
		return failure
	}

	// A successful simulated apply becomes the simulated live state, so a test
	// can read back what it just applied.
	f.mu.Lock()
	f.live = liveFromPayload(payload)
	f.mu.Unlock()
	return nil
}

// liveFromPayload derives the simulated kernel state from a payload by parsing
// the payload itself with the same parsers the real backends use on the
// kernel's output.
//
// That is what makes the fake usable for testing verification and not only
// rendering: a rule that the renderer puts in the wrong chain shows up in the
// wrong chain here too.
func liveFromPayload(payload Payload) Live {
	live := Live{Backend: BackendFake}
	for _, part := range payload.Parts {
		live.Text += part.Text
		switch part.Kind {
		case PartNftables:
			live.Rules = append(live.Rules, parseNftLive(part.Text).Rules...)
		case PartIptables, PartIp6tables:
			live.Rules = append(live.Rules, ParseIptablesRules(part.Text)...)
		}
	}
	return live
}

// Counters returns the simulated counters, which a test seeds with SetCounters.
func (f *Fake) Counters(ctx context.Context) (map[int64]Counter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[int64]Counter, len(f.counters))
	for id, counter := range f.counters {
		out[id] = counter
	}
	return out, nil
}

// SetCounters seeds the simulated counters, which is how a test drives the
// accounting without traffic.
func (f *Fake) SetCounters(counters map[int64]Counter) {
	f.mu.Lock()
	f.counters = counters
	f.mu.Unlock()
}

// Foreign returns the simulated view of the rest of the host's ruleset. It is
// empty and readable by default, because a fake host has nothing else on it,
// and a test seeds it with SetForeign.
func (f *Fake) Foreign(ctx context.Context) (ForeignView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	view := f.foreign
	view.Readable = true
	view.Rules = append([]ForeignRule(nil), view.Rules...)
	view.Managers = managerNames(view.Rules)
	return view, nil
}

// SetForeign seeds the simulated foreign rules, which is how a test arranges a
// rule shadowing the panel's own.
func (f *Fake) SetForeign(view ForeignView) {
	f.mu.Lock()
	f.foreign = view
	f.mu.Unlock()
}

// ReadBack returns the simulated live ruleset.
func (f *Fake) ReadBack(ctx context.Context) (Live, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.live, nil
}

// SetLive seeds the simulated kernel state, which is how a test arranges drift.
func (f *Fake) SetLive(live Live) {
	f.mu.Lock()
	f.live = live
	f.mu.Unlock()
}

// Flush forgets the simulated ruleset.
func (f *Fake) Flush(ctx context.Context) error {
	f.mu.Lock()
	f.live = Live{Backend: BackendFake}
	f.mu.Unlock()
	return nil
}

// Applied returns every payload Apply was given, in order.
func (f *Fake) Applied() []Payload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Payload(nil), f.applied...)
}

// Reset forgets the recorded applies and the simulated state.
func (f *Fake) Reset() {
	f.mu.Lock()
	f.applied = nil
	f.live = Live{}
	f.mu.Unlock()
}
