package tunnel

import (
	"context"
	"time"
)

// PeerProbeResult is the outcome of a short reachability probe.
type PeerProbeResult struct {
	Sent     int      `json:"sent"`
	Received int      `json:"received"`
	RttMs    *float64 `json:"rtt_ms,omitempty"`
}

// PeerProber probes the far end of a tunnel.
//
// It is an interface with no implementation shipped here on purpose. The
// monitoring subsystem owns ICMP probing — one socket per tunnel, unique echo
// identifiers, late replies overriding a loss verdict — and duplicating a
// lesser version of it in the verification path would be two things to get
// right instead of one. The monitor supplies this when it starts.
//
// Until then verification reports the peer check as not run, which is honest:
// a check that did not happen is neither a pass nor a failure, and the peer
// probe is not fatal either way (§9.3).
type PeerProber interface {
	// Probe sends count packets from source to target within the budget and
	// reports how many were answered. It must respect context cancellation.
	Probe(ctx context.Context, source, target string, count int, budget time.Duration) (PeerProbeResult, error)
}

// StaticProber answers with a fixed result. It exists so a test can exercise
// both branches of the peer check without a network.
type StaticProber struct {
	Result PeerProbeResult
	Err    error
}

// Probe returns the configured answer.
func (p StaticProber) Probe(ctx context.Context, source, target string, count int, budget time.Duration) (PeerProbeResult, error) {
	if p.Err != nil {
		return PeerProbeResult{}, p.Err
	}
	result := p.Result
	if result.Sent == 0 {
		result.Sent = count
	}
	return result, nil
}
