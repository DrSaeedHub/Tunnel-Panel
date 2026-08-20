package monitor

import (
	"fmt"

	"github.com/drs/gre-panel/internal/model"
)

// StateName renders a MonitorState identifier for display and for the API.
func StateName(id int64) string {
	switch id {
	case model.MonitorStateUp:
		return "Up"
	case model.MonitorStateDegraded:
		return "Degraded"
	case model.MonitorStateDown:
		return "Down"
	case model.MonitorStateDisabled:
		return "Disabled"
	}
	return "Unknown"
}

// Classify decides which state a set of figures describes, before hysteresis.
//
// Not enough decided probes yet is Unknown rather than Up: a monitor that has
// just started knows nothing, and saying so is more useful than a confident
// answer drawn from one packet (§10.2).
func Classify(stats Stats, cfg Config) (int64, string) {
	if stats.Sent < cfg.StateChangeSamples {
		return model.MonitorStateUnknown, fmt.Sprintf(
			"only %d of the %d probes needed for a verdict have finished", stats.Sent, cfg.StateChangeSamples)
	}
	if stats.LossPercent >= cfg.DownLossPercent {
		// A link carrying traffic is not down, whatever the probes say.
		//
		// On a path where ICMP is filtered -- which is the ordinary condition
		// on a good many of the routes this panel is used across -- a tunnel
		// running at full speed answers no probes at all. Calling that down is
		// not merely a wrong label: it is the input to everything that acts on
		// a tunnel being down, so a working link gets torn up and rebuilt on a
		// schedule. The interface's own counters settle it, and they are the
		// stronger evidence: a probe is a question the far end may decline to
		// answer, and a byte count is packets that actually crossed.
		if stats.CarryingTraffic {
			return model.MonitorStateUp, fmt.Sprintf(
				"%.1f%% of probes are unanswered, but the interface is carrying traffic: the "+
					"path is up and something along it is filtering ICMP rather than dropping packets",
				stats.LossPercent)
		}
		// An idle tunnel carries nothing, so the counters say nothing either.
		// Knocking on the far end over TCP is what separates a tunnel nobody
		// is using from one that does not work, and the far end's stack
		// answering -- by accepting or by refusing -- is proof that the tunnel
		// carried a packet there and carried the answer back.
		if stats.PeerAnswered {
			return model.MonitorStateUp, fmt.Sprintf(
				"%.1f%% of probes are unanswered and the tunnel is idle, but the far end "+
					"answered a TCP connection across it: the path is up and ICMP is being filtered",
				stats.LossPercent)
		}
		return model.MonitorStateDown, fmt.Sprintf(
			"%.1f%% of probes over the last %d are unanswered, at or above the down threshold of %.1f%%",
			stats.LossPercent, stats.Sent, cfg.DownLossPercent)
	}
	if stats.LossPercent >= cfg.DegradedLossPercent {
		// Partial loss with traffic moving is still degraded: some probes did
		// come back, so the far end is answering and the loss is real.
		return model.MonitorStateDegraded, fmt.Sprintf(
			"%.1f%% of probes over the last %d are unanswered, at or above the degraded threshold of %.1f%%",
			stats.LossPercent, stats.Sent, cfg.DegradedLossPercent)
	}
	if cfg.DegradedRttMs != nil && stats.RttAvgMs != nil && *stats.RttAvgMs >= *cfg.DegradedRttMs {
		return model.MonitorStateDegraded, fmt.Sprintf(
			"the average round-trip time of %.1f ms is at or above the degraded threshold of %.1f ms",
			*stats.RttAvgMs, *cfg.DegradedRttMs)
	}
	return model.MonitorStateUp, fmt.Sprintf("%d of %d probes answered", stats.Received, stats.Sent)
}

// Machine applies hysteresis to the classified state.
//
// A state changes only after enough consecutive samples agree on the new one.
// Without it a single lost packet flips the display to Down and the next one
// flips it back, which is the flapping the legacy one-shot check could not
// avoid (§10.2).
type Machine struct {
	current   int64
	candidate int64
	agreed    int
	required  int
	reason    string
	// forced records that the current reason is a fact rather than an
	// inference, so that the evaluator's next sample does not talk over it.
	forced bool
}

// NewMachine returns a machine starting in Unknown.
func NewMachine(required int) *Machine {
	if required < 1 {
		required = 1
	}
	return &Machine{current: model.MonitorStateUnknown, candidate: model.MonitorStateUnknown, required: required}
}

// SetRequired changes the hysteresis depth, which a settings change can do at
// runtime.
func (m *Machine) SetRequired(required int) {
	if required < 1 {
		required = 1
	}
	m.required = required
	if m.agreed > required {
		m.agreed = required
	}
}

// Current returns the state in force, and why.
func (m *Machine) Current() (int64, string) { return m.current, m.reason }

// Release lets measurements explain the state again.
//
// It is called when whatever fact was forced has stopped being true — a prober
// that failed to start and is now running — so that a stale explanation cannot
// outlive its cause while the state itself has not changed.
func (m *Machine) Release() { m.forced = false }

// Transition is one state change, which becomes a MonitorEvent row.
type Transition struct {
	From   int64
	To     int64
	Reason string
}

// Observe feeds one classified sample in and reports a transition when the
// hysteresis threshold is met.
func (m *Machine) Observe(state int64, reason string) (Transition, bool) {
	if state == m.candidate {
		m.agreed++
	} else {
		m.candidate = state
		m.agreed = 1
	}

	if state == m.current {
		// Already there; keep the freshest explanation for the status endpoint
		// — unless the one in force is a fact. An interface that has vanished
		// is Down for a reason a probe timeout cannot discover, and replacing
		// "interface_missing" with "100% of probes are unanswered" would tell
		// an operator only the symptom of what the panel already knows (§10.3).
		if !m.forced {
			m.reason = reason
		}
		return Transition{}, false
	}
	if m.agreed < m.required {
		return Transition{}, false
	}

	from := m.current
	m.current = state
	m.reason = reason
	m.forced = false
	return Transition{From: from, To: state, Reason: reason}, true
}

// Force sets the state immediately, skipping hysteresis.
//
// It is used for the two facts that are not measurements and need no
// corroboration: monitoring being switched off, and the interface having
// vanished, which the netlink subscription reports directly (§10.3).
// A forced reason outranks the evaluator's until the state actually changes.
func (m *Machine) Force(state int64, reason string) (Transition, bool) {
	m.candidate = state
	m.agreed = m.required
	m.forced = true
	if m.current == state {
		m.reason = reason
		return Transition{}, false
	}
	from := m.current
	m.current = state
	m.reason = reason
	return Transition{From: from, To: state, Reason: reason}, true
}
