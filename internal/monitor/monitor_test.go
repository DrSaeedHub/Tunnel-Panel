package monitor

import (
	"errors"
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/drs/gre-panel/internal/model"
)

// ---------------------------------------------------------------- reply matching

// A reply is matched to the probe that caused it by identifier, payload marker
// and sequence number. Every one of those is load-bearing on a raw socket,
// where another process's ICMP traffic arrives here too (§10.1).
func TestReplyIsMatchedToItsProbe(t *testing.T) {
	const (
		identifier = 4242
		tunnelID   = int64(7)
	)
	sentAt := time.Now().Add(-20 * time.Millisecond)

	packet, err := Encode(false, identifier, 5, tunnelID, sentAt, 56)
	if err != nil {
		t.Fatalf("encoding failed: %v", err)
	}
	// Take the payload back out of the request the way a peer echoes it.
	payload := packet[8:]

	reply, err := Decode(false, identifier, tunnelID, replyTo(identifier, 5, payload), &net.IPAddr{IP: net.ParseIP("172.17.1.2")})
	if err != nil {
		t.Fatalf("a reply to our own probe was not matched: %v", err)
	}
	if reply.Kind != ReplyEcho {
		t.Fatalf("kind = %q, want an echo reply", reply.Kind)
	}
	if reply.Sequence != 5 {
		t.Fatalf("sequence = %d, want 5", reply.Sequence)
	}
	if !reply.SentAt.Equal(sentAt.Truncate(time.Nanosecond)) {
		t.Fatalf("the timestamp did not survive the round trip: %v vs %v", reply.SentAt, sentAt)
	}
	if reply.From != "172.17.1.2" {
		t.Fatalf("from = %q", reply.From)
	}
}

func TestForeignRepliesAreDiscarded(t *testing.T) {
	const (
		identifier = 4242
		tunnelID   = int64(7)
	)
	packet, _ := Encode(false, identifier, 5, tunnelID, time.Now(), 56)
	payload := packet[8:]

	cases := map[string][]byte{
		"another socket's identifier": replyTo(identifier+1, 5, payload),
		"another tunnel's payload": func() []byte {
			other, _ := Encode(false, identifier, 5, tunnelID+1, time.Now(), 56)
			return replyTo(identifier, 5, other[8:])
		}(),
		"a payload without our marker":            replyTo(identifier, 5, make([]byte, 56)),
		"a payload too short to carry the header": replyTo(identifier, 5, []byte{1, 2, 3}),
		"our own request looped back":             packet,
		"not an ICMP message at all":              {0xff},
	}
	for why, raw := range cases {
		if _, err := Decode(false, identifier, tunnelID, raw, nil); !errors.Is(err, ErrNotOurs) {
			t.Fatalf("%s was accepted as our reply", why)
		}
	}
}

// An ICMP error quotes the datagram that provoked it, and those quoted bytes
// carry the identifier and sequence number. Reading them is what attributes an
// error to the right probe instead of leaving an unexplained loss (§10.1).
func TestIcmpErrorsAreAttributedToTheRightSequence(t *testing.T) {
	const identifier = 4242

	unreachable := errorReply(ipv4.ICMPTypeDestinationUnreachable, 1, identifier, 9)
	reply, err := Decode(false, identifier, 7, unreachable, &net.IPAddr{IP: net.ParseIP("203.0.113.1")})
	if err != nil {
		t.Fatalf("an unreachable error was not matched: %v", err)
	}
	if reply.Kind != ReplyUnreachable || reply.Sequence != 9 {
		t.Fatalf("reply = %+v, want an unreachable for sequence 9", reply)
	}
	if reply.Detail == "" {
		t.Fatal("an error reply must explain itself")
	}

	exceeded := errorReply(ipv4.ICMPTypeTimeExceeded, 0, identifier, 3)
	reply, err = Decode(false, identifier, 7, exceeded, nil)
	if err != nil || reply.Kind != ReplyTimeExceeded || reply.Sequence != 3 {
		t.Fatalf("time-exceeded reply = %+v, %v", reply, err)
	}

	// The path MTU signal: the next-hop MTU comes back with the error.
	tooBig := fragmentationNeeded(identifier, 11, 1400)
	reply, err = Decode(false, identifier, 7, tooBig, nil)
	if err != nil || reply.Kind != ReplyTooBig || reply.Mtu != 1400 {
		t.Fatalf("packet-too-big reply = %+v, %v", reply, err)
	}

	// An error provoked by somebody else's probe is not ours.
	foreign := errorReply(ipv4.ICMPTypeDestinationUnreachable, 1, identifier+1, 9)
	if _, err := Decode(false, identifier, 7, foreign, nil); !errors.Is(err, ErrNotOurs) {
		t.Fatal("an error quoting another socket's probe was accepted")
	}
}

// ---------------------------------------------------------------- the window

func TestWindowCountsLossOnlyAfterTheTimeout(t *testing.T) {
	w := NewWindow(10)
	start := time.Now()

	w.Sent(1, start, 100*time.Millisecond)

	// Still in flight: it is unfinished, not lost. Counting it as a loss here
	// would put a phantom loss rate on every healthy tunnel.
	stats := w.Stats(start.Add(50 * time.Millisecond))
	if stats.Sent != 0 || stats.Pending != 1 || stats.LossPercent != 0 {
		t.Fatalf("a probe inside its timeout was counted: %+v", stats)
	}

	stats = w.Stats(start.Add(150 * time.Millisecond))
	if stats.Sent != 1 || stats.Lost != 1 || stats.LossPercent != 100 {
		t.Fatalf("a probe past its timeout was not counted as lost: %+v", stats)
	}
}

// The rule that stops a slow link being reported as a broken one: a reply that
// arrives after its timeout overrides the loss verdict for that sequence
// (§10.1).
func TestLateReplyOverridesTheLossVerdict(t *testing.T) {
	w := NewWindow(10)
	start := time.Now()

	w.Sent(1, start, 100*time.Millisecond)
	w.Sent(2, start, 100*time.Millisecond)
	w.Reply(2, 5*time.Millisecond, start.Add(5*time.Millisecond))

	// Sequence 1 has timed out and reads as lost.
	stats := w.Stats(start.Add(150 * time.Millisecond))
	if stats.Sent != 2 || stats.Received != 1 || stats.LossPercent != 50 {
		t.Fatalf("before the late reply: %+v", stats)
	}

	// Then it answers, late. The verdict must be revised, not kept.
	if !w.Reply(1, 200*time.Millisecond, start.Add(200*time.Millisecond)) {
		t.Fatal("a late reply was refused")
	}
	stats = w.Stats(start.Add(250 * time.Millisecond))
	if stats.Received != 2 || stats.Lost != 0 || stats.LossPercent != 0 {
		t.Fatalf("the late reply did not override the loss verdict: %+v", stats)
	}
	if stats.RttMaxMs == nil || *stats.RttMaxMs < 199 {
		t.Fatalf("the late round-trip time was not recorded: %+v", stats.RttMaxMs)
	}
}

func TestWindowStatistics(t *testing.T) {
	w := NewWindow(10)
	start := time.Now()

	for i, rtt := range []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond} {
		w.Sent(i, start, time.Second)
		w.Reply(i, rtt, start)
	}
	stats := w.Stats(start.Add(time.Millisecond))

	if stats.Sent != 3 || stats.Received != 3 || stats.LossPercent != 0 {
		t.Fatalf("counts = %+v", stats)
	}
	if *stats.RttMinMs != 10 || *stats.RttMaxMs != 30 || *stats.RttAvgMs != 20 {
		t.Fatalf("min/avg/max = %v/%v/%v", *stats.RttMinMs, *stats.RttAvgMs, *stats.RttMaxMs)
	}
	// The population standard deviation of 10, 20 and 30 is 8.1649...
	if *stats.RttMdevMs < 8.16 || *stats.RttMdevMs > 8.17 {
		t.Fatalf("mdev = %v", *stats.RttMdevMs)
	}
	// Jitter is the mean absolute successive difference: |20-10| and |30-20|.
	if *stats.JitterMs != 10 {
		t.Fatalf("jitter = %v, want 10", *stats.JitterMs)
	}
}

func TestWindowKeepsOnlyTheLastN(t *testing.T) {
	w := NewWindow(3)
	start := time.Now()
	for i := 0; i < 10; i++ {
		w.Sent(i, start, time.Millisecond)
	}
	stats := w.Stats(start.Add(time.Second))
	if stats.Sent != 3 {
		t.Fatalf("the window kept %d probes, want 3", stats.Sent)
	}

	// Shrinking at runtime drops the oldest rather than needing a restart.
	w.Resize(1)
	if stats := w.Stats(start.Add(time.Second)); stats.Sent != 1 {
		t.Fatalf("after resizing the window kept %d probes, want 1", stats.Sent)
	}
}

func TestWindowRecordsIcmpErrorsAsImmediateFailures(t *testing.T) {
	w := NewWindow(10)
	start := time.Now()

	w.Sent(1, start, time.Hour) // a long timeout it will never reach
	w.Error(1, "no route to the target host")

	stats := w.Stats(time.Now())
	if stats.Sent != 1 || stats.Lost != 1 {
		t.Fatalf("an ICMP error must decide the probe at once: %+v", stats)
	}
	if stats.LastError != "no route to the target host" {
		t.Fatalf("last error = %q", stats.LastError)
	}
}

// ---------------------------------------------------------------- state machine

func TestClassify(t *testing.T) {
	cfg := Config{DegradedLossPercent: 20, DownLossPercent: 100, StateChangeSamples: 3}

	cases := []struct {
		name  string
		stats Stats
		want  int64
	}{
		{"not enough samples yet", Stats{Sent: 2, Received: 2}, model.MonitorStateUnknown},
		{"everything answered", Stats{Sent: 10, Received: 10}, model.MonitorStateUp},
		{"a little loss", Stats{Sent: 10, Received: 9, LossPercent: 10}, model.MonitorStateUp},
		{"loss at the degraded threshold", Stats{Sent: 10, Received: 8, LossPercent: 20}, model.MonitorStateDegraded},
		{"total loss", Stats{Sent: 10, Received: 0, LossPercent: 100}, model.MonitorStateDown},
	}
	for _, tc := range cases {
		got, reason := Classify(tc.stats, cfg)
		if got != tc.want {
			t.Fatalf("%s: state = %s, want %s", tc.name, StateName(got), StateName(tc.want))
		}
		if reason == "" {
			t.Fatalf("%s: every verdict must explain itself", tc.name)
		}
	}

	// The latency criterion is off unless a threshold is set.
	slow := Stats{Sent: 10, Received: 10, RttAvgMs: floatPtr(500)}
	if state, _ := Classify(slow, cfg); state != model.MonitorStateUp {
		t.Fatal("with no latency threshold a slow but lossless link is up")
	}
	cfg.DegradedRttMs = floatPtr(200)
	if state, _ := Classify(slow, cfg); state != model.MonitorStateDegraded {
		t.Fatal("a link past the latency threshold is degraded")
	}
}

// Hysteresis is what stops one lost packet flipping the display (§10.2).
func TestStateMachineHysteresis(t *testing.T) {
	m := NewMachine(3)

	if state, _ := m.Current(); state != model.MonitorStateUnknown {
		t.Fatal("a machine starts in Unknown")
	}

	// Two agreeing samples are not enough.
	for i := 0; i < 2; i++ {
		if _, changed := m.Observe(model.MonitorStateUp, "answered"); changed {
			t.Fatalf("the state changed after only %d agreeing samples", i+1)
		}
	}
	transition, changed := m.Observe(model.MonitorStateUp, "answered")
	if !changed || transition.To != model.MonitorStateUp {
		t.Fatalf("the third agreeing sample must change the state: %+v %v", transition, changed)
	}

	// A single disagreeing sample does not flip it back, and it resets the run.
	if _, changed := m.Observe(model.MonitorStateDown, "lost"); changed {
		t.Fatal("one lost sample flipped the state")
	}
	if _, changed := m.Observe(model.MonitorStateUp, "answered"); changed {
		t.Fatal("returning to the current state is not a transition")
	}
	// The Down run has to start again from scratch.
	for i := 0; i < 2; i++ {
		if _, changed := m.Observe(model.MonitorStateDown, "lost"); changed {
			t.Fatalf("the state changed after only %d Down samples", i+1)
		}
	}
	transition, changed = m.Observe(model.MonitorStateDown, "lost")
	if !changed || transition.From != model.MonitorStateUp || transition.To != model.MonitorStateDown {
		t.Fatalf("transition = %+v, changed = %v", transition, changed)
	}
}

// Some facts are not measurements and need no corroboration: an interface that
// has vanished is down now, not after three more samples (§10.3).
func TestForceSkipsHysteresis(t *testing.T) {
	m := NewMachine(5)
	transition, changed := m.Force(model.MonitorStateDown, ReasonInterfaceMissing)
	if !changed || transition.To != model.MonitorStateDown {
		t.Fatalf("a forced state must apply at once: %+v %v", transition, changed)
	}
	if _, reason := m.Current(); reason != ReasonInterfaceMissing {
		t.Fatalf("reason = %q, want %q", reason, ReasonInterfaceMissing)
	}
	if _, changed := m.Force(model.MonitorStateDown, ReasonInterfaceMissing); changed {
		t.Fatal("forcing the state it is already in is not a transition")
	}
}

// A fact outranks an inference for as long as it holds.
//
// An interface that has vanished is Down for a reason no probe can discover.
// The evaluator goes on classifying the same window a second later and reaches
// the same state by a vaguer route, and if that overwrote the reason, the
// operator would be told the symptom — every probe is unanswered — rather than
// the cause the panel already knows (§10.3).
func TestAForcedReasonSurvivesTheNextSample(t *testing.T) {
	m := NewMachine(3)

	if _, changed := m.Force(model.MonitorStateDown, ReasonInterfaceMissing); !changed {
		t.Fatal("the forced state must apply at once")
	}
	for i := 0; i < 5; i++ {
		if _, changed := m.Observe(model.MonitorStateDown, "100.0% of probes are unanswered"); changed {
			t.Fatal("observing the state it is already in is not a transition")
		}
	}
	if _, reason := m.Current(); reason != ReasonInterfaceMissing {
		t.Fatalf("reason = %q, want the forced %q", reason, ReasonInterfaceMissing)
	}

	// It holds only until the facts change. Once the interface is back and the
	// probes are answered, the measurement takes over again.
	for i := 0; i < 3; i++ {
		m.Observe(model.MonitorStateUp, "every probe was answered")
	}
	state, reason := m.Current()
	if state != model.MonitorStateUp || reason != "every probe was answered" {
		t.Fatalf("state = %d reason = %q, want Up with the measured reason", state, reason)
	}

	// And having recovered, an ordinary sample may explain itself again.
	m.Observe(model.MonitorStateUp, "9 of 10 probes were answered")
	if _, reason := m.Current(); reason != "9 of 10 probes were answered" {
		t.Fatalf("reason = %q, want the freshest measurement", reason)
	}
}

// A fact that has stopped being true must not outlive its cause.
//
// A prober that could not open its socket forces Unknown with that as the
// reason. When it starts on the next attempt the state has not changed, so
// nothing would replace the explanation, and a running prober would go on
// reporting that it could not run.
func TestAReleasedReasonLetsMeasurementsSpeakAgain(t *testing.T) {
	m := NewMachine(3)
	m.Force(model.MonitorStateUnknown, "the prober could not run: bind: cannot assign requested address")

	m.Release()
	m.Observe(model.MonitorStateUnknown, "only 1 of the 3 probes needed for a verdict have finished")

	if _, reason := m.Current(); reason != "only 1 of the 3 probes needed for a verdict have finished" {
		t.Fatalf("reason = %q, want the measurement that replaced the stale fact", reason)
	}
}

func TestStateNames(t *testing.T) {
	names := map[int64]string{
		model.MonitorStateUnknown:  "Unknown",
		model.MonitorStateUp:       "Up",
		model.MonitorStateDegraded: "Degraded",
		model.MonitorStateDown:     "Down",
		model.MonitorStateDisabled: "Disabled",
	}
	for id, want := range names {
		if got := StateName(id); got != want {
			t.Fatalf("StateName(%d) = %q, want %q", id, got, want)
		}
	}
}

func floatPtr(v float64) *float64 { return &v }
