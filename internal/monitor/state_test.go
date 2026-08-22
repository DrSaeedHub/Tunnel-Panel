package monitor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
)

// The condition this panel is used in more often than not: a path where
// something along the way drops ICMP while carrying data perfectly well.
//
// Calling that down is not merely a wrong label. It is the input to everything
// that acts on a tunnel being down, so a link running at full speed gets torn
// up and rebuilt on a schedule, and an operator watching the panel is told the
// tunnel is dead while their users are using it. The far end answering a TCP
// connection is what settles it -- and it is the only thing that does.
func TestOnlyTheFarEndAnsweringOverrulesTheProbes(t *testing.T) {
	cfg := Config{
		StateChangeSamples:  3,
		DownLossPercent:     80,
		DegradedLossPercent: 20,
	}

	state, reason := Classify(Stats{
		Sent: 10, Received: 0, Lost: 10, LossPercent: 100, PeerAnswered: true,
	}, cfg)
	if state != model.MonitorStateUp {
		t.Errorf("state = %s, want Up: the far end answered across the tunnel", StateName(state))
	}
	if !strings.Contains(reason, "TCP") {
		t.Errorf("the reason does not say what settled it: %q", reason)
	}

	// Nothing answering by either means is a tunnel that is genuinely down.
	// This is the case the interface's byte counters used to get wrong: a GRE
	// interface whose far end was never built counts every probe sent out of
	// it, so the counters read as busy while the tunnel carried nothing.
	state, _ = Classify(Stats{
		Sent: 10, Received: 0, Lost: 10, LossPercent: 100, PeerAnswered: false,
	}, cfg)
	if state != model.MonitorStateDown {
		t.Errorf("state = %s, want Down: nothing answers by either means", StateName(state))
	}
}

// Partial loss is real loss. Some probes came back, so the far end is
// answering ICMP, and the ones that did not come back were dropped.
func TestPartialLossIsDegradedWhateverTheFarEndSays(t *testing.T) {
	cfg := Config{StateChangeSamples: 3, DownLossPercent: 80, DegradedLossPercent: 20}
	state, _ := Classify(Stats{
		Sent: 10, Received: 6, Lost: 4, LossPercent: 40, PeerAnswered: true,
	}, cfg)
	if state != model.MonitorStateDegraded {
		t.Errorf("state = %s, want Degraded", StateName(state))
	}
}

// The knock costs a round trip and a socket, and the answer does not change
// between one probe interval and the next.
func TestTheFarEndIsNotKnockedOnEveryInterval(t *testing.T) {
	checker := &countingPeer{answer: true}
	watch := &peerWatch{checker: checker}
	cfg := Config{Source: "172.17.1.1", Target: "172.17.1.2", Timeout: time.Second}

	for i := 0; i < 20; i++ {
		if !watch.answered(context.Background(), cfg) {
			t.Fatal("the remembered answer was lost")
		}
	}
	if checker.calls != 1 {
		t.Errorf("knocked %d times in twenty intervals, want once", checker.calls)
	}
}

type countingPeer struct {
	answer bool
	calls  int
}

func (c *countingPeer) Answered(context.Context, string, string, time.Duration) bool {
	c.calls++
	return c.answer
}
