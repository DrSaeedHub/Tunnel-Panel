package monitor

import (
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
)

// The condition this panel is used in more often than not: a path where
// something along the way drops ICMP while carrying data perfectly well.
//
// Calling that down is not merely a wrong label. It is the input to everything
// that acts on a tunnel being down, so a link running at full speed gets torn
// up and rebuilt on a schedule, and an operator watching the panel is told the
// tunnel is dead while their users are using it.
func TestAFilteredPathCarryingTrafficIsNotDown(t *testing.T) {
	cfg := Config{
		StateChangeSamples:  3,
		DownLossPercent:     80,
		DegradedLossPercent: 20,
	}

	// Every probe lost, and the interface moved bytes between samples.
	state, reason := Classify(Stats{
		Sent: 10, Received: 0, Lost: 10, LossPercent: 100, CarryingTraffic: true,
	}, cfg)
	if state != model.MonitorStateUp {
		t.Errorf("state = %s, want Up: the link is carrying traffic", StateName(state))
	}
	if !strings.Contains(reason, "carrying traffic") {
		t.Errorf("the reason does not say why the probes are being ignored: %q", reason)
	}

	// The same probes with nothing crossing the interface is a tunnel that is
	// genuinely down, and still reads that way.
	state, _ = Classify(Stats{
		Sent: 10, Received: 0, Lost: 10, LossPercent: 100, CarryingTraffic: false,
	}, cfg)
	if state != model.MonitorStateDown {
		t.Errorf("state = %s, want Down: nothing answers and nothing is moving", StateName(state))
	}
}

// Partial loss is real loss. Some probes came back, so the far end is
// answering, and traffic moving does not make the loss disappear.
func TestTrafficDoesNotHidePartialLoss(t *testing.T) {
	cfg := Config{StateChangeSamples: 3, DownLossPercent: 80, DegradedLossPercent: 20}
	state, _ := Classify(Stats{
		Sent: 10, Received: 6, Lost: 4, LossPercent: 40, CarryingTraffic: true,
	}, cfg)
	if state != model.MonitorStateDegraded {
		t.Errorf("state = %s, want Degraded", StateName(state))
	}
}

// One reading is not a measurement: the first sample establishes the baseline
// and reports nothing, or every interface would look busy the moment it was
// first looked at.
func TestTheFirstTrafficReadingIsOnlyABaseline(t *testing.T) {
	reader := &fakeTraffic{totals: map[string]uint64{"gre-a-1": 1000}}
	watch := &trafficWatch{reader: reader}

	if watch.moved("gre-a-1") {
		t.Error("the first reading reported movement it could not have measured")
	}
	if watch.moved("gre-a-1") {
		t.Error("an unchanged counter reported movement")
	}
	reader.totals["gre-a-1"] = 1200
	if !watch.moved("gre-a-1") {
		t.Error("a counter that advanced reported no movement")
	}

	// An interface that was recreated has a counter lower than last time. That
	// is a sign of life rather than of silence: the packets crossed the new one.
	reader.totals["gre-a-1"] = 40
	if !watch.moved("gre-a-1") {
		t.Error("a recreated interface reported no movement")
	}

	// An interface with no counters to read is not a claim either way.
	if watch.moved("gone") {
		t.Error("an interface that does not exist reported movement")
	}
}

type fakeTraffic struct{ totals map[string]uint64 }

func (f *fakeTraffic) Bytes(name string) (uint64, bool) {
	total, ok := f.totals[name]
	return total, ok
}
