package metrics

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestTheFirstSampleCarriesEmptyListsRatherThanNulls is the regression for a
// dashboard that broke for the first sampling interval after every restart.
//
// CPU utilisation is a delta, so the first reading has nothing to subtract from
// and no per-core figures. The field was left as a nil Go slice, which
// encoding/json writes as `null`, and the browser read `point.cpu[0]` and threw
// — taking the Disk and Traffic cards down with it. It recovered a second later
// when the next sample arrived, which is precisely why it survived: it is only
// visible in the moments after an upgrade, when somebody is looking at the
// panel because they have just upgraded it.
//
// A nil slice becoming `null` is an accident of the encoder rather than
// anything anyone meant to say. An empty list says the true thing — no figures
// for this reading — in a shape every consumer already handles.
func TestTheFirstSampleCarriesEmptyListsRatherThanNulls(t *testing.T) {
	sampler := New(Deps{Reader: fixtureReader()})

	// The very first sample: no previous reading exists, so there is no CPU
	// delta to report.
	first := sampler.Sample(context.Background())
	if len(first.Cpu) != 0 {
		t.Fatalf("the first sample reported %d CPU entries; it cannot have any", len(first.Cpu))
	}

	for _, snapshot := range []struct {
		name string
		snap Snapshot
	}{
		{"the first sample", first},
		// Reachable before any sample has run: a request landing between the
		// panel answering and the sampler first ticking gets the zero value.
		{"the latest before any sample", New(Deps{Reader: fixtureReader()}).Latest()},
	} {
		encoded, err := json.Marshal(snapshot.snap)
		if err != nil {
			t.Fatalf("%s: encoding failed: %v", snapshot.name, err)
		}
		body := string(encoded)

		for _, field := range []string{`"cpu":null`, `"disks":null`, `"interfaces":null`} {
			if strings.Contains(body, field) {
				t.Errorf("%s encodes %s, which every consumer has to guard against separately:\n%s",
					snapshot.name, field, body)
			}
		}
		for _, field := range []string{`"cpu":[`, `"disks":[`, `"interfaces":[`} {
			if !strings.Contains(body, field) {
				t.Errorf("%s does not encode %s as a list at all:\n%s", snapshot.name, field, body)
			}
		}
	}
}

// TestASecondSampleReportsCpu holds the other side: making the first sample's
// list empty must not stop the second one reporting real figures.
func TestASecondSampleReportsCpu(t *testing.T) {
	sampler := New(Deps{Reader: fixtureReader()})
	ctx := context.Background()

	sampler.Sample(ctx)
	second := sampler.Sample(ctx)

	if len(second.Cpu) == 0 {
		t.Error("the second sample reported no CPU usage; the delta should be available by then")
	}
}
