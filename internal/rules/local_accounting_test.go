package rules

import (
	"strings"
	"testing"
)

// A rule that also relays traffic the server itself originates has to count
// that traffic. The accounting chain hooks `forward`, and locally-originated
// packets never traverse it: they go output → postrouting on the way out and
// input on the way back. So the counters stayed at zero for traffic the rule
// was demonstrably carrying.
//
// Measured on a live host, with a rule relaying 203.0.113.10:21001 to another
// server's panel and local relaying enabled:
//
//	GET through the forward           -> 200, the far end answered
//	GET /routes/40/connections        -> 7 connections, ESTABLISHED
//	nft list counters                 -> route_40_rx packets 0 bytes 0
//	                                     route_40_tx packets 0 bytes 0
//
// Seven live connections and no bytes is not a plausible pair of readings, and
// the interface shows both, side by side.
func TestLocallyOriginatedTrafficIsCounted(t *testing.T) {
	spec := baseSpec()
	spec.IncludeLocalOriginated = true

	payload, err := nftBackend().Render(Ruleset{Routes: []RouteSpec{spec}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text := payload.Parts[0].Text

	// The counters have to be referenced from a chain each direction of that
	// traffic actually passes through. The names are the same objects the
	// forward accounting uses, so a rule's total covers both paths.
	for _, want := range []struct {
		hook, counter, describes string
	}{
		{"hook output", `counter name "route_1_tx"`, "traffic this server sends to the destination"},
		{"hook input", `counter name "route_1_rx"`, "the replies coming back to it"},
	} {
		if !countedUnder(text, want.hook, want.counter) {
			t.Errorf("no %s under a chain hooked on %s, so %s is never counted",
				want.counter, want.hook, want.describes)
		}
	}
}

// A rule that does not relay local traffic must not grow the chains for it —
// an empty chain on every host would be noise, and the renderer omits chains
// with no rules everywhere else.
func TestAnOrdinaryRuleGrowsNoLocalAccountingChains(t *testing.T) {
	payload, err := nftBackend().Render(Ruleset{Routes: []RouteSpec{baseSpec()}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	text := payload.Parts[0].Text

	for _, hook := range []string{"hook output", "hook input"} {
		if strings.Contains(text, hook) {
			t.Errorf("a rule that does not relay local traffic declared a chain on %s", hook)
		}
	}
}

// countedUnder reports whether the counter appears inside a chain whose
// declaration carries the hook. Searching the whole payload would pass on the
// forward accounting alone, which is the bug this is here to catch.
//
// The hook is on the line after `chain <name> {`, not on it — reading only the
// first line found nothing and reported the fix as absent when it was present.
func countedUnder(text, hook, counter string) bool {
	for _, block := range strings.Split(text, "\tchain ")[1:] {
		lines := strings.SplitN(block, "\n", 3)
		if len(lines) < 2 || !strings.Contains(lines[1], hook) {
			continue
		}
		if strings.Contains(block, counter) {
			return true
		}
	}
	return false
}
