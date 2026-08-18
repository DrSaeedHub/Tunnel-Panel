package diag

import (
	"context"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/monitor"
)

// The tests in this file are the second half of the settings guard. The coarse
// one in internal/api proves each key is named somewhere outside its own schema
// entry, which only establishes that a reader exists; these prove the reader
// honours what it read. The defect they exist to catch is the one this codebase
// keeps producing: a setting that is stored, validated and described on the
// Settings page, and then quietly ignored by the code that should act on it.
//
// Where it is cheap the assertion is made at two different values, because a
// consumer frozen at any single constant — its own fallback or otherwise — has
// to fail at least one of them, whereas a single value can be satisfied by a
// coincidence.

// set moves settings off their defaults through the real store, so the cross-key
// constraints the store enforces are respected rather than bypassed.
func (h *harness) set(t *testing.T, values map[string]any) {
	t.Helper()
	if _, err := h.settings.Update(context.Background(), values, nil); err != nil {
		t.Fatalf("updating settings failed: %v", err)
	}
}

// ---------------------------------------------------------------- ping

// The default applies only to a request that names no count of its own, so that
// is the request the test sends.
func TestTheDefaultPingCountFollowsTheSetting(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	for _, want := range []int64{2, 5} {
		h.set(t, map[string]any{"diagnostics.manual_ping_count": want})

		var sent int
		if _, err := h.service.Ping(ctx, h.tunnelID,
			PingParams{IntervalSecs: 0.01, TimeoutSecs: 0.2}, nil,
			func(monitor.PingPacket) { sent++ }); err != nil {
			t.Fatal(err)
		}
		if sent != int(want) {
			t.Fatalf("a request naming no count sent %d packets, want the configured default of %d",
				sent, want)
		}
	}
}

// The bound exists so one request cannot tie up a socket for an hour, which
// only holds if the request is clamped to the operator's figure rather than to
// a built-in one.
func TestTheMaximumPingCountFollowsTheSetting(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	for _, maximum := range []int64{4, 7} {
		// The default count moves with the maximum only because the store
		// refuses a maximum below the default. The count itself cannot be what
		// is observed below: the request names one explicitly.
		h.set(t, map[string]any{
			"diagnostics.manual_ping_count":     maximum,
			"diagnostics.manual_ping_max_count": maximum,
		})

		var sent int
		if _, err := h.service.Ping(ctx, h.tunnelID,
			PingParams{Count: 100, IntervalSecs: 0.01, TimeoutSecs: 0.2}, nil,
			func(monitor.PingPacket) { sent++ }); err != nil {
			t.Fatal(err)
		}
		if sent != int(maximum) {
			t.Fatalf("a request for 100 packets sent %d, want the configured maximum of %d",
				sent, maximum)
		}
	}
}

func TestTheDefaultPingIntervalFollowsTheSetting(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	rec, err := h.repo.ByID(ctx, h.tunnelID)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []float64{0.02, 0.25} {
		h.set(t, map[string]any{"diagnostics.manual_ping_interval": want})

		request, err := h.service.pingRequest(rec, PingParams{})
		if err != nil {
			t.Fatal(err)
		}
		if request.Interval != seconds(want) {
			t.Fatalf("a request naming no interval asks for %s between packets, want %s",
				request.Interval, seconds(want))
		}
	}

	// The resolved figure has to reach the wire and not merely the struct.
	// Sending is gated on the clock, so three packets a quarter-second apart
	// cannot be done inside half a second; on the 0.1s default the same run
	// would be over in about a fifth of one.
	h.set(t, map[string]any{"diagnostics.manual_ping_interval": 0.25})
	started := time.Now()
	if _, err := h.service.Ping(ctx, h.tunnelID,
		PingParams{Count: 3, TimeoutSecs: 0.2}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 450*time.Millisecond {
		t.Fatalf("three packets a quarter-second apart took %s, which is too quick to have "+
			"waited out the configured interval", elapsed)
	}
}

func TestTheDefaultPingTimeoutFollowsTheSetting(t *testing.T) {
	// Nothing answers, so the run lasts exactly as long as it is willing to
	// wait — which is the only way the timeout is observable at all.
	h := newHarness(t, func(c *fakeConn, id, sequence int, payload []byte, size int, df bool, ttl int) []byte {
		return nil
	})
	ctx := context.Background()

	rec, err := h.repo.ByID(ctx, h.tunnelID)
	if err != nil {
		t.Fatal(err)
	}

	for _, want := range []float64{0.15, 0.4} {
		h.set(t, map[string]any{"diagnostics.manual_ping_timeout": want})

		request, err := h.service.pingRequest(rec, PingParams{})
		if err != nil {
			t.Fatal(err)
		}
		if request.Timeout != seconds(want) {
			t.Fatalf("a request naming no timeout waits %s per packet, want %s",
				request.Timeout, seconds(want))
		}
	}

	h.set(t, map[string]any{"diagnostics.manual_ping_timeout": 0.15})
	started := time.Now()
	if _, err := h.service.Ping(ctx, h.tunnelID,
		PingParams{Count: 1, IntervalSecs: 0.01}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 700*time.Millisecond {
		t.Fatalf("one unanswered packet held the run for %s, which is the built-in one-second "+
			"wait rather than the configured 0.15s", elapsed)
	}
}

// ---------------------------------------------------------------- MTU probe

// The floor is the size the search establishes works before it searches above
// it, so it is always the first step and is directly observable there.
func TestTheMtuSearchFloorFollowsTheSetting(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	for _, low := range []int64{1000, 1300} {
		h.set(t, map[string]any{"diagnostics.mtu_probe_min": low})

		_, result, err := h.service.MtuProbe(ctx, h.tunnelID, MtuParams{TimeoutSecs: 0.2})
		if err != nil {
			t.Fatalf("the probe failed: %v", err)
		}
		if len(result.Steps) == 0 {
			t.Fatal("the search recorded no steps")
		}
		if result.Steps[0].PacketSize != int(low) {
			t.Fatalf("the search started at %d bytes, want the configured floor of %d",
				result.Steps[0].PacketSize, low)
		}
	}
}

// Every size gets through against this peer, so the search can only stop where
// the ceiling tells it to: whatever it discovers is the ceiling itself.
func TestTheMtuSearchCeilingFollowsTheSetting(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	ctx := context.Background()

	for _, high := range []int64{1300, 1450} {
		h.set(t, map[string]any{"diagnostics.mtu_probe_max": high})

		_, result, err := h.service.MtuProbe(ctx, h.tunnelID, MtuParams{TimeoutSecs: 0.2})
		if err != nil {
			t.Fatalf("the probe failed: %v", err)
		}
		if result.DiscoveredPathMtu != int(high) {
			t.Fatalf("the search stopped at %d bytes with nothing refusing a packet, want the "+
				"configured ceiling of %d", result.DiscoveredPathMtu, high)
		}
	}
}

// ---------------------------------------------------------------- capture

// Switching the capture off has to stop tcpdump being run, not merely relabel
// the evidence: the setting exists for operators who will not have a packet
// capture taken on their host, and a capture that ran and was then described as
// forbidden would break exactly the promise they relied on.
func TestPacketCaptureFollowsTheAllowTcpdumpSetting(t *testing.T) {
	h := newHarness(t, alwaysAnswer)
	// The capture only runs when a tcpdump was resolved at startup, so the
	// harness pretends one was; otherwise both halves would be skipped for the
	// wrong reason.
	h.service.tcpdumpBin = "/usr/bin/tcpdump"
	ctx := context.Background()

	h.set(t, map[string]any{"diagnostics.allow_tcpdump": false})
	_, result, err := h.service.Analyze(ctx, h.tunnelID,
		AnalyzeParams{SampleSeconds: 0.05, Capture: true})
	if err != nil {
		t.Fatal(err)
	}
	if ranTcpdump(h) {
		t.Fatal("tcpdump was run even though the setting forbids packet capture")
	}
	capture := evidenceNamed(result, "capture")
	if capture == nil {
		t.Fatal("a refused capture must still be reported, so the operator knows why there is no evidence")
	}
	if !contains(capture.Detail, "switched off") {
		t.Fatalf("the evidence should say the capture was switched off: %q", capture.Detail)
	}

	// And switching it back on has to let the capture run, otherwise the first
	// half would pass against a consumer that never captures at all.
	h.set(t, map[string]any{"diagnostics.allow_tcpdump": true})
	if _, _, err := h.service.Analyze(ctx, h.tunnelID,
		AnalyzeParams{SampleSeconds: 0.05, Capture: true}); err != nil {
		t.Fatal(err)
	}
	if !ranTcpdump(h) {
		t.Fatalf("no capture was taken with the setting allowing it; the runner saw %v", h.runner.Calls())
	}
}

// ranTcpdump reports whether the fake runner was asked to capture.
func ranTcpdump(h *harness) bool {
	for _, call := range h.runner.Calls() {
		if len(call) > 0 && contains(call[0], "tcpdump") {
			return true
		}
	}
	return false
}

// evidenceNamed picks one check out of a verdict's evidence.
func evidenceNamed(result AnalyzeResult, name string) *Evidence {
	for i := range result.Evidence {
		if result.Evidence[i].Name == name {
			return &result.Evidence[i]
		}
	}
	return nil
}
