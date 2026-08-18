package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/tunnel"
)

// These tests cover the monitor.* settings. The coarse check in internal/api
// proves each key is named somewhere; these prove the value is honoured.
//
// Almost every threshold here is resolved in ConfigFor, which is the one place
// a global setting and a tunnel's nullable override are combined (§6, §10.2).
// That makes it the right seam to assert on: the resolved Config is what the
// prober is actually built from, so a value that reaches Config reaches the
// wire. Each is asserted at two distinct non-default values, because a reader
// frozen at any single constant has to fail one of them.

// probeSettings answers the monitor Settings interface from a map. A key that is
// absent answers the zero value, which is what the real store never does — so
// every test here sets what it depends on.
type probeSettings map[string]any

func (s probeSettings) Bool(key string) bool     { b, _ := s[key].(bool); return b }
func (s probeSettings) Int(key string) int64     { n, _ := s[key].(int64); return n }
func (s probeSettings) Float(key string) float64 { f, _ := s[key].(float64); return f }
func (s probeSettings) String(key string) string { v, _ := s[key].(string); return v }
func (s probeSettings) FloatPtr(key string) *float64 {
	f, ok := s[key].(float64)
	if !ok {
		return nil
	}
	return &f
}

// inheriting is a tunnel that overrides nothing, so every threshold comes from
// the settings. Overriding is a separate property with its own tests; what is
// asserted here is that the inherited value is the configured one.
func inheriting() tunnel.Record {
	peer := "172.17.1.2"
	rec := tunnel.Record{}
	rec.TunnelID = 1
	rec.InterfaceName = "gre-a-1"
	rec.IsEnabled = true
	rec.Addresses = []model.TunnelAddress{{
		TunnelID: 1, Address: "172.17.1.1", PrefixLength: 30, PeerAddress: &peer, IsPrimary: true,
	}}
	return rec
}

// configWith resolves a tunnel that inherits everything, against settings whose
// monitoring is switched on.
func configWith(values probeSettings) Config {
	values["monitor.enabled"] = true
	return ConfigFor(inheriting(), values)
}

func TestTheProbeIntervalFollowsTheSetting(t *testing.T) {
	for _, want := range []float64{0.5, 7.5} {
		cfg := configWith(probeSettings{"monitor.interval_seconds": want})
		if cfg.Interval != seconds(want) {
			t.Fatalf("a tunnel that overrides nothing probes every %s, want %s",
				cfg.Interval, seconds(want))
		}
	}
}

func TestTheProbeTimeoutFollowsTheSetting(t *testing.T) {
	for _, want := range []float64{0.25, 9} {
		cfg := configWith(probeSettings{"monitor.timeout_seconds": want})
		if cfg.Timeout != seconds(want) {
			t.Fatalf("a tunnel that overrides nothing waits %s per probe, want %s",
				cfg.Timeout, seconds(want))
		}
	}
}

func TestTheProbePacketSizeFollowsTheSetting(t *testing.T) {
	// Both well above MinPacketSize, which is clamped up to and would otherwise
	// mask the setting entirely.
	for _, want := range []int64{120, 1400} {
		cfg := configWith(probeSettings{"monitor.packet_size": want})
		if cfg.PacketSize != int(want) {
			t.Fatalf("the probe carries %d bytes, want the configured %d", cfg.PacketSize, want)
		}
	}
}

// The window is how many samples the loss figure is computed over, so it decides
// how quickly a tunnel is called down and how long it stays that way.
func TestTheProbeWindowFollowsTheSetting(t *testing.T) {
	for _, want := range []int64{5, 240} {
		cfg := configWith(probeSettings{"monitor.window_size": want})
		if cfg.WindowSize != int(want) {
			t.Fatalf("the loss window holds %d samples, want the configured %d",
				cfg.WindowSize, want)
		}
	}
}

func TestTheDegradedLossThresholdFollowsTheSetting(t *testing.T) {
	for _, want := range []float64{5, 45} {
		cfg := configWith(probeSettings{"monitor.degraded_loss_pct": want})
		if cfg.DegradedLossPercent != want {
			t.Fatalf("degraded starts at %.1f%% loss, want the configured %.1f%%",
				cfg.DegradedLossPercent, want)
		}
	}
}

func TestTheDownLossThresholdFollowsTheSetting(t *testing.T) {
	for _, want := range []float64{75, 90} {
		cfg := configWith(probeSettings{"monitor.down_loss_pct": want})
		if cfg.DownLossPercent != want {
			t.Fatalf("down starts at %.1f%% loss, want the configured %.1f%%",
				cfg.DownLossPercent, want)
		}
	}
}

func TestTheStateChangeSamplesFollowTheSetting(t *testing.T) {
	for _, want := range []int64{2, 9} {
		cfg := configWith(probeSettings{"monitor.state_change_samples": want})
		if cfg.StateChangeSamples != int(want) {
			t.Fatalf("a state change needs %d consecutive samples, want the configured %d",
				cfg.StateChangeSamples, want)
		}
	}
}

// The latency threshold is nullable at both levels, and null is a real value:
// globally it means the criterion is off entirely. A reader that turned an
// absent setting into some number would call tunnels degraded on latency the
// operator never asked to be judged on.
func TestTheDegradedRttThresholdFollowsTheSetting(t *testing.T) {
	for _, want := range []float64{25, 400} {
		cfg := configWith(probeSettings{"monitor.degraded_rtt_ms": want})
		if cfg.DegradedRttMs == nil {
			t.Fatalf("the configured %.0fms latency threshold did not reach the config", want)
		}
		if *cfg.DegradedRttMs != want {
			t.Fatalf("degraded starts at %.0fms, want the configured %.0fms", *cfg.DegradedRttMs, want)
		}
	}

	if cfg := configWith(probeSettings{}); cfg.DegradedRttMs != nil {
		t.Fatalf("with no latency threshold configured the criterion must be off, got %.0fms",
			*cfg.DegradedRttMs)
	}
}

// The aggregate interval is the width of a history bucket: a bucket is written
// once it is older than the interval and left open until then. It is asserted
// through flushHistory, which is the code that reads the setting.
func TestTheHistoryBucketWidthFollowsTheSetting(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// The history rows reference the real table, so the tunnel has to exist for
	// a flushed bucket to land rather than being dropped on a foreign key.
	h.seedTunnelRow(t, 1, "gre-a-1")

	// A bucket opened ninety seconds ago, which is the thing the interval is
	// compared against.
	openBucket := func() {
		h.supervisor.aggregator.add(Config{TunnelID: 1}, Stats{Sent: 5, Received: 5},
			model.MonitorStateUp, time.Now().Add(-90*time.Second))
	}

	// Wider than the bucket's age: nothing is due, so it stays open.
	h.setSetting(t, "monitor.aggregate_interval_seconds", int64(600))
	openBucket()
	h.supervisor.flushHistory(ctx)
	if got := h.openBuckets(); got != 1 {
		t.Fatalf("%d buckets are open after a flush at a ten-minute interval, want the "+
			"ninety-second-old one to still be open", got)
	}

	// Narrower than its age: now it is due and gets written.
	h.setSetting(t, "monitor.aggregate_interval_seconds", int64(60))
	h.supervisor.flushHistory(ctx)
	if got := h.openBuckets(); got != 0 {
		t.Fatalf("%d buckets are still open after a flush at a one-minute interval, want the "+
			"ninety-second-old one written out", got)
	}
	if got := h.storedSamples(t); got != 1 {
		t.Fatalf("%d samples were written, want the one flushed bucket", got)
	}
}

// openBuckets counts the aggregator's unwritten buckets.
func (h *harness) openBuckets() int {
	h.supervisor.aggregator.mu.Lock()
	defer h.supervisor.aggregator.mu.Unlock()
	return len(h.supervisor.aggregator.buckets)
}

// storedSamples counts the history rows actually on disk.
func (h *harness) storedSamples(t *testing.T) int {
	t.Helper()
	var n int
	if err := h.database.Read.QueryRow(`SELECT COUNT(*) FROM MonitorSample`).Scan(&n); err != nil {
		t.Fatalf("counting the stored samples failed: %v", err)
	}
	return n
}

// setSetting moves one setting through the real store.
func (h *harness) setSetting(t *testing.T, key string, value any) {
	t.Helper()
	if _, err := h.settings.Update(context.Background(), map[string]any{key: value}, nil); err != nil {
		t.Fatalf("setting %s failed: %v", key, err)
	}
}
