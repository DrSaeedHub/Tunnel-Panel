package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/drs/gre-panel/internal/validate"
)

// A control that collects a value and a request that never carries it is the
// same defect as having no control at all, and it is harder to see: the field
// is on screen, it accepts input, and nothing looks wrong. The tunnel form
// rendered all eight monitoring overrides and sent none of them.
func TestTheFormSendsEveryMonitoringOverrideItRenders(t *testing.T) {
	source, err := os.ReadFile(filepath.Join("..", "..", "web", "_app", "src",
		"components", "tunnels", "TunnelFormDialog.tsx"))
	if err != nil {
		t.Fatalf("reading the tunnel form: %v", err)
	}
	form := string(source)

	rendered := regexp.MustCompile(`value=\{form\.(monitor_[a-z_]+)\}`)
	found := map[string]bool{}
	for _, match := range rendered.FindAllStringSubmatch(form, -1) {
		found[match[1]] = true
	}
	if len(found) == 0 {
		t.Fatal("no monitoring override control was found; the pattern is not matching")
	}

	for field := range found {
		if !regexp.MustCompile(`patch\.` + field + `\s*=`).MatchString(form) {
			t.Errorf("the form renders a control for %s and never puts it in the request, "+
				"so an operator can set it and watch nothing happen", field)
		}
	}
}

// The per-tunnel monitoring overrides were modelled, persisted, read back and
// resolved by monitor.ConfigFor — and no endpoint would accept them, so the
// resolution chain had never once run with a non-null per-tunnel value. An
// unreachable path does not only withhold a capability; it hides whatever is
// broken behind it, which is exactly what the IPv6 hop limit turned out to be
// doing once a control could finally set it.
func TestTheUpdatePayloadCarriesTheMonitoringOverrides(t *testing.T) {
	// A tunnel that currently inherits everything except the packet size.
	existing := int64(120)
	in := validate.TunnelInput{MonitorPacketSize: &existing}

	var patch tunnelPatch
	body := `{
		"monitor_interval_seconds": 0.5,
		"monitor_timeout_seconds": 1.5,
		"monitor_window_size": 30,
		"monitor_degraded_rtt_ms": 250.5,
		"monitor_state_change_samples": 2
	}`
	if err := json.Unmarshal([]byte(body), &patch); err != nil {
		t.Fatalf("decoding the patch: %v", err)
	}
	patch.applyTo(&in)

	if in.MonitorIntervalSeconds == nil || *in.MonitorIntervalSeconds != 0.5 {
		t.Errorf("monitor_interval_seconds did not reach the input: %v", in.MonitorIntervalSeconds)
	}
	if in.MonitorTimeoutSeconds == nil || *in.MonitorTimeoutSeconds != 1.5 {
		t.Errorf("monitor_timeout_seconds did not reach the input: %v", in.MonitorTimeoutSeconds)
	}
	if in.MonitorWindowSize == nil || *in.MonitorWindowSize != 30 {
		t.Errorf("monitor_window_size did not reach the input: %v", in.MonitorWindowSize)
	}
	if in.MonitorDegradedRttMs == nil || *in.MonitorDegradedRttMs != 250.5 {
		t.Errorf("monitor_degraded_rtt_ms did not reach the input: %v", in.MonitorDegradedRttMs)
	}
	if in.MonitorStateChangeSamples == nil || *in.MonitorStateChangeSamples != 2 {
		t.Errorf("monitor_state_change_samples did not reach the input: %v", in.MonitorStateChangeSamples)
	}
	// A field the patch never mentioned keeps what the tunnel already had.
	if in.MonitorPacketSize == nil || *in.MonitorPacketSize != 120 {
		t.Errorf("an unmentioned override was not preserved: %v", in.MonitorPacketSize)
	}
}

// Null is the instruction that clears an override back to the global, and it
// has to be distinguishable from a field that was simply not mentioned — the
// same reason nullableInt exists for the GRE keys.
func TestSendingNullClearsAnOverrideBackToTheGlobal(t *testing.T) {
	interval, packet := 0.5, int64(120)
	in := validate.TunnelInput{MonitorIntervalSeconds: &interval, MonitorPacketSize: &packet}

	var patch tunnelPatch
	if err := json.Unmarshal([]byte(`{"monitor_interval_seconds": null}`), &patch); err != nil {
		t.Fatalf("decoding the patch: %v", err)
	}
	patch.applyTo(&in)

	if in.MonitorIntervalSeconds != nil {
		t.Errorf("null did not clear the override: %v", *in.MonitorIntervalSeconds)
	}
	if in.MonitorPacketSize == nil || *in.MonitorPacketSize != 120 {
		t.Error("clearing one override disturbed another the request never mentioned")
	}
}
