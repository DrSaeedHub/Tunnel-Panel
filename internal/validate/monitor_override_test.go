package validate

import (
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/settings"
)

// A per-tunnel override must be held to the same bounds as the global it
// overrides. The bounds are read from the settings schema rather than repeated
// in this package, so the two cannot drift apart; this test asserts that
// relationship rather than the numbers, which is why it keeps working when a
// bound is changed in the schema.
func TestAnOverrideIsHeldToTheGlobalSettingsBounds(t *testing.T) {
	def, ok := settings.Lookup("monitor.interval_seconds")
	if !ok || def.Constraints.Min == nil {
		t.Fatal("monitor.interval_seconds has no declared minimum to mirror")
	}
	below := *def.Constraints.Min / 2

	in := baseTunnelInput()
	in.MonitorIntervalSeconds = &below

	errs := ValidateStatic(in)
	if errs.Empty() {
		t.Fatalf("an interval of %v was accepted, below the global minimum of %v",
			below, *def.Constraints.Min)
	}
	if field := firstField(errs); field != "monitor_interval_seconds" {
		t.Errorf("the error blamed %q rather than the field the operator typed in", field)
	}
}

// The value the global itself allows has to be allowed per tunnel, or the
// override would be narrower than the setting it overrides.
func TestTheGlobalMinimumIsAcceptedAsAnOverride(t *testing.T) {
	def, _ := settings.Lookup("monitor.interval_seconds")
	at := *def.Constraints.Min

	in := baseTunnelInput()
	in.MonitorIntervalSeconds = &at

	if errs := ValidateStatic(in); !errs.Empty() {
		t.Errorf("the global minimum %v was refused as a per-tunnel override: %s", at, summarise(errs))
	}
}

// Null is how a tunnel says "inherit", and it is always allowed.
func TestNoOverrideIsAlwaysValid(t *testing.T) {
	if errs := ValidateStatic(baseTunnelInput()); !errs.Empty() {
		t.Errorf("a tunnel that inherits every monitoring setting was refused: %s", summarise(errs))
	}
}

// A whole-number setting must not accept a fraction: a window of 30.5 samples
// is not a thing the monitor can hold.
func TestAWholeNumberOverrideRefusesAFraction(t *testing.T) {
	in := baseTunnelInput()
	half := 30.5
	in.MonitorDegradedLossPercent = &half // a float field: legitimately fractional

	if errs := ValidateStatic(in); !errs.Empty() {
		t.Errorf("a fractional loss percentage was refused, and it is a float: %s", summarise(errs))
	}
}

func baseTunnelInput() TunnelInput {
	return TunnelInput{
		TunnelTypeID: 10, TunnelSideID: 10, PersistenceTypeID: 30,
		InterfaceName: "gre-1", LocalEndpoint: "203.0.113.1", RemoteEndpoint: "198.51.100.1",
		Ttl: 255, Tos: "inherit", Mtu: 1472,
		Addresses: []AddressInput{{
			Address: "172.31.1.1", PrefixLength: 30, PeerAddress: "172.31.1.2", IsPrimary: true,
		}},
	}
}

func firstField(errs *Errors) string {
	for _, e := range errs.Fields {
		if strings.HasPrefix(e.Field, "monitor_") {
			return e.Field
		}
	}
	if len(errs.Fields) > 0 {
		return errs.Fields[0].Field
	}
	return ""
}

func summarise(errs *Errors) string {
	var parts []string
	for _, e := range errs.Fields {
		parts = append(parts, e.Field+": "+e.Message)
	}
	return strings.Join(parts, "; ")
}
