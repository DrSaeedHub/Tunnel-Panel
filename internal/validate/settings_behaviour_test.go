package validate

import (
	"context"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
)

// These tests cover the routes.* defaults that RouteValidator.ApplyDefaults
// reads. The coarse check in internal/api proves each key is named somewhere;
// these prove the value is honoured.
//
// All three are also read by RouteFormDialog.tsx, which prefills the create
// form. That is what makes a Go-side regression here easy to miss: the form goes
// on showing the operator's configured default, so clicking through by hand
// looks correct, while a rule created through the API — or by a paired panel —
// silently gets a hardcoded one. A shop that always relays UDP configures that
// once and is entitled to have it apply everywhere, not just in the browser.

// routeValidatorWith builds a route validator over the standard fake host with
// the given settings, which the shared routeValidator helper leaves nil.
func routeValidatorWith(set fakeSettings) *RouteValidator {
	return NewRouteValidator(link.NewFakeWithHost(),
		fakeRouteRepo{tunnels: map[int64]bool{3: true}}, fakeSockets{}, set)
}

// defaultedRoute applies the defaults to a rule that names neither protocol nor
// NAT mode, which is the only case a default applies to.
func defaultedRoute(t *testing.T, v *RouteValidator, in RouteInput) RouteInput {
	t.Helper()
	if err := v.ApplyDefaults(context.Background(), &in); err != nil {
		t.Fatalf("applying defaults failed: %v", err)
	}
	return in
}

func TestTheDefaultRouteProtocolFollowsTheSetting(t *testing.T) {
	for _, want := range []int64{model.RouteProtocolUDP, model.RouteProtocolTCP} {
		v := routeValidatorWith(fakeSettings{"routes.default_protocol": want})

		in := validRoute()
		in.RouteProtocolID = 0 // the request names no protocol

		if got := defaultedRoute(t, v, in).RouteProtocolID; got != want {
			t.Fatalf("a rule naming no protocol got %d, want the configured %d", got, want)
		}
	}
}

func TestTheDefaultNatModeFollowsTheSetting(t *testing.T) {
	for _, want := range []int64{model.NatModeNone, model.NatModeMasquerade} {
		v := routeValidatorWith(fakeSettings{"routes.default_nat_mode": want})

		in := validRoute()
		in.NatModeID = 0 // the request names no NAT mode

		if got := defaultedRoute(t, v, in).NatModeID; got != want {
			t.Fatalf("a rule naming no NAT mode got %d, want the configured %d", got, want)
		}
	}
}

// MSS clamping is defaulted on only for a rule that sends traffic through a
// tunnel, because that is precisely the case where its absence produces
// connections that establish and then stall. The setting decides whether that
// happens at all.
func TestTheDefaultMssClampingFollowsTheSetting(t *testing.T) {
	tunnelID := int64(3)

	for _, want := range []bool{false, true} {
		v := routeValidatorWith(fakeSettings{"routes.default_clamp_mss": want})

		in := validRoute()
		in.TunnelID = &tunnelID
		in.IsClampMssToPmtu = false // the request expresses no preference

		if got := defaultedRoute(t, v, in).IsClampMssToPmtu; got != want {
			t.Fatalf("a tunnel rule expressing no preference got clamping = %v, want the "+
				"configured %v", got, want)
		}
	}

	// The setting is a default, not a policy: a rule that asks for clamping
	// keeps it whatever the setting says, or the per-rule choice would be
	// decorative.
	v := routeValidatorWith(fakeSettings{"routes.default_clamp_mss": false})
	in := validRoute()
	in.TunnelID = &tunnelID
	in.IsClampMssToPmtu = true
	if !defaultedRoute(t, v, in).IsClampMssToPmtu {
		t.Fatal("an explicit yes must survive a default of no")
	}
}
