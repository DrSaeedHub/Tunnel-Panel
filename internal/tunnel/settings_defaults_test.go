package tunnel

import (
	"context"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/validate"
)

// These tests cover the tunnel.* settings that ApplyDefaults and RenderName
// read. They are the same guard as settings_behaviour_test.go in this package:
// the coarse check in internal/api proves a key is named somewhere, and these
// prove the value is honoured.
//
// The class of defect they catch is specific to this group. Every one of these
// keys is ALSO read by TunnelFormDialog.tsx, which prefills the create form from
// the same settings. That makes the Go side easy to break invisibly: the form
// keeps showing the operator's configured default, so a manual click-through
// looks right, while any request that does not come from that form — the API,
// a script, a paired panel — silently gets a hardcoded value instead.
//
// Each assertion uses two distinct non-default values, because a consumer frozen
// at any single constant has to fail one of them.

// defaulted runs ApplyDefaults over a request that names nothing but its
// endpoints, which is the only case a default applies to.
func (h *harness) defaulted(t *testing.T) validate.TunnelInput {
	t.Helper()
	in := request().TunnelInput
	if err := h.service.ApplyDefaults(context.Background(), &in); err != nil {
		t.Fatalf("applying defaults failed: %v", err)
	}
	return in
}

func TestTheDefaultTunnelTypeFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	for _, want := range []int64{model.TunnelTypeGRETAP, model.TunnelTypeGRE} {
		h.setSetting(t, "tunnel.default_type", want)
		if got := h.defaulted(t).TunnelTypeID; got != want {
			t.Fatalf("a request naming no tunnel type got type %d, want the configured %d", got, want)
		}
	}
}

func TestTheDefaultPersistenceFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	for _, want := range []int64{model.PersistenceTypeRuntime, model.PersistenceTypeNetworkd} {
		h.setSetting(t, "tunnel.default_persistence", want)
		if got := h.defaulted(t).PersistenceTypeID; got != want {
			t.Fatalf("a request naming no persistence got %d, want the configured %d", got, want)
		}
	}
}

func TestTheDefaultMtuFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	for _, want := range []int64{1400, 9000} {
		h.setSetting(t, "tunnel.default_mtu", want)
		if got := h.defaulted(t).Mtu; got != want {
			t.Fatalf("a request naming no MTU got %d, want the configured %d", got, want)
		}
	}
}

func TestTheDefaultTtlFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	// 0 is meaningful here — it means inherit from the inner packet — but it is
	// also what ApplyDefaults treats as "unset", so it cannot be distinguished
	// at this layer and is not asserted.
	for _, want := range []int64{64, 128} {
		h.setSetting(t, "tunnel.default_ttl", want)
		if got := h.defaulted(t).Ttl; got != want {
			t.Fatalf("a request naming no TTL got %d, want the configured %d", got, want)
		}
	}
}

func TestTheDefaultTosFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	for _, want := range []string{"0x10", "inherit"} {
		h.setSetting(t, "tunnel.default_tos", want)
		if got := h.defaulted(t).Tos; got != want {
			t.Fatalf("a request naming no type of service got %q, want the configured %q", got, want)
		}
	}
}

// The default key is applied to both directions, and only when creating: on an
// update, no key is a deliberate instruction and putting the default back would
// silently undo an operator who cleared it.
func TestTheDefaultKeyFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	for _, want := range []int64{4242, 31337} {
		h.setSetting(t, "tunnel.default_key", want)

		in := h.defaulted(t)
		if in.IKey == nil || in.OKey == nil {
			t.Fatalf("a request naming no key got no key at all: ikey=%v okey=%v", in.IKey, in.OKey)
		}
		if *in.IKey != want || *in.OKey != want {
			t.Fatalf("keys = (%d, %d), want the configured %d in both directions",
				*in.IKey, *in.OKey, want)
		}
	}

	// Null is a real value for this setting: it means create tunnels with no
	// key. A reader that treated null as "use the shipped default" would put
	// 2749365187 on every tunnel — the very key the panel warns about sharing.
	h.setSetting(t, "tunnel.default_key", nil)
	if in := h.defaulted(t); in.IKey != nil || in.OKey != nil {
		t.Fatalf("with the default key cleared the tunnel still got keys (%v, %v)", in.IKey, in.OKey)
	}
}

// The template decides the generated interface name, so the name is where it is
// observable. It is rendered rather than pattern-matched: {number} depends on
// the allocation, so only the fixed text and the shape are asserted.
func TestTheNamingTemplateFollowsTheSetting(t *testing.T) {
	h := newHarness(t)

	for _, tc := range []struct {
		template string
		prefix   string
	}{
		{"tun-{side}-{number}", "tun-a-"},
		{"link{number}{side}", "link"},
	} {
		h.setSetting(t, "tunnel.naming_template", tc.template)

		name := h.defaulted(t).InterfaceName
		if !strings.HasPrefix(name, tc.prefix) {
			t.Fatalf("the template %q generated the name %q, want it to start with %q",
				tc.template, name, tc.prefix)
		}
		if err := validate.InterfaceName(name); err != nil {
			t.Fatalf("the template %q generated %q, which is not a usable interface name: %v",
				tc.template, name, err)
		}
	}
}

// The side labels are what {side} renders to. A and B are simply the two ends of
// one tunnel, and an operator who calls them something else has to see that
// everywhere the name is built.
func TestTheSideLabelsFollowTheSetting(t *testing.T) {
	h := newHarness(t)
	h.setSetting(t, "tunnel.naming_template", "gre-{side}-{number}")

	for _, tc := range []struct {
		labels map[string]any
		prefix string
	}{
		{map[string]any{"a": "left", "b": "right"}, "gre-left-"},
		{map[string]any{"a": "one", "b": "two"}, "gre-one-"},
	} {
		h.setSetting(t, "tunnel.side_labels", tc.labels)

		// The request is side A, so the "a" label is the one that renders.
		if name := h.defaulted(t).InterfaceName; !strings.HasPrefix(name, tc.prefix) {
			t.Fatalf("with labels %v the generated name is %q, want it to start with %q",
				tc.labels, name, tc.prefix)
		}
	}
}
