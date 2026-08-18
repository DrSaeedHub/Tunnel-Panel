package api

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestEveryValidatedTunnelFieldHasAControl is the regression for two tunnel
// parameters an operator could never set.
//
// fwmark and tx_queue_length had a nullable column, a type, bounds, dedicated
// validation codes (INVALID_FWMARK, INVALID_QUEUE_LENGTH) and translated labels
// in both locales — and no input anywhere in the panel. The API accepted them;
// the interface could not produce them. The form carried them as data passing
// through, initialising them to null when blank and copying them off an
// existing tunnel when editing, so they round-tripped invisibly and nothing
// ever looked wrong.
//
// The list is taken from the validator rather than written out here, so a
// parameter added to the backend cannot be silently unreachable from the
// interface: it fails this the moment it is validated but not rendered.
func TestEveryValidatedTunnelFieldHasAControl(t *testing.T) {
	root := filepath.Join("..", "..")

	validator, err := os.ReadFile(filepath.Join(root, "internal", "validate", "validate.go"))
	if err != nil {
		t.Fatalf("reading the validator: %v", err)
	}
	// Every field the validator can attach an error to. That is exactly the set
	// an operator can be told off about, so it is exactly the set they must be
	// able to fill in.
	fieldPattern := regexp.MustCompile(`errs\.Addf?\(\s*"([a-z_]+)"`)
	fields := map[string]bool{}
	for _, match := range fieldPattern.FindAllStringSubmatch(string(validator), -1) {
		fields[match[1]] = true
	}
	if len(fields) < 10 {
		t.Fatalf("only %d validated fields were found; the pattern is not matching", len(fields))
	}

	form, err := os.ReadFile(filepath.Join(root, "web", "_app", "src", "components",
		"tunnels", "TunnelFormDialog.tsx"))
	if err != nil {
		t.Fatalf("reading the tunnel form: %v", err)
	}
	body := string(form)

	// Fields the form legitimately does not render as an input of its own.
	// Each one is here for a stated reason rather than because it was missing.
	exempt := map[string]string{
		// Chosen by the addressing mode and the pool selector together.
		"address_pool_id": "the addressing controls set this",
		// Derived from the naming template and the side, and settable through
		// the interface name override.
		"tunnel_number": "derived from the naming template",
	}

	// encap_limit and hop_limit were exempt here on the reasoning that no IPv6
	// tunnel type was offered. That was simply untrue: the capabilities endpoint
	// reports IP6GRE and IP6GRETAP supported — served through the ip command
	// because netlink coverage of them is incomplete — and the type selector
	// offers both. An operator could create an IPv6 tunnel and had no way to set
	// either field, while the backend validated both and plan.go mapped the hop
	// limit onto the link spec. An exemption whose stated reason is false is
	// worse than no exemption at all, because it makes the gap permanent and
	// looks deliberate. Both now have controls, shown when an IPv6 type is
	// selected, so neither is exempt.

	var missing []string
	for field := range fields {
		if _, ok := exempt[field]; ok {
			continue
		}
		// A control is something that writes the field from what the operator
		// typed. Usually that is `set('field', …)`. The GRE key is the exception:
		// one input writes both directions at once through setForm, because the
		// two are modelled separately so an adopted script tunnel can keep
		// asymmetric keys, while an operator setting them differently by hand is
		// a mismatch rather than a feature.
		//
		// Merely reading a field, or copying it off the tunnel being edited, is
		// not a control — that is exactly what fwmark and tx_queue_length did
		// while being unreachable.
		written := strings.Contains(body, `set('`+field+`'`) ||
			regexp.MustCompile(`\b`+regexp.QuoteMeta(field)+`:\s*value\b`).MatchString(body)
		if !written {
			missing = append(missing, field)
		}
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("%d tunnel field(s) are validated by the backend but have no control in the "+
			"create/edit dialog, so an operator can never set them:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
