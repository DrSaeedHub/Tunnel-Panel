package reconcile

import (
	"context"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/validate"
)

// TestKernelStubDevicesAreNotOfferedForAdoption is the regression for a
// dashboard that could never be cleared.
//
// gre0 and gretap0 appear the moment the ip_gre and ip_gretap modules load, on
// every host that has them. They are not tunnels anyone created — they are
// permanently down, have no endpoints, and belong to the kernel. The report
// listed them as unmanaged tunnels and invited the operator to adopt them, so
// "Needs attention" was non-empty on a stock install for ever, with two of its
// three rows describing something no action could resolve.
//
// The panel contradicted itself doing it. validate refuses to create a tunnel
// with any of these names, and safety treats the same list as protected
// devices, so adopting one produces a tunnel whose name the panel's own
// validator rejects.
func TestKernelStubDevicesAreNotOfferedForAdoption(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Every reserved name the kernel might have brought up, as a tunnel-kind
	// link so nothing but the reserved check can exclude it.
	for i, name := range validate.ReservedInterfaceNames {
		if name == "lo" {
			continue // not a tunnel kind, and excluded before this check
		}
		h.links.AddLink(link.Link{
			Name: name, Index: 200 + i, MTU: 1476, Kind: link.KindGRE,
			OperState: "DOWN",
			Tunnel:    &link.TunnelAttrs{Local: "0.0.0.0", Remote: "0.0.0.0"},
		})
	}

	// One genuine unmanaged tunnel, of exactly the kind an operator does want
	// offered: the legacy script's, which §12 says to adopt.
	h.legacyTunnel(t, "gre-ir-15", 15, "172.17.15.1")

	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatalf("the reconcile report failed: %v", err)
	}

	var offered []string
	for _, item := range report.Items {
		if validate.IsReservedInterfaceName(item.InterfaceName) {
			t.Errorf("%s is one of the kernel's own devices and is in the report as %q, "+
				"offering actions %v", item.InterfaceName, item.Status, item.Actions)
		}
		for _, action := range item.Actions {
			if action == "adopt" {
				offered = append(offered, item.InterfaceName)
			}
		}
	}

	// The genuine one is still there, and still adoptable: excluding the stubs
	// must not have excluded the thing the operator actually has to act on.
	if len(offered) != 1 || offered[0] != "gre-ir-15" {
		t.Errorf("adoption is offered for %v, want exactly [gre-ir-15]", offered)
	}
}

// TestTheReservedListIsSharedRatherThanCopied pins that this reads the same
// constant validate and safety do. A fourth copy of the names would drift, and
// the drift would not show up until a kernel grew a new stub device.
func TestTheReservedListIsSharedRatherThanCopied(t *testing.T) {
	for _, name := range []string{"gre0", "gretap0", "erspan0", "ip6gre0", "tunl0", "sit0"} {
		if !validate.IsReservedInterfaceName(name) {
			t.Errorf("%s is a kernel stub device but is not in validate.ReservedInterfaceNames, "+
				"so the reconcile report would offer it for adoption", name)
		}
	}
}
