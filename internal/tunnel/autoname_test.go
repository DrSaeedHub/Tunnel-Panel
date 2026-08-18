package tunnel

import (
	"context"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/validate"
)

// A name the panel renders for the operator has to be a name the operator can
// actually use. The defect these cover is that the number was chosen from the
// free subnets alone: a tunnel addressed by hand holds its name without holding
// the subnet its number maps to, so the allocator handed back a number whose
// rendered name was already taken and the create failed with "a tunnel named
// gre-a-3 already exists" on a form where the operator had typed no name at all.

// handAddressed creates a tunnel with explicit addresses outside the pool's
// allocation for its number, which is what leaves a name taken and a subnet
// free.
func handAddressed(t *testing.T, h *harness, name, remote, address, peer string) {
	t.Helper()
	req := request()
	req.InterfaceName = name
	req.RemoteEndpoint = remote
	req.Addresses = []validate.AddressInput{{
		Address: address, PrefixLength: 30, PeerAddress: peer, IsPrimary: true,
	}}
	h.mustCreate(t, req)
}

func TestAnAutomaticNameSkipsANumberWhoseNameIsTaken(t *testing.T) {
	h := newHarness(t)

	// gre-a-1 and gre-a-2 hold their names, but their addresses come from far
	// up the pool, so subnets 1 and 2 still read as free.
	handAddressed(t, h, "gre-a-1", "198.51.100.21", "172.17.10.1", "172.17.10.2")
	handAddressed(t, h, "gre-a-2", "198.51.100.22", "172.17.11.1", "172.17.11.2")

	in := request().TunnelInput
	in.RemoteEndpoint = "198.51.100.30"
	if err := h.service.ApplyDefaults(context.Background(), &in); err != nil {
		t.Fatalf("applying defaults failed: %v", err)
	}
	if in.InterfaceName == "gre-a-1" || in.InterfaceName == "gre-a-2" {
		t.Fatalf("the panel rendered %q, a name that is already taken", in.InterfaceName)
	}
	if in.TunnelNumber == nil {
		t.Fatal("the panel rendered a name but chose no tunnel number")
	}

	// The number, the name and the subnet must still describe each other: a
	// name of gre-a-N whose address is not in subnet N is the mismatch that
	// makes the two ends of a tunnel impossible to reason about.
	if _, err := h.service.Create(context.Background(), Request{TunnelInput: in}); err != nil {
		t.Fatalf("creating the tunnel the panel named itself failed: %v", err)
	}
}

func TestAnAutomaticNameSkipsANameTheKernelAlreadyHas(t *testing.T) {
	h := newHarness(t)

	// An interface the panel has no record of still owns its name: rendering
	// it would push the operator into an adoption they never asked for.
	h.links.AddLink(link.Link{Name: "gre-a-1", Kind: "gre", MTU: 1476})

	in := request().TunnelInput
	if err := h.service.ApplyDefaults(context.Background(), &in); err != nil {
		t.Fatalf("applying defaults failed: %v", err)
	}
	if in.InterfaceName == "gre-a-1" {
		t.Fatalf("the panel rendered %q, which the kernel already has", in.InterfaceName)
	}
}

func TestHandAddressingStillGetsDistinctAutomaticNames(t *testing.T) {
	h := newHarness(t)

	// Addressing by hand skips the allocator, so there is no number to render
	// from and every tunnel used to render the same name.
	seen := map[string]bool{}
	for _, addresses := range [][3]string{
		{"198.51.100.21", "172.17.20.1", "172.17.20.2"},
		{"198.51.100.22", "172.17.21.1", "172.17.21.2"},
		{"198.51.100.23", "172.17.22.1", "172.17.22.2"},
	} {
		req := request()
		req.RemoteEndpoint = addresses[0]
		req.Addresses = []validate.AddressInput{{
			Address: addresses[1], PrefixLength: 30, PeerAddress: addresses[2], IsPrimary: true,
		}}
		result := h.mustCreate(t, req)
		if seen[result.Tunnel.InterfaceName] {
			t.Fatalf("the panel rendered %q twice", result.Tunnel.InterfaceName)
		}
		seen[result.Tunnel.InterfaceName] = true
	}
}

func TestANameTheOperatorTypedIsNeverRenamedAround(t *testing.T) {
	h := newHarness(t)
	handAddressed(t, h, "gre-a-1", "198.51.100.21", "172.17.10.1", "172.17.10.2")

	// Only a blank name is the panel's to choose. A name the operator typed is
	// an instruction, and a collision with it is an error to report, not
	// something to quietly rename.
	in := request().TunnelInput
	in.InterfaceName = "gre-a-1"
	if err := h.service.ApplyDefaults(context.Background(), &in); err != nil {
		t.Fatalf("applying defaults failed: %v", err)
	}
	if in.InterfaceName != "gre-a-1" {
		t.Fatalf("the panel renamed the operator's %q to %q", "gre-a-1", in.InterfaceName)
	}
	if _, err := h.service.Create(context.Background(), Request{TunnelInput: in}); err == nil {
		t.Fatal("creating a tunnel with a name that is already taken succeeded")
	}
}
