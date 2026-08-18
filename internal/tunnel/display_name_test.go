package tunnel

import (
	"context"
	"testing"
)

// The display name is the name an operator recognises a tunnel by, and it is
// the panel's alone: the kernel never sees it, so it produces no diff against
// the interface. That put it on exactly the path the monitoring overrides were
// once lost on — the update shortcut returned 200 and wrote nothing.
//
// Measured on a live host before this was fixed:
//
//	PATCH /tunnels/3 {"display_name":"test"}  ->  200
//	stored display_name                       ->  null
//	updated_date                              ->  unchanged
func TestADisplayNameThatTheKernelCannotSeeIsStillWritten(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())
	h.links.Reset()

	req := request()
	req.TunnelInput = mergedInput(created.Tunnel)
	req.DisplayName = "Frankfurt to Singapore"

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	if err != nil {
		t.Fatalf("setting a display name failed: %v", err)
	}
	if result.Tunnel.DisplayName == nil {
		t.Fatal("the update reported success and stored no display name at all")
	}
	if *result.Tunnel.DisplayName != "Frankfurt to Singapore" {
		t.Fatalf("stored display name %q, want %q", *result.Tunnel.DisplayName, "Frankfurt to Singapore")
	}

	// Renaming what the panel calls a tunnel must never rebuild it.
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("changing the display name touched the kernel: %v", calls)
	}
	if len(result.Plan.Steps) != 0 {
		t.Fatalf("changing the display name planned %d kernel steps", len(result.Plan.Steps))
	}

	// And it survives a read, rather than living only in the response.
	stored, err := h.service.repo.ByID(ctx, created.Tunnel.TunnelID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DisplayName == nil || *stored.DisplayName != "Frankfurt to Singapore" {
		t.Fatalf("the display name did not reach the database: %v", stored.DisplayName)
	}
}

// A display name given at creation has to be stored by the insert too, not
// only by a later update.
func TestADisplayNameGivenAtCreationIsStored(t *testing.T) {
	req := request()
	req.DisplayName = "Backup path"

	h := newHarness(t)
	created := h.mustCreate(t, req)

	if created.Tunnel.DisplayName == nil || *created.Tunnel.DisplayName != "Backup path" {
		t.Fatalf("display name after create = %v, want %q", created.Tunnel.DisplayName, "Backup path")
	}

	stored, err := h.service.repo.ByID(context.Background(), created.Tunnel.TunnelID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DisplayName == nil || *stored.DisplayName != "Backup path" {
		t.Fatalf("the display name did not reach the database: %v", stored.DisplayName)
	}
}

// An edit the kernel does see travels the other branch of Update, which
// rewrites the row wholesale. The display name has to be carried across it, or
// changing the MTU would silently erase the tunnel's name.
func TestADisplayNameSurvivesAnUnrelatedKernelChange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	req := request()
	req.DisplayName = "Primary link"
	created := h.mustCreate(t, req)

	change := request()
	change.TunnelInput = mergedInput(created.Tunnel)
	change.Mtu = created.Tunnel.Mtu - 24

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, change)
	if err != nil {
		t.Fatalf("changing the MTU failed: %v", err)
	}
	if result.Tunnel.DisplayName == nil || *result.Tunnel.DisplayName != "Primary link" {
		t.Fatalf("display name after an MTU change = %v, want it preserved as %q",
			result.Tunnel.DisplayName, "Primary link")
	}
}

// Clearing the name back to empty is a real instruction, and the field is
// nullable, so it has to come back as NULL rather than as the empty string.
func TestClearingADisplayNameRemovesIt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	req := request()
	req.DisplayName = "Temporary"
	created := h.mustCreate(t, req)

	clear := request()
	clear.TunnelInput = mergedInput(created.Tunnel)
	clear.DisplayName = ""

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, clear)
	if err != nil {
		t.Fatalf("clearing the display name failed: %v", err)
	}
	if result.Tunnel.DisplayName != nil {
		t.Fatalf("the display name survived being cleared: %q", *result.Tunnel.DisplayName)
	}
}
