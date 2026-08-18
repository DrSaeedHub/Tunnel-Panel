package tunnel

import (
	"context"
	"testing"
)

// A monitoring override is stored and never applied: the prober reads it, the
// kernel never sees it. So it produces no diff against the interface, and the
// update path's "nothing to do" shortcut swallowed it — the request returned
// 200, the response carried the old value, and the probe rate did not move.
//
// Measured on a live host before this was fixed:
//
//	PATCH /tunnels/3 {"monitor_interval_seconds":0.25}  ->  200
//	stored monitor_interval_seconds                     ->  null
//	probes over 12 s                                    ->  12, unchanged
//
// A 200 that changes nothing is worse than a rejection, because there is
// nothing on screen to say so.
func TestAnOverrideThatTheKernelCannotSeeIsStillWritten(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())
	h.links.Reset()

	interval := 0.25
	req := request()
	req.TunnelInput = mergedInput(created.Tunnel)
	req.MonitorIntervalSeconds = &interval

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	if err != nil {
		t.Fatalf("setting a monitoring override failed: %v", err)
	}
	if result.Tunnel.MonitorIntervalSeconds == nil {
		t.Fatal("the update reported success and stored no override at all")
	}
	if *result.Tunnel.MonitorIntervalSeconds != interval {
		t.Fatalf("stored interval %v, want %v", *result.Tunnel.MonitorIntervalSeconds, interval)
	}

	// It is a database change and nothing else: an operator adjusting a probe
	// interval must not have their tunnel rebuilt underneath them.
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("changing a monitoring override touched the kernel: %v", calls)
	}
	if len(result.Plan.Steps) != 0 {
		t.Fatalf("changing a monitoring override planned %d kernel steps", len(result.Plan.Steps))
	}

	// And it survives a read, rather than living only in the response.
	stored, err := h.service.repo.ByID(ctx, created.Tunnel.TunnelID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.MonitorIntervalSeconds == nil || *stored.MonitorIntervalSeconds != interval {
		t.Fatalf("the override did not reach the database: %v", stored.MonitorIntervalSeconds)
	}
}

// Clearing it back to null is the instruction to inherit the global again, and
// it has to travel the same path.
func TestClearingAnOverrideReturnsTheTunnelToTheGlobal(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	interval := 0.25
	req := request()
	req.TunnelInput = mergedInput(created.Tunnel)
	req.MonitorIntervalSeconds = &interval
	if _, err := h.service.Update(ctx, created.Tunnel.TunnelID, req); err != nil {
		t.Fatalf("setting the override failed: %v", err)
	}

	stored, _ := h.service.repo.ByID(ctx, created.Tunnel.TunnelID)
	req = request()
	req.TunnelInput = mergedInput(stored)
	req.MonitorIntervalSeconds = nil

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	if err != nil {
		t.Fatalf("clearing the override failed: %v", err)
	}
	if result.Tunnel.MonitorIntervalSeconds != nil {
		t.Fatalf("the override survived being cleared: %v", *result.Tunnel.MonitorIntervalSeconds)
	}
}
