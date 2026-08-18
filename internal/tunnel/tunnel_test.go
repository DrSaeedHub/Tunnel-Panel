package tunnel

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/validate"
)

func i64(v int64) *int64 { return &v }

// ---------------------------------------------------------------- create

func TestCreateAppliesVerifiesAndPersists(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	result := h.mustCreate(t, request())

	// The defaults of §5.3 filled everything in: the name from the template, the
	// subnet from the first enabled pool, the key, the MTU and the TTL.
	rec := result.Tunnel
	if rec.InterfaceName != "gre-a-1" {
		t.Fatalf("interface name = %q, want gre-a-1 from the naming template", rec.InterfaceName)
	}
	if rec.Mtu != 1472 || rec.Ttl != 255 {
		t.Fatalf("defaults were not applied: mtu %d, ttl %d", rec.Mtu, rec.Ttl)
	}
	if rec.IKey == nil || *rec.IKey != 2749365187 {
		t.Fatalf("the default key was not applied: %v", rec.IKey)
	}
	if len(rec.Addresses) != 1 || rec.Addresses[0].Address != "172.17.1.1" {
		t.Fatalf("the address was not allocated: %+v", rec.Addresses)
	}
	if peer := rec.Addresses[0].PeerAddress; peer == nil || *peer != "172.17.1.2" {
		t.Fatalf("the peer address was not recorded: %v", peer)
	}
	if rec.ApplyStatusID != model.ApplyStatusApplied {
		t.Fatalf("apply status = %d, want Applied", rec.ApplyStatusID)
	}

	// The kernel really has it, with the right attributes.
	observed, err := h.links.Get(ctx, "gre-a-1")
	if err != nil {
		t.Fatalf("the interface was not created: %v", err)
	}
	if observed.Kind != link.KindGRE || observed.MTU != 1472 {
		t.Fatalf("the interface is wrong: %+v", observed)
	}
	if !observed.IsUp || !observed.IsLowerUp {
		t.Fatal("the interface is not up")
	}
	if observed.Tunnel == nil || observed.Tunnel.Local != "203.0.113.10" ||
		observed.Tunnel.Remote != "198.51.100.20" {
		t.Fatalf("the endpoints are wrong: %+v", observed.Tunnel)
	}

	// The unit file exists, is panel-owned, enabled and active.
	unit := persist.UnitName("gre-a-1")
	if !persist.Exists(h.unitPath("gre-a-1")) {
		t.Fatal("the unit file was not written")
	}
	if owned, _ := persist.IsPanelOwned(h.unitPath("gre-a-1")); !owned {
		t.Fatal("the unit file does not identify itself as panel-owned")
	}
	if !h.systemd.IsEnabled(unit) || !h.systemd.IsActive(unit) {
		t.Fatal("the unit was not enabled and started")
	}

	if !result.Verify.Ok {
		t.Fatalf("verification failed: %+v", result.Verify.Failures)
	}
}

// A healthy GRE tunnel reports operational state UNKNOWN. Treating that as a
// failure is the single most common way to get this wrong, so the verification
// must pass with it and say so.
func TestOperationalStateUnknownIsNotAFailure(t *testing.T) {
	h := newHarness(t)
	result := h.mustCreate(t, request())

	if result.Verify.OperState != "UNKNOWN" {
		t.Fatalf("operational state = %q; the fake models the real kernel behaviour and should report UNKNOWN",
			result.Verify.OperState)
	}
	if !result.Verify.Ok {
		t.Fatalf("a tunnel reporting UNKNOWN must verify successfully: %+v", result.Verify.Failures)
	}

	var flags VerifyCheck
	for _, check := range result.Verify.Checks {
		if check.Name == CheckFlags {
			flags = check
		}
	}
	if !flags.Ok {
		t.Fatalf("the flag check failed: %+v", flags)
	}
	if !strings.Contains(flags.Detail, "normal for a point-to-point tunnel") {
		t.Fatalf("the flag check should explain the UNKNOWN state: %q", flags.Detail)
	}
}

func TestCreateIsIdempotentByKey(t *testing.T) {
	h := newHarness(t)
	req := request()
	req.IdempotencyKey = "abc-123"

	first := h.mustCreate(t, req)
	second := h.mustCreate(t, req)

	if first.Tunnel.TunnelID != second.Tunnel.TunnelID {
		t.Fatalf("a repeated submission created a second tunnel: %d and %d",
			first.Tunnel.TunnelID, second.Tunnel.TunnelID)
	}
	records, err := h.repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("the database holds %d tunnels, want 1", len(records))
	}
}

func TestSecondTunnelTakesTheNextSubnet(t *testing.T) {
	h := newHarness(t)
	h.mustCreate(t, request())

	second := request()
	second.RemoteEndpoint = "198.51.100.30"
	result := h.mustCreate(t, second)

	if result.Tunnel.InterfaceName != "gre-a-2" {
		t.Fatalf("the second tunnel is named %q", result.Tunnel.InterfaceName)
	}
	if result.Tunnel.Addresses[0].Address != "172.17.2.1" {
		t.Fatalf("the second tunnel took %s", result.Tunnel.Addresses[0].Address)
	}
}

func TestCreateRejectsAnUnparseableEndpointWithoutTouchingTheKernel(t *testing.T) {
	h := newHarness(t)
	h.links.Reset()

	req := request()
	req.LocalEndpoint = "not-an-ip"

	_, err := h.service.Create(context.Background(), req)
	if err == nil {
		t.Fatal("a tunnel with an unparseable local endpoint was created")
	}
	errs, ok := validate.AsErrors(err)
	if !ok || !errs.Has("local_endpoint") {
		t.Fatalf("error = %v, want a field-level failure on local_endpoint", err)
	}
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("the kernel was changed: %v", calls)
	}
	if reads := h.links.ReadCalls(); reads != 0 {
		t.Fatalf("kernel state was read %d times before the input was rejected", reads)
	}
	if entries, _ := os.ReadDir(h.dir + "/systemd"); len(entries) != 0 {
		t.Fatalf("a unit file was written for a rejected request: %v", entries)
	}
}

// ---------------------------------------------------------------- rollback

// The central promise: a failed create is indistinguishable from never having
// run. No interface, no unit file, no enabled unit.
func TestFailedApplyRollsBackCompletely(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.systemd.FailUnitStart = persist.UnitName("gre-a-1")

	_, err := h.service.Create(ctx, request())
	if err == nil {
		t.Fatal("a create whose unit failed to start was reported as a success")
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("error = %v (%T), want an ApplyError", err, err)
	}
	if !applyErr.RolledBack {
		t.Fatal("the failure must report that it was rolled back")
	}

	if _, err := h.links.Get(ctx, "gre-a-1"); !errors.Is(err, link.ErrNotFound) {
		t.Fatal("the interface survived the rollback")
	}
	if persist.Exists(h.unitPath("gre-a-1")) {
		t.Fatal("the unit file survived the rollback")
	}
	if h.systemd.IsEnabled(persist.UnitName("gre-a-1")) {
		t.Fatal("the unit is still enabled after the rollback, which is exactly the legacy bug")
	}

	// The row is kept and marked failed, so an operator can see what happened.
	records, err := h.repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("the database holds %d tunnels, want the failed one kept", len(records))
	}
	if records[0].ApplyStatusID != model.ApplyStatusFailed {
		t.Fatalf("apply status = %d, want Failed", records[0].ApplyStatusID)
	}
	if records[0].LastApplyError == nil || *records[0].LastApplyError == "" {
		t.Fatal("the failure reason was not recorded")
	}
}

// A unit that starts but produces the wrong kernel state must be caught by
// verification, not reported as success. This is the anti-zombie requirement:
// the legacy script printed "installed and active" for a unit that had never
// worked, and this is the test that says that cannot happen here.
func TestVerificationCatchesAUnitThatDidNotDoWhatItSaid(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// The unit starts, systemd reports it active, but the step that brings the
	// interface up quietly does nothing. Every return code says success.
	h.systemd.SkipCommands = []string{"link set dev gre-a-1 up"}

	_, err := h.service.Create(ctx, request())
	if err == nil {
		t.Fatal("a tunnel that never came up was reported as created")
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("error = %v (%T), want an ApplyError", err, err)
	}
	if !strings.Contains(applyErr.Cause, "UP") {
		t.Fatalf("the failure should name the missing flags: %q", applyErr.Cause)
	}
	if _, err := h.links.Get(ctx, "gre-a-1"); !errors.Is(err, link.ErrNotFound) {
		t.Fatal("the rollback left the interface behind")
	}
	if persist.Exists(h.unitPath("gre-a-1")) {
		t.Fatal("the rollback left the unit file behind")
	}
}

// ---------------------------------------------------------------- update

func TestUpdateAppliesAnMtuChangeInPlace(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	req := request()
	req.TunnelInput = mergedInput(created.Tunnel)
	req.Mtu = 1400

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	if err != nil {
		t.Fatalf("updating the MTU failed: %v", err)
	}
	if result.Plan.RequiresRecreate {
		t.Fatal("an MTU change must be applied in place, not by rebuilding the interface")
	}

	observed, _ := h.links.Get(ctx, "gre-a-1")
	if observed.MTU != 1400 {
		t.Fatalf("the kernel MTU is %d, want 1400", observed.MTU)
	}
	// The unit file has to agree, or a reboot would undo the change.
	body, err := persist.Read(h.unitPath("gre-a-1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "mtu 1400") {
		t.Fatalf("the unit file still carries the old MTU:\n%s", body)
	}
}

func TestUpdateThatChangesAnEndpointNeedsConfirmation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	req := request()
	req.TunnelInput = mergedInput(created.Tunnel)
	req.RemoteEndpoint = "198.51.100.99"

	_, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	var recreate *RecreateRequiredError
	if !errors.As(err, &recreate) {
		t.Fatalf("error = %v (%T), want a RecreateRequiredError", err, err)
	}
	if len(recreate.Reasons) == 0 || !strings.Contains(recreate.Reasons[0], "remote_endpoint") {
		t.Fatalf("the reasons must name the field: %+v", recreate.Reasons)
	}

	// Confirmed, it goes through and the kernel really has the new endpoint.
	req.ConfirmRecreate = true
	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	if err != nil {
		t.Fatalf("the confirmed update failed: %v", err)
	}
	if !result.Plan.RequiresRecreate {
		t.Fatal("the plan must say it rebuilt the interface")
	}
	observed, _ := h.links.Get(ctx, "gre-a-1")
	if observed.Tunnel.Remote != "198.51.100.99" {
		t.Fatalf("the remote endpoint is %s", observed.Tunnel.Remote)
	}
}

func TestUpdateWithNoChangesDoesNothing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())
	h.links.Reset()

	req := request()
	req.TunnelInput = mergedInput(created.Tunnel)

	result, err := h.service.Update(ctx, created.Tunnel.TunnelID, req)
	if err != nil {
		t.Fatalf("a no-op update failed: %v", err)
	}
	if len(result.Plan.Steps) != 0 {
		t.Fatalf("a no-op update planned %d steps", len(result.Plan.Steps))
	}
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("a no-op update changed the kernel: %v", calls)
	}
}

// ---------------------------------------------------------------- delete

func TestDeleteRemovesEverythingAndReportsWhatItFound(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	report, err := h.service.Delete(ctx, created.Tunnel.TunnelID, Request{})
	if err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if !report.InterfaceFound {
		t.Fatal("delete must report that the interface was there")
	}
	if len(report.FilesRemoved) != 1 || !strings.HasSuffix(report.FilesRemoved[0], "gre-a-1.service") {
		t.Fatalf("files removed = %v", report.FilesRemoved)
	}

	if _, err := h.links.Get(ctx, "gre-a-1"); !errors.Is(err, link.ErrNotFound) {
		t.Fatal("the interface survived the delete")
	}
	if persist.Exists(h.unitPath("gre-a-1")) {
		t.Fatal("the unit file survived the delete")
	}
	if h.systemd.IsEnabled(persist.UnitName("gre-a-1")) {
		t.Fatal("the unit is still enabled")
	}
	if _, err := h.repo.ByID(ctx, created.Tunnel.TunnelID); !errors.Is(err, ErrNotFound) {
		t.Fatal("the row was not soft-deleted")
	}
}

func TestDeleteIsIdempotentWhenTheInterfaceIsAlreadyGone(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	// Something outside the panel removed the interface and the unit file.
	if err := h.links.Delete(ctx, "gre-a-1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(h.unitPath("gre-a-1")); err != nil {
		t.Fatal(err)
	}

	report, err := h.service.Delete(ctx, created.Tunnel.TunnelID, Request{})
	if err != nil {
		t.Fatalf("deleting an already-gone tunnel failed: %v", err)
	}
	if report.InterfaceFound {
		t.Fatal("delete must report that the interface was not there")
	}
	if len(report.FilesAbsent) != 1 {
		t.Fatalf("delete must report which files were absent: %+v", report)
	}
}

// ---------------------------------------------------------------- up, down

func TestDownLeavesTheInterfaceInPlaceAndDisablesTheUnit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	result, err := h.service.Down(ctx, created.Tunnel.TunnelID, Request{})
	if err != nil {
		t.Fatalf("taking the tunnel down failed: %v", err)
	}
	if !result.Verify.Ok {
		t.Fatalf("verification of the down state failed: %+v", result.Verify.Failures)
	}

	observed, err := h.links.Get(ctx, "gre-a-1")
	if err != nil {
		t.Fatal("down must not delete the interface")
	}
	if observed.IsUp {
		t.Fatal("the interface is still up")
	}
	if h.systemd.IsEnabled(persist.UnitName("gre-a-1")) {
		t.Fatal("the unit must be disabled so a reboot does not quietly bring the tunnel back")
	}

	stored, _ := h.repo.ByID(ctx, created.Tunnel.TunnelID)
	if stored.IsEnabled {
		t.Fatal("the desired state was not recorded as disabled")
	}
}

func TestUpBringsADownedTunnelBack(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	if _, err := h.service.Down(ctx, created.Tunnel.TunnelID, Request{}); err != nil {
		t.Fatalf("down failed: %v", err)
	}
	if _, err := h.service.Up(ctx, created.Tunnel.TunnelID, Request{}); err != nil {
		t.Fatalf("up failed: %v", err)
	}

	observed, _ := h.links.Get(ctx, "gre-a-1")
	if !observed.IsUp || !observed.IsLowerUp {
		t.Fatal("the interface did not come back up")
	}
	if !h.systemd.IsEnabled(persist.UnitName("gre-a-1")) {
		t.Fatal("the unit was not re-enabled")
	}
}

// Reapply is the remedy for drift: it rebuilds the tunnel from the stored
// desired state whatever the kernel currently holds.
func TestReapplyRepairsDrift(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	// Someone changed the MTU outside the panel.
	if err := h.links.SetMTU(ctx, "gre-a-1", 1300); err != nil {
		t.Fatal(err)
	}
	observed, _ := h.links.Get(ctx, "gre-a-1")
	if observed.MTU != 1300 {
		t.Fatal("the drift was not applied to the fake")
	}

	if _, err := h.service.Reapply(ctx, created.Tunnel.TunnelID, Request{}); err != nil {
		t.Fatalf("reapply failed: %v", err)
	}
	observed, _ = h.links.Get(ctx, "gre-a-1")
	if observed.MTU != 1472 {
		t.Fatalf("reapply left the MTU at %d", observed.MTU)
	}
}

// ---------------------------------------------------------------- preview

func TestPreviewChangesNothingAndReturnsTheUnitBody(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.links.Reset()

	preview, err := h.service.PreviewCreate(ctx, request())
	if err != nil {
		t.Fatalf("preview failed: %v", err)
	}

	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("preview changed the kernel: %v", calls)
	}
	if len(h.runner.Calls()) != 0 {
		t.Fatalf("preview ran commands: %v", h.runner.CommandLines())
	}
	if entries, _ := os.ReadDir(h.dir + "/systemd"); len(entries) != 0 {
		t.Fatal("preview wrote a file")
	}
	if records, _ := h.repo.List(ctx); len(records) != 0 {
		t.Fatal("preview stored a tunnel")
	}

	if len(preview.Plan.Steps) == 0 {
		t.Fatal("the preview returned no steps")
	}
	if len(preview.Plan.Files) != 1 || preview.Plan.Files[0].Kind != FileSystemdUnit {
		t.Fatalf("the preview must return the unit body: %+v", preview.Plan.Files)
	}
	if !strings.Contains(preview.Plan.Files[0].Content, "ip link add name gre-a-1 type gre") {
		t.Fatalf("the unit body is wrong:\n%s", preview.Plan.Files[0].Content)
	}
	if preview.Mtu.Recommended != 1472 {
		t.Fatalf("the MTU advisory is %+v", preview.Mtu)
	}
	if len(preview.Plan.Verification) == 0 {
		t.Fatal("the preview must state what will be verified afterwards")
	}
}

func TestPreviewIsDeterministic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	first, err := h.service.PreviewCreate(ctx, request())
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.service.PreviewCreate(ctx, request())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Plan.Steps) != len(second.Plan.Steps) {
		t.Fatal("planning is not deterministic")
	}
	for i := range first.Plan.Steps {
		if first.Plan.Steps[i].Description != second.Plan.Steps[i].Description {
			t.Fatalf("step %d differs between two previews of the same request", i)
		}
	}
}

// ---------------------------------------------------------------- planning

func TestPlanGenerationForEachOperation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	create, err := h.service.PreviewCreate(ctx, request())
	if err == nil {
		kinds := stepKinds(create.Plan)
		want := []string{StepFileWrite, StepDaemonReload, StepUnitEnable, StepUnitStart}
		for _, kind := range want {
			if !contains(kinds, kind) {
				t.Fatalf("the create plan is missing %s: %v", kind, kinds)
			}
		}
	}

	// Delete: stop, disable, remove the file, reload, delete the interface.
	deletePlan := h.service.planner.PlanDelete(created.Tunnel, false, false)
	for _, kind := range []string{StepUnitStop, StepUnitDisable, StepFileRemove, StepDaemonReload, StepLinkDelete} {
		if !contains(stepKinds(deletePlan), kind) {
			t.Fatalf("the delete plan is missing %s: %v", kind, stepKinds(deletePlan))
		}
	}
	for _, step := range deletePlan.Steps {
		if !step.Tolerate {
			t.Fatalf("every delete step must be tolerant so delete is idempotent: %+v", step)
		}
	}

	// An in-place update touches the interface and rewrites the unit, and never
	// restarts the unit, which would bounce the tunnel.
	desired := created.Tunnel
	desired.Mtu = 1400
	diffs := DiffTunnel(created.Tunnel, mergedInput(desired))
	update := h.service.planner.PlanUpdate(created.Tunnel, desired, KeepaliveFor{}, diffs, false)
	if update.RequiresRecreate {
		t.Fatal("an MTU change must not require a rebuild")
	}
	if contains(stepKinds(update), StepUnitStart) || contains(stepKinds(update), StepUnitRestart) {
		t.Fatalf("an in-place update must not restart the unit: %v", stepKinds(update))
	}
	if !contains(stepKinds(update), StepLinkSetMtu) || !contains(stepKinds(update), StepFileWrite) {
		t.Fatalf("the update plan is missing steps: %v", stepKinds(update))
	}
}

func TestWhichChangesForceARebuild(t *testing.T) {
	h := newHarness(t)
	created := h.mustCreate(t, request())
	base := mergedInput(created.Tunnel)

	inPlace := map[string]func(*validate.TunnelInput){
		"mtu":             func(in *validate.TunnelInput) { in.Mtu = 1400 },
		"tx_queue_length": func(in *validate.TunnelInput) { in.TxQueueLength = i64(500) },
		"addresses": func(in *validate.TunnelInput) {
			in.Addresses = []validate.AddressInput{{Address: "172.17.9.1", PrefixLength: 30}}
		},
		"is_enabled": func(in *validate.TunnelInput) { in.IsEnabled = false },
	}
	for field, mutate := range inPlace {
		desired := base
		mutate(&desired)
		if recreate, reasons := RequiresRecreate(DiffTunnel(created.Tunnel, desired)); recreate {
			t.Fatalf("changing %s must be applied in place, got %v", field, reasons)
		}
	}

	rebuild := map[string]func(*validate.TunnelInput){
		"local_endpoint":   func(in *validate.TunnelInput) { in.LocalEndpoint = "203.0.113.11" },
		"remote_endpoint":  func(in *validate.TunnelInput) { in.RemoteEndpoint = "198.51.100.30" },
		"ikey":             func(in *validate.TunnelInput) { in.IKey = i64(42) },
		"okey":             func(in *validate.TunnelInput) { in.OKey = i64(42) },
		"tunnel_type_id":   func(in *validate.TunnelInput) { in.TunnelTypeID = model.TunnelTypeGRETAP },
		"ttl":              func(in *validate.TunnelInput) { in.Ttl = 64 },
		"interface_name":   func(in *validate.TunnelInput) { in.InterfaceName = "gre-a-9" },
		"checksum":         func(in *validate.TunnelInput) { in.HasOutputChecksum = true },
		"sequence":         func(in *validate.TunnelInput) { in.HasOutputSequence = true },
		"path_mtu":         func(in *validate.TunnelInput) { in.IsPathMtuDiscovery = true },
		"bind_device":      func(in *validate.TunnelInput) { in.BindDevice = "eth0" },
		"persistence_type": func(in *validate.TunnelInput) { in.PersistenceTypeID = model.PersistenceTypeRuntime },
	}
	for field, mutate := range rebuild {
		desired := base
		mutate(&desired)
		if recreate, _ := RequiresRecreate(DiffTunnel(created.Tunnel, desired)); !recreate {
			t.Fatalf("changing %s cannot be done on a running tunnel and must force a rebuild", field)
		}
	}
}

// ---------------------------------------------------------------- persistence

func TestRuntimePersistenceWritesNoFiles(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	req := request()
	req.PersistenceTypeID = model.PersistenceTypeRuntime
	result := h.mustCreate(t, req)

	if entries, _ := os.ReadDir(h.dir + "/systemd"); len(entries) != 0 {
		t.Fatalf("a runtime-only tunnel wrote unit files: %v", entries)
	}
	observed, err := h.links.Get(ctx, result.Tunnel.InterfaceName)
	if err != nil {
		t.Fatalf("the interface was not created through netlink: %v", err)
	}
	if !observed.IsUp {
		t.Fatal("the interface is not up")
	}
	// The operator has to be told it will not survive a reboot.
	found := false
	for _, w := range result.Warnings {
		if w.Code == validate.WarnRuntimeOnly {
			found = true
		}
	}
	if !found {
		t.Fatalf("a runtime-only tunnel must warn that it does not survive a reboot: %+v", result.Warnings)
	}
}

func TestNetworkdPersistenceWritesBothFiles(t *testing.T) {
	h := newHarness(t)

	req := request()
	req.PersistenceTypeID = model.PersistenceTypeNetworkd
	result := h.mustCreate(t, req)

	name := result.Tunnel.InterfaceName
	for _, path := range []string{h.store.NetdevPath(name), h.store.NetworkPath(name)} {
		if !persist.Exists(path) {
			t.Fatalf("%s was not written", path)
		}
		owned, _ := persist.IsPanelOwned(path)
		if !owned {
			t.Fatalf("%s does not identify itself as panel-owned", path)
		}
	}
}

func TestKeepaliveUnitIsWrittenOnlyInSystemdUnitMode(t *testing.T) {
	h := newHarness(t)
	created := h.mustCreate(t, request())
	name := created.Tunnel.InterfaceName

	if persist.Exists(h.store.KeepaliveUnitPath(name)) {
		t.Fatal("the default keepalive mode is monitor_only and must write no unit")
	}

	h.setSetting(t, "keepalive.mode", "systemd_unit")
	second := request()
	second.RemoteEndpoint = "198.51.100.30"
	created = h.mustCreate(t, second)

	path := h.store.KeepaliveUnitPath(created.Tunnel.InterfaceName)
	if !persist.Exists(path) {
		t.Fatal("no keepalive unit was written in systemd_unit mode")
	}
	body, _ := persist.Read(path)
	if !strings.Contains(body, "Restart=always") {
		t.Fatalf("the keepalive unit must restart, unlike the tunnel unit:\n%s", body)
	}
}

// ---------------------------------------------------------------- invariants

// §17.1 in the service layer: the guard runs immediately before execution, so
// even a plan that somehow named a protected interface is refused.
func TestServiceRefusesToTouchAProtectedInterface(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	rec := Record{}
	rec.InterfaceName = "eth0"
	rec.IsManaged = true
	rec.PersistenceTypeID = model.PersistenceTypeRuntime

	plan := h.service.planner.PlanDown(rec)
	err := h.service.guardPlan(ctx, plan, rec, false)
	v, ok := safety.AsViolation(err)
	if !ok {
		t.Fatalf("error = %v, want a safety violation", err)
	}
	if v.Code != safety.CodeProtectedDevice {
		t.Fatalf("violation = %q", v.Code)
	}
}

// §17.4: refuse to reconfigure the tunnel the request itself is arriving over.
func TestServiceRefusesToCutTheRequestingClientsConnection(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	req := Request{ClientIP: "172.17.1.2"}
	_, err := h.service.Delete(ctx, created.Tunnel.TunnelID, req)
	v, ok := safety.AsViolation(err)
	if !ok {
		t.Fatalf("error = %v, want a safety violation", err)
	}
	if v.Code != safety.CodeWouldCutOwnAccess {
		t.Fatalf("violation = %q", v.Code)
	}
	if _, err := h.links.Get(ctx, "gre-a-1"); err != nil {
		t.Fatal("the tunnel was deleted despite the refusal")
	}

	req.IUnderstandIMayLoseAccess = true
	if _, err := h.service.Delete(ctx, created.Tunnel.TunnelID, req); err != nil {
		t.Fatalf("the acknowledged delete failed: %v", err)
	}
}

// §17.3: a unit file the panel did not write is never overwritten or removed.
func TestServiceRefusesToOverwriteAForeignUnitFile(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	path := h.unitPath("gre-a-1")
	if err := os.WriteFile(path, []byte("[Unit]\nDescription=Written by hand\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := h.service.Create(ctx, request())
	v, ok := safety.AsViolation(err)
	if !ok {
		t.Fatalf("error = %v, want a safety violation", err)
	}
	if v.Code != safety.CodeForeignUnit {
		t.Fatalf("violation = %q", v.Code)
	}
	body, _ := persist.Read(path)
	if !strings.Contains(body, "Written by hand") {
		t.Fatal("the foreign unit file was modified despite the refusal")
	}
}

// §17.6: every command the plan carries is an argv slice naming a real program,
// never a shell.
func TestEveryPlannedCommandIsAnArgvSlice(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	preview, err := h.service.PreviewCreate(ctx, request())
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range preview.Plan.Steps {
		if len(step.Argv) == 0 {
			continue
		}
		if err := safety.CheckArgv(step.Argv); err != nil {
			t.Fatalf("step %q would run a shell: %v", step.Description, err)
		}
	}

	h.mustCreate(t, request())
	for _, argv := range h.runner.Calls() {
		if err := safety.CheckArgv(argv); err != nil {
			t.Fatalf("the runner was asked to run %v: %v", argv, err)
		}
	}
}

// The mutation lock serialises changes; read paths never take it (§16).
func TestMutationsAreSerialised(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	release, err := h.service.lock(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// A second acquirer waits, and an abandoned request stops waiting rather than
	// blocking forever.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.service.lock(cancelled); err == nil {
		t.Fatal("a cancelled request must not acquire the mutation lock")
	}

	// Reading is never blocked by a held lock.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := h.repo.List(ctx); err != nil {
			t.Errorf("listing tunnels blocked on the mutation lock: %v", err)
		}
	}()
	<-done
	release()
}

// ---------------------------------------------------------------- helpers

func stepKinds(plan Plan) []string {
	out := make([]string, 0, len(plan.Steps))
	for _, s := range plan.Steps {
		out = append(out, s.Kind)
	}
	return out
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// §17 is enforced immediately before execution on every mutating path, delete
// included — it is the most destructive operation the panel has.
func TestDeleteIsGuardedToo(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	created := h.mustCreate(t, request())

	// Something replaced the unit file with one the panel did not write.
	path := h.unitPath("gre-a-1")
	if err := os.WriteFile(path, []byte("[Unit]\nDescription=Replaced by hand\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := h.service.Delete(ctx, created.Tunnel.TunnelID, Request{})
	v, ok := safety.AsViolation(err)
	if !ok {
		t.Fatalf("error = %v, want a safety violation", err)
	}
	if v.Code != safety.CodeForeignUnit {
		t.Fatalf("violation = %q", v.Code)
	}

	body, _ := persist.Read(path)
	if !strings.Contains(body, "Replaced by hand") {
		t.Fatal("the foreign unit was removed despite the refusal")
	}
	if _, err := h.links.Get(ctx, "gre-a-1"); err != nil {
		t.Fatal("the interface was removed despite the refusal")
	}

	// Taking it over is the explicit way through, and it backs the file up.
	if _, err := h.service.Delete(ctx, created.Tunnel.TunnelID, Request{Takeover: true}); err != nil {
		t.Fatalf("the takeover delete failed: %v", err)
	}
	if persist.Exists(path) {
		t.Fatal("the unit file was not removed after the takeover")
	}
}
