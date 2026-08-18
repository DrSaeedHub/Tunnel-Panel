package reconcile

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/settings"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

type harness struct {
	service  *Service
	tunnels  *tunnel.Service
	repo     *tunnel.Repo
	links    *link.Fake
	runner   *exec.FakeRunner
	store    *persist.Store
	settings *settings.Store
	db       *db.DB
	dir      string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	database, err := db.Open(ctx, filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}

	store, err := settings.New(ctx, database)
	if err != nil {
		t.Fatalf("creating the settings store failed: %v", err)
	}

	systemdDir := filepath.Join(dir, "systemd")
	networkdDir := filepath.Join(dir, "networkd")
	for _, d := range []string{systemdDir, networkdDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	links := link.NewFakeWithHost()
	runner := exec.NewFakeRunner()
	repo := tunnel.NewRepo(database)
	persistStore := persist.NewStore(systemdDir, networkdDir, "/bin/systemctl", runner)
	renderer := persist.NewRenderer("/sbin/ip", "/sbin/modprobe", "/bin/ping")

	tunnels := tunnel.New(tunnel.Deps{
		Repo:         repo,
		Links:        links,
		Runner:       runner,
		Renderer:     renderer,
		Store:        persistStore,
		Alloc:        alloc.New(repo, links, store),
		Validator:    validate.New(links, repo.ForValidation(), store, "/api/v1/reconcile/adopt"),
		Guard:        safety.New(links, systemdDir, networkdDir),
		Settings:     store,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		IPBin:        "/sbin/ip",
		SystemctlBin: "/bin/systemctl",
	})

	return &harness{
		service:  New(tunnels, repo, links, persistStore, renderer, store),
		tunnels:  tunnels,
		repo:     repo,
		links:    links,
		runner:   runner,
		store:    persistStore,
		settings: store,
		db:       database,
		dir:      dir,
	}
}

func u32(v uint32) *uint32 { return &v }

// createTunnel makes a tunnel through the panel itself.
//
// It asks for runtime persistence so the fake link manager carries out the
// whole apply. These tests are about classification and adoption; the systemd
// path is covered where it belongs, in the lifecycle package.
func (h *harness) createTunnel(t *testing.T) tunnel.Record {
	t.Helper()
	result, err := h.tunnels.Create(context.Background(), tunnel.Request{TunnelInput: validate.TunnelInput{
		LocalEndpoint:     "203.0.113.10",
		RemoteEndpoint:    "198.51.100.20",
		PersistenceTypeID: model.PersistenceTypeRuntime,
		IsEnabled:         true,
	}})
	if err != nil {
		t.Fatalf("creating the reference tunnel failed: %v", err)
	}
	return result.Tunnel
}

// legacyTunnel adds an interface exactly as the old install script would have
// left it: its naming scheme, its default key, its /30 with the third octet as
// the tunnel number, and operational state UNKNOWN.
func (h *harness) legacyTunnel(t *testing.T, name string, number int, address string) {
	t.Helper()
	h.links.AddLink(link.Link{
		Name: name, Index: 10 + number, MTU: 1472, Kind: link.KindGRE,
		OperState: "UNKNOWN", IsUp: true, IsLowerUp: true, IsRunning: true,
		Flags: []string{"POINTOPOINT", "NOARP", "UP", "LOWER_UP"},
		Tunnel: &link.TunnelAttrs{
			Local: "203.0.113.10", Remote: "198.51.100.20", Ttl: 255,
			IKey: u32(2749365187), OKey: u32(2749365187), Tos: "inherit",
		},
		Addresses: []link.Address{
			{Address: address, PrefixLength: 30, Family: link.FamilyIPv4, Scope: "global"},
		},
	})
}

// legacyUnit writes the unit file the old script produced, defects and all.
func (h *harness) legacyUnit(t *testing.T, name string) string {
	t.Helper()
	body := `[Unit]
Description=GRE Tunnel ` + name + `
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip tunnel add ` + name + ` mode gre local 203.0.113.10 remote 198.51.100.20 ttl 255 key 2749365187
ExecStartPost=/sbin/ip addr add 172.17.7.1/30 dev ` + name + `
ExecStartPost=/sbin/ip link set dev ` + name + ` mtu 1472
ExecStartPost=/sbin/ip link set dev ` + name + ` up
ExecStop=/sbin/ip link set dev ` + name + ` down
ExecStop=/sbin/ip tunnel del ` + name + `
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`
	path := filepath.Join(h.dir, "systemd", name+".service")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------- legacy names

func TestLegacyNamesAreRecognisedAndMapped(t *testing.T) {
	// The script gave its first side marker the .1 address and its second the
	// .2 address, which is exactly the panel's slot rule, so the mapping is
	// determined rather than chosen.
	cases := []struct {
		name   string
		side   int64
		number int64
	}{
		{"gre-ir-7", model.TunnelSideA, 7},
		{"gre-kh-7", model.TunnelSideB, 7},
		{"gre-ir-255", model.TunnelSideA, 255},
		{"gre-kh-1", model.TunnelSideB, 1},
	}
	for _, tc := range cases {
		info, ok := ParseLegacyName(tc.name)
		if !ok {
			t.Fatalf("%q was not recognised as a legacy name", tc.name)
		}
		if info.TunnelSideID != tc.side || info.TunnelNumber != tc.number {
			t.Fatalf("%q mapped to side %d number %d", tc.name, info.TunnelSideID, info.TunnelNumber)
		}
	}

	for _, name := range []string{"gre-a-1", "gre-ir", "gre-ir-", "gre-xx-1", "gre-ir-1x", "tun0"} {
		if _, ok := ParseLegacyName(name); ok {
			t.Fatalf("%q was wrongly treated as a legacy name", name)
		}
	}
}

// ---------------------------------------------------------------- report

func TestReportClassifiesEveryState(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// InSync: created through the panel and untouched.
	created := h.createTunnel(t)

	// Unmanaged: a tunnel the panel has no record of.
	h.legacyTunnel(t, "gre-ir-7", 7, "172.17.7.1")

	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatalf("the report failed: %v", err)
	}

	byName := map[string]Item{}
	for _, item := range report.Items {
		byName[item.InterfaceName] = item
	}

	insync := byName[created.InterfaceName]
	if insync.Status != StatusInSync {
		t.Fatalf("an untouched tunnel is %q with diffs %+v", insync.Status, insync.Diffs)
	}
	if insync.ReconcileStatusID != model.ReconcileStatusInSync {
		t.Fatalf("status id = %d", insync.ReconcileStatusID)
	}

	unmanaged := byName["gre-ir-7"]
	if unmanaged.Status != StatusUnmanaged {
		t.Fatalf("an unknown tunnel is %q", unmanaged.Status)
	}
	if unmanaged.Legacy == nil || unmanaged.Legacy.TunnelNumber != 7 {
		t.Fatalf("the legacy tunnel was not recognised: %+v", unmanaged.Legacy)
	}
	if !contains(unmanaged.Actions, ActionAdopt) {
		t.Fatalf("an unmanaged tunnel must offer adoption: %v", unmanaged.Actions)
	}
	// Never auto-destroy: the offered actions must not include anything that
	// removes an interface the panel does not manage.
	if contains(unmanaged.Actions, ActionDelete) {
		t.Fatalf("an unmanaged interface must not offer deletion: %v", unmanaged.Actions)
	}
}

func TestReportDetectsDriftWithExactFieldDiffs(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created := h.createTunnel(t)
	name := created.InterfaceName

	// Someone changed the MTU outside the panel.
	if err := h.links.SetMTU(ctx, name, 1300); err != nil {
		t.Fatal(err)
	}

	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := findItem(report, name)
	if item.Status != StatusDrifted {
		t.Fatalf("status = %q, want Drifted", item.Status)
	}
	if len(item.Diffs) != 1 {
		t.Fatalf("diffs = %+v", item.Diffs)
	}
	if item.Diffs[0].Field != "mtu" || item.Diffs[0].Desired != "1472" || item.Diffs[0].Actual != "1300" {
		t.Fatalf("the diff must name the field and both values: %+v", item.Diffs[0])
	}
	if !strings.Contains(item.Detail, "mtu") {
		t.Fatalf("the detail must say what drifted: %q", item.Detail)
	}
}

func TestReportDetectsAMissingInterface(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created := h.createTunnel(t)
	if err := h.links.Delete(ctx, created.InterfaceName); err != nil {
		t.Fatal(err)
	}

	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := findItem(report, created.InterfaceName)
	if item.Status != StatusMissing {
		t.Fatalf("status = %q, want Missing", item.Status)
	}
	if !contains(item.Actions, ActionReapply) || !contains(item.Actions, ActionForget) {
		t.Fatalf("a missing tunnel must offer reapply and forget: %v", item.Actions)
	}
}

func TestReportShowsAnInconsistentTunnelProminently(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created := h.createTunnel(t)
	if err := h.repo.SetApplyStatus(ctx, created.TunnelID, model.ApplyStatusInconsistent,
		errNamed("the rollback failed too")); err != nil {
		t.Fatal(err)
	}

	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := findItem(report, created.InterfaceName)
	if item.Status != StatusInconsistent {
		t.Fatalf("status = %q, want Inconsistent", item.Status)
	}
	if !strings.Contains(item.Detail, "the rollback failed too") {
		t.Fatalf("the detail must carry the original failure: %q", item.Detail)
	}
}

func TestIgnoredInterfacesAreStillListedButNotOfferedForChange(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.legacyTunnel(t, "gre-ir-7", 7, "172.17.7.1")

	if _, err := SetIgnored(ctx, h.settings, "gre-ir-7", true, nil); err != nil {
		t.Fatalf("ignoring failed: %v", err)
	}

	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	item := findItem(report, "gre-ir-7")
	if !item.IsIgnored {
		t.Fatal("the interface was not marked ignored")
	}
	if !contains(item.Actions, ActionUnignore) {
		t.Fatalf("an ignored interface must offer unignoring: %v", item.Actions)
	}

	if _, err := SetIgnored(ctx, h.settings, "gre-ir-7", false, nil); err != nil {
		t.Fatalf("unignoring failed: %v", err)
	}
	report, _ = h.service.Report(ctx)
	if findItem(report, "gre-ir-7").IsIgnored {
		t.Fatal("the interface is still ignored")
	}
}

// ---------------------------------------------------------------- adoption

// Adoption imports the parameters from the kernel and must not disturb the
// interface: no rename, no bounce, no address change.
func TestAdoptImportsFromTheKernelWithoutTouchingTheInterface(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.legacyTunnel(t, "gre-ir-7", 7, "172.17.7.1")
	h.links.Reset()

	result, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: "gre-ir-7"})
	if err != nil {
		t.Fatalf("adoption failed: %v", err)
	}

	// Nothing was done to the interface at all.
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("adoption changed the interface: %v", calls)
	}
	if result.InterfaceBounced {
		t.Fatal("adoption must never bounce the interface")
	}

	rec := result.Tunnel
	if rec.InterfaceName != "gre-ir-7" {
		t.Fatalf("the interface was renamed to %q; renaming tears the link down", rec.InterfaceName)
	}
	if rec.IsNameTemplated {
		t.Fatal("an adopted name must not be marked templated, or a later change would rename it")
	}
	if rec.TunnelSideID != model.TunnelSideA {
		t.Fatalf("side = %d; the script's first marker takes the first address, which is slot A", rec.TunnelSideID)
	}
	if rec.TunnelNumber == nil || *rec.TunnelNumber != 7 {
		t.Fatalf("the tunnel number was not inferred: %v", rec.TunnelNumber)
	}
	if rec.LocalEndpoint != "203.0.113.10" || rec.RemoteEndpoint != "198.51.100.20" {
		t.Fatalf("the endpoints were not imported: %+v", rec)
	}
	if rec.Ttl != 255 || rec.Mtu != 1472 {
		t.Fatalf("ttl/mtu were not imported: %d, %d", rec.Ttl, rec.Mtu)
	}
	if rec.IKey == nil || *rec.IKey != 2749365187 {
		t.Fatalf("the key was not imported: %v", rec.IKey)
	}
	if rec.ApplyStatusID != model.ApplyStatusApplied {
		t.Fatalf("an adopted tunnel is already applied; status = %d", rec.ApplyStatusID)
	}

	// The address came across, and the peer was worked out from the /30.
	if len(rec.Addresses) != 1 || rec.Addresses[0].Address != "172.17.7.1" {
		t.Fatalf("the address was not imported: %+v", rec.Addresses)
	}
	if peer := rec.Addresses[0].PeerAddress; peer == nil || *peer != "172.17.7.2" {
		t.Fatalf("the peer address was not derived from the subnet: %v", peer)
	}

	// It now shows as in sync rather than unmanaged.
	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if item := findItem(report, "gre-ir-7"); item.Status != StatusInSync {
		t.Fatalf("after adoption the tunnel is %q with diffs %+v", item.Status, item.Diffs)
	}
}

func TestAdoptTheSecondSideMapsToSlotB(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.legacyTunnel(t, "gre-kh-7", 7, "172.17.7.2")

	result, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: "gre-kh-7"})
	if err != nil {
		t.Fatalf("adoption failed: %v", err)
	}
	if result.Tunnel.TunnelSideID != model.TunnelSideB {
		t.Fatalf("side = %d, want B", result.Tunnel.TunnelSideID)
	}
	if peer := result.Tunnel.Addresses[0].PeerAddress; peer == nil || *peer != "172.17.7.1" {
		t.Fatalf("the peer of the second address must be the first: %v", peer)
	}
}

func TestAdoptWithoutTakeoverLeavesTheLegacyUnitAloneAndWarns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.legacyTunnel(t, "gre-ir-7", 7, "172.17.7.1")
	unitPath := h.legacyUnit(t, "gre-ir-7")
	original, err := persist.Read(unitPath)
	if err != nil {
		t.Fatal(err)
	}

	result, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: "gre-ir-7"})
	if err != nil {
		t.Fatalf("adoption failed: %v", err)
	}

	current, _ := persist.Read(unitPath)
	if current != original {
		t.Fatal("the legacy unit was rewritten without takeover")
	}
	found := false
	for _, w := range result.Warnings {
		if w.Code == WarnLegacyUnitNotOwned {
			found = true
		}
	}
	if !found {
		t.Fatalf("adopting a tunnel whose unit the panel does not own must warn: %+v", result.Warnings)
	}
	if result.Tunnel.PersistenceTypeID != model.PersistenceTypeSystemd {
		t.Fatalf("a tunnel with a unit file is systemd-persisted; got %d", result.Tunnel.PersistenceTypeID)
	}
}

func TestAdoptWithTakeoverRewritesTheUnitAfterBackingItUp(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.legacyTunnel(t, "gre-ir-7", 7, "172.17.7.1")
	unitPath := h.legacyUnit(t, "gre-ir-7")
	original, _ := persist.Read(unitPath)

	// The script also leaves a permanent keepalive unit behind.
	keepalivePath := filepath.Join(h.dir, "systemd", "gre-keepalive-gre-ir-7.service")
	if err := os.WriteFile(keepalivePath, []byte("[Service]\nExecStart=/bin/ping -I 172.17.7.1 172.17.7.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h.links.Reset()

	result, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: "gre-ir-7", Takeover: true})
	if err != nil {
		t.Fatalf("adoption with takeover failed: %v", err)
	}

	// The interface still was not touched.
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("takeover changed the interface: %v", calls)
	}

	// The original is safe.
	if len(result.Backups) == 0 {
		t.Fatal("takeover must back the original up first")
	}
	saved, err := persist.Read(result.Backups[0])
	if err != nil {
		t.Fatalf("the backup is unreadable: %v", err)
	}
	if saved != original {
		t.Fatal("the backup does not hold the original unit")
	}

	// The unit is now the corrected one.
	current, _ := persist.Read(unitPath)
	if !strings.Contains(current, persist.OwnershipMarker) {
		t.Fatal("the rewritten unit does not identify itself as panel-owned")
	}
	if !strings.Contains(current, "After=network-online.target") {
		t.Fatal("the rewritten unit did not correct the ordering")
	}
	if strings.Contains(current, "Restart=on-failure") {
		t.Fatal("the rewritten unit reproduced the inert Restart= directive")
	}
	if !strings.Contains(current, "ip link add name gre-ir-7 type gre") {
		t.Fatalf("the rewritten unit does not create the tunnel:\n%s", current)
	}

	// The script's keepalive unit is superseded by the panel's own prober.
	if persist.Exists(keepalivePath) {
		t.Fatal("the legacy keepalive unit was left in place")
	}

	// Nothing was started or restarted, which is what would have bounced it.
	for _, argv := range h.runner.Calls() {
		if len(argv) > 1 && (argv[1] == "start" || argv[1] == "restart") {
			if strings.Contains(strings.Join(argv, " "), "gre-ir-7.service") {
				t.Fatalf("takeover restarted the tunnel unit: %v", argv)
			}
		}
	}
}

func TestAdoptRefusesWhatItCannotAdopt(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	cases := map[string]string{
		"eth0":     "a physical interface",
		"lo":       "the loopback",
		"nosuchif": "an interface that does not exist",
	}
	for name, why := range cases {
		if _, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: name}); err == nil {
			t.Fatalf("adopting %s (%s) was allowed", name, why)
		}
	}

	// Adopting the same tunnel twice is refused.
	h.legacyTunnel(t, "gre-ir-7", 7, "172.17.7.1")
	if _, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: "gre-ir-7"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.service.Adopt(ctx, AdoptRequest{InterfaceName: "gre-ir-7"}); err == nil {
		t.Fatal("the same interface was adopted twice")
	}
}

// ---------------------------------------------------------------- forget

func TestForgetDropsTheRecordWithoutTouchingTheKernel(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	created := h.createTunnel(t)
	name := created.InterfaceName
	h.links.Reset()

	if _, err := h.service.Forget(ctx, created.TunnelID); err != nil {
		t.Fatalf("forget failed: %v", err)
	}
	if calls := h.links.Calls(); len(calls) != 0 {
		t.Fatalf("forget changed the kernel: %v", calls)
	}
	if _, err := h.links.Get(ctx, name); err != nil {
		t.Fatal("forget removed the interface; it must only drop the record")
	}
	if _, err := h.repo.ByID(ctx, created.TunnelID); err == nil {
		t.Fatal("the record survived forget")
	}

	// It now reads as unmanaged rather than vanishing from the report.
	report, err := h.service.Report(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if item := findItem(report, name); item.Status != StatusUnmanaged {
		t.Fatalf("after forget the interface is %q", item.Status)
	}
}

// ---------------------------------------------------------------- helpers

func findItem(report Report, name string) Item {
	for _, item := range report.Items {
		if item.InterfaceName == name {
			return item
		}
	}
	return Item{}
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

type namedError string

func (e namedError) Error() string { return string(e) }

func errNamed(message string) error { return namedError(message) }
