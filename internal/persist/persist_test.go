package persist

import (
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
)

// -update rewrites the golden files. Run `go test ./internal/persist -update`
// after a deliberate change to the rendered output, and read the diff.
var update = flag.Bool("update", false, "rewrite the golden files")

func u32(v uint32) *uint32 { return &v }

func renderer() *Renderer { return NewRenderer("/sbin/ip", "/sbin/modprobe", "/bin/ping") }

// defaultSpec is the tunnel the documented unit file describes: IPv4 GRE with a
// key, TTL 255, MTU 1472.
func defaultSpec() link.TunnelSpec {
	return link.TunnelSpec{
		Name: "gre-a-7", Kind: link.KindGRE,
		Local: "203.0.113.10", Remote: "198.51.100.20",
		Ttl: 255, Tos: "inherit", Mtu: 1472,
		IKey: u32(2749365187), OKey: u32(2749365187),
	}
}

func defaultAddresses() []link.Address {
	return []link.Address{{Address: "172.17.7.1", PrefixLength: 30, Family: link.FamilyIPv4}}
}

// assertGolden compares rendered output against a checked-in file.
func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\nRun the test with -update to create it.", path, err)
	}
	if got != string(want) {
		t.Fatalf("%s does not match the golden file.\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}

func TestUnitGolden(t *testing.T) {
	assertGolden(t, "gre-a-7.service", renderer().Unit(defaultSpec(), defaultAddresses()))
}

func TestUnitWithEveryOptionGolden(t *testing.T) {
	spec := defaultSpec()
	spec.Name = "gre-b-2"
	spec.HasInputChecksum = true
	spec.HasOutputChecksum = true
	spec.HasInputSequence = true
	spec.HasOutputSequence = true
	spec.IsPathMtuDiscovery = true
	spec.Tos = "0x10"
	spec.BindDevice = "eth0"
	txqlen := 500
	spec.TxQueueLength = &txqlen

	addresses := []link.Address{
		{Address: "172.17.2.2", PrefixLength: 30, Family: link.FamilyIPv4},
		{Address: "fd00::2", PrefixLength: 127, Family: link.FamilyIPv6},
	}
	assertGolden(t, "gre-b-2.service", renderer().Unit(spec, addresses))
}

func TestIPv6UnitGolden(t *testing.T) {
	hop := 64
	spec := link.TunnelSpec{
		Name: "gre6-a-1", Kind: link.KindIP6GRE,
		Local: "2001:db8::1", Remote: "2001:db8::2",
		Ttl: 64, HopLimit: &hop, Mtu: 1440, IKey: u32(7), OKey: u32(7),
	}
	addresses := []link.Address{{Address: "fd00:1::1", PrefixLength: 127, Family: link.FamilyIPv6}}
	assertGolden(t, "gre6-a-1.service", renderer().Unit(spec, addresses))
}

func TestKeepaliveUnitGolden(t *testing.T) {
	got := renderer().KeepaliveUnit("gre-a-7", KeepaliveOptions{
		Source: "172.17.7.1", Target: "172.17.7.2", IntervalSeconds: 1, PacketSize: 56,
	})
	assertGolden(t, "gre-panel-keepalive-gre-a-7.service", got)
}

func TestNetdevGolden(t *testing.T) {
	assertGolden(t, "gre-a-7.netdev", renderer().Netdev(defaultSpec()))
}

func TestNetworkGolden(t *testing.T) {
	assertGolden(t, "gre-a-7.network", renderer().Network(defaultSpec(), defaultAddresses()))
}

func TestNetdevWithAsymmetricKeysGolden(t *testing.T) {
	spec := defaultSpec()
	spec.Name = "gre-b-2"
	spec.IKey = u32(11)
	spec.OKey = u32(22)
	spec.IsPathMtuDiscovery = true
	spec.HasOutputSequence = true
	assertGolden(t, "gre-b-2.netdev", renderer().Netdev(spec))
}

// The corrections of §9.4, asserted individually so a regression names itself
// rather than showing up as an opaque golden-file difference.
func TestUnitCorrectsEveryLegacyDefect(t *testing.T) {
	unit := renderer().Unit(defaultSpec(), defaultAddresses())

	if !strings.Contains(unit, "After=network-online.target") {
		t.Error("the unit must order after network-online.target, not network.target")
	}
	if strings.Contains(unit, "After=network.target\n") {
		t.Error("network.target is not enough: the local endpoint may not exist yet")
	}
	if !strings.Contains(unit, "Wants=network-online.target") {
		t.Error("ordering after a target without wanting it does not pull it in")
	}
	if strings.Contains(unit, "Restart=") {
		t.Error("Restart= on a Type=oneshot unit is inert and misleading")
	}
	if strings.Contains(unit, "RestartSec=") {
		t.Error("RestartSec= on a Type=oneshot unit is inert and misleading")
	}
	if !strings.Contains(unit, "ExecStartPre=-/sbin/ip link del gre-a-7") {
		t.Error("the unit must clean up a leftover device before creating one, tolerantly")
	}
	if !strings.Contains(unit, "ExecStartPre=-/sbin/modprobe ip_gre") {
		t.Error("the module hint must be present and tolerated")
	}
	if !strings.Contains(unit, "ExecStop=-/sbin/ip link set dev gre-a-7 down") ||
		!strings.Contains(unit, "ExecStop=-/sbin/ip link del gre-a-7") {
		t.Error("the stop steps must be tolerant, so stopping a stopped tunnel succeeds")
	}
	if !strings.Contains(unit, OwnershipMarker) {
		t.Error("the unit must identify itself as panel-owned")
	}
	if !strings.Contains(unit, "Type=oneshot") || !strings.Contains(unit, "RemainAfterExit=yes") {
		t.Error("the unit must be a oneshot that remains active")
	}
	if !strings.Contains(unit, "WantedBy=multi-user.target") {
		t.Error("the unit must be installable")
	}
}

// The unit file is the second path to the same result: it must run exactly the
// argv the fallback link manager would have run (§9.4).
func TestUnitRunsTheSameArgvAsTheLinkManager(t *testing.T) {
	spec := defaultSpec()
	addresses := defaultAddresses()
	unit := renderer().Unit(spec, addresses)

	expected := []string{
		strings.Join(link.CreateArgs("/sbin/ip", spec), " "),
		strings.Join(link.AddAddressArgs("/sbin/ip", spec.Name, addresses[0]), " "),
		strings.Join(link.SetMTUArgs("/sbin/ip", spec.Name, spec.Mtu), " "),
		strings.Join(link.SetUpArgs("/sbin/ip", spec.Name), " "),
	}
	for _, want := range expected {
		if !strings.Contains(unit, "ExecStart="+want+"\n") {
			t.Fatalf("the unit does not run %q; it contains:\n%s", want, unit)
		}
	}
}

func TestDaemonReloadIsNeverDaemonReexec(t *testing.T) {
	argv := DaemonReloadArgs("/bin/systemctl")
	if strings.Join(argv, " ") != "/bin/systemctl daemon-reload" {
		t.Fatalf("argv = %v", argv)
	}
	for _, arg := range argv {
		if arg == "daemon-reexec" {
			t.Fatal("daemon-reexec re-executes PID 1 and has nothing to do with loading a unit file")
		}
	}
}

func TestUnitNames(t *testing.T) {
	if UnitName("gre-a-7") != "gre-a-7.service" {
		t.Fatalf("unit name = %q", UnitName("gre-a-7"))
	}
	if KeepaliveUnitName("gre-a-7") != "gre-panel-keepalive-gre-a-7.service" {
		t.Fatalf("keepalive unit name = %q", KeepaliveUnitName("gre-a-7"))
	}
	if ModuleFor(link.KindGRE) != "ip_gre" || ModuleFor(link.KindIP6GRE) != "ip6_gre" {
		t.Fatal("the wrong kernel module was chosen for a tunnel kind")
	}
}

func TestKeepaliveArgs(t *testing.T) {
	got := strings.Join(KeepaliveArgs("/bin/ping", KeepaliveOptions{
		Source: "172.17.7.1", Target: "172.17.7.2", IntervalSeconds: 0.5, PacketSize: 120,
	}), " ")
	want := "/bin/ping -I 172.17.7.1 -O -i 0.5 -s 120 -n 172.17.7.2"
	if got != want {
		t.Fatalf("keepalive argv\n got: %s\nwant: %s", got, want)
	}
}

// -------------------------------------------------------------- file handling

func newStore(t *testing.T) (*Store, *exec.FakeRunner, string) {
	t.Helper()
	dir := t.TempDir()
	runner := exec.NewFakeRunner()
	store := NewStore(filepath.Join(dir, "systemd"), filepath.Join(dir, "networkd"), "/bin/systemctl", runner)
	store.Now = func() time.Time { return time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC) }
	return store, runner, dir
}

func TestWriteAndRemoveAPanelOwnedFile(t *testing.T) {
	store, _, _ := newStore(t)
	ctx := context.Background()
	path := store.UnitPath("gre-a-7")

	content := renderer().Unit(defaultSpec(), defaultAddresses())
	if _, err := store.Write(ctx, path, content, false); err != nil {
		t.Fatalf("writing the unit failed: %v", err)
	}
	stored, err := Read(path)
	if err != nil || stored != content {
		t.Fatalf("the unit was not written back verbatim: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the unit could not be stat'd: %v", err)
	}
	// Windows has no POSIX mode bits: os.Stat synthesises 0666 from the
	// read-only attribute, so asserting the real mode there measures the
	// checkout's operating system rather than the panel's behaviour.
	if runtime.GOOS != "windows" && info.Mode().Perm() != UnitFileMode {
		t.Fatalf("unit permissions = %v, want %v", info.Mode().Perm(), UnitFileMode)
	}

	// Rewriting a file the panel owns is allowed, and leaves no temporary file.
	if _, err := store.Write(ctx, path, content, false); err != nil {
		t.Fatalf("rewriting the unit failed: %v", err)
	}
	if Exists(path + ".tmp") {
		t.Fatal("a temporary file was left behind")
	}

	if _, err := store.Remove(ctx, path, false); err != nil {
		t.Fatalf("removing the unit failed: %v", err)
	}
	if Exists(path) {
		t.Fatal("the unit was not removed")
	}
	// Removing what is already gone is a success, not an error.
	if _, err := store.Remove(ctx, path, false); err != nil {
		t.Fatalf("removing an absent unit failed: %v", err)
	}
}

// §17.3: never delete or overwrite a unit file the panel did not write, unless
// it was explicitly taken over, and only after a backup.
func TestForeignFileIsRefusedUnlessTakenOver(t *testing.T) {
	store, _, _ := newStore(t)
	ctx := context.Background()
	path := store.UnitPath("gre-a-7")

	const foreign = "[Unit]\nDescription=Something an operator wrote by hand\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating the unit directory failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(foreign), 0o644); err != nil {
		t.Fatalf("seeding the foreign unit failed: %v", err)
	}

	if _, err := store.Write(ctx, path, "replacement", false); !errors.Is(err, ErrNotPanelOwned) {
		t.Fatalf("overwriting a foreign unit gave %v, want ErrNotPanelOwned", err)
	}
	if _, err := store.Remove(ctx, path, false); !errors.Is(err, ErrNotPanelOwned) {
		t.Fatalf("deleting a foreign unit gave %v, want ErrNotPanelOwned", err)
	}
	if current, _ := Read(path); current != foreign {
		t.Fatal("the foreign unit was modified despite the refusal")
	}

	// With takeover the original is backed up first, and only then replaced.
	backup, err := store.Write(ctx, path, "replacement", true)
	if err != nil {
		t.Fatalf("taking the unit over failed: %v", err)
	}
	if backup == "" {
		t.Fatal("taking a file over must back the original up first")
	}
	saved, err := Read(backup)
	if err != nil || saved != foreign {
		t.Fatalf("the backup does not hold the original: %v", err)
	}
	if current, _ := Read(path); current != "replacement" {
		t.Fatal("the unit was not replaced after the takeover")
	}
}

func TestIsPanelOwned(t *testing.T) {
	dir := t.TempDir()
	owned := filepath.Join(dir, "owned.service")
	foreign := filepath.Join(dir, "foreign.service")

	if err := os.WriteFile(owned, []byte(renderer().Unit(defaultSpec(), nil)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreign, []byte("[Unit]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if ok, err := IsPanelOwned(owned); err != nil || !ok {
		t.Fatalf("a generated unit must be recognised as panel-owned: %v, %v", ok, err)
	}
	if ok, err := IsPanelOwned(foreign); err != nil || ok {
		t.Fatalf("a hand-written unit must not be recognised as panel-owned: %v, %v", ok, err)
	}
	if ok, err := IsPanelOwned(filepath.Join(dir, "absent.service")); err != nil || !ok {
		t.Fatalf("an absent file must be writable: %v, %v", ok, err)
	}
}

func TestSystemctlQueriesReadTheState(t *testing.T) {
	store, runner, _ := newStore(t)
	ctx := context.Background()

	runner.Responses["/bin/systemctl is-enabled gre-a-7.service"] = exec.Result{Stdout: "enabled\n"}
	runner.Responses["/bin/systemctl is-active gre-a-7.service"] = exec.Result{Stdout: "active\n"}

	enabled, state, err := store.IsEnabled(ctx, "gre-a-7.service")
	if err != nil || !enabled || state != "enabled" {
		t.Fatalf("is-enabled = %v, %q, %v", enabled, state, err)
	}
	active, state, err := store.IsActive(ctx, "gre-a-7.service")
	if err != nil || !active || state != "active" {
		t.Fatalf("is-active = %v, %q, %v", active, state, err)
	}

	// A disabled unit makes systemctl exit non-zero, which is an answer rather
	// than a failure and must not be reported as an error.
	runner.Responses["/bin/systemctl is-enabled gre-b-2.service"] = exec.Result{ExitCode: 1, Stdout: "disabled\n"}
	runner.Errors["/bin/systemctl is-enabled gre-b-2.service"] = errors.New("systemctl exited 1")
	enabled, state, err = store.IsEnabled(ctx, "gre-b-2.service")
	if err != nil {
		t.Fatalf("a disabled unit must not be an error: %v", err)
	}
	if enabled || state != "disabled" {
		t.Fatalf("is-enabled = %v, %q", enabled, state)
	}
}

func TestSystemctlIsUnavailableWithoutTheBinary(t *testing.T) {
	store := NewStore(t.TempDir(), t.TempDir(), "", exec.NewFakeRunner())
	if store.SystemdAvailable() {
		t.Fatal("systemd persistence must not be offered without systemctl")
	}
	if err := store.DaemonReload(context.Background()); err == nil {
		t.Fatal("daemon-reload without systemctl must fail rather than pretend to succeed")
	}
}
