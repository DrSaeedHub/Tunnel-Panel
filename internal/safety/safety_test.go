package safety

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/persist"
)

func newGuard(t *testing.T) (*Guard, *link.Fake, string) {
	t.Helper()
	dir := t.TempDir()
	links := link.NewFakeWithHost()
	systemdDir := filepath.Join(dir, "systemd")
	networkdDir := filepath.Join(dir, "networkd")
	if err := os.MkdirAll(systemdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(networkdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return New(links, systemdDir, networkdDir), links, dir
}

func expectViolation(t *testing.T, err error, code string) {
	t.Helper()
	v, ok := AsViolation(err)
	if !ok {
		t.Fatalf("error %v is not a safety violation", err)
	}
	if v.Code != code {
		t.Fatalf("violation code = %q, want %q (%s)", v.Code, code, v.Message)
	}
}

// Invariant 1: never target a physical interface, a bridge, the loopback, or
// the default-route interface.
func TestNeverTouchesAProtectedInterface(t *testing.T) {
	g, links, _ := newGuard(t)
	ctx := context.Background()

	links.AddLink(link.Link{Name: "br0", Kind: "bridge", Index: 5})
	links.AddLink(link.Link{Name: "enslaved", Kind: link.KindGRE, Index: 6, MasterIndex: 5,
		Tunnel: &link.TunnelAttrs{Local: "203.0.113.10", Remote: "198.51.100.20"}})

	// Every one of these is claimed as managed, which is the point: even a
	// request that insists the panel owns the device is refused.
	cases := map[string]string{
		"lo":       CodeProtectedDevice,
		"eth0":     CodeProtectedDevice,
		"br0":      CodeProtectedDevice,
		"gre0":     CodeProtectedDevice,
		"enslaved": CodeProtectedDevice,
	}
	for name, code := range cases {
		err := g.CheckInterface(ctx, name, true)
		if err == nil {
			t.Fatalf("%q was accepted as a target", name)
		}
		expectViolation(t, err, code)
	}
}

func TestNeverTouchesAnInterfaceItDoesNotManage(t *testing.T) {
	g, links, _ := newGuard(t)
	ctx := context.Background()
	links.AddLink(link.Link{Name: "gre-foreign", Kind: link.KindGRE, Index: 7,
		Tunnel: &link.TunnelAttrs{Local: "203.0.113.10", Remote: "198.51.100.20"}})

	err := g.CheckInterface(ctx, "gre-foreign", false)
	expectViolation(t, err, CodeNotManaged)

	// The same interface, claimed by the panel, is fine.
	if err := g.CheckInterface(ctx, "gre-foreign", true); err != nil {
		t.Fatalf("a managed tunnel was refused: %v", err)
	}
}

// Even a tunnel is off limits when this host's default route runs through it.
func TestNeverTouchesTheDefaultRouteInterface(t *testing.T) {
	g, links, _ := newGuard(t)
	ctx := context.Background()

	links.AddLink(link.Link{Name: "gre-uplink", Kind: link.KindGRE, Index: 8,
		Tunnel: &link.TunnelAttrs{Local: "203.0.113.10", Remote: "198.51.100.20"}})
	links.SetRoutes([]link.Route{
		{Destination: "default", Device: "gre-uplink", IsDefault: true},
	})

	err := g.CheckInterface(ctx, "gre-uplink", true)
	expectViolation(t, err, CodeProtectedDevice)
}

func TestCreatingAnInterfaceThatDoesNotExistYetIsAllowed(t *testing.T) {
	g, _, _ := newGuard(t)
	if err := g.CheckInterface(context.Background(), "gre-a-1", true); err != nil {
		t.Fatalf("creating a new tunnel was refused: %v", err)
	}
}

// Invariant 2: never modify host networking, netplan, DNS, or the default
// route configuration.
func TestNeverWritesProtectedPaths(t *testing.T) {
	g, _, _ := newGuard(t)

	forbidden := []string{
		"/etc/network/interfaces",
		"/etc/network/interfaces.d/eth0",
		"/etc/netplan/01-netcfg.yaml",
		"/etc/resolv.conf",
		"/etc/systemd/resolved.conf",
		"/etc/hosts",
		"/etc/NetworkManager/system-connections/wired",
		"/etc/passwd",
		"relative/path",
	}
	for _, path := range forbidden {
		err := g.CheckPath(path)
		if err == nil {
			t.Fatalf("%q was accepted as a writable path", path)
		}
		expectViolation(t, err, CodeProtectedPath)
	}

	// The two directories the panel owns are writable, and nothing else is.
	if err := g.CheckPath(filepath.Join(g.SystemdDir, "gre-a-1.service")); err != nil {
		t.Fatalf("the unit directory was refused: %v", err)
	}
	if err := g.CheckPath(filepath.Join(g.NetworkdDir, "gre-a-1.netdev")); err != nil {
		t.Fatalf("the networkd directory was refused: %v", err)
	}
	// A traversal out of an allowed directory resolves to a path outside it.
	if err := g.CheckPath(filepath.Join(g.SystemdDir, "..", "..", "etc", "resolv.conf")); err == nil {
		t.Fatal("a path traversing out of the unit directory was accepted")
	}
}

// Invariant 3: never delete a unit file the panel did not write, unless it was
// adopted with takeover, and only after a backup.
func TestNeverDeletesAForeignUnitFile(t *testing.T) {
	g, _, _ := newGuard(t)
	foreign := filepath.Join(g.SystemdDir, "handwritten.service")
	if err := os.WriteFile(foreign, []byte("[Unit]\nDescription=Not ours\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := g.CheckUnitOwnership(foreign, false)
	expectViolation(t, err, CodeForeignUnit)

	if err := g.CheckUnitOwnership(foreign, true); err != nil {
		t.Fatalf("an explicit takeover was refused: %v", err)
	}

	owned := filepath.Join(g.SystemdDir, "gre-a-1.service")
	body := persist.OwnershipMarker + " interface=gre-a-1\n[Unit]\n"
	if err := os.WriteFile(owned, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := g.CheckUnitOwnership(owned, false); err != nil {
		t.Fatalf("a panel-written unit was refused: %v", err)
	}

	// Ownership is only ever considered for a path the panel may write at all.
	if err := g.CheckUnitOwnership("/etc/systemd/resolved.conf", true); err == nil {
		t.Fatal("takeover must not open a protected path")
	}
}

// Invariant 4: refuse to delete or reconfigure a tunnel carrying the requesting
// client's own connection, unless they say they accept losing access.
func TestRefusesToCutTheRequestingClientsOwnConnection(t *testing.T) {
	addresses := []link.Address{
		{Address: "172.17.7.1", PrefixLength: 30, Family: link.FamilyIPv4},
	}

	// The operator is reaching the panel through the tunnel's own subnet.
	err := CheckClientConnection("172.17.7.2", addresses, false)
	expectViolation(t, err, CodeWouldCutOwnAccess)

	v, _ := AsViolation(err)
	if v.Field != "i_understand_i_may_lose_access" {
		t.Fatalf("the refusal must name the acknowledgement field, got %q", v.Field)
	}
	if v.Details["subnet"] != "172.17.7.0/30" {
		t.Fatalf("the refusal must name the subnet, got %+v", v.Details)
	}

	// Acknowledged, it proceeds.
	if err := CheckClientConnection("172.17.7.2", addresses, true); err != nil {
		t.Fatalf("an acknowledged request was still refused: %v", err)
	}
	// From anywhere else there is nothing to lose.
	if err := CheckClientConnection("203.0.113.55", addresses, false); err != nil {
		t.Fatalf("a request from outside the tunnel was refused: %v", err)
	}
	if err := CheckClientConnection("", addresses, false); err != nil {
		t.Fatalf("an unknown source address must not block the operation: %v", err)
	}
}

// Invariant 6: no shell interpretation anywhere.
func TestNeverRunsAShell(t *testing.T) {
	forbidden := [][]string{
		{"/bin/sh", "-c", "ip link del gre-a-1"},
		{"/bin/bash", "-c", "echo hello"},
		{"bash", "-c", "true"},
		{"/bin/busybox", "sh"},
		{},
	}
	for _, argv := range forbidden {
		if err := CheckArgv(argv); err == nil {
			t.Fatalf("%v was accepted as a command", argv)
		}
	}

	allowed := [][]string{
		{"/sbin/ip", "link", "add", "name", "gre-a-1", "type", "gre"},
		{"/bin/systemctl", "daemon-reload"},
		// An argument containing shell metacharacters is only ever an argument.
		{"/sbin/ip", "link", "del", "a; rm -rf /"},
	}
	for _, argv := range allowed {
		if err := CheckArgv(argv); err != nil {
			t.Fatalf("%v was refused: %v", argv, err)
		}
	}
}

// Invariant 5: never log passwords or tokens; redact them in the audit trail.
func TestSecretsAreRedactedInTheAuditTrail(t *testing.T) {
	request := map[string]any{
		"username":     "operator",
		"password":     "correct horse battery staple",
		"csrf_token":   "abc123",
		"ikey":         2749365187,
		"interface":    "gre-a-1",
		"nested":       map[string]any{"refresh_token": "secret", "mtu": 1472},
		"access_token": "xyz",
	}
	redacted, ok := audit.Redact(request).(map[string]any)
	if !ok {
		t.Fatal("redaction changed the shape of the request")
	}

	for _, field := range []string{"password", "csrf_token", "access_token"} {
		if redacted[field] != audit.Redacted {
			t.Fatalf("%s was not redacted: %v", field, redacted[field])
		}
	}
	nested := redacted["nested"].(map[string]any)
	if nested["refresh_token"] != audit.Redacted {
		t.Fatalf("a nested token was not redacted: %v", nested["refresh_token"])
	}

	// The GRE key is configuration, not a credential: redacting it would make the
	// audit trail useless for diagnosing the commonest misconfiguration there is.
	if redacted["ikey"] != 2749365187 {
		t.Fatalf("the GRE key must not be redacted, got %v", redacted["ikey"])
	}
	if nested["mtu"] != 1472 || redacted["interface"] != "gre-a-1" {
		t.Fatal("non-secret fields must survive redaction unchanged")
	}
}

func TestAsViolationIgnoresOtherErrors(t *testing.T) {
	if _, ok := AsViolation(os.ErrNotExist); ok {
		t.Fatal("an unrelated error was reported as a safety violation")
	}
	if _, ok := AsViolation(nil); ok {
		t.Fatal("nil was reported as a safety violation")
	}
}
