// Package safety enforces the hard invariants of §17.
//
// These are not settings and not warnings. No configuration value and no
// `force` flag relaxes them, and they are checked in the service layer
// immediately before execution rather than only at the API boundary, so a code
// path that reaches the kernel without passing through a handler is still
// covered.
//
// The panel runs as root and reconfigures kernel networking on a machine an
// operator reaches over that same network. The worst failure available to it is
// not a broken tunnel; it is taking the host off the network.
package safety

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path"
	"path/filepath"
	"strings"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/persist"
)

// Violation codes. They are stable, because the frontend explains each one
// differently and the audit log is searched by them.
const (
	CodeNotManaged        = "INTERFACE_NOT_MANAGED"
	CodeProtectedDevice   = "PROTECTED_INTERFACE"
	CodeProtectedPath     = "PROTECTED_PATH"
	CodeForeignUnit       = "FOREIGN_UNIT_FILE"
	CodeWouldCutOwnAccess = "WOULD_CUT_OWN_ACCESS"
	CodeShellInvocation   = "SHELL_INVOCATION"
)

// Violation is a refused operation. It is deliberately a distinct type from a
// validation error: validation says the request is malformed, this says the
// request is well-formed and will not be carried out.
type Violation struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Field   string         `json:"field,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

func (v *Violation) Error() string { return v.Message }

func violation(code, field, message string, details map[string]any) *Violation {
	return &Violation{Code: code, Field: field, Message: message, Details: details}
}

// ProtectedPaths are files the panel must never write, whatever else it is
// doing (§17.2). Host networking, name resolution and the default route belong
// to the operator and to the distribution, not to a tunnel panel.
//
// The forwarding subsystem adds the kernel-parameter and firewall-persistence
// paths: /etc/sysctl.conf and everything under /etc/sysctl.d belong to the
// distribution and to other packages, and /etc/iptables belongs to the
// distribution's firewall persistence package, whose whole-system snapshots
// this panel deliberately does not use. The one file under /etc/sysctl.d that
// the panel does own is allowed back in by name in RouteGuard.CheckPath.
var ProtectedPaths = []string{
	"/etc/network/interfaces",
	"/etc/network/interfaces.d",
	"/etc/netplan",
	"/etc/resolv.conf",
	"/etc/systemd/resolved.conf",
	"/etc/systemd/resolved.conf.d",
	"/etc/hosts",
	"/etc/nsswitch.conf",
	"/etc/dhcp",
	"/etc/NetworkManager",
	"/etc/sysctl.conf",
	"/etc/sysctl.d",
	"/etc/iptables",
	"/etc/nftables.conf",
}

// hostPath normalises a path for comparison against the lists above.
//
// Every path either guard reasons about is a path on the Linux host the panel
// manages, so it is compared with POSIX semantics rather than with the
// semantics of whatever operating system happens to be running the code. The
// two agree on Linux, which is the only place the panel runs, and disagree
// everywhere else: filepath.Separator is '\' on Windows, so the prefix tests
// below stop recognising /etc/sysctl.d/99-sysctl.conf as living under
// /etc/sysctl.d and the guard permits exactly what it exists to refuse. A
// safety check whose answer depends on the reader's operating system is not a
// safety check, so the comparison is pinned to the host's own separator.
func hostPath(p string) string { return path.Clean(filepath.ToSlash(p)) }

// isAbsHostPath accepts a POSIX absolute path, and also whatever the running
// OS calls absolute. Both forms are needed: the paths under test are the
// managed host's and begin with '/', while the directories a test hands the
// guard are its own temporary directories, which on Windows are drive-lettered.
func isAbsHostPath(p string) bool {
	return strings.HasPrefix(hostPath(p), "/") || filepath.IsAbs(p)
}

// isUnderHostPath reports whether child is parent or sits beneath it.
func isUnderHostPath(child, parent string) bool {
	child, parent = hostPath(child), hostPath(parent)
	return child == parent || strings.HasPrefix(child, strings.TrimSuffix(parent, "/")+"/")
}

// shellPrograms are interpreters that would reintroduce shell parsing. The
// runner takes an argv slice and never a command string, so this is a
// belt-and-braces check on the argv itself (§17.6).
var shellPrograms = []string{"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox"}

// Guard checks operations against the invariants.
type Guard struct {
	Links link.LinkManager
	// SystemdDir and NetworkdDir bound where generated files may be written.
	SystemdDir  string
	NetworkdDir string
}

// New returns a guard.
func New(links link.LinkManager, systemdDir, networkdDir string) *Guard {
	return &Guard{Links: links, SystemdDir: systemdDir, NetworkdDir: networkdDir}
}

// CheckInterface is invariant 1: the panel only ever creates, modifies, or
// deletes a tunnel-type interface it manages. A physical interface, a bridge,
// the loopback, or the interface carrying the default route is never a target,
// whatever the request says.
//
// managed reports whether the panel's own records claim this interface —
// either a tunnel row or one explicitly adopted. An interface the panel does
// not claim is refused before its kind is even considered.
func (g *Guard) CheckInterface(ctx context.Context, name string, managed bool) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return violation(CodeProtectedDevice, "interface_name", "No interface was named.", nil)
	}
	if isReservedDevice(trimmed) {
		return violation(CodeProtectedDevice, "interface_name",
			fmt.Sprintf("%q is a device the kernel creates for itself and the panel never touches it.", trimmed),
			map[string]any{"interface_name": trimmed})
	}
	if !managed {
		return violation(CodeNotManaged, "interface_name",
			fmt.Sprintf("The panel does not manage %q, so it will not change it. Adopt it first if it "+
				"is a tunnel that should be managed here.", trimmed),
			map[string]any{"interface_name": trimmed})
	}

	observed, err := g.Links.Get(ctx, trimmed)
	if err != nil {
		// The interface does not exist yet, which is the normal case when
		// creating one. Nothing on the host can be harmed by that.
		return nil
	}

	switch {
	case observed.IsLoopback():
		return protected(trimmed, "the loopback interface")
	case observed.IsBridge():
		return protected(trimmed, "a bridge")
	case observed.IsPhysical():
		return protected(trimmed, "a physical interface")
	case !observed.IsTunnel():
		return violation(CodeProtectedDevice, "interface_name",
			fmt.Sprintf("%q is a %s interface, not a tunnel, and the panel only manages tunnels.",
				trimmed, observed.Kind),
			map[string]any{"interface_name": trimmed, "kind": observed.Kind})
	case observed.MasterIndex != 0:
		return violation(CodeProtectedDevice, "interface_name",
			fmt.Sprintf("%q is enslaved to another device, so something else owns it.", trimmed),
			map[string]any{"interface_name": trimmed, "master_index": observed.MasterIndex})
	}

	// Even a tunnel is off limits if this host's default route goes through it:
	// taking it down would take the machine off the network.
	routes, err := g.Links.Routes(ctx)
	if err == nil && link.DefaultRouteDevices(routes)[trimmed] {
		return violation(CodeProtectedDevice, "interface_name",
			fmt.Sprintf("The default route of this server goes through %q. Changing it would take this "+
				"machine off the network, so the panel refuses.", trimmed),
			map[string]any{"interface_name": trimmed})
	}
	return nil
}

func protected(name, what string) *Violation {
	return violation(CodeProtectedDevice, "interface_name",
		fmt.Sprintf("%q is %s. The panel only ever manages tunnel interfaces it created or adopted.",
			name, what),
		map[string]any{"interface_name": name})
}

func isReservedDevice(name string) bool {
	for _, reserved := range []string{"lo", "gre0", "gretap0", "erspan0", "ip6gre0", "ip6gretap0", "ip6tnl0", "tunl0", "sit0"} {
		if name == reserved {
			return true
		}
	}
	return false
}

// CheckPath is invariant 2: the panel never writes host networking, name
// resolution, or routing configuration, and never writes outside the two
// directories it owns.
func (g *Guard) CheckPath(target string) error {
	cleaned := hostPath(target)
	if !isAbsHostPath(target) {
		return violation(CodeProtectedPath, "path",
			fmt.Sprintf("%q is not an absolute path.", target), map[string]any{"path": target})
	}

	for _, protectedPath := range ProtectedPaths {
		if isUnderHostPath(cleaned, protectedPath) {
			return violation(CodeProtectedPath, "path",
				fmt.Sprintf("%s belongs to this system's own network configuration. The panel manages "+
					"tunnel interfaces and never edits it.", cleaned),
				map[string]any{"path": cleaned})
		}
	}

	for _, allowed := range []string{g.SystemdDir, g.NetworkdDir} {
		if allowed == "" {
			continue
		}
		if isUnderHostPath(cleaned, allowed) {
			return nil
		}
	}
	return violation(CodeProtectedPath, "path",
		fmt.Sprintf("%s is outside the directories the panel writes to.", cleaned),
		map[string]any{"path": cleaned, "systemd_dir": g.SystemdDir, "networkd_dir": g.NetworkdDir})
}

// CheckUnitOwnership is invariant 3: a unit file the panel did not write is
// never deleted or overwritten, unless the tunnel was explicitly adopted with
// takeover, and then only after the original has been backed up.
func (g *Guard) CheckUnitOwnership(path string, takeover bool) error {
	if err := g.CheckPath(path); err != nil {
		return err
	}
	owned, err := persist.IsPanelOwned(path)
	if err != nil {
		return err
	}
	if owned || takeover {
		return nil
	}
	return violation(CodeForeignUnit, "path",
		fmt.Sprintf("%s was not written by the panel, so it belongs to whatever created it. Adopt the "+
			"tunnel with takeover to let the panel manage it; the original is backed up first.", path),
		map[string]any{"path": path})
}

// CheckClientConnection is invariant 4: the panel refuses to delete or
// reconfigure a tunnel that is carrying the request itself, unless the operator
// states explicitly that they accept losing access.
//
// The comparison is the request's source address against the tunnel's own
// subnets, which is what catches an operator who reached the panel through the
// very tunnel they are about to remove.
func CheckClientConnection(clientIP string, addresses []link.Address, acknowledged bool) error {
	if acknowledged {
		return nil
	}
	client, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		// An unparseable source address cannot be shown to be inside the tunnel,
		// and refusing every operation because of it would be worse.
		return nil
	}
	client = client.Unmap()

	for _, addr := range addresses {
		prefix, err := addr.Prefix()
		if err != nil {
			continue
		}
		if !prefix.Masked().Contains(client) {
			continue
		}
		return violation(CodeWouldCutOwnAccess, "i_understand_i_may_lose_access",
			fmt.Sprintf("You are connected to this panel from %s, which is inside this tunnel's subnet "+
				"%s. Carrying out this change would cut the connection you are using. Set "+
				"i_understand_i_may_lose_access to proceed anyway.", client, prefix.Masked()),
			map[string]any{"client_ip": client.String(), "subnet": prefix.Masked().String()})
	}
	return nil
}

// CheckArgv is invariant 6 restated as a check on the command itself. The
// runner accepts an argv slice and has no variant that takes a command string,
// so shell interpretation is structurally impossible; this catches an argv that
// would smuggle a shell back in as the program being run.
func CheckArgv(argv []string) error {
	if len(argv) == 0 {
		return violation(CodeShellInvocation, "argv", "No command was given.", nil)
	}
	program := filepath.Base(strings.TrimSpace(argv[0]))
	for _, shell := range shellPrograms {
		if program == shell {
			return violation(CodeShellInvocation, "argv",
				fmt.Sprintf("The panel does not run %s. Every command it executes is an argv slice with "+
					"no shell involved.", program),
				map[string]any{"argv": argv})
		}
	}
	return nil
}

// AsViolation extracts a refusal from an error, if it is one.
func AsViolation(err error) (*Violation, bool) {
	var v *Violation
	if errors.As(err, &v) {
		return v, true
	}
	return nil, false
}
