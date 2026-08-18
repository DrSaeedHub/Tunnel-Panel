package safety

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/drs/gre-panel/internal/rules"
)

// Violation codes for the forwarding subsystem (§6.3 of the port forwarding
// specification). Like the codes above, they are stable: the frontend explains
// each one differently and the audit log is searched by them.
const (
	// CodeProtectedPort is the refusal that matters most here. Redirecting the
	// port the panel or SSH is reached on takes the operator off the machine,
	// and unlike a tunnel mistake it is not recoverable without console access.
	CodeProtectedPort = "PROTECTED_PORT"
	// CodeForeignNetfilter marks an attempt to touch a table, chain or rule the
	// panel did not create.
	CodeForeignNetfilter = "FOREIGN_NETFILTER_OBJECT"
	// CodeProtectedSysctl marks an attempt to write a kernel parameter, or a
	// file holding one, that belongs to the distribution or another package.
	CodeProtectedSysctl = "PROTECTED_SYSCTL"
)

// PanelSysctlFile is the only sysctl file the panel writes. Everything else
// under /etc/sysctl.d, and /etc/sysctl.conf itself, belongs to the distribution
// or to another package (§6.3.3).
const PanelSysctlFile = "/etc/sysctl.d/99-gre-panel.conf"

// AllowedSysctls are the only kernel parameters the panel ever sets, and it
// sets them because a relay cannot work without them.
//
// route_localnet is deliberately absent. Forwarding to 127.0.0.0/8 needs it,
// and turning it on makes the kernel treat loopback as routable on an
// interface, which exposes every service bound to localhost. The panel refuses
// to do that on an operator's behalf, however the request is phrased (§6.3.4).
var AllowedSysctls = []string{
	"net.ipv4.ip_forward",
	"net.ipv6.conf.all.forwarding",
}

// SocketTable is the kernel socket table as the guard reads it. It is an
// interface so the invariants can be tested against a recorded /proc rather
// than against whatever host runs the suite. *rules.SocketReader satisfies it.
type SocketTable interface {
	Listeners() ([]rules.Listener, error)
	SshPorts() ([]int, error)
}

// RouteGuard enforces the invariants of §6.3 for the forwarding subsystem.
//
// None of them is configurable and none is overridable. There is deliberately
// no force parameter on any method here: a flag that could be passed is a flag
// that will be passed, so the refusal is expressed in the type rather than in a
// convention.
type RouteGuard struct {
	// PanelPort is the port this panel is served on.
	PanelPort int
	// Sockets supplies the live SSH port. When it is nil or unreadable the
	// guard falls back to protecting the conventional port as well, because
	// being wrong in that direction only costs a forwarding rule, while being
	// wrong in the other costs access to the machine.
	Sockets SocketTable
	// RulesDir is where rendered rulesets may be written; nothing outside it
	// and the panel's own sysctl file is writable by this subsystem.
	RulesDir string
	// SysctlFile is the panel's own sysctl file. Empty means the default.
	SysctlFile string
}

// NewRouteGuard returns a guard for the forwarding subsystem.
func NewRouteGuard(panelPort int, sockets SocketTable, rulesDir string) *RouteGuard {
	return &RouteGuard{
		PanelPort:  panelPort,
		Sockets:    sockets,
		RulesDir:   rulesDir,
		SysctlFile: PanelSysctlFile,
	}
}

// ProtectedPort is one port no forwarding rule may claim, and why.
type ProtectedPort struct {
	Port   int    `json:"port"`
	Reason string `json:"reason"`
	// Process names what is listening, when that is known.
	Process string `json:"process,omitempty"`
}

// ProtectedPorts returns every port that may never be forwarded, so the
// frontend can grey them out rather than letting an operator discover the
// refusal by submitting.
//
// The SSH port is read from the running daemon rather than assumed to be 22: an
// installation that moved SSH to 2222 and left something else on 22 would
// otherwise be protected on the wrong port and locked out on the right one.
func (g *RouteGuard) ProtectedPorts(ctx context.Context) []ProtectedPort {
	var out []ProtectedPort
	if g.PanelPort > 0 {
		out = append(out, ProtectedPort{
			Port:   g.PanelPort,
			Reason: "this panel is served on it; forwarding it elsewhere would make the panel unreachable",
		})
	}

	ports, err := g.sshPorts()
	for _, port := range ports {
		out = append(out, ProtectedPort{
			Port:    port,
			Reason:  "the SSH daemon is listening on it; forwarding it elsewhere would lock this machine",
			Process: "sshd",
		})
	}
	if err != nil || len(ports) == 0 {
		// Nothing could be read, so the conventional port is protected as well.
		// This is the deliberately conservative direction.
		out = append(out, ProtectedPort{
			Port: DefaultSshPort,
			Reason: "the running SSH daemon could not be identified, so the conventional SSH port is " +
				"protected as a precaution",
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return dedupePorts(out)
}

// DefaultSshPort is the conventional port, used only as the fallback when the
// running daemon cannot be identified.
const DefaultSshPort = 22

func dedupePorts(ports []ProtectedPort) []ProtectedPort {
	seen := map[int]bool{}
	out := ports[:0]
	for _, p := range ports {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		out = append(out, p)
	}
	return append([]ProtectedPort(nil), out...)
}

func (g *RouteGuard) sshPorts() ([]int, error) {
	if g.Sockets == nil {
		return nil, fmt.Errorf("no socket table is available")
	}
	return g.Sockets.SshPorts()
}

// CheckRoute is invariant 1: a rule may never redirect the port the panel is
// served on, nor the port the running SSH daemon is listening on.
//
// The check is on the whole bind range, because a rule forwarding 8000-9000
// takes the panel's port with it just as surely as one naming it. It applies
// whatever address the rule binds: a rule on one address still takes the port
// from a daemon listening on every address, which is what sshd normally does.
func (g *RouteGuard) CheckRoute(ctx context.Context, spec rules.RouteSpec) error {
	// Only TCP can carry SSH or the panel, so a UDP-only rule cannot take
	// either. Stating the reason rather than refusing everything keeps a
	// legitimate UDP relay on port 22 possible.
	if spec.Protocol == rules.ProtocolUDP {
		return nil
	}

	for _, protected := range g.ProtectedPorts(ctx) {
		if !coversPort(spec.BindPorts, protected.Port) {
			continue
		}
		return violation(CodeProtectedPort, "bind_port",
			fmt.Sprintf("This rule would redirect port %d, and %s. The panel will not do that under "+
				"any setting or flag: unlike a tunnel mistake, it is not recoverable without console "+
				"access to this server.", protected.Port, protected.Reason),
			map[string]any{
				"port": protected.Port, "reason": protected.Reason,
				"bind_ports": spec.BindPorts.String(), "process": protected.Process,
			})
	}
	return nil
}

// CheckRuleset applies CheckRoute to every rule of a ruleset, which is what the
// service calls immediately before an apply — after planning, so that no code
// path can reach the kernel without passing through it.
func (g *RouteGuard) CheckRuleset(ctx context.Context, rs rules.Ruleset) error {
	for _, route := range rs.Sorted() {
		if err := g.CheckRoute(ctx, route); err != nil {
			return err
		}
	}
	return nil
}

// coversPort reports whether a bind range includes a port.
func coversPort(r rules.PortRange, port int) bool {
	if r.IsRange() {
		return port >= r.Port && port <= r.End
	}
	return port == r.Port
}

// CheckNetfilterObject is invariant 2: the panel never flushes, reorders or
// deletes a table, chain or rule it did not create. Its own namespace is one
// nftables table and a fixed set of iptables chains, and nothing else is a
// legitimate target.
//
// The single exception is the jump rule the iptables backend adds to a built-in
// chain, which is an addition rather than a modification of anything already
// there, and which is checked before it is installed so it can never duplicate.
func (g *RouteGuard) CheckNetfilterObject(kind, name string) error {
	trimmed := strings.TrimSpace(name)
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "table":
		if trimmed == rules.TableName {
			return nil
		}
	case "chain":
		if rules.IsPanelChain(trimmed) {
			return nil
		}
	default:
		// A kind the panel has no namespace for cannot be one of its own, so
		// the answer is the same refusal rather than a different question.
		return violation(CodeForeignNetfilter, "object",
			fmt.Sprintf("The panel manages netfilter tables and chains of its own and nothing else, so "+
				"it will not touch the %s %q.", kind, trimmed),
			map[string]any{"kind": kind, "name": trimmed})
	}
	return violation(CodeForeignNetfilter, "object",
		fmt.Sprintf("The %s %q was not created by the panel, so the panel will not touch it. It only "+
			"ever rebuilds its own table %q and its own chains.", kind, trimmed, rules.TableName),
		map[string]any{
			"kind": kind, "name": trimmed,
			"owned_table":  rules.TableName,
			"owned_chains": rules.OwnedChains(),
		})
}

// CheckSysctl is invariants 3 and 4 as a check on the parameter itself: the
// panel sets forwarding and nothing else, and it never enables route_localnet.
func (g *RouteGuard) CheckSysctl(key string) error {
	trimmed := strings.TrimSpace(key)
	for _, allowed := range AllowedSysctls {
		if trimmed == allowed {
			return nil
		}
	}
	if strings.Contains(trimmed, "route_localnet") {
		return violation(CodeProtectedSysctl, "sysctl",
			"The panel never enables route_localnet. It makes the kernel treat 127.0.0.0/8 as routable "+
				"on an interface, which exposes every service bound to localhost on this server, and "+
				"that is a decision for the operator to make deliberately and by hand.",
			map[string]any{"sysctl": trimmed})
	}
	return violation(CodeProtectedSysctl, "sysctl",
		fmt.Sprintf("The panel does not set %s. It sets only what a relay cannot work without: %s.",
			trimmed, strings.Join(AllowedSysctls, " and ")),
		map[string]any{"sysctl": trimmed, "allowed": AllowedSysctls})
}

// CheckPath is invariant 3 as a check on the file: the panel writes its own
// rendered rulesets and its own sysctl file, and nothing else.
//
// /etc/iptables is named explicitly because that is where the distribution's
// firewall persistence package keeps its whole-system snapshots, and writing
// there is how the tool this subsystem replaces corrupts the state of a machine
// running Docker.
func (g *RouteGuard) CheckPath(target string) error {
	cleaned := hostPath(target)
	if !isAbsHostPath(target) {
		return violation(CodeProtectedPath, "path",
			fmt.Sprintf("%q is not an absolute path.", target), map[string]any{"path": target})
	}
	if cleaned == hostPath(g.sysctlFile()) {
		return nil
	}
	for _, protectedPath := range ProtectedPaths {
		if isUnderHostPath(cleaned, protectedPath) {
			return violation(CodeProtectedPath, "path",
				fmt.Sprintf("%s belongs to this system's own configuration, not to the panel.", cleaned),
				map[string]any{"path": cleaned})
		}
	}
	if g.RulesDir != "" && isUnderHostPath(cleaned, g.RulesDir) {
		return nil
	}
	return violation(CodeProtectedPath, "path",
		fmt.Sprintf("%s is outside the directories the forwarding subsystem writes to.", cleaned),
		map[string]any{"path": cleaned, "rules_dir": g.RulesDir, "sysctl_file": g.sysctlFile()})
}

func (g *RouteGuard) sysctlFile() string {
	if strings.TrimSpace(g.SysctlFile) == "" {
		return PanelSysctlFile
	}
	return filepath.Clean(g.SysctlFile)
}
