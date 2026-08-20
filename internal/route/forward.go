package route

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/validate"
)

// The kernel parameters a relay cannot work without, and the two files the
// conntrack figures come from.
const (
	SysctlIPv4Forward = "net.ipv4.ip_forward"
	SysctlIPv6Forward = "net.ipv6.conf.all.forwarding"
	// SysctlConntrackAcct makes the kernel count bytes and packets on every
	// tracked connection. It is off by default, and without it a relay can
	// report thousands of connections and not one byte on any of them.
	SysctlConntrackAcct = "net.netfilter.nf_conntrack_acct"

	procIPv4Forward   = "proc/sys/net/ipv4/ip_forward"
	procIPv6Forward   = "proc/sys/net/ipv6/conf/all/forwarding"
	procConntrackMax  = "proc/sys/net/netfilter/nf_conntrack_max"
	procConntrackAcct = "proc/sys/net/netfilter/nf_conntrack_acct"
	procConntrackUsed = "proc/sys/net/netfilter/nf_conntrack_count"
)

// LowConntrackMax is the table size at or below which a busy relay is at
// risk. The
// kernel sizes the table from the machine's memory, which has nothing to do
// with how many connections a relay carries, so a small VPS routinely ships
// with a limit a single busy service can exhaust — and when it does, new
// connections are dropped with nothing in the logs to explain it.
const LowConntrackMax = 65536

// Forwarding owns the kernel parameters and the panel's own sysctl file
// (§2.3).
//
// The panel turns forwarding on, records what it was before, and never turns it
// off by itself: other software on the host may have come to depend on it, and
// silently taking it away would break that software in a way nobody would think
// to attribute to a tunnel panel.
type Forwarding struct {
	// Root is "/" in production and a fixture directory in tests, which is what
	// makes this testable without root and without touching the machine.
	Root string
	// SysctlPath is the panel's own sysctl file.
	SysctlPath string
	Store      *persist.Store
	Renderer   *persist.Renderer
	Guard      *safety.RouteGuard
	Log        *slog.Logger
}

// NewForwarding returns a forwarding manager rooted at the real filesystem.
func NewForwarding(store *persist.Store, renderer *persist.Renderer, guard *safety.RouteGuard) *Forwarding {
	return &Forwarding{Root: "/", SysctlPath: persist.SysctlPath, Store: store, Renderer: renderer, Guard: guard, Log: slog.Default()}
}

func (f *Forwarding) path(parts ...string) string {
	root := f.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func (f *Forwarding) sysctlFile() string {
	if strings.TrimSpace(f.SysctlPath) == "" {
		return persist.SysctlPath
	}
	return f.SysctlPath
}

// Status is the whole forwarding picture, which GET /system/forwarding returns.
type ForwardingStatus struct {
	IPv4Forwarding bool `json:"ipv4_forwarding"`
	IPv6Forwarding bool `json:"ipv6_forwarding"`
	// PanelManaged reports that the panel's own sysctl file is in place, which
	// is how it knows it was the one that turned forwarding on.
	PanelManaged bool `json:"panel_managed"`
	// ByteAccounting reports whether the kernel counts bytes on every tracked
	// connection. Off by default, and the reason a busy relay can report
	// thousands of connections and no traffic on any one of them.
	ByteAccounting bool   `json:"byte_accounting"`
	SysctlPath     string `json:"sysctl_path"`
	// PreviousValues are what the parameters held before the panel changed
	// them, which is what makes the revert offer concrete.
	PreviousValues map[string]string `json:"previous_values,omitempty"`
	CanRevert      bool              `json:"can_revert"`

	ConntrackCount        int     `json:"conntrack_count"`
	ConntrackMax          int     `json:"conntrack_max"`
	ConntrackUsagePercent float64 `json:"conntrack_usage_percent"`

	// Backend and Namespace name what is carrying the rules, so this one
	// endpoint answers "is forwarding working on this host".
	Backend   string `json:"backend,omitempty"`
	Namespace string `json:"namespace,omitempty"`

	Warnings []validate.Warning `json:"warnings,omitempty"`
}

// Warning codes this subsystem adds.
const (
	WarnForwardingDisabled = "IP_FORWARDING_DISABLED"
	WarnConntrackUsage     = "CONNTRACK_TABLE_FILLING"
	WarnConntrackMaxLow    = "CONNTRACK_MAX_LOW"
)

// Status reads the live state. needIPv6 says whether any enabled rule works in
// IPv6, and enabledRules how many rules are enabled at all, because both change
// what is worth warning about.
func (f *Forwarding) Status(ctx context.Context, needIPv6 bool, enabledRules int, warnPercent float64) ForwardingStatus {
	status := ForwardingStatus{
		IPv4Forwarding: f.readFlag(procIPv4Forward),
		IPv6Forwarding: f.readFlag(procIPv6Forward),
		SysctlPath:     f.sysctlFile(),
	}

	if content, err := os.ReadFile(f.sysctlFile()); err == nil {
		owned := strings.Contains(string(content), persist.OwnershipMarker)
		status.PanelManaged = owned
		if owned {
			status.PreviousValues = persist.ParsePreviousValues(string(content))
			status.CanRevert = len(status.PreviousValues) > 0
		}
	}

	status.ByteAccounting = f.ByteAccounting()
	status.ConntrackMax = f.readNumber(procConntrackMax)
	status.ConntrackCount = f.readNumber(procConntrackUsed)
	if status.ConntrackMax > 0 {
		status.ConntrackUsagePercent = float64(status.ConntrackCount) / float64(status.ConntrackMax) * 100
	}

	if enabledRules > 0 && !status.IPv4Forwarding {
		status.Warnings = append(status.Warnings, validate.Warning{
			Code: WarnForwardingDisabled, Field: SysctlIPv4Forward,
			Message: fmt.Sprintf("%d forwarding rule(s) are enabled but this kernel is not forwarding "+
				"packets, so none of them can carry traffic. The rules are installed and doing nothing.",
				enabledRules),
		})
	}
	if needIPv6 && !status.IPv6Forwarding {
		status.Warnings = append(status.Warnings, validate.Warning{
			Code: WarnForwardingDisabled, Field: SysctlIPv6Forward,
			Message: "An enabled rule forwards IPv6, but this kernel is not forwarding IPv6 packets.",
		})
	}
	if warnPercent > 0 && status.ConntrackMax > 0 && status.ConntrackUsagePercent >= warnPercent {
		status.Warnings = append(status.Warnings, validate.Warning{
			Code: WarnConntrackUsage,
			Message: fmt.Sprintf("The connection tracking table is %.0f%% full (%d of %d). When it "+
				"fills, new connections are dropped and nothing in the logs explains it.",
				status.ConntrackUsagePercent, status.ConntrackCount, status.ConntrackMax),
		})
	}
	// At or below, not below. 65536 is the stock default on the machines this
	// panel runs on, and a strict comparison meant the one value most likely
	// to be too small was the one value that never warned.
	if enabledRules > 0 && status.ConntrackMax > 0 && status.ConntrackMax <= LowConntrackMax {
		status.Warnings = append(status.Warnings, validate.Warning{
			Code: WarnConntrackMaxLow,
			Message: fmt.Sprintf("The connection tracking table holds %d connections. The kernel sizes "+
				"it from this machine's memory, which has nothing to do with how many connections a "+
				"relay carries; a busy one can exhaust it. Raise net.netfilter.nf_conntrack_max if this "+
				"relay is expected to be busy.", status.ConntrackMax),
		})
	}
	return status
}

// ByteAccounting reports whether the kernel counts bytes and packets per
// tracked connection.
//
// It is off by default on most kernels, and the symptom is specific: every
// connection is tracked and every one of them reads zero bytes. Attributing
// volume to a destination is impossible without it, so the panel says the
// counting is off rather than reporting that nothing moved.
func (f *Forwarding) ByteAccounting() bool { return f.readFlag(procConntrackAcct) }

// Enable turns forwarding on and persists it to the panel's own file.
//
// It is safe to call when forwarding is already on: the file is rewritten with
// the same content, and nothing else changes. What it records is what the
// parameter held the first time the panel changed it, so the revert offer keeps
// pointing at the operator's original value rather than at the panel's own.
func (f *Forwarding) Enable(ctx context.Context, needIPv6, countBytes bool) error {
	values := []persist.SysctlValue{
		{Key: SysctlIPv4Forward, Value: "1", Previous: f.previousFor(SysctlIPv4Forward, procIPv4Forward)},
	}
	if needIPv6 {
		values = append(values, persist.SysctlValue{
			Key: SysctlIPv6Forward, Value: "1", Previous: f.previousFor(SysctlIPv6Forward, procIPv6Forward),
		})
	}
	if countBytes {
		values = append(values, persist.SysctlValue{
			Key:      SysctlConntrackAcct,
			Value:    "1",
			Previous: f.previousFor(SysctlConntrackAcct, procConntrackAcct),
		})
	}

	for _, v := range values {
		if f.Guard != nil {
			if err := f.Guard.CheckSysctl(v.Key); err != nil {
				return err
			}
		}
	}

	path := f.sysctlFile()
	if f.Guard != nil {
		if err := f.Guard.CheckPath(path); err != nil {
			return err
		}
	}
	if f.Store != nil && f.Renderer != nil {
		if _, err := f.Store.Write(ctx, path, f.Renderer.SysctlFile(values), false); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	// The file makes it survive a reboot; this makes it true now. Writing the
	// /proc file is exactly what sysctl -w does, without spawning a process.
	if err := f.writeFlag(procIPv4Forward, "1"); err != nil {
		return err
	}
	if needIPv6 {
		if err := f.writeFlag(procIPv6Forward, "1"); err != nil {
			return err
		}
	}
	// The counting applies to connections opened after it, so an operator who
	// turns it on watches the figures fill in as the table turns over. A
	// kernel too old to have the parameter is not a failure to apply rules.
	if countBytes {
		if err := f.writeFlag(procConntrackAcct, "1"); err != nil {
			f.logSkipped(err)
		}
	}
	return nil
}

// logSkipped notes a kernel parameter that could not be written but is not
// worth failing an apply over.
func (f *Forwarding) logSkipped(err error) {
	if f.Log != nil {
		f.Log.Warn("a kernel parameter could not be set", "error", err)
	}
}

// Revert puts the parameters back to what they were before the panel changed
// them, and removes the panel's file.
//
// It is only ever called because an operator asked for it. The panel offers
// this when the last rule is deleted and never performs it by itself (§2.3).
func (f *Forwarding) Revert(ctx context.Context) error {
	path := f.sysctlFile()
	if f.Guard != nil {
		if err := f.Guard.CheckPath(path); err != nil {
			return err
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if !strings.Contains(string(content), persist.OwnershipMarker) {
		return fmt.Errorf("%s was not written by the panel, so the panel will not remove it", path)
	}

	for key, previous := range persist.ParsePreviousValues(string(content)) {
		procPath := procPathFor(key)
		if procPath == "" {
			continue
		}
		if err := f.writeFlag(procPath, previous); err != nil {
			return err
		}
	}
	if f.Store != nil {
		if _, err := f.Store.Remove(ctx, path, false); err != nil {
			return err
		}
	}
	return nil
}

// previousFor returns the value to record as "what it was before", which is the
// value already recorded if the panel has been here before, and the live value
// otherwise. Recording the live value on every call would eventually record the
// panel's own 1 and make the revert offer meaningless.
func (f *Forwarding) previousFor(key, procPath string) string {
	if content, err := os.ReadFile(f.sysctlFile()); err == nil {
		if recorded, ok := persist.ParsePreviousValues(string(content))[key]; ok {
			return recorded
		}
	}
	if f.readFlag(procPath) {
		return "" // it was already on, so the panel changed nothing to put back
	}
	return "0"
}

func procPathFor(key string) string {
	switch key {
	case SysctlIPv4Forward:
		return procIPv4Forward
	case SysctlIPv6Forward:
		return procIPv6Forward
	case SysctlConntrackAcct:
		return procConntrackAcct
	}
	return ""
}

func (f *Forwarding) readFlag(procPath string) bool {
	return f.readNumber(procPath) > 0
}

func (f *Forwarding) readNumber(procPath string) int {
	raw, err := os.ReadFile(f.path(procPath))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return 0
	}
	return n
}

func (f *Forwarding) writeFlag(procPath, value string) error {
	full := f.path(procPath)
	if err := os.WriteFile(full, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("setting %s: %w", full, err)
	}
	return nil
}
