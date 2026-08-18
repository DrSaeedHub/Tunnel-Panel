package link

import (
	"github.com/drs/gre-panel/internal/exec"
)

// Every implementation is checked against the interface at compile time, so a
// method added to LinkManager cannot be forgotten in one of them.
var (
	_ LinkManager = (*Netlink)(nil)
	_ LinkManager = (*IPCommand)(nil)
	_ LinkManager = (*Fake)(nil)
	_ LinkManager = (*Fallback)(nil)
)

// Options selects which implementation the panel uses.
type Options struct {
	// IPBin is the resolved path of the ip binary, or "" when none was found.
	IPBin string
	// Runner executes the fallback path's commands.
	Runner exec.Runner
	// DevMode substitutes the fake manager, so the panel can be developed and
	// demonstrated without root and without touching the host (§5.1).
	DevMode bool
	// ForceIPCommand routes every call through the `ip` fallback. This is the
	// troubleshooting switch of §8.1.
	ForceIPCommand bool
}

// Select builds the link manager for these options.
//
// The normal result is netlink with the `ip` command behind it: netlink serves
// what it can express, and the fallback picks up the IPv6 GRE variants and the
// attributes the library does not carry.
func Select(opts Options) LinkManager {
	if opts.DevMode {
		return NewFakeWithHost()
	}
	primary := NewNetlink()
	if opts.IPBin == "" {
		return primary
	}
	fallback := NewFallback(primary, NewIPCommand(opts.IPBin, opts.Runner))
	fallback.Forced = opts.ForceIPCommand
	return fallback
}

// MergeCapabilities folds several managers' capabilities into the per-type view
// the capabilities endpoint reports, attributing each type to the manager that
// would actually serve it.
func MergeCapabilities(managers ...LinkManager) map[string]TypeSupport {
	out := map[string]TypeSupport{}
	for _, kind := range TunnelKinds() {
		out[kind] = TypeSupport{Supported: false, Manager: "", Note: "no link manager can serve this type"}
	}
	for _, m := range managers {
		if m == nil {
			continue
		}
		caps := m.Capabilities()
		for kind, support := range caps.TunnelTypes {
			if existing, ok := out[kind]; ok && existing.Supported {
				continue
			}
			if support.Supported {
				out[kind] = support
			}
		}
	}
	return out
}
