// Package link is the system interaction layer for network interfaces (§8.1).
//
// The full LinkManager — the netlink implementation and the `ip` command
// fallback — lands with the tunnel lifecycle. What is here now is the
// capability probing the health and capabilities endpoints report, which is
// deliberately read-only: it opens a netlink socket and reads /proc and /sys,
// and never changes anything.
package link

import (
	"bufio"
	"os"
	"strings"
)

// GreModule is the kernel module that provides IPv4 GRE. It autoloads on the
// first tunnel creation, so it not being loaded is normal on a fresh server and
// is not a fault.
const GreModule = "ip_gre"

// Ip6GreModule provides the IPv6 GRE variants.
const Ip6GreModule = "ip6_gre"

// Availability describes what the running kernel and this build can do.
type Availability struct {
	// NetlinkAvailable reports whether a netlink route socket could be opened.
	NetlinkAvailable bool `json:"netlink_available"`
	// NetlinkError explains why it could not, when it could not.
	NetlinkError string `json:"netlink_error,omitempty"`
	// LoadedModules lists which of the tunnel modules are currently loaded.
	LoadedModules map[string]bool `json:"loaded_modules"`
	// KernelRelease is the running kernel version.
	KernelRelease string `json:"kernel_release,omitempty"`
}

// Probe collects the current availability. It is cheap enough to call per
// request, but callers that poll should cache it.
func Probe() Availability {
	a := Availability{
		LoadedModules: map[string]bool{
			GreModule:    ModuleLoaded(GreModule),
			Ip6GreModule: ModuleLoaded(Ip6GreModule),
		},
		KernelRelease: KernelRelease(),
	}
	if err := probeNetlink(); err != nil {
		a.NetlinkError = err.Error()
	} else {
		a.NetlinkAvailable = true
	}
	return a
}

// ModuleLoaded reports whether a kernel module is loaded, checking /sys first
// because it is a single stat, and falling back to /proc/modules for kernels
// that do not expose /sys/module.
func ModuleLoaded(name string) bool {
	if _, err := os.Stat("/sys/module/" + name); err == nil {
		return true
	}
	f, err := os.Open("/proc/modules")
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		field, _, _ := strings.Cut(scanner.Text(), " ")
		if field == name {
			return true
		}
	}
	return false
}

// KernelRelease returns the running kernel version, or "" when it cannot be
// read. It comes from /proc/sys/kernel/osrelease rather than from uname(2) so
// the same code works without a syscall wrapper on every platform.
func KernelRelease() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}
