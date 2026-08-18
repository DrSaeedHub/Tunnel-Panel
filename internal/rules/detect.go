package rules

import (
	"context"
	"strings"

	"github.com/drs/gre-panel/internal/exec"
)

// Every implementation is checked against the interface at compile time, so a
// method added to Backend cannot be forgotten in one of them.
var (
	_ Backend = (*Nftables)(nil)
	_ Backend = (*Iptables)(nil)
	_ Backend = (*Fake)(nil)
)

// Options selects which backend the panel uses.
type Options struct {
	// The resolved tool paths, or "" for anything not found on this host.
	NftBin              string
	IptablesBin         string
	IptablesRestoreBin  string
	Ip6tablesBin        string
	Ip6tablesRestoreBin string

	// Dir is where rendered rulesets are written.
	Dir string
	// Runner executes the backends' commands.
	Runner exec.Runner
	// DevMode substitutes the fake backend, so the panel can be developed and
	// demonstrated without root and without touching the host.
	DevMode bool
	// ForceIptables routes everything through the iptables fallback even where
	// nft is available. This is the troubleshooting switch, and the way an
	// operator whose host is managed by an iptables-based tool keeps one
	// interface in charge.
	ForceIptables bool
}

// Detection is what Detect concluded, so startup can log it and the
// capabilities endpoint can explain what is in use and why.
type Detection struct {
	Backend Backend
	// Reason states in one sentence why this backend was chosen.
	Reason string
	// NftVersion and IptablesVersion are the version banners the tools printed,
	// empty when the tool is absent or did not answer.
	NftVersion      string
	IptablesVersion string
	// IptablesIsLegacy reports that iptables here speaks to the legacy
	// netfilter backend rather than to nf_tables.
	IptablesIsLegacy bool
	// Binaries are every netfilter tool that was resolved, including the ones
	// belonging to the backend that was not chosen. Reporting all of them is
	// what lets the capabilities endpoint say "iptables is here too, and
	// nftables was preferred" rather than leaving the operator to wonder
	// whether the other one is even installed.
	Binaries map[string]string
}

// Detect chooses the backend for this host (§2.1).
//
// nftables is preferred wherever nft is present: it allows several tables to
// hook the same point, so the panel's table coexists with rules Docker or
// firewalld installed instead of interleaving with them in shared chains.
// iptables is the fallback, and which netfilter backend it speaks to is
// reported rather than assumed, because an iptables-legacy host does not share
// tables with nftables rules at all.
func Detect(ctx context.Context, opts Options) Detection {
	runner := opts.Runner
	if runner == nil {
		runner = exec.NewRunner()
	}

	nft := NewNftables(opts.NftBin, opts.Dir, runner)
	ipt := NewIptables(opts.IptablesBin, opts.IptablesRestoreBin,
		opts.Ip6tablesBin, opts.Ip6tablesRestoreBin, opts.Dir, runner)

	d := Detection{Binaries: map[string]string{}}
	for name, path := range map[string]string{
		"nft":               opts.NftBin,
		"iptables":          opts.IptablesBin,
		"iptables-restore":  opts.IptablesRestoreBin,
		"ip6tables":         opts.Ip6tablesBin,
		"ip6tables-restore": opts.Ip6tablesRestoreBin,
	} {
		if strings.TrimSpace(path) != "" {
			d.Binaries[name] = path
		}
	}
	if opts.NftBin != "" {
		if res, err := runner.Run(ctx, []string{opts.NftBin, "--version"}); err == nil {
			d.NftVersion = strings.TrimSpace(res.Stdout)
			nft.Version = d.NftVersion
		}
	}
	if opts.IptablesBin != "" {
		if res, err := runner.Run(ctx, []string{opts.IptablesBin, "--version"}); err == nil {
			d.IptablesVersion = strings.TrimSpace(res.Stdout)
			ipt.Version = d.IptablesVersion
			d.IptablesIsLegacy = IsLegacyIptables(d.IptablesVersion)
			ipt.Legacy = d.IptablesIsLegacy
		}
	}

	switch {
	case opts.DevMode:
		d.Backend = NewFakeFor(nft)
		d.Reason = "development mode: rules are rendered but never applied to this host"
	case opts.ForceIptables && ipt.Capabilities().Available:
		d.Backend = ipt
		d.Reason = "iptables was selected explicitly, so the panel keeps to the interface the " +
			"rest of this host is managed with"
	case d.NftVersion != "":
		d.Backend = nft
		d.Reason = "nft is available, so the panel owns one nftables table and replaces it " +
			"atomically without touching anything else on this host"
	case ipt.Capabilities().Available:
		d.Backend = ipt
		d.Reason = "nft was not found, so the panel falls back to iptables with its own chains"
	default:
		// Neither tool is here. The unavailable nftables backend is returned
		// rather than a fake: a fake would report success for rules that were
		// never installed, which is the one failure mode this whole project
		// exists to prevent.
		d.Backend = nft
		d.Reason = "neither nft nor iptables was found on this host, so forwarding rules cannot " +
			"be applied here"
	}
	return d
}

// IsLegacyIptables reports whether an iptables version banner names the legacy
// netfilter backend. The banner reads "iptables v1.8.10 (nf_tables)" or
// "iptables v1.8.10 (legacy)".
func IsLegacyIptables(version string) bool {
	return strings.Contains(strings.ToLower(version), "legacy")
}

// BackendTypeName maps a backend to the RuleBackendType lookup title in the
// spelling internal/model stores, or "" for the fake, which is not a backend an
// installation can be running.
func BackendTypeName(name string) string {
	switch name {
	case BackendNftables:
		return "Nftables"
	case BackendIptablesNft:
		return "IptablesNft"
	case BackendIptablesLegacy:
		return "IptablesLegacy"
	}
	return ""
}
