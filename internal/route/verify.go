package route

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// Verification check names. They are stable so the frontend can render each one
// with its own explanation.
const (
	CheckRulesetReadable = "ruleset_readable"
	CheckRulesPresent    = "rules_present"
	CheckNoStrayRules    = "no_stray_rules"
	CheckNoStaleChains   = "no_stale_chains"
	CheckJumpRules       = "jump_rules"
	CheckForwarding      = "ip_forwarding"
	CheckPersistence     = "persistence_file"
)

// VerifyCheck is the outcome of one verification step.
type VerifyCheck struct {
	Name     string `json:"name"`
	Ok       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
	// Fatal reports whether failing this check fails the apply.
	Fatal bool `json:"fatal"`
	// Skipped marks a check that could not be run at all, which is neither a
	// pass nor a failure and must never be presented as either.
	Skipped bool `json:"skipped,omitempty"`
}

// VerifyReport is everything checked after an apply (§7).
type VerifyReport struct {
	Ok       bool          `json:"ok"`
	Checks   []VerifyCheck `json:"checks"`
	Failures []string      `json:"failures,omitempty"`
	// Backend and RuleCount describe what was read back.
	Backend   string `json:"backend,omitempty"`
	RuleCount int    `json:"rule_count"`
}

// Warnings turns the non-fatal outcomes into response warnings.
func (r VerifyReport) Warnings() []validate.Warning {
	var out []validate.Warning
	for _, check := range r.Checks {
		if check.Fatal || check.Ok || check.Skipped {
			continue
		}
		out = append(out, validate.Warning{
			Code: "VERIFICATION_" + strings.ToUpper(check.Name), Message: check.Detail,
		})
	}
	return out
}

func (r *VerifyReport) add(check VerifyCheck) {
	// A failing check always carries a sentence.
	//
	// The interface renders check.Detail and falls back to check.Name when it is
	// empty, so a check that fails without one puts a bare identifier —
	// `no_stale_chains`, `ip_forwarding` — in front of an operator, untranslated
	// in every language. None of the check names has a locale entry, and none
	// should need one: the name is an API contract for machines, and the
	// explanation is what a person reads. Filling it in here covers every check
	// that exists and every one that gets added later, rather than depending on
	// each author remembering.
	if !check.Ok && !check.Skipped && strings.TrimSpace(check.Detail) == "" {
		switch {
		case check.Expected != "" || check.Actual != "":
			check.Detail = fmt.Sprintf("This check expected %s and found %s.",
				orNone(check.Expected), orNone(check.Actual))
		default:
			check.Detail = "This check did not pass, and the backend gave no further detail."
		}
	}
	r.Checks = append(r.Checks, check)
	if check.Fatal && !check.Ok && !check.Skipped {
		r.Failures = append(r.Failures, check.Detail)
	}
}

func orNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "nothing"
	}
	return value
}

// expectation is one rule the panel intends, and how to recognise it in what
// the kernel reports.
//
// It is expressed as the chain role plus the text that must appear rather than
// as an exact line, because the kernel renders a rule in its own canonical form
// — nftables adds a burst to a rate limit and pads a mark to eight digits, and
// iptables writes its own spelling of every match. Comparing the exact text
// would fail on a ruleset that is precisely right.
type expectation struct {
	routeRuleID int64
	role        string
	contains    []string
	describes   string
}

// expectationsFor lists what a rule must produce in the kernel.
func expectationsFor(spec rules.RouteSpec) []expectation {
	var out []expectation
	protocols := spec.Protocol.Expand()

	for _, d := range spec.Destinations {
		for _, proto := range protocols {
			out = append(out,
				expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RoleForward,
					contains:  []string{d.Address, "accept"},
					describes: fmt.Sprintf("the %s forward permission to %s", proto, d.Address),
				},
				expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RoleAccounting,
					contains:  []string{d.Address},
					describes: fmt.Sprintf("the %s accounting rules for %s", proto, d.Address),
				},
			)
			switch spec.NatMode {
			case rules.NatMasquerade:
				out = append(out, expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RolePostrouting,
					contains:  []string{d.Address, "masquerade"},
					describes: fmt.Sprintf("the masquerade for %s", d.Address),
				})
			case rules.NatSnat:
				out = append(out, expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RolePostrouting,
					contains:  []string{d.Address, "snat"},
					describes: fmt.Sprintf("the source NAT for %s", d.Address),
				})
			}
			if spec.ClampMssToPmtu && proto == rules.ProtocolTCP {
				out = append(out, expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RoleMss,
					contains:  []string{d.Address},
					describes: fmt.Sprintf("the MSS clamp for %s", d.Address),
				})
			}
		}
	}

	for _, proto := range protocols {
		out = append(out, expectation{
			routeRuleID: spec.RouteRuleID, role: rules.RolePrerouting,
			contains:  []string{"dnat"},
			describes: fmt.Sprintf("the %s destination NAT", proto),
		})
		if spec.IncludeLocalOriginated {
			out = append(out, expectation{
				routeRuleID: spec.RouteRuleID, role: rules.RoleOutput,
				contains:  []string{"dnat"},
				describes: fmt.Sprintf("the %s destination NAT for locally-originated traffic", proto),
			}, expectation{
				routeRuleID: spec.RouteRuleID, role: rules.RoleLocalAccounting,
				contains:  []string{"counter"},
				describes: fmt.Sprintf("the %s accounting for locally-originated traffic", proto),
			})
		}
		if spec.FwMark != nil {
			out = append(out, expectation{
				routeRuleID: spec.RouteRuleID, role: rules.RoleMark,
				contains:  []string{"mark"},
				describes: fmt.Sprintf("the %s firewall mark", proto),
			})
		}
	}
	return out
}

// MissingRule is one rule a forwarding rule intends that the kernel does not
// hold.
type MissingRule struct {
	// Role is the chain role it belongs in, which is how the two backends'
	// different chain names are compared.
	Role string `json:"role"`
	// Describes names it the way an operator reads it.
	Describes string `json:"describes"`
}

// MissingRules returns what a forwarding rule intends that the live ruleset
// does not hold.
//
// Verification and reconciliation both call it, so the two can never disagree
// about what "installed" means. The comparison is on the match criteria a rule
// must carry rather than on a rule count, because the two backends render the
// same intent as different numbers of lines and counting would report a ruleset
// that is precisely right as drifted.
func MissingRules(spec rules.RouteSpec, live rules.Live) []MissingRule {
	var out []MissingRule
	for _, want := range expectationsFor(spec) {
		if !satisfied(live, want) {
			out = append(out, MissingRule{Role: want.role, Describes: want.describes})
		}
	}
	return out
}

// ExpectedRuleCount is how many distinct rules a forwarding rule intends, which
// the reconcile report shows beside how many the kernel holds.
func ExpectedRuleCount(spec rules.RouteSpec) int { return len(expectationsFor(spec)) }

// Verify reads the panel's ruleset back from the kernel and confirms it is what
// was asked for (§7).
//
// Nothing here trusts a return code. `nft -f` exits zero for a file it applied
// and for one that changed nothing; the only way to know a rule is installed is
// to ask the kernel for it.
func (s *Service) Verify(ctx context.Context, desired []Record, plan Plan) VerifyReport {
	report := VerifyReport{Backend: s.backend.Name()}
	ruleset := DesiredOf(desired)

	live, err := s.backend.ReadBack(ctx)
	if err != nil {
		report.add(VerifyCheck{
			Name: CheckRulesetReadable, Fatal: true,
			Detail: "the panel's ruleset could not be read back from the kernel: " + err.Error(),
		})
		report.Ok = false
		return report
	}
	report.RuleCount = len(live.Rules)
	report.add(VerifyCheck{
		Name: CheckRulesetReadable, Ok: true, Fatal: true,
		Detail: fmt.Sprintf("read %d rule(s) back from the panel's own %s namespace",
			len(live.Rules), s.backend.Name()),
	})

	// 1. Every rule the panel intends is in the chain it belongs to.
	var missing []string
	for _, spec := range ruleset.Sorted() {
		for _, absent := range MissingRules(spec, live) {
			missing = append(missing, fmt.Sprintf("rule %d (%s): %s",
				spec.RouteRuleID, spec.Title, absent.Describes))
		}
	}
	if len(missing) == 0 {
		report.add(VerifyCheck{
			Name: CheckRulesPresent, Ok: true, Fatal: true,
			Detail: fmt.Sprintf("every rule of the %d enabled forwarding rule(s) is installed",
				len(ruleset.Routes)),
		})
	} else {
		report.add(VerifyCheck{
			Name: CheckRulesPresent, Fatal: true,
			Detail:   "missing from the kernel: " + strings.Join(missing, "; "),
			Expected: fmt.Sprintf("%d rule(s) installed", len(ruleset.Routes)),
			Actual:   fmt.Sprintf("%d missing", len(missing)),
		})
	}

	// 2. Nothing in the panel's own namespace belongs to a rule the panel does
	// not have. That is drift rather than a failed apply, so it is reported and
	// not fatal — reconcile is where an operator decides what to do about it.
	intended := map[int64]bool{}
	for _, spec := range ruleset.Routes {
		intended[spec.RouteRuleID] = true
	}
	var stray []string
	for _, rule := range live.Rules {
		if rule.Structural {
			continue
		}
		if rule.RouteRuleID == 0 {
			stray = append(stray, fmt.Sprintf("an unattributed rule in %s", rule.Chain))
			continue
		}
		if !intended[rule.RouteRuleID] {
			stray = append(stray, fmt.Sprintf("a rule for the forwarding rule %d, which is not enabled",
				rule.RouteRuleID))
		}
	}
	report.add(VerifyCheck{
		Name: CheckNoStrayRules, Ok: len(stray) == 0,
		Detail: strayDetail(stray),
	})

	// 2b. The kernel's chain inventory is the one the ruleset declares.
	//
	// Everything above compares rules, and a rule is only ever seen inside a
	// chain that holds one — so an empty chain is invisible to all of it. That
	// is how two hosts running the same binary came to hold tables of different
	// shapes, one of them still carrying a chain named `mss` from before that
	// name was found to be unparseable on the oldest supported nft. Asking the
	// renderer what it would still remove is the same question the apply asked,
	// put to the kernel after the fact.
	//
	// Not fatal: a leftover chain is empty with an accept policy and changes no
	// packet's fate, and rolling back a ruleset that is otherwise exactly right
	// would do more harm than the thing it is objecting to. It is reported so it
	// cannot go unnoticed the way it did before.
	report.add(s.staleChainCheck(ruleset, live))

	// 3. On the iptables backend, the jump rules are what make the panel's
	// chains reachable at all. A chain full of correct rules that nothing jumps
	// to forwards nothing.
	if len(live.MissingJumps) > 0 {
		report.add(VerifyCheck{
			Name: CheckJumpRules, Fatal: true,
			Detail: "the panel's chains are not reached from: " + strings.Join(live.MissingJumps, ", "),
		})
	} else {
		report.add(VerifyCheck{
			Name: CheckJumpRules, Ok: true, Fatal: true,
			Detail: "every built-in chain jumps into the panel's own",
		})
	}

	// 4. Forwarding, which the rules need to carry anything at all.
	report.add(s.forwardingCheck(ctx, ruleset))

	// 5. The file the boot-time restore reads has to be the one that was
	// applied, or the rules will not come back.
	report.add(persistenceCheck(plan))

	report.Ok = len(report.Failures) == 0
	return report
}

// staleChainCheck asks the renderer whether the inventory the kernel now holds
// still contains chains this ruleset does not declare.
func (s *Service) staleChainCheck(ruleset rules.Ruleset, live rules.Live) VerifyCheck {
	if len(live.Chains) == 0 {
		return VerifyCheck{
			Name: CheckNoStaleChains, Skipped: true,
			Detail: "this backend does not report a chain inventory",
		}
	}
	probe := ruleset
	probe.LiveChains = live.Chains
	payload, err := s.backend.Render(probe)
	if err != nil {
		return VerifyCheck{
			Name: CheckNoStaleChains, Skipped: true,
			Detail: "the chain inventory could not be compared: " + err.Error(),
		}
	}
	if len(payload.RemovesChains) == 0 {
		return VerifyCheck{
			Name: CheckNoStaleChains, Ok: true,
			Detail: fmt.Sprintf("the panel's namespace holds exactly the %d chain(s) this ruleset declares",
				len(live.Chains)),
		}
	}
	return VerifyCheck{
		Name:     CheckNoStaleChains,
		Expected: "no chain the ruleset does not declare",
		Actual:   strings.Join(payload.RemovesChains, ", "),
		Detail: "the panel's namespace still holds " + strings.Join(payload.RemovesChains, ", ") +
			", which this ruleset does not declare. They are empty and accept by policy, so they " +
			"change no packet's fate, but they are hooked into the kernel and the panel no longer " +
			"has a use for them.",
	}
}

func strayDetail(stray []string) string {
	if len(stray) == 0 {
		return "nothing in the panel's namespace is unaccounted for"
	}
	return "the panel's namespace also holds " + strings.Join(stray, "; ") +
		". Nothing was removed: the reconcile report is where that is decided."
}

// satisfied reports whether the live ruleset holds a rule matching one
// expectation.
func satisfied(live rules.Live, want expectation) bool {
	for _, rule := range live.Rules {
		if rule.RouteRuleID != want.routeRuleID || rule.Role != want.role {
			continue
		}
		text := strings.ToLower(rule.Text)
		matched := true
		for _, token := range want.contains {
			if !strings.Contains(text, strings.ToLower(token)) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func (s *Service) forwardingCheck(ctx context.Context, ruleset rules.Ruleset) VerifyCheck {
	if len(ruleset.Routes) == 0 {
		return VerifyCheck{
			Name: CheckForwarding, Ok: true,
			Detail: "no rule is enabled, so forwarding is not needed",
		}
	}
	if s.forwarding == nil {
		return VerifyCheck{
			Name: CheckForwarding, Skipped: true,
			Detail: "the kernel parameters were not checked on this instance",
		}
	}
	status := s.forwarding.Status(ctx, ruleset.HasIPv6(), len(ruleset.Routes), 0)
	switch {
	case !status.IPv4Forwarding:
		return VerifyCheck{
			Name: CheckForwarding, Fatal: true,
			Expected: "1", Actual: "0",
			Detail: "the rules are installed but this kernel is not forwarding packets, so they " +
				"carry nothing",
		}
	case ruleset.HasIPv6() && !status.IPv6Forwarding:
		return VerifyCheck{
			Name: CheckForwarding, Fatal: true,
			Expected: "1", Actual: "0",
			Detail: "an enabled rule forwards IPv6 but this kernel is not forwarding IPv6 packets",
		}
	}
	return VerifyCheck{Name: CheckForwarding, Ok: true, Fatal: true, Detail: "this kernel forwards packets"}
}

// persistenceCheck confirms the rendered ruleset really is on disk and really
// is the one that was applied. Without it the rules work now and vanish at the
// next reboot, which is the zombie state this whole design exists to prevent.
func persistenceCheck(plan Plan) VerifyCheck {
	var files []PlannedFile
	for _, f := range plan.Files {
		if f.Kind == FileRuleset {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return VerifyCheck{
			Name: CheckPersistence, Skipped: true,
			Detail: "this operation rendered no ruleset file",
		}
	}
	for _, f := range files {
		content, err := os.ReadFile(f.Path)
		if err != nil {
			return VerifyCheck{
				Name: CheckPersistence, Fatal: true,
				Expected: f.Path, Actual: "absent",
				Detail: fmt.Sprintf("%s was not written, so the rules would not come back after a "+
					"reboot: %v", f.Path, err),
			}
		}
		if string(content) != f.Content {
			return VerifyCheck{
				Name: CheckPersistence, Fatal: true,
				Expected: fmt.Sprintf("%d bytes", len(f.Content)),
				Actual:   fmt.Sprintf("%d bytes", len(content)),
				Detail: fmt.Sprintf("%s is not the ruleset that was applied, so a reboot would install "+
					"something else", f.Path),
			}
		}
	}
	return VerifyCheck{
		Name: CheckPersistence, Ok: true, Fatal: true,
		Detail: "the boot-time restore file is on disk and is the ruleset that was applied",
	}
}
