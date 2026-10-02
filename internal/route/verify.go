package route

import (
	"context"
	"os"
	"strings"

	"github.com/drs/gre-panel/internal/i18n"
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

func (r *VerifyReport) add(ctx context.Context, check VerifyCheck) {
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
			check.Detail = expectedAndFound(ctx, check.Expected, check.Actual)
		default:
			check.Detail = i18n.T(ctx, "This check did not pass, and the backend gave no further detail.")
		}
	}
	r.Checks = append(r.Checks, check)
	if check.Fatal && !check.Ok && !check.Skipped {
		r.Failures = append(r.Failures, check.Detail)
	}
}

// expectedAndFound is the sentence for a check that failed with only its
// expected and actual values to go on. A blank value reads as "nothing", and
// each combination is its own sentence so it can be said in any language.
func expectedAndFound(ctx context.Context, expected, actual string) string {
	hasExpected := strings.TrimSpace(expected) != ""
	hasActual := strings.TrimSpace(actual) != ""
	switch {
	case hasExpected && hasActual:
		return i18n.T(ctx, "This check expected %s and found %s.", expected, actual)
	case hasExpected:
		return i18n.T(ctx, "This check expected %s and found nothing.", expected)
	case hasActual:
		return i18n.T(ctx, "This check expected nothing and found %s.", actual)
	}
	return i18n.T(ctx, "This check expected nothing and found nothing.")
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

// expectationsFor lists what a rule must produce in the kernel, each described
// in the language ctx carries.
func expectationsFor(ctx context.Context, spec rules.RouteSpec) []expectation {
	var out []expectation
	protocols := spec.Protocol.Expand()

	for _, d := range spec.Destinations {
		for _, proto := range protocols {
			out = append(out,
				expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RoleForward,
					contains:  []string{d.Address, "accept"},
					describes: i18n.T(ctx, "the %s forward permission to %s", string(proto), d.Address),
				},
				expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RoleAccounting,
					contains:  []string{d.Address},
					describes: i18n.T(ctx, "the %s accounting rules for %s", string(proto), d.Address),
				},
			)
			switch spec.NatMode {
			case rules.NatMasquerade:
				out = append(out, expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RolePostrouting,
					contains:  []string{d.Address, "masquerade"},
					describes: i18n.T(ctx, "the masquerade for %s", d.Address),
				})
			case rules.NatSnat:
				out = append(out, expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RolePostrouting,
					contains:  []string{d.Address, "snat"},
					describes: i18n.T(ctx, "the source NAT for %s", d.Address),
				})
			}
			if spec.ClampMssToPmtu && proto == rules.ProtocolTCP {
				out = append(out, expectation{
					routeRuleID: spec.RouteRuleID, role: rules.RoleMss,
					contains:  []string{d.Address},
					describes: i18n.T(ctx, "the MSS clamp for %s", d.Address),
				})
			}
		}
	}

	for _, proto := range protocols {
		out = append(out, expectation{
			routeRuleID: spec.RouteRuleID, role: rules.RolePrerouting,
			contains:  []string{"dnat"},
			describes: i18n.T(ctx, "the %s destination NAT", string(proto)),
		})
		if spec.IncludeLocalOriginated {
			out = append(out, expectation{
				routeRuleID: spec.RouteRuleID, role: rules.RoleOutput,
				contains:  []string{"dnat"},
				describes: i18n.T(ctx, "the %s destination NAT for locally-originated traffic", string(proto)),
			}, expectation{
				routeRuleID: spec.RouteRuleID, role: rules.RoleLocalAccounting,
				contains:  []string{"counter"},
				describes: i18n.T(ctx, "the %s accounting for locally-originated traffic", string(proto)),
			})
		}
		if spec.FwMark != nil {
			out = append(out, expectation{
				routeRuleID: spec.RouteRuleID, role: rules.RoleMark,
				contains:  []string{"mark"},
				describes: i18n.T(ctx, "the %s firewall mark", string(proto)),
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
//
// Describes is said in the panel's language; MissingRulesIn says it in a
// request's.
func MissingRules(spec rules.RouteSpec, live rules.Live) []MissingRule {
	return MissingRulesIn(context.Background(), spec, live)
}

// MissingRulesIn is MissingRules with each Describes said in the language ctx
// carries.
func MissingRulesIn(ctx context.Context, spec rules.RouteSpec, live rules.Live) []MissingRule {
	var out []MissingRule
	for _, want := range expectationsFor(ctx, spec) {
		if !satisfied(live, want) {
			out = append(out, MissingRule{Role: want.role, Describes: want.describes})
		}
	}
	return out
}

// ExpectedRuleCount is how many distinct rules a forwarding rule intends, which
// the reconcile report shows beside how many the kernel holds.
func ExpectedRuleCount(spec rules.RouteSpec) int {
	return len(expectationsFor(context.Background(), spec))
}

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
		report.add(ctx, VerifyCheck{
			Name: CheckRulesetReadable, Fatal: true,
			Detail: i18n.T(ctx, "the panel's ruleset could not be read back from the kernel: %s",
				err.Error()),
		})
		report.Ok = false
		return report
	}
	report.RuleCount = len(live.Rules)
	report.add(ctx, VerifyCheck{
		Name: CheckRulesetReadable, Ok: true, Fatal: true,
		Detail: i18n.T(ctx, "read %d rule(s) back from the panel's own %s namespace",
			len(live.Rules), s.backend.Name()),
	})

	// 1. Every rule the panel intends is in the chain it belongs to.
	var missing []string
	for _, spec := range ruleset.Sorted() {
		for _, absent := range MissingRulesIn(ctx, spec, live) {
			missing = append(missing, i18n.T(ctx, "rule %d (%s): %s",
				spec.RouteRuleID, spec.Title, absent.Describes))
		}
	}
	if len(missing) == 0 {
		report.add(ctx, VerifyCheck{
			Name: CheckRulesPresent, Ok: true, Fatal: true,
			Detail: i18n.T(ctx, "every rule of the %d enabled forwarding rule(s) is installed",
				len(ruleset.Routes)),
		})
	} else {
		report.add(ctx, VerifyCheck{
			Name: CheckRulesPresent, Fatal: true,
			Detail:   i18n.T(ctx, "missing from the kernel: %s", strings.Join(missing, "; ")),
			Expected: i18n.T(ctx, "%d rule(s) installed", len(ruleset.Routes)),
			Actual:   i18n.T(ctx, "%d missing", len(missing)),
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
			stray = append(stray, i18n.T(ctx, "an unattributed rule in %s", rule.Chain))
			continue
		}
		if !intended[rule.RouteRuleID] {
			stray = append(stray, i18n.T(ctx, "a rule for the forwarding rule %d, which is not enabled",
				rule.RouteRuleID))
		}
	}
	report.add(ctx, VerifyCheck{
		Name: CheckNoStrayRules, Ok: len(stray) == 0,
		Detail: strayDetail(ctx, stray),
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
	report.add(ctx, s.staleChainCheck(ctx, ruleset, live))

	// 3. On the iptables backend, the jump rules are what make the panel's
	// chains reachable at all. A chain full of correct rules that nothing jumps
	// to forwards nothing.
	if len(live.MissingJumps) > 0 {
		report.add(ctx, VerifyCheck{
			Name: CheckJumpRules, Fatal: true,
			Detail: i18n.T(ctx, "the panel's chains are not reached from: %s",
				strings.Join(live.MissingJumps, ", ")),
		})
	} else {
		report.add(ctx, VerifyCheck{
			Name: CheckJumpRules, Ok: true, Fatal: true,
			Detail: i18n.T(ctx, "every built-in chain jumps into the panel's own"),
		})
	}

	// 4. Forwarding, which the rules need to carry anything at all.
	report.add(ctx, s.forwardingCheck(ctx, ruleset))

	// 5. The file the boot-time restore reads has to be the one that was
	// applied, or the rules will not come back.
	report.add(ctx, persistenceCheck(ctx, plan))

	report.Ok = len(report.Failures) == 0
	return report
}

// staleChainCheck asks the renderer whether the inventory the kernel now holds
// still contains chains this ruleset does not declare.
func (s *Service) staleChainCheck(ctx context.Context, ruleset rules.Ruleset, live rules.Live) VerifyCheck {
	if len(live.Chains) == 0 {
		return VerifyCheck{
			Name: CheckNoStaleChains, Skipped: true,
			Detail: i18n.T(ctx, "this backend does not report a chain inventory"),
		}
	}
	probe := ruleset
	probe.LiveChains = live.Chains
	payload, err := s.backend.Render(probe)
	if err != nil {
		return VerifyCheck{
			Name: CheckNoStaleChains, Skipped: true,
			Detail: i18n.T(ctx, "the chain inventory could not be compared: %s", err.Error()),
		}
	}
	if len(payload.RemovesChains) == 0 {
		return VerifyCheck{
			Name: CheckNoStaleChains, Ok: true,
			Detail: i18n.T(ctx, "the panel's namespace holds exactly the %d chain(s) this ruleset declares",
				len(live.Chains)),
		}
	}
	return VerifyCheck{
		Name:     CheckNoStaleChains,
		Expected: i18n.T(ctx, "no chain the ruleset does not declare"),
		Actual:   strings.Join(payload.RemovesChains, ", "),
		Detail: i18n.T(ctx, "the panel's namespace still holds %s, which this ruleset does not "+
			"declare. They are empty and accept by policy, so they change no packet's fate, but they "+
			"are hooked into the kernel and the panel no longer has a use for them.",
			strings.Join(payload.RemovesChains, ", ")),
	}
}

func strayDetail(ctx context.Context, stray []string) string {
	if len(stray) == 0 {
		return i18n.T(ctx, "nothing in the panel's namespace is unaccounted for")
	}
	return i18n.T(ctx, "the panel's namespace also holds %s. Nothing was removed: the reconcile "+
		"report is where that is decided.", strings.Join(stray, "; "))
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
			Detail: i18n.T(ctx, "no rule is enabled, so forwarding is not needed"),
		}
	}
	if s.forwarding == nil {
		return VerifyCheck{
			Name: CheckForwarding, Skipped: true,
			Detail: i18n.T(ctx, "the kernel parameters were not checked on this instance"),
		}
	}
	// Forwarding off after an apply is a failure only when the apply was meant
	// to turn it on. With routes.auto_enable_ip_forward off the operator has
	// said they manage it, the plan carried no step for it, and the rules are
	// meant to go in and wait: failing the apply over it rolled back every rule
	// the setting exists to let them install, while the setting, the log line
	// and the preview all said the rules would be installed.
	fatal := s.autoEnablesForwarding()
	status := s.forwarding.Status(ctx, ruleset.HasIPv6(), len(ruleset.Routes), 0)
	switch {
	case !status.IPv4Forwarding:
		detail := i18n.T(ctx, "the rules are installed but this kernel is not forwarding packets, so "+
			"they carry nothing")
		if !fatal {
			detail = i18n.T(ctx, "the rules are installed and carry nothing until IP forwarding is "+
				"turned on: it is off, and the panel is set not to turn it on")
		}
		return VerifyCheck{
			Name: CheckForwarding, Fatal: fatal,
			Expected: "1", Actual: "0",
			Detail: detail,
		}
	case ruleset.HasIPv6() && !status.IPv6Forwarding:
		detail := i18n.T(ctx, "an enabled rule forwards IPv6 but this kernel is not forwarding IPv6 packets")
		if !fatal {
			detail = i18n.T(ctx, "the IPv6 rules are installed and carry nothing until IPv6 forwarding "+
				"is turned on: it is off, and the panel is set not to turn it on")
		}
		return VerifyCheck{
			Name: CheckForwarding, Fatal: fatal,
			Expected: "1", Actual: "0",
			Detail: detail,
		}
	}
	return VerifyCheck{
		Name: CheckForwarding, Ok: true, Fatal: fatal,
		Detail: i18n.T(ctx, "this kernel forwards packets"),
	}
}

// persistenceCheck confirms the rendered ruleset really is on disk and really
// is the one that was applied. Without it the rules work now and vanish at the
// next reboot, which is the zombie state this whole design exists to prevent.
func persistenceCheck(ctx context.Context, plan Plan) VerifyCheck {
	var files []PlannedFile
	for _, f := range plan.Files {
		if f.Kind == FileRuleset {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return VerifyCheck{
			Name: CheckPersistence, Skipped: true,
			Detail: i18n.T(ctx, "this operation rendered no ruleset file"),
		}
	}
	for _, f := range files {
		content, err := os.ReadFile(f.Path)
		if err != nil {
			return VerifyCheck{
				Name: CheckPersistence, Fatal: true,
				Expected: f.Path, Actual: i18n.T(ctx, "absent"),
				Detail: i18n.T(ctx, "%s was not written, so the rules would not come back after a "+
					"reboot: %v", f.Path, err),
			}
		}
		if string(content) != f.Content {
			return VerifyCheck{
				Name: CheckPersistence, Fatal: true,
				Expected: i18n.T(ctx, "%d bytes", len(f.Content)),
				Actual:   i18n.T(ctx, "%d bytes", len(content)),
				Detail: i18n.T(ctx, "%s is not the ruleset that was applied, so a reboot would install "+
					"something else", f.Path),
			}
		}
	}
	return VerifyCheck{
		Name: CheckPersistence, Ok: true, Fatal: true,
		Detail: i18n.T(ctx, "the boot-time restore file is on disk and is the ruleset that was applied"),
	}
}
