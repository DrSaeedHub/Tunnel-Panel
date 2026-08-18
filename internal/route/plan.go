package route

import (
	"fmt"
	"strings"

	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// Step kinds. They are stable strings because a plan is serialised into the
// preview response and into the audit log.
const (
	// StepSnapshotCounters folds the live counters into the persisted totals
	// before the ruleset is replaced. Every rebuild zeroes them, so a snapshot
	// that is skipped is traffic that is lost (§5.2).
	StepSnapshotCounters = "counters_snapshot"
	// StepEnableForwarding turns on the kernel's forwarding and writes the
	// panel's own sysctl file.
	StepEnableForwarding = "enable_forwarding"
	// StepApplyRuleset submits the whole desired ruleset as one transaction.
	StepApplyRuleset = "ruleset_apply"
	// The restore unit, written once and refreshed whenever the payload the
	// backend would run changes.
	StepWriteUnit    = "unit_write"
	StepDaemonReload = "systemd_daemon_reload"
	StepEnableUnit   = "systemd_enable"
)

// Operation names.
const (
	OpCreate    = "create"
	OpUpdate    = "update"
	OpDelete    = "delete"
	OpEnable    = "enable"
	OpDisable   = "disable"
	OpReapply   = "reapply"
	OpReorder   = "reorder"
	OpDuplicate = "duplicate"
	OpApplyAll  = "apply_all"
)

// File kinds reported in a preview.
const (
	FileRuleset = "ruleset"
	FileUnit    = "systemd_unit"
	FileSysctl  = "sysctl"
)

// Step is one operation of a plan. Exactly one of the kind-specific fields is
// meaningful for any given kind; the rest are omitted from the JSON.
type Step struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`

	Argv    []string `json:"argv,omitempty"`
	Path    string   `json:"path,omitempty"`
	Content string   `json:"content,omitempty"`
	Unit    string   `json:"unit,omitempty"`

	// Payload is the ruleset an apply step submits.
	Payload *rules.Payload `json:"payload,omitempty"`
	// Tolerate marks a step whose failure does not fail the plan.
	Tolerate bool `json:"tolerate,omitempty"`
}

// PlannedFile is a rendered file the plan would write, returned by the preview
// endpoint so the operator reads the exact ruleset before committing (§7).
type PlannedFile struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Plan is the ordered, serialisable list of everything an operation would do,
// plus the inverse plan that undoes it.
//
// The plan carries the complete desired ruleset rather than a delta, because
// the apply is a transactional replacement of the panel's namespace. Planning
// is deterministic: the same request against the same state produces the same
// plan, byte for byte, which is what makes the preview trustworthy.
type Plan struct {
	Operation string `json:"operation"`
	// RouteRuleID names the rule the operation is about, or zero for the
	// operations that are about all of them.
	RouteRuleID int64  `json:"route_rule_id,omitempty"`
	Title       string `json:"title,omitempty"`
	Backend     string `json:"backend"`

	Steps    []Step `json:"steps"`
	Rollback []Step `json:"rollback"`

	Files []PlannedFile `json:"files"`

	// AffectedRouteRuleIDs is every rule whose installed rules this plan
	// changes, which for a bulk apply is all of them: one transaction, one
	// verdict, one audit entry.
	AffectedRouteRuleIDs []int64 `json:"affected_route_rule_ids,omitempty"`

	Warnings []validate.Warning `json:"warnings,omitempty"`
	// Verification lists what will be checked after the plan runs, so the
	// preview shows that success is not going to be assumed.
	Verification []string `json:"verification,omitempty"`
}

// Add appends a step.
func (p *Plan) Add(s Step) { p.Steps = append(p.Steps, s) }

// AddFile records a rendered file for the preview.
func (p *Plan) AddFile(kind, path, content string) {
	p.Files = append(p.Files, PlannedFile{Kind: kind, Path: path, Content: content})
}

// IsEmpty reports whether the plan would do nothing.
func (p *Plan) IsEmpty() bool { return len(p.Steps) == 0 }

// Summary renders the plan as one line per step, for a log entry.
func (p *Plan) Summary() []string {
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, s.Kind+": "+s.Description)
	}
	return out
}

// planner turns a desired set of rules into the plan that installs it.
type planner struct {
	backend      rules.Backend
	renderer     *persist.Renderer
	store        *persist.Store
	systemctlBin string
	sysctlPath   string
}

// planInput is everything one plan needs to know.
type planInput struct {
	operation string
	// desired is the state after the change; previous is the state before it,
	// which is what a rollback restores.
	desired  []Record
	previous []Record
	// subject names the rule the operation is about, when it is about one.
	subject *Record
	// retired names rules whose counter objects are still in the kernel but
	// whose rows are gone, so the transaction that rebuilds the ruleset also
	// takes them away.
	retired []int64
	// liveChains names the chains the kernel currently holds in the panel's
	// namespace, so the transaction removes the ones this ruleset no longer
	// declares. Empty when the inventory could not be read, and then nothing is
	// removed.
	liveChains []string
	// lastApplied is the payload this host last accepted, which is what a
	// rollback restores. Nil when nothing has been applied yet in this process,
	// and then the rollback falls back to rendering the previous state.
	lastApplied *rules.Payload
	// forwardingOn reports whether the kernel is already forwarding, so the
	// plan only carries the step when it would change something.
	forwardingOn     bool
	ipv6ForwardingOn bool
	warnings         []validate.Warning
}

// Plan renders the complete payload for the desired state and the steps that
// install it.
func (p *planner) Plan(in planInput) (Plan, error) {
	desired := DesiredOf(in.desired)
	desired.Retired = in.retired
	desired.LiveChains = in.liveChains
	payload, err := p.backend.Render(desired)
	if err != nil {
		return Plan{}, err
	}
	// The rollback deliberately renders the previous state without the live
	// chain inventory. A rollback restores the host to what it was; converging
	// the inventory is a forward change, and doing it on the way back would make
	// a failed apply leave a shape neither the old nor the new ruleset asked for.
	previousPayload, err := p.backend.Render(DesiredOf(in.previous))
	if err != nil {
		// The previous state was rendered once already to be applied, so
		// failing here means the stored state has become unrenderable. Saying so
		// is better than planning a rollback that cannot run.
		return Plan{}, fmt.Errorf("rendering the current ruleset for rollback: %w", err)
	}

	plan := Plan{
		Operation: in.operation,
		Backend:   p.backend.Name(),
		Warnings:  in.warnings,
	}
	if in.subject != nil {
		plan.RouteRuleID = in.subject.RouteRuleID
		plan.Title = in.subject.RouteRuleTitle
	}
	for _, rec := range in.desired {
		if rec.IsEnabled {
			plan.AffectedRouteRuleIDs = append(plan.AffectedRouteRuleIDs, rec.RouteRuleID)
		}
	}

	// 1. The counters are folded into the persisted totals before anything
	// replaces the ruleset, because the replacement zeroes them.
	plan.Add(Step{
		Kind:        StepSnapshotCounters,
		Description: "fold the live traffic counters into the stored totals before the ruleset is replaced",
	})

	// 2. Forwarding, only when it would change something.
	needIPv6 := desired.HasIPv6()
	if len(desired.Routes) > 0 && (!in.forwardingOn || (needIPv6 && !in.ipv6ForwardingOn)) {
		plan.Add(Step{
			Kind: StepEnableForwarding,
			Description: "turn on kernel packet forwarding and record it in the panel's own sysctl file " +
				"at " + p.sysctlFilePath(),
			Path: p.sysctlFilePath(),
		})
	}

	// 3. The transaction itself.
	copied := payload
	applyDescription := fmt.Sprintf(
		"replace the panel's %s ruleset with the %d enabled rule(s), in one transaction",
		p.backend.Name(), len(desired.Routes))
	if len(payload.RemovesChains) > 0 {
		applyDescription += fmt.Sprintf(", and remove the chain(s) it no longer declares: %s",
			strings.Join(payload.RemovesChains, ", "))
	}
	plan.Add(Step{
		Kind:        StepApplyRuleset,
		Description: applyDescription,
		Payload:     &copied,
	})
	for _, part := range payload.Parts {
		plan.AddFile(FileRuleset, part.Path, part.Text)
	}

	// 4. The restore unit, so the ruleset comes back after a reboot without the
	// panel having to be running.
	unit := p.renderer.RulesUnit(unitOptions(p.backend.Name(), payload))
	plan.Add(Step{
		Kind:        StepWriteUnit,
		Description: "write the boot-time restore unit for the panel's own rules",
		Path:        p.unitPath(), Content: unit,
	})
	plan.Add(Step{Kind: StepDaemonReload, Description: "reload systemd so it reads the unit"})
	plan.Add(Step{
		Kind: StepEnableUnit, Unit: persist.RulesUnitName,
		Description: "enable the restore unit so the rules return after a reboot",
	})
	plan.AddFile(FileUnit, p.unitPath(), unit)

	// The rollback puts back the exact payload that was last applied and
	// verified, kept since it succeeded, rather than rendering the previous
	// state again (§7).
	//
	// Re-rendering it looks equivalent and is not: it runs the same renderer
	// that has just failed. When a payload is refused for what the renderer
	// emitted rather than for what the operator asked — a construct this host's
	// nft cannot parse, say — the rollback reproduces the refusal exactly, and
	// a host that could have been left as it was is left inconsistent instead.
	// The retained payload came out of a kernel that accepted it.
	rollback := previousPayload
	source := "rendered from the stored rules"
	if in.lastApplied != nil {
		rollback = *in.lastApplied
		source = "the payload this host last accepted"
	}
	plan.Rollback = []Step{{
		Kind:        StepApplyRuleset,
		Description: "put the previous ruleset back (" + source + ")",
		Payload:     &rollback,
	}}

	plan.Verification = []string{
		"the panel's ruleset is read back from the kernel",
		"every rule the panel intends is present in the chain it belongs to, with its destination and its target",
		"no rule in the panel's namespace belongs to a rule the panel does not have",
		"the panel's namespace holds exactly the chains the ruleset declares",
		"kernel packet forwarding is on when an enabled rule needs it",
		"the boot-time restore file is on disk and is the one that was applied",
	}
	return plan, nil
}

func (p *planner) unitPath() string {
	if p.store == nil {
		return "/etc/systemd/system/" + persist.RulesUnitName
	}
	return p.store.SystemdDir + "/" + persist.RulesUnitName
}

func (p *planner) sysctlFilePath() string {
	if strings.TrimSpace(p.sysctlPath) == "" {
		return persist.SysctlPath
	}
	return p.sysctlPath
}

// unitOptions turns a rendered payload into the restore unit's commands.
//
// The jump rules are deleted before they are installed rather than checked
// first: systemd cannot express "run this only if that failed", and
// delete-then-insert reaches the same place — exactly one jump — without a
// shell. The delete is tolerated because on a fresh boot there is nothing to
// delete.
func unitOptions(backend string, payload rules.Payload) persist.RulesUnitOptions {
	opts := persist.RulesUnitOptions{Backend: backend}
	for _, part := range payload.Parts {
		opts.Restore = append(opts.Restore, part.Argv)
	}
	for _, assertion := range payload.Assertions {
		if len(assertion.Install) == 0 {
			continue
		}
		opts.Remove = append(opts.Remove, deleteFormOf(assertion.Install))
		opts.Install = append(opts.Install, assertion.Install)
	}
	return opts
}

// deleteFormOf turns an insert into the delete that undoes it: iptables spells
// them -I <chain> <position> and -D <chain>, so the position goes too.
func deleteFormOf(install []string) []string {
	out := make([]string, 0, len(install))
	for i := 0; i < len(install); i++ {
		if install[i] == "-I" {
			out = append(out, "-D")
			// The chain follows, then the position, which -D does not take.
			if i+2 < len(install) {
				out = append(out, install[i+1])
				i += 2
				continue
			}
			continue
		}
		out = append(out, install[i])
	}
	return out
}
