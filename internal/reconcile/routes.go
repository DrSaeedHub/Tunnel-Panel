package reconcile

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
)

// RouteSource is what reconciliation needs to know about forwarding rules. It
// is an interface so the report can be produced against a stored set of records
// without a whole service behind it.
type RouteSource interface {
	List(ctx context.Context) ([]route.Record, error)
}

// RouteItem is one line of the forwarding half of the reconcile report.
type RouteItem struct {
	RouteRuleID       *int64      `json:"route_rule_id,omitempty"`
	Title             string      `json:"title"`
	ReconcileStatusID int64       `json:"reconcile_status_id"`
	Status            string      `json:"status"`
	Detail            string      `json:"detail"`
	Diffs             []FieldDiff `json:"diffs,omitempty"`
	Actions           []string    `json:"actions"`

	// Expected and Installed are how many rules the panel intends for this row
	// and how many the kernel actually holds for it, which is what "drifted"
	// means here.
	Expected  int `json:"expected_rules"`
	Installed int `json:"installed_rules"`

	// Shadows are foreign rules claiming this one's traffic. They are reported
	// and never removed: the panel does not delete a rule it does not own.
	Shadows []rules.ForeignRule `json:"shadows,omitempty"`
}

// RouteFindings are the host-wide observations the forwarding half makes,
// which belong to no single rule (§9).
type RouteFindings struct {
	Backend string `json:"backend"`
	// Readable reports whether the panel's own namespace could be listed at
	// all. Everything below is meaningless without it, and an unreadable
	// ruleset is never reported as an empty one.
	Readable bool   `json:"readable"`
	Detail   string `json:"detail,omitempty"`

	// EnabledRules is how many rules the panel intends to have installed.
	EnabledRules int `json:"enabled_rules"`

	// ForwardingEnabled is the live kernel parameter, and ForwardingExpected
	// says whether an enabled rule needs it. The two differing is the classic
	// "the rules are perfect and nothing works" state.
	ForwardingEnabled  bool `json:"ip_forwarding_enabled"`
	ForwardingExpected bool `json:"ip_forwarding_expected"`
	// ForwardingPanelManaged reports that the panel's own sysctl file is in
	// place, which is how "somebody turned it off outside the panel" is told
	// from "it was never on".
	ForwardingPanelManaged bool `json:"ip_forwarding_panel_managed"`

	// MissingJumps names the built-in chains that no longer jump into the
	// panel's own. On the iptables backend this is the classic failure after
	// another tool flushes a chain, and every rule below it stops working
	// while still being present and correct.
	MissingJumps []string `json:"missing_jumps,omitempty"`

	// ForeignReadable reports whether the rest of the host's ruleset could be
	// read; ForeignManagers names the software found managing netfilter here.
	ForeignReadable bool     `json:"foreign_readable"`
	ForeignManagers []string `json:"foreign_managers,omitempty"`
	// ForeignShadows are the foreign rules overlapping the panel's, across
	// every rule. Nothing here is ever modified.
	ForeignShadows []ForeignShadow `json:"foreign_shadows,omitempty"`

	// Notes are the sentences an operator reads, in the order they matter.
	Notes []string `json:"notes,omitempty"`
}

// ForeignShadow is one foreign rule together with the panel rules it overlaps.
type ForeignShadow struct {
	rules.ForeignRule
	ShadowsRouteRuleIDs []int64 `json:"shadows_route_rule_ids"`
}

// RouteBackend is the slice of the netfilter backend reconciliation reads. It
// never applies anything: closing a gap is an action an operator asks for.
type RouteBackend interface {
	Name() string
	ReadBack(ctx context.Context) (rules.Live, error)
	Foreign(ctx context.Context) (rules.ForeignView, error)
}

// ForwardingSource reports the kernel parameters.
type ForwardingSource interface {
	Status(ctx context.Context, needIPv6 bool, enabledRules int, warnPercent float64) route.ForwardingStatus
}

// SetRoutes wires the forwarding subsystem into reconciliation. It is set after
// construction because the route service is built after this one.
func (s *Service) SetRoutes(source RouteSource, backend RouteBackend, forwarding ForwardingSource) {
	s.routes = source
	s.ruleBackend = backend
	s.forwarding = forwarding
}

// RouteReport classifies every stored forwarding rule against the live kernel
// ruleset, matching rules by the identity comment each one carries (§9).
//
// It changes nothing. A foreign rule is never deleted, a drifted rule is never
// silently repaired, and forwarding is never turned back on here: the report
// says what differs and offers the actions, and a person decides.
func (s *Service) RouteReport(ctx context.Context) ([]RouteItem, RouteFindings, error) {
	findings := RouteFindings{}
	if s.routes == nil || s.ruleBackend == nil {
		return nil, findings, nil
	}
	findings.Backend = s.ruleBackend.Name()

	records, err := s.routes.List(ctx)
	if err != nil {
		return nil, findings, err
	}
	desired := route.DesiredOf(records)
	findings.EnabledRules = len(desired.Routes)

	live, err := s.ruleBackend.ReadBack(ctx)
	if err != nil {
		findings.Detail = "the panel's own netfilter namespace could not be read: " + err.Error()
		findings.Notes = append(findings.Notes, findings.Detail)
		return nil, findings, nil
	}
	findings.Readable = true
	findings.MissingJumps = live.MissingJumps

	foreign := s.foreignView(ctx, &findings)
	items := s.classifyRoutes(records, live, foreign)
	items = append(items, unmanagedRouteItems(records, live)...)

	sort.SliceStable(items, func(i, j int) bool {
		left, right := int64(0), int64(0)
		if items[i].RouteRuleID != nil {
			left = *items[i].RouteRuleID
		}
		if items[j].RouteRuleID != nil {
			right = *items[j].RouteRuleID
		}
		return left < right
	})

	s.forwardingFindings(ctx, desired, &findings)
	collectShadows(items, &findings)
	addRouteNotes(items, &findings)
	return items, findings, nil
}

// foreignView reads the rest of the host's ruleset, tolerating a host that
// refuses it.
func (s *Service) foreignView(ctx context.Context, findings *RouteFindings) rules.ForeignView {
	view, err := s.ruleBackend.Foreign(ctx)
	if err != nil || !view.Readable {
		detail := "the rest of this host's netfilter rules could not be read, so a rule shadowing " +
			"the panel's would not have been noticed"
		if err != nil {
			detail += ": " + err.Error()
		}
		findings.Notes = append(findings.Notes, detail)
		return rules.ForeignView{}
	}
	findings.ForeignReadable = true
	findings.ForeignManagers = view.Managers
	return view
}

// classifyRoutes decides the status of every stored rule.
func (s *Service) classifyRoutes(records []route.Record, live rules.Live,
	foreign rules.ForeignView) []RouteItem {

	byRule := map[int64][]rules.LiveRule{}
	for _, rule := range live.Rules {
		if rule.Structural || rule.RouteRuleID == 0 {
			continue
		}
		byRule[rule.RouteRuleID] = append(byRule[rule.RouteRuleID], rule)
	}

	items := make([]RouteItem, 0, len(records))
	for _, rec := range records {
		id := rec.RouteRuleID
		installed := byRule[id]
		item := RouteItem{
			RouteRuleID: &id, Title: rec.RouteRuleTitle,
			Installed: len(installed),
			Actions:   []string{ActionReapply, ActionForget},
		}
		if rec.IsEnabled {
			item.Expected = route.ExpectedRuleCount(rec.Spec())
			item.Shadows = foreign.ShadowsOf(rec.Spec())
		}

		switch {
		// A rule the panel could neither install nor undo is the most serious
		// state there is, and it stays visible until somebody resolves it.
		case rec.ApplyStatusID == model.ApplyStatusInconsistent:
			item.ReconcileStatusID = model.ReconcileStatusInconsistent
			item.Status = StatusInconsistent
			item.Detail = "the last change to this rule failed and could not be undone. The host's " +
				"ruleset may be half-configured; reapply, or put it right by hand and then forget it."
			if rec.LastApplyError != nil {
				item.Detail += " The failure was: " + *rec.LastApplyError
			}

		case !rec.IsEnabled && len(installed) > 0:
			// A disabled rule that is still in the kernel is forwarding traffic
			// the panel believes it is not.
			item.ReconcileStatusID = model.ReconcileStatusDrifted
			item.Status = StatusDrifted
			item.Detail = fmt.Sprintf("%s is disabled in the panel but %d of its rules are still "+
				"installed, so it is still forwarding traffic.", rec.RouteRuleTitle, len(installed))
			item.Diffs = []FieldDiff{{
				Field: "installed", Desired: "no rules", Actual: strconv.Itoa(len(installed)) + " rules",
			}}

		case !rec.IsEnabled:
			item.ReconcileStatusID = model.ReconcileStatusInSync
			item.Status = StatusInSync
			item.Detail = "the rule is disabled and nothing of it is installed, which is what disabled means"

		case len(installed) == 0:
			item.ReconcileStatusID = model.ReconcileStatusMissing
			item.Status = StatusMissing
			item.Detail = fmt.Sprintf("%s is enabled but none of its rules are in the kernel. Reapply "+
				"to install them again, or forget the rule to drop the record.", rec.RouteRuleTitle)

		default:
			if diffs := missingRuleDiffs(rec, live); len(diffs) > 0 {
				item.ReconcileStatusID = model.ReconcileStatusDrifted
				item.Status = StatusDrifted
				item.Diffs = diffs
				fields := make([]string, 0, len(diffs))
				for _, d := range diffs {
					fields = append(fields, d.Field)
				}
				item.Detail = fmt.Sprintf("the installed rules for %s differ from what the panel "+
					"intends in %s", rec.RouteRuleTitle, strings.Join(fields, ", "))
				break
			}
			item.ReconcileStatusID = model.ReconcileStatusInSync
			item.Status = StatusInSync
			item.Detail = fmt.Sprintf("every rule %s needs is installed", rec.RouteRuleTitle)
		}

		if len(item.Shadows) > 0 {
			item.Detail += fmt.Sprintf(" A rule this panel does not own claims the same traffic: %s. "+
				"Nothing was changed.", item.Shadows[0].Describe())
		}
		items = append(items, item)
	}
	return items
}

// missingRuleDiffs reports which parts of a rule are absent from the kernel.
//
// It asks the route package the same question verification asks after an apply,
// so drift and a failed apply can never disagree about what "installed" means.
func missingRuleDiffs(rec route.Record, live rules.Live) []FieldDiff {
	var diffs []FieldDiff
	for _, absent := range route.MissingRules(rec.Spec(), live) {
		diffs = append(diffs, FieldDiff{
			Field: absent.Role, Desired: absent.Describes, Actual: "missing from the kernel",
		})
	}
	return diffs
}

// unmanagedRouteItems reports rules living in the panel's own namespace that no
// live database row accounts for (§9).
//
// These are the residue of a rule deleted while the panel was not running, or
// of a ruleset installed by an older version. They are reported, never deleted
// on sight: the remedy is a reapply, which replaces the namespace with the
// stored state and takes them with it.
func unmanagedRouteItems(records []route.Record, live rules.Live) []RouteItem {
	known := map[int64]bool{}
	for _, rec := range records {
		known[rec.RouteRuleID] = true
	}

	counts := map[int64]int{}
	unattributed := 0
	for _, rule := range live.Rules {
		if rule.Structural {
			continue
		}
		if rule.RouteRuleID == 0 {
			unattributed++
			continue
		}
		if !known[rule.RouteRuleID] {
			counts[rule.RouteRuleID]++
		}
	}

	ids := make([]int64, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	items := make([]RouteItem, 0, len(ids)+1)
	for _, id := range ids {
		orphan := id
		items = append(items, RouteItem{
			RouteRuleID:       &orphan,
			Title:             "forwarding rule " + strconv.FormatInt(id, 10),
			ReconcileStatusID: model.ReconcileStatusUnmanaged,
			Status:            StatusUnmanaged,
			Installed:         counts[id],
			Actions:           []string{ActionReapply},
			Detail: fmt.Sprintf("%d rule(s) in the panel's own namespace carry the identity of "+
				"forwarding rule %d, which the panel has no record of. Reapplying replaces the "+
				"namespace with the stored rules and takes these with it.", counts[id], id),
		})
	}
	if unattributed > 0 {
		items = append(items, RouteItem{
			Title:             "unattributed rules",
			ReconcileStatusID: model.ReconcileStatusUnmanaged,
			Status:            StatusUnmanaged,
			Installed:         unattributed,
			Actions:           []string{ActionReapply},
			Detail: fmt.Sprintf("%d rule(s) in the panel's own namespace carry no identity comment, "+
				"so they cannot be attributed to any forwarding rule. Reapplying replaces the "+
				"namespace with the stored rules.", unattributed),
		})
	}
	return items
}

// forwardingFindings reports the kernel parameters against what the rules need.
func (s *Service) forwardingFindings(ctx context.Context, desired rules.Ruleset, findings *RouteFindings) {
	findings.ForwardingExpected = len(desired.Routes) > 0
	if s.forwarding == nil {
		return
	}
	status := s.forwarding.Status(ctx, desired.HasIPv6(), len(desired.Routes), 0)
	findings.ForwardingEnabled = status.IPv4Forwarding
	findings.ForwardingPanelManaged = status.PanelManaged

	if findings.ForwardingExpected && !status.IPv4Forwarding {
		note := fmt.Sprintf("%d forwarding rule(s) are enabled but net.ipv4.ip_forward is off, so none "+
			"of them can carry traffic.", len(desired.Routes))
		if status.PanelManaged {
			note += " The panel's own sysctl file is in place, so something outside the panel turned " +
				"it off since. Nothing was changed here."
		}
		findings.Notes = append(findings.Notes, note)
	}
	if desired.HasIPv6() && !status.IPv6Forwarding {
		findings.Notes = append(findings.Notes,
			"An enabled rule forwards IPv6, but net.ipv6.conf.all.forwarding is off.")
	}
}

// collectShadows gathers the per-rule shadows into the host-wide list.
func collectShadows(items []RouteItem, findings *RouteFindings) {
	index := map[string]*ForeignShadow{}
	var order []string

	for _, item := range items {
		if item.RouteRuleID == nil {
			continue
		}
		for _, rule := range item.Shadows {
			key := rule.Table + "|" + rule.Chain + "|" + rule.Text
			entry, ok := index[key]
			if !ok {
				entry = &ForeignShadow{ForeignRule: rule}
				index[key] = entry
				order = append(order, key)
			}
			entry.ShadowsRouteRuleIDs = append(entry.ShadowsRouteRuleIDs, *item.RouteRuleID)
		}
	}
	for _, key := range order {
		findings.ForeignShadows = append(findings.ForeignShadows, *index[key])
	}
}

// addRouteNotes turns the counts into the sentences an operator reads.
func addRouteNotes(items []RouteItem, findings *RouteFindings) {
	if len(findings.MissingJumps) > 0 {
		findings.Notes = append(findings.Notes, fmt.Sprintf(
			"The panel's chains are not reached from %s. Its rules are present and correct and none "+
				"of them is being consulted, which is what happens after another tool flushes a "+
				"built-in chain. Reapply any rule to put the jump rules back.",
			strings.Join(findings.MissingJumps, ", ")))
	}
	if len(findings.ForeignShadows) > 0 {
		findings.Notes = append(findings.Notes, fmt.Sprintf(
			"%d rule(s) this panel does not own claim traffic the panel's rules also claim. They are "+
				"reported and never removed: something else on this host owns them.",
			len(findings.ForeignShadows)))
	}

	counts := map[string]int{}
	for _, item := range items {
		counts[item.Status]++
	}
	if counts[StatusUnmanaged] > 0 {
		findings.Notes = append(findings.Notes, fmt.Sprintf(
			"%d entry in the panel's own namespace has no forwarding rule behind it. Reapplying "+
				"replaces the namespace with the stored rules.", counts[StatusUnmanaged]))
	}
}
