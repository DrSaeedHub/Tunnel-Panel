package reconcile

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/route"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// routeHarness adds a forwarding subsystem to the reconcile harness: a real
// repository over the same database, a fake netfilter backend, and a forwarding
// manager rooted at a fixture /proc.
type routeHarness struct {
	*harness
	ctx     context.Context
	routes  *route.Repo
	backend *rules.Fake
	root    string
}

func newRouteHarness(t *testing.T) *routeHarness {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()

	root := filepath.Join(h.dir, "root")
	procDir := filepath.Join(root, "proc", "sys", "net", "ipv4")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "ip_forward"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := route.NewRepo(h.db)
	backend := rules.NewFake()
	forwarding := &route.Forwarding{Root: root, SysctlPath: filepath.Join(root, "sysctl.conf")}
	h.service.SetRoutes(repo, backend, forwarding)

	return &routeHarness{harness: h, ctx: ctx, routes: repo, backend: backend, root: root}
}

// addRule stores a forwarding rule.
func (h *routeHarness) addRule(t *testing.T, title string, port int, enabled bool) int64 {
	t.Helper()
	id, err := h.routes.Insert(h.ctx, validate.RouteInput{
		RouteRuleTitle:  title,
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: port,
		DestinationAddress: "198.51.100.20", DestinationPort: port,
		NatModeID: model.NatModeMasquerade,
		IsEnabled: enabled,
	})
	if err != nil {
		t.Fatalf("storing %s failed: %v", title, err)
	}
	return id
}

// install renders the stored rules and applies them to the fake kernel, which
// is what "in sync" looks like.
func (h *routeHarness) install(t *testing.T) {
	t.Helper()
	records, err := h.routes.List(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := h.backend.Render(route.DesiredOf(records))
	if err != nil {
		t.Fatalf("rendering failed: %v", err)
	}
	if err := h.backend.Apply(h.ctx, payload); err != nil {
		t.Fatalf("applying failed: %v", err)
	}
}

// report runs the whole reconcile report and returns the forwarding half.
func (h *routeHarness) report(t *testing.T) ([]RouteItem, RouteFindings) {
	t.Helper()
	report, err := h.service.Report(h.ctx)
	if err != nil {
		t.Fatalf("Report returned an unexpected error: %v", err)
	}
	return report.Routes, report.RouteFindings
}

// itemFor finds the report line for one rule.
func itemFor(items []RouteItem, id int64) (RouteItem, bool) {
	for _, item := range items {
		if item.RouteRuleID != nil && *item.RouteRuleID == id {
			return item, true
		}
	}
	return RouteItem{}, false
}

// TestRouteClassification walks the five statuses of §9.
func TestRouteClassification(t *testing.T) {
	t.Run("in sync", func(t *testing.T) {
		h := newRouteHarness(t)
		id := h.addRule(t, "Web relay", 2044, true)
		h.install(t)

		items, findings := h.report(t)
		item, ok := itemFor(items, id)
		if !ok {
			t.Fatalf("the rule is not in the report: %+v", items)
		}
		if item.Status != StatusInSync {
			t.Errorf("status %s, want %s: %s", item.Status, StatusInSync, item.Detail)
		}
		if item.Installed == 0 || item.Expected == 0 {
			t.Errorf("the report counts %d installed of %d expected", item.Installed, item.Expected)
		}
		if !findings.Readable {
			t.Error("the findings say the panel's namespace could not be read")
		}
	})

	t.Run("missing", func(t *testing.T) {
		h := newRouteHarness(t)
		id := h.addRule(t, "Web relay", 2044, true)
		// Nothing was ever installed, which is what a host that rebooted
		// without the restore unit looks like.

		items, _ := h.report(t)
		item, _ := itemFor(items, id)
		if item.Status != StatusMissing {
			t.Errorf("status %s, want %s: %s", item.Status, StatusMissing, item.Detail)
		}
		if item.ReconcileStatusID != model.ReconcileStatusMissing {
			t.Errorf("the lookup identifier is %d", item.ReconcileStatusID)
		}
	})

	t.Run("drifted when part of the rule is gone", func(t *testing.T) {
		h := newRouteHarness(t)
		id := h.addRule(t, "Web relay", 2044, true)
		h.install(t)

		// Something flushed the postrouting chain: the rule is still there and
		// the masquerade is not.
		live, err := h.backend.ReadBack(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		kept := make([]rules.LiveRule, 0, len(live.Rules))
		for _, rule := range live.Rules {
			if rule.Role == rules.RolePostrouting {
				continue
			}
			kept = append(kept, rule)
		}
		live.Rules = kept
		h.backend.SetLive(live)

		items, _ := h.report(t)
		item, _ := itemFor(items, id)
		if item.Status != StatusDrifted {
			t.Fatalf("status %s, want %s: %s", item.Status, StatusDrifted, item.Detail)
		}
		if len(item.Diffs) == 0 {
			t.Fatal("the rule drifted with nothing said about what differs")
		}
		if item.Diffs[0].Field != rules.RolePostrouting {
			t.Errorf("the diff names %q, want the postrouting rule", item.Diffs[0].Field)
		}
	})

	t.Run("drifted when a disabled rule is still installed", func(t *testing.T) {
		h := newRouteHarness(t)
		id := h.addRule(t, "Web relay", 2044, true)
		h.install(t)
		if err := h.routes.SetEnabled(h.ctx, id, false); err != nil {
			t.Fatal(err)
		}

		items, _ := h.report(t)
		item, _ := itemFor(items, id)
		if item.Status != StatusDrifted {
			t.Fatalf("status %s, want %s: %s", item.Status, StatusDrifted, item.Detail)
		}
		if !strings.Contains(item.Detail, "still forwarding") {
			t.Errorf("the detail does not say the disabled rule is still live: %s", item.Detail)
		}
	})

	t.Run("unmanaged", func(t *testing.T) {
		h := newRouteHarness(t)
		id := h.addRule(t, "Web relay", 2044, true)
		h.install(t)

		// A rule for a forwarding rule the panel no longer has, left behind by
		// a delete that happened while the panel was not running.
		live, err := h.backend.ReadBack(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		live.Rules = append(live.Rules, rules.LiveRule{
			RouteRuleID: 99, Chain: "prerouting", Role: rules.RolePrerouting,
			Text: "ip daddr 203.0.113.10 tcp dport 9999 dnat to 10.0.0.9:9999 comment \"grep:99\"",
		})
		h.backend.SetLive(live)

		items, _ := h.report(t)
		if item, _ := itemFor(items, id); item.Status != StatusInSync {
			t.Errorf("the managed rule became %s: %s", item.Status, item.Detail)
		}
		orphan, ok := itemFor(items, 99)
		if !ok {
			t.Fatalf("the leftover rule is not in the report: %+v", items)
		}
		if orphan.Status != StatusUnmanaged {
			t.Errorf("status %s, want %s", orphan.Status, StatusUnmanaged)
		}
		// The offered remedy replaces the namespace; nothing is deleted here.
		if len(orphan.Actions) != 1 || orphan.Actions[0] != ActionReapply {
			t.Errorf("the offered actions are %v, want reapply only", orphan.Actions)
		}
	})

	t.Run("inconsistent", func(t *testing.T) {
		h := newRouteHarness(t)
		id := h.addRule(t, "Web relay", 2044, true)
		h.install(t)
		if err := h.routes.SetApplyStatus(h.ctx, id, model.ApplyStatusInconsistent,
			errRuleRefused{}); err != nil {
			t.Fatal(err)
		}

		items, _ := h.report(t)
		item, _ := itemFor(items, id)
		if item.Status != StatusInconsistent {
			t.Fatalf("status %s, want %s: %s", item.Status, StatusInconsistent, item.Detail)
		}
		// The failure that got the host there is quoted, because that is what
		// an operator needs in order to decide what to do.
		if !strings.Contains(item.Detail, "Operation not supported") {
			t.Errorf("the detail does not quote the failure: %s", item.Detail)
		}
	})
}

type errRuleRefused struct{}

func (errRuleRefused) Error() string { return "Error: Could not process rule: Operation not supported" }

// TestReconcileReportsAForeignShadowingRuleWithoutTouchingIt is the case of §9
// that matters most: something else on the host claims the same traffic, and
// the panel says so and changes nothing.
func TestReconcileReportsAForeignShadowingRuleWithoutTouchingIt(t *testing.T) {
	h := newRouteHarness(t)
	id := h.addRule(t, "Web relay", 2044, true)
	h.install(t)

	foreign := rules.ForeignRule{
		Table: "ip nat", Chain: "DOCKER", Manager: "Docker",
		Protocol: "tcp", Address: "203.0.113.10", Port: 2044,
		Text: "ip daddr 203.0.113.10 tcp dport 2044 dnat to 172.17.0.2:80",
	}
	h.backend.SetForeign(rules.ForeignView{Rules: []rules.ForeignRule{foreign}})
	before, err := h.backend.ReadBack(h.ctx)
	if err != nil {
		t.Fatal(err)
	}

	items, findings := h.report(t)
	item, _ := itemFor(items, id)

	if len(item.Shadows) != 1 {
		t.Fatalf("the rule reports %d shadowing rules, want 1", len(item.Shadows))
	}
	if item.Shadows[0].Manager != "Docker" {
		t.Errorf("the shadowing rule was not attributed: %+v", item.Shadows[0])
	}
	if len(findings.ForeignShadows) != 1 ||
		len(findings.ForeignShadows[0].ShadowsRouteRuleIDs) != 1 ||
		findings.ForeignShadows[0].ShadowsRouteRuleIDs[0] != id {
		t.Errorf("the host-wide finding does not name the rule it shadows: %+v", findings.ForeignShadows)
	}
	if len(findings.ForeignManagers) != 1 || findings.ForeignManagers[0] != "Docker" {
		t.Errorf("the foreign managers are %v", findings.ForeignManagers)
	}
	if !strings.Contains(strings.Join(findings.Notes, " "), "never removed") {
		t.Errorf("the notes do not say the foreign rule is left alone: %v", findings.Notes)
	}

	// And nothing was changed.
	after, err := h.backend.ReadBack(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Rules) != len(before.Rules) {
		t.Error("producing the report changed the installed ruleset")
	}
	view, _ := h.backend.Foreign(h.ctx)
	if len(view.Rules) != 1 {
		t.Error("the foreign rule was removed")
	}
}

// TestReconcileReportsMissingJumpRules is the classic iptables failure: the
// panel's chains are present and correct, and nothing jumps into them, so every
// rule in them is being ignored.
func TestReconcileReportsMissingJumpRules(t *testing.T) {
	h := newRouteHarness(t)
	h.addRule(t, "Web relay", 2044, true)
	h.install(t)

	live, err := h.backend.ReadBack(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	live.MissingJumps = []string{"nat/PREROUTING -> GRE_PANEL_PRE", "filter/FORWARD -> GRE_PANEL_FWD"}
	h.backend.SetLive(live)

	_, findings := h.report(t)
	if len(findings.MissingJumps) != 2 {
		t.Fatalf("the report lists %d missing jumps, want 2", len(findings.MissingJumps))
	}
	notes := strings.Join(findings.Notes, " ")
	if !strings.Contains(notes, "GRE_PANEL_PRE") {
		t.Errorf("the notes do not name the missing jump: %v", findings.Notes)
	}
	if !strings.Contains(notes, "Reapply") {
		t.Errorf("the notes do not say how to put it right: %v", findings.Notes)
	}
}

// TestReconcileReportsForwardingTurnedOffOutsideThePanel.
func TestReconcileReportsForwardingTurnedOffOutsideThePanel(t *testing.T) {
	h := newRouteHarness(t)
	h.addRule(t, "Web relay", 2044, true)
	h.install(t)

	path := filepath.Join(h.root, "proc", "sys", "net", "ipv4", "ip_forward")
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, findings := h.report(t)
	if findings.ForwardingEnabled {
		t.Error("the report says forwarding is on")
	}
	if !findings.ForwardingExpected {
		t.Error("the report does not say an enabled rule needs forwarding")
	}
	if !strings.Contains(strings.Join(findings.Notes, " "), "ip_forward is off") {
		t.Errorf("the notes do not report it: %v", findings.Notes)
	}

	// And with the panel's own sysctl file in place, the report says the change
	// came from outside the panel rather than that it was never turned on.
	if err := os.WriteFile(filepath.Join(h.root, "sysctl.conf"),
		[]byte(persist.OwnershipMarker+" role=sysctl\n"+persist.PreviousMarker+
			"net.ipv4.ip_forward=0\nnet.ipv4.ip_forward=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, findings = h.report(t)
	if !findings.ForwardingPanelManaged {
		t.Fatal("the panel's own sysctl file was not recognised")
	}
	if !strings.Contains(strings.Join(findings.Notes, " "), "outside the panel") {
		t.Errorf("the notes do not say who turned it off: %v", findings.Notes)
	}
}

// TestReconcileWithoutTheForwardingSubsystemStillReportsTunnels: an instance
// built without it answers about tunnels rather than failing.
func TestReconcileWithoutTheForwardingSubsystemStillReportsTunnels(t *testing.T) {
	h := newHarness(t)
	h.createTunnel(t)

	report, err := h.service.Report(context.Background())
	if err != nil {
		t.Fatalf("Report returned an unexpected error: %v", err)
	}
	if len(report.Items) == 0 {
		t.Error("the tunnel half of the report is empty")
	}
	if len(report.Routes) != 0 {
		t.Errorf("routes were reported without a forwarding subsystem: %+v", report.Routes)
	}
}
