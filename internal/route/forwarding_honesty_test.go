package route

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

func hasWarning(warnings []validate.Warning, code string) (validate.Warning, bool) {
	for _, w := range warnings {
		if w.Code == code {
			return w, true
		}
	}
	return validate.Warning{}, false
}

func hasStep(plan Plan, kind string) bool {
	for _, step := range plan.Steps {
		if step.Kind == kind {
			return true
		}
	}
	return false
}

func setProc(t *testing.T, h *harness, rel, value string) {
	t.Helper()
	path := filepath.Join(h.dir, "proc", "sys", "net", "ipv4", rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("preparing %s failed: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		t.Fatalf("writing %s failed: %v", rel, err)
	}
}

// An operator saw "the rules are installed and doing nothing" in the form for a
// new rule, applied it without overriding anything, and found it working. The
// preview had described the host as it was, while the plan beside it turned
// forwarding on before installing anything. A warning about a problem the
// panel's own plan fixes teaches the operator that warnings can be ignored.
func TestAPreviewDoesNotWarnAboutForwardingItsOwnPlanTurnsOn(t *testing.T) {
	h := newHarness(t) // ip_forward is 0, and the panel turns it on by default

	preview, err := h.service.PreviewCreate(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("PreviewCreate returned an unexpected error: %v", err)
	}
	if w, found := hasWarning(preview.Warnings, WarnForwardingDisabled); found {
		t.Errorf("the preview warns about forwarding that its own plan turns on: %s", w.Message)
	}
	if !hasStep(preview.Plan, StepEnableForwarding) {
		t.Error("the preview's plan does not say it turns forwarding on")
	}

	// The plan it shows names the backend that will be written to, not the
	// stand-in the preview renders with.
	if preview.Plan.Backend != rules.BackendNftables {
		t.Errorf("the preview's plan names the %q backend, want %q", preview.Plan.Backend, rules.BackendNftables)
	}
	for _, step := range preview.Plan.Steps {
		if strings.Contains(step.Description, rules.BackendFake) || strings.Contains(step.Content, rules.BackendFake) {
			t.Errorf("a preview step talks about the %q backend: %s", rules.BackendFake, step.Description)
		}
	}
}

// With routes.auto_enable_ip_forward off the operator manages forwarding. The
// panel must then say, before the apply, that the rule will carry nothing --
// and then install it, as the setting promises, rather than failing the apply
// over the very thing it was told to leave alone.
func TestARuleIsInstalledAndReportedWhenForwardingIsLeftToTheOperator(t *testing.T) {
	h := newHarness(t)
	h.service.settings = routeSettings{"routes.auto_enable_ip_forward": false}

	preview, err := h.service.PreviewCreate(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("PreviewCreate returned an unexpected error: %v", err)
	}
	w, found := hasWarning(preview.Warnings, WarnForwardingDisabled)
	if !found {
		t.Fatal("the preview does not warn that the rule will carry nothing")
	}
	if w.Details["stage"] != "preview" {
		t.Errorf("the preview's warning describes the %v state, want the outcome of the apply", w.Details["stage"])
	}
	if strings.Contains(w.Message, "installed and doing nothing") {
		t.Errorf("the preview says rules are already installed: %s", w.Message)
	}
	if hasStep(preview.Plan, StepEnableForwarding) {
		t.Error("the plan lists turning forwarding on, which the setting stops it from doing")
	}

	result, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("the rule was refused although the setting says to install it: %v", err)
	}
	if result.Route.ApplyStatusID != model.ApplyStatusApplied {
		t.Errorf("the rule is recorded as %d, want Applied", result.Route.ApplyStatusID)
	}
	if !strings.Contains(h.kernel.liveRuleset(), rules.Identity(result.Route.RouteRuleID)) {
		t.Error("the rule is not in the kernel")
	}
	if _, found := hasWarning(result.Warnings, "VERIFICATION_"+strings.ToUpper(CheckForwarding)); !found {
		t.Errorf("the create does not report that the rule carries nothing yet: %+v", result.Warnings)
	}
	body, _ := os.ReadFile(filepath.Join(h.dir, "proc", "sys", "net", "ipv4", "ip_forward"))
	if strings.TrimSpace(string(body)) != "0" {
		t.Errorf("ip_forward = %q, want it left at 0", body)
	}

	health := h.service.Health(h.ctx, []Record{result.Route})[result.Route.RouteRuleID]
	if health.State != HealthImpaired {
		t.Errorf("a rule that carries nothing reads as %q (%s), want impaired", health.State, health.Detail)
	}
}

// A rule on a host that stopped forwarding read as healthy -- "the path they
// use is up" -- on the same page as a banner saying the kernel forwards
// nothing.
func TestARuleIsImpairedWhileTheKernelDoesNotForward(t *testing.T) {
	h := newHarness(t)
	result, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("Create returned an unexpected error: %v", err)
	}
	id := result.Route.RouteRuleID
	if got := h.service.Health(h.ctx, []Record{result.Route})[id]; got.State != HealthHealthy {
		t.Fatalf("a working rule reads as %q (%s), want healthy", got.State, got.Detail)
	}

	setProc(t, h, "ip_forward", "0") // something outside the panel turned it off
	got := h.service.Health(h.ctx, []Record{result.Route})[id]
	if got.State != HealthImpaired || !strings.Contains(got.Detail, "not forwarding") {
		t.Errorf("with forwarding off the rule reads as %q (%s), want impaired", got.State, got.Detail)
	}
}

// A rule relaying to a loopback address is accepted only when forced, with a
// warning that it needs route_localnet. Until that is on it carries nothing,
// and its health has to say so rather than "healthy".
func TestALoopbackRuleIsImpairedUntilLocalnetIsRouted(t *testing.T) {
	h := newHarness(t)
	req := request("Local relay", 2044)
	req.DestinationAddress = "127.0.0.1"
	req.Force = true
	result, err := h.service.Create(h.ctx, req)
	if err != nil {
		t.Fatalf("Create returned an unexpected error: %v", err)
	}
	id := result.Route.RouteRuleID

	got := h.service.Health(h.ctx, []Record{result.Route})[id]
	if got.State != HealthImpaired || !strings.Contains(got.Detail, "route_localnet") {
		t.Errorf("without route_localnet the rule reads as %q (%s), want impaired", got.State, got.Detail)
	}

	setProc(t, h, "conf/eth0/route_localnet", "1")
	if got := h.service.Health(h.ctx, []Record{result.Route})[id]; got.State != HealthHealthy {
		t.Errorf("with route_localnet on the rule reads as %q (%s), want healthy", got.State, got.Detail)
	}
}
