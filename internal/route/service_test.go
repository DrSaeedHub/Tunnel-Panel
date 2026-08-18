package route

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/validate"
)

// fakeKernel stands in for netfilter: it accepts the payloads the real backend
// hands it, remembers the last one as what the kernel holds, and answers a
// read-back with it.
//
// It is deliberately not a stub that always says yes. Applying makes the rules
// live, failing an apply leaves the previous ruleset in place, and a test can
// make the kernel hold something other than what was applied — which is the
// only way to test that verification actually looks.
type fakeKernel struct {
	mu sync.Mutex
	// live is the ruleset the kernel would report.
	live string
	// applies counts the transactions submitted, which is how "one transaction"
	// is asserted.
	applies int
	// failNext fails the next apply whose payload contains this text.
	failOn string
	// swallow makes an apply report success without installing anything, which
	// is exactly the zombie state verification exists to catch.
	swallow bool
	// counters is what the counter listing returns.
	counters string
}

func newFakeKernel() *fakeKernel {
	return &fakeKernel{counters: `{"nftables":[{"metainfo":{"version":"1.0.9"}}]}`}
}

func (k *fakeKernel) runner() *exec.FakeRunner {
	runner := exec.NewFakeRunner()
	runner.Handler = func(argv []string) (exec.Result, error) {
		line := strings.Join(argv, " ")
		k.mu.Lock()
		defer k.mu.Unlock()

		switch {
		case strings.Contains(line, "-f "):
			path := argv[len(argv)-1]
			content, err := os.ReadFile(path)
			if err != nil {
				return exec.Result{ExitCode: 1, Stderr: err.Error()}, err
			}
			k.applies++
			if k.failOn != "" && strings.Contains(string(content), k.failOn) {
				return exec.Result{ExitCode: 1, Stderr: "Error: Could not process rule: Operation not supported"},
					errors.New("nft exited 1")
			}
			if !k.swallow {
				k.live = string(content)
			}
			return exec.Result{}, nil

		case strings.Contains(line, "list counters"):
			return exec.Result{Stdout: k.counters}, nil

		case strings.Contains(line, "list table"):
			if k.live == "" {
				return exec.Result{ExitCode: 1, Stderr: "Error: No such file or directory"},
					errors.New("nft exited 1")
			}
			return exec.Result{Stdout: k.live}, nil

		case strings.Contains(line, "delete table"):
			k.live = ""
			return exec.Result{}, nil
		}
		return exec.Result{}, nil
	}
	return runner
}

// setCounters makes the counter listing report a live counter pair for each of
// the given rule identifiers, the way `nft -j list counters` does.
func (k *fakeKernel) setCounters(ids ...int64) {
	entries := make([]string, 0, len(ids)*2)
	for _, id := range ids {
		for _, direction := range []string{"rx", "tx"} {
			entries = append(entries, fmt.Sprintf(
				`{"counter":{"family":"inet","table":"gre_panel","name":"route_%d_%s",`+
					`"packets":1,"bytes":64}}`, id, direction))
		}
	}
	k.mu.Lock()
	k.counters = `{"nftables":[` + strings.Join(entries, ",") + `]}`
	k.mu.Unlock()
}

// breakCounters makes the counter listing unreadable, which is a state a real
// host reaches whenever nft is upgraded underneath a running panel.
func (k *fakeKernel) breakCounters() {
	k.mu.Lock()
	k.counters = "not json at all"
	k.mu.Unlock()
}

func (k *fakeKernel) applyCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.applies
}

func (k *fakeKernel) liveRuleset() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.live
}

// harness is a whole route service over a temporary database, a temporary
// filesystem and the fake kernel.
type harness struct {
	t          *testing.T
	ctx        context.Context
	db         *db.DB
	repo       *Repo
	service    *Service
	kernel     *fakeKernel
	runner     *exec.FakeRunner
	dir        string
	forwarding *Forwarding
	counters   *countingStore
}

// countingStore records the counter snapshots the pipeline takes.
type countingStore struct {
	mu        sync.Mutex
	snapshots int
	forgotten []int64
}

func (c *countingStore) Snapshot(ctx context.Context) error {
	c.mu.Lock()
	c.snapshots++
	c.mu.Unlock()
	return nil
}

func (c *countingStore) Forget(ctx context.Context, id int64) error {
	c.mu.Lock()
	c.forgotten = append(c.forgotten, id)
	c.mu.Unlock()
	return nil
}

func newHarness(t *testing.T) *harness {
	return newHarnessWith(t, nil)
}

// newHarnessWith is the same, with the chance to wrap the backend — which is
// how a test stands in for a host whose netfilter refuses what the renderer
// produces.
func newHarnessWith(t *testing.T, wrap func(rules.Backend) rules.Backend) *harness {
	t.Helper()
	ctx, database, repo := openRepo(t)

	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	systemdDir := filepath.Join(dir, "systemd")
	procDir := filepath.Join(dir, "proc", "sys", "net", "ipv4")
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("preparing the fake /proc failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(procDir, "ip_forward"), []byte("0\n"), 0o644); err != nil {
		t.Fatalf("preparing the fake /proc failed: %v", err)
	}
	if err := os.MkdirAll(systemdDir, 0o755); err != nil {
		t.Fatalf("preparing the unit directory failed: %v", err)
	}

	kernel := newFakeKernel()
	runner := kernel.runner()
	var backend rules.Backend = rules.NewNftables("/usr/sbin/nft", rulesDir, runner)
	if wrap != nil {
		backend = wrap(backend)
	}
	store := persist.NewStore(systemdDir, filepath.Join(dir, "networkd"), "", runner)
	renderer := persist.NewRenderer("/sbin/ip", "/sbin/modprobe", "/bin/ping")

	guard := safety.NewRouteGuard(8443, nil, rulesDir)
	guard.SysctlFile = filepath.Join(dir, "sysctl.conf")
	forwarding := &Forwarding{
		Root: dir, SysctlPath: guard.SysctlFile, Store: store, Renderer: renderer, Guard: guard,
	}
	counters := &countingStore{}

	validator := validate.NewRouteValidator(link.NewFakeWithHost(), repo.ForValidation(), nil, nil)
	service := New(Deps{
		Repo: repo, Backend: backend, Runner: runner, Renderer: renderer, Store: store,
		Validator: validator, Guard: guard, Forwarding: forwarding, Counters: counters,
		SystemctlBin: "",
	})

	return &harness{
		t: t, ctx: ctx, db: database, repo: repo, service: service, kernel: kernel,
		runner: runner, dir: dir, forwarding: forwarding, counters: counters,
	}
}

// request is a plain, valid rule.
func request(title string, port int) Request {
	return Request{RouteInput: validate.RouteInput{
		RouteRuleTitle:  title,
		RouteProtocolID: model.RouteProtocolTCP,
		AddressFamilyID: model.AddressFamilyIPv4,
		BindAddress:     "203.0.113.10", BindPort: port,
		DestinationAddress: "198.51.100.20", DestinationPort: port,
		NatModeID: model.NatModeMasquerade, IsEnabled: true,
	}}
}

// ---------------------------------------------------------------- lifecycle

func TestCreateAppliesVerifiesAndPersists(t *testing.T) {
	h := newHarness(t)

	result, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("Create returned an unexpected error: %v", err)
	}
	if !result.Verify.Ok {
		t.Fatalf("the apply was not verified: %+v", result.Verify)
	}
	if result.Route.ApplyStatusID != model.ApplyStatusApplied {
		t.Errorf("the rule is recorded as %d, want Applied", result.Route.ApplyStatusID)
	}

	// One transaction, not one command per rule.
	if h.kernel.applyCount() != 1 {
		t.Errorf("the create submitted %d transactions, want exactly 1", h.kernel.applyCount())
	}
	// The counters were folded in before the ruleset was replaced.
	if h.counters.snapshots != 1 {
		t.Errorf("the counters were snapshotted %d times, want once before the rebuild",
			h.counters.snapshots)
	}
	// The rendered ruleset is on disk, which is what the boot-time restore
	// reads.
	payloadPath := filepath.Join(h.dir, "rules", rules.NftFileName)
	written, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("the ruleset was not written: %v", err)
	}
	if !strings.Contains(string(written), rules.Identity(result.Route.RouteRuleID)) {
		t.Error("the written ruleset does not carry the rule's identity comment")
	}
	// And the unit that restores it at boot.
	unit, err := os.ReadFile(filepath.Join(h.dir, "systemd", persist.RulesUnitName))
	if err != nil {
		t.Fatalf("the restore unit was not written: %v", err)
	}
	for _, want := range []string{"After=network-online.target", "Before=docker.service", payloadPath} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("the restore unit does not contain %q:\n%s", want, unit)
		}
	}
	// Forwarding was turned on and recorded in the panel's own file.
	sysctl, err := os.ReadFile(filepath.Join(h.dir, "sysctl.conf"))
	if err != nil {
		t.Fatalf("the sysctl file was not written: %v", err)
	}
	if !strings.Contains(string(sysctl), "net.ipv4.ip_forward=1") {
		t.Errorf("the sysctl file does not enable forwarding:\n%s", sysctl)
	}
	if !strings.Contains(string(sysctl), persist.PreviousMarker+"net.ipv4.ip_forward=0") {
		t.Errorf("the sysctl file does not record what forwarding was before:\n%s", sysctl)
	}
}

// TestVerificationCatchesAnAcceptedRulesetThatIsNotThere is the whole point of
// reading back: the backend reported success, and the kernel has nothing.
func TestVerificationCatchesAnAcceptedRulesetThatIsNotThere(t *testing.T) {
	h := newHarness(t)
	h.kernel.swallow = true

	_, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err == nil {
		t.Fatal("an apply that installed nothing was reported as a success")
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("got %v, want an ApplyError", err)
	}
	if applyErr.Verify.Ok {
		t.Error("the verification report says the apply worked")
	}
	if !applyErr.RolledBack {
		t.Error("the failure was not rolled back")
	}
	if !strings.Contains(applyErr.Cause, "verification failed") {
		t.Errorf("the cause does not say what happened: %s", applyErr.Cause)
	}

	// The rule is kept and marked failed rather than removed: an operator needs
	// to see what was attempted and why it did not work.
	records, err := h.repo.List(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ApplyStatusID != model.ApplyStatusFailed {
		t.Errorf("the rule was not recorded as failed: %+v", records)
	}
	if records[0].LastApplyError == nil {
		t.Error("the failure was not recorded on the rule")
	}
}

// TestAFailedApplyPutsThePreviousRulesetBack covers the rollback: the ruleset
// the kernel holds afterwards is the one from before the change, not a partial
// one.
func TestAFailedApplyPutsThePreviousRulesetBack(t *testing.T) {
	h := newHarness(t)

	first, err := h.service.Create(h.ctx, request("Working relay", 2044))
	if err != nil {
		t.Fatalf("the first rule failed: %v", err)
	}
	before := h.kernel.liveRuleset()
	if !strings.Contains(before, rules.Identity(first.Route.RouteRuleID)) {
		t.Fatal("the first rule is not in the live ruleset")
	}

	// The second rule's payload is refused by the kernel.
	h.kernel.failOn = "Broken relay"
	_, err = h.service.Create(h.ctx, request("Broken relay", 2045))
	if err == nil {
		t.Fatal("a refused ruleset was reported as applied")
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("got %v, want an ApplyError", err)
	}
	if !applyErr.RolledBack {
		t.Error("the apply was not rolled back")
	}
	if applyErr.Stderr == "" {
		t.Error("the failure does not carry the backend's own message")
	}

	after := h.kernel.liveRuleset()
	if after != before {
		t.Errorf("the live ruleset is not what it was before the failed change:\n%s", after)
	}
	if strings.Contains(after, "Broken relay") {
		t.Error("the refused rule is in the live ruleset")
	}
}

// poisonedRenderer is a backend whose rendering starts producing something this
// kernel refuses, from a point in time.
//
// That is what a version incompatibility looks like from inside the panel: the
// stored rules do not change and the renderer does not change, but the text it
// produces is no longer text this host's nft will take. Rendering the previous
// state again therefore fails in exactly the same way as the change did, which
// is why a rollback cannot be a re-render.
type poisonedRenderer struct {
	rules.Backend
	armed *atomic.Bool
}

func (p poisonedRenderer) Render(rs rules.Ruleset) (rules.Payload, error) {
	payload, err := p.Backend.Render(rs)
	if err != nil || !p.armed.Load() || len(payload.Parts) == 0 {
		return payload, err
	}
	parts := append([]rules.Part(nil), payload.Parts...)
	parts[0].Text += "\n# construct this host's nft cannot parse\n"
	payload.Parts = parts
	return payload, nil
}

// TestARollbackRestoresTheTextTheKernelAccepted is §7's rollback, and the case
// that shows why it has to be the retained payload rather than a fresh render.
//
// Here every render is refused from a point onwards, so a rollback that renders
// the previous state again is refused too and the host is left inconsistent —
// which is precisely what an operator saw on the release whose nft rejected a
// chain the renderer always emitted. Putting back the payload the kernel
// accepted last time cannot fail for that reason: it is the text that worked.
func TestARollbackRestoresTheTextTheKernelAccepted(t *testing.T) {
	armed := &atomic.Bool{}
	h := newHarnessWith(t, func(backend rules.Backend) rules.Backend {
		return poisonedRenderer{Backend: backend, armed: armed}
	})
	// Anything carrying the poisoned line is refused, whichever payload it is.
	h.kernel.failOn = "cannot parse"

	first, err := h.service.Create(h.ctx, request("Working relay", 2044))
	if err != nil {
		t.Fatalf("the first rule failed: %v", err)
	}
	before := h.kernel.liveRuleset()

	// From here the renderer's output is no longer acceptable to this host.
	armed.Store(true)

	_, err = h.service.Create(h.ctx, request("Second relay", 2045))
	if err == nil {
		t.Fatal("a refused ruleset was reported as applied")
	}
	var inconsistent *InconsistentError
	if errors.As(err, &inconsistent) {
		t.Fatalf("the rollback re-rendered instead of restoring, so it failed the same way "+
			"the apply did and the host was left inconsistent: %v", err)
	}
	var applyErr *ApplyError
	if !errors.As(err, &applyErr) {
		t.Fatalf("got %v, want an ApplyError", err)
	}
	if !applyErr.RolledBack {
		t.Error("the failure does not report that the host was put back")
	}

	after := h.kernel.liveRuleset()
	if after != before {
		t.Errorf("the kernel does not hold what it held before the refused change:\n%s", after)
	}
	if !strings.Contains(after, rules.Identity(first.Route.RouteRuleID)) {
		t.Error("the rule that was working before the refused change is no longer installed")
	}
}

// TestTheRollbackNamesWhereItsPayloadCameFrom: the plan is shown to operators
// and read in support, so which of the two sources a rollback would use is
// stated rather than inferred.
func TestTheRollbackNamesWhereItsPayloadCameFrom(t *testing.T) {
	h := newHarness(t)

	// Nothing has been applied yet, so there is nothing retained to put back.
	plan, err := h.service.PreviewCreate(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("previewing failed: %v", err)
	}
	if len(plan.Plan.Rollback) == 0 || !strings.Contains(plan.Plan.Rollback[0].Description, "stored rules") {
		t.Errorf("with nothing applied yet the rollback should say it renders the stored rules: %+v",
			plan.Plan.Rollback)
	}

	if _, err := h.service.Create(h.ctx, request("Web relay", 2044)); err != nil {
		t.Fatalf("creating failed: %v", err)
	}

	plan, err = h.service.PreviewCreate(h.ctx, request("Another relay", 2045))
	if err != nil {
		t.Fatalf("previewing failed: %v", err)
	}
	if len(plan.Plan.Rollback) == 0 || !strings.Contains(plan.Plan.Rollback[0].Description, "last accepted") {
		t.Errorf("after a successful apply the rollback should restore the retained payload: %+v",
			plan.Plan.Rollback)
	}
}

// TestAFailedRollbackIsReportedAsInconsistent: the panel does not pretend the
// host is fine when it could neither apply nor undo.
func TestAFailedRollbackIsReportedAsInconsistent(t *testing.T) {
	h := newHarness(t)

	// Every payload is refused, so the rollback fails too.
	h.kernel.failOn = "table inet gre_panel"
	_, err := h.service.Create(h.ctx, request("Web relay", 2044))
	var inconsistent *InconsistentError
	if !errors.As(err, &inconsistent) {
		t.Fatalf("got %v, want an InconsistentError", err)
	}
	if len(inconsistent.Remediation) == 0 {
		t.Error("an inconsistent host was reported with no remediation commands")
	}
	// Every command an operator is handed touches the panel's own namespace:
	// its table, its chains, its rendered ruleset, or its unit.
	for _, command := range inconsistent.Remediation {
		owned := strings.Contains(command, rules.TableName) ||
			strings.Contains(command, "GRE_PANEL") ||
			strings.Contains(command, rules.NftFileName) ||
			strings.Contains(command, rules.IptablesFileName) ||
			strings.Contains(command, persist.RulesUnitName)
		if !owned {
			t.Errorf("a remediation command touches something outside the panel's namespace: %s", command)
		}
	}

	records, err := h.repo.List(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ApplyStatusID != model.ApplyStatusInconsistent {
		t.Errorf("the rule was not recorded as inconsistent: %+v", records)
	}
}

func TestDisableAndEnableRebuildTheRuleset(t *testing.T) {
	h := newHarness(t)
	created, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Route.RouteRuleID

	if _, err := h.service.SetEnabled(h.ctx, id, false, Request{}); err != nil {
		t.Fatalf("disabling failed: %v", err)
	}
	if strings.Contains(h.kernel.liveRuleset(), rules.Identity(id)) {
		t.Error("a disabled rule is still installed")
	}

	if _, err := h.service.SetEnabled(h.ctx, id, true, Request{}); err != nil {
		t.Fatalf("enabling failed: %v", err)
	}
	if !strings.Contains(h.kernel.liveRuleset(), rules.Identity(id)) {
		t.Error("an enabled rule is not installed")
	}
}

func TestDeleteRemovesTheRulesAndForgetsTheCounters(t *testing.T) {
	h := newHarness(t)
	created, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Route.RouteRuleID

	report, err := h.service.Delete(h.ctx, id, Request{})
	if err != nil {
		t.Fatalf("Delete returned an unexpected error: %v", err)
	}
	if !report.Verify.Ok {
		t.Errorf("the delete was not verified: %+v", report.Verify)
	}
	if strings.Contains(h.kernel.liveRuleset(), rules.Identity(id)) {
		t.Error("the deleted rule is still installed")
	}
	if len(h.counters.forgotten) != 1 || h.counters.forgotten[0] != id {
		t.Errorf("the accounting for the deleted rule was not forgotten: %v", h.counters.forgotten)
	}
	// The panel turned forwarding on, so it offers to put it back — and only
	// offers.
	if !report.ForwardingCanBeReverted {
		t.Error("deleting the last rule did not offer to revert forwarding")
	}
	sysctl := filepath.Join(h.dir, "sysctl.conf")
	if _, err := os.Stat(sysctl); err != nil {
		t.Error("deleting the last rule reverted forwarding by itself")
	}
}

// TestCountersOfARuleThatIsGoneAreRemovedFromTheKernel covers the gap a table
// flush leaves behind. Named counter objects outlive it on purpose, so a rule
// keeps its figures across an edit — but a rule that has been deleted has no
// figures worth keeping, and without this its counters would sit in the kernel
// describing something the panel does not have.
func TestCountersOfARuleThatIsGoneAreRemovedFromTheKernel(t *testing.T) {
	h := newHarness(t)
	created, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatal(err)
	}
	id := created.Route.RouteRuleID

	// The kernel now reports counters for the live rule and for a rule that was
	// deleted before the panel restarted, which is exactly the state a host
	// arrives in after a delete on an older build.
	h.kernel.setCounters(id, 99)

	// Any rebuild is enough; nothing here is about the delete in particular.
	if _, err := h.service.Reapply(h.ctx, id, Request{}); err != nil {
		t.Fatalf("Reapply returned an unexpected error: %v", err)
	}

	live := h.kernel.liveRuleset()
	if !strings.Contains(live, "delete counter inet gre_panel route_99_rx") ||
		!strings.Contains(live, "delete counter inet gre_panel route_99_tx") {
		t.Error("the counters of the rule the panel no longer has were left in the kernel")
	}
	if strings.Contains(live, fmt.Sprintf("delete counter inet gre_panel route_%d_", id)) {
		t.Error("the counters of a rule that still exists were removed")
	}

	// And when the rule itself goes, so do its counters.
	if _, err := h.service.Delete(h.ctx, id, Request{}); err != nil {
		t.Fatalf("Delete returned an unexpected error: %v", err)
	}
	if !strings.Contains(h.kernel.liveRuleset(),
		fmt.Sprintf("delete counter inet gre_panel route_%d_rx", id)) {
		t.Error("deleting a rule left its counters behind")
	}
}

// TestAnUnreadableCounterListDoesNotBlockAChange: the cleanup is a tidy-up, and
// a tidy-up that can refuse an operator's edit is worse than the mess it
// prevents.
func TestAnUnreadableCounterListDoesNotBlockAChange(t *testing.T) {
	h := newHarness(t)
	created, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatal(err)
	}
	h.kernel.breakCounters()

	if _, err := h.service.Reapply(h.ctx, created.Route.RouteRuleID, Request{}); err != nil {
		t.Fatalf("an unreadable counter list stopped a reapply: %v", err)
	}
	if strings.Contains(h.kernel.liveRuleset(), "delete counter") {
		t.Error("counters were deleted on the strength of a listing that could not be read")
	}
}

// TestBulkApplyIsOneTransaction is the requirement of §7: editing several rules
// produces one transaction, not one per rule.
func TestBulkApplyIsOneTransaction(t *testing.T) {
	h := newHarness(t)
	for i, title := range []string{"first", "second", "third"} {
		if _, err := h.service.Create(h.ctx, request(title, 2044+i)); err != nil {
			t.Fatalf("creating %s failed: %v", title, err)
		}
	}

	before := h.kernel.applyCount()
	result, err := h.service.ApplyAll(h.ctx, Request{})
	if err != nil {
		t.Fatalf("ApplyAll returned an unexpected error: %v", err)
	}
	if got := h.kernel.applyCount() - before; got != 1 {
		t.Errorf("applying three rules submitted %d transactions, want 1", got)
	}
	if len(result.Plan.AffectedRouteRuleIDs) != 3 {
		t.Errorf("the plan covers %d rules, want all 3", len(result.Plan.AffectedRouteRuleIDs))
	}
	live := h.kernel.liveRuleset()
	for i := 1; i <= 3; i++ {
		if !strings.Contains(live, rules.Identity(int64(i))) {
			t.Errorf("rule %d is not in the installed ruleset", i)
		}
	}
}

func TestReorderChangesEmissionOrderAndReinstalls(t *testing.T) {
	h := newHarness(t)
	var ids []int64
	for i, title := range []string{"first", "second"} {
		created, err := h.service.Create(h.ctx, request(title, 2044+i))
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.Route.RouteRuleID)
	}

	if _, err := h.service.Reorder(h.ctx, []int64{ids[1], ids[0]}, Request{}); err != nil {
		t.Fatalf("Reorder returned an unexpected error: %v", err)
	}
	live := h.kernel.liveRuleset()
	firstAt := strings.Index(live, rules.Identity(ids[0]))
	secondAt := strings.Index(live, rules.Identity(ids[1]))
	if firstAt < 0 || secondAt < 0 {
		t.Fatalf("both rules should be installed:\n%s", live)
	}
	if secondAt > firstAt {
		t.Error("the reordered rule is not emitted first, so first-match-wins would pick the wrong one")
	}
}

func TestDuplicateCopiesARuleDisabled(t *testing.T) {
	h := newHarness(t)
	created, err := h.service.Create(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatal(err)
	}

	copied, err := h.service.Duplicate(h.ctx, created.Route.RouteRuleID, Request{})
	if err != nil {
		t.Fatalf("Duplicate returned an unexpected error: %v", err)
	}
	if copied.Route.RouteRuleID == created.Route.RouteRuleID {
		t.Fatal("the copy is the original")
	}
	if copied.Route.IsEnabled {
		t.Error("the copy is enabled, so it would claim the original's listener")
	}
	if copied.Route.RouteRuleTitle == created.Route.RouteRuleTitle {
		t.Error("the copy has the same name as the original")
	}
	if copied.Route.BindPort != created.Route.BindPort {
		t.Error("the copy is not a copy: its bind port differs")
	}
	// A disabled copy installs nothing, so the live ruleset is untouched.
	if strings.Contains(h.kernel.liveRuleset(), rules.Identity(copied.Route.RouteRuleID)) {
		t.Error("the disabled copy was installed")
	}
}

// TestPreviewChangesNothing is the trust model of §7: what the operator reads
// before committing is the payload that would be applied, and reading it
// changes nothing.
func TestPreviewChangesNothing(t *testing.T) {
	h := newHarness(t)
	before := h.kernel.applyCount()

	preview, err := h.service.PreviewCreate(h.ctx, request("Web relay", 2044))
	if err != nil {
		t.Fatalf("PreviewCreate returned an unexpected error: %v", err)
	}
	if h.kernel.applyCount() != before {
		t.Error("the preview submitted a transaction")
	}
	if h.kernel.liveRuleset() != "" {
		t.Error("the preview installed rules")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "rules", rules.NftFileName)); err == nil {
		t.Error("the preview wrote the ruleset to disk")
	}
	records, err := h.repo.List(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Error("the preview stored the rule")
	}

	if !strings.Contains(preview.Payload, "dnat") || !strings.Contains(preview.Payload, "198.51.100.20") {
		t.Errorf("the preview payload is not the ruleset:\n%s", preview.Payload)
	}
	if len(preview.Plan.Verification) == 0 {
		t.Error("the preview does not say what will be verified")
	}

	// And it is the same payload the apply installs.
	if _, err := h.service.Create(h.ctx, request("Web relay", 2044)); err != nil {
		t.Fatalf("Create after the preview failed: %v", err)
	}
	applied, err := os.ReadFile(filepath.Join(h.dir, "rules", rules.NftFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.Payload, strings.TrimSpace(string(applied))) &&
		!strings.Contains(string(applied), "dnat ip to 198.51.100.20:2044") {
		t.Error("the preview and the apply do not agree on the ruleset")
	}
}

// TestPlanCarriesTheWholeDesiredRulesetAndItsRollback covers §7: the plan is a
// complete replacement, and its rollback is the previous complete state.
func TestPlanCarriesTheWholeDesiredRulesetAndItsRollback(t *testing.T) {
	h := newHarness(t)
	if _, err := h.service.Create(h.ctx, request("first", 2044)); err != nil {
		t.Fatal(err)
	}

	preview, err := h.service.PreviewCreate(h.ctx, request("second", 2045))
	if err != nil {
		t.Fatalf("PreviewCreate returned an unexpected error: %v", err)
	}

	var applyStep *Step
	for i := range preview.Plan.Steps {
		if preview.Plan.Steps[i].Kind == StepApplyRuleset {
			applyStep = &preview.Plan.Steps[i]
		}
	}
	if applyStep == nil || applyStep.Payload == nil {
		t.Fatal("the plan has no apply step")
	}
	// The desired ruleset holds both rules, because it is the whole state and
	// not the change.
	text := applyStep.Payload.Text()
	if !strings.Contains(text, "first") || !strings.Contains(text, "second") {
		t.Errorf("the plan is a delta rather than the whole desired ruleset:\n%s", text)
	}

	if len(preview.Plan.Rollback) != 1 || preview.Plan.Rollback[0].Payload == nil {
		t.Fatalf("the plan has no rollback payload: %+v", preview.Plan.Rollback)
	}
	rollback := preview.Plan.Rollback[0].Payload.Text()
	if !strings.Contains(rollback, "first") {
		t.Error("the rollback does not restore the rule that was already there")
	}
	if strings.Contains(rollback, "second") {
		t.Error("the rollback carries the rule the change was adding")
	}

	// The first step folds the counters in, because the rebuild zeroes them.
	if preview.Plan.Steps[0].Kind != StepSnapshotCounters {
		t.Errorf("the first step is %q, want the counter snapshot", preview.Plan.Steps[0].Kind)
	}
}

// TestTheSafetyInvariantsStopAnApply is §6.3 checked in the service layer
// immediately before execution, not only at the API boundary.
func TestTheSafetyInvariantsStopAnApply(t *testing.T) {
	h := newHarness(t)

	// The panel is served on 8443, and no flag reaches this.
	req := request("Take the panel down", 8443)
	req.Force = true
	_, err := h.service.Create(h.ctx, req)
	if err == nil {
		t.Fatal("a rule redirecting the panel's own port was applied")
	}
	violation, ok := safety.AsViolation(err)
	if !ok || violation.Code != safety.CodeProtectedPort {
		t.Fatalf("got %v, want a protected-port refusal", err)
	}
	if h.kernel.applyCount() != 0 {
		t.Error("the refused rule reached the kernel")
	}
}

func TestReassertInstallsTheStoredRulesetAtStartup(t *testing.T) {
	h := newHarness(t)
	if _, err := h.service.Create(h.ctx, request("Web relay", 2044)); err != nil {
		t.Fatal(err)
	}

	// Something else flushed the panel's table while it was not running.
	h.kernel.mu.Lock()
	h.kernel.live = ""
	h.kernel.mu.Unlock()

	if err := h.service.Reassert(h.ctx); err != nil {
		t.Fatalf("Reassert returned an unexpected error: %v", err)
	}
	if !strings.Contains(h.kernel.liveRuleset(), rules.Identity(1)) {
		t.Error("the stored ruleset was not reasserted")
	}
}

// TestReassertOnAHostWithNoRulesDoesNothing: a panel that manages no forwarding
// rules must not create a table for them.
func TestReassertOnAHostWithNoRulesDoesNothing(t *testing.T) {
	h := newHarness(t)
	if err := h.service.Reassert(h.ctx); err != nil {
		t.Fatalf("Reassert returned an unexpected error: %v", err)
	}
	if h.kernel.applyCount() != 0 {
		t.Error("a host with no forwarding rules had a ruleset installed")
	}
}

// TestValidationRefusesBeforeTheLockIsTaken keeps a malformed request from
// queueing behind a running apply.
func TestValidationRefusesBeforeAnythingIsStored(t *testing.T) {
	h := newHarness(t)

	req := request("Bad relay", 2044)
	req.DestinationAddress = "not-an-ip"
	if _, err := h.service.Create(h.ctx, req); err == nil {
		t.Fatal("a malformed rule was accepted")
	}
	records, err := h.repo.List(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Error("a rejected rule was stored")
	}
	if h.kernel.applyCount() != 0 {
		t.Error("a rejected rule reached the kernel")
	}
}

// A rule the safety guard forbids can never be applied — the guard says so in
// as many words, "under any setting or flag". Storing it anyway is worse than
// useless: the guard runs over the whole desired ruleset before every apply, so
// one forbidden rule sitting in the database makes every later rule fail too,
// with an error naming a port the operator never mentioned.
//
// Seen on a live panel. Creating a rule on port 22 with force returned 409 and
// stored the rule anyway; after that, creating an ordinary rule on port 9200
// failed with "This rule would redirect port 22", and so did deleting the rule
// that caused it. The whole forwarding subsystem was wedged by one refusal.
func TestARuleTheGuardForbidsIsNeverStored(t *testing.T) {
	h := newHarness(t)

	// 8443 is the panel's own port here. 22 is protected as a precaution,
	// because this harness has no socket table to identify a running sshd —
	// which is exactly the state a sandboxed panel is in on a real host.
	for _, port := range []int{8443, 22} {
		if _, err := h.service.Create(h.ctx, request(fmt.Sprintf("forbidden-%d", port), port)); err == nil {
			t.Fatalf("a rule on the protected port %d was accepted", port)
		}

		records, err := h.repo.List(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 0 {
			t.Fatalf("the rule on port %d was refused and stored anyway: %d record(s) remain",
				port, len(records))
		}
		if h.kernel.applyCount() != 0 {
			t.Fatalf("a rule on the protected port %d reached the kernel", port)
		}
	}

	// The subsystem has to still work afterwards. This is the half that made
	// the live failure so hard to read: the error named port 22 while the
	// operator was creating a rule on 9200.
	if _, err := h.service.Create(h.ctx, request("ordinary", 9200)); err != nil {
		t.Fatalf("an ordinary rule could not be created after a refusal: %v", err)
	}
}
