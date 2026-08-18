package route

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/lock"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/validate"
)

// Settings is the slice of the settings store this package reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	Float(key string) float64
	String(key string) string
}

// CounterStore is the accounting this service snapshots before every rebuild.
// *Accounting satisfies it; a nil one means the counters are not being kept,
// which is what a preview and most tests want.
type CounterStore interface {
	// Snapshot folds the live counters into the persisted totals. It is called
	// immediately before the ruleset is replaced, because replacing it zeroes
	// them (§5.2).
	Snapshot(ctx context.Context) error
	// Forget drops the accounting for a rule that has been deleted.
	Forget(ctx context.Context, routeRuleID int64) error
}

// TunnelSource reports the health of a tunnel a rule sends traffic through, so
// a route whose tunnel is down is reported as impaired rather than as broken
// (§10).
type TunnelSource interface {
	TunnelHealth(ctx context.Context, tunnelID int64) (TunnelHealth, bool)
}

// TunnelHealth is what a rule needs to know about the tunnel it depends on.
type TunnelHealth struct {
	TunnelID      int64  `json:"tunnel_id"`
	InterfaceName string `json:"interface_name"`
	// DisplayName is what the operator called the tunnel, when they named it.
	// The panel names a tunnel by this everywhere it is labelled, so a rule
	// that reports an impaired path can say which tunnel in the operator's own
	// words rather than only in the kernel's.
	DisplayName string `json:"display_name,omitempty"`
	IsEnabled   bool   `json:"is_enabled"`
	// IsUp is the kernel's UP and LOWER_UP flags, never the operational state:
	// a healthy GRE tunnel reports UNKNOWN.
	IsUp bool `json:"is_up"`
	// MonitorState is the prober's verdict, when there is one.
	MonitorState string   `json:"monitor_state,omitempty"`
	PeerAddress  string   `json:"peer_address,omitempty"`
	Addresses    []string `json:"addresses,omitempty"`
}

// Healthy reports whether traffic can be expected to cross this tunnel.
func (h TunnelHealth) Healthy() bool {
	return h.IsEnabled && h.IsUp && !strings.EqualFold(h.MonitorState, "Down")
}

// Deps is everything the service needs. Every dependency is an interface or a
// value the caller constructs, so the whole pipeline runs hermetically against
// the fake backend and the fake process runner.
type Deps struct {
	Repo    *Repo
	Backend rules.Backend
	// Preview renders what would be applied without applying it. It is the fake
	// backend wrapping the real one, so a preview cannot drift from an apply.
	Preview    rules.Backend
	Runner     exec.Runner
	Renderer   *persist.Renderer
	Store      *persist.Store
	Validator  *validate.RouteValidator
	Guard      *safety.RouteGuard
	Forwarding *Forwarding
	Counters   CounterStore
	Tunnels    TunnelSource
	Settings   Settings
	Log        *slog.Logger
	// Mutation is the global mutation lock (§16), shared with the tunnel
	// service: both reconfigure the same kernel.
	Mutation     *lock.Mutation
	SystemctlBin string
}

// Service carries out forwarding rule operations.
type Service struct {
	repo       *Repo
	backend    rules.Backend
	preview    rules.Backend
	runner     exec.Runner
	renderer   *persist.Renderer
	store      *persist.Store
	validator  *validate.RouteValidator
	guard      *safety.RouteGuard
	forwarding *Forwarding
	counters   CounterStore
	settings   Settings
	log        *slog.Logger
	planner    *planner
	mutation   *lock.Mutation

	// appliedMu guards the payload a rollback restores. It is its own lock
	// because a rollback has to be able to read it while an apply is in flight.
	appliedMu   sync.Mutex
	lastApplied *rules.Payload

	mu      sync.Mutex
	tunnels TunnelSource
	// observers are told when the installed ruleset changes, which is what
	// makes the accounting re-read its counter names without a sweep.
	observers []func()
}

// New builds the service.
func New(d Deps) *Service {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	backend := d.Backend
	if backend == nil {
		backend = rules.NewFake()
	}
	preview := d.Preview
	if preview == nil {
		preview = rules.NewFakeFor(backend)
	}
	mutation := d.Mutation
	if mutation == nil {
		mutation = lock.New()
	}
	renderer := d.Renderer
	if renderer == nil {
		renderer = persist.NewRenderer("", "", "")
	}

	sysctlPath := persist.SysctlPath
	if d.Forwarding != nil {
		sysctlPath = d.Forwarding.sysctlFile()
	}
	return &Service{
		repo: d.Repo, backend: backend, preview: preview, runner: d.Runner,
		renderer: renderer, store: d.Store, validator: d.Validator, guard: d.Guard,
		forwarding: d.Forwarding, counters: d.Counters, settings: d.Settings,
		tunnels: d.Tunnels, log: log, mutation: mutation,
		planner: &planner{
			backend: backend, renderer: renderer, store: d.Store,
			systemctlBin: d.SystemctlBin, sysctlPath: sysctlPath,
		},
	}
}

// Repo exposes the repository for the read paths, which never take the mutation
// lock (§16).
func (s *Service) Repo() *Repo { return s.repo }

// Backend exposes the netfilter backend for the read paths.
func (s *Service) Backend() rules.Backend { return s.backend }

// Forwarding exposes the kernel parameter manager.
func (s *Service) Forwarding() *Forwarding { return s.forwarding }

// SetTunnels wires the tunnel health source, which is built after this service.
func (s *Service) SetTunnels(source TunnelSource) {
	s.mu.Lock()
	s.tunnels = source
	s.mu.Unlock()
}

// TunnelSource returns the tunnel health source in force.
func (s *Service) tunnelSource() TunnelSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tunnels
}

// OnChange registers a function called after the installed ruleset changes.
func (s *Service) OnChange(fn func()) {
	s.mu.Lock()
	s.observers = append(s.observers, fn)
	s.mu.Unlock()
}

func (s *Service) notifyChanged() {
	s.mu.Lock()
	observers := append([]func(){}, s.observers...)
	s.mu.Unlock()
	for _, fn := range observers {
		fn()
	}
}

// ---------------------------------------------------------------- requests

// Request is a create or update.
type Request struct {
	validate.RouteInput

	// IdempotencyKey guards against a double submission (§16).
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// ClientIP is filled in by the handler, never by the client.
	ClientIP string `json:"-"`
}

// Result is what a completed operation returns.
type Result struct {
	Route      Record             `json:"route"`
	Plan       Plan               `json:"plan"`
	Verify     VerifyReport       `json:"verification"`
	Warnings   []validate.Warning `json:"warnings,omitempty"`
	Operations []audit.Operation  `json:"operations,omitempty"`
}

// Preview is the result of validate + plan with nothing carried out (§7).
type Preview struct {
	Plan     Plan               `json:"plan"`
	Route    Record             `json:"route"`
	Warnings []validate.Warning `json:"warnings,omitempty"`
	// Payload is the exact ruleset that would be applied, rendered for reading.
	Payload string `json:"payload"`
}

// ApplyError is a plain apply failure that was rolled back successfully.
type ApplyError struct {
	Operation  string       `json:"operation"`
	Title      string       `json:"title,omitempty"`
	Step       string       `json:"step,omitempty"`
	Cause      string       `json:"cause"`
	Stderr     string       `json:"stderr,omitempty"`
	Verify     VerifyReport `json:"verification"`
	RolledBack bool         `json:"rolled_back"`
}

func (e *ApplyError) Error() string {
	if e.Step != "" {
		return fmt.Sprintf("%s failed at %s: %s", e.Operation, e.Step, e.Cause)
	}
	return fmt.Sprintf("%s failed: %s", e.Operation, e.Cause)
}

// InconsistentError is returned when an apply failed and putting the previous
// ruleset back failed too. The panel does not pretend otherwise: the rules are
// recorded as Inconsistent and the exact commands to put the host right are
// returned (§7).
type InconsistentError struct {
	Operation     string   `json:"operation"`
	ApplyError    string   `json:"apply_error"`
	RollbackError string   `json:"rollback_error"`
	Remediation   []string `json:"remediation"`
}

func (e *InconsistentError) Error() string {
	return fmt.Sprintf("the forwarding rules could not be applied and the previous ruleset could not be "+
		"put back either: %s (rollback also failed: %s)", e.ApplyError, e.RollbackError)
}

// ---------------------------------------------------------------- previews

// PreviewCreate runs validate and plan only, returning the exact ruleset that
// would be applied. Nothing is stored and nothing on the host is touched (§7).
func (s *Service) PreviewCreate(ctx context.Context, req Request) (Preview, error) {
	in := req.RouteInput
	in.RouteRuleID = 0
	warnings, err := s.validate(ctx, &in)
	if err != nil {
		return Preview{}, err
	}

	// The preview gets an identifier no stored rule has, so the identity
	// comments in the payload read like the real thing rather than grep:0.
	desired, err := s.repo.List(ctx)
	if err != nil {
		return Preview{}, err
	}
	rec := RecordFrom(in)
	rec.RouteRuleID = nextPreviewID(desired)
	return s.previewOf(ctx, OpCreate, append(desired, rec), desired, &rec, warnings)
}

// PreviewUpdate runs validate and plan for a change to an existing rule.
func (s *Service) PreviewUpdate(ctx context.Context, id int64, req Request) (Preview, error) {
	if _, err := s.repo.ByID(ctx, id); err != nil {
		return Preview{}, err
	}
	in := req.RouteInput
	in.RouteRuleID = id
	warnings, err := s.validate(ctx, &in)
	if err != nil {
		return Preview{}, err
	}

	stored, err := s.repo.List(ctx)
	if err != nil {
		return Preview{}, err
	}
	desired := RecordFrom(in)
	desired.RouteRuleID = id
	return s.previewOf(ctx, OpUpdate, replaceRecord(stored, desired), stored, &desired, warnings)
}

func (s *Service) previewOf(ctx context.Context, operation string, desired, previous []Record,
	subject *Record, warnings []validate.Warning) (Preview, error) {

	status := s.forwardingStatus(ctx, desired)
	previewPlanner := &planner{
		backend: s.preview, renderer: s.planner.renderer, store: s.planner.store,
		systemctlBin: s.planner.systemctlBin, sysctlPath: s.planner.sysctlPath,
	}
	plan, err := previewPlanner.Plan(planInput{
		operation: operation, desired: desired, previous: previous, subject: subject,
		forwardingOn: status.IPv4Forwarding, ipv6ForwardingOn: status.IPv6Forwarding,
		// The preview is the payload that would be submitted, so it carries the
		// counter cleanup too rather than showing a file the apply would not use,
		// and it names the rollback the apply would actually perform. The live
		// chain inventory is read from the real backend for the same reason: the
		// preview has to show the chain removals the apply would really make.
		retired:     s.retiredCounters(ctx, desired),
		liveChains:  s.liveChains(ctx),
		lastApplied: s.appliedPayload(),
		warnings:    warnings,
	})
	if err != nil {
		return Preview{}, err
	}

	out := Preview{Plan: plan, Warnings: append(warnings, status.Warnings...)}
	if subject != nil {
		out.Route = *subject
	}
	for _, step := range plan.Steps {
		if step.Kind == StepApplyRuleset && step.Payload != nil {
			out.Payload = step.Payload.Text()
		}
	}
	return out, nil
}

// nextPreviewID returns an identifier no stored rule uses.
func nextPreviewID(records []Record) int64 {
	highest := int64(0)
	for _, rec := range records {
		if rec.RouteRuleID > highest {
			highest = rec.RouteRuleID
		}
	}
	return highest + 1
}

func replaceRecord(records []Record, desired Record) []Record {
	out := make([]Record, 0, len(records))
	for _, rec := range records {
		if rec.RouteRuleID == desired.RouteRuleID {
			out = append(out, desired)
			continue
		}
		out = append(out, rec)
	}
	return out
}

func withoutRecord(records []Record, id int64) []Record {
	out := make([]Record, 0, len(records))
	for _, rec := range records {
		if rec.RouteRuleID == id {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// ---------------------------------------------------------------- lifecycle

// validate applies the defaults and then every rule of §6, returning the
// warnings a successful validation produces.
func (s *Service) validate(ctx context.Context, in *validate.RouteInput) ([]validate.Warning, error) {
	if s.validator == nil {
		return nil, nil
	}
	if err := s.validator.ApplyDefaults(ctx, in); err != nil {
		return nil, err
	}
	result, err := s.validator.Validate(ctx, *in)
	if err != nil {
		return nil, err
	}
	if err := s.guardInput(ctx, *in); err != nil {
		return nil, err
	}
	return result.Warnings, nil
}

// guardInput applies the §6.3 invariants to a rule before it is stored.
//
// The invariants are also enforced on the whole desired ruleset immediately
// before an apply, which is what keeps them unreachable by any code path. But
// that check happens after the rule has been written, and a rule the guard
// forbids can never be applied — so leaving it in the database wedges the
// subsystem: every later apply re-reads it, fails on it again, and reports a
// port the operator did not name. Refusing here costs one pure conversion and
// means a forbidden rule never reaches the database at all.
func (s *Service) guardInput(ctx context.Context, in validate.RouteInput) error {
	if s.guard == nil {
		return nil
	}
	return s.guard.CheckRoute(ctx, RecordFrom(in).Spec())
}

// Create validates, stores, plans, applies and verifies a new rule, putting the
// previous ruleset back on any verification failure (§7).
func (s *Service) Create(ctx context.Context, req Request) (Result, error) {
	in := req.RouteInput
	in.RouteRuleID = 0
	// Validation runs before the lock is taken: it changes nothing, and a
	// malformed request should not have to queue behind a running apply.
	warnings, err := s.validate(ctx, &in)
	if err != nil {
		return Result{}, err
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	previous, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}
	id, err := s.repo.Insert(ctx, in)
	if err != nil {
		return Result{}, err
	}
	stored, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	result, err := s.apply(ctx, OpCreate, &stored, previous, warnings, trace)
	if err != nil {
		return Result{}, err
	}
	s.notifyChanged()
	return result, nil
}

// Update applies a change to an existing rule.
func (s *Service) Update(ctx context.Context, id int64, req Request) (Result, error) {
	if _, err := s.repo.ByID(ctx, id); err != nil {
		return Result{}, err
	}
	in := req.RouteInput
	in.RouteRuleID = id
	warnings, err := s.validate(ctx, &in)
	if err != nil {
		return Result{}, err
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	previous, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}
	if err := s.repo.Update(ctx, id, in); err != nil {
		return Result{}, err
	}
	stored, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	result, err := s.apply(ctx, OpUpdate, &stored, previous, warnings, trace)
	if err != nil {
		return Result{}, err
	}
	s.notifyChanged()
	return result, nil
}

// DeleteReport says exactly what was removed.
type DeleteReport struct {
	RouteRuleID int64             `json:"route_rule_id"`
	Title       string            `json:"title"`
	Plan        Plan              `json:"plan"`
	Verify      VerifyReport      `json:"verification"`
	Operations  []audit.Operation `json:"operations,omitempty"`
	// ForwardingCanBeReverted reports that this was the last rule and the panel
	// turned forwarding on. It is an offer, never an action (§2.3).
	ForwardingCanBeReverted bool `json:"forwarding_can_be_reverted"`
}

// Delete removes a rule and rebuilds the ruleset without it.
func (s *Service) Delete(ctx context.Context, id int64, req Request) (DeleteReport, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return DeleteReport{}, err
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return DeleteReport{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	previous, err := s.repo.List(ctx)
	if err != nil {
		return DeleteReport{}, err
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return DeleteReport{}, err
	}

	report := DeleteReport{RouteRuleID: id, Title: rec.RouteRuleTitle}
	result, err := s.applyRecords(ctx, OpDelete, &rec, withoutRecord(previous, id), previous, nil, trace)
	report.Plan = result.Plan
	report.Verify = result.Verify
	report.Operations = trace.Operations()
	if err != nil {
		return report, err
	}

	if s.counters != nil {
		if err := s.counters.Forget(ctx, id); err != nil {
			s.log.Error("forgetting the traffic counters of a deleted rule failed",
				"route_rule_id", id, "error", err)
		}
	}
	if len(withoutRecord(previous, id)) == 0 && s.forwarding != nil {
		status := s.forwarding.Status(ctx, false, 0, 0)
		report.ForwardingCanBeReverted = status.CanRevert
	}
	s.notifyChanged()
	return report, nil
}

// SetEnabled turns a rule on or off without deleting it, rebuilding the ruleset
// either way (§7).
func (s *Service) SetEnabled(ctx context.Context, id int64, enabled bool, req Request) (Result, error) {
	if _, err := s.repo.ByID(ctx, id); err != nil {
		return Result{}, err
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	previous, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}
	if err := s.repo.SetEnabled(ctx, id, enabled); err != nil {
		return Result{}, err
	}
	stored, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	operation := OpEnable
	if !enabled {
		operation = OpDisable
	}
	result, err := s.apply(ctx, operation, &stored, previous, nil, trace)
	if err != nil {
		return Result{}, err
	}
	s.notifyChanged()
	return result, nil
}

// Reapply re-renders and re-installs the whole ruleset from the stored state,
// which is the remedy for drift (§9).
func (s *Service) Reapply(ctx context.Context, id int64, req Request) (Result, error) {
	var subject *Record
	if id != 0 {
		stored, err := s.repo.ByID(ctx, id)
		if err != nil {
			return Result{}, err
		}
		subject = &stored
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	stored, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}
	operation := OpReapply
	if id == 0 {
		operation = OpApplyAll
	}
	// Reapplying installs the stored state over whatever is there now, so the
	// state before and after are the same: there is nothing to roll back to
	// except the same ruleset.
	result, err := s.applyRecords(ctx, operation, subject, stored, stored, nil, trace)
	if err != nil {
		return Result{}, err
	}
	s.notifyChanged()
	return result, nil
}

// ApplyAll installs every enabled rule as one transaction, which is what
// editing several rules produces: one apply, not one per rule (§7).
func (s *Service) ApplyAll(ctx context.Context, req Request) (Result, error) {
	return s.Reapply(ctx, 0, req)
}

// Reorder writes a new emission order and reinstalls the ruleset, because the
// order rules are emitted in is what decides which of two overlapping rules
// matches first.
func (s *Service) Reorder(ctx context.Context, ids []int64, req Request) (Result, error) {
	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	previous, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}
	if err := s.repo.Reorder(ctx, ids); err != nil {
		return Result{}, err
	}
	desired, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}

	result, err := s.applyRecords(ctx, OpReorder, nil, desired, previous, nil, trace)
	if err != nil {
		return Result{}, err
	}
	s.notifyChanged()
	return result, nil
}

// Duplicate clones a rule as a starting point for a similar one (§7).
//
// The clone is created disabled and with a free name and a free port, because
// an exact copy of an enabled rule would claim the same listener and be refused
// — and because a copy is something an operator is about to edit.
func (s *Service) Duplicate(ctx context.Context, id int64, req Request) (Result, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	in := Input(rec)
	in.RouteRuleID = 0
	in.IsEnabled = false
	in.SortOrder = 0
	title := strings.TrimSpace(req.RouteRuleTitle)
	if title == "" {
		title, err = s.freeTitle(ctx, rec.RouteRuleTitle)
		if err != nil {
			return Result{}, err
		}
	}
	in.RouteRuleTitle = title

	warnings, err := s.validate(ctx, &in)
	if err != nil {
		return Result{}, err
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	newID, err := s.repo.Insert(ctx, in)
	if err != nil {
		return Result{}, err
	}
	stored, err := s.repo.ByID(ctx, newID)
	if err != nil {
		return Result{}, err
	}
	// The clone is disabled, so it installs nothing and there is nothing to
	// verify against the kernel. Saying that plainly is better than running an
	// apply that changes nothing.
	return Result{
		Route: stored, Warnings: warnings, Operations: trace.Operations(),
		Plan: Plan{Operation: OpDuplicate, RouteRuleID: newID, Title: stored.RouteRuleTitle,
			Backend: s.backend.Name()},
		Verify: VerifyReport{Ok: true, Checks: []VerifyCheck{{
			Name: CheckRulesPresent, Ok: true, Skipped: true,
			Detail: "the copy is disabled, so it installs no rules yet",
		}}},
	}, nil
}

// freeTitle finds a name the copy can have.
func (s *Service) freeTitle(ctx context.Context, original string) (string, error) {
	for i := 2; i < 100; i++ {
		candidate := fmt.Sprintf("%s (copy %d)", original, i)
		if i == 2 {
			candidate = original + " (copy)"
		}
		if len(candidate) > validate.MaxRouteTitleLength {
			candidate = candidate[:validate.MaxRouteTitleLength]
		}
		taken, err := s.repo.TitleExists(ctx, candidate, 0)
		if err != nil {
			return "", err
		}
		if !taken {
			return candidate, nil
		}
	}
	return "", errors.New("route: every copy name is taken; rename the original first")
}

// ---------------------------------------------------------------- pipeline

// apply is the plan → guard → apply → verify → commit or rollback half of the
// pipeline for an operation about one rule.
func (s *Service) apply(ctx context.Context, operation string, subject *Record,
	previous []Record, warnings []validate.Warning, trace *audit.Trace) (Result, error) {

	desired, err := s.repo.List(ctx)
	if err != nil {
		return Result{}, err
	}
	return s.applyRecords(ctx, operation, subject, desired, previous, warnings, trace)
}

// applyRecords installs a desired set of records, rolling back to the previous
// one if anything fails.
func (s *Service) applyRecords(ctx context.Context, operation string, subject *Record,
	desired, previous []Record, warnings []validate.Warning, trace *audit.Trace) (Result, error) {

	status := s.forwardingStatus(ctx, desired)
	plan, err := s.planner.Plan(planInput{
		operation: operation, desired: desired, previous: previous, subject: subject,
		forwardingOn: status.IPv4Forwarding, ipv6ForwardingOn: status.IPv6Forwarding,
		retired:     s.retiredCounters(ctx, desired),
		liveChains:  s.liveChains(ctx),
		lastApplied: s.appliedPayload(),
		warnings:    warnings,
	})
	if err != nil {
		return Result{}, err
	}

	// The invariants are checked here, immediately before anything runs, and
	// not only at the API boundary: a code path that reaches this function has
	// already passed the handlers, and the invariants still hold (§6.3).
	if err := s.guardPlan(ctx, plan, desired); err != nil {
		s.recordStatus(ctx, plan.AffectedRouteRuleIDs, model.ApplyStatusFailed, err)
		return Result{}, err
	}

	applyErr := s.execute(ctx, plan.Steps)

	var report VerifyReport
	if applyErr == nil {
		report = s.Verify(ctx, desired, plan)
		if !report.Ok {
			applyErr = fmt.Errorf("verification failed: %s", strings.Join(report.Failures, "; "))
		}
	}

	if applyErr == nil {
		// This payload is now the one to put back if a later change is refused:
		// the kernel took it and the read-back agreed.
		s.rememberApplied(plan)
		s.recordStatus(ctx, plan.AffectedRouteRuleIDs, model.ApplyStatusApplied, nil)
		result := Result{
			Plan: plan, Verify: report,
			Warnings:   append(append([]validate.Warning(nil), warnings...), report.Warnings()...),
			Operations: trace.Operations(),
		}
		if subject != nil {
			if stored, err := s.repo.ByID(ctx, subject.RouteRuleID); err == nil {
				result.Route = stored
			} else {
				result.Route = *subject
			}
		}
		return result, nil
	}

	// Something failed. Putting the previous ruleset back is one transaction of
	// exactly the same kind, and whether it worked decides whether this is a
	// clean failure or an inconsistent host.
	rollbackErr := s.execute(ctx, plan.Rollback)
	if rollbackErr != nil {
		s.recordStatus(ctx, plan.AffectedRouteRuleIDs, model.ApplyStatusInconsistent, applyErr)
		return Result{Plan: plan, Verify: report}, &InconsistentError{
			Operation:     operation,
			ApplyError:    applyErr.Error(),
			RollbackError: rollbackErr.Error(),
			Remediation:   s.remediation(),
		}
	}

	s.recordStatus(ctx, plan.AffectedRouteRuleIDs, model.ApplyStatusFailed, applyErr)
	return Result{Plan: plan, Verify: report}, &ApplyError{
		Operation: operation, Cause: applyErr.Error(), Stderr: stderrOf(applyErr),
		Verify: report, RolledBack: true,
		Title: titleOf(subject),
	}
}

func titleOf(subject *Record) string {
	if subject == nil {
		return ""
	}
	return subject.RouteRuleTitle
}

// stderrOf pulls the backend's own message out of a wrapped error, which is
// what an operator needs to see when a ruleset is refused.
func stderrOf(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if _, after, ok := strings.Cut(message, ": "); ok {
		return after
	}
	return message
}

// guardPlan applies the §6.3 invariants to the whole desired ruleset and to
// every path the plan would write.
func (s *Service) guardPlan(ctx context.Context, plan Plan, desired []Record) error {
	if s.guard == nil {
		return nil
	}
	if err := s.guard.CheckRuleset(ctx, DesiredOf(desired)); err != nil {
		return err
	}
	for _, step := range plan.Steps {
		if len(step.Argv) > 0 {
			if err := safety.CheckArgv(step.Argv); err != nil {
				return err
			}
		}
		if step.Payload != nil {
			for _, part := range step.Payload.Parts {
				if err := s.guard.CheckPath(part.Path); err != nil {
					return err
				}
				if err := safety.CheckArgv(part.Argv); err != nil {
					return err
				}
			}
			for _, assertion := range step.Payload.Assertions {
				if err := safety.CheckArgv(assertion.Install); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// execute runs the steps of a plan in order, stopping at the first failure of a
// step that is not marked tolerant.
func (s *Service) execute(ctx context.Context, steps []Step) error {
	for _, step := range steps {
		err := s.runStep(ctx, step)
		if err == nil {
			continue
		}
		if step.Tolerate {
			s.log.Debug("tolerated a failed plan step", "step", step.Kind, "error", err)
			continue
		}
		return fmt.Errorf("%s (%s): %w", step.Description, step.Kind, err)
	}
	return nil
}

// runStep carries out one step.
func (s *Service) runStep(ctx context.Context, step Step) error {
	switch step.Kind {
	case StepSnapshotCounters:
		if s.counters == nil {
			return nil
		}
		if err := s.counters.Snapshot(ctx); err != nil {
			// Losing an interval of accounting is not a reason to refuse to
			// install a ruleset, so this is reported and not fatal.
			s.log.Error("snapshotting the traffic counters before a rebuild failed", "error", err)
		}
		return nil

	case StepEnableForwarding:
		if s.forwarding == nil {
			return nil
		}
		if s.settings != nil && !s.settings.Bool("routes.auto_enable_ip_forward") {
			s.log.Warn("kernel forwarding is off and routes.auto_enable_ip_forward is disabled, " +
				"so the rules will be installed and carry nothing")
			return nil
		}
		return s.forwarding.Enable(ctx, s.needsIPv6(ctx))

	case StepApplyRuleset:
		if step.Payload == nil {
			return errors.New("the plan step has no ruleset to apply")
		}
		return s.backend.Apply(ctx, *step.Payload)

	case StepWriteUnit:
		if s.store == nil {
			return nil
		}
		_, err := s.store.Write(ctx, step.Path, step.Content, false)
		return err

	case StepDaemonReload:
		if s.store == nil || !s.store.SystemdAvailable() {
			return nil
		}
		return s.store.DaemonReload(ctx)

	case StepEnableUnit:
		if s.store == nil || !s.store.SystemdAvailable() {
			return nil
		}
		return s.store.Enable(ctx, step.Unit)
	}
	return fmt.Errorf("unknown plan step %q", step.Kind)
}

func (s *Service) needsIPv6(ctx context.Context) bool {
	desired, err := s.repo.Desired(ctx)
	if err != nil {
		return false
	}
	return desired.HasIPv6()
}

func (s *Service) recordStatus(ctx context.Context, ids []int64, statusID int64, cause error) {
	if len(ids) == 0 || s.repo == nil {
		return
	}
	if err := s.repo.SetApplyStatusAll(ctx, ids, statusID, cause); err != nil {
		s.log.Error("recording the apply status failed", "error", err)
	}
}

// forwardingStatus reads the kernel parameters, tolerating a host where they
// cannot be read.
func (s *Service) forwardingStatus(ctx context.Context, desired []Record) ForwardingStatus {
	if s.forwarding == nil {
		return ForwardingStatus{IPv4Forwarding: true, IPv6Forwarding: true}
	}
	ruleset := DesiredOf(desired)
	warnPercent := 0.0
	if s.settings != nil {
		warnPercent = s.settings.Float("routes.warn_conntrack_usage_percent")
	}
	return s.forwarding.Status(ctx, ruleset.HasIPv6(), len(ruleset.Routes), warnPercent)
}

// remediation returns the exact commands an operator should run after a failed
// rollback. Handing over a list of commands is the least a panel that has left
// a host inconsistent can do (§7).
func (s *Service) remediation() []string {
	caps := s.backend.Capabilities()
	commands := []string{}
	switch s.backend.Name() {
	case rules.BackendNftables:
		nft := caps.Binaries["nft"]
		if nft == "" {
			nft = rules.DefaultNftBin
		}
		commands = append(commands,
			fmt.Sprintf("%s list table %s %s", nft, rules.TableFamily, rules.TableName),
			fmt.Sprintf("%s delete table %s %s", nft, rules.TableFamily, rules.TableName),
			fmt.Sprintf("%s -f %s", nft, s.rulesetPath()),
		)
	default:
		iptables := caps.Binaries["iptables"]
		if iptables == "" {
			iptables = rules.DefaultIptablesBin
		}
		restore := caps.Binaries["iptables-restore"]
		if restore == "" {
			restore = rules.DefaultIptablesRestoreBin
		}
		for _, chain := range rules.OwnedChains() {
			commands = append(commands, fmt.Sprintf("%s -S %s", iptables, chain))
		}
		commands = append(commands, fmt.Sprintf("%s --noflush %s", restore, s.rulesetPath()))
	}
	if s.store != nil && s.store.SystemdAvailable() {
		commands = append(commands, "systemctl restart "+persist.RulesUnitName)
	}
	return commands
}

// rememberApplied keeps the ruleset payload of a plan that has just been
// applied and verified, so a later failure can put this exact text back.
func (s *Service) rememberApplied(plan Plan) {
	for _, step := range plan.Steps {
		if step.Kind != StepApplyRuleset || step.Payload == nil {
			continue
		}
		payload := *step.Payload
		s.appliedMu.Lock()
		s.lastApplied = &payload
		s.appliedMu.Unlock()
		return
	}
}

// appliedPayload is the last ruleset this host accepted, or nil when nothing
// has been applied since the panel started.
func (s *Service) appliedPayload() *rules.Payload {
	s.appliedMu.Lock()
	defer s.appliedMu.Unlock()
	return s.lastApplied
}

// retiredCounters reports which rules the kernel still holds counters for and
// the panel no longer has, so the transaction that rebuilds the ruleset removes
// them.
//
// It is deliberately best effort: an unreadable counter list is a reason to
// leave the objects alone, never a reason to refuse a change the operator
// asked for. A disabled rule keeps its counters, because it still exists and
// re-enabling it should not look like the traffic never happened.
func (s *Service) retiredCounters(ctx context.Context, known []Record) []int64 {
	live, err := s.backend.Counters(ctx)
	if err != nil || len(live) == 0 {
		return nil
	}
	stored := make(map[int64]bool, len(known))
	for _, rec := range known {
		stored[rec.RouteRuleID] = true
	}
	var retired []int64
	for id := range live {
		if !stored[id] {
			retired = append(retired, id)
		}
	}
	return retired
}

// liveChains reports the chains the kernel currently holds in the panel's own
// namespace, so the transaction that rebuilds the ruleset also removes the ones
// it no longer declares.
//
// Flushing the panel's table empties its chains but does not remove them, so
// without this a chain an older build rendered survives every apply and the
// kernel's shape becomes a function of the host's install history. Two hosts
// running the identical binary then hold different tables, which is precisely
// the asymmetry that lets a defect ship on one and not the other.
//
// Best effort, like retiredCounters: an inventory that could not be read is a
// reason to leave the kernel alone, never a reason to refuse the operator's
// change.
func (s *Service) liveChains(ctx context.Context) []string {
	live, err := s.backend.ReadBack(ctx)
	if err != nil {
		return nil
	}
	return live.Chains
}

// hasStaleChains reports whether the kernel holds panel-owned chains that the
// stored rules do not account for.
//
// It exists so the startup pass can tell "this host has no forwarding rules and
// no table, leave it alone" apart from "this host has no forwarding rules but is
// still carrying chains an older build left hooked into the kernel". The first
// must create nothing; the second is exactly what startup is for. The question
// is put to the renderer rather than answered here, because which chain names
// the panel owns is the backend's business and not the service's.
func (s *Service) hasStaleChains(ctx context.Context) bool {
	chains := s.liveChains(ctx)
	if len(chains) == 0 {
		return false
	}
	payload, err := s.backend.Render(rules.Ruleset{LiveChains: chains})
	if err != nil {
		return false
	}
	return len(payload.RemovesChains) > 0
}

// rulesetPath is where the current rendered ruleset lives.
func (s *Service) rulesetPath() string {
	payload, err := s.backend.Render(rules.Ruleset{})
	if err != nil || len(payload.Parts) == 0 {
		return rules.DefaultDir + "/" + rules.NftFileName
	}
	return payload.Parts[0].Path
}

// ---------------------------------------------------------------- startup

// Reassert installs the stored ruleset at startup, which is what makes the
// panel's own state authoritative after a reboot or after something else
// changed the ruleset while the panel was not running (§2.2).
//
// It is deliberately quiet when there is nothing to do: a host with no
// forwarding rules must not have a table created for it.
func (s *Service) Reassert(ctx context.Context) error {
	if s.repo == nil {
		return nil
	}
	records, err := s.repo.List(ctx)
	if err != nil {
		return err
	}
	enabled := DesiredOf(records)
	if len(enabled.Routes) == 0 && !s.hasStaleChains(ctx) {
		return nil
	}

	release, err := s.mutation.Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	started := time.Now()
	if _, err := s.applyRecords(ctx, OpReapply, nil, records, records, nil, trace); err != nil {
		return err
	}
	s.log.Info("forwarding rules reasserted at startup",
		"rules", len(enabled.Routes), "backend", s.backend.Name(),
		"duration_ms", time.Since(started).Milliseconds())
	s.notifyChanged()
	return nil
}
