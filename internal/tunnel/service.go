// Package tunnel owns the tunnel lifecycle: validate → plan → apply → verify →
// commit or rollback (§9.1).
//
// The rule the whole package exists to enforce is the one the legacy script
// broke: never report success without verifying reality. After every apply the
// kernel is read back and compared against what was asked for, and any
// mismatch rolls the change back rather than returning a tunnel that is not
// actually up.
//
// This package contains no HTTP concerns. Handlers translate; services act.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/lock"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/safety"
	"github.com/drs/gre-panel/internal/validate"
)

// Settings is the slice of the settings store this package reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	IntPtr(key string) *int64
	Float(key string) float64
	String(key string) string
	StringMap(key string) map[string]string
}

// Deps is everything the service needs. Every dependency is an interface or a
// value the caller constructs, so the whole pipeline runs hermetically against
// the fake link manager and the fake process runner.
type Deps struct {
	Repo          *Repo
	Links         link.LinkManager
	Runner        exec.Runner
	Renderer      *persist.Renderer
	Store         *persist.Store
	Alloc         *alloc.Allocator
	Validator     *validate.Validator
	Guard         *safety.Guard
	Settings      Settings
	Log           *slog.Logger
	IPBin         string
	SystemctlBin  string
	NetworkctlBin string
	// PeerProber probes the far end after an apply. The result is reported and
	// never fatal, because the other end may legitimately not be configured yet
	// (§9.3). A nil prober reports the check as not run rather than as passed.
	PeerProber PeerProber
	// Mutation is the global mutation lock (§16). It is passed in rather than
	// created here because the forwarding subsystem changes the same kernel and
	// has to queue behind the same lock. A nil value gets a private one, which
	// is what a test that exercises tunnels alone wants.
	Mutation *lock.Mutation
}

// Service carries out tunnel operations.
type Service struct {
	repo      *Repo
	links     link.LinkManager
	runner    exec.Runner
	renderer  *persist.Renderer
	store     *persist.Store
	alloc     *alloc.Allocator
	validator *validate.Validator
	guard     *safety.Guard
	settings  Settings
	log       *slog.Logger
	planner   *planner

	// mutation is the global mutation lock of §16, shared with every other
	// subsystem that changes kernel state.
	mutation *lock.Mutation

	idempotency *idempotencyCache

	// mu guards the dependencies wired after construction, because the
	// subsystems that supply them are built after this service is.
	mu       sync.Mutex
	observer Observer
	prober   PeerProber
	// routes and monitorState are the forwarding subsystem and the prober's
	// verdict. Both are optional: without them a tunnel behaves exactly as it
	// did before forwarding rules existed.
	routes       RouteDependants
	monitorState func(tunnelID int64) (string, bool)
}

// New builds the service.
func New(d Deps) *Service {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	mutation := d.Mutation
	if mutation == nil {
		mutation = lock.New()
	}
	s := &Service{
		repo:      d.Repo,
		links:     d.Links,
		runner:    d.Runner,
		renderer:  d.Renderer,
		store:     d.Store,
		alloc:     d.Alloc,
		validator: d.Validator,
		guard:     d.Guard,
		settings:  d.Settings,
		log:       log,
		observer:  nil,
		prober:    d.PeerProber,
		mutation:  mutation,
		planner: &planner{
			renderer:      d.Renderer,
			store:         d.Store,
			ipBin:         orDefault(d.IPBin, persist.DefaultIPBin),
			systemctlBin:  orDefault(d.SystemctlBin, "/bin/systemctl"),
			networkctlBin: d.NetworkctlBin,
		},
		idempotency: newIdempotencyCache(),
	}
	return s
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

// Observer is told when the set of tunnels changes.
//
// The monitoring supervisor implements it, which is what makes a prober start
// or stop the moment a tunnel is created, deleted, enabled or disabled rather
// than at the next sweep (§10.3).
type Observer interface {
	TunnelsChanged()
}

// SetObserver registers the observer notified after every successful change.
func (s *Service) SetObserver(observer Observer) {
	s.mu.Lock()
	s.observer = observer
	s.mu.Unlock()
}

// SetPeerProber supplies the reachability probe verification uses (§9.3).
//
// It is injected rather than built here so there is one ICMP implementation in
// the codebase rather than two that could disagree.
func (s *Service) SetPeerProber(prober PeerProber) {
	s.mu.Lock()
	s.prober = prober
	s.mu.Unlock()
}

// peerProber returns the reachability probe in force, which is wired after
// construction because the subsystem that supplies it is built later.
func (s *Service) peerProber() PeerProber {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prober
}

// notifyChanged tells the observer that the tunnels have moved.
func (s *Service) notifyChanged() {
	s.mu.Lock()
	observer := s.observer
	s.mu.Unlock()
	if observer != nil {
		observer.TunnelsChanged()
	}
}

// Repo exposes the repository for the read paths, which never take the
// mutation lock (§16).
func (s *Service) Repo() *Repo { return s.repo }

// Links exposes the link manager for the read paths.
func (s *Service) Links() link.LinkManager { return s.links }

// Alloc exposes the allocator.
func (s *Service) Alloc() *alloc.Allocator { return s.alloc }

// lock takes the global mutation lock. Concurrent mutations never interleave;
// read paths never call this.
func (s *Service) lock(ctx context.Context) (func(), error) { return s.mutation.Acquire(ctx) }

// ---------------------------------------------------------------- requests

// Request is a create or update. It embeds the validated tunnel description and
// adds the confirmations some operations require.
type Request struct {
	validate.TunnelInput

	// ConfirmRecreate acknowledges that the change needs the interface deleted
	// and rebuilt, which briefly interrupts it (§9.6).
	ConfirmRecreate bool `json:"confirm_recreate,omitempty"`
	// IUnderstandIMayLoseAccess is the acknowledgement of §17.4, required when
	// the request arrives through the very tunnel it is about to change.
	IUnderstandIMayLoseAccess bool `json:"i_understand_i_may_lose_access,omitempty"`
	// Takeover permits rewriting a unit file the panel did not write. It is only
	// honoured for a tunnel that was adopted with it (§17.3).
	Takeover bool `json:"takeover,omitempty"`
	// KeepaliveEnabled overrides the keepalive default for this tunnel.
	KeepaliveEnabled *bool `json:"keepalive_enabled,omitempty"`
	// IdempotencyKey guards against a double submission (§16).
	IdempotencyKey string `json:"idempotency_key,omitempty"`

	// ClientIP is filled in by the handler, never by the client.
	ClientIP string `json:"-"`
}

// Result is what a completed operation returns.
type Result struct {
	Tunnel     Record             `json:"tunnel"`
	Plan       Plan               `json:"plan"`
	Verify     VerifyReport       `json:"verification"`
	Warnings   []validate.Warning `json:"warnings,omitempty"`
	Operations []audit.Operation  `json:"operations,omitempty"`
}

// Preview is the result of validate + plan with nothing carried out (§9.2).
type Preview struct {
	Plan     Plan               `json:"plan"`
	Warnings []validate.Warning `json:"warnings,omitempty"`
	Mtu      validate.MtuAdvice `json:"mtu"`
	Diffs    []Diff             `json:"diffs,omitempty"`
	Tunnel   Record             `json:"tunnel"`
}

// RecreateRequiredError is returned when a change cannot be applied to the
// running interface and the request has not confirmed the rebuild (§9.6).
type RecreateRequiredError struct {
	Interface string   `json:"interface"`
	Reasons   []string `json:"reasons"`
}

func (e *RecreateRequiredError) Error() string {
	return fmt.Sprintf("changing %s needs the interface deleted and rebuilt: %s",
		e.Interface, strings.Join(e.Reasons, "; "))
}

// InconsistentError is returned when an apply failed and the rollback failed
// too. The panel does not pretend otherwise: the tunnel is recorded as
// Inconsistent, and the exact commands to put the host right are returned
// (§9.3).
type InconsistentError struct {
	Interface     string   `json:"interface"`
	TunnelID      int64    `json:"tunnel_id"`
	ApplyError    string   `json:"apply_error"`
	RollbackError string   `json:"rollback_error"`
	Remediation   []string `json:"remediation"`
	Journal       string   `json:"journal,omitempty"`
}

func (e *InconsistentError) Error() string {
	return fmt.Sprintf("%s could not be configured and could not be cleaned up either: %s "+
		"(rollback also failed: %s)", e.Interface, e.ApplyError, e.RollbackError)
}

// ApplyError is a plain apply failure that was rolled back successfully.
type ApplyError struct {
	Interface  string       `json:"interface"`
	Step       string       `json:"step"`
	Cause      string       `json:"cause"`
	Journal    string       `json:"journal,omitempty"`
	Verify     VerifyReport `json:"verification"`
	RolledBack bool         `json:"rolled_back"`
}

func (e *ApplyError) Error() string {
	if e.Step != "" {
		return fmt.Sprintf("%s: %s failed: %s", e.Interface, e.Step, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Interface, e.Cause)
}

// ---------------------------------------------------------------- defaults

// ApplyDefaults fills in every field the request left unset from the settings,
// so a minimal request produces a complete, explicit tunnel (§5.3).
func (s *Service) ApplyDefaults(ctx context.Context, in *validate.TunnelInput) error {
	// What the request itself got wrong is rejected here, before a default is
	// chosen and before anything is read. Allocating a subnet reads kernel state,
	// so without this an unparseable endpoint would still cost a kernel call
	// before being refused — and the whole point of §7.2 is that it does not.
	if errs := validate.ValidateSupplied(*in); !errs.Empty() {
		return errs
	}

	if in.TunnelTypeID == 0 {
		in.TunnelTypeID = s.settings.Int("tunnel.default_type")
	}
	if in.TunnelSideID == 0 {
		in.TunnelSideID = model.TunnelSideA
	}
	if in.PersistenceTypeID == 0 {
		in.PersistenceTypeID = s.settings.Int("tunnel.default_persistence")
	}
	if in.Mtu == 0 {
		in.Mtu = s.settings.Int("tunnel.default_mtu")
	}
	if in.Ttl == 0 {
		in.Ttl = s.settings.Int("tunnel.default_ttl")
	}
	if strings.TrimSpace(in.Tos) == "" {
		in.Tos = s.settings.String("tunnel.default_tos")
	}
	// The default key is applied only when creating. On an update, no key is a
	// deliberate instruction — an operator clearing the keys means it — and
	// putting the default back would silently undo it.
	if in.TunnelID == 0 && in.IKey == nil && in.OKey == nil {
		if key := s.settings.IntPtr("tunnel.default_key"); key != nil {
			value := *key
			in.IKey = &value
			second := *key
			in.OKey = &second
		}
	}

	if in.AddressPoolID == nil && len(in.Addresses) == 0 {
		pool, err := s.alloc.DefaultPool(ctx)
		if err != nil {
			return err
		}
		in.AddressPoolID = &pool.AddressPoolID
	}

	// Allocate a subnet when the request named no addresses of its own.
	if len(in.Addresses) == 0 && in.AddressPoolID != nil {
		pool, err := s.alloc.Repo.PoolByID(ctx, *in.AddressPoolID)
		if err != nil {
			return err
		}
		prefixLen := s.alloc.DefaultPrefixLength()

		var allocation alloc.Allocation
		if in.TunnelNumber != nil {
			allocation, err = alloc.At(pool, prefixLen, *in.TunnelNumber)
		} else {
			allocation, err = s.alloc.NextFree(ctx, pool, prefixLen)
		}
		if err != nil {
			return err
		}
		if in.TunnelNumber == nil {
			number := allocation.TunnelNumber
			in.TunnelNumber = &number
		}
		in.Addresses = []validate.AddressInput{{
			Address:      allocation.OwnAddress(in.TunnelSideID),
			PrefixLength: allocation.PrefixLength,
			PeerAddress:  allocation.PeerAddress(in.TunnelSideID),
			IsPrimary:    true,
		}}
	}

	if strings.TrimSpace(in.InterfaceName) == "" {
		name, err := s.RenderName(*in)
		if err != nil {
			return err
		}
		in.InterfaceName = name
	}
	return nil
}

// RenderName builds an interface name from the naming template, the side labels
// and the tunnel number (§5.3, §5.4).
func (s *Service) RenderName(in validate.TunnelInput) (string, error) {
	template := s.settings.String("tunnel.naming_template")
	if strings.TrimSpace(template) == "" {
		template = "gre-{side}-{number}"
	}
	labels := s.settings.StringMap("tunnel.side_labels")
	slot := model.SideSlot(in.TunnelSideID)
	label := labels[slot]
	if label == "" {
		label = slot
	}
	number := "0"
	if in.TunnelNumber != nil {
		number = fmt.Sprintf("%d", *in.TunnelNumber)
	}

	rendered := strings.NewReplacer(
		"{side}", label,
		"{number}", number,
		"{type}", model.TunnelTypeKind(in.TunnelTypeID),
	).Replace(template)

	if err := validate.InterfaceName(rendered); err != nil {
		return "", fmt.Errorf("the naming template %q with side label %q and number %s renders to %q, "+
			"which %s", template, label, number, rendered, err.Error())
	}
	return rendered, nil
}

// KeepaliveFor works out whether a tunnel gets a keepalive unit, and with what
// parameters (§9.5).
//
// With the default mode the answer is always no: the panel's own prober already
// sends continuous ICMP from the tunnel source address, so it is a keepalive,
// and a second one would be one process per tunnel for nothing.
func (s *Service) KeepaliveFor(rec Record, override *bool) KeepaliveFor {
	if s.settings.String("keepalive.mode") != "systemd_unit" {
		return KeepaliveFor{Enabled: false}
	}
	enabled := s.settings.Bool("keepalive.enabled_by_default")
	if override != nil {
		enabled = *override
	}
	if !enabled || len(rec.Addresses) == 0 {
		return KeepaliveFor{Enabled: false}
	}

	primary := rec.Addresses[0]
	target := derefString(primary.PeerAddress)
	if target == "" {
		return KeepaliveFor{Enabled: false}
	}
	return KeepaliveFor{
		Enabled: true,
		Options: persist.KeepaliveOptions{
			Source:          primary.Address,
			Target:          target,
			IntervalSeconds: s.settings.Float("keepalive.interval_seconds"),
			PacketSize:      int(s.settings.Int("keepalive.packet_size")),
		},
	}
}

// ---------------------------------------------------------------- preview

// PreviewCreate runs validate and plan only, returning the exact operations and
// unit file bodies that would run (§9.2).
func (s *Service) PreviewCreate(ctx context.Context, req Request) (Preview, error) {
	in := req.TunnelInput
	if err := s.ApplyDefaults(ctx, &in); err != nil {
		return Preview{}, err
	}
	result, err := s.validator.Validate(ctx, in)
	if err != nil {
		return Preview{}, err
	}

	rec := RecordFromInput(in)
	plan := s.planner.PlanCreate(rec, s.KeepaliveFor(rec, req.KeepaliveEnabled), false)
	plan.Warnings = result.Warnings

	return Preview{Plan: plan, Warnings: result.Warnings, Mtu: result.Mtu, Tunnel: rec}, nil
}

// PreviewUpdate runs validate and plan for a change to an existing tunnel.
func (s *Service) PreviewUpdate(ctx context.Context, id int64, req Request) (Preview, error) {
	current, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Preview{}, err
	}
	desired, result, diffs, err := s.prepareUpdate(ctx, current, req)
	if err != nil {
		return Preview{}, err
	}

	plan := s.planner.PlanUpdate(current, desired, s.KeepaliveFor(desired, req.KeepaliveEnabled), diffs, req.Takeover)
	plan.Warnings = result.Warnings
	return Preview{Plan: plan, Warnings: result.Warnings, Mtu: result.Mtu, Diffs: diffs, Tunnel: desired}, nil
}

// prepareUpdate merges a request onto the stored tunnel and validates the
// result, returning the desired record and the field-by-field difference.
func (s *Service) prepareUpdate(ctx context.Context, current Record, req Request) (Record, validate.Result, []Diff, error) {
	in := req.TunnelInput
	in.TunnelID = current.TunnelID
	if err := s.ApplyDefaults(ctx, &in); err != nil {
		return Record{}, validate.Result{}, nil, err
	}

	result, err := s.validator.Validate(ctx, in)
	if err != nil {
		return Record{}, validate.Result{}, nil, err
	}

	desired := RecordFromInput(in)
	desired.TunnelID = current.TunnelID
	desired.IsManaged = current.IsManaged
	return desired, result, DiffTunnel(current, in), nil
}

// ---------------------------------------------------------------- create

// Create validates, plans, applies and verifies a new tunnel, rolling back on
// any verification failure (§9.1).
func (s *Service) Create(ctx context.Context, req Request) (Result, error) {
	if cached, ok := s.idempotency.get(req.IdempotencyKey); ok {
		return cached, nil
	}

	in := req.TunnelInput
	if err := s.ApplyDefaults(ctx, &in); err != nil {
		return Result{}, err
	}
	// Validation runs before the lock is taken: it changes nothing, and a
	// malformed request should not have to queue behind a running apply.
	validation, err := s.validator.Validate(ctx, in)
	if err != nil {
		return Result{}, err
	}

	release, err := s.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	id, err := s.repo.Insert(ctx, in, true, req.TunnelInput.InterfaceName == "")
	if err != nil {
		return Result{}, err
	}
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	plan := s.planner.PlanCreate(rec, s.KeepaliveFor(rec, req.KeepaliveEnabled), false)
	plan.Warnings = validation.Warnings

	result, err := s.run(ctx, rec, plan, req, trace)
	if err != nil {
		// The row is kept and marked failed rather than removed: an operator
		// needs to see what was attempted and why it did not work.
		return Result{}, err
	}
	result.Warnings = append(validation.Warnings, result.Warnings...)
	s.idempotency.put(req.IdempotencyKey, result)
	s.notifyChanged()
	return result, nil
}

// ---------------------------------------------------------------- update

// Update applies a change to an existing tunnel (§9.6).
func (s *Service) Update(ctx context.Context, id int64, req Request) (Result, error) {
	current, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	desired, validation, diffs, err := s.prepareUpdate(ctx, current, req)
	if err != nil {
		return Result{}, err
	}
	if len(diffs) == 0 {
		// Nothing the kernel would notice. Some fields are stored and never
		// applied — the monitoring overrides are read by the prober, not by ip
		// link — so "no kernel diff" is not the same as "nothing to write". The
		// early return used to cover both, which made an override that changed
		// only the probe interval return 200 and change nothing at all.
		if !storedFieldsDiffer(current, desired) {
			return Result{Tunnel: current, Plan: Plan{Operation: OpUpdate, Interface: current.InterfaceName}}, nil
		}
		if err := s.repo.Update(ctx, id, mergedInput(desired), desired.IsNameTemplated); err != nil {
			return Result{}, err
		}
		stored, err := s.repo.ByID(ctx, id)
		if err != nil {
			return Result{}, err
		}
		s.notifyChanged()
		return Result{
			Tunnel: stored,
			Plan:   Plan{Operation: OpUpdate, Interface: current.InterfaceName},
		}, nil
	}

	if recreate, reasons := RequiresRecreate(diffs); recreate && !req.ConfirmRecreate {
		return Result{}, &RecreateRequiredError{Interface: current.InterfaceName, Reasons: reasons}
	}

	// The request may be arriving through the very tunnel it is changing (§17.4).
	if err := safety.CheckClientConnection(req.ClientIP, AddressesOf(current), req.IUnderstandIMayLoseAccess); err != nil {
		return Result{}, err
	}

	release, err := s.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	plan := s.planner.PlanUpdate(current, desired, s.KeepaliveFor(desired, req.KeepaliveEnabled), diffs, req.Takeover)
	plan.Warnings = validation.Warnings

	if err := s.repo.Update(ctx, id, mergedInput(desired), desired.IsNameTemplated); err != nil {
		return Result{}, err
	}
	stored, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}

	result, err := s.run(ctx, stored, plan, req, trace)
	if err != nil {
		return Result{}, err
	}
	result.Warnings = append(validation.Warnings, result.Warnings...)
	s.notifyChanged()
	return result, nil
}

// storedFieldsDiffer reports whether a change touches something the database
// keeps but the kernel never sees: the per-tunnel monitoring overrides, which
// are resolved by monitor.ConfigFor at probe time rather than written to an
// interface, and the display name, which is only ever shown in the panel.
// Neither produces a kernel diff, so both would otherwise be dropped by the
// "nothing to do" path — renaming a tunnel and changing nothing else would
// return 200 and save nothing.
func storedFieldsDiffer(current, desired Record) bool {
	sameFloat := func(a, b *float64) bool {
		switch {
		case a == nil && b == nil:
			return true
		case a == nil || b == nil:
			return false
		default:
			return *a == *b
		}
	}
	sameInt := func(a, b *int64) bool {
		switch {
		case a == nil && b == nil:
			return true
		case a == nil || b == nil:
			return false
		default:
			return *a == *b
		}
	}
	return derefString(current.DisplayName) != derefString(desired.DisplayName) ||
		!sameFloat(current.MonitorIntervalSeconds, desired.MonitorIntervalSeconds) ||
		!sameFloat(current.MonitorTimeoutSeconds, desired.MonitorTimeoutSeconds) ||
		!sameInt(current.MonitorPacketSize, desired.MonitorPacketSize) ||
		!sameInt(current.MonitorWindowSize, desired.MonitorWindowSize) ||
		!sameFloat(current.MonitorDegradedLossPercent, desired.MonitorDegradedLossPercent) ||
		!sameFloat(current.MonitorDownLossPercent, desired.MonitorDownLossPercent) ||
		!sameFloat(current.MonitorDegradedRttMs, desired.MonitorDegradedRttMs) ||
		!sameInt(current.MonitorStateChangeSamples, desired.MonitorStateChangeSamples)
}

// mergedInput turns a record back into the request shape the repository writes.
func mergedInput(rec Record) validate.TunnelInput {
	in := validate.TunnelInput{
		TunnelID:          rec.TunnelID,
		TunnelTypeID:      rec.TunnelTypeID,
		TunnelSideID:      rec.TunnelSideID,
		PersistenceTypeID: rec.PersistenceTypeID,
		InterfaceName:     rec.InterfaceName,
		DisplayName:       derefString(rec.DisplayName),
		TunnelNumber:      rec.TunnelNumber,
		LocalEndpoint:     rec.LocalEndpoint,
		RemoteEndpoint:    rec.RemoteEndpoint,
		BindDevice:        derefString(rec.BindDevice),
		Ttl:               rec.Ttl,
		Tos:               rec.Tos,
		Mtu:               rec.Mtu,
		IKey:              rec.IKey,
		OKey:              rec.OKey,

		HasInputChecksum:  rec.HasInputChecksum,
		HasOutputChecksum: rec.HasOutputChecksum,
		HasInputSequence:  rec.HasInputSequence,
		HasOutputSequence: rec.HasOutputSequence,

		IsPathMtuDiscovery: rec.IsPathMtuDiscovery,
		IsIgnoreDf:         rec.IsIgnoreDf,
		FwMark:             rec.FwMark,
		TxQueueLength:      rec.TxQueueLength,
		HopLimit:           rec.HopLimit,
		EncapLimit:         rec.EncapLimit,
		TrafficClass:       derefString(rec.TrafficClass),
		FlowLabel:          derefString(rec.FlowLabel),
		AddressPoolID:      rec.AddressPoolID,
		IsEnabled:          rec.IsEnabled,

		MonitorIntervalSeconds:     rec.MonitorIntervalSeconds,
		MonitorTimeoutSeconds:      rec.MonitorTimeoutSeconds,
		MonitorPacketSize:          rec.MonitorPacketSize,
		MonitorWindowSize:          rec.MonitorWindowSize,
		MonitorDegradedLossPercent: rec.MonitorDegradedLossPercent,
		MonitorDownLossPercent:     rec.MonitorDownLossPercent,
		MonitorDegradedRttMs:       rec.MonitorDegradedRttMs,
		MonitorStateChangeSamples:  rec.MonitorStateChangeSamples,
	}
	for _, a := range rec.Addresses {
		in.Addresses = append(in.Addresses, validate.AddressInput{
			Address:      a.Address,
			PrefixLength: int(a.PrefixLength),
			PeerAddress:  derefString(a.PeerAddress),
			IsPrimary:    a.IsPrimary,
		})
	}
	return in
}

// ---------------------------------------------------------------- delete

// DeleteReport says exactly what was and was not found, which delete must do
// even when it succeeds (§9.6).
type DeleteReport struct {
	TunnelID       int64             `json:"tunnel_id"`
	Interface      string            `json:"interface"`
	Plan           Plan              `json:"plan"`
	InterfaceFound bool              `json:"interface_found"`
	FilesRemoved   []string          `json:"files_removed"`
	FilesAbsent    []string          `json:"files_absent"`
	Operations     []audit.Operation `json:"operations,omitempty"`
	// Warnings carries what the deletion breaks that is not a tunnel, which
	// today means the forwarding rules that relayed traffic through it (§10).
	Warnings []validate.Warning `json:"warnings,omitempty"`
	// DependentRoutes lists them, so the frontend can name them rather than
	// only counting them.
	DependentRoutes []DependentRoute `json:"dependent_routes,omitempty"`
}

// Delete removes a tunnel. It is idempotent when the interface is already gone,
// and reports exactly what it found (§9.6).
func (s *Service) Delete(ctx context.Context, id int64, req Request) (DeleteReport, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return DeleteReport{}, err
	}
	if err := safety.CheckClientConnection(req.ClientIP, AddressesOf(rec), req.IUnderstandIMayLoseAccess); err != nil {
		return DeleteReport{}, err
	}

	release, err := s.lock(ctx)
	if err != nil {
		return DeleteReport{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	_, interfaceFound := s.observe(ctx, rec.InterfaceName)
	report := DeleteReport{
		TunnelID: id, Interface: rec.InterfaceName, InterfaceFound: interfaceFound,
		FilesRemoved: []string{}, FilesAbsent: []string{},
	}
	// Forwarding rules that relayed through this tunnel keep their rules and
	// lose their path. Saying so is the difference between a deliberate change
	// and a relay that quietly stopped working (§10).
	report.DependentRoutes, _ = s.DependentRoutes(ctx, id)
	report.Warnings = s.routeDependencyWarning(ctx, id, rec, "away")

	keepalive := s.KeepaliveFor(rec, req.KeepaliveEnabled)
	plan := s.planner.PlanDelete(rec, keepalive.Enabled, req.Takeover)
	report.Plan = plan

	for _, step := range plan.Steps {
		if step.Kind == StepFileRemove {
			if persist.Exists(step.Path) {
				report.FilesRemoved = append(report.FilesRemoved, step.Path)
			} else {
				report.FilesAbsent = append(report.FilesAbsent, step.Path)
			}
		}
	}

	// The invariants are checked here, immediately before anything runs, and not
	// only at the API boundary. Delete is the most destructive operation the
	// panel has, so it is the last place to take that on trust (§17).
	if err := s.guardPlan(ctx, plan, rec, req.Takeover); err != nil {
		return report, err
	}
	if err := s.execute(ctx, plan.Steps, rec, req.Takeover); err != nil {
		return report, err
	}
	// The interface really must be gone; delete is the one operation where
	// "probably" is not good enough.
	if _, stillThere := s.observe(ctx, rec.InterfaceName); stillThere {
		return report, &ApplyError{
			Interface: rec.InterfaceName,
			Cause:     "the interface is still present after every removal step ran",
		}
	}
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return report, err
	}
	report.Operations = trace.Operations()
	s.notifyChanged()
	return report, nil
}

// ---------------------------------------------------------------- state

// Up brings a tunnel up (§9.6).
func (s *Service) Up(ctx context.Context, id int64, req Request) (Result, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if _, exists := s.observe(ctx, rec.InterfaceName); !exists {
		// The interface is gone entirely, so bringing it up means building it
		// again from the stored desired state.
		return s.Reapply(ctx, id, req)
	}

	release, err := s.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	if err := s.repo.SetEnabled(ctx, id, true); err != nil {
		return Result{}, err
	}
	rec.IsEnabled = true
	defer s.notifyChanged()
	return s.run(ctx, rec, s.planner.PlanUp(rec), req, trace)
}

// Down takes a tunnel down without removing it (§9.6).
func (s *Service) Down(ctx context.Context, id int64, req Request) (Result, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if err := safety.CheckClientConnection(req.ClientIP, AddressesOf(rec), req.IUnderstandIMayLoseAccess); err != nil {
		return Result{}, err
	}

	release, err := s.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	plan := s.planner.PlanDown(rec)
	if err := s.guardPlan(ctx, plan, rec, req.Takeover); err != nil {
		return Result{}, err
	}
	if err := s.execute(ctx, plan.Steps, rec, req.Takeover); err != nil {
		return Result{}, err
	}
	if err := s.repo.SetEnabled(ctx, id, false); err != nil {
		return Result{}, err
	}

	rec.IsEnabled = false
	report := s.verifyDown(ctx, rec)
	s.notifyChanged()
	return Result{
		Tunnel: rec, Plan: plan, Verify: report, Operations: trace.Operations(),
		// The forwarding rules crossing this tunnel are still installed and
		// still correct; what they relayed over has just gone (§10).
		Warnings: s.routeDependencyWarning(ctx, id, rec, "down"),
	}, nil
}

// Restart bounces a tunnel: down, then up again (§9.6).
func (s *Service) Restart(ctx context.Context, id int64, req Request) (Result, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if err := safety.CheckClientConnection(req.ClientIP, AddressesOf(rec), req.IUnderstandIMayLoseAccess); err != nil {
		return Result{}, err
	}
	// A restart is a reapply that does not pretend to be gentler than it is: the
	// interface goes away and comes back with the stored configuration.
	return s.Reapply(ctx, id, req)
}

// Reapply re-renders and re-applies a tunnel from its stored desired state,
// which is the remedy for drift (§9.6, §12).
func (s *Service) Reapply(ctx context.Context, id int64, req Request) (Result, error) {
	rec, err := s.repo.ByID(ctx, id)
	if err != nil {
		return Result{}, err
	}
	if err := safety.CheckClientConnection(req.ClientIP, AddressesOf(rec), req.IUnderstandIMayLoseAccess); err != nil {
		return Result{}, err
	}

	release, err := s.lock(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()

	trace := audit.NewTrace()
	ctx = audit.WithTrace(ctx, trace)

	keepalive := s.KeepaliveFor(rec, req.KeepaliveEnabled)
	plan := s.planner.PlanCreate(rec, keepalive, req.Takeover)
	plan.Operation = OpReapply

	// Reapplying starts from a clean slate, so whatever is there now is removed
	// first. Every teardown step is tolerant, so a tunnel that is already gone
	// reapplies just as well as one that is drifted.
	teardown := s.planner.PlanDelete(rec, keepalive.Enabled, req.Takeover)
	plan.Steps = append(teardown.Steps, plan.Steps...)

	defer s.notifyChanged()
	return s.run(ctx, rec, plan, req, trace)
}

// ---------------------------------------------------------------- pipeline

// run is the apply → verify → commit or rollback half of the pipeline (§9.1).
func (s *Service) run(ctx context.Context, rec Record, plan Plan, req Request, trace *audit.Trace) (Result, error) {
	if err := s.guardPlan(ctx, plan, rec, req.Takeover); err != nil {
		_ = s.repo.SetApplyStatus(ctx, rec.TunnelID, model.ApplyStatusFailed, err)
		return Result{}, err
	}

	applyErr := s.execute(ctx, plan.Steps, rec, req.Takeover)

	var report VerifyReport
	if applyErr == nil {
		report = s.Verify(ctx, rec)
		if !report.Ok {
			applyErr = fmt.Errorf("verification failed: %s", strings.Join(report.Failures, "; "))
		}
	}

	if applyErr == nil {
		if err := s.repo.SetApplyStatus(ctx, rec.TunnelID, model.ApplyStatusApplied, nil); err != nil {
			return Result{}, err
		}
		stored, err := s.repo.ByID(ctx, rec.TunnelID)
		if err != nil {
			stored = rec
		}
		return Result{
			Tunnel: stored, Plan: plan, Verify: report,
			Warnings: report.Warnings(), Operations: trace.Operations(),
		}, nil
	}

	// Something failed. The inverse plan runs, and the result of that decides
	// whether this is a clean failure or an inconsistent host.
	journal := s.journalFor(ctx, rec)
	rollbackErr := s.execute(ctx, plan.Rollback, rec, req.Takeover)
	if rollbackErr != nil {
		_ = s.repo.SetApplyStatus(ctx, rec.TunnelID, model.ApplyStatusInconsistent, applyErr)
		return Result{}, &InconsistentError{
			Interface:     rec.InterfaceName,
			TunnelID:      rec.TunnelID,
			ApplyError:    applyErr.Error(),
			RollbackError: rollbackErr.Error(),
			Remediation:   s.remediation(rec),
			Journal:       journal,
		}
	}

	_ = s.repo.SetApplyStatus(ctx, rec.TunnelID, model.ApplyStatusFailed, applyErr)
	return Result{}, &ApplyError{
		Interface:  rec.InterfaceName,
		Cause:      applyErr.Error(),
		Journal:    journal,
		Verify:     report,
		RolledBack: true,
	}
}

// guardPlan applies the §17 invariants to every step of a plan, immediately
// before any of it runs. Checking here rather than only at the API boundary is
// the point: a code path that reaches this function has already passed the
// handlers, and the invariants still hold.
func (s *Service) guardPlan(ctx context.Context, plan Plan, rec Record, takeover bool) error {
	if s.guard == nil {
		return nil
	}
	managed := rec.IsManaged
	checked := map[string]bool{}

	for _, step := range plan.Steps {
		if step.Interface != "" && !checked[step.Interface] {
			if err := s.guard.CheckInterface(ctx, step.Interface, managed); err != nil {
				return err
			}
			checked[step.Interface] = true
		}
		if step.Path != "" {
			if step.Kind == StepFileRemove || step.Kind == StepFileWrite {
				if err := s.guard.CheckUnitOwnership(step.Path, step.Takeover && takeover); err != nil {
					return err
				}
			} else if err := s.guard.CheckPath(step.Path); err != nil {
				return err
			}
		}
		if len(step.Argv) > 0 {
			if err := safety.CheckArgv(step.Argv); err != nil {
				return err
			}
		}
	}
	return nil
}

// execute runs the steps of a plan in order, stopping at the first failure of a
// step that is not marked tolerant.
func (s *Service) execute(ctx context.Context, steps []Step, rec Record, takeover bool) error {
	for _, step := range steps {
		err := s.runStep(ctx, step, takeover)
		if err == nil {
			continue
		}
		if step.Tolerate {
			s.log.Debug("tolerated a failed plan step",
				"step", step.Kind, "interface", step.Interface, "error", err)
			continue
		}
		return fmt.Errorf("%s (%s): %w", step.Description, step.Kind, err)
	}
	return nil
}

// runStep carries out one step.
func (s *Service) runStep(ctx context.Context, step Step, takeover bool) error {
	switch step.Kind {
	case StepLinkCreate:
		if step.Spec == nil {
			return errors.New("the plan step has no tunnel specification")
		}
		return s.links.Create(ctx, *step.Spec)
	case StepLinkDelete:
		return s.links.Delete(ctx, step.Interface)
	case StepLinkUp:
		return s.links.SetUp(ctx, step.Interface)
	case StepLinkDown:
		return s.links.SetDown(ctx, step.Interface)
	case StepLinkSetMtu:
		return s.links.SetMTU(ctx, step.Interface, step.Mtu)
	case StepLinkSetTxQueue:
		return s.links.SetTxQueueLength(ctx, step.Interface, step.TxQueueLength)
	case StepAddressAdd:
		if step.Address == nil {
			return errors.New("the plan step has no address")
		}
		return s.links.AddAddress(ctx, step.Interface, *step.Address)
	case StepAddressRemove:
		if step.Address == nil {
			return errors.New("the plan step has no address")
		}
		return s.links.RemoveAddress(ctx, step.Interface, *step.Address)

	case StepFileWrite:
		_, err := s.store.Write(ctx, step.Path, step.Content, step.Takeover && takeover)
		return err
	case StepFileRemove:
		_, err := s.store.Remove(ctx, step.Path, step.Takeover && takeover)
		return err

	case StepDaemonReload:
		return s.store.DaemonReload(ctx)
	case StepUnitEnable:
		return s.store.Enable(ctx, step.Unit)
	case StepUnitDisable:
		return s.store.Disable(ctx, step.Unit)
	case StepUnitStart:
		s.store.ResetFailed(ctx, step.Unit)
		return s.store.Start(ctx, step.Unit)
	case StepUnitStop:
		return s.store.Stop(ctx, step.Unit)
	case StepUnitRestart:
		return s.store.Restart(ctx, step.Unit)
	case StepUnitResetFailed:
		s.store.ResetFailed(ctx, step.Unit)
		return nil

	case StepNetworkdReload:
		_, err := s.runner.Run(ctx, step.Argv)
		return err
	}
	return fmt.Errorf("unknown plan step %q", step.Kind)
}

// remediation returns the exact commands an operator should run to put the host
// right after a failed rollback. Handing over a list of commands is the least a
// panel that has left a machine inconsistent can do (§9.3).
func (s *Service) remediation(rec Record) []string {
	name := rec.InterfaceName
	commands := []string{}
	if rec.PersistenceTypeID == model.PersistenceTypeSystemd {
		unit := persist.UnitName(name)
		commands = append(commands,
			strings.Join(persist.StopArgs(s.planner.systemctlBin, unit), " "),
			strings.Join(persist.DisableArgs(s.planner.systemctlBin, unit), " "),
			"rm -f "+s.store.UnitPath(name),
			strings.Join(persist.DaemonReloadArgs(s.planner.systemctlBin), " "),
		)
	}
	if rec.PersistenceTypeID == model.PersistenceTypeNetworkd {
		commands = append(commands,
			"rm -f "+s.store.NetdevPath(name),
			"rm -f "+s.store.NetworkPath(name),
		)
	}
	commands = append(commands, strings.Join(link.DeleteArgs(s.planner.ipBin, name), " "))
	return commands
}

// journalFor returns the tail of the unit's log, which is what an operator
// actually needs when an apply fails (§9.1).
func (s *Service) journalFor(ctx context.Context, rec Record) string {
	if rec.PersistenceTypeID != model.PersistenceTypeSystemd {
		return ""
	}
	return s.store.JournalTail(ctx, persist.UnitName(rec.InterfaceName), 50)
}

// observe reads one interface without failing the caller when it is absent.
func (s *Service) observe(ctx context.Context, name string) (link.Link, bool) {
	observed, err := s.links.Get(ctx, name)
	if err != nil {
		return link.Link{}, false
	}
	return observed, true
}

// ---------------------------------------------------------------- idempotency

// idempotencyCache remembers recent results by key so a double submission
// returns the first answer instead of creating a second tunnel (§16).
type idempotencyCache struct {
	mu      sync.Mutex
	entries map[string]idempotencyEntry
}

type idempotencyEntry struct {
	result  Result
	expires time.Time
}

// idempotencyTTL is how long a key is remembered. It is long enough to cover a
// retry after a timeout and short enough that a key can be reused later.
const idempotencyTTL = 10 * time.Minute

func newIdempotencyCache() *idempotencyCache {
	return &idempotencyCache{entries: map[string]idempotencyEntry{}}
}

func (c *idempotencyCache) get(key string) (Result, bool) {
	if strings.TrimSpace(key) == "" {
		return Result{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expires) {
		delete(c.entries, key)
		return Result{}, false
	}
	return entry.result, true
}

func (c *idempotencyCache) put(key string, result Result) {
	if strings.TrimSpace(key) == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Drop anything stale while the lock is held, so the map cannot grow without
	// bound on a long-running panel.
	now := time.Now()
	for k, entry := range c.entries {
		if now.After(entry.expires) {
			delete(c.entries, k)
		}
	}
	c.entries[key] = idempotencyEntry{result: result, expires: now.Add(idempotencyTTL)}
}
