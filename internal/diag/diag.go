// Package diag is the on-demand diagnostics: a high-precision ping, a path MTU
// probe, a traceroute, and an automated analysis (§13).
//
// Every measurement here goes through the same native ICMP path the continuous
// monitoring uses, so the on-demand answer and the background one cannot
// disagree about what the link is doing, and no `ping` process is ever spawned.
package diag

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/exec"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/monitor"
	"github.com/drs/gre-panel/internal/tunnel"
)

// ErrNotFound is returned when no such diagnostic run exists.
var ErrNotFound = errors.New("diag: no such diagnostic run")

// Settings is the slice of the settings store this package reads.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	Float(key string) float64
}

// Run is one diagnostic execution and its result.
type Run struct {
	DiagnosticRunID  int64  `json:"diagnostic_run_id"`
	TunnelID         *int64 `json:"tunnel_id"`
	DiagnosticTypeID int64  `json:"diagnostic_type_id"`
	Type             string `json:"type"`
	Params           any    `json:"params"`
	Result           any    `json:"result,omitempty"`
	StartedDate      string `json:"started_date"`
	FinishedDate     string `json:"finished_date,omitempty"`
	IsSuccess        bool   `json:"is_success"`
	// Running reports whether this run is still in progress, which is what makes
	// the cancel action meaningful.
	Running bool `json:"running"`
}

// TypeName renders a DiagnosticType identifier.
func TypeName(id int64) string {
	switch id {
	case model.DiagnosticTypePing:
		return "ping"
	case model.DiagnosticTypeMtuProbe:
		return "mtu-probe"
	case model.DiagnosticTypeTraceroute:
		return "traceroute"
	case model.DiagnosticTypeAnalyze:
		return "analyze"
	}
	return "unknown"
}

// Deps is what the service needs.
type Deps struct {
	DB       *db.DB
	Repo     *tunnel.Repo
	Links    link.LinkManager
	Dialer   monitor.Dialer
	Runner   exec.Runner
	Settings Settings
	Log      *slog.Logger
	// TcpdumpBin, NftBin and IptablesBin are resolved at startup. An empty path
	// means that evidence simply is not gathered, which the verdict says.
	TcpdumpBin  string
	NftBin      string
	IptablesBin string
}

// Service runs diagnostics and remembers them.
type Service struct {
	db       *db.DB
	repo     *tunnel.Repo
	links    link.LinkManager
	dialer   monitor.Dialer
	runner   exec.Runner
	settings Settings
	log      *slog.Logger

	tcpdumpBin  string
	nftBin      string
	iptablesBin string

	mu sync.Mutex
	// cancels holds the in-flight runs, so deleting a run stops it (§13.1).
	cancels map[int64]context.CancelFunc
}

// New returns a diagnostics service.
func New(d Deps) *Service {
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	dialer := d.Dialer
	if dialer == nil {
		dialer = monitor.SystemDialer{}
	}
	return &Service{
		db: d.DB, repo: d.Repo, links: d.Links, dialer: dialer, runner: d.Runner,
		settings: d.Settings, log: log,
		tcpdumpBin: d.TcpdumpBin, nftBin: d.NftBin, iptablesBin: d.IptablesBin,
		cancels: map[int64]context.CancelFunc{},
	}
}

// begin records the start of a run and returns its identifier.
func (s *Service) begin(ctx context.Context, tunnelID *int64, typeID int64, params any) (int64, error) {
	encoded, err := json.Marshal(params)
	if err != nil {
		encoded = []byte("{}")
	}
	now := model.NowUTC()
	res, err := s.db.Write.ExecContext(ctx, `
		INSERT INTO DiagnosticRun
			(TunnelID, DiagnosticTypeID, ParamsJson, StartedDate, IsSuccess, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, 0, ?, ?, 0)`,
		tunnelID, typeID, string(encoded), now, now, now)
	if err != nil {
		return 0, fmt.Errorf("recording the start of a diagnostic run: %w", err)
	}
	return res.LastInsertId()
}

// finish records the outcome.
func (s *Service) finish(ctx context.Context, id int64, result any, success bool) error {
	encoded, err := json.Marshal(result)
	if err != nil {
		encoded = []byte("{}")
	}
	now := model.NowUTC()
	// The context that ran the diagnostic may already be cancelled — that is
	// exactly what deleting a run does — so the result is written with a fresh
	// one rather than lost.
	writeCtx := context.WithoutCancel(ctx)
	_, err = s.db.Write.ExecContext(writeCtx, `
		UPDATE DiagnosticRun SET ResultJson = ?, FinishedDate = ?, IsSuccess = ?, UpdatedDate = ?
		WHERE DiagnosticRunID = ?`, string(encoded), now, boolInt(success), now, id)
	if err != nil {
		return fmt.Errorf("recording the result of diagnostic run %d: %w", id, err)
	}
	return nil
}

// finalRun re-reads a finished run, falling back to what the caller already
// knows when the row has been deleted.
//
// Deleting a run is how an in-flight one is cancelled, so by the time a
// cancelled run finishes its row may be gone. Returning what it measured is
// more useful than reporting that the thing the operator just deleted cannot
// be found.
func (s *Service) finalRun(ctx context.Context, runID int64, fallback Run) Run {
	run, err := s.RunByID(context.WithoutCancel(ctx), runID)
	if err != nil {
		fallback.DiagnosticRunID = runID
		fallback.Running = false
		return fallback
	}
	return run
}

// track registers an in-flight run so it can be cancelled, and returns the
// function that unregisters it.
func (s *Service) track(id int64, cancel context.CancelFunc) func() {
	s.mu.Lock()
	s.cancels[id] = cancel
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.cancels, id)
		s.mu.Unlock()
	}
}

// Cancel stops an in-flight run. Deleting a run is how a long ping is stopped
// (§13.1).
func (s *Service) Cancel(id int64) bool {
	s.mu.Lock()
	cancel, running := s.cancels[id]
	s.mu.Unlock()
	if running {
		cancel()
	}
	return running
}

// Running reports whether a run is still in progress.
func (s *Service) Running(id int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, running := s.cancels[id]
	return running
}

// ---------------------------------------------------------------- run records

// RunFilter selects stored runs.
type RunFilter struct {
	TunnelID *int64
	TypeID   *int64
	Limit    int
	Offset   int
}

// Runs lists stored diagnostic runs, newest first, with a total for paging.
func (s *Service) Runs(ctx context.Context, filter RunFilter) ([]Run, int, error) {
	where := "WHERE IsDeleted = 0"
	args := []any{}
	if filter.TunnelID != nil {
		where += " AND TunnelID = ?"
		args = append(args, *filter.TunnelID)
	}
	if filter.TypeID != nil {
		where += " AND DiagnosticTypeID = ?"
		args = append(args, *filter.TypeID)
	}

	var total int
	if err := s.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM DiagnosticRun `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting diagnostic runs: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := s.db.Read.QueryContext(ctx, `
		SELECT DiagnosticRunID, TunnelID, DiagnosticTypeID, ParamsJson, ResultJson,
		       StartedDate, FinishedDate, IsSuccess
		FROM DiagnosticRun `+where+`
		ORDER BY StartedDate DESC, DiagnosticRunID DESC LIMIT ? OFFSET ?`,
		append(args, limit, filter.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("reading diagnostic runs: %w", err)
	}
	defer rows.Close()

	out := []Run{}
	for rows.Next() {
		run, err := scanRun(rows.Scan)
		if err != nil {
			return nil, 0, err
		}
		run.Running = s.Running(run.DiagnosticRunID)
		out = append(out, run)
	}
	return out, total, rows.Err()
}

// RunByID returns one stored run.
func (s *Service) RunByID(ctx context.Context, id int64) (Run, error) {
	row := s.db.Read.QueryRowContext(ctx, `
		SELECT DiagnosticRunID, TunnelID, DiagnosticTypeID, ParamsJson, ResultJson,
		       StartedDate, FinishedDate, IsSuccess
		FROM DiagnosticRun WHERE DiagnosticRunID = ? AND IsDeleted = 0`, id)

	run, err := scanRun(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, fmt.Errorf("%w: %d", ErrNotFound, id)
	}
	if err != nil {
		return Run{}, err
	}
	run.Running = s.Running(id)
	return run, nil
}

// DeleteRun cancels a run if it is still going and drops the record (§13.1).
func (s *Service) DeleteRun(ctx context.Context, id int64) (bool, error) {
	if _, err := s.RunByID(ctx, id); err != nil {
		return false, err
	}
	cancelled := s.Cancel(id)

	if _, err := s.db.Write.ExecContext(ctx,
		`UPDATE DiagnosticRun SET IsDeleted = 1, UpdatedDate = ? WHERE DiagnosticRunID = ?`,
		model.NowUTC(), id); err != nil {
		return cancelled, fmt.Errorf("deleting diagnostic run %d: %w", id, err)
	}
	return cancelled, nil
}

func scanRun(scan func(...any) error) (Run, error) {
	var (
		run          Run
		tunnelID     sql.NullInt64
		paramsJson   string
		resultJson   sql.NullString
		finishedDate sql.NullString
		success      int64
	)
	if err := scan(&run.DiagnosticRunID, &tunnelID, &run.DiagnosticTypeID, &paramsJson,
		&resultJson, &run.StartedDate, &finishedDate, &success); err != nil {
		return Run{}, err
	}
	if tunnelID.Valid {
		id := tunnelID.Int64
		run.TunnelID = &id
	}
	run.Type = TypeName(run.DiagnosticTypeID)
	run.IsSuccess = success != 0
	if finishedDate.Valid {
		run.FinishedDate = finishedDate.String
	}
	// The stored documents are re-decoded rather than passed through as strings,
	// so the API returns real JSON rather than JSON inside a string.
	var params any
	if err := json.Unmarshal([]byte(paramsJson), &params); err == nil {
		run.Params = params
	}
	if resultJson.Valid {
		var result any
		if err := json.Unmarshal([]byte(resultJson.String), &result); err == nil {
			run.Result = result
		}
	}
	return run, nil
}

// PruneRuns drops runs older than the retention window, alongside the audit log.
func (s *Service) PruneRuns(ctx context.Context, retentionDays int64) (int64, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := model.FormatTime(time.Now().AddDate(0, 0, -int(retentionDays)))
	res, err := s.db.Write.ExecContext(ctx,
		`DELETE FROM DiagnosticRun WHERE StartedDate < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("pruning diagnostic runs: %w", err)
	}
	return res.RowsAffected()
}

// ---------------------------------------------------------------- ping

// PingParams is a manual high-precision ping (§13.1).
type PingParams struct {
	Count        int     `json:"count,omitempty"`
	IntervalSecs float64 `json:"interval_seconds,omitempty"`
	TimeoutSecs  float64 `json:"timeout_seconds,omitempty"`
	PacketSize   int     `json:"packet_size,omitempty"`
	DontFragment bool    `json:"df,omitempty"`
	// Source and Target override the tunnel's own addresses.
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
}

// Ping runs a manual measurement, streaming each packet as it is decided.
//
// onStart is called with the run identifier as soon as it exists, so a
// streaming client can be told what to delete in order to cancel.
func (s *Service) Ping(ctx context.Context, tunnelID int64, params PingParams,
	onStart func(Run), onPacket func(monitor.PingPacket)) (Run, error) {

	rec, err := s.repo.ByID(ctx, tunnelID)
	if err != nil {
		return Run{}, err
	}
	request, err := s.pingRequest(rec, params)
	if err != nil {
		return Run{}, err
	}

	runID, err := s.begin(ctx, &tunnelID, model.DiagnosticTypePing, params)
	if err != nil {
		return Run{}, err
	}

	runCtx, cancel := context.WithCancel(ctx)
	release := s.track(runID, cancel)
	defer cancel()

	if onStart != nil {
		run, err := s.RunByID(ctx, runID)
		if err == nil {
			run.Running = true
			onStart(run)
		}
	}

	result, pingErr := monitor.Ping(runCtx, s.dialer, request, onPacket)
	// Unregister before the run is read back, so it is not reported as still
	// running in the answer that says it finished.
	release()
	// A cancelled run still reports what it measured before it was stopped:
	// those packets happened, and discarding them would waste the operator's
	// time as well as the packets.
	cancelled := errors.Is(pingErr, context.Canceled)
	success := pingErr == nil || cancelled

	payload := map[string]any{
		"summary":   result,
		"source":    request.Source,
		"target":    request.Target,
		"cancelled": cancelled,
	}
	if pingErr != nil && !cancelled {
		payload["error"] = pingErr.Error()
	}
	if err := s.finish(ctx, runID, payload, success); err != nil {
		s.log.Error("recording a ping result failed", "run_id", runID, "error", err)
	}

	run := s.finalRun(ctx, runID, Run{
		TunnelID: &tunnelID, DiagnosticTypeID: model.DiagnosticTypePing,
		Type: TypeName(model.DiagnosticTypePing), Params: params, Result: payload,
		IsSuccess: success,
	})
	if pingErr != nil && !cancelled {
		return run, pingErr
	}
	return run, nil
}

// pingRequest resolves the parameters against the settings and the tunnel.
func (s *Service) pingRequest(rec tunnel.Record, params PingParams) (monitor.PingRequest, error) {
	request := monitor.PingRequest{
		TunnelID:     rec.TunnelID,
		Count:        params.Count,
		PacketSize:   params.PacketSize,
		DontFragment: params.DontFragment,
		Source:       params.Source,
		Target:       params.Target,
	}

	if request.Count <= 0 {
		request.Count = int(s.settingInt("diagnostics.manual_ping_count", 100))
	}
	// The bound exists so one request cannot tie up a socket for an hour.
	if maximum := int(s.settingInt("diagnostics.manual_ping_max_count", 10000)); request.Count > maximum {
		request.Count = maximum
	}
	if params.IntervalSecs > 0 {
		request.Interval = seconds(params.IntervalSecs)
	} else {
		request.Interval = seconds(s.settingFloat("diagnostics.manual_ping_interval", 0.1))
	}
	if params.TimeoutSecs > 0 {
		request.Timeout = seconds(params.TimeoutSecs)
	} else {
		request.Timeout = seconds(s.settingFloat("diagnostics.manual_ping_timeout", 1))
	}

	if request.Source == "" || request.Target == "" {
		source, target := probeEndpoints(rec)
		if request.Source == "" {
			request.Source = source
		}
		if request.Target == "" {
			request.Target = target
		}
	}
	if request.Source == "" {
		return request, fmt.Errorf("this tunnel has no address to probe from; give an explicit source")
	}
	if request.Target == "" {
		return request, fmt.Errorf("no peer address is recorded for this tunnel; give an explicit target")
	}
	return request, nil
}

// probeEndpoints picks the tunnel's own address and its peer.
func probeEndpoints(rec tunnel.Record) (source, target string) {
	if len(rec.Addresses) == 0 {
		return "", ""
	}
	primary := rec.Addresses[0]
	for _, a := range rec.Addresses {
		if a.IsPrimary {
			primary = a
			break
		}
	}
	source = primary.Address
	if primary.PeerAddress != nil {
		target = *primary.PeerAddress
	}
	if rec.MonitorTarget != nil && *rec.MonitorTarget != "" {
		target = *rec.MonitorTarget
	}
	return source, target
}

func (s *Service) settingInt(key string, fallback int64) int64 {
	if s.settings == nil {
		return fallback
	}
	if v := s.settings.Int(key); v > 0 {
		return v
	}
	return fallback
}

func (s *Service) settingFloat(key string, fallback float64) float64 {
	if s.settings == nil {
		return fallback
	}
	if v := s.settings.Float(key); v > 0 {
		return v
	}
	return fallback
}

func seconds(v float64) time.Duration { return time.Duration(v * float64(time.Second)) }

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}
