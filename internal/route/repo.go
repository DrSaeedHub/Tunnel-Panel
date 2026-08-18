package route

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/rules"
	"github.com/drs/gre-panel/internal/validate"
)

// ErrNotFound is returned when no live forwarding rule has that identifier.
var ErrNotFound = errors.New("route: not found")

// routeColumns is the full column list, in the order rows are scanned. It is a
// single constant so the SELECT list and the scan can never drift apart.
const routeColumns = `
	RouteRuleID, RouteRuleTitle, Description, RouteProtocolID, AddressFamilyID,
	BindAddress, BindPort, BindPortRangeEnd, BindInterface,
	DestinationAddress, DestinationPort, DestinationPortRangeEnd,
	NatModeID, SnatAddress, LoadBalanceModeID, TunnelID,
	IsClampMssToPmtu, IsIncludeLocalOriginated, IsLoggingEnabled, FwMark,
	MaxConnectionsPerSource, ConnectionRateLimit,
	IsEnabled, ApplyStatusID, LastAppliedDate, LastApplyError,
	SortOrder, TagsJson, CreatedDate, UpdatedDate, IsDeleted`

// Repo is the database view of forwarding rules, their destinations and their
// allowlists. It satisfies validate.RouteRepository through ForValidation.
type Repo struct {
	db *db.DB
}

// NewRepo returns a repository over the given database.
func NewRepo(database *db.DB) *Repo { return &Repo{db: database} }

// validationView adapts the repository to validate.RouteRepository.
type validationView struct{ *Repo }

func (v validationView) ExistingRoutes(ctx context.Context) ([]validate.ExistingRoute, error) {
	records, err := v.Repo.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]validate.ExistingRoute, 0, len(records))
	for _, rec := range records {
		out = append(out, validate.ExistingRoute{
			RouteRuleID:      rec.RouteRuleID,
			Title:            rec.RouteRuleTitle,
			RouteProtocolID:  rec.RouteProtocolID,
			BindAddress:      rec.BindAddress,
			BindPort:         int(rec.BindPort),
			BindPortRangeEnd: intOrZero(rec.BindPortRangeEnd),
			IsEnabled:        rec.IsEnabled,
		})
	}
	return out, nil
}

// TunnelExists reports whether a live tunnel carries that identifier, which is
// what keeps a rule from naming one that is not there (§10).
func (v validationView) TunnelExists(ctx context.Context, tunnelID int64) (bool, error) {
	return v.Repo.TunnelExists(ctx, tunnelID)
}

// ForValidation returns the repository as validation sees it.
func (r *Repo) ForValidation() validate.RouteRepository { return validationView{r} }

// ---------------------------------------------------------------- reading

func scanRoute(scan func(...any) error) (model.RouteRule, error) {
	var rule model.RouteRule
	var (
		bindPortRangeEnd, destinationPortRangeEnd        sql.NullInt64
		tunnelID, fwMark, maxConnections, connectionRate sql.NullInt64
		bindInterface, snatAddress                       sql.NullString
		lastAppliedDate, lastApplyError, tagsJson        sql.NullString
		isClampMss, isIncludeLocal, isLogging            int64
		isEnabled, isDeleted                             int64
		description                                      string
	)

	err := scan(
		&rule.RouteRuleID, &rule.RouteRuleTitle, &description, &rule.RouteProtocolID, &rule.AddressFamilyID,
		&rule.BindAddress, &rule.BindPort, &bindPortRangeEnd, &bindInterface,
		&rule.DestinationAddress, &rule.DestinationPort, &destinationPortRangeEnd,
		&rule.NatModeID, &snatAddress, &rule.LoadBalanceModeID, &tunnelID,
		&isClampMss, &isIncludeLocal, &isLogging, &fwMark,
		&maxConnections, &connectionRate,
		&isEnabled, &rule.ApplyStatusID, &lastAppliedDate, &lastApplyError,
		&rule.SortOrder, &tagsJson, &rule.CreatedDate, &rule.UpdatedDate, &isDeleted,
	)
	if err != nil {
		return rule, err
	}

	rule.Description = description
	rule.BindPortRangeEnd = nullInt(bindPortRangeEnd)
	rule.BindInterface = nullString(bindInterface)
	rule.DestinationPortRangeEnd = nullInt(destinationPortRangeEnd)
	rule.SnatAddress = nullString(snatAddress)
	rule.TunnelID = nullInt(tunnelID)
	rule.IsClampMssToPmtu = isClampMss != 0
	rule.IsIncludeLocalOriginated = isIncludeLocal != 0
	rule.IsLoggingEnabled = isLogging != 0
	rule.FwMark = nullInt(fwMark)
	rule.MaxConnectionsPerSource = nullInt(maxConnections)
	rule.ConnectionRateLimit = nullInt(connectionRate)
	rule.IsEnabled = isEnabled != 0
	rule.LastAppliedDate = nullString(lastAppliedDate)
	rule.LastApplyError = nullString(lastApplyError)
	rule.TagsJson = nullString(tagsJson)
	rule.IsDeleted = isDeleted != 0
	return rule, nil
}

// List returns every live rule in emission order, with its destinations and
// allowlist. Emission order is the operator's, because overlapping matches
// resolve first-match-wins.
func (r *Repo) List(ctx context.Context) ([]Record, error) {
	rows, err := r.db.Read.QueryContext(ctx,
		`SELECT `+routeColumns+` FROM RouteRule WHERE IsDeleted = 0 ORDER BY SortOrder, RouteRuleID`)
	if err != nil {
		return nil, fmt.Errorf("listing forwarding rules: %w", err)
	}
	defer rows.Close()

	var out []Record
	for rows.Next() {
		rule, err := scanRoute(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("reading a forwarding rule row: %w", err)
		}
		out = append(out, Record{RouteRule: rule})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing forwarding rules: %w", err)
	}

	destinations, err := r.allDestinations(ctx)
	if err != nil {
		return nil, err
	}
	sources, err := r.allAllowedSources(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Destinations = destinations[out[i].RouteRuleID]
		out[i].AllowedSources = sources[out[i].RouteRuleID]
		out[i] = out[i].normalise()
	}
	return out, nil
}

// ByID returns one live rule with its children.
func (r *Repo) ByID(ctx context.Context, id int64) (Record, error) {
	row := r.db.Read.QueryRowContext(ctx,
		`SELECT `+routeColumns+` FROM RouteRule WHERE RouteRuleID = ? AND IsDeleted = 0`, id)
	rule, err := scanRoute(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("%w: forwarding rule %d", ErrNotFound, id)
	}
	if err != nil {
		return Record{}, fmt.Errorf("reading forwarding rule %d: %w", id, err)
	}

	destinations, err := r.destinationsFor(ctx, id)
	if err != nil {
		return Record{}, err
	}
	sources, err := r.allowedSourcesFor(ctx, id)
	if err != nil {
		return Record{}, err
	}
	return Record{RouteRule: rule, Destinations: destinations, AllowedSources: sources}.normalise(), nil
}

// ByTunnel returns every live rule whose destination is reached through a
// tunnel, which is what makes a tunnel's dependants listable before it is
// deleted (§10).
func (r *Repo) ByTunnel(ctx context.Context, tunnelID int64) ([]Record, error) {
	all, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []Record
	for _, rec := range all {
		if rec.TunnelID != nil && *rec.TunnelID == tunnelID {
			out = append(out, rec)
		}
	}
	return out, nil
}

const destinationColumns = `
	RouteDestinationID, RouteRuleID, Address, Port, PortRangeEnd, Weight, IsEnabled, SortOrder,
	CreatedDate, UpdatedDate, IsDeleted`

func scanDestinations(rows *sql.Rows) ([]model.RouteDestination, error) {
	var out []model.RouteDestination
	for rows.Next() {
		var d model.RouteDestination
		var portRangeEnd sql.NullInt64
		var isEnabled, isDeleted int64
		if err := rows.Scan(&d.RouteDestinationID, &d.RouteRuleID, &d.Address, &d.Port,
			&portRangeEnd, &d.Weight, &isEnabled, &d.SortOrder,
			&d.CreatedDate, &d.UpdatedDate, &isDeleted); err != nil {
			return nil, fmt.Errorf("reading a destination row: %w", err)
		}
		d.PortRangeEnd = nullInt(portRangeEnd)
		d.IsEnabled = isEnabled != 0
		d.IsDeleted = isDeleted != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

func (r *Repo) destinationsFor(ctx context.Context, id int64) ([]model.RouteDestination, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+destinationColumns+`
		FROM RouteDestination WHERE RouteRuleID = ? AND IsDeleted = 0
		ORDER BY SortOrder, RouteDestinationID`, id)
	if err != nil {
		return nil, fmt.Errorf("reading the destinations of rule %d: %w", id, err)
	}
	defer rows.Close()
	return scanDestinations(rows)
}

func (r *Repo) allDestinations(ctx context.Context) (map[int64][]model.RouteDestination, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+destinationColumns+`
		FROM RouteDestination WHERE IsDeleted = 0 ORDER BY RouteRuleID, SortOrder, RouteDestinationID`)
	if err != nil {
		return nil, fmt.Errorf("reading destinations: %w", err)
	}
	defer rows.Close()

	list, err := scanDestinations(rows)
	if err != nil {
		return nil, err
	}
	out := map[int64][]model.RouteDestination{}
	for _, d := range list {
		out[d.RouteRuleID] = append(out[d.RouteRuleID], d)
	}
	return out, nil
}

const allowedSourceColumns = `
	RouteAllowedSourceID, RouteRuleID, Cidr, Description, CreatedDate, UpdatedDate, IsDeleted`

func scanAllowedSources(rows *sql.Rows) ([]model.RouteAllowedSource, error) {
	var out []model.RouteAllowedSource
	for rows.Next() {
		var s model.RouteAllowedSource
		var isDeleted int64
		if err := rows.Scan(&s.RouteAllowedSourceID, &s.RouteRuleID, &s.Cidr, &s.Description,
			&s.CreatedDate, &s.UpdatedDate, &isDeleted); err != nil {
			return nil, fmt.Errorf("reading an allowlist row: %w", err)
		}
		s.IsDeleted = isDeleted != 0
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *Repo) allowedSourcesFor(ctx context.Context, id int64) ([]model.RouteAllowedSource, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+allowedSourceColumns+`
		FROM RouteAllowedSource WHERE RouteRuleID = ? AND IsDeleted = 0
		ORDER BY RouteAllowedSourceID`, id)
	if err != nil {
		return nil, fmt.Errorf("reading the allowlist of rule %d: %w", id, err)
	}
	defer rows.Close()
	return scanAllowedSources(rows)
}

func (r *Repo) allAllowedSources(ctx context.Context) (map[int64][]model.RouteAllowedSource, error) {
	rows, err := r.db.Read.QueryContext(ctx, `SELECT `+allowedSourceColumns+`
		FROM RouteAllowedSource WHERE IsDeleted = 0 ORDER BY RouteRuleID, RouteAllowedSourceID`)
	if err != nil {
		return nil, fmt.Errorf("reading allowlists: %w", err)
	}
	defer rows.Close()

	list, err := scanAllowedSources(rows)
	if err != nil {
		return nil, err
	}
	out := map[int64][]model.RouteAllowedSource{}
	for _, s := range list {
		out[s.RouteRuleID] = append(out[s.RouteRuleID], s)
	}
	return out, nil
}

// Desired returns the ruleset every enabled rule describes, which is what an
// apply installs. A disabled rule contributes nothing: that is what disabling
// means.
func (r *Repo) Desired(ctx context.Context) (rules.Ruleset, error) {
	records, err := r.List(ctx)
	if err != nil {
		return rules.Ruleset{}, err
	}
	return DesiredOf(records), nil
}

// DesiredOf builds the ruleset a set of records describes.
func DesiredOf(records []Record) rules.Ruleset {
	var rs rules.Ruleset
	for _, rec := range records {
		if !rec.IsEnabled {
			continue
		}
		rs.Routes = append(rs.Routes, rec.Spec())
	}
	return rs
}

// ---------------------------------------------------------------- writing

// Insert stores a new rule with its children and returns its identifier.
func (r *Repo) Insert(ctx context.Context, in validate.RouteInput) (int64, error) {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("beginning the forwarding rule transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	rec := RecordFrom(in)
	res, err := tx.ExecContext(ctx, `
		INSERT INTO RouteRule
			(RouteRuleTitle, Description, RouteProtocolID, AddressFamilyID,
			 BindAddress, BindPort, BindPortRangeEnd, BindInterface,
			 DestinationAddress, DestinationPort, DestinationPortRangeEnd,
			 NatModeID, SnatAddress, LoadBalanceModeID, TunnelID,
			 IsClampMssToPmtu, IsIncludeLocalOriginated, IsLoggingEnabled, FwMark,
			 MaxConnectionsPerSource, ConnectionRateLimit,
			 IsEnabled, ApplyStatusID, SortOrder, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		rec.RouteRuleTitle, rec.Description, rec.RouteProtocolID, rec.AddressFamilyID,
		rec.BindAddress, rec.BindPort, rec.BindPortRangeEnd, rec.BindInterface,
		rec.DestinationAddress, rec.DestinationPort, rec.DestinationPortRangeEnd,
		rec.NatModeID, rec.SnatAddress, rec.LoadBalanceModeID, rec.TunnelID,
		boolToInt(rec.IsClampMssToPmtu), boolToInt(rec.IsIncludeLocalOriginated),
		boolToInt(rec.IsLoggingEnabled), rec.FwMark,
		rec.MaxConnectionsPerSource, rec.ConnectionRateLimit,
		boolToInt(rec.IsEnabled), model.ApplyStatusPending, nextSortOrder(ctx, tx, rec.SortOrder),
		now, now)
	if err != nil {
		return 0, fmt.Errorf("storing the forwarding rule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("reading the new forwarding rule identifier: %w", err)
	}

	if err := replaceChildren(ctx, tx, id, rec, now); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing the forwarding rule: %w", err)
	}
	return id, nil
}

// nextSortOrder keeps a new rule at the end of the list unless the request
// placed it deliberately, so creating one never silently reorders the others.
func nextSortOrder(ctx context.Context, tx *sql.Tx, requested int64) int64 {
	if requested != 0 {
		return requested
	}
	var highest sql.NullInt64
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(SortOrder) FROM RouteRule WHERE IsDeleted = 0`).Scan(&highest); err != nil {
		return 0
	}
	if !highest.Valid {
		return 10
	}
	return highest.Int64 + 10
}

// Update replaces a rule and its children with what the request describes.
func (r *Repo) Update(ctx context.Context, id int64, in validate.RouteInput) error {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the forwarding rule transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	rec := RecordFrom(in)
	if _, err := tx.ExecContext(ctx, `
		UPDATE RouteRule SET
			RouteRuleTitle = ?, Description = ?, RouteProtocolID = ?, AddressFamilyID = ?,
			BindAddress = ?, BindPort = ?, BindPortRangeEnd = ?, BindInterface = ?,
			DestinationAddress = ?, DestinationPort = ?, DestinationPortRangeEnd = ?,
			NatModeID = ?, SnatAddress = ?, LoadBalanceModeID = ?, TunnelID = ?,
			IsClampMssToPmtu = ?, IsIncludeLocalOriginated = ?, IsLoggingEnabled = ?, FwMark = ?,
			MaxConnectionsPerSource = ?, ConnectionRateLimit = ?,
			IsEnabled = ?, SortOrder = ?, UpdatedDate = ?
		WHERE RouteRuleID = ? AND IsDeleted = 0`,
		rec.RouteRuleTitle, rec.Description, rec.RouteProtocolID, rec.AddressFamilyID,
		rec.BindAddress, rec.BindPort, rec.BindPortRangeEnd, rec.BindInterface,
		rec.DestinationAddress, rec.DestinationPort, rec.DestinationPortRangeEnd,
		rec.NatModeID, rec.SnatAddress, rec.LoadBalanceModeID, rec.TunnelID,
		boolToInt(rec.IsClampMssToPmtu), boolToInt(rec.IsIncludeLocalOriginated),
		boolToInt(rec.IsLoggingEnabled), rec.FwMark,
		rec.MaxConnectionsPerSource, rec.ConnectionRateLimit,
		boolToInt(rec.IsEnabled), rec.SortOrder, now, id); err != nil {
		return fmt.Errorf("updating forwarding rule %d: %w", id, err)
	}

	if err := replaceChildren(ctx, tx, id, rec, now); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing forwarding rule %d: %w", id, err)
	}
	return nil
}

// replaceChildren rewrites a rule's destinations and allowlist.
//
// The rows are soft-deleted and written again rather than diffed: a rule's
// children are small, always read as a unit, and a diff here would be code that
// exists only to save writes that nobody is counting.
func replaceChildren(ctx context.Context, tx *sql.Tx, id int64, rec Record, now string) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE RouteDestination SET IsDeleted = 1, UpdatedDate = ? WHERE RouteRuleID = ? AND IsDeleted = 0`,
		now, id); err != nil {
		return fmt.Errorf("replacing the destinations of rule %d: %w", id, err)
	}
	for _, d := range rec.Destinations {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO RouteDestination
				(RouteRuleID, Address, Port, PortRangeEnd, Weight, IsEnabled, SortOrder,
				 CreatedDate, UpdatedDate, IsDeleted)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
			id, d.Address, d.Port, d.PortRangeEnd, d.Weight, boolToInt(d.IsEnabled), d.SortOrder,
			now, now); err != nil {
			return fmt.Errorf("storing a destination of rule %d: %w", id, err)
		}
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE RouteAllowedSource SET IsDeleted = 1, UpdatedDate = ? WHERE RouteRuleID = ? AND IsDeleted = 0`,
		now, id); err != nil {
		return fmt.Errorf("replacing the allowlist of rule %d: %w", id, err)
	}
	for _, s := range rec.AllowedSources {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO RouteAllowedSource (RouteRuleID, Cidr, Description, CreatedDate, UpdatedDate, IsDeleted)
			VALUES (?, ?, ?, ?, ?, 0)`,
			id, s.Cidr, s.Description, now, now); err != nil {
			return fmt.Errorf("storing an allowlist entry of rule %d: %w", id, err)
		}
	}
	return nil
}

// SoftDelete marks a rule and its children deleted. Business rows are never
// hard-deleted (§6).
func (r *Repo) SoftDelete(ctx context.Context, id int64) error {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the delete transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for _, stmt := range []string{
		`UPDATE RouteRule SET IsDeleted = 1, IsEnabled = 0, UpdatedDate = ? WHERE RouteRuleID = ?`,
		`UPDATE RouteDestination SET IsDeleted = 1, UpdatedDate = ? WHERE RouteRuleID = ?`,
		`UPDATE RouteAllowedSource SET IsDeleted = 1, UpdatedDate = ? WHERE RouteRuleID = ?`,
	} {
		if _, err := tx.ExecContext(ctx, stmt, now, id); err != nil {
			return fmt.Errorf("deleting forwarding rule %d: %w", id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing the deletion of rule %d: %w", id, err)
	}
	return nil
}

// SetEnabled turns a rule on or off without deleting it (§7).
func (r *Repo) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	if _, err := r.db.Write.ExecContext(ctx,
		`UPDATE RouteRule SET IsEnabled = ?, UpdatedDate = ? WHERE RouteRuleID = ? AND IsDeleted = 0`,
		boolToInt(enabled), model.NowUTC(), id); err != nil {
		return fmt.Errorf("changing the enabled state of rule %d: %w", id, err)
	}
	return nil
}

// SetApplyStatus records the outcome of an apply.
func (r *Repo) SetApplyStatus(ctx context.Context, id, statusID int64, cause error) error {
	var message any
	if cause != nil {
		message = cause.Error()
	}
	var applied any
	if statusID == model.ApplyStatusApplied {
		applied = model.NowUTC()
	}
	if _, err := r.db.Write.ExecContext(ctx, `
		UPDATE RouteRule SET
			ApplyStatusID = ?, LastApplyError = ?,
			LastAppliedDate = COALESCE(?, LastAppliedDate), UpdatedDate = ?
		WHERE RouteRuleID = ? AND IsDeleted = 0`,
		statusID, message, applied, model.NowUTC(), id); err != nil {
		return fmt.Errorf("recording the apply status of rule %d: %w", id, err)
	}
	return nil
}

// SetApplyStatusAll records the same outcome for several rules, which is what a
// bulk apply produces: one transaction, one verdict.
func (r *Repo) SetApplyStatusAll(ctx context.Context, ids []int64, statusID int64, cause error) error {
	for _, id := range ids {
		if err := r.SetApplyStatus(ctx, id, statusID, cause); err != nil {
			return err
		}
	}
	return nil
}

// Reorder writes a new emission order. Rules not named keep their place after
// the ones that were, so reordering a page of a long list does not shuffle the
// rest.
func (r *Repo) Reorder(ctx context.Context, ids []int64) error {
	now := model.NowUTC()
	tx, err := r.db.Write.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning the reorder transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for i, id := range ids {
		res, err := tx.ExecContext(ctx,
			`UPDATE RouteRule SET SortOrder = ?, UpdatedDate = ? WHERE RouteRuleID = ? AND IsDeleted = 0`,
			int64((i+1)*10), now, id)
		if err != nil {
			return fmt.Errorf("reordering forwarding rule %d: %w", id, err)
		}
		if affected, err := res.RowsAffected(); err == nil && affected == 0 {
			return fmt.Errorf("%w: forwarding rule %d", ErrNotFound, id)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing the new order: %w", err)
	}
	return nil
}

// TunnelExists reports whether a live tunnel carries that identifier.
func (r *Repo) TunnelExists(ctx context.Context, tunnelID int64) (bool, error) {
	var count int
	if err := r.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM Tunnel WHERE TunnelID = ? AND IsDeleted = 0`, tunnelID).Scan(&count); err != nil {
		return false, fmt.Errorf("checking tunnel %d: %w", tunnelID, err)
	}
	return count > 0, nil
}

// TitleExists reports whether a live rule other than the one given already
// carries a title, which duplicate uses to find a free name.
func (r *Repo) TitleExists(ctx context.Context, title string, exceptID int64) (bool, error) {
	var count int
	err := r.db.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM RouteRule WHERE RouteRuleTitle = ? AND RouteRuleID <> ? AND IsDeleted = 0`,
		title, exceptID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking the name %q: %w", title, err)
	}
	return count > 0, nil
}

// ---------------------------------------------------------------- helpers

func boolToInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func nullInt(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

func nullString(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}
