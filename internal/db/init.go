package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/drs/gre-panel/internal/model"
)

// Init creates the schema and applies the seeds. It is safe to call on a fresh
// database and on an existing one, and safe to call repeatedly: every table is
// created IF NOT EXISTS, every index is guarded, and every seed is written with
// ON CONFLICT DO NOTHING.
//
// Seeds run on every startup rather than only when a table is empty. Seeding
// only-when-empty is a trap: values added in a later release would silently
// never reach an installation that already has rows (§6).
func Init(ctx context.Context, d *DB) error {
	if err := createLookupTables(ctx, d.Write); err != nil {
		return err
	}
	for _, stmt := range entityDDL {
		if _, err := d.Write.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("applying schema: %w\nstatement: %s", err, stmt)
		}
	}
	if err := applyColumnAdditions(ctx, d.Write); err != nil {
		return err
	}
	if err := recordSchemaVersion(ctx, d.Write); err != nil {
		return err
	}
	if err := seedLookups(ctx, d.Write); err != nil {
		return err
	}
	if err := seedAddressPools(ctx, d.Write); err != nil {
		return err
	}
	// The WAL sidecars only exist after the first write, so harden again now
	// that initialisation has certainly written something.
	return d.Harden()
}

// createLookupTables generates the DDL for every lookup table declared in
// internal/model, so the shape of a lookup table is defined in exactly one
// place and a new one needs no hand-written SQL.
func createLookupTables(ctx context.Context, x *sql.DB) error {
	for _, t := range model.LookupTables() {
		stmt := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
	%s        INTEGER PRIMARY KEY,
	%s        TEXT    NOT NULL,
	SortOrder   INTEGER NOT NULL DEFAULT 0,
	IsActive    INTEGER NOT NULL DEFAULT 1,
	CreatedDate TEXT    NOT NULL,
	UpdatedDate TEXT    NOT NULL,
	IsDeleted   INTEGER NOT NULL DEFAULT 0
)`, t.Name, t.IDColumn(), t.TitleColumn())
		if _, err := x.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("creating lookup table %s: %w", t.Name, err)
		}
		idx := fmt.Sprintf(`CREATE UNIQUE INDEX IF NOT EXISTS UX_%s_Title ON %s (%s)`,
			t.Name, t.Name, t.TitleColumn())
		if _, err := x.ExecContext(ctx, idx); err != nil {
			return fmt.Errorf("indexing lookup table %s: %w", t.Name, err)
		}
	}
	return nil
}

// seedLookups inserts every declared lookup value. A row an operator has
// renamed or deactivated keeps its customisation, because the conflict clause
// does nothing rather than overwriting.
func seedLookups(ctx context.Context, x *sql.DB) error {
	now := model.NowUTC()
	tx, err := x.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning seed transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for _, t := range model.LookupTables() {
		stmt := fmt.Sprintf(
			`INSERT INTO %s (%s, %s, SortOrder, IsActive, CreatedDate, UpdatedDate, IsDeleted)
			 VALUES (?, ?, ?, 1, ?, ?, 0)
			 ON CONFLICT (%s) DO NOTHING`,
			t.Name, t.IDColumn(), t.TitleColumn(), t.IDColumn())
		for _, v := range t.Values {
			// SortOrder mirrors the identifier, so the natural display order is
			// the declared order without a second thing to keep in sync.
			if _, err := tx.ExecContext(ctx, stmt, v.ID, v.Title, v.ID, now, now); err != nil {
				return fmt.Errorf("seeding %s.%d (%s): %w", t.Name, v.ID, v.Title, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing lookup seeds: %w", err)
	}
	return nil
}

// seededPool is one of the four AddressPool rows of §6. They carry fixed
// identifiers for the same reason lookup rows do: the conflict clause needs a
// stable key to match on, so re-seeding never duplicates them.
type seededPool struct {
	id            int64
	title         string
	cidr          string
	prefixLength  int64
	isPublicRange bool
	isEnabled     bool
	description   string
}

// SeededPools are the pools created on every startup (§6).
//
// The two legacy pools are real, globally routable blocks that the script this
// panel replaces used as if they were private. Using them is address squatting
// and blackholes those destinations from this server, so they ship disabled and
// flagged, kept only so tunnels created by that script can be adopted.
var SeededPools = []seededPool{
	{
		id: 10, title: "Private 172.17.0.0/16", cidr: "172.17.0.0/16", prefixLength: 30,
		isPublicRange: false, isEnabled: true,
		description: "Default RFC 1918 range. Matches the range the legacy install script used by default.",
	},
	{
		id: 20, title: "Private 10.10.0.0/16", cidr: "10.10.0.0/16", prefixLength: 30,
		isPublicRange: false, isEnabled: true,
		description: "Alternative RFC 1918 range, for installations where 172.17.0.0/16 is already in use.",
	},
	{
		id: 30, title: "Legacy 109.194.0.0/16", cidr: "109.194.0.0/16", prefixLength: 30,
		isPublicRange: true, isEnabled: false,
		description: "Compatibility only. This is a globally routable block: assigning it to a tunnel " +
			"squats on someone else's address space and blackholes those destinations from this server. " +
			"Enable only to adopt tunnels that already use it.",
	},
	{
		id: 40, title: "Legacy 87.107.0.0/16", cidr: "87.107.0.0/16", prefixLength: 30,
		isPublicRange: true, isEnabled: false,
		description: "Compatibility only. This is a globally routable block: assigning it to a tunnel " +
			"squats on someone else's address space and blackholes those destinations from this server. " +
			"Enable only to adopt tunnels that already use it.",
	},
}

func seedAddressPools(ctx context.Context, x *sql.DB) error {
	now := model.NowUTC()
	const stmt = `
		INSERT INTO AddressPool
			(AddressPoolID, AddressPoolTitle, Cidr, PrefixLength, IsPublicRange, IsEnabled,
			 Description, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
		ON CONFLICT (AddressPoolID) DO NOTHING`

	tx, err := x.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning pool seed transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	for _, p := range SeededPools {
		if _, err := tx.ExecContext(ctx, stmt, p.id, p.title, p.cidr, p.prefixLength,
			boolToInt(p.isPublicRange), boolToInt(p.isEnabled), p.description, now, now); err != nil {
			return fmt.Errorf("seeding address pool %s: %w", p.cidr, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing address pool seeds: %w", err)
	}
	return nil
}

// columnAddition is one column added to an existing table after its initial
// release. CREATE TABLE IF NOT EXISTS never touches a table that already
// exists, so a column added straight to entityDDL would silently never reach
// an installation whose table predates it — every query mentioning the new
// column would fail on it forever. Listing it here instead gets it added on
// the next startup.
type columnAddition struct {
	table  string
	column string
	ddl    string // the column definition, e.g. "TEXT"
}

var columnAdditions = []columnAddition{
	{"Tunnel", "DisplayName", "TEXT"},

	// Monitoring a forwarding rule's destinations. Every one is optional and
	// inherits from the rule, which inherits from the panel-wide setting, so
	// an installation that predates them behaves exactly as it did.
	{"RouteRule", "IsMonitorEnabled", "INTEGER"},
	{"RouteRule", "MonitorModeID", "INTEGER"},
	{"RouteRule", "MonitorIntervalSeconds", "REAL"},
	{"RouteRule", "MonitorTimeoutSeconds", "REAL"},
	{"RouteRule", "MonitorFailureThreshold", "INTEGER"},
	{"RouteRule", "MonitorRecoveryThreshold", "INTEGER"},
	{"RouteDestination", "IsMonitorEnabled", "INTEGER"},
	{"RouteDestination", "MonitorPort", "INTEGER"},
	{"RouteDestination", "MonitorIntervalSeconds", "REAL"},
	{"RouteDestination", "MonitorTimeoutSeconds", "REAL"},
	{"RouteDestination", "MonitorFailureThreshold", "INTEGER"},
	{"RouteDestination", "MonitorRecoveryThreshold", "INTEGER"},
	// NOT NULL with a default is safe to add to an existing table: SQLite
	// fills the existing rows with it.
	{"RouteDestination", "IsSuppressed", "INTEGER NOT NULL DEFAULT 0"},

	// Which direction a traffic limit counts. Both is 10, which is what every
	// limit created before the column meant.
	{"TrafficQuota", "DirectionID", "INTEGER NOT NULL DEFAULT 10"},
}

// applyColumnAdditions adds every column in columnAdditions that is missing
// from its table.
func applyColumnAdditions(ctx context.Context, x *sql.DB) error {
	for _, c := range columnAdditions {
		has, err := hasColumn(ctx, x, c.table, c.column)
		if err != nil {
			return fmt.Errorf("checking for %s.%s: %w", c.table, c.column, err)
		}
		if has {
			continue
		}
		stmt := fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, c.table, c.column, c.ddl)
		if _, err := x.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("adding %s.%s: %w", c.table, c.column, err)
		}
	}
	return nil
}

// hasColumn reports whether table already has the given column.
func hasColumn(ctx context.Context, x *sql.DB, table, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, fmt.Errorf("reading the columns of %s: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid, notNull, pk int
		var name, ctype string
		var dfltValue any
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return false, fmt.Errorf("reading a column of %s: %w", table, err)
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	return false, rows.Err()
}

// recordSchemaVersion writes the single SchemaVersion row, advancing it when
// this build is newer than what the file records.
func recordSchemaVersion(ctx context.Context, x *sql.DB) error {
	now := model.NowUTC()
	if _, err := x.ExecContext(ctx,
		`INSERT INTO SchemaVersion (SchemaVersionID, Version, AppliedDate)
		 VALUES (1, ?, ?)
		 ON CONFLICT (SchemaVersionID) DO UPDATE SET
			Version     = excluded.Version,
			AppliedDate = excluded.AppliedDate
		 WHERE excluded.Version > SchemaVersion.Version`,
		SchemaVersion, now); err != nil {
		return fmt.Errorf("recording schema version: %w", err)
	}
	return nil
}

// CurrentSchemaVersion reads the recorded structural schema version.
func CurrentSchemaVersion(ctx context.Context, d *DB) (int, error) {
	var v int
	err := d.Read.QueryRowContext(ctx, `SELECT Version FROM SchemaVersion WHERE SchemaVersionID = 1`).Scan(&v)
	if err != nil {
		return 0, err
	}
	return v, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
