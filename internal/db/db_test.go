package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/model"
)

// openTemp opens a database in a temporary directory and initialises it once.
func openTemp(t *testing.T) (context.Context, string, *DB) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "panel.db")

	d, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open returned an unexpected error: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	if err := Init(ctx, d); err != nil {
		t.Fatalf("Init returned an unexpected error: %v", err)
	}
	return ctx, path, d
}

func count(t *testing.T, d *DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := d.Read.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("counting with %q failed: %v", query, err)
	}
	return n
}

func TestPragmasAreApplied(t *testing.T) {
	ctx, _, d := openTemp(t)

	var journalMode string
	if err := d.Write.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatalf("reading journal_mode failed: %v", err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}

	var foreignKeys int
	if err := d.Write.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("reading foreign_keys failed: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	var busyTimeout int
	if err := d.Write.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		t.Fatalf("reading busy_timeout failed: %v", err)
	}
	if busyTimeout != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", busyTimeout)
	}

	var synchronous int
	if err := d.Write.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil {
		t.Fatalf("reading synchronous failed: %v", err)
	}
	if synchronous != 1 { // 1 == NORMAL
		t.Errorf("synchronous = %d, want 1 (NORMAL)", synchronous)
	}
}

func TestEveryTableAndIndexExists(t *testing.T) {
	ctx, _, d := openTemp(t)

	wantTables := []string{
		"SchemaVersion", "AppUser", "AddressPool", "Tunnel", "TunnelAddress",
		"MonitorSample", "MonitorEvent", "DiagnosticRun", "InterfaceTrafficCounter",
		"AppSetting", "AuditLog",
		"RouteRule", "RouteDestination", "RouteAllowedSource",
		"RouteTrafficCounter", "RouteTrafficSample",
	}
	for _, lt := range model.LookupTables() {
		wantTables = append(wantTables, lt.Name)
	}
	for _, name := range wantTables {
		var found string
		err := d.Read.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&found)
		if err != nil {
			t.Errorf("table %s is missing: %v", name, err)
		}
	}

	// The partial unique index of §6 is what makes soft deletion and interface
	// name uniqueness coexist, so its filter is asserted explicitly.
	var indexSQL string
	err := d.Read.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'UX_Tunnel_InterfaceName'`).Scan(&indexSQL)
	if err != nil {
		t.Fatalf("the partial unique index on Tunnel.InterfaceName is missing: %v", err)
	}
	if !strings.Contains(indexSQL, "IsDeleted = 0") {
		t.Errorf("UX_Tunnel_InterfaceName = %q, want it filtered on IsDeleted = 0", indexSQL)
	}
}

// insertRoute writes one RouteRule row with the given listener, returning the
// error so a test can assert that the unique index rejected it.
func insertRoute(d *DB, title string, protocolID int64, bindAddress string, bindPort int, enabled bool) error {
	now := model.NowUTC()
	_, err := d.Write.Exec(`
		INSERT INTO RouteRule
			(RouteRuleTitle, RouteProtocolID, AddressFamilyID, BindAddress, BindPort,
			 DestinationAddress, DestinationPort, NatModeID, LoadBalanceModeID, IsEnabled,
			 CreatedDate, UpdatedDate, IsDeleted)
		VALUES (?, ?, ?, ?, ?, '198.51.100.20', 2044, ?, ?, ?, ?, ?, 0)`,
		title, protocolID, model.AddressFamilyIPv4, bindAddress, bindPort,
		model.NatModeMasquerade, model.LoadBalanceModeNone, boolToInt(enabled), now, now)
	return err
}

// TestRouteListenerUniquenessIsPartial covers the index of §4 of the port
// forwarding specification. Two live, enabled rules may not claim the same
// listener, but a disabled one generates no rules and therefore does not hold
// the port — which is what makes building a replacement rule possible.
func TestRouteListenerUniquenessIsPartial(t *testing.T) {
	ctx, _, d := openTemp(t)

	var indexSQL string
	err := d.Read.QueryRowContext(ctx,
		`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'UX_RouteRule_Listener'`).Scan(&indexSQL)
	if err != nil {
		t.Fatalf("the partial unique index on the route listener is missing: %v", err)
	}
	for _, want := range []string{"IsDeleted = 0", "IsEnabled = 1", "RouteProtocolID", "BindAddress", "BindPort"} {
		if !strings.Contains(indexSQL, want) {
			t.Errorf("UX_RouteRule_Listener = %q, want it to contain %q", indexSQL, want)
		}
	}

	if err := insertRoute(d, "first", model.RouteProtocolTCP, "203.0.113.10", 2044, true); err != nil {
		t.Fatalf("inserting the first route failed: %v", err)
	}
	if err := insertRoute(d, "second", model.RouteProtocolTCP, "203.0.113.10", 2044, true); err == nil {
		t.Error("a second enabled rule claiming the same listener was accepted; the unique index did not fire")
	}
	// A different protocol on the same address and port is a different listener.
	if err := insertRoute(d, "udp", model.RouteProtocolUDP, "203.0.113.10", 2044, true); err != nil {
		t.Errorf("a UDP rule on the same address and port was rejected: %v", err)
	}
	// A disabled rule generates nothing, so it may share the listener.
	if err := insertRoute(d, "disabled", model.RouteProtocolTCP, "203.0.113.10", 2044, false); err != nil {
		t.Errorf("a disabled rule sharing the listener was rejected: %v", err)
	}

	// And a soft-deleted rule must not reserve the listener forever.
	if _, err := d.Write.ExecContext(ctx,
		`UPDATE RouteRule SET IsDeleted = 1 WHERE RouteRuleTitle = 'first'`); err != nil {
		t.Fatalf("soft-deleting the first route failed: %v", err)
	}
	if err := insertRoute(d, "replacement", model.RouteProtocolTCP, "203.0.113.10", 2044, true); err != nil {
		t.Errorf("a replacement for a soft-deleted rule was rejected: %v", err)
	}
}

// TestRouteChildRowsRequireTheirRule asserts the foreign keys, which is what
// stops a destination or an allowlist entry outliving the rule it belongs to.
func TestRouteChildRowsRequireTheirRule(t *testing.T) {
	ctx, _, d := openTemp(t)
	now := model.NowUTC()

	if _, err := d.Write.ExecContext(ctx, `
		INSERT INTO RouteDestination
			(RouteRuleID, Address, Port, Weight, IsEnabled, SortOrder, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (9999, '198.51.100.20', 2044, 1, 1, 0, ?, ?, 0)`, now, now); err == nil {
		t.Error("a destination referencing a rule that does not exist was accepted")
	}
	if _, err := d.Write.ExecContext(ctx, `
		INSERT INTO RouteAllowedSource (RouteRuleID, Cidr, Description, CreatedDate, UpdatedDate, IsDeleted)
		VALUES (9999, '10.0.0.0/8', '', ?, ?, 0)`, now, now); err == nil {
		t.Error("an allowlist entry referencing a rule that does not exist was accepted")
	}
}

func TestSchemaVersionIsRecorded(t *testing.T) {
	ctx, _, d := openTemp(t)
	got, err := CurrentSchemaVersion(ctx, d)
	if err != nil {
		t.Fatalf("CurrentSchemaVersion returned an unexpected error: %v", err)
	}
	if got != SchemaVersion {
		t.Errorf("recorded schema version = %d, want %d", got, SchemaVersion)
	}
	if n := count(t, d, `SELECT COUNT(*) FROM SchemaVersion`); n != 1 {
		t.Errorf("SchemaVersion has %d rows, want exactly 1", n)
	}
}

func TestSeedsAreCompleteAndUseTheDeclaredIdentifiers(t *testing.T) {
	_, _, d := openTemp(t)

	for _, lt := range model.LookupTables() {
		got := count(t, d, `SELECT COUNT(*) FROM `+lt.Name)
		if got != len(lt.Values) {
			t.Errorf("%s has %d rows, want %d", lt.Name, got, len(lt.Values))
		}
		for _, v := range lt.Values {
			var title string
			err := d.Read.QueryRow(
				`SELECT `+lt.TitleColumn()+` FROM `+lt.Name+` WHERE `+lt.IDColumn()+` = ?`, v.ID).Scan(&title)
			if err != nil {
				t.Errorf("%s row %d (%s) is missing: %v", lt.Name, v.ID, v.Title, err)
				continue
			}
			if title != v.Title {
				t.Errorf("%s row %d title = %q, want %q", lt.Name, v.ID, title, v.Title)
			}
		}
	}

	if n := count(t, d, `SELECT COUNT(*) FROM AddressPool`); n != len(SeededPools) {
		t.Fatalf("AddressPool has %d rows, want %d", n, len(SeededPools))
	}
	// The two legacy compatibility pools are globally routable and must ship
	// disabled and flagged (§6).
	for _, cidr := range []string{"109.194.0.0/16", "87.107.0.0/16"} {
		var isPublic, isEnabled int
		err := d.Read.QueryRow(
			`SELECT IsPublicRange, IsEnabled FROM AddressPool WHERE Cidr = ?`, cidr).Scan(&isPublic, &isEnabled)
		if err != nil {
			t.Fatalf("legacy pool %s is missing: %v", cidr, err)
		}
		if isPublic != 1 {
			t.Errorf("pool %s IsPublicRange = %d, want 1", cidr, isPublic)
		}
		if isEnabled != 0 {
			t.Errorf("pool %s IsEnabled = %d, want 0 (disabled by default)", cidr, isEnabled)
		}
	}
	for _, cidr := range []string{"172.17.0.0/16", "10.10.0.0/16"} {
		var isPublic, isEnabled int
		err := d.Read.QueryRow(
			`SELECT IsPublicRange, IsEnabled FROM AddressPool WHERE Cidr = ?`, cidr).Scan(&isPublic, &isEnabled)
		if err != nil {
			t.Fatalf("pool %s is missing: %v", cidr, err)
		}
		if isPublic != 0 {
			t.Errorf("pool %s IsPublicRange = %d, want 0", cidr, isPublic)
		}
		if isEnabled != 1 {
			t.Errorf("pool %s IsEnabled = %d, want 1", cidr, isEnabled)
		}
	}
}

// TestInitIsIdempotent is the core guarantee of §6: initialising twice against
// the same file must not duplicate seeds and must not overwrite anything an
// operator has customised.
func TestInitIsIdempotent(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "panel.db")

	first, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open returned an unexpected error: %v", err)
	}
	if err := Init(ctx, first); err != nil {
		t.Fatalf("first Init returned an unexpected error: %v", err)
	}

	// Customise a lookup row and a pool row the way an operator would.
	if _, err := first.Write.ExecContext(ctx,
		`UPDATE TunnelType SET TunnelTypeTitle = 'GRE (renamed)' WHERE TunnelTypeID = ?`,
		model.TunnelTypeGRE); err != nil {
		t.Fatalf("renaming a lookup row failed: %v", err)
	}
	if _, err := first.Write.ExecContext(ctx,
		`UPDATE AddressPool SET IsEnabled = 1, AddressPoolTitle = 'Adopted legacy range'
		 WHERE Cidr = '109.194.0.0/16'`); err != nil {
		t.Fatalf("customising a pool row failed: %v", err)
	}
	// And add a row of real data, to prove initialisation does not disturb it.
	if _, err := first.Write.ExecContext(ctx,
		`INSERT INTO AppUser (Username, PasswordHash, CreatedDate, UpdatedDate)
		 VALUES ('operator', 'hash', ?, ?)`, model.NowUTC(), model.NowUTC()); err != nil {
		t.Fatalf("inserting a user failed: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("closing the first handle failed: %v", err)
	}

	// Restart against the same file.
	second, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening returned an unexpected error: %v", err)
	}
	defer second.Close()
	if err := Init(ctx, second); err != nil {
		t.Fatalf("second Init returned an unexpected error: %v", err)
	}
	// A third time, because "idempotent" means any number of times.
	if err := Init(ctx, second); err != nil {
		t.Fatalf("third Init returned an unexpected error: %v", err)
	}

	for _, lt := range model.LookupTables() {
		if got := count(t, second, `SELECT COUNT(*) FROM `+lt.Name); got != len(lt.Values) {
			t.Errorf("%s has %d rows after re-initialisation, want %d — seeds were duplicated",
				lt.Name, got, len(lt.Values))
		}
	}
	if got := count(t, second, `SELECT COUNT(*) FROM AddressPool`); got != len(SeededPools) {
		t.Errorf("AddressPool has %d rows after re-initialisation, want %d", got, len(SeededPools))
	}

	var title string
	if err := second.Read.QueryRow(
		`SELECT TunnelTypeTitle FROM TunnelType WHERE TunnelTypeID = ?`, model.TunnelTypeGRE).Scan(&title); err != nil {
		t.Fatalf("reading the customised lookup row failed: %v", err)
	}
	if title != "GRE (renamed)" {
		t.Errorf("customised lookup title = %q, want it preserved as %q", title, "GRE (renamed)")
	}

	var poolTitle string
	var enabled int
	if err := second.Read.QueryRow(
		`SELECT AddressPoolTitle, IsEnabled FROM AddressPool WHERE Cidr = '109.194.0.0/16'`).
		Scan(&poolTitle, &enabled); err != nil {
		t.Fatalf("reading the customised pool row failed: %v", err)
	}
	if poolTitle != "Adopted legacy range" || enabled != 1 {
		t.Errorf("customised pool = (%q, enabled=%d), want it preserved as (%q, enabled=1)",
			poolTitle, enabled, "Adopted legacy range")
	}

	if got := count(t, second, `SELECT COUNT(*) FROM AppUser`); got != 1 {
		t.Errorf("AppUser has %d rows after re-initialisation, want the 1 that was inserted", got)
	}
}

// TestColumnAdditionsReachAnExistingTable reproduces upgrading an
// installation whose Tunnel table predates a column in columnAdditions:
// CREATE TABLE IF NOT EXISTS is a no-op against a table that already exists,
// so without an explicit ALTER TABLE the column would never arrive and every
// query mentioning it (the whole tunnel list, in DisplayName's case) would
// fail forever.
func TestColumnAdditionsReachAnExistingTable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "panel.db")

	d, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open returned an unexpected error: %v", err)
	}
	defer d.Close()

	// Build the schema as it looked before DisplayName existed, by running
	// every entity statement except the one that creates the Tunnel table
	// with a hand-written definition missing the column, then everything
	// else Init would normally do.
	if err := createLookupTables(ctx, d.Write); err != nil {
		t.Fatalf("createLookupTables returned an unexpected error: %v", err)
	}
	if _, err := d.Write.ExecContext(ctx, `
		CREATE TABLE Tunnel (
			TunnelID          INTEGER PRIMARY KEY AUTOINCREMENT,
			TunnelTypeID      INTEGER NOT NULL,
			TunnelSideID      INTEGER NOT NULL,
			PersistenceTypeID INTEGER NOT NULL,
			InterfaceName     TEXT    NOT NULL,
			LocalEndpoint     TEXT    NOT NULL,
			RemoteEndpoint    TEXT    NOT NULL,
			ApplyStatusID     INTEGER NOT NULL DEFAULT 10,
			IsEnabled         INTEGER NOT NULL DEFAULT 1,
			IsManaged         INTEGER NOT NULL DEFAULT 1,
			IsNameTemplated   INTEGER NOT NULL DEFAULT 1,
			CreatedDate       TEXT    NOT NULL,
			UpdatedDate       TEXT    NOT NULL,
			IsDeleted         INTEGER NOT NULL DEFAULT 0
		)`); err != nil {
		t.Fatalf("creating the pre-migration Tunnel table failed: %v", err)
	}
	if has, err := hasColumn(ctx, d.Write, "Tunnel", "DisplayName"); err != nil {
		t.Fatalf("hasColumn returned an unexpected error: %v", err)
	} else if has {
		t.Fatal("the pre-migration table already has DisplayName; the test fixture is wrong")
	}

	// A real tunnel row, to prove the migration does not disturb existing data.
	now := model.NowUTC()
	if _, err := d.Write.ExecContext(ctx, `
		INSERT INTO Tunnel (TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName,
			LocalEndpoint, RemoteEndpoint, CreatedDate, UpdatedDate)
		VALUES (?, ?, ?, 'gre-a-0', '203.0.113.10', '198.51.100.20', ?, ?)`,
		model.TunnelTypeGRE, model.TunnelSideA, model.PersistenceTypeSystemd, now, now); err != nil {
		t.Fatalf("inserting a pre-migration tunnel failed: %v", err)
	}

	// Upgrading is exactly Init on the existing file — this is what a
	// restart after deploying the new binary does.
	if err := Init(ctx, d); err != nil {
		t.Fatalf("Init against a pre-migration database returned an unexpected error: %v", err)
	}

	if has, err := hasColumn(ctx, d.Write, "Tunnel", "DisplayName"); err != nil {
		t.Fatalf("hasColumn returned an unexpected error: %v", err)
	} else if !has {
		t.Error("DisplayName was not added to an existing Tunnel table")
	}

	var interfaceName string
	var displayName sql.NullString
	if err := d.Read.QueryRow(
		`SELECT InterfaceName, DisplayName FROM Tunnel WHERE InterfaceName = 'gre-a-0'`).
		Scan(&interfaceName, &displayName); err != nil {
		t.Fatalf("reading the pre-migration tunnel after upgrade failed: %v", err)
	}
	if displayName.Valid {
		t.Errorf("DisplayName = %q on a row that predates the column, want NULL", displayName.String)
	}

	// Init must still be idempotent against the now-upgraded table.
	if err := Init(ctx, d); err != nil {
		t.Fatalf("re-running Init after the column was added returned an unexpected error: %v", err)
	}
}

// TestSeedsRunOnEveryStartup proves seeds are not gated on the table being
// empty. Deleting one value and re-initialising must restore it, which is the
// mechanism that carries values added in a later release to an existing
// installation (§6).
func TestSeedsRunOnEveryStartup(t *testing.T) {
	ctx, _, d := openTemp(t)

	if _, err := d.Write.ExecContext(ctx,
		`DELETE FROM MonitorState WHERE MonitorStateID = ?`, model.MonitorStateDisabled); err != nil {
		t.Fatalf("deleting a lookup row failed: %v", err)
	}
	if got := count(t, d, `SELECT COUNT(*) FROM MonitorState WHERE MonitorStateID = ?`,
		model.MonitorStateDisabled); got != 0 {
		t.Fatalf("the lookup row was not deleted")
	}

	if err := Init(ctx, d); err != nil {
		t.Fatalf("re-initialising returned an unexpected error: %v", err)
	}
	if got := count(t, d, `SELECT COUNT(*) FROM MonitorState WHERE MonitorStateID = ?`,
		model.MonitorStateDisabled); got != 1 {
		t.Error("the missing lookup value was not re-seeded; seeds are gated on the table being empty")
	}
}

// TestInterfaceNameUniquenessIgnoresDeletedRows exercises the partial unique
// index: a live duplicate is rejected, but a name freed by a soft delete can be
// reused.
func TestInterfaceNameUniquenessIgnoresDeletedRows(t *testing.T) {
	ctx, _, d := openTemp(t)

	insert := func(name string) error {
		now := model.NowUTC()
		_, err := d.Write.ExecContext(ctx,
			`INSERT INTO Tunnel
				(TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName,
				 LocalEndpoint, RemoteEndpoint, ApplyStatusID, CreatedDate, UpdatedDate)
			 VALUES (?, ?, ?, ?, '203.0.113.1', '198.51.100.1', ?, ?, ?)`,
			model.TunnelTypeGRE, model.TunnelSideA, model.PersistenceTypeSystemd, name,
			model.ApplyStatusPending, now, now)
		return err
	}

	if err := insert("gre-a-1"); err != nil {
		t.Fatalf("inserting the first tunnel failed: %v", err)
	}
	if err := insert("gre-a-1"); err == nil {
		t.Fatal("inserting a duplicate live interface name succeeded, want a uniqueness error")
	}

	if _, err := d.Write.ExecContext(ctx,
		`UPDATE Tunnel SET IsDeleted = 1 WHERE InterfaceName = 'gre-a-1'`); err != nil {
		t.Fatalf("soft-deleting the tunnel failed: %v", err)
	}
	if err := insert("gre-a-1"); err != nil {
		t.Fatalf("reusing the name of a soft-deleted tunnel failed: %v", err)
	}
}

// TestForeignKeysAreEnforced confirms the pragma is not merely set but active.
func TestForeignKeysAreEnforced(t *testing.T) {
	ctx, _, d := openTemp(t)
	now := model.NowUTC()
	_, err := d.Write.ExecContext(ctx,
		`INSERT INTO Tunnel
			(TunnelTypeID, TunnelSideID, PersistenceTypeID, InterfaceName,
			 LocalEndpoint, RemoteEndpoint, ApplyStatusID, CreatedDate, UpdatedDate)
		 VALUES (9999, ?, ?, 'gre-bad-1', '203.0.113.1', '198.51.100.1', ?, ?, ?)`,
		model.TunnelSideA, model.PersistenceTypeSystemd, model.ApplyStatusPending, now, now)
	if err == nil {
		t.Fatal("inserting a tunnel with an unknown TunnelTypeID succeeded, want a foreign key error")
	}
}

func TestHealthyReportsAClosedDatabase(t *testing.T) {
	ctx, _, d := openTemp(t)
	if err := d.Healthy(ctx); err != nil {
		t.Fatalf("Healthy on an open database returned %v, want nil", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close returned an unexpected error: %v", err)
	}
	if err := d.Healthy(ctx); err == nil {
		t.Fatal("Healthy on a closed database returned nil, want an error")
	}
}

func TestFilePermissionsAreRestricted(t *testing.T) {
	_, path, d := openTemp(t)
	if err := d.Harden(); err != nil {
		t.Fatalf("Harden returned an unexpected error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat on the database failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != FileMode {
		t.Errorf("database permissions = %04o, want %04o", perm, FileMode)
	}
}
