package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/db"
)

// sqliteMagic is the first 16 bytes of every SQLite 3 file. Checking it costs
// nothing and turns "this upload is not a database" into a clear refusal
// instead of a confusing failure several steps later.
const sqliteMagic = "SQLite format 3\x00"

// tablesARestoreMustHave are the tables that make a file this panel's database
// rather than somebody else's. The list is deliberately short: enough to catch
// a wrong file, not so long that a database from a slightly different version
// is refused for a table nobody needs.
var tablesARestoreMustHave = []string{"AppUser", "Tunnel", "RouteRule", "AppSetting"}

// Snapshot writes a consistent copy of the live database to path.
//
// VACUUM INTO rather than copying the file. The panel runs in WAL mode with
// writers active, so the file on disk is not the database — recent commits live
// in the -wal until a checkpoint, and a plain copy can land anywhere between
// two transactions. VACUUM INTO takes a read lock and writes a complete,
// checkpointed database, which is the only form worth handing to somebody as a
// backup.
func Snapshot(ctx context.Context, database *db.DB, path string) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, fmt.Errorf("preparing the snapshot directory: %w", err)
	}
	// VACUUM INTO refuses to overwrite, so a leftover from a previous attempt
	// would fail the next one with a confusing error.
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("clearing the previous snapshot: %w", err)
	}
	if _, err := database.Write.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return 0, fmt.Errorf("taking the snapshot: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("measuring the snapshot: %w", err)
	}
	return info.Size(), nil
}

// Verify reports whether path is a SQLite database this panel could restore.
//
// It opens the file read-only and asks it what tables it has. Reading the magic
// bytes alone would accept a corrupt file with the right first sixteen bytes,
// and accepting somebody else's SQLite database would replace the panel's
// state with something that has no operator account in it — which locks the
// operator out of the panel with no way back except the CLI.
func Verify(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening the uploaded file: %w", err)
	}
	header := make([]byte, len(sqliteMagic))
	n, readErr := io.ReadFull(f, header)
	f.Close() //nolint:errcheck // read-only
	if readErr != nil || n != len(sqliteMagic) || string(header) != sqliteMagic {
		return errors.New("this is not a SQLite database file")
	}

	// Read-only, and immutable so opening it cannot create a -wal beside a file
	// that is about to be moved.
	handle, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return fmt.Errorf("opening the uploaded database: %w", err)
	}
	defer handle.Close() //nolint:errcheck // read-only

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var missing []string
	for _, table := range tablesARestoreMustHave {
		var name string
		err := handle.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			missing = append(missing, table)
			continue
		}
		if err != nil {
			return fmt.Errorf("reading the uploaded database: %w", err)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("this database is missing %s, so it is not a panel backup",
			strings.Join(missing, ", "))
	}

	// A backup with no operator account would restore a panel nobody can log
	// in to. Better to refuse it now, while the current one still works.
	var users int
	if err := handle.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM AppUser WHERE IsDeleted = 0`).Scan(&users); err != nil {
		return fmt.Errorf("counting the accounts in the uploaded database: %w", err)
	}
	if users == 0 {
		return errors.New("this database has no operator account, so restoring it would lock you out")
	}
	return nil
}

// Counts reports what a verified backup would bring with it, for telling an
// operator what they are about to restore before they commit to it.
type Counts struct {
	Users   int `json:"users"`
	Tunnels int `json:"tunnels"`
	Routes  int `json:"routes"`
}

// Describe counts the interesting rows in a database file.
func Describe(ctx context.Context, path string) (Counts, error) {
	handle, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		return Counts{}, fmt.Errorf("opening the uploaded database: %w", err)
	}
	defer handle.Close() //nolint:errcheck // read-only

	var c Counts
	for _, q := range []struct {
		sql  string
		into *int
	}{
		{`SELECT COUNT(*) FROM AppUser WHERE IsDeleted = 0`, &c.Users},
		{`SELECT COUNT(*) FROM Tunnel WHERE IsDeleted = 0`, &c.Tunnels},
		{`SELECT COUNT(*) FROM RouteRule WHERE IsDeleted = 0`, &c.Routes},
	} {
		if err := handle.QueryRowContext(ctx, q.sql).Scan(q.into); err != nil {
			return Counts{}, fmt.Errorf("counting rows in the uploaded database: %w", err)
		}
	}
	return c, nil
}

// Install puts a verified database file in place of the live one.
//
// The current database is kept beside it as .previous rather than deleted. A
// restore is the one operation that discards everything the panel knows, and
// the cost of keeping the old file until the next restore is one copy on disk
// against the operator having no way back at all.
//
// The -wal and -shm are removed, not moved: they belong to the database being
// replaced, and leaving them beside a different file is how SQLite is handed a
// journal that does not match its database.
func Install(livePath, uploaded string) error {
	if _, err := os.Stat(uploaded); err != nil {
		return fmt.Errorf("the uploaded database is not there: %w", err)
	}
	previous := livePath + ".previous"
	if _, err := os.Stat(livePath); err == nil {
		if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clearing the previous backup: %w", err)
		}
		if err := os.Rename(livePath, previous); err != nil {
			return fmt.Errorf("setting the current database aside: %w", err)
		}
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(livePath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clearing %s: %w", livePath+suffix, err)
		}
	}
	if err := os.Rename(uploaded, livePath); err != nil {
		// Rename fails across filesystems; the upload may be in a temp
		// directory on another mount, so fall back to a copy.
		if copyErr := copyFile(uploaded, livePath); copyErr != nil {
			return fmt.Errorf("putting the uploaded database in place: %w", copyErr)
		}
		os.Remove(uploaded) //nolint:errcheck // best effort
	}
	return os.Chmod(livePath, 0o600)
}

func copyFile(from, to string) error {
	src, err := os.Open(from)
	if err != nil {
		return err
	}
	defer src.Close() //nolint:errcheck // read-only

	dst, err := os.OpenFile(to, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close() //nolint:errcheck // the copy already failed
		return err
	}
	return dst.Close()
}
