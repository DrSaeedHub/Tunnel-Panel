// Package db owns the SQLite schema, its idempotent initialisation, and the
// connection pools.
//
// The driver is modernc.org/sqlite, a pure-Go implementation: a CGO driver
// would forfeit the static-binary and cross-compilation guarantees the whole
// stack is built around (§3).
package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO
)

// FileMode is the permission mask for the database files (§18).
const FileMode os.FileMode = 0o600

// DB holds the two connection pools. SQLite tolerates exactly one writer, so
// writes go through a pool capped at a single connection while reads use a
// separate pool that never blocks behind a write (§3, §16).
type DB struct {
	Write *sql.DB
	Read  *sql.DB
	Path  string
}

// dsn builds the connection string. The pragmas of §3 are attached to the DSN
// so they are applied to every connection the pool opens, not just the first.
func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	if readOnly {
		q.Set("mode", "ro")
	}
	return "file:" + path + "?" + q.Encode()
}

// Open creates the database file if needed and returns both pools with the
// required pragmas applied. The file and its WAL sidecars are chmodded to 0600.
func Open(ctx context.Context, path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("creating database directory: %w", err)
		}
	}

	write, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		return nil, fmt.Errorf("opening database for writing: %w", err)
	}
	// One writer, held open for the process lifetime: SQLite serialises writers
	// anyway and a single connection keeps WAL checkpointing predictable.
	write.SetMaxOpenConns(1)
	write.SetMaxIdleConns(1)
	write.SetConnMaxLifetime(0)

	if err := write.PingContext(ctx); err != nil {
		write.Close()
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	read, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		write.Close()
		return nil, fmt.Errorf("opening database for reading: %w", err)
	}
	read.SetMaxOpenConns(4)
	read.SetMaxIdleConns(4)
	read.SetConnMaxLifetime(time.Hour)

	d := &DB{Write: write, Read: read, Path: path}
	if err := d.Harden(); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// Harden restricts the database file and its WAL sidecars to 0600. It runs at
// open time and again after initialisation, since the sidecars only appear once
// the first write happens.
func (d *DB) Harden() error {
	for _, suffix := range []string{"", "-wal", "-shm"} {
		p := d.Path + suffix
		if _, err := os.Stat(p); err != nil {
			continue // sidecar not created yet; nothing to harden
		}
		if err := os.Chmod(p, FileMode); err != nil {
			return fmt.Errorf("restricting permissions on %s: %w", p, err)
		}
	}
	return nil
}

// Close closes both pools, returning the first error encountered.
func (d *DB) Close() error {
	var first error
	if d.Read != nil {
		if err := d.Read.Close(); err != nil {
			first = err
		}
	}
	if d.Write != nil {
		if err := d.Write.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// Healthy runs a trivial query against both pools so the health endpoint
// reports the state of the connection rather than the state of a cached flag.
func (d *DB) Healthy(ctx context.Context) error {
	var one int
	if err := d.Read.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil {
		return fmt.Errorf("read pool: %w", err)
	}
	if err := d.Write.PingContext(ctx); err != nil {
		return fmt.Errorf("write pool: %w", err)
	}
	return nil
}
