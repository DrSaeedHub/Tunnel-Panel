package persist

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/exec"
)

// UnitFileMode is the permission mask for a generated unit file. systemd units
// are ordinarily world-readable and carry no secrets.
const UnitFileMode os.FileMode = 0o644

// BackupSuffix marks a copy of a file the panel took over from something else
// (§17.3). The timestamp keeps repeated takeovers from overwriting each other.
const BackupSuffix = ".gre-panel-backup"

// ErrNotPanelOwned is returned when an operation would delete or overwrite a
// file the panel did not write. It is a hard invariant, not a warning: the file
// belongs to whatever created it (§17.3).
var ErrNotPanelOwned = errors.New("persist: this file was not written by the panel")

// Store reads and writes the generated files and drives systemctl.
type Store struct {
	SystemdDir   string
	NetworkdDir  string
	SystemctlBin string
	Runner       exec.Runner
	// Now supplies the timestamp used in backup file names, injected so a test
	// gets a predictable path.
	Now func() time.Time
}

// NewStore returns a store writing into the given directories.
func NewStore(systemdDir, networkdDir, systemctlBin string, runner exec.Runner) *Store {
	if runner == nil {
		runner = exec.NewRunner()
	}
	return &Store{
		SystemdDir:   systemdDir,
		NetworkdDir:  networkdDir,
		SystemctlBin: systemctlBin,
		Runner:       runner,
		Now:          time.Now,
	}
}

// UnitPath is the absolute path of a tunnel's unit file.
func (s *Store) UnitPath(interfaceName string) string {
	return filepath.Join(s.SystemdDir, UnitName(interfaceName))
}

// KeepaliveUnitPath is the absolute path of a tunnel's keepalive unit file.
func (s *Store) KeepaliveUnitPath(interfaceName string) string {
	return filepath.Join(s.SystemdDir, KeepaliveUnitName(interfaceName))
}

// NetdevPath and NetworkPath are the absolute paths of the networkd files.
func (s *Store) NetdevPath(interfaceName string) string {
	return filepath.Join(s.NetworkdDir, NetdevName(interfaceName))
}

func (s *Store) NetworkPath(interfaceName string) string {
	return filepath.Join(s.NetworkdDir, NetworkName(interfaceName))
}

// Exists reports whether a file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// IsPanelOwned reports whether a file carries the ownership marker. A file that
// does not exist counts as owned, because writing it creates it fresh.
func IsPanelOwned(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", path, err)
	}
	return strings.Contains(string(raw), OwnershipMarker), nil
}

// Write writes a generated file atomically, refusing to overwrite one the panel
// does not own unless takeover is set, and backing the original up first when
// it is (§17.3).
func (s *Store) Write(ctx context.Context, path, content string, takeover bool) (backupPath string, err error) {
	owned, err := IsPanelOwned(path)
	if err != nil {
		return "", err
	}
	if !owned {
		if !takeover {
			return "", fmt.Errorf("%w: %s. Adopt the tunnel with takeover to let the panel manage it",
				ErrNotPanelOwned, path)
		}
		backupPath, err = s.Backup(ctx, path)
		if err != nil {
			return "", err
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return backupPath, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	// Write to a sibling and rename, so a crash mid-write cannot leave systemd
	// reading half a unit file.
	temp := path + ".tmp"
	if err := os.WriteFile(temp, []byte(content), UnitFileMode); err != nil {
		return backupPath, fmt.Errorf("writing %s: %w", temp, err)
	}
	if err := os.Rename(temp, path); err != nil {
		_ = os.Remove(temp)
		return backupPath, fmt.Errorf("installing %s: %w", path, err)
	}
	if err := os.Chmod(path, UnitFileMode); err != nil {
		return backupPath, fmt.Errorf("setting permissions on %s: %w", path, err)
	}
	s.trace(ctx, "write "+path, nil)
	return backupPath, nil
}

// Backup copies a file aside before the panel takes it over (§17.3).
func (s *Store) Backup(ctx context.Context, path string) (string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("reading %s to back it up: %w", path, err)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	backup := fmt.Sprintf("%s%s.%s", path, BackupSuffix, now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, raw, UnitFileMode); err != nil {
		return "", fmt.Errorf("writing the backup %s: %w", backup, err)
	}
	s.trace(ctx, "backup "+path+" to "+backup, nil)
	return backup, nil
}

// Remove deletes a generated file, refusing to delete one the panel did not
// write unless takeover is set, in which case it is backed up first (§17.3).
// Removing a file that is not there is a success.
func (s *Store) Remove(ctx context.Context, path string, takeover bool) (backupPath string, err error) {
	if !Exists(path) {
		return "", nil
	}
	owned, err := IsPanelOwned(path)
	if err != nil {
		return "", err
	}
	if !owned {
		if !takeover {
			return "", fmt.Errorf("%w: %s", ErrNotPanelOwned, path)
		}
		backupPath, err = s.Backup(ctx, path)
		if err != nil {
			return "", err
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return backupPath, fmt.Errorf("removing %s: %w", path, err)
	}
	s.trace(ctx, "remove "+path, nil)
	return backupPath, nil
}

// Read returns the contents of a generated file.
func Read(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (s *Store) trace(ctx context.Context, detail string, err error) {
	op := audit.Operation{Kind: audit.KindFile, Detail: detail}
	if err != nil {
		op.Error = err.Error()
	}
	audit.TraceFrom(ctx).Add(op)
}
