//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// dataDirLock is an advisory lock held for the lifetime of the process.
type dataDirLock struct {
	file *os.File
	// held is false when the filesystem does not support locking; the lock file
	// still exists, but it guarantees nothing.
	held bool
}

// acquireDataDirLock takes an exclusive advisory lock on the data directory so
// two panel instances cannot manage the same host (§16).
//
// A filesystem that does not implement flock is reported to the caller as a
// warning rather than treated as a failure: refusing to start there would be a
// worse outcome than starting without the guarantee.
func acquireDataDirLock(path string) (*dataDirLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the lock file %s: %w", path, err)
	}

	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		// Record which process holds it, so the message the next instance sees
		// names something actionable.
		_ = f.Truncate(0)
		if _, werr := f.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0); werr != nil {
			// Not fatal: the lock itself is held, only the hint is missing.
			_ = werr
		}
		return &dataDirLock{file: f, held: true}, nil

	case errors.Is(err, unix.EWOULDBLOCK):
		holder := readLockHolder(f)
		f.Close()
		return nil, fmt.Errorf("another gre-panel instance is already using this data directory "+
			"(lock file %s%s). Stop it before starting another, or point this one at a different "+
			"GRE_PANEL_DATA_DIR", path, holder)

	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOLCK), errors.Is(err, unix.EINVAL):
		// Network and emulated filesystems sometimes lack flock entirely.
		return &dataDirLock{file: f, held: false}, nil

	default:
		f.Close()
		return nil, fmt.Errorf("locking the data directory: %w", err)
	}
}

func readLockHolder(f *os.File) string {
	buf := make([]byte, 32)
	n, err := f.ReadAt(buf, 0)
	if n <= 0 || (err != nil && n == 0) {
		return ""
	}
	pid := string(buf[:n])
	for i, c := range pid {
		if c == '\n' {
			pid = pid[:i]
			break
		}
	}
	if pid == "" {
		return ""
	}
	return ", held by pid " + pid
}

// Held reports whether the advisory lock is actually enforced.
func (l *dataDirLock) Held() bool { return l != nil && l.held }

// Release unlocks and closes the lock file.
func (l *dataDirLock) Release() {
	if l == nil || l.file == nil {
		return
	}
	if l.held {
		_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	}
	_ = l.file.Close()
}
