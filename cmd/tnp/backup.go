package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/backup"
)

// backupLink issues the download link and prints it.
//
// It writes the grant straight to the database rather than asking the panel to,
// which is what makes this work when the panel is not running. The link itself
// is served by the panel, so the operator is told plainly when it is down: a
// URL that cannot answer is worse than a refusal, because it looks like it
// ought to work.
func (a *app) backupLink(ctx context.Context) int {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	database, err := a.openDB(env)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	defer database.Close() //nolint:errcheck // read-only use of the handle

	now := time.Now()
	before, liveErr := backup.Live(ctx, database, now)
	grant, err := backup.Issue(ctx, database, nil, now)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}

	effective, addrErr := a.currentAddress(ctx)
	base := ""
	if addrErr == nil {
		base = fmt.Sprintf("http://%s:%d", panelHost(), effective.Port)
		if effective.WebPath != "" {
			base += "/" + effective.WebPath
		}
	}

	// A reused grant has no token to show: only its hash was kept. Saying so is
	// better than issuing a second link, which would leave the first one
	// working until it expired.
	if liveErr == nil && grant.Token == "" {
		a.sayf("")
		a.sayf("  %s", yellow("A download link is already out."))
		a.sayf("  It expires in %s. The token is not stored, so it cannot be shown again.", humanDuration(before.Remaining()))
		a.sayf("  Downloads so far: %d", before.Downloads)
		a.sayf("")
		a.sayf("  Revoke it and issue a new one with:  tnp backup --new")
		a.sayf("")
		return exitOK
	}

	url := base + "/api/v1/system/backup/download?token=" + grant.Token
	a.emit(map[string]any{
		"url":                url,
		"expires_at":         grant.ExpiresAt.UTC().Format(time.RFC3339),
		"expires_in_seconds": int(grant.Remaining().Seconds()),
	}, func() {
		a.sayf("")
		a.sayf("  %s", bold("Database download link"))
		a.sayf("")
		a.sayf("  %s", cyan(url))
		a.sayf("")
		a.sayf("  Valid for %s, until %s.", humanDuration(backup.Window),
			grant.ExpiresAt.Local().Format("15:04:05"))
		a.sayf("  Asking again inside that window shows this same link.")
		a.sayf("")
		a.sayf("  %s This file holds every operator password hash and the panel's", red("Careful:"))
		a.sayf("  signing key. Anyone with the link can download it until it expires.")
		a.sayf("")
		// Named here because this is where somebody learns the pair exists. A
		// backup nobody knows how to put back is not a backup.
		a.sayf("  To put a file like this back, on this server or another one:")
		a.sayf("    tnp restore <file>   or   %s", cyan(a.restoreURL(ctx)))
		if addrErr != nil {
			a.sayf("")
			a.sayf("  %s the panel's address could not be read, so the host in that URL", yellow("Note:"))
			a.sayf("  is a guess. The token is correct.")
		}
		a.sayf("")
	})
	return exitOK
}

// backupRevoke ends every live link.
func (a *app) backupRevoke(ctx context.Context) int {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	database, err := a.openDB(env)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	defer database.Close() //nolint:errcheck // read-only use of the handle

	n, err := backup.Revoke(ctx, database, time.Now())
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	a.emit(map[string]any{"revoked": n}, func() {
		if n == 0 {
			a.sayf("There was no live link to revoke.")
			return
		}
		a.sayf("Revoked %d link(s). The next 'tnp backup' issues a new one.", n)
	})
	return exitOK
}

// backupSave writes a snapshot to a path on this machine, for an operator who
// would rather scp it than use a link.
func (a *app) backupSave(ctx context.Context, path string) int {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	database, err := a.openDB(env)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	defer database.Close() //nolint:errcheck // read-only use of the handle

	if path == "" {
		path = fmt.Sprintf("gre-panel-%s.db", time.Now().UTC().Format("20060102-150405"))
	}
	abs, _ := filepath.Abs(path)
	size, err := backup.Snapshot(ctx, database, abs)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	a.emit(map[string]any{"path": abs, "size_bytes": size}, func() {
		a.sayf("Wrote %s (%s).", abs, humanBytes(size))
	})
	return exitOK
}

// restoreFrom replaces the live database with a file on this machine.
//
// The panel is stopped first. Replacing the file under a running panel leaves
// it holding a handle to a database that is no longer the one on disk, and the
// next write goes somewhere nobody will look for it again.
func (a *app) restoreFrom(ctx context.Context, path string) int {
	// Naming the page here as well as in the menu, because this is where an
	// operator lands when they type the command without knowing it needs a file
	// already on the server — and the file they want is usually on their own
	// machine, which is what the page is for.
	if strings.TrimSpace(path) == "" {
		a.sayf("")
		a.sayf("  %s  a .db file already on this server:", bold("tnp restore <file>"))
		a.sayf("    %s", dim("tnp restore /root/gre-panel-20260817.db"))
		a.sayf("")
		a.sayf("  To upload one from your own computer, open the restore page,")
		a.sayf("  which shows the progress and signs you back in afterwards:")
		a.sayf("")
		a.sayf("    %s", cyan(a.restoreURL(ctx)))
		a.sayf("")
		return exitUsage
	}
	if _, err := os.Stat(path); err != nil {
		a.failf("There is no file at %s.", path)
		a.sayf("To upload one from your computer instead: %s", cyan(a.restoreURL(ctx)))
		return exitUsage
	}

	env, err := readPanelEnv(a.envPath)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}

	if err := backup.Verify(ctx, path); err != nil {
		a.failf("%v", err)
		return exitFailed
	}
	counts, err := backup.Describe(ctx, path)
	if err != nil {
		a.failf("%v", err)
		return exitFailed
	}

	a.sayf("")
	a.sayf("  Restoring %s", path)
	a.sayf("  It carries %d account(s), %d tunnel(s) and %d forwarding rule(s).",
		counts.Users, counts.Tunnels, counts.Routes)
	a.sayf("")
	a.sayf("  %s everything the panel currently knows is replaced, including", red("This replaces:"))
	a.sayf("  who can log in. The current database is kept as %s.previous", env.DBPath)
	a.sayf("")
	ok, err := a.confirm(ctx, "Restore it?")
	if err != nil {
		return exitCancelled
	}
	if !ok {
		a.sayf("Nothing was changed.")
		return exitCancelled
	}

	wasRunning := strings.HasPrefix(readServiceState(ctx).Active, "active")
	if wasRunning {
		a.sayf("Stopping the panel.")
		if _, err := systemctl(ctx, "stop", serviceName); err != nil {
			a.sayf("The panel would not stop: %v", err)
			return exitFailed
		}
	}

	// The file is copied into place rather than moved, so the operator still
	// has the file they named if anything below fails.
	staged := env.DBPath + ".incoming"
	if err := copyPath(path, staged); err != nil {
		a.failf("%v", err)
		if wasRunning {
			systemctl(ctx, "start", serviceName) //nolint:errcheck // best effort
		}
		return exitFailed
	}
	if err := backup.Install(env.DBPath, staged); err != nil {
		a.failf("%v", err)
		if wasRunning {
			systemctl(ctx, "start", serviceName) //nolint:errcheck // best effort
		}
		return exitRollbackFailed
	}

	a.sayf("Starting the panel.")
	if _, err := systemctl(ctx, "start", serviceName); err != nil {
		a.sayf("The database was restored but the panel did not start: %v", err)
		a.sayf("The previous database is at %s.previous", env.DBPath)
		return exitRollbackFailed
	}

	a.emit(map[string]any{
		"restored": true, "users": counts.Users,
		"tunnels": counts.Tunnels, "routes": counts.Routes,
	}, func() {
		a.sayf("")
		a.sayf("  %s", green("Restored."))
		a.sayf("  Tunnels and forwarding rules are being applied from the restored database.")
		a.sayf("  Sign in with an account from the backup; the previous ones are gone.")
		a.sayf("")
	})
	return exitOK
}

// panelHost is the address to put in a link. The panel binds 0.0.0.0, which is
// not something anyone can paste, so the first non-loopback address of this
// host is used and the operator is told it is a guess.
func panelHost() string {
	if out, err := exec.Command("hostname", "-I").Output(); err == nil {
		if fields := strings.Fields(string(out)); len(fields) > 0 {
			return fields[0]
		}
	}
	return "127.0.0.1"
}

func copyPath(from, to string) error {
	data, err := os.ReadFile(from)
	if err != nil {
		return fmt.Errorf("reading %s: %w", from, err)
	}
	if err := os.WriteFile(to, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", to, err)
	}
	return nil
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d >= time.Minute {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%d minutes", m)
		}
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%d seconds", int(d.Seconds()))
}
