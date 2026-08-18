package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/model"
)

// accountChange is what a reset or a rename did.
type accountChange struct {
	UserID          int64  `json:"user_id"`
	Username        string `json:"username"`
	PreviousName    string `json:"previous_username,omitempty"`
	TokenVersion    int64  `json:"token_version"`
	SessionsRevoked bool   `json:"sessions_revoked"`
	LockoutCleared  bool   `json:"lockout_cleared"`
	Detail          string `json:"detail"`
}

// resetPassword sets a password without knowing the old one.
//
// It goes straight to the database on purpose. The API cannot do this: every
// route that changes a password requires a session, and the operator asking for
// this is by definition the one who cannot get a session. Root already owns the
// machine — the database, the signing key and the binary are all readable to
// it — so this is not an escalation, it is the recovery path that the panel
// would otherwise not have.
//
// Three things make it a real reset rather than a hash swap:
//
//   - TokenVersion is incremented, which is how the panel signs every existing
//     session out. Every request resolves its token against the stored version,
//     so this takes effect immediately and without a restart.
//   - The lockout is cleared. An operator who has forgotten their password has
//     usually locked the account trying to remember it, and leaving them locked
//     out with a working password is a cruel way to finish.
//   - It is written to the audit log. A password changed by someone who could
//     not log in is exactly the event that has to be findable afterwards.
func (a *app) resetPassword(ctx context.Context, username, password string) (*accountChange, error) {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		return nil, err
	}
	database, err := a.openDB(env)
	if err != nil {
		return nil, err
	}
	defer database.Close() //nolint:errcheck // closed on the way out

	user, err := findUser(ctx, database, username)
	if err != nil {
		return nil, err
	}
	if err := auth.ValidatePassword(password, user.Username); err != nil {
		return nil, fmt.Errorf("that password is not acceptable: %w", err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := model.NowUTC()
	res, err := database.Write.ExecContext(ctx,
		`UPDATE AppUser
		    SET PasswordHash = ?, TokenVersion = TokenVersion + 1,
		        FailedLoginCount = 0, LockedUntilDate = NULL, IsActive = 1, UpdatedDate = ?
		  WHERE UserID = ?`, hash, now, user.UserID)
	if err != nil {
		return nil, fmt.Errorf("resetting the password: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, fmt.Errorf("resetting the password changed %d rows, want 1", n)
	}

	after, err := findUser(ctx, database, user.Username)
	if err != nil {
		return nil, err
	}
	change := &accountChange{
		UserID: after.UserID, Username: after.Username,
		TokenVersion:    after.TokenVersion,
		SessionsRevoked: after.TokenVersion > user.TokenVersion,
		LockoutCleared:  user.LockedUntilDate != nil || user.FailedLoginCount > 0,
	}
	change.Detail = fmt.Sprintf("The password for %s was reset. Every existing session is now "+
		"invalid, so anyone signed in has been signed out.", after.Username)
	if change.LockoutCleared {
		change.Detail += " The account was locked or had failed attempts recorded; that was cleared."
	}

	a.audit(ctx, database, model.AuditActionPasswordReset, true, map[string]any{
		"username": after.Username, "actor": "tnp",
		"token_version_from": user.TokenVersion, "token_version_to": after.TokenVersion,
		"lockout_cleared": change.LockoutCleared,
	}, "")
	return change, nil
}

// setUsername renames the operator account.
//
// Unlike the password, this does not invalidate sessions. The token carries the
// name for display, and the identity it resolves against is the user id, so a
// rename does not change who anyone is. Forcing a re-login for it would be
// theatre.
func (a *app) setUsername(ctx context.Context, current, wanted string) (*accountChange, error) {
	env, err := readPanelEnv(a.envPath)
	if err != nil {
		return nil, err
	}
	database, err := a.openDB(env)
	if err != nil {
		return nil, err
	}
	defer database.Close() //nolint:errcheck // closed on the way out

	wanted = strings.TrimSpace(wanted)
	if err := auth.ValidateUsername(wanted); err != nil {
		return nil, err
	}
	user, err := findUser(ctx, database, current)
	if err != nil {
		return nil, err
	}
	if existing, err := findUser(ctx, database, wanted); err == nil && existing.UserID != user.UserID {
		return nil, fmt.Errorf("the username %q is already in use", wanted)
	}

	if _, err := database.Write.ExecContext(ctx,
		`UPDATE AppUser SET Username = ?, UpdatedDate = ? WHERE UserID = ?`,
		wanted, model.NowUTC(), user.UserID); err != nil {
		return nil, fmt.Errorf("changing the username: %w", err)
	}

	change := &accountChange{
		UserID: user.UserID, Username: wanted, PreviousName: user.Username,
		TokenVersion: user.TokenVersion,
		Detail: fmt.Sprintf("%s is now %s. Existing sessions keep working: a session identifies "+
			"the account, not the name.", user.Username, wanted),
	}
	a.audit(ctx, database, model.AuditActionUsernameChange, true, map[string]any{
		"username": wanted, "previous_username": user.Username, "actor": "tnp",
	}, "")
	return change, nil
}

// storedUser is the subset of AppUser the CLI reads.
type storedUser struct {
	UserID           int64
	Username         string
	TokenVersion     int64
	FailedLoginCount int64
	LockedUntilDate  *string
	IsActive         bool
}

// findUser looks an account up by name, or returns the only account when no
// name is given.
//
// The single-account case matters: an operator who has forgotten the password
// has often forgotten the username too, and refusing to act because they cannot
// name the one account on the machine would be unhelpful. Where there is more
// than one, the name is required and the list is printed.
func findUser(ctx context.Context, database dbHandle, username string) (*storedUser, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		names, err := listUsernames(ctx, database)
		if err != nil {
			return nil, err
		}
		switch len(names) {
		case 0:
			return nil, errors.New("this panel has no operator account yet; create one at its " +
				"first-run screen, or reinstall")
		case 1:
			username = names[0]
		default:
			return nil, fmt.Errorf("this panel has %d accounts (%s); name the one to change with "+
				"--username", len(names), strings.Join(names, ", "))
		}
	}

	var u storedUser
	var locked sql.NullString
	err := database.Read.QueryRowContext(ctx,
		`SELECT UserID, Username, TokenVersion, FailedLoginCount, LockedUntilDate, IsActive
		   FROM AppUser WHERE Username = ? AND IsDeleted = 0`, username).
		Scan(&u.UserID, &u.Username, &u.TokenVersion, &u.FailedLoginCount, &locked, &u.IsActive)
	if errors.Is(err, sql.ErrNoRows) {
		names, _ := listUsernames(ctx, database)
		if len(names) == 0 {
			return nil, fmt.Errorf("there is no account named %q, and this panel has none at all", username)
		}
		return nil, fmt.Errorf("there is no account named %q; this panel has: %s",
			username, strings.Join(names, ", "))
	}
	if err != nil {
		return nil, fmt.Errorf("reading the account: %w", err)
	}
	if locked.Valid {
		u.LockedUntilDate = &locked.String
	}
	return &u, nil
}

func listUsernames(ctx context.Context, database dbHandle) ([]string, error) {
	rows, err := database.Read.QueryContext(ctx,
		`SELECT Username FROM AppUser WHERE IsDeleted = 0 ORDER BY UserID`)
	if err != nil {
		return nil, fmt.Errorf("listing accounts: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}
