package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/settings"
)

// Errors returned by the service. ErrInvalidCredentials is deliberately the
// single answer for both an unknown username and a wrong password (§18);
// distinguishing them would let an attacker enumerate accounts.
var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is temporarily locked")
	ErrRateLimited        = errors.New("too many login attempts")
	ErrAccountInactive    = errors.New("account is not active")
	ErrSetupComplete      = errors.New("setup has already been completed")
	ErrUsernameTaken      = errors.New("username is already in use")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidUsername    = errors.New("username must be 1-64 characters from A-Z a-z 0-9 . _ - and start with a letter or digit")
)

// usernameRe allows one character upwards. The floor was three, which refused
// "jo" and "ab" for no reason anyone could act on: a username is an identifier
// the operator picked, not a secret, and its length protects nothing. What is
// still enforced is the shape — it must start with a letter or digit and hold
// only characters that survive a URL, a log line and a shell without quoting.
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// LockedError reports how long an account remains locked.
type LockedError struct {
	Until time.Time
}

func (e *LockedError) Error() string {
	return fmt.Sprintf("account is locked until %s", model.FormatTime(e.Until))
}

func (e *LockedError) Unwrap() error { return ErrAccountLocked }

// Service owns authentication state and the AppUser table.
type Service struct {
	database *db.DB
	settings *settings.Store
	signer   *Signer
	limiter  *RateLimiter

	// userExists caches the "has any user been created" answer. It only ever
	// flips false to true, so the SETUP_REQUIRED gate costs one atomic load per
	// request once setup is done, instead of a query.
	userExists atomic.Bool
}

// NewService wires the service. It probes for an existing user immediately so
// the setup gate is correct from the first request.
func NewService(ctx context.Context, database *db.DB, store *settings.Store, signer *Signer) (*Service, error) {
	s := &Service{
		database: database,
		settings: store,
		signer:   signer,
		limiter:  NewRateLimiter(),
	}
	if _, err := s.HasUser(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// Signer exposes the token signer for handlers that need to mint tokens.
func (s *Service) Signer() *Signer { return s.signer }

// HasUser reports whether any operator account exists. Until one does, the API
// serves only setup and health (§18).
func (s *Service) HasUser(ctx context.Context) (bool, error) {
	if s.userExists.Load() {
		return true, nil
	}
	var count int
	err := s.database.Read.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM AppUser WHERE IsDeleted = 0`).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("checking for an existing user: %w", err)
	}
	if count > 0 {
		s.userExists.Store(true)
	}
	return count > 0, nil
}

// AccessTTL and RefreshTTL come from settings so an operator can shorten them
// without a rebuild.
func (s *Service) AccessTTL() time.Duration {
	return time.Duration(s.settings.Int("security.token_ttl_minutes")) * time.Minute
}

func (s *Service) RefreshTTL() time.Duration {
	return time.Duration(s.settings.Int("security.refresh_ttl_days")) * 24 * time.Hour
}

func (s *Service) loginLimit() int {
	return int(s.settings.Int("security.login_rate_limit_per_minute"))
}

func (s *Service) lockoutDuration() time.Duration {
	return time.Duration(s.settings.Int("security.login_lockout_minutes")) * time.Minute
}

// ValidateUsername applies the username policy.
func ValidateUsername(username string) error {
	if !usernameRe.MatchString(username) {
		return ErrInvalidUsername
	}
	return nil
}

// Setup creates the first operator account. It fails once any user exists, so
// the endpoint cannot be used to add a second account without authenticating.
func (s *Service) Setup(ctx context.Context, username, password string) (*model.AppUser, error) {
	username = strings.TrimSpace(username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	if err := ValidatePassword(password, username); err != nil {
		return nil, err
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}
	now := model.NowUTC()

	tx, err := s.database.Write.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("beginning setup transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the commit succeeds

	// Re-check inside the transaction: two concurrent setup requests must not
	// both create an account.
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM AppUser WHERE IsDeleted = 0`).Scan(&count); err != nil {
		return nil, fmt.Errorf("checking for an existing user: %w", err)
	}
	if count > 0 {
		return nil, ErrSetupComplete
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO AppUser
			(Username, PasswordHash, IsActive, FailedLoginCount, TokenVersion,
			 CreatedDate, UpdatedDate, IsDeleted)
		 VALUES (?, ?, 1, 0, 1, ?, ?, 0)`,
		username, hash, now, now)
	if err != nil {
		return nil, fmt.Errorf("creating the first user: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("reading the new user id: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("committing setup: %w", err)
	}
	s.userExists.Store(true)

	return &model.AppUser{
		UserID: id, Username: username, PasswordHash: hash, IsActive: true, TokenVersion: 1,
		Standard: model.Standard{CreatedDate: now, UpdatedDate: now},
	}, nil
}

// Authenticate verifies credentials and applies rate limiting and lockout.
//
// The work done is deliberately the same whether or not the username exists:
// an unknown user still costs one argon2 verification, and the error returned
// is identical.
func (s *Service) Authenticate(ctx context.Context, username, password, clientIP string) (*model.AppUser, error) {
	username = strings.TrimSpace(username)
	limit := s.loginLimit()

	user, err := s.userByUsername(ctx, username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}

	// The lockout is reported before the rate limit, because a locked account
	// costs nothing to detect — one indexed read, no hashing — and "locked
	// until 10:15" tells the operator something a generic throttle does not.
	if user != nil && user.LockedUntilDate != nil {
		if until, perr := model.ParseTime(*user.LockedUntilDate); perr == nil && until.After(time.Now()) {
			return nil, &LockedError{Until: until}
		}
	}

	// Limit by account and by client address separately. Limiting only by
	// account lets one client walk a list of usernames; limiting only by
	// address lets a distributed attempt through. Both checks come before the
	// argon2 verification, which is the expensive part worth protecting.
	if !s.limiter.Allow("user:"+strings.ToLower(username), limit, time.Minute) {
		return nil, ErrRateLimited
	}
	if clientIP != "" && !s.limiter.Allow("ip:"+clientIP, limit*4, time.Minute) {
		return nil, ErrRateLimited
	}

	if user == nil {
		burnPasswordTime(password)
		return nil, ErrInvalidCredentials
	}

	ok, err := VerifyPassword(user.PasswordHash, password)
	if err != nil {
		// A malformed stored hash is an operational fault, not a credential
		// problem, but the caller still learns nothing beyond "no".
		return nil, fmt.Errorf("verifying password for %q: %w", username, err)
	}
	if !ok {
		if err := s.recordFailure(ctx, user, limit); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}
	if !user.IsActive {
		return nil, ErrAccountInactive
	}

	if err := s.recordSuccess(ctx, user); err != nil {
		return nil, err
	}
	s.limiter.Reset("user:" + strings.ToLower(username))
	return user, nil
}

// recordFailure increments the failure counter and locks the account once it
// reaches the configured threshold.
func (s *Service) recordFailure(ctx context.Context, user *model.AppUser, threshold int) error {
	now := model.NowUTC()
	failures := user.FailedLoginCount + 1

	if threshold > 0 && failures >= threshold {
		until := model.FormatTime(time.Now().Add(s.lockoutDuration()))
		_, err := s.database.Write.ExecContext(ctx,
			`UPDATE AppUser SET FailedLoginCount = 0, LockedUntilDate = ?, UpdatedDate = ?
			 WHERE UserID = ?`, until, now, user.UserID)
		if err != nil {
			return fmt.Errorf("locking account: %w", err)
		}
		return nil
	}
	_, err := s.database.Write.ExecContext(ctx,
		`UPDATE AppUser SET FailedLoginCount = ?, UpdatedDate = ? WHERE UserID = ?`,
		failures, now, user.UserID)
	if err != nil {
		return fmt.Errorf("recording failed login: %w", err)
	}
	return nil
}

func (s *Service) recordSuccess(ctx context.Context, user *model.AppUser) error {
	now := model.NowUTC()
	_, err := s.database.Write.ExecContext(ctx,
		`UPDATE AppUser SET FailedLoginCount = 0, LockedUntilDate = NULL,
			LastLoginDate = ?, UpdatedDate = ? WHERE UserID = ?`,
		now, now, user.UserID)
	if err != nil {
		return fmt.Errorf("recording successful login: %w", err)
	}
	user.LastLoginDate = &now
	return nil
}

// IssueSession mints an access and a refresh token for a user.
func (s *Service) IssueSession(user *model.AppUser) (access string, accessExpiry time.Time, refresh string, refreshExpiry time.Time, err error) {
	access, accessExpiry, err = s.signer.Issue(user.UserID, user.Username, user.TokenVersion, UseAccess, s.AccessTTL())
	if err != nil {
		return "", time.Time{}, "", time.Time{}, err
	}
	refresh, refreshExpiry, err = s.signer.Issue(user.UserID, user.Username, user.TokenVersion, UseRefresh, s.RefreshTTL())
	if err != nil {
		return "", time.Time{}, "", time.Time{}, err
	}
	return access, accessExpiry, refresh, refreshExpiry, nil
}

// ResolveToken verifies a token and returns the user it belongs to, rejecting
// tokens whose TokenVersion no longer matches the stored one.
func (s *Service) ResolveToken(ctx context.Context, raw, wantUse string) (*model.AppUser, *Claims, error) {
	claims, err := s.signer.Parse(raw, wantUse)
	if err != nil {
		return nil, nil, err
	}
	user, err := s.UserByID(ctx, claims.UserID())
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, nil, ErrTokenInvalid
		}
		return nil, nil, err
	}
	if user.TokenVersion != claims.TokenVersion {
		return nil, nil, ErrTokenSuperseded
	}
	if !user.IsActive {
		return nil, nil, ErrAccountInactive
	}
	return user, claims, nil
}

// ChangePassword replaces a user's password after verifying the current one and
// increments TokenVersion, which signs every existing session out (§18).
func (s *Service) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword string) (*model.AppUser, error) {
	user, err := s.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	ok, err := VerifyPassword(user.PasswordHash, currentPassword)
	if err != nil {
		return nil, fmt.Errorf("verifying current password: %w", err)
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if err := ValidatePassword(newPassword, user.Username); err != nil {
		return nil, err
	}

	hash, err := HashPassword(newPassword)
	if err != nil {
		return nil, err
	}
	now := model.NowUTC()
	if _, err := s.database.Write.ExecContext(ctx,
		`UPDATE AppUser SET PasswordHash = ?, TokenVersion = TokenVersion + 1, UpdatedDate = ?
		 WHERE UserID = ?`, hash, now, userID); err != nil {
		return nil, fmt.Errorf("changing password: %w", err)
	}
	return s.UserByID(ctx, userID)
}

// ChangeUsername renames a user.
func (s *Service) ChangeUsername(ctx context.Context, userID int64, username string) (*model.AppUser, error) {
	username = strings.TrimSpace(username)
	if err := ValidateUsername(username); err != nil {
		return nil, err
	}
	existing, err := s.userByUsername(ctx, username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}
	if existing != nil && existing.UserID != userID {
		return nil, ErrUsernameTaken
	}
	if _, err := s.database.Write.ExecContext(ctx,
		`UPDATE AppUser SET Username = ?, UpdatedDate = ? WHERE UserID = ?`,
		username, model.NowUTC(), userID); err != nil {
		return nil, fmt.Errorf("changing username: %w", err)
	}
	return s.UserByID(ctx, userID)
}

// UserByID loads a user by primary key.
func (s *Service) UserByID(ctx context.Context, id int64) (*model.AppUser, error) {
	return s.scanUser(s.database.Read.QueryRowContext(ctx, userSelect+` WHERE UserID = ? AND IsDeleted = 0`, id))
}

func (s *Service) userByUsername(ctx context.Context, username string) (*model.AppUser, error) {
	// COLLATE NOCASE would make usernames case-insensitive; they are compared
	// exactly instead, matching how the unique index stores them.
	return s.scanUser(s.database.Read.QueryRowContext(ctx, userSelect+` WHERE Username = ? AND IsDeleted = 0`, username))
}

const userSelect = `
	SELECT UserID, Username, PasswordHash, IsActive, LastLoginDate, FailedLoginCount,
	       LockedUntilDate, TokenVersion, CreatedDate, UpdatedDate, IsDeleted
	FROM AppUser`

func (s *Service) scanUser(row *sql.Row) (*model.AppUser, error) {
	var u model.AppUser
	var lastLogin, lockedUntil sql.NullString
	err := row.Scan(&u.UserID, &u.Username, &u.PasswordHash, &u.IsActive, &lastLogin,
		&u.FailedLoginCount, &lockedUntil, &u.TokenVersion,
		&u.CreatedDate, &u.UpdatedDate, &u.IsDeleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("reading user: %w", err)
	}
	if lastLogin.Valid {
		u.LastLoginDate = &lastLogin.String
	}
	if lockedUntil.Valid {
		u.LockedUntilDate = &lockedUntil.String
	}
	return &u, nil
}
