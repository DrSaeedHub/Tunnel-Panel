package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/settings"
)

const testPassword = "correct horse battery staple"

func newTestService(t *testing.T) (context.Context, *db.DB, *settings.Store, *Service) {
	t.Helper()
	ctx := context.Background()

	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening the test database failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database failed: %v", err)
	}

	store, err := settings.New(ctx, database)
	if err != nil {
		t.Fatalf("creating the settings store failed: %v", err)
	}
	signer, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("creating the signer failed: %v", err)
	}
	service, err := NewService(ctx, database, store, signer)
	if err != nil {
		t.Fatalf("creating the auth service failed: %v", err)
	}
	return ctx, database, store, service
}

// ---------------------------------------------------------------- passwords

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword returned an unexpected error: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash = %q, want an argon2id PHC string", hash)
	}
	if strings.Contains(hash, testPassword) {
		t.Fatal("the hash contains the plaintext password")
	}

	ok, err := VerifyPassword(hash, testPassword)
	if err != nil {
		t.Fatalf("VerifyPassword returned an unexpected error: %v", err)
	}
	if !ok {
		t.Error("VerifyPassword rejected the correct password")
	}

	ok, err = VerifyPassword(hash, testPassword+"x")
	if err != nil {
		t.Fatalf("VerifyPassword returned an unexpected error: %v", err)
	}
	if ok {
		t.Error("VerifyPassword accepted a wrong password")
	}
}

func TestHashesAreSalted(t *testing.T) {
	first, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword returned an unexpected error: %v", err)
	}
	second, err := HashPassword(testPassword)
	if err != nil {
		t.Fatalf("HashPassword returned an unexpected error: %v", err)
	}
	if first == second {
		t.Error("hashing the same password twice produced identical output; the salt is not random")
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	malformed := []string{
		"",
		"not-a-hash",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",  // wrong algorithm
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdA",        // truncated
		"$argon2id$v=99$m=65536,t=3,p=4$c2FsdA$aGFzaA", // unsupported version
		"$argon2id$v=19$bad-params$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$aGFzaA", // salt is not base64
	}
	for _, hash := range malformed {
		ok, err := VerifyPassword(hash, testPassword)
		if ok {
			t.Errorf("VerifyPassword(%q) accepted a malformed hash", hash)
		}
		if err == nil {
			t.Errorf("VerifyPassword(%q) returned no error for a malformed hash", hash)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	// Eight is the enforced floor; twelve is advice the interface gives and
	// nothing rejects. A rule that refuses a password somebody has already
	// chosen mostly teaches them to append two digits to it.
	if MinPasswordLength != 8 {
		t.Fatalf("MinPasswordLength = %d, want the enforced floor of 8", MinPasswordLength)
	}
	if RecommendedPasswordLength != 12 {
		t.Fatalf("RecommendedPasswordLength = %d, want 12", RecommendedPasswordLength)
	}
	// Between the floor and the recommendation is explicitly allowed.
	if err := ValidatePassword("aB3xY7zQ", "operator"); err != nil {
		t.Errorf("an 8-character password was refused: %v; 12 is a recommendation, not a rule", err)
	}

	tooShort := "aB3xY7" // 6 characters, under the floor
	if err := ValidatePassword(tooShort, "operator"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("ValidatePassword(%q) = %v, want ErrPasswordTooShort", tooShort, err)
	}
	if err := ValidatePassword(strings.Repeat("a", MaxPasswordLength+1), "operator"); !errors.Is(err, ErrPasswordTooLong) {
		t.Error("an over-long password was accepted")
	}

	weak := []string{
		"password123",
		"PASSWORD123",
		"123456789012",
		"abcdefghijkl",
		"aaaaaaaaaaaa",
	}
	for _, pw := range weak {
		if err := ValidatePassword(pw, "operator"); !errors.Is(err, ErrPasswordWeak) &&
			!errors.Is(err, ErrPasswordTooShort) {
			t.Errorf("ValidatePassword(%q) = %v, want it rejected as weak", pw, err)
		}
	}

	if err := ValidatePassword("administrator", "administrator"); !errors.Is(err, ErrPasswordWeak) {
		t.Error("a password identical to the username was accepted")
	}

	good := []string{
		testPassword,
		"Tr0ubador&3-Horse",
		"a-perfectly-fine-passphrase",
	}
	for _, pw := range good {
		if err := ValidatePassword(pw, "operator"); err != nil {
			t.Errorf("ValidatePassword(%q) = %v, want nil", pw, err)
		}
	}
}

// ------------------------------------------------------------------- tokens

func TestSignerIssueAndParse(t *testing.T) {
	signer, err := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewSigner returned an unexpected error: %v", err)
	}

	token, expires, err := signer.Issue(7, "operator", 3, UseAccess, time.Hour)
	if err != nil {
		t.Fatalf("Issue returned an unexpected error: %v", err)
	}
	if !expires.After(time.Now()) {
		t.Error("the token expiry is not in the future")
	}

	claims, err := signer.Parse(token, UseAccess)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if claims.UserID() != 7 {
		t.Errorf("UserID() = %d, want 7", claims.UserID())
	}
	if claims.Username != "operator" {
		t.Errorf("Username = %q, want operator", claims.Username)
	}
	if claims.TokenVersion != 3 {
		t.Errorf("TokenVersion = %d, want 3", claims.TokenVersion)
	}
}

func TestSignerRejectsTheWrongTokenUse(t *testing.T) {
	signer, _ := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	refresh, _, err := signer.Issue(1, "operator", 1, UseRefresh, time.Hour)
	if err != nil {
		t.Fatalf("Issue returned an unexpected error: %v", err)
	}
	if _, err := signer.Parse(refresh, UseAccess); !errors.Is(err, ErrTokenWrongUse) {
		t.Errorf("parsing a refresh token as an access token = %v, want ErrTokenWrongUse", err)
	}
}

func TestSignerRejectsForeignAndExpiredTokens(t *testing.T) {
	mine, _ := NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	theirs, _ := NewSigner([]byte("ffffffffffffffffffffffffffffffff"))

	foreign, _, err := theirs.Issue(1, "operator", 1, UseAccess, time.Hour)
	if err != nil {
		t.Fatalf("Issue returned an unexpected error: %v", err)
	}
	if _, err := mine.Parse(foreign, UseAccess); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("parsing a token signed with another key = %v, want ErrTokenInvalid", err)
	}

	expired, _, err := mine.Issue(1, "operator", 1, UseAccess, -time.Hour)
	if err != nil {
		t.Fatalf("Issue returned an unexpected error: %v", err)
	}
	if _, err := mine.Parse(expired, UseAccess); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("parsing an expired token = %v, want ErrTokenInvalid", err)
	}

	if _, err := mine.Parse("not.a.token", UseAccess); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("parsing garbage = %v, want ErrTokenInvalid", err)
	}
}

func TestNewSignerRejectsAShortKey(t *testing.T) {
	if _, err := NewSigner([]byte("too short")); err == nil {
		t.Error("NewSigner accepted a key shorter than 32 bytes")
	}
}

func TestLoadOrCreateSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwt.key")

	first, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("LoadOrCreateSecret returned an unexpected error: %v", err)
	}
	if len(first) < 32 {
		t.Fatalf("generated secret is %d bytes, want at least 32", len(first))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat on the key file failed: %v", err)
	}
	if perm := info.Mode().Perm(); perm != SecretFileMode {
		t.Errorf("key file permissions = %04o, want %04o", perm, SecretFileMode)
	}

	// A restart must reuse the same key, or every session would be invalidated.
	second, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("second LoadOrCreateSecret returned an unexpected error: %v", err)
	}
	if string(first) != string(second) {
		t.Error("the persisted secret changed between calls")
	}

	// Permissions loosened out of band are tightened rather than trusted.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}
	if _, err := LoadOrCreateSecret(path); err != nil {
		t.Fatalf("LoadOrCreateSecret returned an unexpected error: %v", err)
	}
	info, _ = os.Stat(path)
	if perm := info.Mode().Perm(); perm != SecretFileMode {
		t.Errorf("key file permissions = %04o after reload, want them tightened to %04o", perm, SecretFileMode)
	}

	if err := os.WriteFile(path, []byte("zzzz"), 0o600); err != nil {
		t.Fatalf("writing a malformed key failed: %v", err)
	}
	if _, err := LoadOrCreateSecret(path); err == nil {
		t.Error("LoadOrCreateSecret accepted a malformed key file")
	}
}

// ------------------------------------------------------------------ service

func TestSetupCreatesTheFirstUserOnlyOnce(t *testing.T) {
	ctx, _, _, service := newTestService(t)

	if has, err := service.HasUser(ctx); err != nil || has {
		t.Fatalf("HasUser on a fresh database = (%v, %v), want (false, nil)", has, err)
	}

	user, err := service.Setup(ctx, "operator", testPassword)
	if err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}
	if user.UserID == 0 || user.Username != "operator" || user.TokenVersion != 1 {
		t.Errorf("Setup returned %+v, want a persisted active user with TokenVersion 1", user)
	}
	if has, err := service.HasUser(ctx); err != nil || !has {
		t.Fatalf("HasUser after Setup = (%v, %v), want (true, nil)", has, err)
	}

	if _, err := service.Setup(ctx, "second", testPassword); !errors.Is(err, ErrSetupComplete) {
		t.Errorf("a second Setup = %v, want ErrSetupComplete", err)
	}
}

func TestSetupEnforcesThePasswordPolicy(t *testing.T) {
	ctx, _, _, service := newTestService(t)
	if _, err := service.Setup(ctx, "operator", "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("Setup with a short password = %v, want ErrPasswordTooShort", err)
	}
	// A short username is allowed now: its length protects nothing. What is
	// still refused is a shape that would not survive a URL or a log line.
	if _, err := service.Setup(ctx, "bad name", testPassword); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("Setup with a username containing a space = %v, want ErrInvalidUsername", err)
	}
	if has, _ := service.HasUser(ctx); has {
		t.Error("a rejected Setup still created a user")
	}
}

// TestUnknownUserAndWrongPasswordAreIndistinguishable covers the §18 rule: the
// two failures must produce the same error, or an attacker can enumerate
// accounts.
func TestUnknownUserAndWrongPasswordAreIndistinguishable(t *testing.T) {
	ctx, _, _, service := newTestService(t)
	if _, err := service.Setup(ctx, "operator", testPassword); err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}

	_, unknownErr := service.Authenticate(ctx, "nobody", testPassword, "203.0.113.5")
	_, wrongErr := service.Authenticate(ctx, "operator", "the wrong password", "203.0.113.6")

	if !errors.Is(unknownErr, ErrInvalidCredentials) {
		t.Fatalf("unknown user error = %v, want ErrInvalidCredentials", unknownErr)
	}
	if !errors.Is(wrongErr, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v, want ErrInvalidCredentials", wrongErr)
	}
	if unknownErr.Error() != wrongErr.Error() {
		t.Errorf("errors differ: unknown user %q, wrong password %q", unknownErr, wrongErr)
	}
}

func TestAuthenticateSucceedsAndClearsFailures(t *testing.T) {
	ctx, database, _, service := newTestService(t)
	if _, err := service.Setup(ctx, "operator", testPassword); err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}

	if _, err := service.Authenticate(ctx, "operator", "wrong", "203.0.113.5"); err == nil {
		t.Fatal("authenticating with a wrong password succeeded")
	}
	var failures int
	if err := database.Read.QueryRowContext(ctx,
		`SELECT FailedLoginCount FROM AppUser WHERE Username = 'operator'`).Scan(&failures); err != nil {
		t.Fatalf("reading the failure count failed: %v", err)
	}
	if failures != 1 {
		t.Errorf("FailedLoginCount = %d after one failure, want 1", failures)
	}

	user, err := service.Authenticate(ctx, "operator", testPassword, "203.0.113.5")
	if err != nil {
		t.Fatalf("Authenticate with the correct password returned %v", err)
	}
	if user.LastLoginDate == nil {
		t.Error("LastLoginDate was not recorded on a successful sign-in")
	}
	if err := database.Read.QueryRowContext(ctx,
		`SELECT FailedLoginCount FROM AppUser WHERE Username = 'operator'`).Scan(&failures); err != nil {
		t.Fatalf("reading the failure count failed: %v", err)
	}
	if failures != 0 {
		t.Errorf("FailedLoginCount = %d after a success, want it cleared to 0", failures)
	}
}

func TestAccountLocksAfterTheConfiguredNumberOfFailures(t *testing.T) {
	ctx, _, store, service := newTestService(t)
	if _, err := service.Setup(ctx, "operator", testPassword); err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}
	// A small threshold and a generous rate limit, so this exercises lockout
	// rather than throttling.
	if _, err := store.Update(ctx, map[string]any{
		"security.login_rate_limit_per_minute": 3,
		"security.login_lockout_minutes":       15,
	}, nil); err != nil {
		t.Fatalf("configuring the lockout threshold failed: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := service.Authenticate(ctx, "operator", "wrong", ""); err == nil {
			t.Fatalf("attempt %d with a wrong password succeeded", i+1)
		}
	}

	// Even the correct password is refused while the account is locked.
	_, err := service.Authenticate(ctx, "operator", testPassword, "")
	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("Authenticate after the threshold = %v, want a LockedError", err)
	}
	if !errors.Is(err, ErrAccountLocked) {
		t.Errorf("LockedError does not unwrap to ErrAccountLocked")
	}
	if !locked.Until.After(time.Now()) {
		t.Errorf("locked until %v, want a time in the future", locked.Until)
	}
}

func TestRateLimitingBlocksBeforeTheHashingWork(t *testing.T) {
	ctx, _, store, service := newTestService(t)
	if _, err := service.Setup(ctx, "operator", testPassword); err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}
	if _, err := store.Update(ctx, map[string]any{"security.login_rate_limit_per_minute": 2}, nil); err != nil {
		t.Fatalf("configuring the rate limit failed: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := service.Authenticate(ctx, "nobody", "whatever", "203.0.113.9"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", i+1, err)
		}
	}
	if _, err := service.Authenticate(ctx, "nobody", "whatever", "203.0.113.9"); !errors.Is(err, ErrRateLimited) {
		t.Errorf("the attempt past the limit = %v, want ErrRateLimited", err)
	}
}

// TestPasswordChangeInvalidatesExistingTokens is the TokenVersion guarantee of
// §18: after a password change, every token issued before it stops working.
func TestPasswordChangeInvalidatesExistingTokens(t *testing.T) {
	ctx, _, _, service := newTestService(t)
	user, err := service.Setup(ctx, "operator", testPassword)
	if err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}

	access, _, refresh, _, err := service.IssueSession(user)
	if err != nil {
		t.Fatalf("IssueSession returned an unexpected error: %v", err)
	}
	if _, _, err := service.ResolveToken(ctx, access, UseAccess); err != nil {
		t.Fatalf("the freshly issued access token was rejected: %v", err)
	}

	const newPassword = "an entirely different passphrase"
	updated, err := service.ChangePassword(ctx, user.UserID, testPassword, newPassword)
	if err != nil {
		t.Fatalf("ChangePassword returned an unexpected error: %v", err)
	}
	if updated.TokenVersion != user.TokenVersion+1 {
		t.Errorf("TokenVersion = %d after a password change, want %d",
			updated.TokenVersion, user.TokenVersion+1)
	}

	if _, _, err := service.ResolveToken(ctx, access, UseAccess); !errors.Is(err, ErrTokenSuperseded) {
		t.Errorf("the old access token resolved to %v, want ErrTokenSuperseded", err)
	}
	if _, _, err := service.ResolveToken(ctx, refresh, UseRefresh); !errors.Is(err, ErrTokenSuperseded) {
		t.Errorf("the old refresh token resolved to %v, want ErrTokenSuperseded", err)
	}

	// A session issued after the change works, and the new password is in force.
	newAccess, _, _, _, err := service.IssueSession(updated)
	if err != nil {
		t.Fatalf("IssueSession returned an unexpected error: %v", err)
	}
	if _, _, err := service.ResolveToken(ctx, newAccess, UseAccess); err != nil {
		t.Errorf("the reissued access token was rejected: %v", err)
	}
	if _, err := service.Authenticate(ctx, "operator", newPassword, ""); err != nil {
		t.Errorf("authenticating with the new password failed: %v", err)
	}
	if _, err := service.Authenticate(ctx, "operator", testPassword, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("the old password still works: %v", err)
	}
}

func TestChangePasswordRequiresTheCurrentPassword(t *testing.T) {
	ctx, _, _, service := newTestService(t)
	user, err := service.Setup(ctx, "operator", testPassword)
	if err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}
	if _, err := service.ChangePassword(ctx, user.UserID, "not the password", "a new long passphrase"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("ChangePassword with a wrong current password = %v, want ErrInvalidCredentials", err)
	}
	if _, err := service.ChangePassword(ctx, user.UserID, testPassword, "short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("ChangePassword to a short password = %v, want ErrPasswordTooShort", err)
	}
}

func TestChangeUsername(t *testing.T) {
	ctx, _, _, service := newTestService(t)
	user, err := service.Setup(ctx, "operator", testPassword)
	if err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}
	updated, err := service.ChangeUsername(ctx, user.UserID, "admin.two")
	if err != nil {
		t.Fatalf("ChangeUsername returned an unexpected error: %v", err)
	}
	if updated.Username != "admin.two" {
		t.Errorf("Username = %q, want admin.two", updated.Username)
	}
	if _, err := service.ChangeUsername(ctx, user.UserID, "!!"); !errors.Is(err, ErrInvalidUsername) {
		t.Errorf("ChangeUsername with an invalid name = %v, want ErrInvalidUsername", err)
	}
}

func TestResolveTokenRejectsAnInactiveAccount(t *testing.T) {
	ctx, database, _, service := newTestService(t)
	user, err := service.Setup(ctx, "operator", testPassword)
	if err != nil {
		t.Fatalf("Setup returned an unexpected error: %v", err)
	}
	access, _, _, _, err := service.IssueSession(user)
	if err != nil {
		t.Fatalf("IssueSession returned an unexpected error: %v", err)
	}
	if _, err := database.Write.ExecContext(ctx,
		`UPDATE AppUser SET IsActive = 0 WHERE UserID = ?`, user.UserID); err != nil {
		t.Fatalf("deactivating the user failed: %v", err)
	}
	if _, _, err := service.ResolveToken(ctx, access, UseAccess); !errors.Is(err, ErrAccountInactive) {
		t.Errorf("ResolveToken for an inactive account = %v, want ErrAccountInactive", err)
	}
}

func TestTokenTTLsComeFromSettings(t *testing.T) {
	ctx, _, store, service := newTestService(t)
	if got, want := service.AccessTTL(), 720*time.Minute; got != want {
		t.Errorf("AccessTTL = %v, want the default %v", got, want)
	}
	if got, want := service.RefreshTTL(), 30*24*time.Hour; got != want {
		t.Errorf("RefreshTTL = %v, want the default %v", got, want)
	}
	if _, err := store.Update(ctx, map[string]any{
		"security.token_ttl_minutes": 15,
		"security.refresh_ttl_days":  1,
	}, nil); err != nil {
		t.Fatalf("updating the token settings failed: %v", err)
	}
	if got, want := service.AccessTTL(), 15*time.Minute; got != want {
		t.Errorf("AccessTTL = %v after the settings change, want %v", got, want)
	}
	if got, want := service.RefreshTTL(), 24*time.Hour; got != want {
		t.Errorf("RefreshTTL = %v after the settings change, want %v", got, want)
	}
}

// -------------------------------------------------------------- rate limiter

func TestRateLimiterSlidesItsWindow(t *testing.T) {
	limiter := NewRateLimiter()
	base := time.Now()
	limiter.now = func() time.Time { return base }

	for i := 0; i < 3; i++ {
		if !limiter.Allow("key", 3, time.Minute) {
			t.Fatalf("attempt %d was blocked inside the limit", i+1)
		}
	}
	if limiter.Allow("key", 3, time.Minute) {
		t.Error("the fourth attempt inside the window was allowed")
	}

	// A separate key has its own budget.
	if !limiter.Allow("other", 3, time.Minute) {
		t.Error("a different key was blocked by another key's attempts")
	}

	// Once the window passes, the budget is available again.
	limiter.now = func() time.Time { return base.Add(2 * time.Minute) }
	if !limiter.Allow("key", 3, time.Minute) {
		t.Error("the key was still blocked after its window had passed")
	}
}

func TestRateLimiterResetAndDisable(t *testing.T) {
	limiter := NewRateLimiter()
	for i := 0; i < 5; i++ {
		limiter.Allow("key", 2, time.Minute)
	}
	if limiter.Allow("key", 2, time.Minute) {
		t.Fatal("the key is not blocked")
	}
	limiter.Reset("key")
	if !limiter.Allow("key", 2, time.Minute) {
		t.Error("Reset did not clear the key's history")
	}
	if !limiter.Allow("key", 0, time.Minute) {
		t.Error("a limit of zero should disable the check")
	}
}
