package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/settings"
)

// testApp builds a CLI pointed at a temporary installation: its own environment
// file, its own database, and buffers instead of the terminal.
func testApp(t *testing.T) (*app, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "panel.db")
	envPath := filepath.Join(dir, "gre-panel.env")

	body := fmt.Sprintf("GRE_PANEL_DATA_DIR=%s\nGRE_PANEL_DB_PATH=%s\n"+
		"GRE_PANEL_BIND_HOST=127.0.0.1\nGRE_PANEL_BIND_PORT=18443\nGRE_PANEL_WEB_PATH=abc123\n",
		dir, dbPath)
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the environment file: %v", err)
	}

	a := &app{
		envPath: envPath,
		out:     &bytes.Buffer{},
		err:     &bytes.Buffer{},
		in:      strings.NewReader(""),
	}
	return a, dbPath
}

// seedPanelDatabase creates the schema and one operator account, the way a real
// installation looks after its first run.
func seedPanelDatabase(t *testing.T, dbPath, username, password string) *db.DB {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising: %v", err)
	}
	store, err := settings.New(ctx, database)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	signer, err := auth.NewSigner([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	service, err := auth.NewService(ctx, database, store, signer)
	if err != nil {
		t.Fatalf("auth service: %v", err)
	}
	if _, err := service.Setup(ctx, username, password); err != nil {
		t.Fatalf("creating the first account: %v", err)
	}
	return database
}

// The three things that make this a reset rather than a hash swap: the new
// password verifies, TokenVersion moves so every session dies, and the lockout
// is cleared.
func TestResetPasswordRevokesSessionsAndClearsTheLockout(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	database := seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	// Lock the account the way a forgotten password locks it, so the clearing
	// is a real change rather than a no-op that would pass either way.
	if _, err := database.Write.ExecContext(ctx,
		`UPDATE AppUser SET FailedLoginCount = 5, LockedUntilDate = '2099-01-01T00:00:00Z'
		  WHERE Username = 'operator'`); err != nil {
		t.Fatalf("locking the account: %v", err)
	}

	before, err := findUser(ctx, database, "operator")
	if err != nil {
		t.Fatalf("reading before: %v", err)
	}

	change, err := a.resetPassword(ctx, "operator", "a new and better password")
	if err != nil {
		t.Fatalf("resetting: %v", err)
	}

	after, err := findUser(ctx, database, "operator")
	if err != nil {
		t.Fatalf("reading after: %v", err)
	}
	if after.TokenVersion != before.TokenVersion+1 {
		t.Errorf("TokenVersion went %d -> %d, want +1; without that every existing session "+
			"stays valid and the reset does not lock anyone out",
			before.TokenVersion, after.TokenVersion)
	}
	if !change.SessionsRevoked {
		t.Error("the result does not report that sessions were revoked")
	}
	if after.LockedUntilDate != nil || after.FailedLoginCount != 0 {
		t.Errorf("the account is still locked (until %v, %d failures) after a reset",
			after.LockedUntilDate, after.FailedLoginCount)
	}
	if !change.LockoutCleared {
		t.Error("the result does not report that the lockout was cleared")
	}

	// The new password verifies against the stored hash, and the old one does
	// not. Checking only the first would pass against a hash that was never
	// replaced.
	var hash string
	if err := database.Read.QueryRowContext(ctx,
		`SELECT PasswordHash FROM AppUser WHERE Username = 'operator'`).Scan(&hash); err != nil {
		t.Fatalf("reading the hash: %v", err)
	}
	if ok, err := auth.VerifyPassword(hash, "a new and better password"); err != nil || !ok {
		t.Errorf("the new password does not verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := auth.VerifyPassword(hash, "correct horse battery staple"); ok {
		t.Error("the old password still verifies, so nothing was actually replaced")
	}
}

func TestResetPasswordIsAudited(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	database := seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	if _, err := a.resetPassword(ctx, "operator", "a new and better password"); err != nil {
		t.Fatalf("resetting: %v", err)
	}

	var count int
	var request, clientIP string
	err := database.Read.QueryRowContext(ctx,
		`SELECT COUNT(*), MAX(RequestJson), MAX(ClientIp) FROM AuditLog WHERE AuditActionID = ?`,
		model.AuditActionPasswordReset).Scan(&count, &request, &clientIP)
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	if count != 1 {
		t.Fatalf("%d audit entries, want exactly 1", count)
	}
	if !strings.Contains(request, "operator") || !strings.Contains(request, "tnp") {
		t.Errorf("the entry does not say who was changed or by what: %s", request)
	}
	if strings.Contains(request, "a new and better password") {
		t.Errorf("the audit entry contains the password: %s", request)
	}
	if clientIP == "" {
		t.Error("the entry has no client address at all; it should say this was local")
	}
}

// The policy is the panel's, not a second copy of it, so a password the panel
// would refuse is refused here too.
func TestResetPasswordAppliesThePanelsOwnPolicy(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	for _, bad := range []string{"", "password123", "changeme1234", "123456789012"} {
		if _, err := a.resetPassword(ctx, "operator", bad); err == nil {
			t.Errorf("the password %q was accepted; the panel itself refuses it", bad)
		}
	}
}

// An operator who has forgotten the password has often forgotten the username.
// With one account there is no ambiguity to resolve.
func TestTheOnlyAccountNeedsNoName(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	database := seedPanelDatabase(t, dbPath, "the-only-one", "correct horse battery staple")

	change, err := a.resetPassword(ctx, "", "a new and better password")
	if err != nil {
		t.Fatalf("resetting without a username: %v", err)
	}
	if change.Username != "the-only-one" {
		t.Errorf("changed %q, want the only account", change.Username)
	}

	// With two, guessing would be worse than refusing, and the refusal has to
	// list them.
	if _, err := database.Write.ExecContext(ctx,
		`INSERT INTO AppUser (Username, PasswordHash, IsActive, FailedLoginCount, TokenVersion,
			CreatedDate, UpdatedDate, IsDeleted)
		 VALUES ('second', 'x', 1, 0, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0)`); err != nil {
		t.Fatalf("adding a second account: %v", err)
	}
	_, err = a.resetPassword(ctx, "", "a new and better password")
	if err == nil {
		t.Fatal("with two accounts the reset picked one on its own")
	}
	if !strings.Contains(err.Error(), "the-only-one") || !strings.Contains(err.Error(), "second") {
		t.Errorf("the refusal does not list the accounts to choose from: %v", err)
	}
}

func TestAnUnknownAccountIsReportedWithTheOnesThatExist(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	_, err := a.resetPassword(ctx, "nobody", "a new and better password")
	if err == nil {
		t.Fatal("resetting an account that does not exist succeeded")
	}
	if !strings.Contains(err.Error(), "operator") {
		t.Errorf("the error does not say which accounts exist: %v", err)
	}
}

// A rename must not sign anyone out: a session identifies the account, not the
// name, and forcing a re-login for it would be theatre.
func TestRenamingKeepsSessionsAlive(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	database := seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	before, _ := findUser(ctx, database, "operator")
	change, err := a.setUsername(ctx, "operator", "admin")
	if err != nil {
		t.Fatalf("renaming: %v", err)
	}
	after, err := findUser(ctx, database, "admin")
	if err != nil {
		t.Fatalf("the renamed account cannot be found: %v", err)
	}
	if after.UserID != before.UserID {
		t.Errorf("the rename created a new account (%d -> %d)", before.UserID, after.UserID)
	}
	if after.TokenVersion != before.TokenVersion {
		t.Errorf("TokenVersion moved %d -> %d on a rename, signing everyone out for no reason",
			before.TokenVersion, after.TokenVersion)
	}
	if change.PreviousName != "operator" {
		t.Errorf("previous name = %q", change.PreviousName)
	}
}

func TestRenamingRefusesANameAlreadyInUseAndAnInvalidOne(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)
	database := seedPanelDatabase(t, dbPath, "operator", "correct horse battery staple")

	if _, err := database.Write.ExecContext(ctx,
		`INSERT INTO AppUser (Username, PasswordHash, IsActive, FailedLoginCount, TokenVersion,
			CreatedDate, UpdatedDate, IsDeleted)
		 VALUES ('taken', 'x', 1, 0, 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 0)`); err != nil {
		t.Fatalf("adding the other account: %v", err)
	}

	if _, err := a.setUsername(ctx, "operator", "taken"); err == nil {
		t.Error("a username already in use was accepted")
	}
	// "ab" is deliberately absent: a short username is allowed now, because its
	// length protects nothing. The shape is still enforced.
	for _, bad := range []string{"", "has space", "-leading"} {
		if _, err := a.setUsername(ctx, "operator", bad); err == nil {
			t.Errorf("the invalid username %q was accepted", bad)
		}
	}
}

// The CLI must say so plainly when there is no installation here, rather than
// creating an empty database and reporting success against it.
func TestAMissingDatabaseIsAnErrorRatherThanANewOne(t *testing.T) {
	ctx := context.Background()
	a, dbPath := testApp(t)

	_, err := a.resetPassword(ctx, "operator", "a new and better password")
	if err == nil {
		t.Fatal("resetting against a host with no panel succeeded")
	}
	if !strings.Contains(err.Error(), "no panel database") {
		t.Errorf("the error does not name the cause: %v", err)
	}
	if _, statErr := os.Stat(dbPath); statErr == nil {
		t.Error("an empty database was created by a command that should have refused")
	}
}
