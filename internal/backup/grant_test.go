package backup

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
)

func newDB(t *testing.T) (context.Context, *db.DB) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatalf("opening a test database: %v", err)
	}
	if err := db.Init(ctx, database); err != nil {
		t.Fatalf("initialising the test database: %v", err)
	}
	t.Cleanup(func() { database.Close() }) //nolint:errcheck // test teardown
	return ctx, database
}

// Asking twice inside the window must give back the same link. Minting a second
// would leave the first working until it expired, so every extra look would
// widen the set of URLs that can read the database — the opposite of what a
// time limit is for.
func TestAskingTwiceReturnsTheSameGrant(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()

	first, err := Issue(ctx, database, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if first.Token == "" {
		t.Fatal("the first issue returned no token")
	}

	second, err := Issue(ctx, database, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("issuing again: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("a second ask created grant %d, want the live one %d", second.ID, first.ID)
	}
	if second.Token != "" {
		t.Error("a reused grant handed out a token; only the hash is stored, so it cannot have one")
	}
	// And the first token still works, which is what "the same link" means.
	if _, err := Redeem(ctx, database, first.Token, now.Add(2*time.Minute)); err != nil {
		t.Errorf("the original token stopped working after a second ask: %v", err)
	}
}

// The expiry is a timestamp in the database, not a timer in the process. This
// is the test for the claim that a restart does not matter: the handle is
// closed and reopened between issuing and redeeming, which is everything a
// restart does to in-process state.
func TestALinkSurvivesTheProcessGoingAway(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "panel.db")

	first, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if err := db.Init(ctx, first); err != nil {
		t.Fatalf("initialising: %v", err)
	}
	now := time.Now()
	grant, err := Issue(ctx, first, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("closing: %v", err)
	}

	second, err := db.Open(ctx, path)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	defer second.Close() //nolint:errcheck // test teardown

	if _, err := Redeem(ctx, second, grant.Token, now.Add(5*time.Minute)); err != nil {
		t.Errorf("the link did not survive the process restarting: %v", err)
	}
}

// And it stops working when the window closes, measured against the clock
// rather than by waiting fifteen minutes.
func TestALinkStopsWorkingWhenTheWindowCloses(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()

	grant, err := Issue(ctx, database, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if _, err := Redeem(ctx, database, grant.Token, now.Add(Window-time.Second)); err != nil {
		t.Errorf("the link was refused one second before expiry: %v", err)
	}
	if _, err := Redeem(ctx, database, grant.Token, now.Add(Window+time.Second)); err == nil {
		t.Error("the link still worked one second after expiry")
	}
}

// An expired grant must not be handed back as the live one, or asking again
// after the window would return "a link is already out" and issue nothing.
func TestAfterExpiryTheNextAskIssuesANewLink(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()

	first, err := Issue(ctx, database, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	later := now.Add(Window + time.Minute)
	second, err := Issue(ctx, database, nil, later)
	if err != nil {
		t.Fatalf("issuing after expiry: %v", err)
	}
	if second.Token == "" {
		t.Fatal("no new token was issued after the first expired")
	}
	if second.ID == first.ID {
		t.Error("the expired grant was reused")
	}
	if _, err := Redeem(ctx, database, first.Token, later); err == nil {
		t.Error("the expired token still worked")
	}
}

func TestAWrongTokenIsRefused(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()
	if _, err := Issue(ctx, database, nil, now); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	for _, bad := range []string{"", "not-a-token", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"} {
		if _, err := Redeem(ctx, database, bad, now); err == nil {
			t.Errorf("the token %q was accepted", bad)
		}
	}
}

// Revoking ends the link now, which is the way to replace one that has been
// shared with the wrong person.
func TestRevokeEndsTheLinkImmediately(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()

	grant, err := Issue(ctx, database, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	if _, err := Revoke(ctx, database, now); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if _, err := Redeem(ctx, database, grant.Token, now.Add(time.Minute)); err == nil {
		t.Error("a revoked token still worked")
	}
	next, err := Issue(ctx, database, nil, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("issuing after revoke: %v", err)
	}
	if next.Token == "" {
		t.Error("no new token was issued after a revoke")
	}
}

// Downloads are counted, because "was this link used, and how often" is the
// question asked after one is shared by mistake.
func TestDownloadsAreCounted(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()

	grant, err := Issue(ctx, database, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	for i := 1; i <= 3; i++ {
		got, err := Redeem(ctx, database, grant.Token, now)
		if err != nil {
			t.Fatalf("redeeming: %v", err)
		}
		if got.Downloads != i {
			t.Errorf("download %d was counted as %d", i, got.Downloads)
		}
	}
}

// Sweeping is housekeeping, not enforcement: Redeem already refuses an expired
// token, so this only tidies. The test says so, because a reader who thinks the
// sweep is what stops an expired link will not look for the real check.
func TestSweepRemovesOnlyExpiredRows(t *testing.T) {
	ctx, database := newDB(t)
	now := time.Now()

	if _, err := Issue(ctx, database, nil, now.Add(-2*Window)); err != nil {
		t.Fatalf("issuing an old grant: %v", err)
	}
	live, err := Issue(ctx, database, nil, now)
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	n, err := Sweep(ctx, database, now)
	if err != nil {
		t.Fatalf("sweeping: %v", err)
	}
	if n != 1 {
		t.Errorf("the sweep removed %d rows, want 1", n)
	}
	if _, err := Redeem(ctx, database, live.Token, now); err != nil {
		t.Errorf("the sweep took the live link with it: %v", err)
	}
}
