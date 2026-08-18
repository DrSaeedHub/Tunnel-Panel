package auth

import (
	"errors"
	"testing"
	"time"
)

// The lockout window is the one security.* setting nothing asserted the value
// of. TestAccountLocksAfterTheConfiguredNumberOfFailures sets it to fifteen
// minutes and then only checks that the lock expires at some point in the
// future, which any positive duration satisfies — including a hardcoded one.
//
// The duration is the setting's whole content: an operator who shortens it to
// two minutes is trading a little security for not locking themselves out of
// their own panel before a maintenance window, and one who lengthens it to a day
// means it. Getting a different number than the one on the Settings page is a
// defect in both directions.
func TestTheLockoutDurationFollowsTheSetting(t *testing.T) {
	for _, minutes := range []int64{2, 240} {
		ctx, _, store, service := newTestService(t)
		if _, err := service.Setup(ctx, "operator", testPassword); err != nil {
			t.Fatalf("Setup failed: %v", err)
		}
		// A generous rate limit, so this exercises lockout rather than
		// throttling, and a threshold small enough to reach quickly.
		if _, err := store.Update(ctx, map[string]any{
			"security.login_rate_limit_per_minute": 3,
			"security.login_lockout_minutes":       minutes,
		}, nil); err != nil {
			t.Fatalf("configuring the lockout failed: %v", err)
		}

		for i := 0; i < 3; i++ {
			if _, err := service.Authenticate(ctx, "operator", "wrong", ""); err == nil {
				t.Fatalf("attempt %d with a wrong password succeeded", i+1)
			}
		}

		before := time.Now()
		_, err := service.Authenticate(ctx, "operator", testPassword, "")
		var locked *LockedError
		if !errors.As(err, &locked) {
			t.Fatalf("Authenticate past the threshold = %v, want a LockedError", err)
		}

		// The lock was stamped between the last failure and now, so the window
		// it grants is bounded on both sides by the configured length. A minute
		// of slack covers the time the hashing work takes.
		want := time.Duration(minutes) * time.Minute
		granted := locked.Until.Sub(before)
		if granted > want || granted < want-time.Minute {
			t.Fatalf("a %d-minute lockout locked the account for %s, want about %s",
				minutes, granted.Round(time.Second), want)
		}
	}
}
