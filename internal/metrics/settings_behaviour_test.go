package metrics

import (
	"context"
	"testing"
	"time"
)

// The tests in this file are the second half of the settings guard. The coarse
// one in internal/api proves each key is named somewhere outside its own schema
// entry, which only establishes that a reader exists; these prove the reader
// honours what it read. The defect they exist to catch is the one this codebase
// keeps producing: a setting that is stored, validated and described on the
// Settings page, and then quietly ignored by the code that should act on it.
//
// So every test here moves a setting off its default and watches the behaviour
// move with it. Where it is cheap, the assertion is made at two different
// values, because a consumer frozen at any single constant — its own default or
// otherwise — has to fail at least one of them, whereas a single value can be
// satisfied by a coincidence.

// The sampling cadence is what this setting is for, so it is asserted against
// the running loop and not only against the duration the sampler derives: a
// sampler that computed the right interval and then ticked on a hardcoded one
// would satisfy the arithmetic and still sample at the wrong rate.
func TestTheSampleIntervalFollowsTheSetting(t *testing.T) {
	for _, tc := range []struct {
		seconds float64
		want    time.Duration
	}{
		{0.25, 250 * time.Millisecond},
		{2.5, 2500 * time.Millisecond},
	} {
		sampler := New(Deps{
			Reader:   fixtureReader(),
			Settings: fakeSettings{"metrics.sample_interval_seconds": tc.seconds},
		})
		if got := sampler.interval(); got != tc.want {
			t.Fatalf("with the setting at %.2fs the sampler ticks every %s, want %s",
				tc.seconds, got, tc.want)
		}
	}

	// And the derived figure has to reach the ticker. Start takes one reading
	// immediately, so at a quarter of a second three quarters of a second is
	// comfortably enough for that one plus two more; on the one-second default
	// the immediate reading would still be the only one.
	sampler := New(Deps{
		Reader: fixtureReader(),
		Settings: fakeSettings{
			"metrics.sample_interval_seconds": 0.25,
			// Large enough that the ring buffer cannot be what bounds the count.
			"metrics.history_points": int64(1000),
		},
	})
	if err := sampler.Start(context.Background()); err != nil {
		t.Fatalf("starting the sampler failed: %v", err)
	}
	defer sampler.Stop()

	time.Sleep(750 * time.Millisecond)
	if got := len(sampler.History(0)); got < 3 {
		t.Fatalf("the sampler took %d readings in 750ms at a 0.25s interval, want at least 3; "+
			"it is ticking on something other than the setting", got)
	}
}

// The ring buffer is what the dashboard sparklines are drawn from, so its depth
// has to be the operator's number rather than the one the sampler was born with.
func TestTheHistoryDepthFollowsTheSetting(t *testing.T) {
	const readings = 12

	for _, points := range []int64{4, 9} {
		sampler := New(Deps{
			Reader:   fixtureReader(),
			Settings: fakeSettings{"metrics.history_points": points},
		})

		ctx := context.Background()
		for i := 0; i < readings; i++ {
			sampler.Sample(ctx)
		}

		if got := len(sampler.History(0)); got != int(points) {
			t.Fatalf("the ring buffer kept %d of %d readings with the setting at %d",
				got, readings, points)
		}
	}
}

// FilterDisks is already tested on its own; what is tested here is that the
// sampler actually asks it to filter, which is the wiring the helper's own test
// cannot see. The mounts fixture carries proc, sysfs, tmpfs and cgroup2
// alongside two real filesystems, so both answers are visible in one reading.
func TestHidingPseudoFilesystemsFollowsTheSetting(t *testing.T) {
	sample := func(hide bool) []Disk {
		sampler := New(Deps{
			Reader:   fixtureReader(),
			Settings: fakeSettings{"metrics.hide_pseudo_filesystems": hide},
		})
		return sampler.Sample(context.Background()).Disks
	}

	hidden := sample(true)
	if len(hidden) == 0 {
		t.Fatal("the reading has no filesystems at all, so it proves nothing about hiding them")
	}
	for _, disk := range hidden {
		if disk.IsPseudo {
			t.Fatalf("%s is a %s mount and the setting asks for kernel filesystems to be hidden",
				disk.MountPoint, disk.FsType)
		}
	}

	// Switching the setting off has to bring them back: the full list stays
	// retrievable is the promise the setting's description makes.
	shown := sample(false)
	pseudo := 0
	for _, disk := range shown {
		if disk.IsPseudo {
			pseudo++
		}
	}
	if pseudo == 0 {
		t.Fatalf("with the setting off the reading still holds no kernel filesystems: %+v", shown)
	}
	if len(shown) <= len(hidden) {
		t.Fatalf("the reading holds %d mounts with kernel filesystems shown and %d with them "+
			"hidden, want strictly more", len(shown), len(hidden))
	}
}
