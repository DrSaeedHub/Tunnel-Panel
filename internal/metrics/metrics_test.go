package metrics

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/link"
)

// fixtureReader reads the recorded /proc files under testdata, so the parsers
// are tested against known output rather than against whatever machine happens
// to be running the tests.
func fixtureReader() *Reader { return &Reader{Root: "testdata"} }

// ---------------------------------------------------------------- CPU

func TestCpuParsing(t *testing.T) {
	times, err := fixtureReader().CPU()
	if err != nil {
		t.Fatalf("reading CPU times failed: %v", err)
	}
	if len(times) != 3 {
		t.Fatalf("parsed %d CPU lines, want the aggregate plus two cores", len(times))
	}

	total := times[0]
	if total.Name != "cpu" {
		t.Fatalf("the first line is %q, want the aggregate", total.Name)
	}
	if total.User != 102030 || total.System != 40000 || total.Idle != 900000 {
		t.Fatalf("columns parsed wrongly: %+v", total)
	}
	// Steal matters on a virtual server, so it must survive parsing.
	if total.Steal != 700 {
		t.Fatalf("steal = %d, want 700", total.Steal)
	}
	if total.Iowait != 3000 {
		t.Fatalf("iowait = %d, want 3000", total.Iowait)
	}

	// Guest time is already inside user time, so it must not be added again.
	want := uint64(102030 + 500 + 40000 + 900000 + 3000 + 0 + 1200 + 700)
	if total.Total() != want {
		t.Fatalf("total = %d, want %d", total.Total(), want)
	}
}

// Utilisation is a difference between two readings, never a share of the
// cumulative totals (§11.1).
func TestCpuUtilisationComesFromTheDelta(t *testing.T) {
	before := []CPUTimes{{Name: "cpu", User: 100, System: 100, Idle: 800}}
	after := []CPUTimes{{Name: "cpu", User: 150, System: 150, Idle: 900, Iowait: 50, Steal: 50}}

	usage := CPUDelta(before, after)
	if len(usage) != 1 {
		t.Fatalf("usage = %+v", usage)
	}
	// The interval added 50 user, 50 system, 100 idle, 50 iowait and 50 steal:
	// 300 jiffies, of which 150 were idle or waiting.
	got := usage[0]
	if got.UsagePercent < 49.9 || got.UsagePercent > 50.1 {
		t.Fatalf("usage = %.2f%%, want 50%%", got.UsagePercent)
	}
	if got.StealPercent < 16.6 || got.StealPercent > 16.7 {
		t.Fatalf("steal = %.2f%%, want about 16.67%%", got.StealPercent)
	}
	if got.IowaitPercent < 16.6 || got.IowaitPercent > 16.7 {
		t.Fatalf("iowait = %.2f%%", got.IowaitPercent)
	}

	// Two identical readings mean nothing happened, not a division by zero.
	if usage := CPUDelta(after, after); usage[0].UsagePercent != 0 {
		t.Fatalf("an empty interval reported %.2f%% usage", usage[0].UsagePercent)
	}
	// A core that was not in the previous reading reports nothing rather than
	// a figure derived from a missing baseline.
	if usage := CPUDelta(nil, after); usage[0].UsagePercent != 0 {
		t.Fatal("a core with no baseline must report no usage")
	}
}

func TestLoadAverageParsing(t *testing.T) {
	load, err := fixtureReader().Load()
	if err != nil {
		t.Fatalf("reading the load average failed: %v", err)
	}
	if load.One != 0.52 || load.Five != 0.31 || load.Fifteen != 0.24 {
		t.Fatalf("load = %+v", load)
	}
	if load.RunningEntities != 2 || load.TotalEntities != 187 {
		t.Fatalf("entities = %d/%d, want 2/187", load.RunningEntities, load.TotalEntities)
	}
}

// ---------------------------------------------------------------- memory

func TestMemoryParsing(t *testing.T) {
	memory, swap, err := fixtureReader().MemoryInfo()
	if err != nil {
		t.Fatalf("reading memory information failed: %v", err)
	}

	const kb = 1024
	if memory.TotalBytes != 4030548*kb {
		t.Fatalf("total = %d bytes", memory.TotalBytes)
	}
	if memory.AvailableBytes != 3124560*kb {
		t.Fatalf("available = %d bytes", memory.AvailableBytes)
	}
	if memory.BuffersBytes != 104220*kb || memory.CachedBytes != 2610408*kb {
		t.Fatalf("buffers/cached = %d/%d", memory.BuffersBytes, memory.CachedBytes)
	}

	// Used is total minus available. Total minus free would count the page
	// cache as used and report this machine as 95% full when it is 22% full.
	if memory.UsedBytes != (4030548-3124560)*kb {
		t.Fatalf("used = %d bytes, want total minus available", memory.UsedBytes)
	}
	if memory.UsedPercent < 22 || memory.UsedPercent > 23 {
		t.Fatalf("used = %.1f%%, want about 22.5%%", memory.UsedPercent)
	}
	// The naive figure is exposed too, so the interface can show the breakdown.
	if memory.UnavailableBytes != (4030548-210984)*kb {
		t.Fatalf("unavailable = %d bytes, want total minus free", memory.UnavailableBytes)
	}
	if memory.UnavailablePercent < 94 || memory.UnavailablePercent > 95 {
		t.Fatalf("the naive figure is %.1f%%, want about 94.8%%", memory.UnavailablePercent)
	}

	if !swap.Configured {
		t.Fatal("this fixture has swap configured")
	}
	if swap.UsedBytes != (1048572-917500)*kb {
		t.Fatalf("swap used = %d bytes", swap.UsedBytes)
	}
}

// A machine with no swap must say so rather than showing a misleading 0%.
func TestSwapReportsWhenNoneIsConfigured(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "proc", "meminfo"),
		"MemTotal: 1024 kB\nMemFree: 512 kB\nMemAvailable: 700 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n"); err != nil {
		t.Fatal(err)
	}
	_, swap, err := (&Reader{Root: dir}).MemoryInfo()
	if err != nil {
		t.Fatal(err)
	}
	if swap.Configured {
		t.Fatal("a machine with no swap must report none configured")
	}
	if swap.UsedPercent != 0 || swap.TotalBytes != 0 {
		t.Fatalf("swap = %+v", swap)
	}
}

// ---------------------------------------------------------------- network

func TestProcNetDevParsing(t *testing.T) {
	counters, err := fixtureReader().ProcNetDev()
	if err != nil {
		t.Fatalf("reading interface counters failed: %v", err)
	}
	if len(counters) != 3 {
		t.Fatalf("parsed %d interfaces, want 3: %+v", len(counters), counters)
	}

	eth0 := counters["eth0"]
	if eth0.RxBytes != 981234567 || eth0.TxBytes != 123456789 {
		t.Fatalf("eth0 bytes = %d/%d", eth0.RxBytes, eth0.TxBytes)
	}
	if eth0.RxPackets != 874512 || eth0.TxPackets != 654321 {
		t.Fatalf("eth0 packets = %d/%d", eth0.RxPackets, eth0.TxPackets)
	}
	if eth0.RxErrors != 3 || eth0.RxDropped != 7 || eth0.TxErrors != 1 || eth0.TxDropped != 2 {
		t.Fatalf("eth0 errors and drops = %+v", eth0)
	}

	// An interface name butted up against the colon still parses.
	tunnel := counters["gre-a-1"]
	if tunnel.RxBytes != 45678 || tunnel.TxBytes != 98765 {
		t.Fatalf("gre-a-1 bytes = %d/%d", tunnel.RxBytes, tunnel.TxBytes)
	}
}

func TestInterfaceClassification(t *testing.T) {
	cases := []struct {
		name       string
		kind       string
		isLoopback bool
		want       string
	}{
		{"lo", "loopback", true, ClassLoopback},
		{"eth0", "device", false, ClassPhysical},
		{"eth0", "", false, ClassPhysical},
		{"gre-a-1", link.KindGRE, false, ClassTunnel},
		{"gre6-a-1", link.KindIP6GRE, false, ClassTunnel},
		// A tunnel the panel has not adopted is still a tunnel.
		{"gre-ir-7", "", false, ClassTunnel},
		{"br0", "bridge", false, ClassOther},
		{"docker0", "bridge", false, ClassOther},
	}
	for _, tc := range cases {
		if got := ClassifyInterface(tc.name, tc.kind, tc.isLoopback); got != tc.want {
			t.Fatalf("%s (%s) classified as %q, want %q", tc.name, tc.kind, got, tc.want)
		}
	}
}

func TestThroughputComesFromTheDelta(t *testing.T) {
	interfaces := []Interface{
		{Name: "eth0", Counters: InterfaceCounters{RxBytes: 2000, TxBytes: 3000}},
		{Name: "gre-a-1", Counters: InterfaceCounters{RxBytes: 500, TxBytes: 100}},
	}
	previous := map[string]InterfaceCounters{
		"eth0": {RxBytes: 1000, TxBytes: 1000},
		// The tunnel's counter went backwards: it was recreated.
		"gre-a-1": {RxBytes: 900, TxBytes: 900},
	}

	ApplyThroughput(interfaces, previous, 2)

	if interfaces[0].RxBytesPerSecond != 500 || interfaces[0].TxBytesPerSecond != 1000 {
		t.Fatalf("eth0 throughput = %v/%v", interfaces[0].RxBytesPerSecond, interfaces[0].TxBytesPerSecond)
	}
	// A counter that restarted reports no rate rather than a negative or an
	// enormous one.
	if interfaces[1].RxBytesPerSecond != 0 || interfaces[1].TxBytesPerSecond != 0 {
		t.Fatalf("a restarted counter reported a rate: %+v", interfaces[1])
	}
}

func TestTotalsExcludeLoopback(t *testing.T) {
	totals := Totals([]Interface{
		{Name: "lo", IsLoopback: true, RxBytesPerSecond: 1000, RxBytesSinceBoot: 5000},
		{Name: "eth0", RxBytesPerSecond: 10, TxBytesPerSecond: 20, RxBytesSinceBoot: 100, TxBytesSinceBoot: 200},
	})
	if totals.RxBytesPerSecond != 10 || totals.TxBytesPerSecond != 20 {
		t.Fatalf("loopback traffic leaked into the totals: %+v", totals)
	}
	if totals.RxBytesSinceBoot != 100 {
		t.Fatalf("volume totals = %+v", totals)
	}
}

// ---------------------------------------------------------------- disks

func TestMountParsing(t *testing.T) {
	mounts, err := fixtureReader().Mounts()
	if err != nil {
		t.Fatalf("reading the mount table failed: %v", err)
	}
	if len(mounts) != 6 {
		t.Fatalf("parsed %d mounts, want 6", len(mounts))
	}
	if mounts[0].Device != "/dev/sda1" || mounts[0].MountPoint != "/" || mounts[0].FsType != "ext4" {
		t.Fatalf("the root mount parsed wrongly: %+v", mounts[0])
	}
	// The octal escape /proc/mounts uses for a space must be decoded.
	if mounts[5].MountPoint != "/mnt/with space" {
		t.Fatalf("escaped mount point = %q", mounts[5].MountPoint)
	}

	pseudo := map[string]bool{}
	for _, mount := range mounts {
		pseudo[mount.MountPoint] = IsPseudoFilesystem(mount.FsType)
	}
	for _, point := range []string{"/proc", "/sys", "/run", "/sys/fs/cgroup"} {
		if !pseudo[point] {
			t.Fatalf("%s should be recognised as a kernel filesystem", point)
		}
	}
	for _, point := range []string{"/", "/mnt/with space"} {
		if pseudo[point] {
			t.Fatalf("%s should be recognised as real storage", point)
		}
	}
}

// sandboxedReader reads the mount table the panel's own process actually sees.
//
// The unit sets ProtectSystem=full with ReadWritePaths, which systemd
// implements with bind mounts, so the panel runs in a mount namespace of its
// own. This fixture is /proc/<pid>/mountinfo copied verbatim off a running
// panel on server A.
func sandboxedReader() *Reader { return &Reader{Root: filepath.Join("testdata", "sandboxed")} }

// TestBindMountsAreNotCountedAsSeparateFilesystems is the regression for a
// dashboard that invented disks.
//
// Server A has two filesystems: /dev/sda1 on / and /dev/sda15 on /boot/efi. The
// Disk card listed eleven, ten of them reporting byte-identical figures,
// because the mount table the panel sees inside its own namespace holds
// /dev/sda1 nine more times over as bind mounts of its subtrees. Deduplicating
// on the mount point could never catch that: the whole point of a bind mount is
// that the path is different. It has to be the filesystem's identity.
//
// Hiding pseudo filesystems does not help either — every one of these is ext4.
func TestBindMountsAreNotCountedAsSeparateFilesystems(t *testing.T) {
	mounts, err := sandboxedReader().Mounts()
	if err != nil {
		t.Fatalf("reading the mount table failed: %v", err)
	}

	byPoint := map[string]Mount{}
	for _, m := range mounts {
		if _, clash := byPoint[m.MountPoint]; clash {
			t.Errorf("%s appears twice in the reading", m.MountPoint)
		}
		byPoint[m.MountPoint] = m
	}

	// The real storage: one entry each, at the canonical mount point.
	for _, want := range []struct{ point, device, fsType string }{
		{"/", "/dev/sda1", "ext4"},
		{"/boot/efi", "/dev/sda15", "vfat"},
	} {
		got, ok := byPoint[want.point]
		if !ok {
			t.Fatalf("%s is missing from the reading", want.point)
		}
		if got.Device != want.device || got.FsType != want.fsType {
			t.Errorf("%s = %+v, want %s %s", want.point, got, want.device, want.fsType)
		}
	}

	// Every one of these is /dev/sda1 seen through a systemd sandbox bind mount.
	// None of them is a filesystem, and reporting them made the machine look
	// like it had nine extra disks all exactly as full as the root one.
	for _, phantom := range []string{
		"/boot", "/etc", "/etc/sysctl.d", "/etc/systemd/network", "/etc/systemd/system",
		"/tmp", "/usr", "/var/lib/gre-panel", "/var/tmp",
	} {
		if _, present := byPoint[phantom]; present {
			t.Errorf("%s is reported as a filesystem of its own; it is a bind mount of /dev/sda1", phantom)
		}
	}

	// Hiding pseudo filesystems is not what fixes this, and must not be what the
	// assertion above depends on.
	real := 0
	for _, m := range mounts {
		if !IsPseudoFilesystem(m.FsType) {
			real++
		}
	}
	if real != 2 {
		var names []string
		for _, m := range mounts {
			if !IsPseudoFilesystem(m.FsType) {
				names = append(names, m.MountPoint)
			}
		}
		t.Errorf("this machine has two filesystems; the reading has %d: %v", real, names)
	}

	disks, err := sandboxedReader().Disks()
	if err != nil {
		t.Fatalf("measuring the disks failed: %v", err)
	}
	if got := len(FilterDisks(disks, true)); got != 2 {
		t.Errorf("Disks() reports %d filesystems with pseudo filesystems hidden, want 2", got)
	}
}

// TestSeparateTmpfsInstancesStaySeparate is the other half of the same fix.
//
// Collapsing by device must not collapse filesystems that only look alike. A
// tmpfs is a real filesystem with its own capacity, and the kernel gives each
// instance its own minor number; /dev/shm and /run/lock are genuinely different
// storage and have to be reported as such. Meanwhile /run, /run/netns and
// /run/systemd all share one minor number, because they are one tmpfs.
func TestSeparateTmpfsInstancesStaySeparate(t *testing.T) {
	mounts, err := sandboxedReader().Mounts()
	if err != nil {
		t.Fatalf("reading the mount table failed: %v", err)
	}
	points := map[string]bool{}
	for _, m := range mounts {
		points[m.MountPoint] = true
	}
	for _, want := range []string{"/run", "/dev/shm", "/run/lock"} {
		if !points[want] {
			t.Errorf("%s is a tmpfs instance of its own and was collapsed away", want)
		}
	}
	for _, gone := range []string{"/run/netns", "/run/systemd", "/run/user", "/home", "/root"} {
		if points[gone] {
			t.Errorf("%s is another view of the /run tmpfs and is counted twice", gone)
		}
	}
}

// TestMountInfoIsPreferredButProcMountsStillWorks keeps the fallback honest: a
// fixture with no mountinfo still parses, just without device identity.
func TestMountInfoIsPreferredButProcMountsStillWorks(t *testing.T) {
	mounts, err := fixtureReader().Mounts()
	if err != nil {
		t.Fatalf("reading the mount table failed: %v", err)
	}
	if len(mounts) != 6 {
		t.Fatalf("the /proc/mounts fallback parsed %d mounts, want 6", len(mounts))
	}
	for _, m := range mounts {
		if m.DeviceID != "" {
			t.Errorf("%s claims a device identity /proc/mounts cannot supply: %q", m.MountPoint, m.DeviceID)
		}
	}

	// The sandboxed fixture carries BOTH files, which is what makes "preferred"
	// a claim at all: with only mountinfo present there would be nothing to
	// prefer it over, and this would pass by having no alternative.
	//
	// Both assertions below exist because neither is enough alone. Without the
	// length check an empty result satisfies the loop and the test passes
	// having read nothing — it did, when the fixture was deleted to see what
	// this would say. Without the DeviceID check a parse of the wrong file
	// passes. The count differs from the /proc/mounts copy on purpose, so
	// reading the wrong one is visible as a number rather than only as a
	// missing field.
	if _, err := os.Stat(filepath.Join("testdata", "sandboxed", "proc", "mounts")); err != nil {
		t.Fatalf("the sandboxed fixture must keep a /proc/mounts for mountinfo to be preferred over: %v", err)
	}

	sandboxed, err := sandboxedReader().Mounts()
	if err != nil {
		t.Fatalf("reading the mount table failed: %v", err)
	}
	if len(sandboxed) == 0 {
		t.Fatal("the sandboxed mount table is empty, so nothing below was checked")
	}
	for _, m := range sandboxed {
		if m.DeviceID == "" {
			t.Errorf("%s has no device identity, so mountinfo was not used", m.MountPoint)
		}
	}
}

func TestFilterDisksKeepsTheFullListRetrievable(t *testing.T) {
	disks := []Disk{
		{Mount: Mount{MountPoint: "/"}, IsPseudo: false},
		{Mount: Mount{MountPoint: "/run"}, IsPseudo: true},
	}
	if got := FilterDisks(disks, true); len(got) != 1 || got[0].MountPoint != "/" {
		t.Fatalf("filtering kept %+v", got)
	}
	if got := FilterDisks(disks, false); len(got) != 2 {
		t.Fatalf("unfiltered = %+v", got)
	}
}

// ---------------------------------------------------------------- volumes

func newCounters(t *testing.T) *Counters {
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
	return NewCounters(database)
}

// Cumulative volume has to survive the counter restarting, which happens on
// every reboot and every time a tunnel is rebuilt (§11.3).
func TestVolumeSurvivesADecreasingCounter(t *testing.T) {
	c := newCounters(t)

	// First sighting starts the accounting at what is already there, so
	// installing the panel does not credit the interface with everything since
	// the machine booted.
	c.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 1000, TxBytes: 2000}})
	if v := c.Volumes()["eth0"]; v.RxBytesTotal != 0 || v.TxBytesTotal != 0 {
		t.Fatalf("the first sighting counted pre-existing traffic: %+v", v)
	}

	c.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 1500, TxBytes: 2400}})
	if v := c.Volumes()["eth0"]; v.RxBytesTotal != 500 || v.TxBytesTotal != 400 {
		t.Fatalf("ordinary accumulation = %+v", v)
	}

	// The counter restarts: everything the new counter holds is new traffic,
	// and the total so far must survive.
	volumes := c.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 100, TxBytes: 50}})
	if !volumes[0].ResetDetected {
		t.Fatal("a decreasing counter must be recognised as a reset")
	}
	if v := c.Volumes()["eth0"]; v.RxBytesTotal != 600 || v.TxBytesTotal != 450 {
		t.Fatalf("the total was lost across the reset: %+v", v)
	}

	// And accounting continues normally from the new baseline.
	c.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 300, TxBytes: 150}})
	if v := c.Volumes()["eth0"]; v.RxBytesTotal != 800 || v.TxBytesTotal != 550 {
		t.Fatalf("accounting after the reset = %+v", v)
	}
}

// The other way an interface restarts: it is deleted and recreated, so the
// counter may be higher than before but the index has changed (§11.3).
func TestVolumeSurvivesAnInterfaceIndexChange(t *testing.T) {
	c := newCounters(t)

	c.Observe([]Observation{{Name: "gre-a-1", Index: 5, RxBytes: 0, TxBytes: 0}})
	c.Observe([]Observation{{Name: "gre-a-1", Index: 5, RxBytes: 900, TxBytes: 800}})
	if v := c.Volumes()["gre-a-1"]; v.RxBytesTotal != 900 {
		t.Fatalf("before the rebuild = %+v", v)
	}

	// Rebuilt: a new index, and a counter that happens to be higher than the
	// last one, so only the index change reveals the restart.
	volumes := c.Observe([]Observation{{Name: "gre-a-1", Index: 9, RxBytes: 1000, TxBytes: 950}})
	if !volumes[0].ResetDetected {
		t.Fatal("a changed interface index must be recognised as a reset")
	}
	if v := c.Volumes()["gre-a-1"]; v.RxBytesTotal != 1900 || v.TxBytesTotal != 1750 {
		t.Fatalf("the total was lost across the rebuild: %+v", v)
	}
	if v := c.Volumes()["gre-a-1"]; v.InterfaceIndex != 9 {
		t.Fatalf("the new index was not recorded: %+v", v)
	}
}

func TestVolumesArePersistedAndReloaded(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := db.Init(ctx, database); err != nil {
		t.Fatal(err)
	}

	first := NewCounters(database)
	first.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 0, TxBytes: 0}})
	first.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 5000, TxBytes: 6000}})
	if err := first.Flush(ctx); err != nil {
		t.Fatalf("flushing failed: %v", err)
	}

	// A restart reloads the totals and carries on from them.
	second := NewCounters(database)
	if err := second.Load(ctx); err != nil {
		t.Fatalf("loading failed: %v", err)
	}
	if v := second.Volumes()["eth0"]; v.RxBytesTotal != 5000 || v.LastRawRxBytes != 5000 {
		t.Fatalf("reloaded volume = %+v", v)
	}
	second.Observe([]Observation{{Name: "eth0", Index: 2, RxBytes: 5500, TxBytes: 6200}})
	if v := second.Volumes()["eth0"]; v.RxBytesTotal != 5500 {
		t.Fatalf("accounting after a restart = %+v", v)
	}
}

// ---------------------------------------------------------------- sampler

func TestSamplerProducesReadingsAndHistory(t *testing.T) {
	links := link.NewFakeWithHost()
	// Give the simulated host some traffic, the way netlink reports it.
	links.AddLink(link.Link{
		Name: "eth0", Index: 2, MTU: 1500, Kind: "device",
		OperState: "UP", IsUp: true, IsLowerUp: true,
		Addresses:  []link.Address{{Address: "203.0.113.10", PrefixLength: 24, Family: link.FamilyIPv4, Scope: "global"}},
		Statistics: &link.Statistics{RxBytes: 981234567, TxBytes: 123456789, RxPackets: 874512, TxPackets: 654321},
	})
	sampler := New(Deps{
		Reader:   fixtureReader(),
		Links:    links,
		Counters: newCounters(t),
		Settings: fakeSettings{"metrics.history_points": int64(3)},
	})

	ctx := context.Background()
	first := sampler.Sample(ctx)
	if len(first.Network.Interfaces) == 0 {
		t.Fatal("the reading has no interfaces")
	}
	// The first reading has no baseline, so it reports no CPU utilisation
	// rather than inventing one.
	if len(first.Cpu) != 0 {
		t.Fatalf("the first reading reported utilisation with no baseline: %+v", first.Cpu)
	}

	second := sampler.Sample(ctx)
	if len(second.Cpu) == 0 {
		t.Fatal("the second reading must have utilisation")
	}
	if second.Memory.TotalBytes == 0 {
		t.Fatal("the reading has no memory figures")
	}

	// Since boot and since install are separate fields, never blended.
	for _, iface := range second.Network.Interfaces {
		if iface.Name != "eth0" {
			continue
		}
		if iface.RxBytesSinceBoot == 0 {
			t.Fatal("the since-boot figure is the kernel's own counter")
		}
		if iface.RxBytesSinceInstall != 0 {
			t.Fatal("nothing has accumulated since install in this test")
		}
	}

	// The ring buffer is bounded by the setting.
	for i := 0; i < 5; i++ {
		sampler.Sample(ctx)
	}
	if history := sampler.History(0); len(history) != 3 {
		t.Fatalf("the ring buffer holds %d readings, want 3", len(history))
	}
	if latest := sampler.Latest(); latest.At.IsZero() {
		t.Fatal("the latest reading is empty")
	}
}

func TestSamplerFallsBackToProcWhenNetlinkFails(t *testing.T) {
	sampler := New(Deps{
		Reader:   fixtureReader(),
		Links:    nil, // no link manager at all
		Settings: fakeSettings{},
	})
	snapshot := sampler.Sample(context.Background())

	if len(snapshot.Network.Interfaces) != 3 {
		t.Fatalf("the fallback parsed %d interfaces, want 3", len(snapshot.Network.Interfaces))
	}
	names := map[string]bool{}
	for _, iface := range snapshot.Network.Interfaces {
		names[iface.Name] = true
	}
	if !names["eth0"] || !names["gre-a-1"] {
		t.Fatalf("the fallback is missing interfaces: %v", names)
	}
}

// Every subscriber receives readings and every goroutine exits on disconnect.
func TestMetricsHubCleansUp(t *testing.T) {
	hub := NewHub()

	var wg sync.WaitGroup
	ids := make([]int, 4)
	counts := make([]int, 4)
	for i := range ids {
		var ch <-chan Snapshot
		ids[i], ch = hub.Subscribe()
		wg.Add(1)
		go func(i int, ch <-chan Snapshot) {
			defer wg.Done()
			for range ch {
				counts[i]++
			}
		}(i, ch)
	}

	hub.Publish(Snapshot{At: time.Now()})
	hub.Publish(Snapshot{At: time.Now()})

	for _, id := range ids {
		hub.Unsubscribe(id)
	}
	wg.Wait()

	if hub.Subscribers() != 0 {
		t.Fatalf("%d subscribers survived disconnect", hub.Subscribers())
	}
	for i, count := range counts {
		if count == 0 {
			t.Fatalf("subscriber %d received nothing", i)
		}
	}
}

// ---------------------------------------------------------------- helpers

type fakeSettings map[string]any

func (s fakeSettings) Bool(key string) bool { b, _ := s[key].(bool); return b }
func (s fakeSettings) Int(key string) int64 { n, _ := s[key].(int64); return n }
func (s fakeSettings) Float(key string) float64 {
	f, _ := s[key].(float64)
	return f
}

// writeFile creates a fixture file and the directories above it.
func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}
