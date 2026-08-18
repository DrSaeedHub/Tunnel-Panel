package tunnel

import (
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/persist"
)

// The tests in this file are the second half of the settings guard. The coarse
// one in internal/api proves each key is named somewhere outside its own schema
// entry, which only establishes that a reader exists; these prove the reader
// honours what it read. The defect they exist to catch is the one this codebase
// keeps producing: a setting that is stored, validated and described on the
// Settings page, and then quietly ignored by the code that should act on it.
//
// The keepalive settings are all read by KeepaliveFor, and three of the four
// only ever apply in systemd_unit mode, so most of these tests switch the mode
// first. Where it is cheap the assertion is made at two different values,
// because a consumer frozen at any single constant has to fail at least one of
// them, whereas a single value can be satisfied by a coincidence.

// keepaliveUnitFor creates a tunnel and returns the keepalive unit body written
// for it, which is where the rendered parameters actually land.
func (h *harness) keepaliveUnitFor(t *testing.T, remoteEndpoint string) (string, bool) {
	t.Helper()

	req := request()
	req.RemoteEndpoint = remoteEndpoint
	created := h.mustCreate(t, req)

	path := h.store.KeepaliveUnitPath(created.Tunnel.InterfaceName)
	if !persist.Exists(path) {
		return "", false
	}
	body, err := persist.Read(path)
	if err != nil {
		t.Fatalf("reading %s failed: %v", path, err)
	}
	return body, true
}

// The mode decides whether a separate ping unit exists at all. The default
// relies on the panel's own prober, which is already continuous ICMP from the
// tunnel source address, so a second process per tunnel would buy nothing.
func TestTheKeepaliveModeFollowsTheSetting(t *testing.T) {
	h := newHarness(t)
	created := h.mustCreate(t, request())

	// The default is monitor_only, so nothing is planned and nothing is written.
	if decision := h.service.KeepaliveFor(created.Tunnel, nil); decision.Enabled {
		t.Fatalf("monitor_only planned a keepalive unit: %+v", decision)
	}
	if persist.Exists(h.store.KeepaliveUnitPath(created.Tunnel.InterfaceName)) {
		t.Fatal("monitor_only must write no keepalive unit")
	}

	h.setSetting(t, "keepalive.mode", "systemd_unit")
	if decision := h.service.KeepaliveFor(created.Tunnel, nil); !decision.Enabled {
		t.Fatal("systemd_unit must plan a keepalive unit for a tunnel with a peer address")
	}
	if _, written := h.keepaliveUnitFor(t, "198.51.100.30"); !written {
		t.Fatal("systemd_unit must write a keepalive unit")
	}
}

// The default enablement decides what a newly created tunnel gets when the
// request says nothing either way, which is the only case it applies to: an
// explicit choice on the tunnel still overrides it.
func TestTheKeepaliveDefaultEnablementFollowsTheSetting(t *testing.T) {
	h := newHarness(t)
	h.setSetting(t, "keepalive.mode", "systemd_unit")
	created := h.mustCreate(t, request())

	h.setSetting(t, "keepalive.enabled_by_default", false)
	if decision := h.service.KeepaliveFor(created.Tunnel, nil); decision.Enabled {
		t.Fatal("a tunnel that expresses no preference must follow the setting, which is off")
	}
	if _, written := h.keepaliveUnitFor(t, "198.51.100.30"); written {
		t.Fatal("no keepalive unit may be written while the default is off")
	}

	h.setSetting(t, "keepalive.enabled_by_default", true)
	if decision := h.service.KeepaliveFor(created.Tunnel, nil); !decision.Enabled {
		t.Fatal("a tunnel that expresses no preference must follow the setting, which is on")
	}
	if _, written := h.keepaliveUnitFor(t, "198.51.100.40"); !written {
		t.Fatal("a keepalive unit must be written while the default is on")
	}

	// The setting is a default and not a policy: a tunnel that asks for the
	// opposite still gets it, or the per-tunnel override would be decorative.
	off, on := false, true
	h.setSetting(t, "keepalive.enabled_by_default", false)
	if decision := h.service.KeepaliveFor(created.Tunnel, &on); !decision.Enabled {
		t.Fatal("an explicit yes must survive a default of no")
	}
	h.setSetting(t, "keepalive.enabled_by_default", true)
	if decision := h.service.KeepaliveFor(created.Tunnel, &off); decision.Enabled {
		t.Fatal("an explicit no must survive a default of yes")
	}
}

// The interval is only useful if it reaches ping's own -i flag in the unit
// file, which is the thing that actually paces the packets.
func TestTheKeepaliveIntervalFollowsTheSetting(t *testing.T) {
	h := newHarness(t)
	h.setSetting(t, "keepalive.mode", "systemd_unit")
	created := h.mustCreate(t, request())

	for _, tc := range []struct {
		seconds float64
		flag    string
	}{
		{2.5, "-i 2.5"},
		{0.5, "-i 0.5"},
	} {
		h.setSetting(t, "keepalive.interval_seconds", tc.seconds)

		decision := h.service.KeepaliveFor(created.Tunnel, nil)
		if decision.Options.IntervalSeconds != tc.seconds {
			t.Fatalf("the planned interval is %v, want %v",
				decision.Options.IntervalSeconds, tc.seconds)
		}
		if args := strings.Join(persist.KeepaliveArgs(testPingBin, decision.Options), " "); !strings.Contains(args, tc.flag) {
			t.Fatalf("the rendered command is %q, want it to carry %q", args, tc.flag)
		}
	}

	// End to end: the figure has to survive into the unit file on disk, which
	// is what systemd will actually run.
	h.setSetting(t, "keepalive.interval_seconds", 2.5)
	body, written := h.keepaliveUnitFor(t, "198.51.100.30")
	if !written {
		t.Fatal("no keepalive unit was written")
	}
	if !strings.Contains(body, "-i 2.5") {
		t.Fatalf("the keepalive unit does not pace at the configured interval:\n%s", body)
	}
}

// The packet size is only useful if it reaches ping's own -s flag, for the same
// reason as the interval.
func TestTheKeepalivePacketSizeFollowsTheSetting(t *testing.T) {
	h := newHarness(t)
	h.setSetting(t, "keepalive.mode", "systemd_unit")
	created := h.mustCreate(t, request())

	for _, tc := range []struct {
		bytes int64
		flag  string
	}{
		{128, "-s 128"},
		{512, "-s 512"},
	} {
		h.setSetting(t, "keepalive.packet_size", tc.bytes)

		decision := h.service.KeepaliveFor(created.Tunnel, nil)
		if decision.Options.PacketSize != int(tc.bytes) {
			t.Fatalf("the planned packet size is %d, want %d", decision.Options.PacketSize, tc.bytes)
		}
		if args := strings.Join(persist.KeepaliveArgs(testPingBin, decision.Options), " "); !strings.Contains(args, tc.flag) {
			t.Fatalf("the rendered command is %q, want it to carry %q", args, tc.flag)
		}
	}

	h.setSetting(t, "keepalive.packet_size", int64(128))
	body, written := h.keepaliveUnitFor(t, "198.51.100.30")
	if !written {
		t.Fatal("no keepalive unit was written")
	}
	if !strings.Contains(body, "-s 128") {
		t.Fatalf("the keepalive unit does not send the configured packet size:\n%s", body)
	}
}
