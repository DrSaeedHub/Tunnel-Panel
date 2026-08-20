package tuning

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/safety"
)

// newHost builds a fixture filesystem with the kernel parameters a real host
// would have, so the manager can be exercised without touching this machine.
func newHost(t *testing.T, memoryMB int, values map[string]string) *Manager {
	t.Helper()
	root := t.TempDir()

	write := func(rel, content string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/meminfo", "MemTotal:       "+itoa(memoryMB*1024)+" kB")
	for _, parameter := range Catalogue() {
		if value, ok := values[parameter.Key]; ok {
			write(parameter.Proc, value)
		}
	}
	return &Manager{Root: root, SysctlPath: "/etc/sysctl.d/99-test.conf"}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

// The table has to be sized for the connections the rules carry, not for the
// machine's memory. Either input alone gets it wrong: a large machine with no
// traffic does not need a huge table, and a small machine carrying forty
// thousand connections needs one whatever its memory says.
func TestTheTableIsSizedForTheTrafficAndNotOnlyTheMemory(t *testing.T) {
	small := RecommendedConntrackMax(Facts{MemoryMB: 2048, LiveConnections: 0})
	if small < 262144 {
		t.Errorf("a quiet 2 GB host is offered %d, want at least the floor of 262144", small)
	}

	// A host carrying 200,000 connections needs room for its peak, not for its
	// average, and certainly not for what 2 GB of memory suggests.
	busy := RecommendedConntrackMax(Facts{MemoryMB: 2048, LiveConnections: 200000})
	if busy <= small {
		t.Errorf("a busy host is offered %d, no more than the quiet one's %d", busy, small)
	}
	if busy < 200000 {
		t.Errorf("a host carrying 200000 connections is offered a table of %d", busy)
	}

	// And it is bounded: no recommendation should be able to eat the machine.
	huge := RecommendedConntrackMax(Facts{MemoryMB: 1 << 20, LiveConnections: 1 << 30})
	if huge > 2097152 {
		t.Errorf("the recommendation is unbounded at %d", huge)
	}
}

// The whole point of the safety group is that it does not wait to be asked.
func TestTheTableIsResizedWithoutBeingAsked(t *testing.T) {
	host := newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max":                     "65536",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "432000",
	})

	applied, err := host.EnsureSafety(context.Background(), 30000)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 2 {
		t.Fatalf("applied %d parameters, want both of the safety pair", applied)
	}

	max := host.mustRead(t, "proc/sys/net/netfilter/nf_conntrack_max")
	if max == "65536" {
		t.Error("the table was left at the stock size on a host carrying 30000 connections")
	}
	// Five days is what lets the dead connections pile up until the table is
	// full, which is the actual mechanism of the outage.
	if got := host.mustRead(t, "proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established"); got != "21600" {
		t.Errorf("the established timeout is %s, want six hours", got)
	}
}

// An operator who has given the table more room than the panel would has a
// reason, and taking it away is not the panel's to do.
func TestAnOperatorsOwnSizingIsNeverReducedNorTheirShorterTimeoutLengthened(t *testing.T) {
	host := newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max":                     "1048576",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "600",
	})

	applied, err := host.EnsureSafety(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if applied != 0 {
		t.Errorf("changed %d parameters that were already better than the recommendation", applied)
	}
	if got := host.mustRead(t, "proc/sys/net/netfilter/nf_conntrack_max"); got != "1048576" {
		t.Errorf("the table was reduced to %s", got)
	}
	if got := host.mustRead(t, "proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established"); got != "600" {
		t.Errorf("a shorter timeout was lengthened to %s", got)
	}
}

// The throughput group is offered and never applied on its own initiative:
// those are machine-wide choices that affect every other service on the host.
func TestTheThroughputGroupIsNotAppliedBySafety(t *testing.T) {
	host := newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max":  "65536",
		"net.ipv4.tcp_congestion_control": "cubic",
	})

	if _, err := host.EnsureSafety(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}
	if got := host.mustRead(t, "proc/sys/net/ipv4/tcp_congestion_control"); got != "cubic" {
		t.Errorf("congestion control was changed to %s without being asked", got)
	}
}

// The report is what the interface renders: every parameter, what it is now,
// what it should be, and whether anything is outstanding.
func TestTheReportSaysWhatIsOutstanding(t *testing.T) {
	host := newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max":  "65536",
		"net.ipv4.tcp_congestion_control": "cubic",
		"net.core.default_qdisc":          "fq",
	})

	report := host.Report(1000)
	if report.Facts.MemoryMB < 2000 || report.Facts.MemoryMB > 2100 {
		t.Errorf("memory read as %d MB, want about 2048", report.Facts.MemoryMB)
	}
	if report.SafetyPending == 0 {
		t.Error("a host with the stock table size reports nothing outstanding in the safety group")
	}

	byKey := map[string]Reading{}
	for _, reading := range report.Readings {
		byKey[reading.Key] = reading
	}
	// One already at the recommended value is not outstanding.
	if qdisc := byKey["net.core.default_qdisc"]; !qdisc.Matches {
		t.Errorf("a parameter already set to the recommendation reads as outstanding: %+v", qdisc)
	}
	// One this kernel does not have is reported as unavailable rather than as
	// wrong: some of these only exist once a module is loaded.
	if missing := byKey["net.core.rmem_max"]; missing.Available {
		t.Error("a parameter absent from the fixture is reported as readable")
	}
	// And every one carries an explanation, because a list of kernel names is
	// not something an operator can act on.
	for _, reading := range report.Readings {
		if strings.TrimSpace(reading.Explain) == "" || strings.TrimSpace(reading.Title) == "" {
			t.Errorf("%s has no plain-language explanation", reading.Key)
		}
	}
}

func (m *Manager) mustRead(t *testing.T, proc string) string {
	t.Helper()
	value, ok := m.read(proc)
	if !ok {
		t.Fatalf("%s could not be read", proc)
	}
	return value
}

// Every parameter the panel offers is one the panel is allowed to set, and the
// file it writes them to is one it is allowed to write.
//
// The regression this guards is the one that made tuning impossible: the file
// was given a path of its own and the guard was never told, so every apply came
// back as a protected-path refusal — the panel forbidding itself. The same trap
// is one line away for a parameter added to the catalogue without being added
// to the guard's list, and an operator would meet it as a button that silently
// does less than it says.
func TestEveryOfferedParameterIsOneThePanelMaySet(t *testing.T) {
	guard := safety.NewRouteGuard(8443, nil, "/var/lib/gre-panel/rules")

	if err := guard.CheckPath(TuningSysctlFile); err != nil {
		t.Errorf("the panel may not write its own tuning file %s: %v", TuningSysctlFile, err)
	}
	for _, parameter := range Catalogue() {
		if err := guard.CheckSysctl(parameter.Key); err != nil {
			t.Errorf("%s is offered but the guard refuses it: %v", parameter.Key, err)
		}
	}
}
