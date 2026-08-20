package tuning

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/persist"
)

// managed gives a fixture host a real file to write its parameters to, which is
// what every test about keeping values needs: the file is the record of what
// the panel has been asked to hold, and without one there is nothing to hold.
func managed(t *testing.T, host *Manager) *Manager {
	t.Helper()
	host.SysctlPath = "/etc/sysctl.d/99-gre-panel-tuning.conf"
	host.Store = persist.NewStore(t.TempDir(), t.TempDir(), "", nil)
	host.Renderer = persist.NewRenderer("", "", "")
	return host
}

func (m *Manager) fileValues(t *testing.T) map[string]string {
	t.Helper()
	content, err := os.ReadFile(m.sysctlFile())
	if err != nil {
		t.Fatalf("the panel wrote no file: %v", err)
	}
	return persist.ParseValues(string(content))
}

// Editing one parameter must not throw away the others.
//
// The panel rewrites its whole sysctl file every time it changes anything, so a
// save that only wrote the parameter being edited would drop every other value
// the operator had asked it to keep. The loss is invisible until the host
// reboots: the running kernel still holds them, the file no longer does, and
// the machine comes back untuned for reasons nothing on it can explain.
func TestEditingOneParameterKeepsTheRest(t *testing.T) {
	host := managed(t, newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max":  "65536",
		"net.ipv4.tcp_congestion_control": "cubic",
		"net.core.default_qdisc":          "pfifo_fast",
		"net.ipv4.tcp_fin_timeout":        "60",
	}))

	if _, err := host.Apply(context.Background(), GroupSafety, GroupThroughput); err != nil {
		t.Fatal(err)
	}
	before := host.fileValues(t)
	if len(before) < 4 {
		t.Fatalf("applying the recommendations kept only %d parameters: %v", len(before), before)
	}

	// One field edited, by itself, the way the interface sends it.
	if _, err := host.Set(context.Background(), map[string]string{
		"net.ipv4.tcp_fin_timeout": "30",
	}); err != nil {
		t.Fatal(err)
	}

	after := host.fileValues(t)
	if after["net.ipv4.tcp_fin_timeout"] != "30" {
		t.Errorf("the edited value is %q, want 30", after["net.ipv4.tcp_fin_timeout"])
	}
	for key, value := range before {
		if key == "net.ipv4.tcp_fin_timeout" {
			continue
		}
		if after[key] != value {
			t.Errorf("%s was %q before the edit and is %q after it", key, value, after[key])
		}
	}
	if got := host.mustRead(t, "proc/sys/net/ipv4/tcp_fin_timeout"); got != "30" {
		t.Errorf("the kernel holds %s, want the edited 30", got)
	}
}

// An operator's own value is theirs. The panel records it, sets it, and reports
// it as a choice rather than as something outstanding.
func TestAnOperatorsOwnValueIsKeptAndReportedAsTheirs(t *testing.T) {
	host := managed(t, newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max": "65536",
		"net.ipv4.tcp_keepalive_time":    "7200",
	}))

	if _, err := host.Set(context.Background(), map[string]string{
		"net.ipv4.tcp_keepalive_time": "45",
	}); err != nil {
		t.Fatal(err)
	}
	if got := host.mustRead(t, "proc/sys/net/ipv4/tcp_keepalive_time"); got != "45" {
		t.Errorf("the kernel holds %s, want the chosen 45", got)
	}

	reading := host.reading(t, "net.ipv4.tcp_keepalive_time")
	if reading.Desired != "45" {
		t.Errorf("the panel reports it is keeping %q, want 45", reading.Desired)
	}
	if !reading.Custom {
		t.Error("a value the operator chose over the recommendation is not marked as theirs")
	}
	if reading.Drifted {
		t.Error("a value the kernel holds is reported as drifted")
	}
}

// A value the parameter will not take is refused whole, before anything is
// written. The alternative is a host left half-tuned by a typo.
func TestABadValueIsRefusedAndChangesNothing(t *testing.T) {
	host := managed(t, newHost(t, 2048, map[string]string{
		"net.ipv4.tcp_fin_timeout":     "60",
		"net.ipv4.ip_local_port_range": "32768 60999",
		"net.core.default_qdisc":       "fq",
	}))

	for name, values := range map[string]map[string]string{
		"not a number":      {"net.ipv4.tcp_fin_timeout": "soon"},
		"below the floor":   {"net.ipv4.tcp_fin_timeout": "1"},
		"above the ceiling": {"net.ipv4.tcp_fin_timeout": "99999"},
		"wrong field count": {"net.ipv4.ip_local_port_range": "1024"},
		"not a real key":    {"net.ipv4.tcp_made_up": "1"},
	} {
		if _, err := host.Set(context.Background(), values); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if got := host.mustRead(t, "proc/sys/net/ipv4/tcp_fin_timeout"); got != "60" {
		t.Errorf("a refused save changed the kernel to %s", got)
	}
	if persist.Exists(host.sysctlFile()) {
		t.Error("a refused save wrote the panel's file")
	}

	// A qdisc the panel has never heard of is still allowed: the panel cannot
	// ask this kernel what queueing disciplines it has, and refusing a value an
	// operator knows their host supports would be the panel getting in the way.
	if _, err := host.Set(context.Background(), map[string]string{
		"net.core.default_qdisc": "htb",
	}); err != nil {
		t.Errorf("a queueing discipline outside the panel's list was refused: %v", err)
	}
}

// Congestion control is the one parameter whose choices the kernel publishes,
// and the published list is incomplete: BBR usually lives in a module that is
// not loaded until something asks for it. Offering only what is loaded would
// hide the recommendation behind the fact that nobody had chosen it yet.
func TestTheRecommendedAlgorithmIsOfferedEvenWhenTheModuleIsNotLoadedYet(t *testing.T) {
	host := newHost(t, 2048, map[string]string{"net.ipv4.tcp_congestion_control": "cubic"})
	if err := os.WriteFile(
		host.Root+"/proc/sys/net/ipv4/tcp_available_congestion_control",
		[]byte("reno cubic\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	offered := map[string]bool{}
	for _, choice := range host.reading(t, "net.ipv4.tcp_congestion_control").Choices {
		offered[choice.Value] = true
		// The ones the panel knows carry a note on what picking them does. The
		// ones only the kernel named are offered bare, which is the honest
		// thing to do with a value nobody here can describe.
		if choice.Value == "bbr" && strings.TrimSpace(choice.Detail) == "" {
			t.Error("the recommended algorithm is offered with no explanation")
		}
	}
	for _, want := range []string{"reno", "cubic", "bbr"} {
		if !offered[want] {
			t.Errorf("%s is not offered", want)
		}
	}
	if err := host.Validate("net.ipv4.tcp_congestion_control", "bbr"); err != nil {
		t.Errorf("the panel's own recommendation is refused: %v", err)
	}
	if err := host.Validate("net.ipv4.tcp_congestion_control", "vegas"); err == nil {
		t.Error("an algorithm this kernel does not have was accepted")
	}
}

// An empty value asks the panel to stop keeping a parameter. The kernel holds
// whatever it holds; only the record goes.
func TestAnEmptyValueStopsThePanelKeepingAParameter(t *testing.T) {
	host := managed(t, newHost(t, 2048, map[string]string{
		"net.ipv4.tcp_fin_timeout":    "60",
		"net.ipv4.tcp_keepalive_time": "7200",
	}))

	if _, err := host.Set(context.Background(), map[string]string{
		"net.ipv4.tcp_fin_timeout":    "20",
		"net.ipv4.tcp_keepalive_time": "600",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.Set(context.Background(), map[string]string{
		"net.ipv4.tcp_fin_timeout": "",
	}); err != nil {
		t.Fatal(err)
	}

	kept := host.fileValues(t)
	if _, still := kept["net.ipv4.tcp_fin_timeout"]; still {
		t.Error("the panel is still keeping a parameter it was told to let go")
	}
	if kept["net.ipv4.tcp_keepalive_time"] != "600" {
		t.Errorf("letting one parameter go took another with it: %v", kept)
	}
	// The kernel keeps what it was last set to. Letting go is the panel
	// stepping back, not undoing.
	if got := host.mustRead(t, "proc/sys/net/ipv4/tcp_fin_timeout"); got != "20" {
		t.Errorf("the kernel was changed to %s by a parameter being let go", got)
	}

	// And letting go of the last one removes the file, so that "the panel is
	// not tuning this host" is readable rather than an empty file to puzzle at.
	if _, err := host.Set(context.Background(), map[string]string{
		"net.ipv4.tcp_keepalive_time": "",
	}); err != nil {
		t.Fatal(err)
	}
	if persist.Exists(host.sysctlFile()) {
		t.Error("the panel's file survived the last parameter being let go")
	}
}

// The safety group does not wait to be asked, but it does not argue with an
// operator who has already answered. What it keeps doing is holding the host to
// the value they chose when something else moves it.
func TestSafetyHoldsTheOperatorsChoiceRatherThanOverridingIt(t *testing.T) {
	host := managed(t, newHost(t, 2048, map[string]string{
		"net.netfilter.nf_conntrack_max":                     "65536",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "432000",
	}))

	// A deliberately smaller table than the panel would pick.
	if _, err := host.Set(context.Background(), map[string]string{
		"net.netfilter.nf_conntrack_max": "131072",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := host.EnsureSafety(context.Background(), 200000); err != nil {
		t.Fatal(err)
	}
	if got := host.mustRead(t, "proc/sys/net/netfilter/nf_conntrack_max"); got != "131072" {
		t.Errorf("the panel overrode the operator's own sizing with %s", got)
	}
	// The parameter they said nothing about is still the panel's to keep.
	if got := host.mustRead(t,
		"proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established"); got != "21600" {
		t.Errorf("the established timeout is %s, want the panel's six hours", got)
	}

	// Something outside the panel moves it. The panel puts it back, because
	// keeping it there is the whole of what it was asked to do.
	if err := host.write("proc/sys/net/netfilter/nf_conntrack_max", "65536"); err != nil {
		t.Fatal(err)
	}
	if reading := host.reading(t, "net.netfilter.nf_conntrack_max"); !reading.Drifted {
		t.Error("a value the kernel no longer holds is not reported as drifted")
	}
	if _, err := host.EnsureSafety(context.Background(), 200000); err != nil {
		t.Fatal(err)
	}
	if got := host.mustRead(t, "proc/sys/net/netfilter/nf_conntrack_max"); got != "131072" {
		t.Errorf("a parameter moved out from under the panel was left at %s", got)
	}
}

func (m *Manager) reading(t *testing.T, key string) Reading {
	t.Helper()
	for _, reading := range m.Report(1000).Readings {
		if reading.Key == key {
			return reading
		}
	}
	t.Fatalf("%s is not in the report", key)
	return Reading{}
}
