package tuning

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/safety"
)

// Reading is one parameter as it stands on this host, beside what the panel
// would set it to.
type Reading struct {
	Key     string `json:"key"`
	Group   Group  `json:"group"`
	Title   string `json:"title"`
	Explain string `json:"explain"`
	// Current is what the kernel holds now. Empty means the parameter does not
	// exist on this kernel, which is not a fault: some are module parameters
	// that appear only once the module is loaded.
	Current string `json:"current"`
	// Recommended is what the panel would set it to on this host. Empty means
	// the panel has no opinion.
	Recommended string `json:"recommended"`
	// Available reports that the parameter exists and can be read.
	Available bool `json:"available"`
	// Matches reports that the current value is already the recommended one.
	Matches bool `json:"matches"`
}

// Report is the whole picture: what the recommendations were computed from,
// and every parameter beside its recommendation.
type Report struct {
	Facts Facts `json:"facts"`
	// PanelManaged reports that the panel's tuning file is in place, which is
	// what makes the revert offer meaningful.
	PanelManaged bool      `json:"panel_managed"`
	SysctlPath   string    `json:"sysctl_path"`
	Readings     []Reading `json:"readings"`
	// Pending counts the parameters that are not yet at the recommended value,
	// which is the one number the interface leads with.
	Pending int `json:"pending"`
	// SafetyPending counts only those in the safety group, because those are
	// the ones whose being wrong takes the host off the network rather than
	// making it slow.
	SafetyPending int `json:"safety_pending"`
}

// Manager reads and applies the tuning parameters.
//
// It writes through the same persistence the rest of the panel uses: its own
// file, carrying what each parameter was before the panel first changed it, so
// that reverting puts back the operator's values and not the panel's.
type Manager struct {
	// Root is "/" in production and a fixture directory in tests.
	Root       string
	SysctlPath string
	Store      *persist.Store
	Renderer   *persist.Renderer
	Guard      *safety.RouteGuard
	Log        *slog.Logger
}

// TuningSysctlFile is the panel's own file for these parameters. It is separate
// from the forwarding one so that reverting the throughput tuning never touches
// the parameters a relay cannot work without.
const TuningSysctlFile = "/etc/sysctl.d/99-gre-panel-tuning.conf"

// New returns a manager rooted at the real filesystem.
func New(store *persist.Store, renderer *persist.Renderer, guard *safety.RouteGuard, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		Root: "/", SysctlPath: TuningSysctlFile,
		Store: store, Renderer: renderer, Guard: guard, Log: log,
	}
}

// HostFacts reads what the recommendations are computed from.
//
// liveConnections is what the relays are carrying now, which the caller knows
// and this package does not.
func (m *Manager) HostFacts(liveConnections int) Facts {
	return Facts{
		MemoryMB:        m.memoryMB(),
		Cores:           runtime.NumCPU(),
		LiveConnections: liveConnections,
	}
}

// Report reads every parameter and pairs it with its recommendation.
func (m *Manager) Report(liveConnections int) Report {
	facts := m.HostFacts(liveConnections)
	report := Report{Facts: facts, SysctlPath: m.sysctlFile()}

	if content, err := os.ReadFile(m.sysctlFile()); err == nil {
		report.PanelManaged = strings.Contains(string(content), persist.OwnershipMarker)
	}

	for _, parameter := range Catalogue() {
		current, ok := m.read(parameter.Proc)
		recommended := ""
		if parameter.Recommend != nil {
			recommended = parameter.Recommend(facts)
		}
		reading := Reading{
			Key: parameter.Key, Group: parameter.Group,
			Title: parameter.Title, Explain: parameter.Explain,
			Current: current, Recommended: recommended, Available: ok,
		}
		reading.Matches = ok && recommended != "" && Matches(current, recommended)
		if ok && recommended != "" && !reading.Matches {
			report.Pending++
			if parameter.Group == GroupSafety {
				report.SafetyPending++
			}
		}
		report.Readings = append(report.Readings, reading)
	}
	return report
}

// Apply sets the parameters of the given groups and records them.
//
// It writes the file first and the live values second, for the same reason the
// forwarding manager does: the file is what survives a reboot, and a panel that
// set the value and then failed to record it would leave a host tuned until the
// next restart and mysteriously untuned after it.
func (m *Manager) Apply(ctx context.Context, groups ...Group) (int, error) {
	wanted := map[Group]bool{}
	for _, group := range groups {
		wanted[group] = true
	}
	facts := m.HostFacts(0)

	var values []persist.SysctlValue
	var live []struct{ proc, value string }
	for _, parameter := range Catalogue() {
		if !wanted[parameter.Group] || parameter.Recommend == nil {
			continue
		}
		recommended := parameter.Recommend(facts)
		current, ok := m.read(parameter.Proc)
		if recommended == "" || !ok || Matches(current, recommended) {
			continue
		}
		if m.Guard != nil {
			if err := m.Guard.CheckSysctl(parameter.Key); err != nil {
				return 0, err
			}
		}
		values = append(values, persist.SysctlValue{
			Key: parameter.Key, Value: recommended,
			Previous: m.previousFor(parameter.Key, current),
		})
		live = append(live, struct{ proc, value string }{parameter.Proc, recommended})
	}
	if len(values) == 0 {
		return 0, nil
	}

	path := m.sysctlFile()
	if m.Guard != nil {
		if err := m.Guard.CheckPath(path); err != nil {
			return 0, err
		}
	}
	if m.Store != nil && m.Renderer != nil {
		if _, err := m.Store.Write(ctx, path, m.Renderer.SysctlFile(values), false); err != nil {
			return 0, fmt.Errorf("writing %s: %w", path, err)
		}
	}

	applied := 0
	for _, item := range live {
		if err := m.write(item.proc, item.value); err != nil {
			// One parameter a kernel will not accept does not undo the rest.
			// Some of these do not exist on older kernels, and refusing the
			// whole apply over one of them would leave the host untuned for a
			// parameter it was never going to have.
			m.logger().Warn("a tuning parameter could not be set", "path", item.proc, "error", err)
			continue
		}
		applied++
	}
	return applied, nil
}

// Revert puts back what the parameters were before the panel changed them and
// removes the panel's file.
func (m *Manager) Revert(ctx context.Context) error {
	path := m.sysctlFile()
	if m.Guard != nil {
		if err := m.Guard.CheckPath(path); err != nil {
			return err
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if !strings.Contains(string(content), persist.OwnershipMarker) {
		return fmt.Errorf("%s was not written by the panel, so the panel will not remove it", path)
	}

	byKey := map[string]string{}
	for _, parameter := range Catalogue() {
		byKey[parameter.Key] = parameter.Proc
	}
	for key, previous := range persist.ParsePreviousValues(string(content)) {
		proc, ok := byKey[key]
		if !ok || previous == "" {
			continue
		}
		if err := m.write(proc, previous); err != nil {
			m.logger().Warn("a tuning parameter could not be put back", "key", key, "error", err)
		}
	}
	if m.Store != nil {
		if _, err := m.Store.Remove(ctx, path, false); err != nil {
			return err
		}
	}
	return nil
}

// EnsureSafety keeps the parameters in the safety group at their recommended
// values.
//
// This one runs without being asked, because the thing it prevents is not
// slowness. When the connection tracking table fills, the kernel refuses every
// new connection on the host — the panel's own port, SSH, everything — and
// writes one line to the kernel log that nobody is reading. The panel's rules
// are what fill it, so keeping it sized is the panel's job.
func (m *Manager) EnsureSafety(ctx context.Context, liveConnections int) (int, error) {
	facts := m.HostFacts(liveConnections)

	var values []persist.SysctlValue
	var live []struct{ proc, value string }
	for _, parameter := range Catalogue() {
		if parameter.Group != GroupSafety || parameter.Recommend == nil {
			continue
		}
		recommended := parameter.Recommend(facts)
		current, ok := m.read(parameter.Proc)
		if !ok || recommended == "" {
			continue
		}
		// Only ever raised, never lowered: an operator who has given the table
		// more room than the panel would has a reason, and taking it away is
		// not the panel's to do. The timeout is the other way round -- shorter
		// is what stops the table filling -- so it is set when it is longer.
		if !shouldReplace(parameter.Key, current, recommended) {
			continue
		}
		if m.Guard != nil {
			if err := m.Guard.CheckSysctl(parameter.Key); err != nil {
				return 0, err
			}
		}
		values = append(values, persist.SysctlValue{
			Key: parameter.Key, Value: recommended,
			Previous: m.previousFor(parameter.Key, current),
		})
		live = append(live, struct{ proc, value string }{parameter.Proc, recommended})
	}
	if len(values) == 0 {
		return 0, nil
	}

	path := m.sysctlFile()
	if m.Store != nil && m.Renderer != nil {
		if _, err := m.Store.Write(ctx, path, m.Renderer.SysctlFile(values), false); err != nil {
			return 0, fmt.Errorf("writing %s: %w", path, err)
		}
	}
	applied := 0
	for _, item := range live {
		if err := m.write(item.proc, item.value); err != nil {
			m.logger().Warn("a safety parameter could not be set", "path", item.proc, "error", err)
			continue
		}
		applied++
	}
	m.logger().Info("connection tracking was resized for the traffic this host carries",
		"parameters", applied, "connections", liveConnections)
	return applied, nil
}

// shouldReplace decides whether a safety parameter's current value is worse
// than the recommendation, in the direction that matters for that parameter.
func shouldReplace(key, current, recommended string) bool {
	now, err1 := strconv.Atoi(strings.TrimSpace(current))
	want, err2 := strconv.Atoi(strings.TrimSpace(recommended))
	if err1 != nil || err2 != nil {
		return current != recommended
	}
	if strings.HasSuffix(key, "timeout_established") {
		// A longer timeout is what fills the table, so replace one that is
		// longer than recommended and leave a shorter one alone.
		return now > want
	}
	return now < want
}

// logger is nil-safe, because a Manager built by hand -- in a test, or by a
// caller that has no logger to give it -- is still a working manager.
func (m *Manager) logger() *slog.Logger {
	if m.Log == nil {
		return slog.Default()
	}
	return m.Log
}

func (m *Manager) sysctlFile() string {
	path := m.SysctlPath
	if path == "" {
		path = TuningSysctlFile
	}
	if m.Root == "" || m.Root == "/" {
		return path
	}
	return filepath.Join(m.Root, strings.TrimPrefix(path, "/"))
}

func (m *Manager) read(proc string) (string, bool) {
	root := m.Root
	if root == "" {
		root = "/"
	}
	raw, err := os.ReadFile(filepath.Join(root, proc))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

func (m *Manager) write(proc, value string) error {
	root := m.Root
	if root == "" {
		root = "/"
	}
	full := filepath.Join(root, proc)
	if err := os.WriteFile(full, []byte(value+"\n"), 0o644); err != nil {
		return fmt.Errorf("setting %s: %w", full, err)
	}
	return nil
}

// previousFor is what the parameter held the first time the panel changed it,
// so that reverting keeps pointing at the operator's own value rather than at
// one the panel wrote on a previous run.
func (m *Manager) previousFor(key, current string) string {
	if content, err := os.ReadFile(m.sysctlFile()); err == nil {
		if recorded, ok := persist.ParsePreviousValues(string(content))[key]; ok {
			return recorded
		}
	}
	return current
}

// memoryMB reads total memory from /proc/meminfo. Zero when it cannot be read,
// which makes every memory-derived recommendation fall to its floor rather than
// to nonsense.
func (m *Manager) memoryMB() int {
	root := m.Root
	if root == "" {
		root = "/"
	}
	raw, err := os.ReadFile(filepath.Join(root, "proc/meminfo"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		return kb / 1024
	}
	return 0
}
