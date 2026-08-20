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

	// Kind is the shape of the value, and so the control the interface offers
	// for editing it.
	Kind Kind `json:"kind"`
	// Choices are the values this kernel takes here, each with the
	// plain-language name for what picking it does.
	Choices []Choice `json:"choices,omitempty"`
	// Open marks a choice an operator may type into as well as pick from,
	// because the panel has no way to ask this kernel what it supports.
	Open bool `json:"open,omitempty"`
	// Min and Max bound a number. Zero means unbounded in that direction.
	Min int `json:"min,omitempty"`
	Max int `json:"max,omitempty"`
	// Fields is how many numbers a multi-number value wants.
	Fields int `json:"fields,omitempty"`
	// Unit is what the number counts, in the operator's words.
	Unit string `json:"unit,omitempty"`
	// Desired is what the panel's own file sets this to, which is where an
	// edited field starts. Empty means the panel is not keeping this one and
	// the field starts from whatever the kernel holds.
	Desired string `json:"desired"`
	// Custom reports that the operator chose a value of their own here rather
	// than the panel's recommendation.
	Custom bool `json:"custom"`
	// Drifted reports that the panel is keeping a value the kernel does not
	// hold: something else set it since, or the kernel refused the write.
	Drifted bool `json:"drifted"`
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

// TuningSysctlFile is the panel's own file for these parameters. It is
// separate from the forwarding one so that reverting the throughput tuning
// never touches the parameters a relay cannot work without.
//
// It is the safety package's constant rather than a second spelling of the
// same path: the guard refuses to write a file it does not recognise as the
// panel's, so a copy here that drifted would refuse every apply with a
// message about protected paths.
const TuningSysctlFile = safety.PanelTuningSysctlFile

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

	recorded, _ := m.recorded()

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

			Kind: parameter.Kind, Open: parameter.Open,
			Min: parameter.Min, Max: parameter.Max,
			Fields: parameter.Fields, Unit: parameter.Unit,
			Choices: m.offeredChoices(parameter),
			Desired: recorded[parameter.Key],
		}
		reading.Custom = reading.Desired != "" && recommended != "" &&
			!Matches(reading.Desired, recommended)
		reading.Drifted = reading.Desired != "" && ok && !Matches(current, reading.Desired)
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

// Apply sets the parameters of the given groups to what the panel recommends.
//
// This is the one-click tuning: it says nothing about the operator's own
// choices except to replace them, which is what pressing a button labelled
// "use the recommended values" is asking for.
func (m *Manager) Apply(ctx context.Context, groups ...Group) (int, error) {
	inGroup := map[Group]bool{}
	for _, group := range groups {
		inGroup[group] = true
	}
	facts := m.HostFacts(0)

	wanted := map[string]string{}
	for _, parameter := range Catalogue() {
		if !inGroup[parameter.Group] || parameter.Recommend == nil {
			continue
		}
		if recommended := parameter.Recommend(facts); recommended != "" {
			wanted[parameter.Key] = recommended
		}
	}
	return m.commit(ctx, wanted)
}

// Set makes the panel keep the values an operator chose, alongside whatever it
// was already keeping. An empty value asks it to stop keeping that parameter:
// the kernel holds whatever it holds, and only the record goes.
//
// Values are validated before anything is written, so a rejected field leaves
// the host exactly as it was rather than half-tuned.
func (m *Manager) Set(ctx context.Context, values map[string]string) (int, error) {
	for key, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if err := m.Validate(key, value); err != nil {
			return 0, err
		}
	}
	return m.commit(ctx, values)
}

// Validate checks one value against the parameter it is for, using what this
// kernel says it supports rather than what the panel assumes.
func (m *Manager) Validate(key, value string) error {
	parameter, ok := ParameterFor(key)
	if !ok {
		return fmt.Errorf("not a parameter the panel knows")
	}
	allowed := make([]string, 0, len(parameter.Choices))
	for _, choice := range m.offeredChoices(parameter) {
		allowed = append(allowed, choice.Value)
	}
	return parameter.Validate(value, allowed)
}

// offeredChoices is what a choice parameter may be set to on this host.
//
// The kernel's own list comes first where it publishes one, because which
// algorithms a kernel has depends on the modules it was built with. The panel's
// list is merged in rather than replaced: a module the kernel will load on
// demand is not in the published list until something asks for it, and BBR --
// the recommendation on nearly every relay -- is usually exactly that module.
func (m *Manager) offeredChoices(parameter Parameter) []Choice {
	if parameter.Kind != KindChoice {
		return nil
	}
	detail := map[string]string{}
	for _, choice := range parameter.Choices {
		detail[choice.Value] = choice.Detail
	}

	var out []Choice
	seen := map[string]bool{}
	add := func(value string) {
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		out = append(out, Choice{Value: value, Detail: detail[value]})
	}

	if parameter.ChoicesProc != "" {
		if raw, ok := m.read(parameter.ChoicesProc); ok {
			for _, value := range strings.Fields(raw) {
				add(value)
			}
		}
	}
	for _, choice := range parameter.Choices {
		add(choice.Value)
	}
	return out
}

// commit makes the panel's file say what wanted says, on top of what it already
// said, and sets live every parameter whose kernel value differs from it.
//
// The whole desired set is written every time rather than only the part that
// changed. Writing the delta was a quiet way to lose work: editing one
// parameter would rewrite the file with that parameter alone, and every other
// value the operator had asked the panel to keep would be gone at the next
// reboot -- present in the running kernel, absent from the file, and so
// impossible to notice until the host came back untuned.
//
// The file goes first and the live values second, for the same reason the
// forwarding manager does it that way: the file is what survives a reboot, and
// a panel that set a value and then failed to record it would leave a host
// tuned until the next restart and mysteriously untuned after it.
func (m *Manager) commit(ctx context.Context, wanted map[string]string) (int, error) {
	recorded, previous := m.recorded()

	desired := map[string]string{}
	for key, value := range recorded {
		desired[key] = value
	}
	for key, value := range wanted {
		if strings.TrimSpace(value) == "" {
			delete(desired, key)
			continue
		}
		desired[key] = strings.TrimSpace(value)
	}

	var values []persist.SysctlValue
	var live []struct{ proc, value string }
	// Catalogue order rather than map order, so the file reads the same way
	// twice running and a diff of it shows what actually changed.
	for _, parameter := range Catalogue() {
		value, keeping := desired[parameter.Key]
		if !keeping {
			continue
		}
		if m.Guard != nil {
			if err := m.Guard.CheckSysctl(parameter.Key); err != nil {
				// Skipped, not fatal. An operator asking for the host to be
				// tuned wants it tuned as far as it can be; handing them a
				// refusal and nothing done is the worse answer.
				m.logger().Warn("a tuning parameter is not one the panel may set",
					"key", parameter.Key, "error", err)
				continue
			}
		}
		current, readable := m.read(parameter.Proc)
		was := previous[parameter.Key]
		if was == "" {
			was = current
		}
		values = append(values, persist.SysctlValue{
			Key: parameter.Key, Value: value, Previous: was,
		})
		if readable && !Matches(current, value) {
			live = append(live, struct{ proc, value string }{parameter.Proc, value})
		}
	}

	path := m.sysctlFile()
	if m.Guard != nil {
		if err := m.Guard.CheckPath(path); err != nil {
			return 0, err
		}
	}
	if len(values) == 0 {
		// Nothing left to keep. Removing the file rather than leaving an empty
		// one is what makes "the panel is not tuning this host" readable, both
		// in the interface and to anyone reading /etc/sysctl.d by hand.
		if m.Store != nil && persist.Exists(path) {
			if _, err := m.Store.Remove(ctx, path, false); err != nil {
				return 0, err
			}
		}
		return 0, nil
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

// recorded is what the panel's own file currently sets, and what each parameter
// held before the panel first touched it.
func (m *Manager) recorded() (values, previous map[string]string) {
	content, err := os.ReadFile(m.sysctlFile())
	if err != nil || !strings.Contains(string(content), persist.OwnershipMarker) {
		return map[string]string{}, map[string]string{}
	}
	return persist.ParseValues(string(content)), persist.ParsePreviousValues(string(content))
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
	recorded, _ := m.recorded()

	wanted := map[string]string{}
	for _, parameter := range Catalogue() {
		if parameter.Group != GroupSafety || parameter.Recommend == nil {
			continue
		}
		current, ok := m.read(parameter.Proc)
		if !ok {
			continue
		}
		// An operator who has said what this parameter should be has said it.
		// The panel holds the host to that value and does not offer a second
		// opinion about it -- the point of an editable field is that editing it
		// means something.
		if chosen, said := recorded[parameter.Key]; said {
			if !Matches(current, chosen) {
				wanted[parameter.Key] = chosen
			}
			continue
		}
		recommended := parameter.Recommend(facts)
		if recommended == "" {
			continue
		}
		// Only ever raised, never lowered: an operator who has given the table
		// more room than the panel would has a reason, and taking it away is
		// not the panel's to do. The timeout is the other way round -- shorter
		// is what stops the table filling -- so it is set when it is longer.
		if !shouldReplace(parameter.Key, current, recommended) {
			continue
		}
		wanted[parameter.Key] = recommended
	}
	if len(wanted) == 0 {
		return 0, nil
	}

	applied, err := m.commit(ctx, wanted)
	if err != nil {
		return 0, err
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
