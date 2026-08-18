// Package reconcile compares what the panel believes against what the kernel
// and the filesystem actually hold, and offers the actions that close the gap
// (§12).
//
// An operator can change things outside the panel, so the database and the
// kernel will diverge. The panel's answer is to notice, say exactly what
// differs, and let a person decide — never to quietly destroy an interface it
// does not recognise.
package reconcile

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// Status names, matching the ReconcileStatus lookup table (§6).
const (
	StatusInSync       = "InSync"
	StatusDrifted      = "Drifted"
	StatusMissing      = "Missing"
	StatusUnmanaged    = "Unmanaged"
	StatusInconsistent = "Inconsistent"
)

// Offered actions.
const (
	ActionAdopt    = "adopt"
	ActionReapply  = "reapply"
	ActionForget   = "forget"
	ActionIgnore   = "ignore"
	ActionUnignore = "unignore"
	ActionDelete   = "delete"
)

// legacyNameRe matches the interface names the install script this panel
// replaces produced: a fixed prefix, one of its two side markers, and a number.
// Recognising them is what makes those tunnels adoptable without downtime
// (§1, §12).
var legacyNameRe = regexp.MustCompile(`^gre-(ir|kh)-(\d+)$`)

// legacySideSlots maps the script's two side markers onto the panel's slots.
// The mapping is not arbitrary: the script gave the first marker the .1 address
// and the second the .2 address, which is exactly the slot rule of §5.4.
var legacySideSlots = map[string]int64{
	"ir": model.TunnelSideA,
	"kh": model.TunnelSideB,
}

// legacyKeepalivePrefix is the unit name prefix the script used for its
// permanent ping process.
const legacyKeepalivePrefix = "gre-keepalive-"

// LegacyInfo describes an interface the old install script created.
type LegacyInfo struct {
	// Marker is the side marker in the name, kept verbatim so an operator
	// recognises their own tunnel.
	Marker string `json:"marker"`
	// TunnelSideID is the slot that marker corresponds to.
	TunnelSideID int64  `json:"tunnel_side_id"`
	SideSlot     string `json:"side_slot"`
	// TunnelNumber is the number in the name.
	TunnelNumber int64 `json:"tunnel_number"`
	// UnitPath is the script's unit file, if it is still there.
	UnitPath string `json:"unit_path,omitempty"`
	// KeepalivePath is the script's keepalive unit, if it is still there.
	KeepalivePath string `json:"keepalive_unit_path,omitempty"`
	// IsPanelOwned reports whether the unit file has already been taken over.
	IsPanelOwned bool `json:"is_panel_owned"`
}

// ParseLegacyName recognises an interface the old script created.
func ParseLegacyName(name string) (LegacyInfo, bool) {
	match := legacyNameRe.FindStringSubmatch(name)
	if match == nil {
		return LegacyInfo{}, false
	}
	number, err := strconv.ParseInt(match[2], 10, 64)
	if err != nil {
		return LegacyInfo{}, false
	}
	side := legacySideSlots[match[1]]
	return LegacyInfo{
		Marker:       match[1],
		TunnelSideID: side,
		SideSlot:     model.SideSlot(side),
		TunnelNumber: number,
	}, true
}

// FieldDiff is one attribute that differs between the stored tunnel and the
// live one. Reporting the exact field is the whole point: "drifted" without
// saying what drifted is no more useful than the legacy script's opaque status.
type FieldDiff struct {
	Field   string `json:"field"`
	Desired string `json:"desired"`
	Actual  string `json:"actual"`
}

// Item is one line of the reconcile report.
type Item struct {
	TunnelID          *int64      `json:"tunnel_id,omitempty"`
	InterfaceName     string      `json:"interface_name"`
	ReconcileStatusID int64       `json:"reconcile_status_id"`
	Status            string      `json:"status"`
	Detail            string      `json:"detail"`
	Diffs             []FieldDiff `json:"diffs,omitempty"`
	Observed          *Observed   `json:"observed,omitempty"`
	Legacy            *LegacyInfo `json:"legacy,omitempty"`
	Actions           []string    `json:"actions"`
	IsIgnored         bool        `json:"is_ignored"`
}

// Observed is the live state of an interface, reduced to what the report shows.
type Observed struct {
	Kind           string   `json:"kind"`
	Mtu            int      `json:"mtu"`
	OperState      string   `json:"oper_state"`
	IsUp           bool     `json:"is_up"`
	IsLowerUp      bool     `json:"is_lower_up"`
	LocalEndpoint  string   `json:"local_endpoint,omitempty"`
	RemoteEndpoint string   `json:"remote_endpoint,omitempty"`
	Ttl            int      `json:"ttl,omitempty"`
	IKey           *int64   `json:"ikey,omitempty"`
	OKey           *int64   `json:"okey,omitempty"`
	Addresses      []string `json:"addresses,omitempty"`
}

// Report is the whole comparison.
type Report struct {
	CheckedAt string         `json:"checked_at"`
	Items     []Item         `json:"items"`
	Counts    map[string]int `json:"counts"`

	// Routes is the forwarding half (§9 of the port forwarding specification),
	// classified the same way and by the same status names. Findings holds what
	// belongs to the host rather than to any one rule: forwarding turned off
	// externally, the panel's jump rules missing from a built-in chain, and
	// foreign rules overlapping the panel's.
	Routes        []RouteItem    `json:"routes"`
	RouteCounts   map[string]int `json:"route_counts"`
	RouteFindings RouteFindings  `json:"route_findings"`
}

// Settings is the slice of the settings store this package reads.
type Settings interface {
	Bool(key string) bool
	StringSlice(key string) []string
}

// Service compares stored state against live state and carries out the actions.
type Service struct {
	Tunnels  *tunnel.Service
	Repo     *tunnel.Repo
	Links    link.LinkManager
	Store    *persist.Store
	Renderer *persist.Renderer
	Settings Settings

	// The forwarding half, wired by SetRoutes after construction because the
	// route service is built after this one. Without them the report covers
	// tunnels only rather than failing.
	routes      RouteSource
	ruleBackend RouteBackend
	forwarding  ForwardingSource
}

// New returns a reconciliation service.
func New(tunnels *tunnel.Service, repo *tunnel.Repo, links link.LinkManager,
	store *persist.Store, renderer *persist.Renderer, set Settings) *Service {
	return &Service{
		Tunnels: tunnels, Repo: repo, Links: links,
		Store: store, Renderer: renderer, Settings: set,
	}
}

// Report classifies every stored tunnel and every unmanaged tunnel interface on
// the host (§12).
func (s *Service) Report(ctx context.Context) (Report, error) {
	records, err := s.Repo.List(ctx)
	if err != nil {
		return Report{}, err
	}
	links, err := s.Links.List(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("reading interfaces: %w", err)
	}

	observed := link.ByName(links)
	ignored := map[string]bool{}
	if s.Settings != nil {
		for _, name := range s.Settings.StringSlice("system.ignored_interfaces") {
			ignored[name] = true
		}
	}

	report := Report{
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Counts:    map[string]int{}, RouteCounts: map[string]int{}, Routes: []RouteItem{},
	}
	managed := map[string]bool{}

	for _, rec := range records {
		managed[rec.InterfaceName] = true
		report.Items = append(report.Items, s.classify(rec, observed[rec.InterfaceName],
			observed != nil && hasLink(observed, rec.InterfaceName)))
	}

	for _, l := range links {
		if !l.IsTunnel() || managed[l.Name] {
			continue
		}
		// The kernel's own stub devices are not tunnels anybody made. gre0 and
		// gretap0 appear the moment the ip_gre and ip_gretap modules load, on
		// every host that has them, permanently down and with no endpoints.
		//
		// They were being offered for adoption, which cannot work and which the
		// panel contradicts in two other places: validate refuses to create a
		// tunnel with one of these names, and safety treats them as protected
		// devices. Inviting an operator to adopt one is inviting them to click
		// something the rest of the panel is built to refuse.
		//
		// They are dropped from the report rather than shown as a non-adoptable
		// row, because this report is what feeds "Needs attention", and a row
		// that can never be actioned or cleared is what teaches an operator to
		// stop reading the card. Nothing is hidden by it: every interface on the
		// host is still listed in the traffic breakdown, where it belongs.
		//
		// The list is the same one validate and safety use, so a name added
		// there is covered here without a fourth copy going stale.
		if validate.IsReservedInterfaceName(l.Name) {
			continue
		}
		report.Items = append(report.Items, s.classifyUnmanaged(l, ignored[l.Name]))
	}

	sort.SliceStable(report.Items, func(i, j int) bool {
		return report.Items[i].InterfaceName < report.Items[j].InterfaceName
	})
	for _, item := range report.Items {
		report.Counts[item.Status]++
	}

	// The forwarding half. A failure to read the netfilter ruleset does not
	// fail the whole report: an operator asking about their tunnels should not
	// be told nothing because nft is missing.
	routes, findings, err := s.RouteReport(ctx)
	if err != nil {
		findings.Notes = append(findings.Notes,
			"the forwarding rules could not be compared: "+err.Error())
	}
	if routes != nil {
		report.Routes = routes
	}
	report.RouteFindings = findings
	for _, item := range report.Routes {
		report.RouteCounts[item.Status]++
	}
	return report, nil
}

func hasLink(byName map[string]link.Link, name string) bool {
	_, ok := byName[name]
	return ok
}

// classify decides the status of one stored tunnel.
func (s *Service) classify(rec tunnel.Record, observed link.Link, exists bool) Item {
	id := rec.TunnelID
	item := Item{
		TunnelID: &id, InterfaceName: rec.InterfaceName,
		Actions: []string{ActionReapply, ActionForget, ActionDelete},
	}
	if legacy, ok := ParseLegacyName(rec.InterfaceName); ok {
		item.Legacy = &legacy
	}

	// A tunnel the panel could neither configure nor clean up is the most
	// serious state there is, and it stays visible until someone resolves it.
	if rec.ApplyStatusID == model.ApplyStatusInconsistent {
		item.ReconcileStatusID = model.ReconcileStatusInconsistent
		item.Status = StatusInconsistent
		item.Detail = "the last change to this tunnel failed and could not be undone. The host may be " +
			"half-configured; reapply, or clean it up by hand and then forget it."
		if rec.LastApplyError != nil {
			item.Detail += " The failure was: " + *rec.LastApplyError
		}
		return item
	}

	if !exists {
		item.ReconcileStatusID = model.ReconcileStatusMissing
		item.Status = StatusMissing
		item.Detail = fmt.Sprintf("the panel has a tunnel called %s but no such interface exists on this "+
			"host. Reapply to build it again, or forget it to drop the record.", rec.InterfaceName)
		return item
	}

	item.Observed = summarise(observed)
	item.Diffs = compare(rec, observed)
	if len(item.Diffs) == 0 {
		item.ReconcileStatusID = model.ReconcileStatusInSync
		item.Status = StatusInSync
		item.Detail = "the running interface matches the stored configuration"
		return item
	}

	item.ReconcileStatusID = model.ReconcileStatusDrifted
	item.Status = StatusDrifted
	fields := make([]string, 0, len(item.Diffs))
	for _, d := range item.Diffs {
		fields = append(fields, d.Field)
	}
	item.Detail = "the running interface differs from the stored configuration in " + strings.Join(fields, ", ")
	return item
}

// classifyUnmanaged describes a tunnel interface the panel has no record of.
// It is never destroyed automatically: something else on this host may own it.
func (s *Service) classifyUnmanaged(l link.Link, ignored bool) Item {
	item := Item{
		InterfaceName:     l.Name,
		ReconcileStatusID: model.ReconcileStatusUnmanaged,
		Status:            StatusUnmanaged,
		Observed:          summarise(l),
		IsIgnored:         ignored,
		Actions:           []string{ActionAdopt, ActionIgnore},
	}
	if ignored {
		item.Actions = []string{ActionAdopt, ActionUnignore}
		item.Detail = fmt.Sprintf("%s is a tunnel this panel does not manage, and you have asked for it "+
			"not to be reported. It is never changed or removed.", l.Name)
		return item
	}

	item.Detail = fmt.Sprintf("%s is a tunnel on this host that the panel has no record of. Adopt it to "+
		"manage it here, or ignore it if something else owns it. The panel never removes an interface "+
		"it does not manage.", l.Name)

	if legacy, ok := ParseLegacyName(l.Name); ok {
		legacy.UnitPath = s.Store.UnitPath(l.Name)
		if !persist.Exists(legacy.UnitPath) {
			legacy.UnitPath = ""
		} else {
			legacy.IsPanelOwned, _ = persist.IsPanelOwned(legacy.UnitPath)
		}
		keepalive := s.legacyKeepalivePath(l.Name)
		if persist.Exists(keepalive) {
			legacy.KeepalivePath = keepalive
		}
		item.Legacy = &legacy
		item.Detail = fmt.Sprintf("%s was created by the install script this panel replaces. Adopting it "+
			"imports its parameters from the kernel; the interface is never renamed and never "+
			"interrupted.", l.Name)
	}
	return item
}

// legacyKeepalivePath is where the old script put its permanent ping unit.
func (s *Service) legacyKeepalivePath(name string) string {
	return filepath.Join(s.Store.SystemdDir, legacyKeepalivePrefix+name+persist.UnitSuffix)
}

func summarise(l link.Link) *Observed {
	out := &Observed{
		Kind: l.Kind, Mtu: l.MTU, OperState: l.OperState,
		IsUp: l.IsUp, IsLowerUp: l.IsLowerUp,
	}
	if l.Tunnel != nil {
		out.LocalEndpoint = l.Tunnel.Local
		out.RemoteEndpoint = l.Tunnel.Remote
		out.Ttl = l.Tunnel.Ttl
		out.IKey = keyInt(l.Tunnel.IKey)
		out.OKey = keyInt(l.Tunnel.OKey)
	}
	for _, a := range l.Addresses {
		out.Addresses = append(out.Addresses, a.String())
	}
	return out
}

func keyInt(v *uint32) *int64 {
	if v == nil {
		return nil
	}
	n := int64(*v)
	return &n
}

// compare produces the exact field diffs between the stored tunnel and the
// running interface.
func compare(rec tunnel.Record, observed link.Link) []FieldDiff {
	desired := tunnel.SpecOf(rec)
	var diffs []FieldDiff
	add := func(field, want, got string) {
		if want != got {
			diffs = append(diffs, FieldDiff{Field: field, Desired: want, Actual: got})
		}
	}

	add("tunnel_type", desired.Kind, observed.Kind)
	add("mtu", strconv.Itoa(desired.Mtu), strconv.Itoa(observed.MTU))

	if observed.Tunnel == nil {
		diffs = append(diffs, FieldDiff{
			Field: "tunnel_attributes", Desired: "present", Actual: "the interface reports none",
		})
	} else {
		add("local_endpoint", desired.Local, observed.Tunnel.Local)
		add("remote_endpoint", desired.Remote, observed.Tunnel.Remote)
		add("ttl", strconv.Itoa(desired.Ttl), strconv.Itoa(observed.Tunnel.Ttl))
		add("ikey", keyText(desired.IKey), keyText(observed.Tunnel.IKey))
		add("okey", keyText(desired.OKey), keyText(observed.Tunnel.OKey))
		add("has_input_checksum", yesNo(desired.HasInputChecksum), yesNo(observed.Tunnel.HasInputChecksum))
		add("has_output_checksum", yesNo(desired.HasOutputChecksum), yesNo(observed.Tunnel.HasOutputChecksum))
		add("has_input_sequence", yesNo(desired.HasInputSequence), yesNo(observed.Tunnel.HasInputSequence))
		add("has_output_sequence", yesNo(desired.HasOutputSequence), yesNo(observed.Tunnel.HasOutputSequence))
	}

	// The administrative state is compared through the flags, never through the
	// operational state: a healthy GRE tunnel reports UNKNOWN (§2).
	add("is_up", yesNo(rec.IsEnabled), yesNo(observed.IsUp))

	for _, want := range tunnel.AddressesOf(rec) {
		if !observed.HasAddress(want) {
			diffs = append(diffs, FieldDiff{
				Field: "address " + want.String(), Desired: "present", Actual: "missing",
			})
		}
	}
	for _, got := range observed.Addresses {
		if got.Scope == "link" {
			continue // link-local addresses the kernel adds itself
		}
		found := false
		for _, want := range tunnel.AddressesOf(rec) {
			if want.Address == got.Address && want.PrefixLength == got.PrefixLength {
				found = true
				break
			}
		}
		if !found {
			diffs = append(diffs, FieldDiff{
				Field: "address " + got.String(), Desired: "not configured", Actual: "present",
			})
		}
	}
	return diffs
}

func keyText(key *uint32) string {
	if key == nil {
		return "none"
	}
	return strconv.FormatUint(uint64(*key), 10)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// ---------------------------------------------------------------- actions

// Forget drops the panel's record of a tunnel without touching the kernel
// (§12). It is the right action for a tunnel that something else now owns.
func (s *Service) Forget(ctx context.Context, id int64) (tunnel.Record, error) {
	rec, err := s.Repo.ByID(ctx, id)
	if err != nil {
		return tunnel.Record{}, err
	}
	if err := s.Repo.SoftDelete(ctx, id); err != nil {
		return tunnel.Record{}, err
	}
	return rec, nil
}

// Ignore stops reconcile reporting an unmanaged interface, and Unignore undoes
// that. Neither touches the interface.
type IgnoreStore interface {
	Update(ctx context.Context, updates map[string]any, userID *int64) ([]string, error)
	StringSlice(key string) []string
}

// SetIgnored adds or removes an interface from the ignore list.
func SetIgnored(ctx context.Context, store IgnoreStore, name string, ignored bool, userID *int64) ([]string, error) {
	if err := validate.InterfaceName(name); err != nil {
		return nil, fmt.Errorf("%q is not a valid interface name: %s", name, err.Error())
	}

	current := store.StringSlice("system.ignored_interfaces")
	next := make([]any, 0, len(current)+1)
	seen := false
	for _, existing := range current {
		if existing == name {
			seen = true
			if !ignored {
				continue
			}
		}
		next = append(next, existing)
	}
	if ignored && !seen {
		next = append(next, name)
	}

	if _, err := store.Update(ctx, map[string]any{"system.ignored_interfaces": next}, userID); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(next))
	for _, item := range next {
		out = append(out, item.(string))
	}
	return out, nil
}
