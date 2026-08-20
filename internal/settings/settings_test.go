package settings

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

func newTestStore(t *testing.T) (context.Context, *db.DB, *Store) {
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
	store, err := New(ctx, database)
	if err != nil {
		t.Fatalf("creating the settings store failed: %v", err)
	}
	return ctx, database, store
}

// specifiedKeys is every key of §5.3, transcribed from the specification. The
// test below compares it against what the code declares in both directions, so
// a key that is missing and a key that was invented both fail.
var specifiedKeys = []string{
	"tunnel.default_type",
	"tunnel.default_key",
	"tunnel.default_mtu",
	"tunnel.default_ttl",
	"tunnel.default_tos",
	"tunnel.default_pmtudisc",
	"tunnel.default_csum",
	"tunnel.default_seq",
	"tunnel.naming_template",
	"tunnel.side_labels",
	"tunnel.default_persistence",
	"tunnel.auto_mtu_from_underlay",

	"addressing.default_pool_id",
	"addressing.default_prefix_len",
	"addressing.allow_public_ranges",
	"addressing.check_route_overlap",

	"keepalive.enabled_by_default",
	"keepalive.interval_seconds",
	"keepalive.packet_size",
	"keepalive.mode",

	"monitor.enabled",
	"monitor.interval_seconds",
	"monitor.timeout_seconds",
	"monitor.packet_size",
	"monitor.window_size",
	"monitor.degraded_loss_pct",
	"monitor.down_loss_pct",
	"monitor.degraded_rtt_ms",
	"monitor.state_change_samples",
	"monitor.aggregate_interval_seconds",
	"monitor.history_retention_days",

	"diagnostics.manual_ping_count",
	"diagnostics.manual_ping_interval",
	"diagnostics.manual_ping_timeout",
	"diagnostics.manual_ping_max_count",
	"diagnostics.mtu_probe_min",
	"diagnostics.mtu_probe_max",
	"diagnostics.allow_tcpdump",

	"metrics.sample_interval_seconds",
	"metrics.history_points",
	"metrics.hide_loopback",
	"metrics.hide_pseudo_filesystems",
	"metrics.disk_warn_pct",
	"metrics.disk_critical_pct",

	"display.language",
	"display.theme",
	"display.throughput_unit",
	"display.volume_unit",
	"display.binary_units",
	"display.digits",
	"display.calendar",

	"security.token_ttl_minutes",
	"security.refresh_ttl_days",
	"security.login_rate_limit_per_minute",
	"security.login_lockout_minutes",
	"security.allowed_origins",

	"system.reconcile_interval_seconds",
	"system.audit_retention_days",
	"system.auto_reapply_on_drift",

	// §11 of the port forwarding specification.
	"routes.default_nat_mode",
	"routes.default_protocol",
	"routes.default_clamp_mss",
	"routes.counter_interval_seconds",
	"routes.conntrack_interval_seconds",
	"routes.aggregate_interval_seconds",
	"routes.history_retention_days",
	"routes.auto_enable_ip_forward",
	"routes.warn_conntrack_usage_percent",
}

// additionalKeys are settings the panel declares beyond the table in §5.3.
// Every one of them exists because a value would otherwise have been hardcoded,
// which the flexibility requirement forbids. They are listed here explicitly so
// the check below still catches a key added by accident or by typo.
var additionalKeys = []string{
	// Reconciliation lists tunnel interfaces the panel does not manage. Which
	// of them an operator wants to stop hearing about is a policy, so it is a
	// setting rather than a hardcoded exclusion list.
	"system.ignored_interfaces",
	// Whether the panel asks the release host about newer versions, and how
	// long it reuses the answer. Both are policy: a server that must make no
	// outbound connections turns the first off, and the second is what keeps
	// one dashboard from becoming a stream of requests to the release host.
	"system.update_check_enabled",
	"system.update_check_interval_hours",
	// Whether the kernel counts the bytes on every tracked connection. It is
	// off by default there, and without it a load-balanced rule can report how
	// many connections each destination is taking and nothing about what is
	// crossing them. It is a setting because the counting costs a little on
	// every packet, which is a trade only the operator can make.
	"routes.count_connection_bytes",
	// Monitoring a forwarding rule's destinations, which the specification
	// describes for tunnels and not for relays. The defaults live here for
	// the same reason the tunnel probe's do: a rule overrides what it needs
	// and inherits the rest.
	// Keeping the connection tracking table sized for what the rules carry.
	// It is a setting rather than unconditional because it is the panel
	// changing a machine-wide kernel parameter on its own initiative, and an
	// operator who wants to size it themselves should be able to say so.
	"routes.manage_conntrack",
	"routes.monitor_enabled",
	"routes.monitor_interval_seconds",
	"routes.monitor_timeout_seconds",
	"routes.monitor_failure_threshold",
	"routes.monitor_recovery_threshold",
}

func TestEverySpecifiedKeyIsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range Keys() {
		if declared[k] {
			t.Errorf("setting %q is declared more than once", k)
		}
		declared[k] = true
	}
	for _, k := range specifiedKeys {
		if !declared[k] {
			t.Errorf("setting %q from the specification is not declared", k)
		}
		delete(declared, k)
	}
	for _, k := range additionalKeys {
		if !declared[k] {
			t.Errorf("setting %q is listed as an addition but is not declared", k)
		}
		delete(declared, k)
	}
	extra := make([]string, 0, len(declared))
	for k := range declared {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		t.Errorf("setting %q is declared but is not in the specification", k)
	}
}

// TestEverySettingCategoryIsNamedInTheInterface is the regression for a whole
// section of the Settings page that had no name.
//
// The page renders generically from this schema and groups by category, which
// is the point — a setting added here needs no frontend change. A *category*
// added here does: it needs a title and a description in every locale, and
// without them the page falls back to printing the raw identifier. The routes
// category shipped that way and the section was headed by the lowercase word
// "routes", with no explanation under it, in both languages.
//
// Reaching across into the frontend's files from a Go test is unusual, and it
// is done because this is the only place that knows the authoritative list.
// Every other check happens on one side of the boundary and so cannot see the
// gap at all.
func TestEverySettingCategoryIsNamedInTheInterface(t *testing.T) {
	categories := map[string]bool{}
	for _, d := range Definitions() {
		categories[d.Category] = true
	}
	if len(categories) == 0 {
		t.Fatal("no categories at all")
	}

	for _, locale := range []string{"en", "fa"} {
		path := filepath.Join("..", "..", "web", "_app", "src", "i18n", "locales", locale+".ts")
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		// Line endings are the checkout's business, not this test's: a Windows
		// working tree holds these files with CRLF, and a search written for LF
		// finds nothing there and reports it as a missing block rather than as
		// what it is.
		text := strings.ReplaceAll(string(body), "\r\n", "\n")

		for _, block := range []string{"category", "categoryHelp"} {
			section, ok := localeBlock(text, block)
			if !ok {
				t.Errorf("%s: no settings.%s block", locale, block)
				continue
			}
			for category := range categories {
				if !strings.Contains(section, "\n      "+category+":") {
					t.Errorf("%s: settings.%s has no entry for the %q category, so that section of "+
						"the Settings page renders its raw identifier", locale, block, category)
				}
			}
		}
	}
}

// localeBlock returns the body of one object in a locale file, found by its key
// and closed at the first line indented back to the key's own level.
func localeBlock(text, name string) (string, bool) {
	open := "\n    " + name + ": {\n"
	start := strings.Index(text, open)
	if start < 0 {
		return "", false
	}
	start += len(open)
	end := strings.Index(text[start:], "\n    },")
	if end < 0 {
		return "", false
	}
	return "\n" + text[start:start+end], true
}

// TestEveryDefinitionIsComplete enforces the §5.3 rule that every setting has a
// key, a type, a default, a description, constraints, a category, and a
// restart-required flag — the schema endpoint is useless if any of them is
// blank.
func TestEveryDefinitionIsComplete(t *testing.T) {
	validKinds := map[Kind]bool{
		KindBool: true, KindInt: true, KindFloat: true,
		KindString: true, KindEnum: true, KindJSON: true, KindLookup: true,
	}
	validCategories := map[string]bool{
		CategoryTunnel: true, CategoryAddressing: true, CategoryKeepalive: true,
		CategoryMonitor: true, CategoryDiagnostics: true, CategoryMetrics: true,
		CategoryDisplay: true, CategorySecurity: true, CategorySystem: true,
		CategoryRoutes: true,
	}

	for _, d := range Definitions() {
		if d.Key == "" {
			t.Fatal("a setting has an empty key")
		}
		if !validKinds[d.Type] {
			t.Errorf("%s: type %q is not a known kind", d.Key, d.Type)
		}
		if !validCategories[d.Category] {
			t.Errorf("%s: category %q is not a known category", d.Key, d.Category)
		}
		if len(d.Description) < 20 {
			t.Errorf("%s: description %q is too short to be useful in the UI", d.Key, d.Description)
		}
		if d.Type == KindEnum && len(d.Constraints.EnumValues) < 2 {
			t.Errorf("%s: an enum needs at least two values", d.Key)
		}
		if d.Type == KindLookup {
			table, ok := model.LookupTableByName(d.Constraints.LookupTable)
			if !ok {
				t.Errorf("%s: lookup table %q does not exist", d.Key, d.Constraints.LookupTable)
			}
			// The frontend builds the select box from the schema alone. Naming
			// the table without sending its rows leaves the operator with an
			// empty control and no way to choose anything.
			if len(d.Constraints.Options) != len(table.Values) {
				t.Errorf("%s: schema carries %d options for %s, want its %d rows",
					d.Key, len(d.Constraints.Options), d.Constraints.LookupTable, len(table.Values))
			}
			for i, opt := range d.Constraints.Options {
				if i < len(table.Values) {
					if opt.Value != table.Values[i].ID || opt.Label != table.Values[i].Title {
						t.Errorf("%s: option %d = {%d %q}, want {%d %q}",
							d.Key, i, opt.Value, opt.Label,
							table.Values[i].ID, table.Values[i].Title)
					}
				}
				if opt.Label == "" {
					t.Errorf("%s: option %d has no label to display", d.Key, i)
				}
			}
		}
		if d.Type == KindJSON && d.Constraints.JsonShape == "" {
			t.Errorf("%s: a JSON setting must declare its shape", d.Key)
		}
		if d.Default == nil && !d.Constraints.Nullable {
			t.Errorf("%s: default is null but the setting is not nullable", d.Key)
		}
		// The declared default must satisfy the declared constraints, or the
		// panel ships in a state it would reject if you saved it.
		if _, err := d.Coerce(d.Default); err != nil {
			t.Errorf("%s: the declared default %#v is rejected by its own constraints: %v",
				d.Key, d.Default, err)
		}
		// And it must survive a JSON round trip, since that is how it reaches
		// the frontend and comes back.
		encoded, err := json.Marshal(d.Default)
		if err != nil {
			t.Errorf("%s: the default cannot be encoded as JSON: %v", d.Key, err)
			continue
		}
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Errorf("%s: the encoded default cannot be decoded: %v", d.Key, err)
			continue
		}
		if _, err := d.Coerce(decoded); err != nil {
			t.Errorf("%s: the default does not survive a JSON round trip: %v", d.Key, err)
		}
	}
}

func TestDefaultsMatchTheSpecification(t *testing.T) {
	_, _, store := newTestStore(t)

	expectInt := map[string]int64{
		"tunnel.default_type":                  model.TunnelTypeGRE,
		"tunnel.default_key":                   2749365187,
		"tunnel.default_mtu":                   1472,
		"tunnel.default_ttl":                   255,
		"tunnel.default_persistence":           model.PersistenceTypeSystemd,
		"addressing.default_prefix_len":        30,
		"keepalive.packet_size":                56,
		"monitor.packet_size":                  56,
		"monitor.window_size":                  60,
		"monitor.state_change_samples":         3,
		"monitor.aggregate_interval_seconds":   60,
		"monitor.history_retention_days":       30,
		"diagnostics.manual_ping_count":        100,
		"diagnostics.manual_ping_max_count":    10000,
		"diagnostics.mtu_probe_min":            1200,
		"diagnostics.mtu_probe_max":            1500,
		"metrics.history_points":               300,
		"security.token_ttl_minutes":           720,
		"security.refresh_ttl_days":            30,
		"security.login_rate_limit_per_minute": 5,
		"security.login_lockout_minutes":       15,
		"system.reconcile_interval_seconds":    300,
		"system.audit_retention_days":          90,
	}
	for key, want := range expectInt {
		if got := store.Int(key); got != want {
			t.Errorf("%s default = %d, want %d", key, got, want)
		}
	}

	expectFloat := map[string]float64{
		"keepalive.interval_seconds":       1.0,
		"monitor.interval_seconds":         1.0,
		"monitor.timeout_seconds":          2.0,
		"monitor.degraded_loss_pct":        20.0,
		"monitor.down_loss_pct":            100.0,
		"diagnostics.manual_ping_interval": 0.1,
		"diagnostics.manual_ping_timeout":  1.0,
		"metrics.sample_interval_seconds":  1.0,
		"metrics.disk_warn_pct":            85.0,
		"metrics.disk_critical_pct":        95.0,
	}
	for key, want := range expectFloat {
		if got := store.Float(key); got != want {
			t.Errorf("%s default = %v, want %v", key, got, want)
		}
	}

	expectBool := map[string]bool{
		"tunnel.default_pmtudisc":         false,
		"tunnel.default_csum":             false,
		"tunnel.default_seq":              false,
		"tunnel.auto_mtu_from_underlay":   true,
		"addressing.allow_public_ranges":  false,
		"addressing.check_route_overlap":  true,
		"keepalive.enabled_by_default":    true,
		"monitor.enabled":                 true,
		"diagnostics.allow_tcpdump":       true,
		"metrics.hide_loopback":           true,
		"metrics.hide_pseudo_filesystems": true,
		"display.binary_units":            true,
		"system.auto_reapply_on_drift":    false,
	}
	for key, want := range expectBool {
		if got := store.Bool(key); got != want {
			t.Errorf("%s default = %v, want %v", key, got, want)
		}
	}

	expectString := map[string]string{
		"tunnel.default_tos":      "inherit",
		"tunnel.naming_template":  "gre-{side}-{number}",
		"keepalive.mode":          "monitor_only",
		"display.language":        "en",
		"display.theme":           "system",
		"display.throughput_unit": "bytes",
		"display.volume_unit":     "bytes",
		"display.digits":          "latin",
		"display.calendar":        "gregorian",
	}
	for key, want := range expectString {
		if got := store.String(key); got != want {
			t.Errorf("%s default = %q, want %q", key, got, want)
		}
	}

	// Nullable settings default to null, which is different from zero.
	if got := store.FloatPtr("monitor.degraded_rtt_ms"); got != nil {
		t.Errorf("monitor.degraded_rtt_ms default = %v, want null", *got)
	}
	if got := store.IntPtr("addressing.default_pool_id"); got != nil {
		t.Errorf("addressing.default_pool_id default = %v, want null", *got)
	}

	if got := store.StringMap("tunnel.side_labels"); !reflect.DeepEqual(got, map[string]string{"a": "a", "b": "b"}) {
		t.Errorf("tunnel.side_labels default = %v, want a and b", got)
	}
	if got := store.StringSlice("security.allowed_origins"); len(got) != 0 {
		t.Errorf("security.allowed_origins default = %v, want it empty", got)
	}
}

// TestUpdateSurvivesAReload is the round trip the settings endpoints depend on:
// what PUT /settings writes must be what a freshly started panel reads back.
func TestUpdateSurvivesAReload(t *testing.T) {
	ctx, database, store := newTestStore(t)

	updates := map[string]any{
		"monitor.interval_seconds": 2.5,
		"monitor.window_size":      120,
		"monitor.degraded_rtt_ms":  250.0,
		"display.theme":            "dark",
		"tunnel.naming_template":   "tun{number}",
		"tunnel.side_labels":       map[string]any{"a": "one", "b": "two"},
		"security.allowed_origins": []any{"https://panel.example.org"},
		"tunnel.default_key":       nil,
	}
	changed, err := store.Update(ctx, updates, nil)
	if err != nil {
		t.Fatalf("Update returned an unexpected error: %v", err)
	}
	if len(changed) != len(updates) {
		t.Errorf("Update reported %d changed keys, want %d: %v", len(changed), len(updates), changed)
	}

	reloaded, err := New(ctx, database)
	if err != nil {
		t.Fatalf("reloading the store failed: %v", err)
	}
	if got := reloaded.Float("monitor.interval_seconds"); got != 2.5 {
		t.Errorf("monitor.interval_seconds = %v after reload, want 2.5", got)
	}
	if got := reloaded.Int("monitor.window_size"); got != 120 {
		t.Errorf("monitor.window_size = %d after reload, want 120", got)
	}
	if got := reloaded.FloatPtr("monitor.degraded_rtt_ms"); got == nil || *got != 250.0 {
		t.Errorf("monitor.degraded_rtt_ms = %v after reload, want 250", got)
	}
	if got := reloaded.String("display.theme"); got != "dark" {
		t.Errorf("display.theme = %q after reload, want dark", got)
	}
	if got := reloaded.StringMap("tunnel.side_labels"); !reflect.DeepEqual(got, map[string]string{"a": "one", "b": "two"}) {
		t.Errorf("tunnel.side_labels = %v after reload, want one and two", got)
	}
	if got := reloaded.StringSlice("security.allowed_origins"); !reflect.DeepEqual(got, []string{"https://panel.example.org"}) {
		t.Errorf("security.allowed_origins = %v after reload, want the configured origin", got)
	}
	// A nullable setting explicitly set to null must come back as null, not as
	// its non-null default.
	if got := reloaded.IntPtr("tunnel.default_key"); got != nil {
		t.Errorf("tunnel.default_key = %v after reload, want null", *got)
	}
}

func TestUpdateRejectsInvalidValuesPerKey(t *testing.T) {
	ctx, _, store := newTestStore(t)

	cases := []struct {
		name         string
		updates      map[string]any
		wantKeys     []string
		wantFragment string
	}{
		{"below minimum", map[string]any{"monitor.interval_seconds": 0.01},
			[]string{"monitor.interval_seconds"}, "at least"},
		{"above maximum", map[string]any{"tunnel.default_mtu": 100000},
			[]string{"tunnel.default_mtu"}, "at most"},
		{"not a whole number", map[string]any{"monitor.window_size": 1.5},
			[]string{"monitor.window_size"}, "whole number"},
		{"wrong type", map[string]any{"monitor.enabled": "yes"},
			[]string{"monitor.enabled"}, "true or false"},
		{"unknown enum value", map[string]any{"display.theme": "neon"},
			[]string{"display.theme"}, "must be one of"},
		{"unknown key", map[string]any{"monitor.does_not_exist": 1},
			[]string{"monitor.does_not_exist"}, "unknown setting"},
		{"null on a non-nullable setting", map[string]any{"monitor.enabled": nil},
			[]string{"monitor.enabled"}, "must not be null"},
		{"invalid lookup reference", map[string]any{"tunnel.default_type": 99},
			[]string{"tunnel.default_type"}, "not a valid TunnelType"},
		{"naming template with an unknown placeholder", map[string]any{"tunnel.naming_template": "gre-{region}-{number}"},
			[]string{"tunnel.naming_template"}, "unknown placeholder"},
		{"naming template too long once rendered", map[string]any{"tunnel.naming_template": "extremely-long-{number}"},
			[]string{"tunnel.naming_template"}, "not a valid interface name"},
		{"side labels missing a slot", map[string]any{"tunnel.side_labels": map[string]any{"a": "one"}},
			[]string{"tunnel.side_labels"}, `missing label for slot "b"`},
		{"wildcard origin", map[string]any{"security.allowed_origins": []any{"*"}},
			[]string{"security.allowed_origins"}, "not accepted"},
		{"origin with a path", map[string]any{"security.allowed_origins": []any{"https://example.org/panel"}},
			[]string{"security.allowed_origins"}, "no path"},
		{"tos not a valid form", map[string]any{"tunnel.default_tos": "lowdelay"},
			[]string{"tunnel.default_tos"}, "inherit"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.Update(ctx, tc.updates, nil)
			if err == nil {
				t.Fatalf("Update(%v) succeeded, want a validation error", tc.updates)
			}
			verr, ok := err.(*ValidationError)
			if !ok {
				t.Fatalf("Update returned %T, want *ValidationError", err)
			}
			for _, key := range tc.wantKeys {
				msg, present := verr.Errors[key]
				if !present {
					t.Fatalf("no error reported for %q; got %v", key, verr.Errors)
				}
				if tc.wantFragment != "" && !containsFold(msg, tc.wantFragment) {
					t.Errorf("error for %q = %q, want it to mention %q", key, msg, tc.wantFragment)
				}
			}
		})
	}
}

// TestUpdateIsAtomic checks that one bad key rejects the whole batch, so a
// half-applied configuration can never be observed.
func TestUpdateIsAtomic(t *testing.T) {
	ctx, _, store := newTestStore(t)
	before := store.Int("monitor.window_size")

	_, err := store.Update(ctx, map[string]any{
		"monitor.window_size": 99,
		"display.theme":       "neon", // invalid
	}, nil)
	if err == nil {
		t.Fatal("Update with one invalid key succeeded, want it rejected")
	}
	if got := store.Int("monitor.window_size"); got != before {
		t.Errorf("monitor.window_size = %d after a rejected batch, want it unchanged at %d", got, before)
	}
}

func TestCrossKeyValidation(t *testing.T) {
	ctx, _, store := newTestStore(t)

	// Raising the Degraded threshold above the Down threshold on its own is a
	// contradiction and must be rejected.
	_, err := store.Update(ctx, map[string]any{"monitor.degraded_loss_pct": 100.0, "monitor.down_loss_pct": 50.0}, nil)
	if err == nil {
		t.Fatal("Update with degraded > down succeeded, want it rejected")
	}
	verr, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("Update returned %T, want *ValidationError", err)
	}
	if _, present := verr.Errors["monitor.degraded_loss_pct"]; !present {
		t.Errorf("no error reported for monitor.degraded_loss_pct; got %v", verr.Errors)
	}

	// Changing both sides consistently in one request must be accepted.
	if _, err := store.Update(ctx, map[string]any{
		"monitor.degraded_loss_pct": 10.0,
		"monitor.down_loss_pct":     80.0,
	}, nil); err != nil {
		t.Fatalf("a consistent pair was rejected: %v", err)
	}

	if _, err := store.Update(ctx, map[string]any{"diagnostics.mtu_probe_min": 1600}, nil); err == nil {
		t.Error("an MTU probe lower bound above the upper bound was accepted, want it rejected")
	}
}

func TestReset(t *testing.T) {
	ctx, database, store := newTestStore(t)

	if _, err := store.Update(ctx, map[string]any{
		"display.theme":       "dark",
		"monitor.window_size": 120,
	}, nil); err != nil {
		t.Fatalf("Update returned an unexpected error: %v", err)
	}

	// Resetting one key leaves the other alone.
	changed, err := store.Reset(ctx, []string{"display.theme"})
	if err != nil {
		t.Fatalf("Reset returned an unexpected error: %v", err)
	}
	if !reflect.DeepEqual(changed, []string{"display.theme"}) {
		t.Errorf("Reset reported %v changed, want display.theme only", changed)
	}
	if got := store.String("display.theme"); got != "system" {
		t.Errorf("display.theme = %q after reset, want the default system", got)
	}
	if got := store.Int("monitor.window_size"); got != 120 {
		t.Errorf("monitor.window_size = %d, want the untouched override 120", got)
	}

	// Resetting everything clears the remaining overrides from storage too.
	if _, err := store.Reset(ctx, nil); err != nil {
		t.Fatalf("full Reset returned an unexpected error: %v", err)
	}
	var stored int
	if err := database.Read.QueryRowContext(ctx, `SELECT COUNT(*) FROM AppSetting`).Scan(&stored); err != nil {
		t.Fatalf("counting stored settings failed: %v", err)
	}
	if stored != 0 {
		t.Errorf("AppSetting has %d rows after a full reset, want 0", stored)
	}
	if got := store.Int("monitor.window_size"); got != 60 {
		t.Errorf("monitor.window_size = %d after a full reset, want the default 60", got)
	}

	if _, err := store.Reset(ctx, []string{"not.a.setting"}); err == nil {
		t.Error("resetting an unknown key succeeded, want it rejected")
	}
}

func TestSubscribeReportsChangedKeysOnly(t *testing.T) {
	ctx, _, store := newTestStore(t)

	var notified [][]string
	store.Subscribe(func(changed []string) {
		notified = append(notified, changed)
	})

	if _, err := store.Update(ctx, map[string]any{"monitor.window_size": 90}, nil); err != nil {
		t.Fatalf("Update returned an unexpected error: %v", err)
	}
	// Writing the same value again is not a change, so no listener runs.
	if _, err := store.Update(ctx, map[string]any{"monitor.window_size": 90}, nil); err != nil {
		t.Fatalf("second Update returned an unexpected error: %v", err)
	}

	if len(notified) != 1 {
		t.Fatalf("listener ran %d times, want once: %v", len(notified), notified)
	}
	if !reflect.DeepEqual(notified[0], []string{"monitor.window_size"}) {
		t.Errorf("listener received %v, want [monitor.window_size]", notified[0])
	}
}

func TestSchemaCarriesMetadataAndCurrentValues(t *testing.T) {
	ctx, _, store := newTestStore(t)
	if _, err := store.Update(ctx, map[string]any{"display.theme": "light"}, nil); err != nil {
		t.Fatalf("Update returned an unexpected error: %v", err)
	}

	entries := store.Schema()
	if want := len(specifiedKeys) + len(additionalKeys); len(entries) != want {
		t.Fatalf("schema has %d entries, want %d", len(entries), want)
	}

	found := false
	for _, e := range entries {
		if e.Key != "display.theme" {
			continue
		}
		found = true
		if e.Value != "light" {
			t.Errorf("display.theme schema value = %v, want the current value light", e.Value)
		}
		if e.Default != "system" {
			t.Errorf("display.theme schema default = %v, want system", e.Default)
		}
		if len(e.Constraints.EnumValues) != 3 {
			t.Errorf("display.theme enum values = %v, want three", e.Constraints.EnumValues)
		}
	}
	if !found {
		t.Error("display.theme is missing from the schema")
	}

	// The schema is what the frontend renders from, so it must be encodable.
	if _, err := json.Marshal(entries); err != nil {
		t.Fatalf("the schema cannot be encoded as JSON: %v", err)
	}
}

// TestStoredValueThatNoLongerValidatesFallsBackToTheDefault covers a downgrade
// or a constraint tightened in a later release: the panel must still start.
func TestStoredValueThatNoLongerValidatesFallsBackToTheDefault(t *testing.T) {
	ctx, database, _ := newTestStore(t)

	if _, err := database.Write.ExecContext(ctx,
		`INSERT INTO AppSetting (SettingKey, ValueJson, UpdatedDate) VALUES (?, ?, ?)`,
		"monitor.window_size", "-5", model.NowUTC()); err != nil {
		t.Fatalf("inserting an out-of-range setting failed: %v", err)
	}
	if _, err := database.Write.ExecContext(ctx,
		`INSERT INTO AppSetting (SettingKey, ValueJson, UpdatedDate) VALUES (?, ?, ?)`,
		"a.key.from.the.future", "true", model.NowUTC()); err != nil {
		t.Fatalf("inserting an unknown setting failed: %v", err)
	}

	store, err := New(ctx, database)
	if err != nil {
		t.Fatalf("the store refused to load with an invalid stored value: %v", err)
	}
	if got := store.Int("monitor.window_size"); got != 60 {
		t.Errorf("monitor.window_size = %d, want the default 60 after rejecting the stored value", got)
	}
}

func TestValidateNamingTemplate(t *testing.T) {
	valid := []string{
		"gre-{side}-{number}",
		"tun{number}",
		"gre{number}",
		"{type}-{number}",
		"link_{side}{number}",
		"a.b-{number}",
	}
	for _, tpl := range valid {
		if err := ValidateNamingTemplate(tpl); err != nil {
			t.Errorf("ValidateNamingTemplate(%q) = %v, want nil", tpl, err)
		}
	}

	invalid := []string{
		"",
		"   ",
		"gre-{region}-{number}",
		"gre tunnel {number}",
		"-leading-dash{number}",
		"this-template-is-far-too-long-{number}",
		"gre/{number}",
	}
	for _, tpl := range invalid {
		if err := ValidateNamingTemplate(tpl); err == nil {
			t.Errorf("ValidateNamingTemplate(%q) = nil, want an error", tpl)
		}
	}
}

func TestRenderNamingTemplate(t *testing.T) {
	got := RenderNamingTemplate("gre-{side}-{number}", "a", "7", "gre")
	if want := "gre-a-7"; got != want {
		t.Errorf("RenderNamingTemplate = %q, want %q", got, want)
	}
	// The legacy naming scheme must still be expressible, so tunnels created by
	// the script this panel replaces can be adopted without renaming (§1).
	got = RenderNamingTemplate("gre-{side}-{number}", "ir", "7", "gre")
	if want := "gre-ir-7"; got != want {
		t.Errorf("RenderNamingTemplate = %q, want the legacy form %q", got, want)
	}
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
