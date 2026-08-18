// Package settings is the typed, database-backed runtime settings store (§5.3).
//
// Every setting carries a key, a type, a default, a description, its
// constraints, a category, and a restart-required flag, and the whole schema is
// served from GET /settings/schema so the frontend can render the settings UI
// generically. That is what makes the flexibility requirement work: adding a
// backend setting must never require a frontend change.
package settings

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/drs/gre-panel/internal/model"
)

// Kind is the value type of a setting.
type Kind string

const (
	KindBool   Kind = "bool"
	KindInt    Kind = "int"
	KindFloat  Kind = "float"
	KindString Kind = "string"
	KindEnum   Kind = "enum"
	KindJSON   Kind = "json"
	// KindLookup is an integer referencing a row of a lookup table (§6). The
	// referenced table is named by Definition.LookupTable so the frontend can
	// render a select box without hardcoding the options.
	KindLookup Kind = "lookup"
)

// Categories group settings in the UI.
const (
	CategoryTunnel      = "tunnel"
	CategoryAddressing  = "addressing"
	CategoryKeepalive   = "keepalive"
	CategoryMonitor     = "monitor"
	CategoryDiagnostics = "diagnostics"
	CategoryMetrics     = "metrics"
	CategoryRoutes      = "routes"
	CategoryDisplay     = "display"
	CategorySecurity    = "security"
	CategorySystem      = "system"
)

// Constraints is the machine-readable validation contract for one setting.
// Fields that do not apply are omitted rather than sent as zero values, so the
// frontend can tell "no minimum" from "minimum zero".
type Constraints struct {
	Min        *float64 `json:"min,omitempty"`
	Max        *float64 `json:"max,omitempty"`
	EnumValues []string `json:"enum_values,omitempty"`
	// LookupTable names the lookup table a KindLookup value must exist in.
	LookupTable string `json:"lookup_table,omitempty"`
	// Options are the selectable values of that lookup table, filled in when the
	// schema is served. Naming the table alone is not enough: the frontend
	// renders settings generically from this schema, so without the values it
	// has nothing to put in the select box and the operator sees an empty
	// control. Sending them keeps the promise that a new lookup value needs no
	// frontend change.
	Options []Option `json:"options,omitempty"`
	// JsonShape is "object" or "array" for KindJSON settings.
	JsonShape string `json:"json_shape,omitempty"`
	// Pattern documents an additional format rule enforced by the validator.
	Pattern string `json:"pattern,omitempty"`
	// Nullable reports whether null is an accepted value.
	Nullable bool `json:"nullable"`
}

// Option is one selectable value of a lookup-typed setting: the integer that is
// stored and the title an operator reads.
type Option struct {
	Value int64  `json:"value"`
	Label string `json:"label"`
}

// Definition is the complete metadata for one setting.
type Definition struct {
	Key             string      `json:"key"`
	Type            Kind        `json:"type"`
	Category        string      `json:"category"`
	Description     string      `json:"description"`
	Default         any         `json:"default"`
	Constraints     Constraints `json:"constraints"`
	RestartRequired bool        `json:"restart_required"`
	// Unit labels the value for display, e.g. "seconds" or "bytes".
	Unit string `json:"unit,omitempty"`

	// validate is an extra per-setting rule applied after the generic type and
	// constraint checks. It is not serialised; the human-readable form of the
	// rule lives in Description and Constraints.Pattern.
	validate func(v any) error
}

func f64(v float64) *float64 { return &v }

var (
	languageRe  = regexp.MustCompile(`^[a-z]{2}(-[A-Za-z0-9]{2,8})?$`)
	tosRe       = regexp.MustCompile(`^(inherit|0x[0-9a-fA-F]{1,2}|[0-9]{1,3})$`)
	sideLabelRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,7}$`)
	// Interface names are capped at 15 characters by Linux (IFNAMSIZ is 16
	// including the NUL); §7.1 spells out the full rule.
	ifNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	// A naming template may contain name characters and the three placeholders.
	templatePlaceholderRe = regexp.MustCompile(`\{[a-z]+\}`)
)

// definitions declares every setting of §5.3, in the order the specification
// lists them. This slice is the single source of truth for the store, the
// schema endpoint, and validation.
var definitions = []Definition{
	// ---------------------------------------------------------------- tunnel
	{
		Key: "tunnel.default_type", Type: KindLookup, Category: CategoryTunnel,
		Description: "Tunnel technology preselected when creating a tunnel.",
		Default:     model.TunnelTypeGRE,
		Constraints: Constraints{LookupTable: "TunnelType"},
	},
	{
		Key: "tunnel.default_key", Type: KindInt, Category: CategoryTunnel,
		Description: "Default GRE key. Both ends of a tunnel must use the same key. " +
			"Null creates tunnels with no key. Change this from the shipped default: " +
			"the script this panel replaces used one key for every one of its users.",
		Default:     int64(2749365187),
		Constraints: Constraints{Min: f64(0), Max: f64(4294967295), Nullable: true},
	},
	{
		Key: "tunnel.default_mtu", Type: KindInt, Category: CategoryTunnel, Unit: "bytes",
		Description: "Default tunnel MTU. 1472 is correct for IPv4 GRE with a key over a " +
			"1500-byte underlay (20 outer IP + 4 GRE + 4 key = 28 bytes of overhead).",
		Default:     int64(1472),
		Constraints: Constraints{Min: f64(576), Max: f64(9216)},
	},
	{
		Key: "tunnel.default_ttl", Type: KindInt, Category: CategoryTunnel,
		Description: "Default outer TTL. 0 means inherit from the inner packet.",
		Default:     int64(255),
		Constraints: Constraints{Min: f64(0), Max: f64(255)},
	},
	{
		Key: "tunnel.default_tos", Type: KindString, Category: CategoryTunnel,
		Description: `Default outer type of service: "inherit", or a value such as 0x10 or 16.`,
		Default:     "inherit",
		Constraints: Constraints{Pattern: `^(inherit|0x[0-9a-fA-F]{1,2}|[0-9]{1,3})$`},
		validate: func(v any) error {
			s, _ := v.(string)
			if !tosRe.MatchString(s) {
				return fmt.Errorf(`must be "inherit" or a value such as 0x10 or 16`)
			}
			return nil
		},
	},
	{
		Key: "tunnel.default_pmtudisc", Type: KindBool, Category: CategoryTunnel,
		Description: "Enable path MTU discovery on new tunnels by default.",
		Default:     false,
	},
	{
		Key: "tunnel.default_csum", Type: KindBool, Category: CategoryTunnel,
		Description: "Enable GRE checksums on new tunnels by default. Adds 4 bytes of overhead " +
			"and must match on both ends.",
		Default: false,
	},
	{
		Key: "tunnel.default_seq", Type: KindBool, Category: CategoryTunnel,
		Description: "Enable GRE sequence numbers on new tunnels by default. Adds 4 bytes of " +
			"overhead and must match on both ends.",
		Default: false,
	},
	{
		Key: "tunnel.naming_template", Type: KindString, Category: CategoryTunnel,
		Description: "Template for generated interface names. Supports {side}, {number}, {type} " +
			"and free text. The rendered name must satisfy the Linux interface name rules: " +
			"at most 15 characters from A-Z a-z 0-9 . _ - starting with a letter or digit.",
		Default:     "gre-{side}-{number}",
		Constraints: Constraints{Pattern: `rendered name must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`},
		validate: func(v any) error {
			s, _ := v.(string)
			return ValidateNamingTemplate(s)
		},
	},
	{
		Key: "tunnel.side_labels", Type: KindJSON, Category: CategoryTunnel,
		Description: `Labels substituted for {side} in the naming template. A and B are simply ` +
			`the two ends of one tunnel; neither has a special role.`,
		Default:     map[string]any{"a": "a", "b": "b"},
		Constraints: Constraints{JsonShape: "object", Pattern: `keys "a" and "b", each 1-8 name characters`},
		validate:    validateSideLabels,
	},
	{
		Key: "tunnel.default_persistence", Type: KindLookup, Category: CategoryTunnel,
		Description: "How new tunnels survive a reboot: a systemd unit, a systemd-networkd file, " +
			"or Runtime, which configures the kernel only and does not survive a reboot.",
		Default:     model.PersistenceTypeSystemd,
		Constraints: Constraints{LookupTable: "PersistenceType"},
	},
	{
		Key: "tunnel.auto_mtu_from_underlay", Type: KindBool, Category: CategoryTunnel,
		Description: "Compute the suggested tunnel MTU from the underlay interface MTU minus the " +
			"encapsulation overhead. The suggestion is never applied silently over an explicit choice.",
		Default: true,
	},

	// ------------------------------------------------------------ addressing
	{
		Key: "addressing.default_pool_id", Type: KindInt, Category: CategoryAddressing,
		Description: "Address pool preselected when creating a tunnel. Null selects the first " +
			"enabled pool.",
		Default:     nil,
		Constraints: Constraints{Min: f64(1), Nullable: true},
	},
	{
		Key: "addressing.default_prefix_len", Type: KindInt, Category: CategoryAddressing,
		Description: "Prefix length of the point-to-point subnet allocated per tunnel. For IPv4 " +
			"use 30, or 31 for the two-address form of RFC 3021. IPv6 tunnels may use up to 127.",
		Default:     int64(30),
		Constraints: Constraints{Min: f64(30), Max: f64(127)},
	},
	{
		Key: "addressing.allow_public_ranges", Type: KindBool, Category: CategoryAddressing,
		Description: "Permit tunnel addresses from globally routable ranges. Doing so squats on " +
			"address space belonging to someone else and blackholes those destinations from this " +
			"server; a warning is returned either way.",
		Default: false,
	},
	{
		Key: "addressing.check_route_overlap", Type: KindBool, Category: CategoryAddressing,
		Description: "Reject a tunnel subnet that overlaps an existing route unless the request " +
			"sets force.",
		Default: true,
	},

	// ------------------------------------------------------------- keepalive
	{
		Key: "keepalive.enabled_by_default", Type: KindBool, Category: CategoryKeepalive,
		Description: "Enable keepalive on newly created tunnels.",
		Default:     true,
	},
	{
		Key: "keepalive.interval_seconds", Type: KindFloat, Category: CategoryKeepalive, Unit: "seconds",
		Description: "Seconds between keepalive packets.",
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(3600)},
	},
	{
		Key: "keepalive.packet_size", Type: KindInt, Category: CategoryKeepalive, Unit: "bytes",
		Description: "ICMP payload size of keepalive packets.",
		Default:     int64(56),
		Constraints: Constraints{Min: f64(0), Max: f64(65507)},
	},
	{
		Key: "keepalive.mode", Type: KindEnum, Category: CategoryKeepalive,
		Description: "monitor_only relies on the panel's own prober, which already sends " +
			"continuous ICMP from the tunnel source address and therefore is a keepalive. " +
			"systemd_unit writes a separate ping unit so keepalive survives panel downtime, at the " +
			"cost of one extra process per tunnel.",
		Default:     "monitor_only",
		Constraints: Constraints{EnumValues: []string{"systemd_unit", "monitor_only"}},
	},

	// --------------------------------------------------------------- monitor
	{
		Key: "monitor.enabled", Type: KindBool, Category: CategoryMonitor,
		Description: "Run the continuous liveness prober. Individual tunnels may override this.",
		Default:     true,
	},
	{
		Key: "monitor.interval_seconds", Type: KindFloat, Category: CategoryMonitor, Unit: "seconds",
		Description: "Seconds between probe packets.",
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(3600)},
	},
	{
		Key: "monitor.timeout_seconds", Type: KindFloat, Category: CategoryMonitor, Unit: "seconds",
		Description: "How long a probe may go unanswered before it counts as lost. A reply that " +
			"arrives later still overrides the loss verdict for that sequence.",
		Default:     2.0,
		Constraints: Constraints{Min: f64(0.1), Max: f64(3600)},
	},
	{
		Key: "monitor.packet_size", Type: KindInt, Category: CategoryMonitor, Unit: "bytes",
		Description: "ICMP payload size of probe packets.",
		Default:     int64(56),
		Constraints: Constraints{Min: f64(16), Max: f64(65507)},
	},
	{
		Key: "monitor.window_size", Type: KindInt, Category: CategoryMonitor, Unit: "samples",
		Description: "Number of recent probes the rolling loss and latency figures cover.",
		Default:     int64(60),
		Constraints: Constraints{Min: f64(1), Max: f64(10000)},
	},
	{
		Key: "monitor.degraded_loss_pct", Type: KindFloat, Category: CategoryMonitor, Unit: "percent",
		Description: "Loss over the rolling window at or above which a tunnel is Degraded.",
		Default:     20.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},
	{
		Key: "monitor.down_loss_pct", Type: KindFloat, Category: CategoryMonitor, Unit: "percent",
		Description: "Loss over the rolling window at or above which a tunnel is Down. Must be at " +
			"least the Degraded threshold.",
		Default:     100.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},
	{
		Key: "monitor.degraded_rtt_ms", Type: KindFloat, Category: CategoryMonitor, Unit: "milliseconds",
		Description: "Average round-trip time at or above which a tunnel is Degraded even with no " +
			"loss. Null disables the latency criterion.",
		Default:     nil,
		Constraints: Constraints{Min: f64(0), Max: f64(600000), Nullable: true},
	},
	{
		Key: "monitor.state_change_samples", Type: KindInt, Category: CategoryMonitor, Unit: "samples",
		Description: "Consecutive agreeing samples required before the state changes. This " +
			"hysteresis is what stops the display flapping on a single lost packet.",
		Default:     int64(3),
		Constraints: Constraints{Min: f64(1), Max: f64(100)},
	},
	{
		Key: "monitor.aggregate_interval_seconds", Type: KindInt, Category: CategoryMonitor, Unit: "seconds",
		Description: "How much probe history one stored MonitorSample row covers.",
		Default:     int64(60),
		Constraints: Constraints{Min: f64(1), Max: f64(86400)},
	},
	{
		Key: "monitor.history_retention_days", Type: KindInt, Category: CategoryMonitor, Unit: "days",
		Description: "How long aggregated monitoring history is kept before pruning.",
		Default:     int64(30),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},

	// ----------------------------------------------------------- diagnostics
	{
		Key: "diagnostics.manual_ping_count", Type: KindInt, Category: CategoryDiagnostics, Unit: "packets",
		Description: "Default packet count for the on-demand high-precision ping.",
		Default:     int64(100),
		Constraints: Constraints{Min: f64(1), Max: f64(1000000)},
	},
	{
		Key: "diagnostics.manual_ping_interval", Type: KindFloat, Category: CategoryDiagnostics, Unit: "seconds",
		Description: "Default interval between packets for the on-demand ping.",
		Default:     0.1,
		Constraints: Constraints{Min: f64(0.001), Max: f64(60)},
	},
	{
		Key: "diagnostics.manual_ping_timeout", Type: KindFloat, Category: CategoryDiagnostics, Unit: "seconds",
		Description: "Default per-packet timeout for the on-demand ping.",
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.01), Max: f64(600)},
	},
	{
		Key: "diagnostics.manual_ping_max_count", Type: KindInt, Category: CategoryDiagnostics, Unit: "packets",
		Description: "Hard upper bound on the packet count a single on-demand ping may request.",
		Default:     int64(10000),
		Constraints: Constraints{Min: f64(1), Max: f64(10000000)},
	},
	{
		Key: "diagnostics.mtu_probe_min", Type: KindInt, Category: CategoryDiagnostics, Unit: "bytes",
		Description: "Lower bound of the path MTU binary search.",
		Default:     int64(1200),
		Constraints: Constraints{Min: f64(68), Max: f64(65535)},
	},
	{
		Key: "diagnostics.mtu_probe_max", Type: KindInt, Category: CategoryDiagnostics, Unit: "bytes",
		Description: "Upper bound of the path MTU binary search. Must be at least the lower bound.",
		Default:     int64(1500),
		Constraints: Constraints{Min: f64(68), Max: f64(65535)},
	},
	{
		Key: "diagnostics.allow_tcpdump", Type: KindBool, Category: CategoryDiagnostics,
		Description: "Allow automated analysis to capture briefly with tcpdump to prove whether " +
			"GRE packets are actually leaving or arriving.",
		Default: true,
	},

	// --------------------------------------------------------------- metrics
	{
		Key: "metrics.sample_interval_seconds", Type: KindFloat, Category: CategoryMetrics, Unit: "seconds",
		Description: "How often system and interface counters are sampled.",
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(600)},
	},
	{
		Key: "metrics.history_points", Type: KindInt, Category: CategoryMetrics, Unit: "samples",
		Description: "Number of samples kept in memory for the dashboard sparklines.",
		Default:     int64(300),
		Constraints: Constraints{Min: f64(10), Max: f64(100000)},
	},
	{
		Key: "metrics.hide_loopback", Type: KindBool, Category: CategoryMetrics,
		Description: "Hide the loopback interface in the traffic view by default.",
		Default:     true,
	},
	{
		Key: "metrics.hide_pseudo_filesystems", Type: KindBool, Category: CategoryMetrics,
		Description: "Hide tmpfs, devtmpfs, proc, sysfs, cgroup, overlay and squashfs mounts in " +
			"the disk view by default. The full list stays retrievable.",
		Default: true,
	},
	{
		Key: "metrics.disk_warn_pct", Type: KindFloat, Category: CategoryMetrics, Unit: "percent",
		Description: "Disk usage at or above which a mount is shown as a warning.",
		Default:     85.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},
	{
		Key: "metrics.disk_critical_pct", Type: KindFloat, Category: CategoryMetrics, Unit: "percent",
		Description: "Disk usage at or above which a mount is shown as critical. Must be at least " +
			"the warning threshold.",
		Default:     95.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},

	// ---------------------------------------------------------------- routes
	{
		Key: "routes.default_nat_mode", Type: KindLookup, Category: CategoryRoutes,
		Description: "How the source address of relayed traffic is treated on new forwarding rules. " +
			"Masquerade always works and makes the destination see this server; None preserves the " +
			"client address but needs the destination's replies to come back through here.",
		Default:     model.NatModeMasquerade,
		Constraints: Constraints{LookupTable: "NatMode"},
	},
	{
		Key: "routes.default_protocol", Type: KindLookup, Category: CategoryRoutes,
		Description: "Protocol preselected when creating a forwarding rule.",
		Default:     model.RouteProtocolTCP,
		Constraints: Constraints{LookupTable: "RouteProtocol"},
	},
	{
		Key: "routes.default_clamp_mss", Type: KindBool, Category: CategoryRoutes,
		Description: "Clamp the TCP maximum segment size on new rules whose destination is reached " +
			"through a tunnel. Without it those connections establish normally and then stall on the " +
			"first large transfer, which is the most common way a working tunnel looks broken.",
		Default: true,
	},
	{
		Key: "routes.counter_interval_seconds", Type: KindFloat, Category: CategoryRoutes, Unit: "seconds",
		Description: "How often the per-rule byte and packet counters are sampled.",
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(600)},
	},
	{
		Key: "routes.conntrack_interval_seconds", Type: KindFloat, Category: CategoryRoutes, Unit: "seconds",
		Description: "How often the connection table is read for per-rule connection counts. It is " +
			"sampled less often than the byte counters because reading it is expensive on a busy host.",
		Default:     5.0,
		Constraints: Constraints{Min: f64(0.5), Max: f64(3600)},
	},
	{
		Key: "routes.aggregate_interval_seconds", Type: KindInt, Category: CategoryRoutes, Unit: "seconds",
		Description: "How much traffic history one stored per-rule sample row covers.",
		Default:     int64(60),
		Constraints: Constraints{Min: f64(1), Max: f64(86400)},
	},
	{
		Key: "routes.history_retention_days", Type: KindInt, Category: CategoryRoutes, Unit: "days",
		Description: "How long aggregated per-rule traffic history is kept before pruning.",
		Default:     int64(30),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},
	{
		Key: "routes.auto_enable_ip_forward", Type: KindBool, Category: CategoryRoutes,
		Description: "Turn on IP forwarding when the first forwarding rule is applied, and record that " +
			"the panel did. Turning it off again is never automatic: other software on this server may " +
			"have come to depend on it.",
		Default: true,
	},
	{
		Key: "routes.warn_conntrack_usage_percent", Type: KindFloat, Category: CategoryRoutes, Unit: "percent",
		Description: "Connection tracking table usage at or above which the panel warns. A relay that " +
			"fills the table starts dropping new connections with nothing in the logs to explain it.",
		Default:     80.0,
		Constraints: Constraints{Min: f64(1), Max: f64(100)},
	},

	// --------------------------------------------------------------- display
	{
		Key: "display.language", Type: KindString, Category: CategoryDisplay,
		Description: "Interface language as a BCP 47 tag, for example en or fa.",
		Default:     "en",
		Constraints: Constraints{Pattern: `^[a-z]{2}(-[A-Za-z0-9]{2,8})?$`},
		validate: func(v any) error {
			s, _ := v.(string)
			if !languageRe.MatchString(s) {
				return fmt.Errorf("must be a language tag such as en or fa")
			}
			return nil
		},
	},
	{
		Key: "display.theme", Type: KindEnum, Category: CategoryDisplay,
		Description: "Colour theme; system follows the operating system preference.",
		Default:     "system",
		Constraints: Constraints{EnumValues: []string{"system", "light", "dark"}},
	},
	{
		Key: "display.throughput_unit", Type: KindEnum, Category: CategoryDisplay,
		Description: "Show throughput in bytes per second or bits per second. The API always " +
			"returns raw bytes; this only affects presentation.",
		Default:     "bytes",
		Constraints: Constraints{EnumValues: []string{"bytes", "bits"}},
	},
	{
		Key: "display.volume_unit", Type: KindEnum, Category: CategoryDisplay,
		Description: "Show cumulative volume in bytes or bits.",
		Default:     "bytes",
		Constraints: Constraints{EnumValues: []string{"bytes", "bits"}},
	},
	{
		Key: "display.binary_units", Type: KindBool, Category: CategoryDisplay,
		Description: "Use binary multiples (MiB, 1024-based) rather than decimal ones (MB, 1000-based).",
		Default:     true,
	},
	{
		Key: "display.digits", Type: KindEnum, Category: CategoryDisplay,
		Description: "Numeral system used for displayed numbers.",
		Default:     "latin",
		Constraints: Constraints{EnumValues: []string{"latin", "persian"}},
	},
	{
		Key: "display.calendar", Type: KindEnum, Category: CategoryDisplay,
		Description: "Calendar used for displayed dates. Stored timestamps are always UTC ISO-8601.",
		Default:     "gregorian",
		Constraints: Constraints{EnumValues: []string{"gregorian", "jalali"}},
	},

	// -------------------------------------------------------------- security
	{
		Key: "security.token_ttl_minutes", Type: KindInt, Category: CategorySecurity, Unit: "minutes",
		Description: "Lifetime of an access token. Applies to tokens issued from now on.",
		Default:     int64(720),
		Constraints: Constraints{Min: f64(1), Max: f64(43200)},
	},
	{
		Key: "security.refresh_ttl_days", Type: KindInt, Category: CategorySecurity, Unit: "days",
		Description: "Lifetime of a refresh token. Changing a password invalidates every existing " +
			"session regardless of this value.",
		Default:     int64(30),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},
	{
		Key: "security.login_rate_limit_per_minute", Type: KindInt, Category: CategorySecurity, Unit: "attempts",
		Description: "Login attempts allowed per minute per account and per client address. The " +
			"same number of consecutive failures locks the account.",
		Default:     int64(5),
		Constraints: Constraints{Min: f64(1), Max: f64(1000)},
	},
	{
		Key: "security.login_lockout_minutes", Type: KindInt, Category: CategorySecurity, Unit: "minutes",
		Description: "How long an account stays locked after too many consecutive failed logins.",
		Default:     int64(15),
		Constraints: Constraints{Min: f64(1), Max: f64(43200)},
	},
	{
		Key: "security.allowed_origins", Type: KindJSON, Category: CategorySecurity,
		Description: "Cross-origin request origins allowed to call the API, for example " +
			`"https://panel.example.org". Empty means same-origin only, which is the right ` +
			"setting unless the frontend is served from somewhere else.",
		Default:     []any{},
		Constraints: Constraints{JsonShape: "array", Pattern: "scheme://host[:port], no path, no wildcard"},
		validate:    validateAllowedOrigins,
	},

	// ---------------------------------------------------------------- system
	{
		Key: "system.reconcile_interval_seconds", Type: KindInt, Category: CategorySystem, Unit: "seconds",
		Description: "How often the panel compares its database against live kernel state.",
		Default:     int64(300),
		Constraints: Constraints{Min: f64(10), Max: f64(86400)},
	},
	{
		Key: "system.audit_retention_days", Type: KindInt, Category: CategorySystem, Unit: "days",
		Description: "How long audit log entries are kept before pruning.",
		Default:     int64(90),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},
	{
		Key: "system.auto_reapply_on_drift", Type: KindBool, Category: CategorySystem,
		Description: "Automatically reapply the stored configuration when reconcile finds a tunnel " +
			"has drifted. Off by default: an operator who changed something outside the panel " +
			"usually meant to.",
		Default: false,
	},
	{
		Key: "system.ignored_interfaces", Type: KindJSON, Category: CategorySystem,
		Description: "Tunnel interfaces reconcile should stop reporting as unmanaged. Use this for " +
			"tunnels another tool owns on this host: they are listed but never adopted, changed or " +
			"removed. The panel never touches an interface it does not manage either way.",
		Default:     []any{},
		Constraints: Constraints{JsonShape: "array", Pattern: "interface names"},
		validate:    validateInterfaceNameList,
	},
}

func validateInterfaceNameList(v any) error {
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("must be a list of interface names")
	}
	for i, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("entry %d must be a string", i)
		}
		if !ifNameRe.MatchString(s) {
			return fmt.Errorf("entry %d (%q) is not a valid interface name", i, s)
		}
	}
	return nil
}

// Resolving the options into the declarations themselves, rather than at each
// call site, is deliberate: the store serves the schema straight from this
// slice, and a resolution step somewhere else is one any future reader can
// bypass without noticing -- which is exactly how the select box came to be
// empty in the first place.
func init() {
	for i := range definitions {
		definitions[i].Constraints.Options = lookupOptions(definitions[i].Constraints.LookupTable)
	}
}

// Definitions returns every declared setting in specification order, with the
// options of each lookup-typed setting resolved from the lookup tables.
func Definitions() []Definition {
	out := make([]Definition, len(definitions))
	copy(out, definitions)
	return out
}

// lookupOptions resolves a lookup table name to its selectable values. The
// values come from the same declaration internal/db seeds from, so a value
// added there appears in the settings UI with no further change anywhere.
func lookupOptions(table string) []Option {
	if table == "" {
		return nil
	}
	t, ok := model.LookupTableByName(table)
	if !ok {
		return nil
	}
	out := make([]Option, 0, len(t.Values))
	for _, v := range t.Values {
		out = append(out, Option{Value: v.ID, Label: v.Title})
	}
	return out
}

// Lookup returns the definition for a key.
func Lookup(key string) (Definition, bool) {
	for _, d := range definitions {
		if d.Key == key {
			return d, true
		}
	}
	return Definition{}, false
}

// Keys returns every declared setting key, in specification order.
func Keys() []string {
	out := make([]string, 0, len(definitions))
	for _, d := range definitions {
		out = append(out, d.Key)
	}
	return out
}

// ValidateNamingTemplate applies the rules of §7.1 to a naming template by
// rendering it with the shortest realistic substitutions and checking the
// result. The real name is validated again at creation time against the actual
// side label and number, because a long label can push a valid template over
// the 15-character limit.
func ValidateNamingTemplate(t string) error {
	if strings.TrimSpace(t) == "" {
		return fmt.Errorf("must not be empty")
	}
	for _, ph := range templatePlaceholderRe.FindAllString(t, -1) {
		switch ph {
		case "{side}", "{number}", "{type}":
		default:
			return fmt.Errorf("unknown placeholder %s: use {side}, {number} or {type}", ph)
		}
	}
	rendered := RenderNamingTemplate(t, "a", "1", "gre")
	if !ifNameRe.MatchString(rendered) {
		return fmt.Errorf("renders to %q, which is not a valid interface name: at most 15 "+
			"characters from A-Z a-z 0-9 . _ - starting with a letter or digit", rendered)
	}
	return nil
}

// RenderNamingTemplate substitutes the three supported placeholders.
func RenderNamingTemplate(t, side, number, typ string) string {
	r := strings.NewReplacer("{side}", side, "{number}", number, "{type}", typ)
	return r.Replace(t)
}

func validateSideLabels(v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf(`must be an object such as {"a":"a","b":"b"}`)
	}
	for _, slot := range []string{"a", "b"} {
		raw, present := m[slot]
		if !present {
			return fmt.Errorf("missing label for slot %q", slot)
		}
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("label for slot %q must be a string", slot)
		}
		if !sideLabelRe.MatchString(s) {
			return fmt.Errorf("label %q for slot %q must be 1-8 characters from A-Z a-z 0-9 . _ - "+
				"and start with a letter or digit, so the rendered interface name stays valid", s, slot)
		}
	}
	for k := range m {
		if k != "a" && k != "b" {
			return fmt.Errorf("unknown slot %q: a tunnel has exactly two ends, a and b", k)
		}
	}
	return nil
}

func validateAllowedOrigins(v any) error {
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("must be a list of origins")
	}
	for i, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("entry %d must be a string", i)
		}
		if s == "*" {
			return fmt.Errorf(`entry %d: "*" is not accepted, because the panel sends credentials `+
				"with cross-origin requests; list the exact origins instead", i)
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("entry %d (%q) must be an origin such as https://panel.example.org", i, s)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("entry %d (%q): scheme must be http or https", i, s)
		}
		if u.Path != "" && u.Path != "/" {
			return fmt.Errorf("entry %d (%q): an origin has no path", i, s)
		}
		if s != strings.TrimSuffix(s, "/") {
			return fmt.Errorf("entry %d (%q): drop the trailing slash", i, s)
		}
	}
	return nil
}

// Coerce converts a value decoded from JSON into the canonical Go type for the
// definition and validates it against the constraints. It returns a message
// suitable for showing next to the field.
func (d Definition) Coerce(raw any) (any, error) {
	if raw == nil {
		if !d.Constraints.Nullable {
			return nil, fmt.Errorf("must not be null")
		}
		return nil, nil
	}

	switch d.Type {
	case KindBool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("must be true or false")
		}
		return b, nil

	case KindInt, KindLookup:
		n, err := toFloat(raw)
		if err != nil {
			return nil, fmt.Errorf("must be a whole number")
		}
		if n != math.Trunc(n) {
			return nil, fmt.Errorf("must be a whole number")
		}
		i := int64(n)
		if err := d.checkRange(float64(i)); err != nil {
			return nil, err
		}
		if d.Type == KindLookup {
			if !model.HasLookupValue(d.Constraints.LookupTable, i) {
				return nil, fmt.Errorf("%d is not a valid %s", i, d.Constraints.LookupTable)
			}
		}
		return i, d.runExtra(i)

	case KindFloat:
		n, err := toFloat(raw)
		if err != nil {
			return nil, fmt.Errorf("must be a number")
		}
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, fmt.Errorf("must be a finite number")
		}
		if err := d.checkRange(n); err != nil {
			return nil, err
		}
		return n, d.runExtra(n)

	case KindString:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("must be a string")
		}
		return s, d.runExtra(s)

	case KindEnum:
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("must be one of %s", strings.Join(d.Constraints.EnumValues, ", "))
		}
		for _, allowed := range d.Constraints.EnumValues {
			if s == allowed {
				return s, d.runExtra(s)
			}
		}
		return nil, fmt.Errorf("must be one of %s", strings.Join(d.Constraints.EnumValues, ", "))

	case KindJSON:
		switch d.Constraints.JsonShape {
		case "object":
			if _, ok := raw.(map[string]any); !ok {
				return nil, fmt.Errorf("must be an object")
			}
		case "array":
			if _, ok := raw.([]any); !ok {
				return nil, fmt.Errorf("must be a list")
			}
		}
		return raw, d.runExtra(raw)
	}
	return nil, fmt.Errorf("setting has an unknown type %q", d.Type)
}

func (d Definition) runExtra(v any) error {
	if d.validate == nil {
		return nil
	}
	return d.validate(v)
}

func (d Definition) checkRange(n float64) error {
	if d.Constraints.Min != nil && n < *d.Constraints.Min {
		return fmt.Errorf("must be at least %s", formatNumber(*d.Constraints.Min))
	}
	if d.Constraints.Max != nil && n > *d.Constraints.Max {
		return fmt.Errorf("must be at most %s", formatNumber(*d.Constraints.Max))
	}
	return nil
}

func formatNumber(f float64) string {
	if f == math.Trunc(f) && math.Abs(f) < 1e15 {
		return fmt.Sprintf("%d", int64(f))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", f), "0"), ".")
}

// toFloat accepts the numeric shapes that survive a JSON round trip as well as
// the native Go types the defaults are declared with.
func toFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case float32:
		return float64(n), nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case json.Number:
		f, err := n.Float64()
		return f, err
	}
	return 0, fmt.Errorf("not a number")
}
