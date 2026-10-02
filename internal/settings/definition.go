// Package settings is the typed, database-backed runtime settings store (§5.3).
//
// Every setting carries a key, a type, a default, a description, its
// constraints, a category, and a restart-required flag, and the whole schema is
// served from GET /settings/schema so the frontend can render the settings UI
// generically. That is what makes the flexibility requirement work: adding a
// backend setting must never require a frontend change.
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	"github.com/drs/gre-panel/internal/i18n"
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
//
// Label, Description, Unit and the option labels are kept in English and
// marked for translation; they are said in the operator's language where the
// schema is served.
type Definition struct {
	Key string `json:"key"`
	// Label is the short name an operator reads for the setting, where the key
	// is the name the API knows it by. Description says what it does.
	Label           string      `json:"label"`
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
	// rule lives in Description and Constraints.Pattern. Its message is said in
	// the language ctx carries.
	validate func(ctx context.Context, v any) error
}

// What a setting's number counts.
var (
	unitBytes        = i18n.N("bytes")
	unitSeconds      = i18n.N("seconds")
	unitMilliseconds = i18n.N("milliseconds")
	unitMinutes      = i18n.N("minutes")
	unitHours        = i18n.N("hours")
	unitDays         = i18n.N("days")
	unitPercent      = i18n.N("percent")
	unitSamples      = i18n.N("samples")
	unitPackets      = i18n.N("packets")
	unitProbes       = i18n.N("probes")
	unitAttempts     = i18n.N("attempts")
)

// The titles of the lookup values the settings page offers that read
// differently in another language. The rest -- GRE, Systemd, TCP, Masquerade --
// are names that stay as they are in every language. The titles themselves are
// declared in internal/model; these marks are what let them be said where the
// schema is served.
var _ = []string{
	i18n.N("Runtime"),
	i18n.N("Both"),
	i18n.N("None"),
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
		Label:       i18n.N("Default tunnel type"),
		Description: i18n.N("Tunnel technology preselected when creating a tunnel."),
		Default:     model.TunnelTypeGRE,
		Constraints: Constraints{LookupTable: "TunnelType"},
	},
	{
		Key: "tunnel.default_key", Type: KindInt, Category: CategoryTunnel,
		Label: i18n.N("Default GRE key"),
		Description: i18n.N("Default GRE key. Both ends of a tunnel must use the same key. " +
			"Null creates tunnels with no key. Change this from the shipped default: " +
			"the script this panel replaces used one key for every one of its users."),
		Default:     int64(2749365187),
		Constraints: Constraints{Min: f64(0), Max: f64(4294967295), Nullable: true},
	},
	{
		Key: "tunnel.default_mtu", Type: KindInt, Category: CategoryTunnel, Unit: unitBytes,
		Label: i18n.N("Default tunnel MTU"),
		Description: i18n.N("Default tunnel MTU. 1472 is correct for IPv4 GRE with a key over a " +
			"1500-byte underlay (20 outer IP + 4 GRE + 4 key = 28 bytes of overhead)."),
		Default:     int64(1472),
		Constraints: Constraints{Min: f64(576), Max: f64(9216)},
	},
	{
		Key: "tunnel.default_ttl", Type: KindInt, Category: CategoryTunnel,
		Label:       i18n.N("Default outer TTL"),
		Description: i18n.N("Default outer TTL. 0 means inherit from the inner packet."),
		Default:     int64(255),
		Constraints: Constraints{Min: f64(0), Max: f64(255)},
	},
	{
		Key: "tunnel.default_tos", Type: KindString, Category: CategoryTunnel,
		Label:       i18n.N("Default outer type of service"),
		Description: i18n.N(`Default outer type of service: "inherit", or a value such as 0x10 or 16.`),
		Default:     "inherit",
		Constraints: Constraints{Pattern: `^(inherit|0x[0-9a-fA-F]{1,2}|[0-9]{1,3})$`},
		validate: func(ctx context.Context, v any) error {
			s, _ := v.(string)
			if !tosRe.MatchString(s) {
				return i18n.Errorf(ctx, `must be "inherit" or a value such as 0x10 or 16`)
			}
			return nil
		},
	},
	{
		Key: "tunnel.default_pmtudisc", Type: KindBool, Category: CategoryTunnel,
		Label:       i18n.N("Path MTU discovery on new tunnels"),
		Description: i18n.N("Enable path MTU discovery on new tunnels by default."),
		Default:     false,
	},
	{
		Key: "tunnel.default_csum", Type: KindBool, Category: CategoryTunnel,
		Label: i18n.N("GRE checksums on new tunnels"),
		Description: i18n.N("Enable GRE checksums on new tunnels by default. Adds 4 bytes of overhead " +
			"and must match on both ends."),
		Default: false,
	},
	{
		Key: "tunnel.default_seq", Type: KindBool, Category: CategoryTunnel,
		Label: i18n.N("GRE sequence numbers on new tunnels"),
		Description: i18n.N("Enable GRE sequence numbers on new tunnels by default. Adds 4 bytes of " +
			"overhead and must match on both ends."),
		Default: false,
	},
	{
		Key: "tunnel.naming_template", Type: KindString, Category: CategoryTunnel,
		Label: i18n.N("Interface name template"),
		Description: i18n.N("Template for generated interface names. Supports {side}, {number}, {type} " +
			"and free text. The rendered name must satisfy the Linux interface name rules: " +
			"at most 15 characters from A-Z a-z 0-9 . _ - starting with a letter or digit."),
		Default:     "gre-{side}-{number}",
		Constraints: Constraints{Pattern: `rendered name must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`},
		validate: func(ctx context.Context, v any) error {
			s, _ := v.(string)
			return validateNamingTemplate(ctx, s)
		},
	},
	{
		Key: "tunnel.side_labels", Type: KindJSON, Category: CategoryTunnel,
		Label: i18n.N("Side labels in interface names"),
		Description: i18n.N(`Labels substituted for {side} in the naming template. A and B are simply ` +
			`the two ends of one tunnel; neither has a special role.`),
		Default:     map[string]any{"a": "a", "b": "b"},
		Constraints: Constraints{JsonShape: "object", Pattern: `keys "a" and "b", each 1-8 name characters`},
		validate:    validateSideLabels,
	},
	{
		Key: "tunnel.default_persistence", Type: KindLookup, Category: CategoryTunnel,
		Label: i18n.N("How new tunnels survive a reboot"),
		Description: i18n.N("How new tunnels survive a reboot: a systemd unit, a systemd-networkd file, " +
			"or Runtime, which configures the kernel only and does not survive a reboot."),
		Default:     model.PersistenceTypeSystemd,
		Constraints: Constraints{LookupTable: "PersistenceType"},
	},
	{
		Key: "tunnel.auto_mtu_from_underlay", Type: KindBool, Category: CategoryTunnel,
		Label: i18n.N("Suggest the MTU from the underlay"),
		Description: i18n.N("Compute the suggested tunnel MTU from the underlay interface MTU minus the " +
			"encapsulation overhead. The suggestion is never applied silently over an explicit choice."),
		Default: true,
	},

	// ------------------------------------------------------------ addressing
	{
		Key: "addressing.default_pool_id", Type: KindInt, Category: CategoryAddressing,
		Label: i18n.N("Default address pool"),
		Description: i18n.N("Address pool preselected when creating a tunnel. Null selects the first " +
			"enabled pool."),
		Default:     nil,
		Constraints: Constraints{Min: f64(1), Nullable: true},
	},
	{
		Key: "addressing.default_prefix_len", Type: KindInt, Category: CategoryAddressing,
		Label: i18n.N("Tunnel subnet prefix length"),
		Description: i18n.N("Prefix length of the point-to-point subnet allocated per tunnel. For IPv4 " +
			"use 30, or 31 for the two-address form of RFC 3021. IPv6 tunnels may use up to 127."),
		Default:     int64(30),
		Constraints: Constraints{Min: f64(30), Max: f64(127)},
	},
	{
		Key: "addressing.allow_public_ranges", Type: KindBool, Category: CategoryAddressing,
		Label: i18n.N("Allow public address ranges"),
		Description: i18n.N("Permit tunnel addresses from globally routable ranges. Doing so squats on " +
			"address space belonging to someone else and blackholes those destinations from this " +
			"server; a warning is returned either way."),
		Default: false,
	},
	{
		Key: "addressing.check_route_overlap", Type: KindBool, Category: CategoryAddressing,
		Label: i18n.N("Reject subnets that overlap a route"),
		Description: i18n.N("Reject a tunnel subnet that overlaps an existing route unless the request " +
			"sets force."),
		Default: true,
	},

	// ------------------------------------------------------------- keepalive
	{
		Key: "keepalive.enabled_by_default", Type: KindBool, Category: CategoryKeepalive,
		Label:       i18n.N("Keepalive on new tunnels"),
		Description: i18n.N("Enable keepalive on newly created tunnels."),
		Default:     true,
	},
	{
		Key: "keepalive.interval_seconds", Type: KindFloat, Category: CategoryKeepalive, Unit: unitSeconds,
		Label:       i18n.N("Keepalive interval"),
		Description: i18n.N("Seconds between keepalive packets."),
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(3600)},
	},
	{
		Key: "keepalive.packet_size", Type: KindInt, Category: CategoryKeepalive, Unit: unitBytes,
		Label:       i18n.N("Keepalive packet size"),
		Description: i18n.N("ICMP payload size of keepalive packets."),
		Default:     int64(56),
		Constraints: Constraints{Min: f64(0), Max: f64(65507)},
	},
	{
		Key: "keepalive.mode", Type: KindEnum, Category: CategoryKeepalive,
		Label: i18n.N("How keepalive is sent"),
		Description: i18n.N("monitor_only relies on the panel's own prober, which already sends " +
			"continuous ICMP from the tunnel source address and therefore is a keepalive. " +
			"systemd_unit writes a separate ping unit so keepalive survives panel downtime, at the " +
			"cost of one extra process per tunnel."),
		Default:     "monitor_only",
		Constraints: Constraints{EnumValues: []string{"systemd_unit", "monitor_only"}},
	},

	// --------------------------------------------------------------- monitor
	{
		Key: "monitor.enabled", Type: KindBool, Category: CategoryMonitor,
		Label:       i18n.N("Monitor tunnels"),
		Description: i18n.N("Run the continuous liveness prober. Individual tunnels may override this."),
		Default:     true,
	},
	{
		Key: "monitor.interval_seconds", Type: KindFloat, Category: CategoryMonitor, Unit: unitSeconds,
		Label:       i18n.N("Tunnel probe interval"),
		Description: i18n.N("Seconds between probe packets."),
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(3600)},
	},
	{
		Key: "monitor.timeout_seconds", Type: KindFloat, Category: CategoryMonitor, Unit: unitSeconds,
		Label: i18n.N("Tunnel probe timeout"),
		Description: i18n.N("How long a probe may go unanswered before it counts as lost. A reply that " +
			"arrives later still overrides the loss verdict for that sequence."),
		Default:     2.0,
		Constraints: Constraints{Min: f64(0.1), Max: f64(3600)},
	},
	{
		Key: "monitor.packet_size", Type: KindInt, Category: CategoryMonitor, Unit: unitBytes,
		Label:       i18n.N("Tunnel probe packet size"),
		Description: i18n.N("ICMP payload size of probe packets."),
		Default:     int64(56),
		Constraints: Constraints{Min: f64(16), Max: f64(65507)},
	},
	{
		Key: "monitor.window_size", Type: KindInt, Category: CategoryMonitor, Unit: unitSamples,
		Label:       i18n.N("Probes in the rolling window"),
		Description: i18n.N("Number of recent probes the rolling loss and latency figures cover."),
		Default:     int64(60),
		Constraints: Constraints{Min: f64(1), Max: f64(10000)},
	},
	{
		Key: "monitor.degraded_loss_pct", Type: KindFloat, Category: CategoryMonitor, Unit: unitPercent,
		Label:       i18n.N("Loss that marks a tunnel Degraded"),
		Description: i18n.N("Loss over the rolling window at or above which a tunnel is Degraded."),
		Default:     20.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},
	{
		Key: "monitor.down_loss_pct", Type: KindFloat, Category: CategoryMonitor, Unit: unitPercent,
		Label: i18n.N("Loss that marks a tunnel Down"),
		Description: i18n.N("Loss over the rolling window at or above which a tunnel is Down. Must be at " +
			"least the Degraded threshold."),
		Default:     100.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},
	{
		Key: "monitor.degraded_rtt_ms", Type: KindFloat, Category: CategoryMonitor, Unit: unitMilliseconds,
		Label: i18n.N("Latency that marks a tunnel Degraded"),
		Description: i18n.N("Average round-trip time at or above which a tunnel is Degraded even with no " +
			"loss. Null disables the latency criterion."),
		Default:     nil,
		Constraints: Constraints{Min: f64(0), Max: f64(600000), Nullable: true},
	},
	{
		Key: "monitor.state_change_samples", Type: KindInt, Category: CategoryMonitor, Unit: unitSamples,
		Label: i18n.N("Samples before the state changes"),
		Description: i18n.N("Consecutive agreeing samples required before the state changes. This " +
			"hysteresis is what stops the display flapping on a single lost packet."),
		Default:     int64(3),
		Constraints: Constraints{Min: f64(1), Max: f64(100)},
	},
	{
		Key: "monitor.aggregate_interval_seconds", Type: KindInt, Category: CategoryMonitor, Unit: unitSeconds,
		Label:       i18n.N("Monitoring history resolution"),
		Description: i18n.N("How much probe history one stored MonitorSample row covers."),
		Default:     int64(60),
		Constraints: Constraints{Min: f64(1), Max: f64(86400)},
	},
	{
		Key: "monitor.history_retention_days", Type: KindInt, Category: CategoryMonitor, Unit: unitDays,
		Label:       i18n.N("Keep monitoring history for"),
		Description: i18n.N("How long aggregated monitoring history is kept before pruning."),
		Default:     int64(30),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},

	// ----------------------------------------------------------- diagnostics
	{
		Key: "diagnostics.manual_ping_count", Type: KindInt, Category: CategoryDiagnostics, Unit: unitPackets,
		Label:       i18n.N("Ping packet count"),
		Description: i18n.N("Default packet count for the on-demand high-precision ping."),
		Default:     int64(100),
		Constraints: Constraints{Min: f64(1), Max: f64(1000000)},
	},
	{
		Key: "diagnostics.manual_ping_interval", Type: KindFloat, Category: CategoryDiagnostics, Unit: unitSeconds,
		Label:       i18n.N("Interval between ping packets"),
		Description: i18n.N("Default interval between packets for the on-demand ping."),
		Default:     0.1,
		Constraints: Constraints{Min: f64(0.001), Max: f64(60)},
	},
	{
		Key: "diagnostics.manual_ping_timeout", Type: KindFloat, Category: CategoryDiagnostics, Unit: unitSeconds,
		Label:       i18n.N("Timeout for each ping packet"),
		Description: i18n.N("Default per-packet timeout for the on-demand ping."),
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.01), Max: f64(600)},
	},
	{
		Key: "diagnostics.manual_ping_max_count", Type: KindInt, Category: CategoryDiagnostics, Unit: unitPackets,
		Label:       i18n.N("Largest ping packet count"),
		Description: i18n.N("Hard upper bound on the packet count a single on-demand ping may request."),
		Default:     int64(10000),
		Constraints: Constraints{Min: f64(1), Max: f64(10000000)},
	},
	{
		Key: "diagnostics.mtu_probe_min", Type: KindInt, Category: CategoryDiagnostics, Unit: unitBytes,
		Label:       i18n.N("Lowest MTU the search tries"),
		Description: i18n.N("Lower bound of the path MTU binary search."),
		Default:     int64(1200),
		Constraints: Constraints{Min: f64(68), Max: f64(65535)},
	},
	{
		Key: "diagnostics.mtu_probe_max", Type: KindInt, Category: CategoryDiagnostics, Unit: unitBytes,
		Label:       i18n.N("Highest MTU the search tries"),
		Description: i18n.N("Upper bound of the path MTU binary search. Must be at least the lower bound."),
		Default:     int64(1500),
		Constraints: Constraints{Min: f64(68), Max: f64(65535)},
	},
	{
		Key: "diagnostics.allow_tcpdump", Type: KindBool, Category: CategoryDiagnostics,
		Label: i18n.N("Allow capturing packets with tcpdump"),
		Description: i18n.N("Allow automated analysis to capture briefly with tcpdump to prove whether " +
			"GRE packets are actually leaving or arriving."),
		Default: true,
	},

	// --------------------------------------------------------------- metrics
	{
		Key: "metrics.sample_interval_seconds", Type: KindFloat, Category: CategoryMetrics, Unit: unitSeconds,
		Label:       i18n.N("Server sampling interval"),
		Description: i18n.N("How often system and interface counters are sampled."),
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(600)},
	},
	{
		Key: "metrics.history_points", Type: KindInt, Category: CategoryMetrics, Unit: unitSamples,
		Label:       i18n.N("Samples kept for the charts"),
		Description: i18n.N("Number of samples kept in memory for the dashboard sparklines."),
		Default:     int64(300),
		Constraints: Constraints{Min: f64(10), Max: f64(100000)},
	},
	{
		Key: "metrics.hide_loopback", Type: KindBool, Category: CategoryMetrics,
		Label:       i18n.N("Hide the loopback interface"),
		Description: i18n.N("Hide the loopback interface in the traffic view by default."),
		Default:     true,
	},
	{
		Key: "metrics.hide_pseudo_filesystems", Type: KindBool, Category: CategoryMetrics,
		Label: i18n.N("Hide pseudo filesystems"),
		Description: i18n.N("Hide tmpfs, devtmpfs, proc, sysfs, cgroup, overlay and squashfs mounts in " +
			"the disk view by default. The full list stays retrievable."),
		Default: true,
	},
	{
		Key: "metrics.disk_warn_pct", Type: KindFloat, Category: CategoryMetrics, Unit: unitPercent,
		Label:       i18n.N("Disk usage that shows a warning"),
		Description: i18n.N("Disk usage at or above which a mount is shown as a warning."),
		Default:     85.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},
	{
		Key: "metrics.disk_critical_pct", Type: KindFloat, Category: CategoryMetrics, Unit: unitPercent,
		Label: i18n.N("Disk usage that shows as critical"),
		Description: i18n.N("Disk usage at or above which a mount is shown as critical. Must be at least " +
			"the warning threshold."),
		Default:     95.0,
		Constraints: Constraints{Min: f64(0), Max: f64(100)},
	},

	// ---------------------------------------------------------------- routes
	{
		Key: "routes.default_nat_mode", Type: KindLookup, Category: CategoryRoutes,
		Label: i18n.N("Default source address handling"),
		Description: i18n.N("How the source address of relayed traffic is treated on new forwarding rules. " +
			"Masquerade always works and makes the destination see this server; None preserves the " +
			"client address but needs the destination's replies to come back through here."),
		Default:     model.NatModeMasquerade,
		Constraints: Constraints{LookupTable: "NatMode"},
	},
	{
		Key: "routes.default_protocol", Type: KindLookup, Category: CategoryRoutes,
		Label:       i18n.N("Default forwarding protocol"),
		Description: i18n.N("Protocol preselected when creating a forwarding rule."),
		Default:     model.RouteProtocolTCP,
		Constraints: Constraints{LookupTable: "RouteProtocol"},
	},
	{
		Key: "routes.default_clamp_mss", Type: KindBool, Category: CategoryRoutes,
		Label: i18n.N("Clamp TCP MSS through tunnels"),
		Description: i18n.N("Clamp the TCP maximum segment size on new rules whose destination is reached " +
			"through a tunnel. Without it those connections establish normally and then stall on the " +
			"first large transfer, which is the most common way a working tunnel looks broken."),
		Default: true,
	},
	{
		Key: "routes.counter_interval_seconds", Type: KindFloat, Category: CategoryRoutes, Unit: unitSeconds,
		Label:       i18n.N("Traffic counter interval"),
		Description: i18n.N("How often the per-rule byte and packet counters are sampled."),
		Default:     1.0,
		Constraints: Constraints{Min: f64(0.2), Max: f64(600)},
	},
	{
		Key: "routes.conntrack_interval_seconds", Type: KindFloat, Category: CategoryRoutes, Unit: unitSeconds,
		Label: i18n.N("Connection count interval"),
		Description: i18n.N("How often the connection table is read for per-rule connection counts. It is " +
			"sampled less often than the byte counters because reading it is expensive on a busy host."),
		Default:     5.0,
		Constraints: Constraints{Min: f64(0.5), Max: f64(3600)},
	},
	{
		Key: "routes.aggregate_interval_seconds", Type: KindInt, Category: CategoryRoutes, Unit: unitSeconds,
		Label:       i18n.N("Traffic history resolution"),
		Description: i18n.N("How much traffic history one stored per-rule sample row covers."),
		Default:     int64(60),
		Constraints: Constraints{Min: f64(1), Max: f64(86400)},
	},
	{
		Key: "routes.history_retention_days", Type: KindInt, Category: CategoryRoutes, Unit: unitDays,
		Label:       i18n.N("Keep traffic history for"),
		Description: i18n.N("How long aggregated per-rule traffic history is kept before pruning."),
		Default:     int64(30),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},
	{
		Key: "routes.auto_enable_ip_forward", Type: KindBool, Category: CategoryRoutes,
		Label: i18n.N("Turn on IP forwarding automatically"),
		Description: i18n.N("Turn on IP forwarding when the first forwarding rule is applied, and record that " +
			"the panel did. Turning it off again is never automatic: other software on this server may " +
			"have come to depend on it."),
		Default: true,
	},
	{
		Key: "routes.manage_conntrack", Type: KindBool, Category: CategoryRoutes,
		Label: i18n.N("Keep the connection tracking table sized"),
		Description: i18n.N("Keep the connection tracking table sized for the traffic these rules carry. " +
			"The kernel sizes it from how much memory the machine has, which has nothing to do with " +
			"how many connections a relay carries; when it fills, every new connection on the host is " +
			"refused, SSH included, and the only trace is one line in the kernel log. The panel's own " +
			"rules are what fill it, so it keeps it sized and records what the values were first."),
		Default: true,
	},
	{
		Key: "routes.monitor_enabled", Type: KindBool, Category: CategoryRoutes,
		Label: i18n.N("Probe forwarding destinations"),
		Description: i18n.N("Probe the destinations of forwarding rules on a schedule, so a backend that " +
			"stopped listening is named rather than inferred from a share that went to zero. Each " +
			"rule, and each destination, may override this. What a failure costs is a per-rule " +
			"choice: reporting only, or taking the destination out of the rotation."),
		Default: false,
	},
	{
		Key: "routes.monitor_interval_seconds", Type: KindFloat, Category: CategoryRoutes, Unit: unitSeconds,
		Label: i18n.N("Destination probe interval"),
		Description: i18n.N("Seconds between probes of one destination. A destination is one TCP connect " +
			"per interval, so this is also how much traffic the monitoring itself makes."),
		Default:     15.0,
		Constraints: Constraints{Min: f64(1), Max: f64(3600)},
	},
	{
		Key: "routes.monitor_timeout_seconds", Type: KindFloat, Category: CategoryRoutes, Unit: unitSeconds,
		Label:       i18n.N("Destination probe timeout"),
		Description: i18n.N("How long one probe waits for an answer before it counts as a failure."),
		Default:     3.0,
		Constraints: Constraints{Min: f64(0.1), Max: f64(60)},
	},
	{
		Key: "routes.monitor_failure_threshold", Type: KindInt, Category: CategoryRoutes, Unit: unitProbes,
		Label: i18n.N("Failed probes before a destination is down"),
		Description: i18n.N("Consecutive failed probes before a destination is called down. More than one " +
			"because a single lost probe is a lost probe, not an outage."),
		Default:     int64(3),
		Constraints: Constraints{Min: f64(1), Max: f64(100)},
	},
	{
		Key: "routes.monitor_recovery_threshold", Type: KindInt, Category: CategoryRoutes, Unit: unitProbes,
		Label: i18n.N("Good probes before a destination is up again"),
		Description: i18n.N("Consecutive good probes before a destination that was down is called up " +
			"again, and put back in the rotation where the rule fails over. Raising it is what " +
			"stops a flapping backend rebuilding the ruleset every minute."),
		Default:     int64(2),
		Constraints: Constraints{Min: f64(1), Max: f64(100)},
	},
	{
		Key: "routes.count_connection_bytes", Type: KindBool, Category: CategoryRoutes,
		Label: i18n.N("Count the bytes on each connection"),
		Description: i18n.N("Have the kernel count the bytes on every tracked connection, and record " +
			"that the panel asked for it. Without it a relay reports how many connections each " +
			"destination is taking and nothing about what is crossing them, which is what makes a " +
			"load-balanced rule readable. The counting costs a little on every packet; turn it off " +
			"on a machine where that matters more than the figures."),
		Default: true,
	},
	{
		Key: "routes.warn_conntrack_usage_percent", Type: KindFloat, Category: CategoryRoutes, Unit: unitPercent,
		Label: i18n.N("Connection tracking usage that warns"),
		Description: i18n.N("Connection tracking table usage at or above which the panel warns. A relay that " +
			"fills the table starts dropping new connections with nothing in the logs to explain it."),
		Default:     80.0,
		Constraints: Constraints{Min: f64(1), Max: f64(100)},
	},

	// --------------------------------------------------------------- display
	{
		Key: "display.language", Type: KindString, Category: CategoryDisplay,
		Label:       i18n.N("Interface language"),
		Description: i18n.N("Interface language as a BCP 47 tag, for example en or fa."),
		Default:     "en",
		Constraints: Constraints{Pattern: `^[a-z]{2}(-[A-Za-z0-9]{2,8})?$`},
		validate: func(ctx context.Context, v any) error {
			s, _ := v.(string)
			if !languageRe.MatchString(s) {
				return i18n.Errorf(ctx, "must be a language tag such as en or fa")
			}
			return nil
		},
	},
	{
		Key: "display.theme", Type: KindEnum, Category: CategoryDisplay,
		Label:       i18n.N("Colour theme"),
		Description: i18n.N("Colour theme; system follows the operating system preference."),
		Default:     "system",
		Constraints: Constraints{EnumValues: []string{"system", "light", "dark"}},
	},
	{
		Key: "display.throughput_unit", Type: KindEnum, Category: CategoryDisplay,
		Label: i18n.N("Throughput unit"),
		Description: i18n.N("Show throughput in bytes per second or bits per second. The API always " +
			"returns raw bytes; this only affects presentation."),
		Default:     "bytes",
		Constraints: Constraints{EnumValues: []string{"bytes", "bits"}},
	},
	{
		Key: "display.volume_unit", Type: KindEnum, Category: CategoryDisplay,
		Label:       i18n.N("Traffic volume unit"),
		Description: i18n.N("Show cumulative volume in bytes or bits."),
		Default:     "bytes",
		Constraints: Constraints{EnumValues: []string{"bytes", "bits"}},
	},
	{
		Key: "display.binary_units", Type: KindBool, Category: CategoryDisplay,
		Label:       i18n.N("Binary multiples (MiB)"),
		Description: i18n.N("Use binary multiples (MiB, 1024-based) rather than decimal ones (MB, 1000-based)."),
		Default:     true,
	},
	{
		Key: "display.digits", Type: KindEnum, Category: CategoryDisplay,
		Label:       i18n.N("Numerals"),
		Description: i18n.N("Numeral system used for displayed numbers."),
		Default:     "latin",
		Constraints: Constraints{EnumValues: []string{"latin", "persian"}},
	},
	{
		Key: "display.calendar", Type: KindEnum, Category: CategoryDisplay,
		Label:       i18n.N("Calendar"),
		Description: i18n.N("Calendar used for displayed dates. Stored timestamps are always UTC ISO-8601."),
		Default:     "gregorian",
		Constraints: Constraints{EnumValues: []string{"gregorian", "jalali"}},
	},

	// -------------------------------------------------------------- security
	{
		Key: "security.token_ttl_minutes", Type: KindInt, Category: CategorySecurity, Unit: unitMinutes,
		Label:       i18n.N("Access token lifetime"),
		Description: i18n.N("Lifetime of an access token. Applies to tokens issued from now on."),
		Default:     int64(720),
		Constraints: Constraints{Min: f64(1), Max: f64(43200)},
	},
	{
		Key: "security.refresh_ttl_days", Type: KindInt, Category: CategorySecurity, Unit: unitDays,
		Label: i18n.N("Refresh token lifetime"),
		Description: i18n.N("Lifetime of a refresh token. Changing a password invalidates every existing " +
			"session regardless of this value."),
		Default:     int64(30),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},
	{
		Key: "security.login_rate_limit_per_minute", Type: KindInt, Category: CategorySecurity, Unit: unitAttempts,
		Label: i18n.N("Login attempts per minute"),
		Description: i18n.N("Login attempts allowed per minute per account and per client address. The " +
			"same number of consecutive failures locks the account."),
		Default:     int64(5),
		Constraints: Constraints{Min: f64(1), Max: f64(1000)},
	},
	{
		Key: "security.login_lockout_minutes", Type: KindInt, Category: CategorySecurity, Unit: unitMinutes,
		Label:       i18n.N("Account lockout duration"),
		Description: i18n.N("How long an account stays locked after too many consecutive failed logins."),
		Default:     int64(15),
		Constraints: Constraints{Min: f64(1), Max: f64(43200)},
	},
	{
		Key: "security.allowed_origins", Type: KindJSON, Category: CategorySecurity,
		Label: i18n.N("Allowed cross-origin origins"),
		Description: i18n.N("Cross-origin request origins allowed to call the API, for example " +
			`"https://panel.example.org". Empty means same-origin only, which is the right ` +
			"setting unless the frontend is served from somewhere else."),
		Default:     []any{},
		Constraints: Constraints{JsonShape: "array", Pattern: "scheme://host[:port], no path, no wildcard"},
		validate:    validateAllowedOrigins,
	},

	// ---------------------------------------------------------------- system
	{
		Key: "system.reconcile_interval_seconds", Type: KindInt, Category: CategorySystem, Unit: unitSeconds,
		Label:       i18n.N("Reconcile interval"),
		Description: i18n.N("How often the panel compares its database against live kernel state."),
		Default:     int64(300),
		Constraints: Constraints{Min: f64(10), Max: f64(86400)},
	},
	{
		Key: "system.audit_retention_days", Type: KindInt, Category: CategorySystem, Unit: unitDays,
		Label:       i18n.N("Keep the audit log for"),
		Description: i18n.N("How long audit log entries are kept before pruning."),
		Default:     int64(90),
		Constraints: Constraints{Min: f64(1), Max: f64(3650)},
	},
	{
		Key: "system.auto_reapply_on_drift", Type: KindBool, Category: CategorySystem,
		Label: i18n.N("Reapply drifted tunnels automatically"),
		Description: i18n.N("Automatically reapply the stored configuration when reconcile finds a tunnel " +
			"has drifted. Off by default: an operator who changed something outside the panel " +
			"usually meant to."),
		Default: false,
	},
	{
		Key: "system.ignored_interfaces", Type: KindJSON, Category: CategorySystem,
		Label: i18n.N("Ignored interfaces"),
		Description: i18n.N("Tunnel interfaces reconcile should stop reporting as unmanaged. Use this for " +
			"tunnels another tool owns on this host: they are listed but never adopted, changed or " +
			"removed. The panel never touches an interface it does not manage either way."),
		Default:     []any{},
		Constraints: Constraints{JsonShape: "array", Pattern: "interface names"},
		validate:    validateInterfaceNameList,
	},
	{
		Key: "system.update_check_enabled", Type: KindBool, Category: CategorySystem,
		Label: i18n.N("Check for updates automatically"),
		Description: i18n.N("Let the panel ask the release host whether a newer version exists. Turn this " +
			"off on a server that must make no outbound connections; the update button still works, " +
			"and checks then happen only when an operator asks for one."),
		Default: true,
	},
	{
		Key: "system.update_check_interval_hours", Type: KindInt, Category: CategorySystem, Unit: unitHours,
		Label: i18n.N("Update check interval"),
		Description: i18n.N("How long an answer from the release host is reused before asking again. The " +
			"dashboard reads this answer on every load, so this is what stops one panel becoming " +
			"a stream of requests to the release host."),
		Default:     int64(6),
		Constraints: Constraints{Min: f64(1), Max: f64(168)},
	},
}

func validateInterfaceNameList(ctx context.Context, v any) error {
	list, ok := v.([]any)
	if !ok {
		return i18n.Errorf(ctx, "must be a list of interface names")
	}
	for i, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return i18n.Errorf(ctx, "entry %d must be a string", i)
		}
		if !ifNameRe.MatchString(s) {
			return i18n.Errorf(ctx, "entry %d (%q) is not a valid interface name", i, s)
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
//
// The message is said in the panel's language; the store says it in the
// language of the request that asked.
func ValidateNamingTemplate(t string) error {
	return validateNamingTemplate(context.Background(), t)
}

func validateNamingTemplate(ctx context.Context, t string) error {
	if strings.TrimSpace(t) == "" {
		return i18n.Errorf(ctx, "must not be empty")
	}
	for _, ph := range templatePlaceholderRe.FindAllString(t, -1) {
		switch ph {
		case "{side}", "{number}", "{type}":
		default:
			return i18n.Errorf(ctx, "unknown placeholder %s: use {side}, {number} or {type}", ph)
		}
	}
	rendered := RenderNamingTemplate(t, "a", "1", "gre")
	if !ifNameRe.MatchString(rendered) {
		return i18n.Errorf(ctx, "renders to %q, which is not a valid interface name: at most 15 "+
			"characters from A-Z a-z 0-9 . _ - starting with a letter or digit", rendered)
	}
	return nil
}

// RenderNamingTemplate substitutes the three supported placeholders.
func RenderNamingTemplate(t, side, number, typ string) string {
	r := strings.NewReplacer("{side}", side, "{number}", number, "{type}", typ)
	return r.Replace(t)
}

func validateSideLabels(ctx context.Context, v any) error {
	m, ok := v.(map[string]any)
	if !ok {
		return i18n.Errorf(ctx, `must be an object such as {"a":"a","b":"b"}`)
	}
	for _, slot := range []string{"a", "b"} {
		raw, present := m[slot]
		if !present {
			return i18n.Errorf(ctx, "missing label for slot %q", slot)
		}
		s, ok := raw.(string)
		if !ok {
			return i18n.Errorf(ctx, "label for slot %q must be a string", slot)
		}
		if !sideLabelRe.MatchString(s) {
			return i18n.Errorf(ctx, "label %q for slot %q must be 1-8 characters from A-Z a-z 0-9 . _ - "+
				"and start with a letter or digit, so the rendered interface name stays valid", s, slot)
		}
	}
	for k := range m {
		if k != "a" && k != "b" {
			return i18n.Errorf(ctx, "unknown slot %q: a tunnel has exactly two ends, a and b", k)
		}
	}
	return nil
}

func validateAllowedOrigins(ctx context.Context, v any) error {
	list, ok := v.([]any)
	if !ok {
		return i18n.Errorf(ctx, "must be a list of origins")
	}
	for i, raw := range list {
		s, ok := raw.(string)
		if !ok {
			return i18n.Errorf(ctx, "entry %d must be a string", i)
		}
		if s == "*" {
			return i18n.Errorf(ctx, `entry %d: "*" is not accepted, because the panel sends credentials `+
				"with cross-origin requests; list the exact origins instead", i)
		}
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return i18n.Errorf(ctx, "entry %d (%q) must be an origin such as https://panel.example.org", i, s)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return i18n.Errorf(ctx, "entry %d (%q): scheme must be http or https", i, s)
		}
		if u.Path != "" && u.Path != "/" {
			return i18n.Errorf(ctx, "entry %d (%q): an origin has no path", i, s)
		}
		if s != strings.TrimSuffix(s, "/") {
			return i18n.Errorf(ctx, "entry %d (%q): drop the trailing slash", i, s)
		}
	}
	return nil
}

// Coerce converts a value decoded from JSON into the canonical Go type for the
// definition and validates it against the constraints. It returns a message
// suitable for showing next to the field, in the panel's language; the store
// says it in the language of the request that asked.
func (d Definition) Coerce(raw any) (any, error) {
	return d.coerce(context.Background(), raw)
}

func (d Definition) coerce(ctx context.Context, raw any) (any, error) {
	if raw == nil {
		if !d.Constraints.Nullable {
			return nil, i18n.Errorf(ctx, "must not be null")
		}
		return nil, nil
	}

	switch d.Type {
	case KindBool:
		b, ok := raw.(bool)
		if !ok {
			return nil, i18n.Errorf(ctx, "must be true or false")
		}
		return b, nil

	case KindInt, KindLookup:
		n, err := toFloat(raw)
		if err != nil {
			return nil, i18n.Errorf(ctx, "must be a whole number")
		}
		if n != math.Trunc(n) {
			return nil, i18n.Errorf(ctx, "must be a whole number")
		}
		i := int64(n)
		if err := d.checkRange(ctx, float64(i)); err != nil {
			return nil, err
		}
		if d.Type == KindLookup {
			if !model.HasLookupValue(d.Constraints.LookupTable, i) {
				return nil, i18n.Errorf(ctx, "%d is not a valid %s", i, d.Constraints.LookupTable)
			}
		}
		return i, d.runExtra(ctx, i)

	case KindFloat:
		n, err := toFloat(raw)
		if err != nil {
			return nil, i18n.Errorf(ctx, "must be a number")
		}
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, i18n.Errorf(ctx, "must be a finite number")
		}
		if err := d.checkRange(ctx, n); err != nil {
			return nil, err
		}
		return n, d.runExtra(ctx, n)

	case KindString:
		s, ok := raw.(string)
		if !ok {
			return nil, i18n.Errorf(ctx, "must be a string")
		}
		return s, d.runExtra(ctx, s)

	case KindEnum:
		s, ok := raw.(string)
		if !ok {
			return nil, i18n.Errorf(ctx, "must be one of %s", strings.Join(d.Constraints.EnumValues, ", "))
		}
		for _, allowed := range d.Constraints.EnumValues {
			if s == allowed {
				return s, d.runExtra(ctx, s)
			}
		}
		return nil, i18n.Errorf(ctx, "must be one of %s", strings.Join(d.Constraints.EnumValues, ", "))

	case KindJSON:
		switch d.Constraints.JsonShape {
		case "object":
			if _, ok := raw.(map[string]any); !ok {
				return nil, i18n.Errorf(ctx, "must be an object")
			}
		case "array":
			if _, ok := raw.([]any); !ok {
				return nil, i18n.Errorf(ctx, "must be a list")
			}
		}
		return raw, d.runExtra(ctx, raw)
	}
	return nil, i18n.Errorf(ctx, "setting has an unknown type %q", d.Type)
}

func (d Definition) runExtra(ctx context.Context, v any) error {
	if d.validate == nil {
		return nil
	}
	return d.validate(ctx, v)
}

func (d Definition) checkRange(ctx context.Context, n float64) error {
	if d.Constraints.Min != nil && n < *d.Constraints.Min {
		return i18n.Errorf(ctx, "must be at least %s", formatNumber(*d.Constraints.Min))
	}
	if d.Constraints.Max != nil && n > *d.Constraints.Max {
		return i18n.Errorf(ctx, "must be at most %s", formatNumber(*d.Constraints.Max))
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
