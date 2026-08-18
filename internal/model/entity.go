package model

import "time"

// TimeFormat is the ISO-8601 UTC layout used for every date column (§6).
// Milliseconds are always emitted and the trailing Z is literal, so the text
// sorts lexicographically in exactly chronological order.
const TimeFormat = "2006-01-02T15:04:05.000Z"

// NowUTC returns the current time in the canonical storage format.
func NowUTC() string { return FormatTime(time.Now()) }

// FormatTime renders t in the canonical storage format, converting to UTC first.
func FormatTime(t time.Time) string { return t.UTC().Format(TimeFormat) }

// ParseTime parses a canonical storage timestamp.
func ParseTime(s string) (time.Time, error) { return time.Parse(TimeFormat, s) }

// Standard carries the columns every entity table has (§6). Rows are
// soft-deleted; business rows are never hard-deleted.
type Standard struct {
	CreatedDate string `json:"created_date"`
	UpdatedDate string `json:"updated_date"`
	IsDeleted   bool   `json:"is_deleted"`
}

// AppUser is a panel operator. TokenVersion increments on password change,
// which invalidates every JWT issued before the change.
type AppUser struct {
	UserID           int64   `json:"user_id"`
	Username         string  `json:"username"`
	PasswordHash     string  `json:"-"` // never serialised
	IsActive         bool    `json:"is_active"`
	LastLoginDate    *string `json:"last_login_date"`
	FailedLoginCount int     `json:"failed_login_count"`
	LockedUntilDate  *string `json:"locked_until_date"`
	TokenVersion     int64   `json:"token_version"`
	Standard
}

// Tunnel is the desired state of one tunnel and the source of truth for it.
// Unit files are rendered output, never state.
//
// The Monitor* fields are nullable overrides: NULL means "inherit the global
// setting", which is what powers the inherit/override control in the UI (§6).
type Tunnel struct {
	TunnelID          int64   `json:"tunnel_id"`
	TunnelTypeID      int64   `json:"tunnel_type_id"`
	TunnelSideID      int64   `json:"tunnel_side_id"`
	PersistenceTypeID int64   `json:"persistence_type_id"`
	InterfaceName     string  `json:"interface_name"`
	TunnelNumber      *int64  `json:"tunnel_number"`
	LocalEndpoint     string  `json:"local_endpoint"`
	RemoteEndpoint    string  `json:"remote_endpoint"`
	BindDevice        *string `json:"bind_device"`

	Ttl  int64  `json:"ttl"`
	Tos  string `json:"tos"`
	Mtu  int64  `json:"mtu"`
	IKey *int64 `json:"ikey"`
	OKey *int64 `json:"okey"`

	HasInputChecksum   bool `json:"has_input_checksum"`
	HasOutputChecksum  bool `json:"has_output_checksum"`
	HasInputSequence   bool `json:"has_input_sequence"`
	HasOutputSequence  bool `json:"has_output_sequence"`
	IsPathMtuDiscovery bool `json:"is_path_mtu_discovery"`
	IsIgnoreDf         bool `json:"is_ignore_df"`

	FwMark        *int64 `json:"fwmark"`
	TxQueueLength *int64 `json:"tx_queue_length"`

	// IPv6 tunnel modes only.
	HopLimit     *int64  `json:"hop_limit"`
	EncapLimit   *int64  `json:"encap_limit"`
	TrafficClass *string `json:"traffic_class"`
	FlowLabel    *string `json:"flow_label"`

	AddressPoolID   *int64 `json:"address_pool_id"`
	IsEnabled       bool   `json:"is_enabled"`
	IsManaged       bool   `json:"is_managed"`
	IsNameTemplated bool   `json:"is_name_templated"`

	ApplyStatusID   int64   `json:"apply_status_id"`
	LastAppliedDate *string `json:"last_applied_date"`
	LastApplyError  *string `json:"last_apply_error"`

	Note     *string `json:"note"`
	TagsJson *string `json:"tags_json"`

	// Per-tunnel monitoring overrides; NULL means inherit.
	MonitorIntervalSeconds     *float64 `json:"monitor_interval_seconds"`
	MonitorTimeoutSeconds      *float64 `json:"monitor_timeout_seconds"`
	MonitorPacketSize          *int64   `json:"monitor_packet_size"`
	MonitorWindowSize          *int64   `json:"monitor_window_size"`
	MonitorDegradedLossPercent *float64 `json:"monitor_degraded_loss_percent"`
	MonitorDownLossPercent     *float64 `json:"monitor_down_loss_percent"`
	MonitorDegradedRttMs       *float64 `json:"monitor_degraded_rtt_ms"`
	MonitorStateChangeSamples  *int64   `json:"monitor_state_change_samples"`
	MonitorTarget              *string  `json:"monitor_target"`
	IsMonitorEnabled           *bool    `json:"is_monitor_enabled"`

	Standard
}

// TunnelAddress is one address on a tunnel. A tunnel may carry several; the
// panel never assumes exactly one.
type TunnelAddress struct {
	TunnelAddressID int64   `json:"tunnel_address_id"`
	TunnelID        int64   `json:"tunnel_id"`
	Address         string  `json:"address"`
	PrefixLength    int64   `json:"prefix_length"`
	PeerAddress     *string `json:"peer_address"`
	AddressFamilyID int64   `json:"address_family_id"`
	IsPrimary       bool    `json:"is_primary"`
	SortOrder       int64   `json:"sort_order"`
	Standard
}

// AddressPool is a range that point-to-point tunnel subnets are allocated from.
// IsPublicRange marks globally routable ranges: usable, but only deliberately.
type AddressPool struct {
	AddressPoolID    int64  `json:"address_pool_id"`
	AddressPoolTitle string `json:"address_pool_title"`
	Cidr             string `json:"cidr"`
	PrefixLength     int64  `json:"prefix_length"`
	IsPublicRange    bool   `json:"is_public_range"`
	IsEnabled        bool   `json:"is_enabled"`
	Description      string `json:"description"`
	Standard
}

// MonitorSample is one aggregated monitoring bucket for one tunnel.
type MonitorSample struct {
	MonitorSampleID int64    `json:"monitor_sample_id"`
	TunnelID        int64    `json:"tunnel_id"`
	BucketStartDate string   `json:"bucket_start_date"`
	SentCount       int64    `json:"sent_count"`
	ReceivedCount   int64    `json:"received_count"`
	LossPercent     float64  `json:"loss_percent"`
	RttMinMs        *float64 `json:"rtt_min_ms"`
	RttAvgMs        *float64 `json:"rtt_avg_ms"`
	RttMaxMs        *float64 `json:"rtt_max_ms"`
	RttMdevMs       *float64 `json:"rtt_mdev_ms"`
	JitterMs        *float64 `json:"jitter_ms"`
	MonitorStateID  int64    `json:"monitor_state_id"`
	Standard
}

// MonitorEvent records one state machine transition.
type MonitorEvent struct {
	MonitorEventID     int64    `json:"monitor_event_id"`
	TunnelID           int64    `json:"tunnel_id"`
	FromMonitorStateID int64    `json:"from_monitor_state_id"`
	ToMonitorStateID   int64    `json:"to_monitor_state_id"`
	Reason             string   `json:"reason"`
	LossPercent        *float64 `json:"loss_percent"`
	RttAvgMs           *float64 `json:"rtt_avg_ms"`
	CreatedDate        string   `json:"created_date"`
}

// DiagnosticRun is one diagnostic execution and its result.
type DiagnosticRun struct {
	DiagnosticRunID  int64   `json:"diagnostic_run_id"`
	TunnelID         *int64  `json:"tunnel_id"`
	DiagnosticTypeID int64   `json:"diagnostic_type_id"`
	ParamsJson       string  `json:"params_json"`
	ResultJson       *string `json:"result_json"`
	StartedDate      string  `json:"started_date"`
	FinishedDate     *string `json:"finished_date"`
	IsSuccess        bool    `json:"is_success"`
	Standard
}

// InterfaceTrafficCounter persists cumulative volume across reboots and across
// interface recreation, both of which reset the kernel counters (§11.3).
type InterfaceTrafficCounter struct {
	InterfaceTrafficCounterID int64  `json:"interface_traffic_counter_id"`
	InterfaceName             string `json:"interface_name"`
	InterfaceIndex            int64  `json:"interface_index"`
	RxBytesTotal              int64  `json:"rx_bytes_total"`
	TxBytesTotal              int64  `json:"tx_bytes_total"`
	LastRawRxBytes            int64  `json:"last_raw_rx_bytes"`
	LastRawTxBytes            int64  `json:"last_raw_tx_bytes"`
	LastSeenDate              string `json:"last_seen_date"`
	Standard
}

// RouteRule is the desired state of one port forwarding rule and the source of
// truth for it. The generated netfilter ruleset is rendered output, never state.
//
// SortOrder matters: overlapping matches resolve first-match-wins, so the
// operator controls the order rules are emitted in.
type RouteRule struct {
	RouteRuleID    int64  `json:"route_rule_id"`
	RouteRuleTitle string `json:"route_rule_title"`
	Description    string `json:"description"`

	RouteProtocolID int64 `json:"route_protocol_id"`
	AddressFamilyID int64 `json:"address_family_id"`

	BindAddress      string  `json:"bind_address"`
	BindPort         int64   `json:"bind_port"`
	BindPortRangeEnd *int64  `json:"bind_port_range_end"`
	BindInterface    *string `json:"bind_interface"`

	DestinationAddress      string `json:"destination_address"`
	DestinationPort         int64  `json:"destination_port"`
	DestinationPortRangeEnd *int64 `json:"destination_port_range_end"`

	NatModeID         int64   `json:"nat_mode_id"`
	SnatAddress       *string `json:"snat_address"`
	LoadBalanceModeID int64   `json:"load_balance_mode_id"`

	// TunnelID is set when the destination is reached through a tunnel this
	// panel manages, which is what makes MSS clamping default on and what lets a
	// route report a tunnel outage as its own impairment.
	TunnelID *int64 `json:"tunnel_id"`

	IsClampMssToPmtu         bool   `json:"is_clamp_mss_to_pmtu"`
	IsIncludeLocalOriginated bool   `json:"is_include_local_originated"`
	IsLoggingEnabled         bool   `json:"is_logging_enabled"`
	FwMark                   *int64 `json:"fwmark"`

	MaxConnectionsPerSource *int64 `json:"max_connections_per_source"`
	ConnectionRateLimit     *int64 `json:"connection_rate_limit"`

	IsEnabled       bool    `json:"is_enabled"`
	ApplyStatusID   int64   `json:"apply_status_id"`
	LastAppliedDate *string `json:"last_applied_date"`
	LastApplyError  *string `json:"last_apply_error"`

	SortOrder int64   `json:"sort_order"`
	TagsJson  *string `json:"tags_json"`

	Standard
}

// RouteDestination is one destination of a rule. A single-destination rule has
// exactly one row: the schema does not special-case it, so load balancing is
// only ever a mode change rather than a different shape of record.
type RouteDestination struct {
	RouteDestinationID int64  `json:"route_destination_id"`
	RouteRuleID        int64  `json:"route_rule_id"`
	Address            string `json:"address"`
	Port               int64  `json:"port"`
	PortRangeEnd       *int64 `json:"port_range_end"`
	Weight             int64  `json:"weight"`
	IsEnabled          bool   `json:"is_enabled"`
	SortOrder          int64  `json:"sort_order"`
	Standard
}

// RouteAllowedSource restricts which source addresses may use a relay. With no
// rows the relay is open to every source that can reach the bind address.
type RouteAllowedSource struct {
	RouteAllowedSourceID int64  `json:"route_allowed_source_id"`
	RouteRuleID          int64  `json:"route_rule_id"`
	Cidr                 string `json:"cidr"`
	Description          string `json:"description"`
	Standard
}

// RouteTrafficCounter persists cumulative relay volume across rule rebuilds,
// which happen on every edit, enable, disable, reboot and reconcile repair
// (§5.2 of the port forwarding specification).
//
// The LastRaw* columns hold the kernel counters at the last sample, already
// folded into the totals, which is what makes a counter that went backwards
// recognisable as a reset rather than as negative traffic.
type RouteTrafficCounter struct {
	RouteTrafficCounterID int64  `json:"route_traffic_counter_id"`
	RouteRuleID           int64  `json:"route_rule_id"`
	RxBytesTotal          int64  `json:"rx_bytes_total"`
	TxBytesTotal          int64  `json:"tx_bytes_total"`
	RxPacketsTotal        int64  `json:"rx_packets_total"`
	TxPacketsTotal        int64  `json:"tx_packets_total"`
	LastRawRxBytes        int64  `json:"last_raw_rx_bytes"`
	LastRawTxBytes        int64  `json:"last_raw_tx_bytes"`
	LastRawRxPackets      int64  `json:"last_raw_rx_packets"`
	LastRawTxPackets      int64  `json:"last_raw_tx_packets"`
	LastSeenDate          string `json:"last_seen_date"`
	Standard
}

// RouteTrafficSample is one aggregated traffic bucket for one rule.
type RouteTrafficSample struct {
	RouteTrafficSampleID int64  `json:"route_traffic_sample_id"`
	RouteRuleID          int64  `json:"route_rule_id"`
	BucketStartDate      string `json:"bucket_start_date"`
	RxBytes              int64  `json:"rx_bytes"`
	TxBytes              int64  `json:"tx_bytes"`
	RxPackets            int64  `json:"rx_packets"`
	TxPackets            int64  `json:"tx_packets"`
	ActiveConnections    int64  `json:"active_connections"`
	NewConnections       int64  `json:"new_connections"`
	Standard
}

// AppSetting is one persisted override of a setting default. Settings with no
// row here take the default declared in internal/settings.
type AppSetting struct {
	SettingKey      string `json:"setting_key"`
	ValueJson       string `json:"value_json"`
	UpdatedByUserID *int64 `json:"updated_by_user_id"`
	UpdatedDate     string `json:"updated_date"`
}

// AuditLog is one audited request. RequestJson has secrets redacted;
// OperationsJson records every netlink call or command executed with its result.
type AuditLog struct {
	AuditLogID     int64   `json:"audit_log_id"`
	AuditActionID  int64   `json:"audit_action_id"`
	UserID         *int64  `json:"user_id"`
	TargetType     string  `json:"target_type"`
	TargetID       string  `json:"target_id"`
	RequestJson    string  `json:"request_json"`
	OperationsJson string  `json:"operations_json"`
	IsSuccess      bool    `json:"is_success"`
	ErrorMessage   *string `json:"error_message"`
	DurationMs     int64   `json:"duration_ms"`
	ClientIp       string  `json:"client_ip"`
	CreatedDate    string  `json:"created_date"`
}
