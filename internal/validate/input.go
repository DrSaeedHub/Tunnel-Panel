package validate

import (
	"context"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
)

// AddressInput is one address the operator asked to put on a tunnel.
type AddressInput struct {
	Address      string `json:"address"`
	PrefixLength int    `json:"prefix_length"`
	PeerAddress  string `json:"peer_address,omitempty"`
	IsPrimary    bool   `json:"is_primary"`
}

// TunnelInput is the complete desired state of one tunnel as a request states
// it. It is the type the API decodes into, the type validation checks, and the
// type the planner turns into operations, so the same fields carry all the way
// through with no re-mapping in between.
type TunnelInput struct {
	// TunnelID is zero when creating. On update it names the row being changed,
	// so the tunnel does not conflict with itself.
	TunnelID int64 `json:"tunnel_id,omitempty"`

	TunnelTypeID      int64  `json:"tunnel_type_id"`
	TunnelSideID      int64  `json:"tunnel_side_id"`
	PersistenceTypeID int64  `json:"persistence_type_id"`
	InterfaceName     string `json:"interface_name"`
	TunnelNumber      *int64 `json:"tunnel_number"`

	LocalEndpoint  string `json:"local_endpoint"`
	RemoteEndpoint string `json:"remote_endpoint"`
	BindDevice     string `json:"bind_device,omitempty"`

	Ttl  int64  `json:"ttl"`
	Tos  string `json:"tos"`
	Mtu  int64  `json:"mtu"`
	IKey *int64 `json:"ikey"`
	OKey *int64 `json:"okey"`

	HasInputChecksum  bool `json:"has_input_checksum"`
	HasOutputChecksum bool `json:"has_output_checksum"`
	HasInputSequence  bool `json:"has_input_sequence"`
	HasOutputSequence bool `json:"has_output_sequence"`

	IsPathMtuDiscovery bool `json:"is_path_mtu_discovery"`
	IsIgnoreDf         bool `json:"is_ignore_df"`

	FwMark        *int64 `json:"fwmark"`
	TxQueueLength *int64 `json:"tx_queue_length"`

	HopLimit     *int64 `json:"hop_limit"`
	EncapLimit   *int64 `json:"encap_limit"`
	TrafficClass string `json:"traffic_class,omitempty"`
	FlowLabel    string `json:"flow_label,omitempty"`

	AddressPoolID *int64         `json:"address_pool_id"`
	Addresses     []AddressInput `json:"addresses"`

	IsEnabled bool `json:"is_enabled"`

	// The per-tunnel monitoring overrides. Null means inherit the global
	// setting, which is what the nullable columns, monitor.ConfigFor and the
	// interface's inherit/override control all already mean by it.
	MonitorIntervalSeconds     *float64 `json:"monitor_interval_seconds"`
	MonitorTimeoutSeconds      *float64 `json:"monitor_timeout_seconds"`
	MonitorPacketSize          *int64   `json:"monitor_packet_size"`
	MonitorWindowSize          *int64   `json:"monitor_window_size"`
	MonitorDegradedLossPercent *float64 `json:"monitor_degraded_loss_percent"`
	MonitorDownLossPercent     *float64 `json:"monitor_down_loss_percent"`
	MonitorDegradedRttMs       *float64 `json:"monitor_degraded_rtt_ms"`
	MonitorStateChangeSamples  *int64   `json:"monitor_state_change_samples"`

	// Force overrides the warnings that are overridable. It never overrides a
	// §17 invariant (§15).
	Force bool `json:"force,omitempty"`
}

// MonitorOverride is one per-tunnel override paired with the global setting it
// overrides. The bounds live in the settings schema and are read from it, so a
// tunnel can never be given a value the same field would refuse globally, and
// the two cannot drift apart when one of them is changed.
type MonitorOverride struct {
	// Field is the JSON name, for the error the operator reads.
	Field string
	// SettingKey is the global this overrides, and the source of its bounds.
	SettingKey string
	// Value is what was asked for, or nil to inherit.
	Value *float64
	// Whole reports a field the schema declares as a whole number.
	Whole bool
}

// MonitorOverrides lists the overrides on this input, in a fixed order.
func (in TunnelInput) MonitorOverrides() []MonitorOverride {
	asFloat := func(v *int64) *float64 {
		if v == nil {
			return nil
		}
		f := float64(*v)
		return &f
	}
	return []MonitorOverride{
		{"monitor_interval_seconds", "monitor.interval_seconds", in.MonitorIntervalSeconds, false},
		{"monitor_timeout_seconds", "monitor.timeout_seconds", in.MonitorTimeoutSeconds, false},
		{"monitor_packet_size", "monitor.packet_size", asFloat(in.MonitorPacketSize), true},
		{"monitor_window_size", "monitor.window_size", asFloat(in.MonitorWindowSize), true},
		{"monitor_degraded_loss_percent", "monitor.degraded_loss_pct", in.MonitorDegradedLossPercent, false},
		{"monitor_down_loss_percent", "monitor.down_loss_pct", in.MonitorDownLossPercent, false},
		{"monitor_degraded_rtt_ms", "monitor.degraded_rtt_ms", in.MonitorDegradedRttMs, false},
		{"monitor_state_change_samples", "monitor.state_change_samples", asFloat(in.MonitorStateChangeSamples), true},
	}
}

// Kind returns the kernel name of the requested tunnel type.
func (in TunnelInput) Kind() string { return model.TunnelTypeKind(in.TunnelTypeID) }

// IsIPv6 reports whether the underlay is IPv6.
func (in TunnelInput) IsIPv6() bool { return link.IsIPv6Kind(in.Kind()) }

// HasKey reports whether the tunnel carries a GRE key, which costs four bytes
// of encapsulation overhead (§7.6).
func (in TunnelInput) HasKey() bool { return in.IKey != nil || in.OKey != nil }

// ExistingTunnel is the database's view of a tunnel, reduced to the fields
// conflict detection needs (§7.5).
type ExistingTunnel struct {
	TunnelID       int64
	InterfaceName  string
	LocalEndpoint  string
	RemoteEndpoint string
	IKey           *int64
	OKey           *int64
	Addresses      []AddressInput
}

// Pool is the database's view of an address pool, reduced to what validation
// needs.
type Pool struct {
	AddressPoolID int64
	Title         string
	Cidr          string
	PrefixLength  int
	IsPublicRange bool
	IsEnabled     bool
}

// Repository is the database view validation needs. Keeping it an interface
// declared here means validation can be tested with a handful of rows and no
// database at all.
type Repository interface {
	// ExistingTunnels returns every tunnel row that is not soft-deleted.
	ExistingTunnels(ctx context.Context) ([]ExistingTunnel, error)
	// PoolByID returns one address pool.
	PoolByID(ctx context.Context, id int64) (Pool, error)
}

// Settings is the slice of the settings store validation reads. *settings.Store
// satisfies it.
type Settings interface {
	Bool(key string) bool
	Int(key string) int64
	String(key string) string
}

// State is the live picture validation checks against: what the kernel has, and
// what the database has. It is collected once per validation pass so that every
// rule sees the same snapshot.
type State struct {
	Links   []link.Link
	Routes  []link.Route
	Tunnels []ExistingTunnel
}

// LinkByName returns the observed interface of that name.
func (s State) LinkByName(name string) (link.Link, bool) {
	for _, l := range s.Links {
		if l.Name == name {
			return l, true
		}
	}
	return link.Link{}, false
}

// Result is what a successful validation produces: the warnings the operator
// should read, and the MTU advisory.
type Result struct {
	Warnings []Warning `json:"warnings"`
	Mtu      MtuAdvice `json:"mtu"`
}

// AddWarning appends a warning.
func (r *Result) AddWarning(w Warning) { r.Warnings = append(r.Warnings, w) }
