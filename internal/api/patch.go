package api

import (
	"encoding/json"
	"fmt"

	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// nullableInt tells an absent field from one explicitly set to null, which
// ordinary pointers cannot. A GRE key of null means "no key" and is a different
// instruction from not mentioning the key at all.
type nullableInt struct {
	Set   bool
	Value *int64
}

func (n *nullableInt) UnmarshalJSON(raw []byte) error {
	// UnmarshalJSON runs only for a key that is present, so reaching here is
	// itself the signal that the field was supplied.
	n.Set = true
	if string(raw) == "null" {
		n.Value = nil
		return nil
	}
	var v int64
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("must be a whole number or null")
	}
	n.Value = &v
	return nil
}

func (n nullableInt) MarshalJSON() ([]byte, error) { return json.Marshal(n.Value) }

// nullableFloat is the same three-state field for a fractional value. The
// monitoring overrides need it because null is meaningful there too: it is how
// a tunnel says "inherit the global", which is a different instruction from not
// mentioning the field at all.
// nullableBool is a flag that can be sent, sent as null, or left out. The three
// mean set it, go back to inheriting it, and change nothing.
type nullableBool struct {
	Set   bool
	Value *bool
}

func (n *nullableBool) UnmarshalJSON(raw []byte) error {
	n.Set = true
	if string(raw) == "null" {
		n.Value = nil
		return nil
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	n.Value = &v
	return nil
}

type nullableFloat struct {
	Set   bool
	Value *float64
}

func (n *nullableFloat) UnmarshalJSON(raw []byte) error {
	n.Set = true
	if string(raw) == "null" {
		n.Value = nil
		return nil
	}
	var v float64
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("must be a number or null")
	}
	n.Value = &v
	return nil
}

func (n nullableFloat) MarshalJSON() ([]byte, error) { return json.Marshal(n.Value) }

// tunnelPatch is the request body for creating, previewing and updating a
// tunnel.
//
// Every field is optional. On create, what is absent takes its default from the
// settings; on update, what is absent keeps the value the tunnel already has.
// That is what makes a PATCH that says only `{"mtu": 1400}` change the MTU and
// nothing else — including not regenerating the interface name from the naming
// template, which would rename the interface and tear the tunnel down.
type tunnelPatch struct {
	// TunnelID selects an existing tunnel for the preview endpoint. The update
	// endpoint takes the identifier from the path instead.
	TunnelID *int64 `json:"tunnel_id,omitempty"`

	TunnelTypeID      *int64      `json:"tunnel_type_id,omitempty"`
	TunnelSideID      *int64      `json:"tunnel_side_id,omitempty"`
	PersistenceTypeID *int64      `json:"persistence_type_id,omitempty"`
	InterfaceName     *string     `json:"interface_name,omitempty"`
	DisplayName       *string     `json:"display_name,omitempty"`
	TunnelNumber      nullableInt `json:"tunnel_number,omitempty"`

	LocalEndpoint  *string `json:"local_endpoint,omitempty"`
	RemoteEndpoint *string `json:"remote_endpoint,omitempty"`
	BindDevice     *string `json:"bind_device,omitempty"`

	Ttl  *int64      `json:"ttl,omitempty"`
	Tos  *string     `json:"tos,omitempty"`
	Mtu  *int64      `json:"mtu,omitempty"`
	IKey nullableInt `json:"ikey,omitempty"`
	OKey nullableInt `json:"okey,omitempty"`

	HasInputChecksum  *bool `json:"has_input_checksum,omitempty"`
	HasOutputChecksum *bool `json:"has_output_checksum,omitempty"`
	HasInputSequence  *bool `json:"has_input_sequence,omitempty"`
	HasOutputSequence *bool `json:"has_output_sequence,omitempty"`

	IsPathMtuDiscovery *bool `json:"is_path_mtu_discovery,omitempty"`
	IsIgnoreDf         *bool `json:"is_ignore_df,omitempty"`

	FwMark        nullableInt `json:"fwmark,omitempty"`
	TxQueueLength nullableInt `json:"tx_queue_length,omitempty"`
	HopLimit      nullableInt `json:"hop_limit,omitempty"`
	EncapLimit    nullableInt `json:"encap_limit,omitempty"`
	TrafficClass  *string     `json:"traffic_class,omitempty"`
	FlowLabel     *string     `json:"flow_label,omitempty"`

	// The per-tunnel monitoring overrides, where null means inherit the global.
	MonitorIntervalSeconds     nullableFloat `json:"monitor_interval_seconds,omitempty"`
	MonitorTimeoutSeconds      nullableFloat `json:"monitor_timeout_seconds,omitempty"`
	MonitorPacketSize          nullableInt   `json:"monitor_packet_size,omitempty"`
	MonitorWindowSize          nullableInt   `json:"monitor_window_size,omitempty"`
	MonitorDegradedLossPercent nullableFloat `json:"monitor_degraded_loss_percent,omitempty"`
	MonitorDownLossPercent     nullableFloat `json:"monitor_down_loss_percent,omitempty"`
	MonitorDegradedRttMs       nullableFloat `json:"monitor_degraded_rtt_ms,omitempty"`
	MonitorStateChangeSamples  nullableInt   `json:"monitor_state_change_samples,omitempty"`

	AddressPoolID nullableInt              `json:"address_pool_id,omitempty"`
	Addresses     *[]validate.AddressInput `json:"addresses,omitempty"`
	IsEnabled     *bool                    `json:"is_enabled,omitempty"`
	Force         *bool                    `json:"force,omitempty"`

	// The confirmations some operations require (§9.6, §17.3, §17.4).
	ConfirmRecreate           bool    `json:"confirm_recreate,omitempty"`
	IUnderstandIMayLoseAccess bool    `json:"i_understand_i_may_lose_access,omitempty"`
	Takeover                  bool    `json:"takeover,omitempty"`
	KeepaliveEnabled          *bool   `json:"keepalive_enabled,omitempty"`
	IdempotencyKey            *string `json:"idempotency_key,omitempty"`
}

// applyTo overlays the supplied fields onto a tunnel description.
func (p tunnelPatch) applyTo(in *validate.TunnelInput) {
	setInt := func(dst *int64, src *int64) {
		if src != nil {
			*dst = *src
		}
	}
	setString := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	setBool := func(dst *bool, src *bool) {
		if src != nil {
			*dst = *src
		}
	}
	setNullable := func(dst **int64, src nullableInt) {
		if src.Set {
			*dst = src.Value
		}
	}
	setNullableFloat := func(dst **float64, src nullableFloat) {
		if src.Set {
			*dst = src.Value
		}
	}

	setInt(&in.TunnelTypeID, p.TunnelTypeID)
	setInt(&in.TunnelSideID, p.TunnelSideID)
	setInt(&in.PersistenceTypeID, p.PersistenceTypeID)
	setString(&in.InterfaceName, p.InterfaceName)
	setString(&in.DisplayName, p.DisplayName)
	setNullable(&in.TunnelNumber, p.TunnelNumber)

	setString(&in.LocalEndpoint, p.LocalEndpoint)
	setString(&in.RemoteEndpoint, p.RemoteEndpoint)
	setString(&in.BindDevice, p.BindDevice)

	setInt(&in.Ttl, p.Ttl)
	setString(&in.Tos, p.Tos)
	setInt(&in.Mtu, p.Mtu)
	setNullable(&in.IKey, p.IKey)
	setNullable(&in.OKey, p.OKey)

	setBool(&in.HasInputChecksum, p.HasInputChecksum)
	setBool(&in.HasOutputChecksum, p.HasOutputChecksum)
	setBool(&in.HasInputSequence, p.HasInputSequence)
	setBool(&in.HasOutputSequence, p.HasOutputSequence)
	setBool(&in.IsPathMtuDiscovery, p.IsPathMtuDiscovery)
	setBool(&in.IsIgnoreDf, p.IsIgnoreDf)

	setNullable(&in.FwMark, p.FwMark)
	setNullable(&in.TxQueueLength, p.TxQueueLength)
	setNullable(&in.HopLimit, p.HopLimit)
	setNullable(&in.EncapLimit, p.EncapLimit)
	setString(&in.TrafficClass, p.TrafficClass)
	setString(&in.FlowLabel, p.FlowLabel)

	setNullableFloat(&in.MonitorIntervalSeconds, p.MonitorIntervalSeconds)
	setNullableFloat(&in.MonitorTimeoutSeconds, p.MonitorTimeoutSeconds)
	setNullable(&in.MonitorPacketSize, p.MonitorPacketSize)
	setNullable(&in.MonitorWindowSize, p.MonitorWindowSize)
	setNullableFloat(&in.MonitorDegradedLossPercent, p.MonitorDegradedLossPercent)
	setNullableFloat(&in.MonitorDownLossPercent, p.MonitorDownLossPercent)
	setNullableFloat(&in.MonitorDegradedRttMs, p.MonitorDegradedRttMs)
	setNullable(&in.MonitorStateChangeSamples, p.MonitorStateChangeSamples)

	setNullable(&in.AddressPoolID, p.AddressPoolID)
	if p.Addresses != nil {
		in.Addresses = *p.Addresses
	}
	setBool(&in.IsEnabled, p.IsEnabled)
	setBool(&in.Force, p.Force)
}

// request builds the service request from a patch overlaid on a starting point.
func (p tunnelPatch) request(base validate.TunnelInput, clientIP string) tunnel.Request {
	p.applyTo(&base)
	req := tunnel.Request{
		TunnelInput:               base,
		ConfirmRecreate:           p.ConfirmRecreate,
		IUnderstandIMayLoseAccess: p.IUnderstandIMayLoseAccess,
		Takeover:                  p.Takeover,
		KeepaliveEnabled:          p.KeepaliveEnabled,
		ClientIP:                  clientIP,
	}
	if p.IdempotencyKey != nil {
		req.IdempotencyKey = *p.IdempotencyKey
	}
	return req
}

// newTunnelRequest is the starting point for a create: an empty description
// that IsEnabled defaults to true on, because a tunnel nobody asked to be down
// is meant to come up.
func newTunnelRequest() validate.TunnelInput {
	return validate.TunnelInput{IsEnabled: true}
}
