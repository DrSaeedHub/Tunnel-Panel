package tunnel

import (
	"fmt"
	"strings"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/validate"
)

// Step kinds. They are stable strings because a plan is serialised into the
// preview response and into the audit log.
const (
	StepLinkCreate      = "link_create"
	StepLinkDelete      = "link_delete"
	StepLinkUp          = "link_up"
	StepLinkDown        = "link_down"
	StepLinkSetMtu      = "link_set_mtu"
	StepLinkSetTxQueue  = "link_set_txqueuelen"
	StepAddressAdd      = "address_add"
	StepAddressRemove   = "address_remove"
	StepFileWrite       = "file_write"
	StepFileRemove      = "file_remove"
	StepDaemonReload    = "systemd_daemon_reload"
	StepUnitEnable      = "systemd_enable"
	StepUnitDisable     = "systemd_disable"
	StepUnitStart       = "systemd_start"
	StepUnitStop        = "systemd_stop"
	StepUnitRestart     = "systemd_restart"
	StepUnitResetFailed = "systemd_reset_failed"
	StepNetworkdReload  = "networkd_reload"
)

// Operation names.
const (
	OpCreate  = "create"
	OpUpdate  = "update"
	OpDelete  = "delete"
	OpUp      = "up"
	OpDown    = "down"
	OpRestart = "restart"
	OpReapply = "reapply"
	OpAdopt   = "adopt"
)

// File kinds reported in a preview.
const (
	FileSystemdUnit   = "systemd_unit"
	FileKeepaliveUnit = "systemd_keepalive_unit"
	FileNetdev        = "networkd_netdev"
	FileNetwork       = "networkd_network"
)

// Step is one operation of a plan. Exactly one of the kind-specific fields is
// meaningful for any given kind; the rest are omitted from the JSON.
//
// Argv is filled in for every step that can be expressed as a command, even for
// the ones carried out through netlink, so the preview shows the operator
// something concrete and the audit trail reads the same way whichever path ran.
type Step struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`

	Interface string   `json:"interface,omitempty"`
	Argv      []string `json:"argv,omitempty"`

	Path     string `json:"path,omitempty"`
	Content  string `json:"content,omitempty"`
	FileKind string `json:"file_kind,omitempty"`
	Unit     string `json:"unit,omitempty"`

	Mtu           int              `json:"mtu,omitempty"`
	TxQueueLength int              `json:"tx_queue_length,omitempty"`
	Address       *link.Address    `json:"address,omitempty"`
	Spec          *link.TunnelSpec `json:"spec,omitempty"`

	// Takeover permits writing over or deleting a file the panel does not own.
	// It reaches the file store only when the tunnel was adopted with it set.
	Takeover bool `json:"takeover,omitempty"`
	// Tolerate marks a step whose failure does not fail the plan, which is how
	// cleanup steps are expressed. It is never set on a step that establishes
	// state.
	Tolerate bool `json:"tolerate,omitempty"`
}

// PlannedFile is a rendered file the plan would write, returned by the preview
// endpoint so the operator sees the exact unit body before committing (§9.2).
type PlannedFile struct {
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Plan is the ordered, serialisable list of everything an operation would do,
// plus the inverse plan that undoes it (§9.1).
//
// Planning is completely deterministic: the same request against the same state
// produces the same plan, byte for byte, which is what makes the preview
// endpoint trustworthy.
type Plan struct {
	Operation string `json:"operation"`
	Interface string `json:"interface"`
	TunnelID  int64  `json:"tunnel_id,omitempty"`

	Steps    []Step `json:"steps"`
	Rollback []Step `json:"rollback"`

	Files []PlannedFile `json:"files"`

	// RequiresRecreate reports that the change cannot be applied to the running
	// interface and needs it deleted and built again (§9.6).
	RequiresRecreate bool     `json:"requires_recreate"`
	RecreateReasons  []string `json:"recreate_reasons,omitempty"`

	Warnings []validate.Warning `json:"warnings,omitempty"`
	// Verification lists what will be checked after the plan runs, so the
	// preview shows that success is not going to be assumed (§9.3).
	Verification []string `json:"verification,omitempty"`
}

// Add appends a step.
func (p *Plan) Add(s Step) { p.Steps = append(p.Steps, s) }

// AddRollback appends an inverse step. The inverse plan is built in the order
// it will run, which is the reverse of the order the steps were planned in, so
// callers prepend rather than append.
func (p *Plan) AddRollback(s Step) { p.Rollback = append([]Step{s}, p.Rollback...) }

// AddFile records a rendered file for the preview.
func (p *Plan) AddFile(kind, path, content string) {
	p.Files = append(p.Files, PlannedFile{Kind: kind, Path: path, Content: content})
}

// IsEmpty reports whether the plan would do nothing.
func (p *Plan) IsEmpty() bool { return len(p.Steps) == 0 }

// Summary renders the plan as one line per step, for a log entry.
func (p *Plan) Summary() []string {
	out := make([]string, 0, len(p.Steps))
	for _, s := range p.Steps {
		out = append(out, s.Kind+": "+s.Description)
	}
	return out
}

// SpecOf builds the link specification for a tunnel record. It is the single
// translation from stored state to what the kernel and the unit file are told,
// so the two can never be given different things.
func SpecOf(rec Record) link.TunnelSpec {
	spec := link.TunnelSpec{
		Name:   rec.InterfaceName,
		Kind:   model.TunnelTypeKind(rec.TunnelTypeID),
		Local:  rec.LocalEndpoint,
		Remote: rec.RemoteEndpoint,
		Ttl:    int(rec.Ttl),
		Tos:    rec.Tos,
		Mtu:    int(rec.Mtu),

		HasInputChecksum:  rec.HasInputChecksum,
		HasOutputChecksum: rec.HasOutputChecksum,
		HasInputSequence:  rec.HasInputSequence,
		HasOutputSequence: rec.HasOutputSequence,

		IsPathMtuDiscovery: rec.IsPathMtuDiscovery,
		IsIgnoreDf:         rec.IsIgnoreDf,
		TrafficClass:       derefString(rec.TrafficClass),
		FlowLabel:          derefString(rec.FlowLabel),
	}
	if rec.BindDevice != nil {
		spec.BindDevice = *rec.BindDevice
	}
	if rec.IKey != nil {
		key := uint32(*rec.IKey)
		spec.IKey = &key
	}
	if rec.OKey != nil {
		key := uint32(*rec.OKey)
		spec.OKey = &key
	}
	if rec.FwMark != nil {
		mark := uint32(*rec.FwMark)
		spec.FwMark = &mark
	}
	if rec.TxQueueLength != nil {
		length := int(*rec.TxQueueLength)
		spec.TxQueueLength = &length
	}
	if rec.HopLimit != nil {
		hop := int(*rec.HopLimit)
		spec.HopLimit = &hop
	}
	if rec.EncapLimit != nil {
		limit := int(*rec.EncapLimit)
		spec.EncapLimit = &limit
	}
	return spec
}

// SpecOfInput builds the link specification from a request, for previewing a
// tunnel that has not been stored yet.
func SpecOfInput(in validate.TunnelInput) link.TunnelSpec {
	return SpecOf(Record{Tunnel: recordFromInput(in)})
}

// AddressesOf converts stored addresses into the link layer's form.
func AddressesOf(rec Record) []link.Address {
	out := make([]link.Address, 0, len(rec.Addresses))
	for _, a := range rec.Addresses {
		out = append(out, link.Address{
			Address:      a.Address,
			PrefixLength: int(a.PrefixLength),
			Peer:         derefString(a.PeerAddress),
			Family:       familyName(a.AddressFamilyID),
		})
	}
	return out
}

// AddressesOfInput converts a request's addresses into the link layer's form.
func AddressesOfInput(in validate.TunnelInput) []link.Address {
	out := make([]link.Address, 0, len(in.Addresses))
	for _, a := range in.Addresses {
		family := link.FamilyIPv4
		if strings.Contains(a.Address, ":") {
			family = link.FamilyIPv6
		}
		out = append(out, link.Address{
			Address: a.Address, PrefixLength: a.PrefixLength, Peer: a.PeerAddress, Family: family,
		})
	}
	return out
}

func familyName(id int64) string {
	if id == model.AddressFamilyIPv6 {
		return link.FamilyIPv6
	}
	return link.FamilyIPv4
}

// recordFromInput builds an in-memory record from a request, so previewing an
// unsaved tunnel goes through exactly the same planning code as applying a
// stored one.
func recordFromInput(in validate.TunnelInput) model.Tunnel {
	t := model.Tunnel{
		TunnelID:          in.TunnelID,
		TunnelTypeID:      in.TunnelTypeID,
		TunnelSideID:      in.TunnelSideID,
		PersistenceTypeID: in.PersistenceTypeID,
		InterfaceName:     in.InterfaceName,
		DisplayName:       stringPtr(in.DisplayName),
		TunnelNumber:      in.TunnelNumber,
		LocalEndpoint:     in.LocalEndpoint,
		RemoteEndpoint:    in.RemoteEndpoint,
		Ttl:               in.Ttl,
		Tos:               in.Tos,
		Mtu:               in.Mtu,
		IKey:              in.IKey,
		OKey:              in.OKey,

		HasInputChecksum:  in.HasInputChecksum,
		HasOutputChecksum: in.HasOutputChecksum,
		HasInputSequence:  in.HasInputSequence,
		HasOutputSequence: in.HasOutputSequence,

		IsPathMtuDiscovery: in.IsPathMtuDiscovery,
		IsIgnoreDf:         in.IsIgnoreDf,
		FwMark:             in.FwMark,
		TxQueueLength:      in.TxQueueLength,
		HopLimit:           in.HopLimit,
		EncapLimit:         in.EncapLimit,
		AddressPoolID:      in.AddressPoolID,
		IsEnabled:          in.IsEnabled,
		IsManaged:          true,

		MonitorIntervalSeconds:     in.MonitorIntervalSeconds,
		MonitorTimeoutSeconds:      in.MonitorTimeoutSeconds,
		MonitorPacketSize:          in.MonitorPacketSize,
		MonitorWindowSize:          in.MonitorWindowSize,
		MonitorDegradedLossPercent: in.MonitorDegradedLossPercent,
		MonitorDownLossPercent:     in.MonitorDownLossPercent,
		MonitorDegradedRttMs:       in.MonitorDegradedRttMs,
		MonitorStateChangeSamples:  in.MonitorStateChangeSamples,
	}
	if in.BindDevice != "" {
		device := in.BindDevice
		t.BindDevice = &device
	}
	if in.TrafficClass != "" {
		class := in.TrafficClass
		t.TrafficClass = &class
	}
	if in.FlowLabel != "" {
		label := in.FlowLabel
		t.FlowLabel = &label
	}
	return t
}

// RecordFromInput exposes the conversion for the preview path, where nothing
// has been stored yet.
func RecordFromInput(in validate.TunnelInput) Record {
	rec := Record{Tunnel: recordFromInput(in)}
	for i, a := range in.Addresses {
		family := int64(model.AddressFamilyIPv4)
		if strings.Contains(a.Address, ":") {
			family = model.AddressFamilyIPv6
		}
		rec.Addresses = append(rec.Addresses, model.TunnelAddress{
			TunnelID:        in.TunnelID,
			Address:         a.Address,
			PrefixLength:    int64(a.PrefixLength),
			PeerAddress:     stringPtr(a.PeerAddress),
			AddressFamilyID: family,
			IsPrimary:       a.IsPrimary || i == 0,
			SortOrder:       int64(i),
		})
	}
	return rec
}

func stringPtr(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

// KeepaliveFor describes the keepalive unit a tunnel would get, or reports that
// it gets none.
type KeepaliveFor struct {
	Enabled bool
	Options persist.KeepaliveOptions
}

// planner turns records into plans. It holds the rendering and path knowledge
// so the planning functions stay readable.
type planner struct {
	renderer      *persist.Renderer
	store         *persist.Store
	ipBin         string
	systemctlBin  string
	networkctlBin string
}

// PlanCreate builds the plan that brings a tunnel into being (§9.1).
//
// For systemd persistence the unit file is what configures the kernel: the plan
// writes it, reloads systemd, enables it and starts it. Doing it that way means
// the file and the running kernel cannot disagree, and — the point of the whole
// exercise — it proves the unit actually works now, rather than discovering at
// the next reboot that it never did. The legacy script enabled units it had
// never successfully run.
func (p *planner) PlanCreate(rec Record, keepalive KeepaliveFor, takeover bool) Plan {
	spec := SpecOf(rec)
	addresses := AddressesOf(rec)
	plan := Plan{
		Operation: OpCreate,
		Interface: rec.InterfaceName,
		TunnelID:  rec.TunnelID,
		Verification: []string{
			"the interface exists and is of the requested type",
			"the local endpoint, remote endpoint, TTL, MTU and keys match what was asked for",
			"every requested address is present with the right prefix length",
			"the flags include UP and LOWER_UP",
		},
	}

	switch rec.PersistenceTypeID {
	case model.PersistenceTypeSystemd:
		p.planSystemdCreate(&plan, rec, spec, addresses, keepalive, takeover)
	case model.PersistenceTypeNetworkd:
		p.planNetworkdCreate(&plan, rec, spec, addresses, takeover)
	default:
		p.planRuntimeCreate(&plan, spec, addresses)
	}
	return plan
}

func (p *planner) planSystemdCreate(plan *Plan, rec Record, spec link.TunnelSpec,
	addresses []link.Address, keepalive KeepaliveFor, takeover bool) {

	name := rec.InterfaceName
	unit := persist.UnitName(name)
	unitPath := p.store.UnitPath(name)
	body := p.renderer.Unit(spec, addresses)

	plan.AddFile(FileSystemdUnit, unitPath, body)
	plan.Add(Step{
		Kind: StepFileWrite, Description: "write the systemd unit " + unit,
		Path: unitPath, Content: body, FileKind: FileSystemdUnit, Unit: unit,
		Interface: name, Takeover: takeover,
	})
	plan.AddRollback(Step{
		Kind: StepFileRemove, Description: "remove the systemd unit " + unit,
		Path: unitPath, Unit: unit, Interface: name, Takeover: takeover, Tolerate: true,
	})

	if keepalive.Enabled {
		keepaliveUnit := persist.KeepaliveUnitName(name)
		keepalivePath := p.store.KeepaliveUnitPath(name)
		keepaliveBody := p.renderer.KeepaliveUnit(name, keepalive.Options)

		plan.AddFile(FileKeepaliveUnit, keepalivePath, keepaliveBody)
		plan.Add(Step{
			Kind: StepFileWrite, Description: "write the keepalive unit " + keepaliveUnit,
			Path: keepalivePath, Content: keepaliveBody, FileKind: FileKeepaliveUnit,
			Unit: keepaliveUnit, Interface: name, Takeover: takeover,
		})
		plan.AddRollback(Step{
			Kind: StepFileRemove, Description: "remove the keepalive unit " + keepaliveUnit,
			Path: keepalivePath, Unit: keepaliveUnit, Interface: name, Tolerate: true,
		})
	}

	// daemon-reload, never daemon-reexec.
	plan.Add(Step{
		Kind: StepDaemonReload, Description: "reload the systemd unit files",
		Argv: persist.DaemonReloadArgs(p.systemctlBin),
	})
	plan.Add(Step{
		Kind: StepUnitEnable, Description: "enable " + unit + " so the tunnel returns after a reboot",
		Unit: unit, Interface: name, Argv: persist.EnableArgs(p.systemctlBin, unit),
	})
	plan.AddRollback(Step{
		Kind: StepUnitDisable, Description: "disable " + unit,
		Unit: unit, Interface: name, Argv: persist.DisableArgs(p.systemctlBin, unit), Tolerate: true,
	})
	plan.Add(Step{
		Kind: StepUnitStart, Description: "start " + unit + ", which creates and configures the interface",
		Unit: unit, Interface: name, Argv: persist.StartArgs(p.systemctlBin, unit),
	})
	plan.AddRollback(Step{
		Kind: StepUnitStop, Description: "stop " + unit,
		Unit: unit, Interface: name, Argv: persist.StopArgs(p.systemctlBin, unit), Tolerate: true,
	})

	if keepalive.Enabled {
		keepaliveUnit := persist.KeepaliveUnitName(name)
		plan.Add(Step{
			Kind: StepUnitEnable, Description: "enable " + keepaliveUnit,
			Unit: keepaliveUnit, Interface: name,
			Argv: persist.EnableArgs(p.systemctlBin, keepaliveUnit),
		})
		plan.Add(Step{
			Kind: StepUnitStart, Description: "start " + keepaliveUnit,
			Unit: keepaliveUnit, Interface: name,
			Argv: persist.StartArgs(p.systemctlBin, keepaliveUnit),
		})
		plan.AddRollback(Step{
			Kind: StepUnitStop, Description: "stop " + keepaliveUnit,
			Unit: keepaliveUnit, Interface: name,
			Argv: persist.StopArgs(p.systemctlBin, keepaliveUnit), Tolerate: true,
		})
		plan.AddRollback(Step{
			Kind: StepUnitDisable, Description: "disable " + keepaliveUnit,
			Unit: keepaliveUnit, Interface: name,
			Argv: persist.DisableArgs(p.systemctlBin, keepaliveUnit), Tolerate: true,
		})
	}

	// The rollback ends by removing the interface, so a failed create leaves the
	// host exactly as it was found.
	plan.AddRollback(Step{
		Kind: StepLinkDelete, Description: "delete the interface " + name,
		Interface: name, Argv: link.DeleteArgs(p.ipBin, name), Tolerate: true,
	})
	plan.AddRollback(Step{
		Kind: StepDaemonReload, Description: "reload the systemd unit files",
		Argv: persist.DaemonReloadArgs(p.systemctlBin), Tolerate: true,
	})

	plan.Verification = append(plan.Verification, "the systemd unit is enabled and active")
}

func (p *planner) planNetworkdCreate(plan *Plan, rec Record, spec link.TunnelSpec,
	addresses []link.Address, takeover bool) {

	name := rec.InterfaceName

	// The kernel is configured through netlink first so the tunnel exists
	// immediately and deterministically; the networkd files are what bring it
	// back after a reboot. Reloading networkd afterwards makes it adopt the
	// device that is already there rather than racing to create it.
	p.planRuntimeCreate(plan, spec, addresses)

	netdevPath := p.store.NetdevPath(name)
	netdevBody := p.renderer.Netdev(spec)
	networkPath := p.store.NetworkPath(name)
	networkBody := p.renderer.Network(spec, addresses)

	plan.AddFile(FileNetdev, netdevPath, netdevBody)
	plan.AddFile(FileNetwork, networkPath, networkBody)

	plan.Add(Step{
		Kind: StepFileWrite, Description: "write " + persist.NetdevName(name),
		Path: netdevPath, Content: netdevBody, FileKind: FileNetdev, Interface: name, Takeover: takeover,
	})
	plan.AddRollback(Step{
		Kind: StepFileRemove, Description: "remove " + persist.NetdevName(name),
		Path: netdevPath, Interface: name, Tolerate: true,
	})
	plan.Add(Step{
		Kind: StepFileWrite, Description: "write " + persist.NetworkName(name),
		Path: networkPath, Content: networkBody, FileKind: FileNetwork, Interface: name, Takeover: takeover,
	})
	plan.AddRollback(Step{
		Kind: StepFileRemove, Description: "remove " + persist.NetworkName(name),
		Path: networkPath, Interface: name, Tolerate: true,
	})
	plan.Add(Step{
		Kind: StepNetworkdReload, Description: "reload systemd-networkd",
		Argv: p.networkdReloadArgs(), Tolerate: true,
	})
}

func (p *planner) planRuntimeCreate(plan *Plan, spec link.TunnelSpec, addresses []link.Address) {
	name := spec.Name

	plan.Add(Step{
		Kind: StepLinkCreate, Description: "create the interface " + name,
		Interface: name, Spec: &spec, Argv: link.CreateArgs(p.ipBin, spec),
	})
	plan.AddRollback(Step{
		Kind: StepLinkDelete, Description: "delete the interface " + name,
		Interface: name, Argv: link.DeleteArgs(p.ipBin, name), Tolerate: true,
	})

	for i := range addresses {
		addr := addresses[i]
		plan.Add(Step{
			Kind: StepAddressAdd, Description: fmt.Sprintf("add %s to %s", addr, name),
			Interface: name, Address: &addr, Argv: link.AddAddressArgs(p.ipBin, name, addr),
		})
	}
	if spec.Mtu > 0 {
		plan.Add(Step{
			Kind: StepLinkSetMtu, Description: fmt.Sprintf("set the MTU of %s to %d", name, spec.Mtu),
			Interface: name, Mtu: spec.Mtu, Argv: link.SetMTUArgs(p.ipBin, name, spec.Mtu),
		})
	}
	if spec.TxQueueLength != nil {
		plan.Add(Step{
			Kind:        StepLinkSetTxQueue,
			Description: fmt.Sprintf("set the transmit queue length of %s to %d", name, *spec.TxQueueLength),
			Interface:   name, TxQueueLength: *spec.TxQueueLength,
			Argv: link.SetTxQueueLenArgs(p.ipBin, name, *spec.TxQueueLength),
		})
	}
	plan.Add(Step{
		Kind: StepLinkUp, Description: "bring " + name + " up",
		Interface: name, Argv: link.SetUpArgs(p.ipBin, name),
	})
}

func (p *planner) networkdReloadArgs() []string {
	if strings.TrimSpace(p.networkctlBin) != "" {
		return []string{p.networkctlBin, "reload"}
	}
	return []string{p.systemctlBin, "reload-or-restart", "systemd-networkd.service"}
}

// PlanDelete builds the plan that removes a tunnel (§9.6).
//
// Every step is tolerant, because delete must be idempotent when the interface
// or the unit is already gone, and must report exactly what was and was not
// found rather than failing on the first absence.
func (p *planner) PlanDelete(rec Record, hadKeepalive, takeover bool) Plan {
	name := rec.InterfaceName
	plan := Plan{
		Operation: OpDelete,
		Interface: name,
		TunnelID:  rec.TunnelID,
		Verification: []string{
			"the interface is gone",
			"no unit file the panel wrote is left behind",
		},
	}

	if rec.PersistenceTypeID == model.PersistenceTypeSystemd {
		unit := persist.UnitName(name)
		if hadKeepalive {
			keepaliveUnit := persist.KeepaliveUnitName(name)
			plan.Add(Step{
				Kind: StepUnitStop, Description: "stop " + keepaliveUnit,
				Unit: keepaliveUnit, Interface: name,
				Argv: persist.StopArgs(p.systemctlBin, keepaliveUnit), Tolerate: true,
			})
			plan.Add(Step{
				Kind: StepUnitDisable, Description: "disable " + keepaliveUnit,
				Unit: keepaliveUnit, Interface: name,
				Argv: persist.DisableArgs(p.systemctlBin, keepaliveUnit), Tolerate: true,
			})
			plan.Add(Step{
				Kind: StepFileRemove, Description: "remove " + keepaliveUnit,
				Path: p.store.KeepaliveUnitPath(name), Unit: keepaliveUnit,
				Interface: name, Takeover: takeover, Tolerate: true,
			})
		}
		plan.Add(Step{
			Kind: StepUnitStop, Description: "stop " + unit,
			Unit: unit, Interface: name, Argv: persist.StopArgs(p.systemctlBin, unit), Tolerate: true,
		})
		plan.Add(Step{
			Kind: StepUnitDisable, Description: "disable " + unit,
			Unit: unit, Interface: name, Argv: persist.DisableArgs(p.systemctlBin, unit), Tolerate: true,
		})
		plan.Add(Step{
			Kind: StepFileRemove, Description: "remove " + unit,
			Path: p.store.UnitPath(name), Unit: unit, Interface: name, Takeover: takeover, Tolerate: true,
		})
		plan.Add(Step{
			Kind: StepDaemonReload, Description: "reload the systemd unit files",
			Argv: persist.DaemonReloadArgs(p.systemctlBin), Tolerate: true,
		})
	}

	if rec.PersistenceTypeID == model.PersistenceTypeNetworkd {
		plan.Add(Step{
			Kind: StepFileRemove, Description: "remove " + persist.NetdevName(name),
			Path: p.store.NetdevPath(name), Interface: name, Takeover: takeover, Tolerate: true,
		})
		plan.Add(Step{
			Kind: StepFileRemove, Description: "remove " + persist.NetworkName(name),
			Path: p.store.NetworkPath(name), Interface: name, Takeover: takeover, Tolerate: true,
		})
		plan.Add(Step{
			Kind: StepNetworkdReload, Description: "reload systemd-networkd",
			Argv: p.networkdReloadArgs(), Tolerate: true,
		})
	}

	// The link is deleted last, and tolerantly: stopping the unit has usually
	// removed it already, and an interface that is already gone is the requested
	// end state rather than a failure.
	plan.Add(Step{
		Kind: StepLinkDelete, Description: "delete the interface " + name,
		Interface: name, Argv: link.DeleteArgs(p.ipBin, name), Tolerate: true,
	})
	return plan
}

// inPlaceFields are the attributes the kernel can change on a live interface.
// Everything else needs the interface deleted and rebuilt (§9.6).
var inPlaceFields = map[string]bool{
	"mtu":              true,
	"tx_queue_length":  true,
	"addresses":        true,
	"is_enabled":       true,
	"note":             true,
	"tags":             true,
	"monitor_settings": true,
}

// Diff is one changed field between the stored tunnel and the requested one.
type Diff struct {
	Field    string `json:"field"`
	From     string `json:"from"`
	To       string `json:"to"`
	InPlace  bool   `json:"in_place"`
	Describe string `json:"describe,omitempty"`
}

// DiffTunnel compares the stored tunnel with the requested one, field by field.
// The result drives both the update plan and the explanation the preview shows.
func DiffTunnel(current Record, desired validate.TunnelInput) []Diff {
	var diffs []Diff
	add := func(field, from, to string) {
		if from == to {
			return
		}
		diffs = append(diffs, Diff{Field: field, From: from, To: to, InPlace: inPlaceFields[field]})
	}

	add("tunnel_type_id", itoa(current.TunnelTypeID), itoa(desired.TunnelTypeID))
	add("tunnel_side_id", itoa(current.TunnelSideID), itoa(desired.TunnelSideID))
	add("persistence_type_id", itoa(current.PersistenceTypeID), itoa(desired.PersistenceTypeID))
	add("interface_name", current.InterfaceName, desired.InterfaceName)
	add("local_endpoint", current.LocalEndpoint, desired.LocalEndpoint)
	add("remote_endpoint", current.RemoteEndpoint, desired.RemoteEndpoint)
	add("bind_device", derefString(current.BindDevice), desired.BindDevice)
	add("ttl", itoa(current.Ttl), itoa(desired.Ttl))
	add("tos", current.Tos, desired.Tos)
	add("mtu", itoa(current.Mtu), itoa(desired.Mtu))
	add("ikey", optInt(current.IKey), optInt(desired.IKey))
	add("okey", optInt(current.OKey), optInt(desired.OKey))
	add("has_input_checksum", boolText(current.HasInputChecksum), boolText(desired.HasInputChecksum))
	add("has_output_checksum", boolText(current.HasOutputChecksum), boolText(desired.HasOutputChecksum))
	add("has_input_sequence", boolText(current.HasInputSequence), boolText(desired.HasInputSequence))
	add("has_output_sequence", boolText(current.HasOutputSequence), boolText(desired.HasOutputSequence))
	add("is_path_mtu_discovery", boolText(current.IsPathMtuDiscovery), boolText(desired.IsPathMtuDiscovery))
	add("is_ignore_df", boolText(current.IsIgnoreDf), boolText(desired.IsIgnoreDf))
	add("fwmark", optInt(current.FwMark), optInt(desired.FwMark))
	add("tx_queue_length", optInt(current.TxQueueLength), optInt(desired.TxQueueLength))
	add("hop_limit", optInt(current.HopLimit), optInt(desired.HopLimit))
	add("encap_limit", optInt(current.EncapLimit), optInt(desired.EncapLimit))
	add("addresses", addressText(AddressesOf(current)), addressText(AddressesOfInput(desired)))
	add("is_enabled", boolText(current.IsEnabled), boolText(desired.IsEnabled))
	return diffs
}

// RequiresRecreate reports whether any of the changes needs the interface
// deleted and rebuilt, and why (§9.6).
func RequiresRecreate(diffs []Diff) (bool, []string) {
	var reasons []string
	for _, d := range diffs {
		if d.InPlace {
			continue
		}
		reasons = append(reasons, fmt.Sprintf("%s changes from %s to %s, which the kernel cannot alter "+
			"on a running tunnel", d.Field, quoteEmpty(d.From), quoteEmpty(d.To)))
	}
	return len(reasons) > 0, reasons
}

func quoteEmpty(s string) string {
	if s == "" {
		return `""`
	}
	return s
}

func addressText(addresses []link.Address) string {
	parts := make([]string, 0, len(addresses))
	for _, a := range addresses {
		text := a.String()
		if a.Peer != "" {
			text += " peer " + a.Peer
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, ", ")
}

func itoa(v int64) string { return fmt.Sprintf("%d", v) }

func optInt(v *int64) string {
	if v == nil {
		return ""
	}
	return itoa(*v)
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// PlanUpdate builds the plan for a change to an existing tunnel (§9.6).
//
// Changes the kernel can make on a live interface — the MTU, the transmit queue
// length and the addresses — are applied in place. Anything else needs the
// interface deleted and rebuilt, which the preview states explicitly and which
// the request has to confirm.
func (p *planner) PlanUpdate(current Record, desired Record, keepalive KeepaliveFor,
	diffs []Diff, takeover bool) Plan {

	recreate, reasons := RequiresRecreate(diffs)
	if recreate {
		plan := p.PlanCreate(desired, keepalive, takeover)
		plan.Operation = OpUpdate
		plan.TunnelID = current.TunnelID
		plan.RequiresRecreate = true
		plan.RecreateReasons = reasons

		// Rebuilding means removing what is there first. The teardown steps go in
		// front of the create steps, and the rollback rebuilds the tunnel as it
		// was, so a failed update leaves the previous tunnel running.
		teardown := p.PlanDelete(current, keepalive.Enabled, takeover)
		plan.Steps = append(teardown.Steps, plan.Steps...)

		restore := p.PlanCreate(current, keepalive, takeover)
		plan.Rollback = append(plan.Rollback, restore.Steps...)
		return plan
	}

	name := current.InterfaceName
	plan := Plan{
		Operation: OpUpdate,
		Interface: name,
		TunnelID:  current.TunnelID,
		Verification: []string{
			"every changed parameter matches what was asked for",
			"every requested address is present with the right prefix length",
			"the flags include UP and LOWER_UP",
		},
	}

	currentAddresses := AddressesOf(current)
	desiredAddresses := AddressesOf(desired)

	if current.Mtu != desired.Mtu {
		plan.Add(Step{
			Kind: StepLinkSetMtu, Description: fmt.Sprintf("set the MTU of %s to %d", name, desired.Mtu),
			Interface: name, Mtu: int(desired.Mtu),
			Argv: link.SetMTUArgs(p.ipBin, name, int(desired.Mtu)),
		})
		plan.AddRollback(Step{
			Kind: StepLinkSetMtu, Description: fmt.Sprintf("restore the MTU of %s to %d", name, current.Mtu),
			Interface: name, Mtu: int(current.Mtu),
			Argv: link.SetMTUArgs(p.ipBin, name, int(current.Mtu)),
		})
	}

	if desired.TxQueueLength != nil && !sameOptInt(current.TxQueueLength, desired.TxQueueLength) {
		length := int(*desired.TxQueueLength)
		plan.Add(Step{
			Kind:        StepLinkSetTxQueue,
			Description: fmt.Sprintf("set the transmit queue length of %s to %d", name, length),
			Interface:   name, TxQueueLength: length,
			Argv: link.SetTxQueueLenArgs(p.ipBin, name, length),
		})
		if current.TxQueueLength != nil {
			previous := int(*current.TxQueueLength)
			plan.AddRollback(Step{
				Kind:        StepLinkSetTxQueue,
				Description: fmt.Sprintf("restore the transmit queue length of %s to %d", name, previous),
				Interface:   name, TxQueueLength: previous,
				Argv: link.SetTxQueueLenArgs(p.ipBin, name, previous),
			})
		}
	}

	for _, addr := range removedAddresses(currentAddresses, desiredAddresses) {
		removed := addr
		plan.Add(Step{
			Kind: StepAddressRemove, Description: fmt.Sprintf("remove %s from %s", removed, name),
			Interface: name, Address: &removed, Argv: link.DelAddressArgs(p.ipBin, name, removed),
		})
		plan.AddRollback(Step{
			Kind: StepAddressAdd, Description: fmt.Sprintf("restore %s on %s", removed, name),
			Interface: name, Address: &removed, Argv: link.AddAddressArgs(p.ipBin, name, removed),
		})
	}
	for _, addr := range removedAddresses(desiredAddresses, currentAddresses) {
		added := addr
		plan.Add(Step{
			Kind: StepAddressAdd, Description: fmt.Sprintf("add %s to %s", added, name),
			Interface: name, Address: &added, Argv: link.AddAddressArgs(p.ipBin, name, added),
		})
		plan.AddRollback(Step{
			Kind: StepAddressRemove, Description: fmt.Sprintf("remove %s from %s", added, name),
			Interface: name, Address: &added, Argv: link.DelAddressArgs(p.ipBin, name, added),
		})
	}

	if current.IsEnabled != desired.IsEnabled {
		if desired.IsEnabled {
			plan.Add(Step{
				Kind: StepLinkUp, Description: "bring " + name + " up",
				Interface: name, Argv: link.SetUpArgs(p.ipBin, name),
			})
			plan.AddRollback(Step{
				Kind: StepLinkDown, Description: "bring " + name + " down again",
				Interface: name, Argv: link.SetDownArgs(p.ipBin, name),
			})
		} else {
			plan.Add(Step{
				Kind: StepLinkDown, Description: "bring " + name + " down",
				Interface: name, Argv: link.SetDownArgs(p.ipBin, name),
			})
			plan.AddRollback(Step{
				Kind: StepLinkUp, Description: "bring " + name + " up again",
				Interface: name, Argv: link.SetUpArgs(p.ipBin, name),
			})
		}
	}

	// The persistence files are rewritten so a reboot reproduces the new state,
	// but the unit is deliberately not restarted: restarting it would delete and
	// recreate the interface, which is exactly what applying in place avoids.
	p.planRewritePersistence(&plan, current, desired, keepalive, takeover)
	return plan
}

// planRewritePersistence rewrites the files describing a tunnel without
// disturbing the running interface.
func (p *planner) planRewritePersistence(plan *Plan, current, desired Record,
	keepalive KeepaliveFor, takeover bool) {

	name := desired.InterfaceName
	spec := SpecOf(desired)
	addresses := AddressesOf(desired)

	switch desired.PersistenceTypeID {
	case model.PersistenceTypeSystemd:
		unit := persist.UnitName(name)
		unitPath := p.store.UnitPath(name)
		body := p.renderer.Unit(spec, addresses)
		previous := p.renderer.Unit(SpecOf(current), AddressesOf(current))

		plan.AddFile(FileSystemdUnit, unitPath, body)
		plan.Add(Step{
			Kind: StepFileWrite, Description: "rewrite the systemd unit " + unit,
			Path: unitPath, Content: body, FileKind: FileSystemdUnit, Unit: unit,
			Interface: name, Takeover: takeover,
		})
		plan.AddRollback(Step{
			Kind: StepFileWrite, Description: "restore the previous systemd unit " + unit,
			Path: unitPath, Content: previous, FileKind: FileSystemdUnit, Unit: unit,
			Interface: name, Takeover: takeover,
		})

		if keepalive.Enabled {
			keepaliveUnit := persist.KeepaliveUnitName(name)
			keepalivePath := p.store.KeepaliveUnitPath(name)
			keepaliveBody := p.renderer.KeepaliveUnit(name, keepalive.Options)
			plan.AddFile(FileKeepaliveUnit, keepalivePath, keepaliveBody)
			plan.Add(Step{
				Kind: StepFileWrite, Description: "rewrite the keepalive unit " + keepaliveUnit,
				Path: keepalivePath, Content: keepaliveBody, FileKind: FileKeepaliveUnit,
				Unit: keepaliveUnit, Interface: name, Takeover: takeover,
			})
			plan.Add(Step{
				Kind: StepUnitRestart, Description: "restart " + keepaliveUnit,
				Unit: keepaliveUnit, Interface: name,
				Argv: persist.RestartArgs(p.systemctlBin, keepaliveUnit), Tolerate: true,
			})
		}

		plan.Add(Step{
			Kind: StepDaemonReload, Description: "reload the systemd unit files",
			Argv: persist.DaemonReloadArgs(p.systemctlBin),
		})
		plan.Verification = append(plan.Verification, "the systemd unit is enabled and active")

	case model.PersistenceTypeNetworkd:
		netdevPath := p.store.NetdevPath(name)
		netdevBody := p.renderer.Netdev(spec)
		networkPath := p.store.NetworkPath(name)
		networkBody := p.renderer.Network(spec, addresses)

		plan.AddFile(FileNetdev, netdevPath, netdevBody)
		plan.AddFile(FileNetwork, networkPath, networkBody)
		plan.Add(Step{
			Kind: StepFileWrite, Description: "rewrite " + persist.NetdevName(name),
			Path: netdevPath, Content: netdevBody, FileKind: FileNetdev, Interface: name, Takeover: takeover,
		})
		plan.Add(Step{
			Kind: StepFileWrite, Description: "rewrite " + persist.NetworkName(name),
			Path: networkPath, Content: networkBody, FileKind: FileNetwork, Interface: name, Takeover: takeover,
		})
		plan.Add(Step{
			Kind: StepNetworkdReload, Description: "reload systemd-networkd",
			Argv: p.networkdReloadArgs(), Tolerate: true,
		})
	}
}

// PlanUp builds the plan that brings a tunnel up (§9.6).
func (p *planner) PlanUp(rec Record) Plan {
	name := rec.InterfaceName
	plan := Plan{
		Operation: OpUp, Interface: name, TunnelID: rec.TunnelID,
		Verification: []string{"the flags include UP and LOWER_UP"},
	}
	plan.Add(Step{
		Kind: StepLinkUp, Description: "bring " + name + " up",
		Interface: name, Argv: link.SetUpArgs(p.ipBin, name),
	})
	plan.AddRollback(Step{
		Kind: StepLinkDown, Description: "bring " + name + " down again",
		Interface: name, Argv: link.SetDownArgs(p.ipBin, name), Tolerate: true,
	})
	if rec.PersistenceTypeID == model.PersistenceTypeSystemd {
		unit := persist.UnitName(name)
		plan.Add(Step{
			Kind: StepUnitEnable, Description: "enable " + unit + " so the tunnel returns after a reboot",
			Unit: unit, Interface: name, Argv: persist.EnableArgs(p.systemctlBin, unit), Tolerate: true,
		})
		plan.Verification = append(plan.Verification, "the systemd unit is enabled and active")
	}
	return plan
}

// PlanDown builds the plan that takes a tunnel down (§9.6).
//
// The interface is left in place rather than deleted: down is a state, not a
// removal, and an operator who wanted it gone would have said delete. The unit
// is disabled so a reboot does not quietly bring it back.
func (p *planner) PlanDown(rec Record) Plan {
	name := rec.InterfaceName
	plan := Plan{
		Operation: OpDown, Interface: name, TunnelID: rec.TunnelID,
		Verification: []string{"the interface is no longer up"},
	}
	plan.Add(Step{
		Kind: StepLinkDown, Description: "bring " + name + " down",
		Interface: name, Argv: link.SetDownArgs(p.ipBin, name),
	})
	plan.AddRollback(Step{
		Kind: StepLinkUp, Description: "bring " + name + " up again",
		Interface: name, Argv: link.SetUpArgs(p.ipBin, name), Tolerate: true,
	})
	if rec.PersistenceTypeID == model.PersistenceTypeSystemd {
		unit := persist.UnitName(name)
		plan.Add(Step{
			Kind: StepUnitDisable, Description: "disable " + unit + " so it does not return after a reboot",
			Unit: unit, Interface: name, Argv: persist.DisableArgs(p.systemctlBin, unit), Tolerate: true,
		})
	}
	return plan
}

// removedAddresses returns the entries of a that are not in b.
func removedAddresses(a, b []link.Address) []link.Address {
	var out []link.Address
	for _, candidate := range a {
		found := false
		for _, other := range b {
			if candidate.Equal(other) {
				found = true
				break
			}
		}
		if !found {
			out = append(out, candidate)
		}
	}
	return out
}

func sameOptInt(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
