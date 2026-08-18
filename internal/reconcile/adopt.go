package reconcile

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/persist"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// AdoptRequest asks the panel to take over an interface that already exists.
type AdoptRequest struct {
	InterfaceName string `json:"interface_name"`
	// TunnelSideID overrides the slot. For a tunnel the old script created the
	// slot is inferred from the name and this is not needed.
	TunnelSideID *int64 `json:"tunnel_side_id,omitempty"`
	// PersistenceTypeID overrides how the adopted tunnel is persisted. By
	// default it keeps whatever it already has.
	PersistenceTypeID *int64 `json:"persistence_type_id,omitempty"`
	AddressPoolID     *int64 `json:"address_pool_id,omitempty"`
	Note              string `json:"note,omitempty"`
	// Takeover rewrites the unit file that currently owns this interface in the
	// panel's corrected format, after backing the original up (§12, §17.3).
	Takeover bool `json:"takeover,omitempty"`
}

// AdoptResult reports what was imported and what was touched.
type AdoptResult struct {
	Tunnel   tunnel.Record      `json:"tunnel"`
	Legacy   *LegacyInfo        `json:"legacy,omitempty"`
	Imported map[string]any     `json:"imported"`
	Warnings []validate.Warning `json:"warnings,omitempty"`
	// UnitsTakenOver and Backups record the files the panel now owns and where
	// the originals were saved.
	UnitsTakenOver []string `json:"units_taken_over,omitempty"`
	Backups        []string `json:"backups,omitempty"`
	// InterfaceBounced is always false and is reported so the answer to "did
	// adopting this interrupt my tunnel?" is explicit rather than implied.
	InterfaceBounced bool `json:"interface_bounced"`
}

// Warning codes specific to adoption.
const (
	WarnLegacyUnitNotOwned = "LEGACY_UNIT_NOT_OWNED"
	WarnNoPeerAddress      = "NO_PEER_ADDRESS"
	WarnPublicRangeAdopted = "PUBLIC_RANGE_ADOPTED"
	WarnUnitNotActive      = "ADOPTED_UNIT_NOT_ACTIVE"
)

// Adopt imports an existing tunnel into the panel (§12).
//
// Adoption is strictly non-disruptive. Every parameter is read from the kernel,
// nothing is written to the interface, and the name is kept exactly as it is:
// renaming an interface tears the link down, which would defeat the entire
// purpose of adopting a working tunnel instead of rebuilding it.
func (s *Service) Adopt(ctx context.Context, req AdoptRequest) (AdoptResult, error) {
	name := strings.TrimSpace(req.InterfaceName)
	if err := validate.InterfaceName(name); err != nil {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidName, "The interface name "+err.Error()+".", nil)
		return AdoptResult{}, errs
	}

	observed, err := s.Links.Get(ctx, name)
	if err != nil {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidName,
			fmt.Sprintf("No interface called %q exists on this host.", name), nil)
		return AdoptResult{}, errs
	}
	if !observed.IsTunnel() {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidName,
			fmt.Sprintf("%q is a %s interface, not a tunnel. The panel manages tunnels only.",
				name, observed.Kind), nil)
		return AdoptResult{}, errs
	}
	if existing, err := s.Repo.ByInterfaceName(ctx, name); err == nil {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeNameConflict,
			fmt.Sprintf("The panel already manages %q as tunnel %d.", name, existing.TunnelID), nil)
		return AdoptResult{}, errs
	}

	result := AdoptResult{Imported: map[string]any{}}
	legacy, isLegacy := ParseLegacyName(name)

	in, warnings, err := s.importFrom(observed, req, legacy, isLegacy)
	if err != nil {
		return AdoptResult{}, err
	}
	result.Warnings = warnings

	// The unit file decides how this tunnel is persisted, unless the request
	// says otherwise.
	unitPath := s.Store.UnitPath(name)
	unitExists := persist.Exists(unitPath)
	unitOwned := false
	if unitExists {
		unitOwned, _ = persist.IsPanelOwned(unitPath)
	}
	if req.PersistenceTypeID != nil {
		in.PersistenceTypeID = *req.PersistenceTypeID
	} else if unitExists {
		in.PersistenceTypeID = model.PersistenceTypeSystemd
	} else {
		in.PersistenceTypeID = model.PersistenceTypeRuntime
	}

	if isLegacy {
		legacy.UnitPath = ""
		if unitExists {
			legacy.UnitPath = unitPath
			legacy.IsPanelOwned = unitOwned
		}
		keepalivePath := filepath.Join(s.Store.SystemdDir, legacyKeepalivePrefix+name+persist.UnitSuffix)
		if persist.Exists(keepalivePath) {
			legacy.KeepalivePath = keepalivePath
		}
		result.Legacy = &legacy
	}

	// Only the syntactic rules apply here: the tunnel already exists, so the
	// conflict rules would object to the very interface being adopted.
	if errs := validate.ValidateStatic(in); !errs.Empty() {
		return AdoptResult{}, errs
	}

	// IsNameTemplated is deliberately false: this name came from somewhere else
	// and regenerating it from the template later would rename the interface
	// and tear the tunnel down (§12).
	id, err := s.Repo.Insert(ctx, in, true, false)
	if err != nil {
		return AdoptResult{}, err
	}
	// The tunnel is already running exactly as described, so it is Applied from
	// the moment it is adopted; nothing was changed to make that true.
	if err := s.Repo.SetApplyStatus(ctx, id, model.ApplyStatusApplied, nil); err != nil {
		return AdoptResult{}, err
	}

	if req.Takeover && unitExists && !unitOwned {
		taken, backups, err := s.takeOverUnits(ctx, name, id, isLegacy)
		if err != nil {
			return AdoptResult{}, err
		}
		result.UnitsTakenOver = taken
		result.Backups = backups

		// The interface is deliberately not bounced, so the rewritten unit has
		// not run. Saying so is the difference between this panel and the script
		// it replaces, which reported units it had never successfully started.
		if active, state, err := s.Store.IsActive(ctx, persist.UnitName(name)); err == nil && !active {
			result.Warnings = append(result.Warnings, validate.Warning{
				Code:  WarnUnitNotActive,
				Field: "takeover",
				Message: fmt.Sprintf("The unit %s is %s: the interface was left running untouched, so the "+
					"rewritten unit has not been run and a reboot is the first time it would be. Reapply "+
					"this tunnel during a maintenance window to prove it works, which briefly interrupts it.",
					persist.UnitName(name), state),
				Details: map[string]any{"unit": persist.UnitName(name), "state": state},
			})
		}
	} else if unitExists && !unitOwned {
		result.Warnings = append(result.Warnings, validate.Warning{
			Code:  WarnLegacyUnitNotOwned,
			Field: "takeover",
			Message: fmt.Sprintf("%s still owns this interface at boot and was not written by the panel. "+
				"Until you adopt with takeover, the panel will refuse to change or remove it, and a "+
				"reboot applies whatever that file says.", unitPath),
			Details: map[string]any{"unit_path": unitPath},
		})
	}

	stored, err := s.Repo.ByID(ctx, id)
	if err != nil {
		return AdoptResult{}, err
	}
	result.Tunnel = stored
	result.Imported = importedSummary(observed)
	result.InterfaceBounced = false
	return result, nil
}

// importFrom builds the tunnel description from what the kernel reports.
func (s *Service) importFrom(observed link.Link, req AdoptRequest,
	legacy LegacyInfo, isLegacy bool) (validate.TunnelInput, []validate.Warning, error) {

	typeID, ok := model.TunnelTypeForKind(observed.Kind)
	if !ok {
		errs := &validate.Errors{}
		errs.Add("interface_name", validate.CodeInvalidType,
			fmt.Sprintf("%q is a %s interface, which this panel does not model.", observed.Name, observed.Kind), nil)
		return validate.TunnelInput{}, nil, errs
	}

	in := validate.TunnelInput{
		TunnelTypeID:  typeID,
		InterfaceName: observed.Name,
		Mtu:           int64(observed.MTU),
		Tos:           "inherit",
		AddressPoolID: req.AddressPoolID,
		IsEnabled:     observed.IsUp,
	}

	switch {
	case req.TunnelSideID != nil:
		in.TunnelSideID = *req.TunnelSideID
	case isLegacy:
		// The script gave its first side marker the .1 address and the second the
		// .2 address, which is exactly the panel's slot rule, so the mapping
		// carries over without guessing.
		in.TunnelSideID = legacy.TunnelSideID
	default:
		in.TunnelSideID = model.TunnelSideA
	}
	if isLegacy {
		number := legacy.TunnelNumber
		in.TunnelNumber = &number
	}

	if observed.Tunnel != nil {
		t := observed.Tunnel
		in.LocalEndpoint = t.Local
		in.RemoteEndpoint = t.Remote
		in.Ttl = int64(t.Ttl)
		in.BindDevice = t.BindDevice
		in.HasInputChecksum = t.HasInputChecksum
		in.HasOutputChecksum = t.HasOutputChecksum
		in.HasInputSequence = t.HasInputSequence
		in.HasOutputSequence = t.HasOutputSequence
		in.IsPathMtuDiscovery = t.IsPathMtuDiscovery
		in.IsIgnoreDf = t.IsIgnoreDf
		if t.Tos != "" {
			in.Tos = t.Tos
		}
		in.IKey = keyInt(t.IKey)
		in.OKey = keyInt(t.OKey)
		if t.FwMark != nil {
			mark := int64(*t.FwMark)
			in.FwMark = &mark
		}
		if t.HopLimit != nil {
			hop := int64(*t.HopLimit)
			in.HopLimit = &hop
		}
		if t.EncapLimit != nil {
			limit := int64(*t.EncapLimit)
			in.EncapLimit = &limit
		}
	}

	var warnings []validate.Warning
	for _, addr := range observed.Addresses {
		if addr.Scope == "link" {
			continue // the kernel's own link-local address, not configuration
		}
		imported := validate.AddressInput{
			Address:      addr.Address,
			PrefixLength: addr.PrefixLength,
			PeerAddress:  addr.Peer,
			IsPrimary:    len(in.Addresses) == 0,
		}
		if imported.PeerAddress == "" {
			if peer, ok := peerWithinSubnet(addr); ok {
				imported.PeerAddress = peer
			} else {
				warnings = append(warnings, validate.Warning{
					Code:  WarnNoPeerAddress,
					Field: "addresses",
					Message: fmt.Sprintf("The peer address for %s could not be worked out from its subnet, "+
						"so monitoring has no target until you set one.", addr),
				})
			}
		}
		if parsed, err := netip.ParseAddr(addr.Address); err == nil && validate.IsPublicRange(parsed) {
			warnings = append(warnings, validate.Warning{
				Code:  WarnPublicRangeAdopted,
				Field: "addresses",
				Message: fmt.Sprintf("This tunnel uses %s, which is globally routable. It is adopted as it "+
					"is, but it squats on address space belonging to someone else and blackholes those "+
					"destinations from this server.", addr),
			})
		}
		in.Addresses = append(in.Addresses, imported)
	}
	return in, warnings, nil
}

// peerWithinSubnet works out the other end's address from a point-to-point
// subnet: on a /30 or /31 there is exactly one other usable address.
func peerWithinSubnet(addr link.Address) (string, bool) {
	prefix, err := addr.Prefix()
	if err != nil {
		return "", false
	}
	self := prefix.Addr()
	network := prefix.Masked()

	// Only a two-address point-to-point subnet has an unambiguous answer. On
	// anything wider the peer could be any of several addresses, and guessing
	// would give monitoring a target that is not the other end of the tunnel.
	switch {
	case self.Is4() && (prefix.Bits() == 30 || prefix.Bits() == 31):
	case !self.Is4() && (prefix.Bits() == 126 || prefix.Bits() == 127):
	default:
		return "", false
	}

	first := network.Addr()
	if (self.Is4() && prefix.Bits() == 30) || (!self.Is4() && prefix.Bits() == 126) {
		first = first.Next() // skip the network address
	}
	second := first.Next()

	switch self {
	case first:
		return second.String(), true
	case second:
		return first.String(), true
	}
	return "", false
}

func importedSummary(observed link.Link) map[string]any {
	out := map[string]any{
		"interface_name": observed.Name,
		"kind":           observed.Kind,
		"mtu":            observed.MTU,
		"oper_state":     observed.OperState,
		"is_up":          observed.IsUp,
	}
	if observed.Tunnel != nil {
		out["local_endpoint"] = observed.Tunnel.Local
		out["remote_endpoint"] = observed.Tunnel.Remote
		out["ttl"] = observed.Tunnel.Ttl
		out["ikey"] = keyInt(observed.Tunnel.IKey)
		out["okey"] = keyInt(observed.Tunnel.OKey)
	}
	addresses := make([]string, 0, len(observed.Addresses))
	for _, a := range observed.Addresses {
		addresses = append(addresses, a.String())
	}
	out["addresses"] = addresses
	return out
}

// takeOverUnits rewrites the unit files that currently own an adopted interface
// in the panel's corrected format, backing each original up first (§12, §17.3).
//
// The interface itself is not touched. The unit is a oneshot that systemd
// already considers active, so rewriting the file and reloading does not stop
// or restart anything; a reboot is when the corrected version takes effect.
func (s *Service) takeOverUnits(ctx context.Context, name string, id int64, isLegacy bool) ([]string, []string, error) {
	rec, err := s.Repo.ByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}

	var taken, backups []string
	unitPath := s.Store.UnitPath(name)
	body := s.Renderer.Unit(tunnel.SpecOf(rec), tunnel.AddressesOf(rec))

	backup, err := s.Store.Write(ctx, unitPath, body, true)
	if err != nil {
		return nil, nil, fmt.Errorf("taking over %s: %w", unitPath, err)
	}
	taken = append(taken, unitPath)
	if backup != "" {
		backups = append(backups, backup)
	}

	// The script's separate keepalive unit is superseded by the panel's own
	// prober, so it is backed up and removed rather than rewritten.
	if isLegacy {
		keepalivePath := filepath.Join(s.Store.SystemdDir, legacyKeepalivePrefix+name+persist.UnitSuffix)
		if persist.Exists(keepalivePath) {
			unit := legacyKeepalivePrefix + name + persist.UnitSuffix
			_ = s.Store.Stop(ctx, unit)
			_ = s.Store.Disable(ctx, unit)
			backup, err := s.Store.Remove(ctx, keepalivePath, true)
			if err != nil {
				return taken, backups, fmt.Errorf("taking over %s: %w", keepalivePath, err)
			}
			taken = append(taken, keepalivePath)
			if backup != "" {
				backups = append(backups, backup)
			}
		}
	}

	if err := s.Store.DaemonReload(ctx); err != nil {
		return taken, backups, err
	}
	// Enabling is safe: it creates a symlink and does not start, stop or
	// otherwise disturb the running interface.
	if err := s.Store.Enable(ctx, persist.UnitName(name)); err != nil {
		return taken, backups, err
	}
	return taken, backups, nil
}
