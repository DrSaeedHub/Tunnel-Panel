package api

import (
	"context"
	_ "embed"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/link"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/pairing"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// sideInfoSummary is the canonical help text of §5.4, which the backend owns
// and the frontend renders beside the side selector.
//
// It lives in a data file rather than in a Go string literal for one specific
// reason: the text is quoted verbatim from the specification, and the sentence
// that makes its point names the very words this codebase must never use to
// label a side. Keeping it as data preserves the text exactly while leaving the
// Go source free of them.
//
//go:embed side_info.txt
var sideInfoSummary string

// tunnelResponse is one tunnel as the API reports it: the stored desired state
// plus what the kernel currently has, which are deliberately separate fields
// because conflating them is how a panel ends up reporting a tunnel as working
// when it is not.
type tunnelResponse struct {
	Tunnel   tunnel.Record `json:"tunnel"`
	Observed *observedLink `json:"observed"`
}

type observedLink struct {
	Exists         bool     `json:"exists"`
	Kind           string   `json:"kind,omitempty"`
	Index          int      `json:"index,omitempty"`
	Mtu            int      `json:"mtu,omitempty"`
	OperState      string   `json:"oper_state,omitempty"`
	IsUp           bool     `json:"is_up"`
	IsLowerUp      bool     `json:"is_lower_up"`
	Flags          []string `json:"flags,omitempty"`
	LocalEndpoint  string   `json:"local_endpoint,omitempty"`
	RemoteEndpoint string   `json:"remote_endpoint,omitempty"`
	Addresses      []string `json:"addresses,omitempty"`
}

func observe(l link.Link, exists bool) *observedLink {
	if !exists {
		return &observedLink{Exists: false}
	}
	out := &observedLink{
		Exists: true, Kind: l.Kind, Index: l.Index, Mtu: l.MTU,
		OperState: l.OperState, IsUp: l.IsUp, IsLowerUp: l.IsLowerUp, Flags: l.Flags,
	}
	if l.Tunnel != nil {
		out.LocalEndpoint = l.Tunnel.Local
		out.RemoteEndpoint = l.Tunnel.Remote
	}
	for _, a := range l.Addresses {
		out.Addresses = append(out.Addresses, a.String())
	}
	return out
}

// listResponse is the paginated envelope every list endpoint uses (§15).
type listResponse struct {
	Tunnels []tunnelResponse `json:"tunnels"`
	Total   int              `json:"total"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
}

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	records, err := s.tunnels.Repo().List(ctx)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	// One read of live state for the whole list rather than one per tunnel.
	observedByName := map[string]link.Link{}
	if links, err := s.tunnels.Links().List(ctx); err == nil {
		observedByName = link.ByName(links)
	}

	limit, offset := pagination(r)
	total := len(records)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	out := listResponse{Tunnels: []tunnelResponse{}, Total: total, Limit: limit, Offset: offset}
	for _, rec := range records[offset:end] {
		observedLink, exists := observedByName[rec.InterfaceName]
		out.Tunnels = append(out.Tunnels, tunnelResponse{
			Tunnel: rec, Observed: observe(observedLink, exists),
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetTunnel(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	observedLink, exists := s.observeInterface(r.Context(), rec.InterfaceName)
	writeJSON(w, http.StatusOK, tunnelResponse{Tunnel: rec, Observed: observe(observedLink, exists)})
}

// createResponse carries the tunnel, the plan that was carried out, the
// verification report, and the warnings (§15).
type createResponse struct {
	Tunnel       tunnel.Record       `json:"tunnel"`
	Plan         tunnel.Plan         `json:"plan"`
	Verification tunnel.VerifyReport `json:"verification"`
	Warnings     []Warning           `json:"warnings"`
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var patch tunnelPatch
	if !decodeJSON(w, r, &patch) {
		return
	}
	req := patch.request(newTunnelRequest(), ClientIP(r))

	result, err := s.tunnels.Create(r.Context(), req)
	if err != nil {
		s.auditTunnel(r, model.AuditActionTunnelCreate, req.InterfaceName, patch, nil, err, start)
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelCreate, result.Tunnel.InterfaceName, patch,
		result.Operations, nil, start)
	writeJSON(w, http.StatusCreated, createResponse{
		Tunnel: result.Tunnel, Plan: result.Plan, Verification: result.Verify,
		Warnings: warningsOf(result.Warnings),
	})
}

func (s *Server) handleUpdateTunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	var patch tunnelPatch
	if !decodeJSON(w, r, &patch) {
		return
	}
	// An update starts from what the tunnel already is, so a request that
	// mentions only the MTU changes only the MTU — and in particular does not
	// regenerate the interface name from the naming template, which would rename
	// the interface and tear the tunnel down.
	req := patch.request(tunnelInputOf(rec), ClientIP(r))

	result, err := s.tunnels.Update(r.Context(), rec.TunnelID, req)
	if err != nil {
		s.auditTunnel(r, model.AuditActionTunnelUpdate, rec.InterfaceName, patch, nil, err, start)
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelUpdate, rec.InterfaceName, patch, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, createResponse{
		Tunnel: result.Tunnel, Plan: result.Plan, Verification: result.Verify,
		Warnings: warningsOf(result.Warnings),
	})
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	var patch tunnelPatch
	if r.ContentLength > 0 {
		if !decodeJSON(w, r, &patch) {
			return
		}
	}
	req := patch.request(tunnelInputOf(rec), ClientIP(r))

	report, err := s.tunnels.Delete(r.Context(), rec.TunnelID, req)
	if err != nil {
		s.auditTunnel(r, model.AuditActionTunnelDelete, rec.InterfaceName, patch, report.Operations, err, start)
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelDelete, rec.InterfaceName, patch, report.Operations, nil, start)
	writeJSON(w, http.StatusOK, report)
}

// tunnelAction serves up, down, restart and reapply, which differ only in which
// service method they call and which audit action they record (§9.6).
func (s *Server) tunnelAction(action string, actionID int64,
	run func(context.Context, int64, tunnel.Request) (tunnel.Result, error)) http.HandlerFunc {

	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec, ok := s.tunnelFromPath(w, r)
		if !ok {
			return
		}

		var patch tunnelPatch
		if r.ContentLength > 0 {
			if !decodeJSON(w, r, &patch) {
				return
			}
		}
		req := patch.request(tunnelInputOf(rec), ClientIP(r))

		result, err := run(r.Context(), rec.TunnelID, req)
		if err != nil {
			s.auditTunnel(r, actionID, rec.InterfaceName, patch, nil, err, start)
			s.writeDomainError(w, r, err)
			return
		}

		s.auditTunnel(r, actionID, rec.InterfaceName, patch, result.Operations, nil, start)
		writeJSON(w, http.StatusOK, map[string]any{
			"action":       action,
			"tunnel":       result.Tunnel,
			"plan":         result.Plan,
			"verification": result.Verify,
			"warnings":     warningsOf(result.Warnings),
		})
	}
}

// previewResponse is the body of POST /tunnels/preview (§9.2).
type previewResponse struct {
	Plan     tunnel.Plan        `json:"plan"`
	Mtu      validate.MtuAdvice `json:"mtu"`
	Warnings []Warning          `json:"warnings"`
	Diffs    []tunnel.Diff      `json:"diffs,omitempty"`
	Tunnel   tunnel.Record      `json:"tunnel"`
}

// handlePreviewTunnel runs validate and plan only, returning the exact
// operations and unit file bodies that would run. Nothing is created, nothing
// is written, and nothing on the host is touched (§9.2).
func (s *Server) handlePreviewTunnel(w http.ResponseWriter, r *http.Request) {
	var patch tunnelPatch
	if !decodeJSON(w, r, &patch) {
		return
	}

	var (
		preview tunnel.Preview
		err     error
	)
	if patch.TunnelID != nil {
		rec, lookupErr := s.tunnels.Repo().ByID(r.Context(), *patch.TunnelID)
		if lookupErr != nil {
			s.writeDomainError(w, r, lookupErr)
			return
		}
		req := patch.request(tunnelInputOf(rec), ClientIP(r))
		preview, err = s.tunnels.PreviewUpdate(r.Context(), rec.TunnelID, req)
	} else {
		preview, err = s.tunnels.PreviewCreate(r.Context(), patch.request(newTunnelRequest(), ClientIP(r)))
	}
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, previewResponse{
		Plan: preview.Plan, Mtu: preview.Mtu, Diffs: preview.Diffs,
		Warnings: warningsOf(preview.Warnings), Tunnel: preview.Tunnel,
	})
}

// ---------------------------------------------------------------- addresses

type addressesResponse struct {
	Addresses []model.TunnelAddress `json:"addresses"`
	Observed  []string              `json:"observed"`
}

func (s *Server) handleListAddresses(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	out := addressesResponse{Addresses: rec.Addresses, Observed: []string{}}
	if observed, exists := s.observeInterface(r.Context(), rec.InterfaceName); exists {
		for _, a := range observed.Addresses {
			out.Observed = append(out.Observed, a.String())
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// addressRequest adds or removes one address on a tunnel.
type addressRequest struct {
	Address      string `json:"address"`
	PrefixLength int    `json:"prefix_length"`
	PeerAddress  string `json:"peer_address,omitempty"`
	IsPrimary    bool   `json:"is_primary,omitempty"`

	IUnderstandIMayLoseAccess bool `json:"i_understand_i_may_lose_access,omitempty"`
	Force                     bool `json:"force,omitempty"`
}

// handleAddAddress and handleRemoveAddress go through the ordinary update path
// rather than poking the kernel directly, so an address change is validated,
// planned, applied, verified and rolled back exactly like any other change.
func (s *Server) handleAddAddress(w http.ResponseWriter, r *http.Request) {
	s.changeAddresses(w, r, func(current []validate.AddressInput, req addressRequest) []validate.AddressInput {
		return append(current, validate.AddressInput{
			Address: req.Address, PrefixLength: req.PrefixLength,
			PeerAddress: req.PeerAddress, IsPrimary: req.IsPrimary,
		})
	})
}

func (s *Server) handleRemoveAddress(w http.ResponseWriter, r *http.Request) {
	s.changeAddresses(w, r, func(current []validate.AddressInput, req addressRequest) []validate.AddressInput {
		kept := make([]validate.AddressInput, 0, len(current))
		for _, a := range current {
			if a.Address == req.Address && (req.PrefixLength == 0 || a.PrefixLength == req.PrefixLength) {
				continue
			}
			kept = append(kept, a)
		}
		return kept
	})
}

func (s *Server) changeAddresses(w http.ResponseWriter, r *http.Request,
	mutate func([]validate.AddressInput, addressRequest) []validate.AddressInput) {

	start := time.Now()
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}
	var body addressRequest
	if !decodeJSON(w, r, &body) {
		return
	}

	in := tunnelInputOf(rec)
	in.Addresses = mutate(in.Addresses, body)
	in.Force = body.Force
	req := tunnel.Request{
		TunnelInput:               in,
		IUnderstandIMayLoseAccess: body.IUnderstandIMayLoseAccess,
		ClientIP:                  ClientIP(r),
	}

	result, err := s.tunnels.Update(r.Context(), rec.TunnelID, req)
	if err != nil {
		s.auditTunnel(r, model.AuditActionTunnelUpdate, rec.InterfaceName, body, nil, err, start)
		s.writeDomainError(w, r, err)
		return
	}

	s.auditTunnel(r, model.AuditActionTunnelUpdate, rec.InterfaceName, body, result.Operations, nil, start)
	writeJSON(w, http.StatusOK, createResponse{
		Tunnel: result.Tunnel, Plan: result.Plan, Verification: result.Verify,
		Warnings: warningsOf(result.Warnings),
	})
}

// tunnelInputOf turns a stored tunnel back into the request shape, so a partial
// change can be expressed as a complete desired state.
func tunnelInputOf(rec tunnel.Record) validate.TunnelInput {
	in := validate.TunnelInput{
		TunnelID:          rec.TunnelID,
		TunnelTypeID:      rec.TunnelTypeID,
		TunnelSideID:      rec.TunnelSideID,
		PersistenceTypeID: rec.PersistenceTypeID,
		InterfaceName:     rec.InterfaceName,
		TunnelNumber:      rec.TunnelNumber,
		LocalEndpoint:     rec.LocalEndpoint,
		RemoteEndpoint:    rec.RemoteEndpoint,
		Ttl:               rec.Ttl,
		Tos:               rec.Tos,
		Mtu:               rec.Mtu,
		IKey:              rec.IKey,
		OKey:              rec.OKey,

		HasInputChecksum:  rec.HasInputChecksum,
		HasOutputChecksum: rec.HasOutputChecksum,
		HasInputSequence:  rec.HasInputSequence,
		HasOutputSequence: rec.HasOutputSequence,

		IsPathMtuDiscovery: rec.IsPathMtuDiscovery,
		IsIgnoreDf:         rec.IsIgnoreDf,
		FwMark:             rec.FwMark,
		TxQueueLength:      rec.TxQueueLength,
		HopLimit:           rec.HopLimit,
		EncapLimit:         rec.EncapLimit,
		AddressPoolID:      rec.AddressPoolID,
		IsEnabled:          rec.IsEnabled,

		// Carried across so a PATCH that does not mention an override keeps it.
		// Without this the update would rewrite every one of them to NULL, and a
		// tunnel would silently fall back to the global on an unrelated edit.
		MonitorIntervalSeconds:     rec.MonitorIntervalSeconds,
		MonitorTimeoutSeconds:      rec.MonitorTimeoutSeconds,
		MonitorPacketSize:          rec.MonitorPacketSize,
		MonitorWindowSize:          rec.MonitorWindowSize,
		MonitorDegradedLossPercent: rec.MonitorDegradedLossPercent,
		MonitorDownLossPercent:     rec.MonitorDownLossPercent,
		MonitorDegradedRttMs:       rec.MonitorDegradedRttMs,
		MonitorStateChangeSamples:  rec.MonitorStateChangeSamples,
	}
	if rec.DisplayName != nil {
		in.DisplayName = *rec.DisplayName
	}
	if rec.BindDevice != nil {
		in.BindDevice = *rec.BindDevice
	}
	if rec.TrafficClass != nil {
		in.TrafficClass = *rec.TrafficClass
	}
	if rec.FlowLabel != nil {
		in.FlowLabel = *rec.FlowLabel
	}
	for _, a := range rec.Addresses {
		address := validate.AddressInput{
			Address: a.Address, PrefixLength: int(a.PrefixLength), IsPrimary: a.IsPrimary,
		}
		if a.PeerAddress != nil {
			address.PeerAddress = *a.PeerAddress
		}
		in.Addresses = append(in.Addresses, address)
	}
	return in
}

// ---------------------------------------------------------------- pairing

func (s *Server) handlePairingCode(w http.ResponseWriter, r *http.Request) {
	rec, ok := s.tunnelFromPath(w, r)
	if !ok {
		return
	}

	payload := pairing.Payload{
		TunnelTypeID:    rec.TunnelTypeID,
		TunnelSideID:    rec.TunnelSideID,
		Name:            rec.InterfaceName,
		IsNameTemplated: rec.IsNameTemplated,
		TunnelNumber:    rec.TunnelNumber,
		LocalEndpoint:   rec.LocalEndpoint,
		RemoteEndpoint:  rec.RemoteEndpoint,
		Ttl:             rec.Ttl,
		Tos:             rec.Tos,
		Mtu:             rec.Mtu,
		IKey:            rec.IKey,
		OKey:            rec.OKey,

		HasInputChecksum:  rec.HasInputChecksum,
		HasOutputChecksum: rec.HasOutputChecksum,
		HasInputSequence:  rec.HasInputSequence,
		HasOutputSequence: rec.HasOutputSequence,

		IsPathMtuDiscovery: rec.IsPathMtuDiscovery,
		IsIgnoreDf:         rec.IsIgnoreDf,
		HopLimit:           rec.HopLimit,
		EncapLimit:         rec.EncapLimit,
		AddressPoolID:      rec.AddressPoolID,
	}
	for _, a := range rec.Addresses {
		peer := ""
		if a.PeerAddress != nil {
			peer = *a.PeerAddress
		}
		// The code carries both ends' addresses so the far side needs no
		// arithmetic and cannot get the allocation scheme wrong.
		first, second := a.Address, peer
		if rec.TunnelSideID == model.TunnelSideB {
			first, second = peer, a.Address
		}
		payload.Addresses = append(payload.Addresses, pairing.PairAddress{
			AddressA: first, AddressB: second,
			PrefixLength: int(a.PrefixLength), IsPrimary: a.IsPrimary,
		})
	}

	code, err := pairing.Encode(payload)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pairing_code": code,
		"summary":      payload.Summarise(),
		"note": "This code is configuration, not a credential. It carries the GRE key, which is not a " +
			"security boundary, but it describes a specific pair of hosts and should not be posted publicly.",
	})
}

type fromPairingCodeRequest struct {
	PairingCode string `json:"pairing_code"`
}

// handleFromPairingCode decodes a code and returns a prefilled create payload
// with the side flipped. It creates nothing: the operator reviews and submits
// (§14).
func (s *Server) handleFromPairingCode(w http.ResponseWriter, r *http.Request) {
	var req fromPairingCodeRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	payload, err := pairing.Decode(req.PairingCode)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed, err.Error(), "pairing_code", nil)
		return
	}

	in := payload.Flipped()
	// A name that came from a template belongs to the server that generated it,
	// so this end renders its own from its own settings.
	if in.InterfaceName == "" {
		if name, err := s.tunnels.RenderName(in); err == nil {
			in.InterfaceName = name
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tunnel":  in,
		"summary": payload.Summarise(),
		"note": "Nothing has been created. Review these values and submit them to create the tunnel on " +
			"this server.",
	})
}

// ---------------------------------------------------------------- side info

// sideRole describes what one slot means, for the table the frontend renders.
type sideRole struct {
	Slot             string `json:"slot"`
	Label            string `json:"label"`
	Endpoints        string `json:"endpoints"`
	AddressInSubnet  string `json:"address_in_subnet"`
	NameSubstitution string `json:"name_substitution"`
}

// handleSideInfo serves the canonical help text of §5.4 plus the table it
// summarises. The backend owns this text so both ends of every install give the
// same answer.
func (s *Server) handleSideInfo(w http.ResponseWriter, r *http.Request) {
	labels := s.settings.StringMap("tunnel.side_labels")
	labelFor := func(slot string) string {
		if labels[slot] != "" {
			return labels[slot]
		}
		return slot
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary": strings.TrimSpace(sideInfoSummary),
		"sides": []sideRole{
			{
				Slot: "a", Label: labelFor("a"),
				Endpoints:        "this server is the local endpoint and the peer is the remote one",
				AddressInSubnet:  "the first usable address",
				NameSubstitution: "the label for slot a",
			},
			{
				Slot: "b", Label: labelFor("b"),
				Endpoints:        "mirrored relative to slot a",
				AddressInSubnet:  "the second usable address",
				NameSubstitution: "the label for slot b",
			},
		},
		"identical_on_both_ends": []string{
			"tunnel type", "inbound key", "outbound key", "MTU", "TTL",
			"checksum flags", "sequence flags",
		},
		"tunnel_side_ids": map[string]int64{"a": model.TunnelSideA, "b": model.TunnelSideB},
	})
}

// ---------------------------------------------------------------- helpers

// tunnelFromPath resolves {id} and writes the error response itself when it
// cannot.
func (s *Server) tunnelFromPath(w http.ResponseWriter, r *http.Request) (tunnel.Record, bool) {
	raw := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"The tunnel identifier in the path is not a number.", "id", nil)
		return tunnel.Record{}, false
	}
	rec, err := s.tunnels.Repo().ByID(r.Context(), id)
	if err != nil {
		s.writeDomainError(w, r, err)
		return tunnel.Record{}, false
	}
	return rec, true
}

func (s *Server) observeInterface(ctx context.Context, name string) (link.Link, bool) {
	observed, err := s.tunnels.Links().Get(ctx, name)
	if err != nil {
		return link.Link{}, false
	}
	return observed, true
}

// pagination reads limit and offset with sane bounds (§15).
func pagination(r *http.Request) (limit, offset int) {
	const defaultLimit, maxLimit = 100, 1000
	limit, offset = defaultLimit, 0

	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			offset = n
		}
	}
	return limit, offset
}

// auditTunnel records one mutating request with its actor, its client address,
// and the exact operations performed (§18).
func (s *Server) auditTunnel(r *http.Request, actionID int64, target string, request any,
	operations []audit.Operation, err error, start time.Time) {

	entry := audit.Entry{
		ActionID: actionID, TargetType: "Tunnel", TargetID: target,
		Request: request, Operations: operations,
		IsSuccess: err == nil, Duration: time.Since(start), ClientIP: ClientIP(r),
	}
	if user := UserFromContext(r.Context()); user != nil {
		id := user.UserID
		entry.UserID = &id
	}
	if err != nil {
		entry.ErrorMessage = err.Error()
	}
	s.audit.Write(r.Context(), entry)
}
