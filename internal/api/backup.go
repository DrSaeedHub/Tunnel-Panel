package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/drs/gre-panel/internal/alloc"
	"github.com/drs/gre-panel/internal/model"
	"github.com/drs/gre-panel/internal/tunnel"
	"github.com/drs/gre-panel/internal/validate"
)

// BackupVersion is the format version of an exported document. An import
// refuses a version it does not understand rather than guessing.
const BackupVersion = 1

// Backup is the exported configuration (§15).
//
// It deliberately carries no credentials: no operator accounts, no password
// hashes, and not the token signing key. A backup travels — to another machine,
// into a repository, through a chat window — and configuration that can be
// re-entered is worth far less to an attacker than a hash that cannot.
type Backup struct {
	Version    int    `json:"version"`
	ExportedAt string `json:"exported_at"`
	Panel      struct {
		Version  string `json:"version"`
		Hostname string `json:"hostname,omitempty"`
	} `json:"panel"`

	Settings map[string]any `json:"settings"`
	Pools    []alloc.Pool   `json:"pools"`
	Tunnels  []backupTunnel `json:"tunnels"`

	Note string `json:"note"`
}

// backupTunnel is one tunnel's desired state, in the same shape a create
// request takes, so an import is an ordinary create rather than a second path
// into the database.
type backupTunnel struct {
	validate.TunnelInput
	IsNameTemplated bool `json:"is_name_templated"`
}

// handleBackupExport writes the configuration out.
func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	backup := Backup{Version: BackupVersion, ExportedAt: model.NowUTC()}
	backup.Panel.Version = s.build.Version
	backup.Settings = s.settings.All()
	backup.Note = "This backup carries configuration only. It contains no operator accounts, no " +
		"password hashes and no signing key, so restoring it does not restore access to the panel."

	if s.tunnels != nil {
		pools, err := s.tunnels.Repo().Pools(r.Context())
		if err != nil {
			s.writeDomainError(w, r, err)
			return
		}
		backup.Pools = pools

		records, err := s.tunnels.Repo().List(r.Context())
		if err != nil {
			s.writeDomainError(w, r, err)
			return
		}
		for _, rec := range records {
			backup.Tunnels = append(backup.Tunnels, backupTunnel{
				TunnelInput:     tunnelInputOf(rec),
				IsNameTemplated: rec.IsNameTemplated,
			})
		}
	}
	if backup.Pools == nil {
		backup.Pools = []alloc.Pool{}
	}
	if backup.Tunnels == nil {
		backup.Tunnels = []backupTunnel{}
	}

	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="gre-panel-backup-%s.json"`,
			time.Now().UTC().Format("20060102-150405")))
	writeJSON(w, http.StatusOK, backup)
}

// importRequest is the body of an import.
type importRequest struct {
	Backup Backup `json:"backup"`
	// DryRun reports what would change without changing anything (§15).
	DryRun bool `json:"dry_run,omitempty"`
	// IncludeSettings and IncludePools let an operator restore part of a backup.
	IncludeSettings *bool `json:"include_settings,omitempty"`
	IncludePools    *bool `json:"include_pools,omitempty"`
	IncludeTunnels  *bool `json:"include_tunnels,omitempty"`
}

// importAction is one thing an import would do or did.
type importAction struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// handleBackupImport restores a backup, or reports what it would restore.
//
// A dry run is not a courtesy here. Importing tunnels means creating them for
// real — validate, plan, apply, verify — on a host that already has its own,
// so seeing the list first is how an operator avoids finding out afterwards.
func (s *Server) handleBackupImport(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req importRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	if req.Backup.Version == 0 {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			"This does not look like a panel backup: it carries no version.", "backup.version", nil)
		return
	}
	if req.Backup.Version != BackupVersion {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			fmt.Sprintf("This backup is version %d and this panel understands version %d.",
				req.Backup.Version, BackupVersion), "backup.version", nil)
		return
	}

	include := func(flag *bool) bool { return flag == nil || *flag }
	actions := []importAction{}
	failures := 0

	// Settings first: an imported tunnel is validated against them, so applying
	// them in the other order would validate against the wrong rules.
	if include(req.IncludeSettings) && len(req.Backup.Settings) > 0 {
		actions = append(actions, s.importSettings(r, req)...)
	}
	if include(req.IncludePools) && len(req.Backup.Pools) > 0 {
		actions = append(actions, s.importPools(r, req)...)
	}
	if include(req.IncludeTunnels) && len(req.Backup.Tunnels) > 0 {
		actions = append(actions, s.importTunnels(r, req)...)
	}
	for _, action := range actions {
		if action.Error != "" {
			failures++
		}
	}

	if !req.DryRun {
		s.auditTunnel(r, model.AuditActionBackupImport, "backup",
			map[string]any{
				"version":  req.Backup.Version,
				"tunnels":  len(req.Backup.Tunnels),
				"pools":    len(req.Backup.Pools),
				"settings": len(req.Backup.Settings),
			}, nil, nil, start)
	}

	status := http.StatusOK
	if failures > 0 && !req.DryRun {
		// Some of it did not apply. That is a partial success, and saying so
		// with the list is more useful than one status code either way.
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, map[string]any{
		"dry_run":  req.DryRun,
		"actions":  actions,
		"failures": failures,
		"note": "Settings and pools are applied directly. Tunnels are created through the ordinary " +
			"pipeline, so each one is validated, applied and verified exactly as if it had been " +
			"created by hand.",
	})
}

func (s *Server) importSettings(r *http.Request, req importRequest) []importAction {
	// A backup carries every setting, including the ones this build does not
	// know; validation reports those rather than silently dropping them.
	updates := map[string]any{}
	actions := []importAction{}
	for key, value := range req.Backup.Settings {
		updates[key] = value
	}

	if _, verr := s.settings.Validate(updates); verr != nil {
		for key, message := range verr.Errors {
			actions = append(actions, importAction{
				Kind: "setting", Target: key, Action: "skip", Error: message,
			})
			delete(updates, key)
		}
	}
	if len(updates) == 0 {
		return actions
	}

	if req.DryRun {
		actions = append(actions, importAction{
			Kind: "setting", Target: fmt.Sprintf("%d settings", len(updates)), Action: "would apply",
		})
		return actions
	}

	var userID *int64
	if user := UserFromContext(r.Context()); user != nil {
		id := user.UserID
		userID = &id
	}
	changed, err := s.settings.Update(r.Context(), updates, userID)
	if err != nil {
		actions = append(actions, importAction{
			Kind: "setting", Target: "settings", Action: "failed", Error: err.Error(),
		})
		return actions
	}
	actions = append(actions, importAction{
		Kind: "setting", Target: fmt.Sprintf("%d settings", len(changed)), Action: "applied",
		Detail: "settings whose value already matched were left alone",
	})
	return actions
}

func (s *Server) importPools(r *http.Request, req importRequest) []importAction {
	actions := []importAction{}
	if s.tunnels == nil {
		return actions
	}

	existing, err := s.tunnels.Repo().Pools(r.Context())
	if err != nil {
		return append(actions, importAction{
			Kind: "pool", Target: "pools", Action: "failed", Error: err.Error(),
		})
	}
	byCidr := map[string]alloc.Pool{}
	for _, pool := range existing {
		byCidr[pool.Cidr] = pool
	}

	for _, pool := range req.Backup.Pools {
		if _, exists := byCidr[pool.Cidr]; exists {
			actions = append(actions, importAction{
				Kind: "pool", Target: pool.Cidr, Action: "skip",
				Detail: "a pool with this range already exists",
			})
			continue
		}
		if req.DryRun {
			actions = append(actions, importAction{Kind: "pool", Target: pool.Cidr, Action: "would create"})
			continue
		}
		// The identifier is left to the database: reusing the exported one
		// would collide with whatever this host already has.
		pool.AddressPoolID = 0
		if _, err := s.tunnels.Repo().InsertPool(r.Context(), pool); err != nil {
			actions = append(actions, importAction{
				Kind: "pool", Target: pool.Cidr, Action: "failed", Error: err.Error(),
			})
			continue
		}
		actions = append(actions, importAction{Kind: "pool", Target: pool.Cidr, Action: "created"})
	}
	return actions
}

func (s *Server) importTunnels(r *http.Request, req importRequest) []importAction {
	actions := []importAction{}
	if s.tunnels == nil {
		return actions
	}

	existing, err := s.tunnels.Repo().List(r.Context())
	if err != nil {
		return append(actions, importAction{
			Kind: "tunnel", Target: "tunnels", Action: "failed", Error: err.Error(),
		})
	}
	byName := map[string]bool{}
	for _, rec := range existing {
		byName[rec.InterfaceName] = true
	}

	for _, imported := range req.Backup.Tunnels {
		name := imported.InterfaceName
		if byName[name] {
			actions = append(actions, importAction{
				Kind: "tunnel", Target: name, Action: "skip",
				Detail: "a tunnel of this name already exists here; it was left alone",
			})
			continue
		}

		in := imported.TunnelInput
		in.TunnelID = 0

		if req.DryRun {
			// Validation runs even for a dry run, so the report says which
			// tunnels would actually have applied rather than only listing them.
			preview, err := s.tunnels.PreviewCreate(r.Context(), tunnel.Request{TunnelInput: in})
			action := importAction{Kind: "tunnel", Target: name, Action: "would create"}
			if err != nil {
				action.Action = "would fail"
				action.Error = err.Error()
			} else {
				action.Detail = fmt.Sprintf("%d operations", len(preview.Plan.Steps))
			}
			actions = append(actions, action)
			continue
		}

		result, err := s.tunnels.Create(r.Context(), tunnel.Request{
			TunnelInput: in, ClientIP: ClientIP(r),
		})
		if err != nil {
			actions = append(actions, importAction{
				Kind: "tunnel", Target: name, Action: "failed", Error: err.Error(),
			})
			continue
		}
		actions = append(actions, importAction{
			Kind: "tunnel", Target: result.Tunnel.InterfaceName, Action: "created",
			Detail: fmt.Sprintf("verified: %v", result.Verify.Ok),
		})
		byName[result.Tunnel.InterfaceName] = true
	}
	return actions
}
