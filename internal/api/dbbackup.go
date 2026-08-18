package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/backup"
	"github.com/drs/gre-panel/internal/model"
)

// maxUploadBytes bounds a restore upload. The database is a few hundred
// kilobytes on a busy host; 256 MiB is far above anything real and still stops
// a stranger filling the disk through one endpoint.
const maxUploadBytes = 256 << 20

type backupLinkResponse struct {
	URL string `json:"url"`
	// Path is the URL without the origin, for a caller that knows where the
	// panel is better than the panel does — behind a proxy, the Host header is
	// the only clue it has, and it can be wrong.
	Path       string `json:"path"`
	ExpiresAt  string `json:"expires_at"`
	ExpiresIn  int    `json:"expires_in_seconds"`
	Downloads  int    `json:"downloads"`
	Reused     bool   `json:"reused"`
	WindowSecs int    `json:"window_seconds"`
	Warning    string `json:"warning"`
}

// handleBackupLink issues the download link, or returns the live one.
//
// Asking twice inside the window gives back the same link. Minting a second
// would leave the first working until it expired, so every extra look would
// widen the set of URLs that can read the database — the opposite of what a
// time limit is for.
func (s *Server) handleBackupLink(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	before, liveErr := backup.Live(r.Context(), s.db, now)
	reused := liveErr == nil

	grant, err := backup.Issue(r.Context(), s.db, userIDOf(r), now)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	// A reused grant cannot show its token: only the hash was kept, which is
	// the point. The caller is told the link is already out and when it lapses,
	// and can revoke it to get a new one.
	if reused && grant.Token == "" {
		writeJSON(w, http.StatusOK, backupLinkResponse{
			ExpiresAt:  model.FormatTime(before.ExpiresAt),
			ExpiresIn:  int(before.Remaining().Seconds()),
			Downloads:  before.Downloads,
			Reused:     true,
			WindowSecs: int(backup.Window.Seconds()),
			Warning: "A link is already out and this is the same one. The token is not stored, " +
				"so it cannot be shown again; revoke it to issue a new link.",
		})
		return
	}

	path := s.backupPath(grant.Token)
	writeJSON(w, http.StatusOK, backupLinkResponse{
		URL:        s.absoluteURL(r, path),
		Path:       path,
		ExpiresAt:  model.FormatTime(grant.ExpiresAt),
		ExpiresIn:  int(grant.Remaining().Seconds()),
		Downloads:  grant.Downloads,
		Reused:     false,
		WindowSecs: int(backup.Window.Seconds()),
		Warning: "This file contains every operator password hash and the panel's signing key. " +
			"Anyone with this link can download it until it expires.",
	})
}

func (s *Server) backupPath(token string) string {
	return s.cfg.APIBasePath() + "/system/backup/download?token=" + token
}

// absoluteURL builds a link from the request's own Host, which is the only
// thing the panel knows about how it was reached.
func (s *Server) absoluteURL(r *http.Request, path string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		scheme = forwarded
	}
	return scheme + "://" + r.Host + path
}

// handleBackupRevoke ends every live link.
func (s *Server) handleBackupRevoke(w http.ResponseWriter, r *http.Request) {
	n, err := backup.Revoke(r.Context(), s.db, time.Now())
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// handleBackupDownload streams the database to a holder of the token.
//
// This is the one route that answers without a session, because a link that
// needed a login would not be a link. The token is the whole authorisation, it
// is 256 bits, and it stops working when the window closes.
func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	grant, err := backup.Redeem(r.Context(), s.db, token, time.Now())
	if err != nil {
		// One answer for a wrong token and an expired one. Distinguishing them
		// tells somebody guessing that they guessed a real token.
		writeError(w, http.StatusNotFound, CodeNotFound,
			"That download link is not valid. It may have expired.", "", nil)
		return
	}

	dir, err := os.MkdirTemp("", "gre-panel-backup-")
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	defer os.RemoveAll(dir) //nolint:errcheck // best effort

	snapshot := filepath.Join(dir, "panel.db")
	size, err := backup.Snapshot(r.Context(), s.db, snapshot)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}

	name := fmt.Sprintf("gre-panel-%s.db", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
	// A backup is not something a proxy or browser should keep a copy of.
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	f, err := os.Open(snapshot)
	if err != nil {
		s.writeDomainError(w, r, err)
		return
	}
	defer f.Close() //nolint:errcheck // read-only

	s.writeAudit(r, model.AuditActionDatabaseDownload, "BackupGrant",
		fmt.Sprintf("%d", grant.ID), map[string]any{
			"download_number": grant.Downloads,
			"size_bytes":      size,
			"actor":           "link",
		})
	http.ServeContent(w, r, name, time.Now(), f)
}

// ---------------------------------------------------------------- restore

// restoreStage is where a restore has got to. The upload is measured by the
// browser; everything after it is only visible from here, and a restore that
// shows nothing between "uploaded" and "the panel came back" looks like a hang
// at the exact moment an operator is most worried.
type restoreStage string

const (
	stageVerifying  restoreStage = "verifying"
	stageInstalling restoreStage = "installing"
	stageRestarting restoreStage = "restarting"
	stageDone       restoreStage = "done"
	stageFailed     restoreStage = "failed"
)

type restoreState struct {
	mu       sync.Mutex
	Stage    restoreStage
	Message  string
	Counts   backup.Counts
	Started  time.Time
	Finished time.Time
	Err      string
}

func (rs *restoreState) set(stage restoreStage, message string) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.Stage = stage
	rs.Message = message
	if stage == stageDone || stage == stageFailed {
		rs.Finished = time.Now()
	}
}

func (rs *restoreState) snapshot() map[string]any {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := map[string]any{
		"stage":   string(rs.Stage),
		"message": rs.Message,
		"counts":  rs.Counts,
	}
	if rs.Err != "" {
		out["error"] = rs.Err
	}
	return out
}

// handleRestoreStatus reports the last restore's progress.
//
// It is deliberately a poll rather than a stream: the last stage is the panel
// restarting, which ends every connection it has, so a stream would die exactly
// when the answer mattered. A poll simply fails and is retried, and the client
// then watches for the panel to answer again.
func (s *Server) handleRestoreStatus(w http.ResponseWriter, r *http.Request) {
	if s.restoreState == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stage": "idle"})
		return
	}
	writeJSON(w, http.StatusOK, s.restoreState.snapshot())
}

// handleRestoreUpload takes a .db file and puts it in place of the live one.
//
// Authenticated, unlike the download. A download needs a link somebody can
// paste; an upload replaces every account in the panel, so anyone who could
// call it unauthenticated could take the panel over by uploading a database
// with their own account in it.
func (s *Server) handleRestoreUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, CodeValidationFailed,
			"The upload could not be read; it may be larger than the limit.", "file", nil)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			"Attach the database file as the field named 'file'.", "file", nil)
		return
	}
	defer file.Close() //nolint:errcheck // read-only

	state := &restoreState{Stage: stageVerifying, Started: time.Now(),
		Message: "Checking the uploaded file."}
	s.restoreState = state

	// The upload lands beside the live database rather than in /tmp, so the
	// install is a rename within one filesystem and cannot half-copy.
	dir := filepath.Dir(s.db.Path)
	staged := filepath.Join(dir, "restore-upload.db")
	dst, err := os.OpenFile(staged, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		state.fail(w, r, s, "The upload could not be written: "+err.Error())
		return
	}
	if _, err := copyInto(dst, file); err != nil {
		dst.Close() //nolint:errcheck // the write already failed
		os.Remove(staged)
		state.fail(w, r, s, "The upload did not finish: "+err.Error())
		return
	}
	if err := dst.Close(); err != nil {
		os.Remove(staged)
		state.fail(w, r, s, "The upload could not be completed: "+err.Error())
		return
	}

	if err := backup.Verify(r.Context(), staged); err != nil {
		os.Remove(staged)
		state.fail(w, r, s, err.Error())
		return
	}
	counts, err := backup.Describe(r.Context(), staged)
	if err != nil {
		os.Remove(staged)
		state.fail(w, r, s, err.Error())
		return
	}
	state.mu.Lock()
	state.Counts = counts
	state.mu.Unlock()

	state.set(stageInstalling, "Putting the database in place.")
	if err := backup.Install(s.db.Path, staged); err != nil {
		state.fail(w, r, s, err.Error())
		return
	}

	s.writeAudit(r, model.AuditActionDatabaseRestore, "Database", s.db.Path, map[string]any{
		"filename": header.Filename,
		"users":    counts.Users, "tunnels": counts.Tunnels, "routes": counts.Routes,
	})

	// The answer goes out before the restart, for the same reason the address
	// change does: the connection carrying it is the one the restart breaks.
	restarting := s.underSystemd && s.restart != nil
	state.set(stageRestarting, "Restarting the panel to load the restored database.")
	writeJSON(w, http.StatusOK, map[string]any{
		"restored":   true,
		"restarting": restarting,
		"counts":     counts,
		"detail": func() string {
			if restarting {
				return "The panel is restarting. Every session is now signed out, because the " +
					"accounts in the restored database are the ones that exist."
			}
			return "The database is in place. Restart the panel by hand to load it."
		}(),
		"url": s.cfg.BasePath(),
	})

	if restarting {
		s.restart("a database was restored")
	} else {
		state.set(stageDone, "Restored. Restart the panel to load it.")
	}
}

func (rs *restoreState) fail(w http.ResponseWriter, r *http.Request, s *Server, message string) {
	rs.mu.Lock()
	rs.Err = message
	rs.mu.Unlock()
	rs.set(stageFailed, message)
	writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed, message, "file", nil)
}

// userIDOf is the acting operator, when there is one. The download route has
// no session by design, so this is nil there.
func userIDOf(r *http.Request) *int64 {
	if user := UserFromContext(r.Context()); user != nil {
		return &user.UserID
	}
	return nil
}

// writeAudit records one of the two database actions. Both are written even
// when the request then fails to reach the operator, because the question
// afterwards is what happened to the database, not what the browser saw.
func (s *Server) writeAudit(r *http.Request, action int64, targetType, targetID string, req map[string]any) {
	if s.audit == nil {
		return
	}
	entry := audit.Entry{
		ActionID:   action,
		TargetType: targetType,
		TargetID:   targetID,
		Request:    req,
		IsSuccess:  true,
		ClientIP:   ClientIP(r),
	}
	if user := UserFromContext(r.Context()); user != nil {
		entry.UserID = &user.UserID
	}
	// A restore ends with the process exiting, so the write must not be
	// cancelled by the request context going away with it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	s.audit.Write(ctx, entry)
}

// copyInto streams the upload without holding it in memory.
func copyInto(dst *os.File, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
