package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/drs/gre-panel/internal/audit"
	"github.com/drs/gre-panel/internal/auth"
	"github.com/drs/gre-panel/internal/model"
)

// setupRequest is the body of POST /auth/setup.
type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginRequest is the body of POST /auth/login.
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// updateMeRequest is the body of PUT /auth/me. Both changes are optional, but
// either one requires the current password: a stolen session must not be enough
// to take over the account.
type updateMeRequest struct {
	Username        *string `json:"username,omitempty"`
	CurrentPassword string  `json:"current_password"`
	NewPassword     *string `json:"new_password,omitempty"`
}

// userResponse is the public view of an operator account. The password hash is
// not part of it, by construction rather than by omission.
type userResponse struct {
	UserID        int64   `json:"user_id"`
	Username      string  `json:"username"`
	IsActive      bool    `json:"is_active"`
	LastLoginDate *string `json:"last_login_date"`
	CreatedDate   string  `json:"created_date"`
}

func toUserResponse(u *model.AppUser) userResponse {
	return userResponse{
		UserID:        u.UserID,
		Username:      u.Username,
		IsActive:      u.IsActive,
		LastLoginDate: u.LastLoginDate,
		CreatedDate:   u.CreatedDate,
	}
}

// sessionResponse is returned by setup, login, and refresh. The tokens
// themselves stay in httpOnly cookies; only their expiry is disclosed, so the
// frontend can refresh before they lapse.
type sessionResponse struct {
	User             userResponse `json:"user"`
	AccessExpiresAt  string       `json:"access_expires_at"`
	RefreshExpiresAt string       `json:"refresh_expires_at"`
	CsrfToken        string       `json:"csrf_token"`
}

// handleSetup creates the first operator account. It is one of the two
// endpoints reachable before setup is done, and it refuses once any account
// exists (§18).
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	exists, err := s.auth.HasUser(r.Context())
	if err != nil {
		s.log.Error("checking setup state failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, CodeUnavailable,
			"The panel could not read its database.", "", nil)
		return
	}
	if exists {
		writeError(w, http.StatusConflict, CodeSetupComplete,
			"An operator account already exists. Sign in instead.", "", nil)
		return
	}

	var req setupRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	user, err := s.auth.Setup(r.Context(), req.Username, req.Password)
	if err != nil {
		s.writeCredentialPolicyError(w, err)
		return
	}

	s.log.Info("first operator account created", "username", user.Username, "user_id", user.UserID)
	s.writeSession(w, r, user, http.StatusCreated)
	s.audit.Write(r.Context(), audit.Entry{
		ActionID: model.AuditActionLogin, UserID: &user.UserID,
		TargetType: "AppUser", TargetID: itoa(user.UserID),
		Request:   map[string]any{"username": user.Username, "endpoint": "setup"},
		IsSuccess: true, Duration: time.Since(start), ClientIP: ClientIP(r),
	})
}

// handleLogin authenticates an operator.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	clientIP := ClientIP(r)

	user, err := s.auth.Authenticate(r.Context(), req.Username, req.Password, clientIP)
	if err != nil {
		s.auditFailedLogin(r.Context(), req.Username, clientIP, err, time.Since(start))

		var locked *auth.LockedError
		switch {
		case errors.As(err, &locked):
			writeError(w, http.StatusTooManyRequests, CodeAccountLocked,
				"Too many failed sign-in attempts. Try again later.", "",
				map[string]any{"locked_until": model.FormatTime(locked.Until)})
		case errors.Is(err, auth.ErrRateLimited):
			writeError(w, http.StatusTooManyRequests, CodeRateLimited,
				"Too many sign-in attempts. Try again in a minute.", "", nil)
		case errors.Is(err, auth.ErrAccountInactive):
			writeError(w, http.StatusForbidden, CodeAccountInactive,
				"This account is not active.", "", nil)
		case errors.Is(err, auth.ErrInvalidCredentials):
			// Deliberately identical for an unknown username and a wrong
			// password: telling them apart would enumerate accounts (§18).
			writeError(w, http.StatusUnauthorized, CodeInvalidCredentials,
				"Invalid username or password.", "", nil)
		default:
			s.log.Error("authentication failed", "error", err)
			writeError(w, http.StatusInternalServerError, CodeInternal,
				"The sign-in could not be completed.", "", nil)
		}
		return
	}

	s.writeSession(w, r, user, http.StatusOK)
	s.audit.Write(r.Context(), audit.Entry{
		ActionID: model.AuditActionLogin, UserID: &user.UserID,
		TargetType: "AppUser", TargetID: itoa(user.UserID),
		Request:   map[string]any{"username": user.Username},
		IsSuccess: true, Duration: time.Since(start), ClientIP: clientIP,
	})
}

func (s *Server) auditFailedLogin(ctx context.Context, username, clientIP string, cause error, took time.Duration) {
	s.audit.Write(ctx, audit.Entry{
		ActionID:   model.AuditActionLoginFailed,
		TargetType: "AppUser", TargetID: username,
		Request:      map[string]any{"username": username},
		IsSuccess:    false,
		ErrorMessage: cause.Error(),
		Duration:     took, ClientIP: clientIP,
	})
}

// handleRefresh exchanges a valid refresh token for a new session. The refresh
// token is read from its cookie, so a script that somehow ran on the page
// cannot mint itself a fresh session.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	token := auth.CookieValue(r, auth.CookieRefresh)
	if token == "" {
		token = auth.BearerToken(r)
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, CodeUnauthenticated,
			"No refresh token was supplied.", "", nil)
		return
	}

	user, _, err := s.auth.ResolveToken(r.Context(), token, auth.UseRefresh)
	if err != nil {
		s.cookies.Clear(w, r)
		switch {
		case errors.Is(err, auth.ErrTokenSuperseded):
			writeError(w, http.StatusUnauthorized, CodeUnauthenticated,
				"This session ended when the password was changed. Sign in again.", "", nil)
		case errors.Is(err, auth.ErrAccountInactive):
			writeError(w, http.StatusForbidden, CodeAccountInactive,
				"This account is not active.", "", nil)
		case errors.Is(err, auth.ErrTokenInvalid), errors.Is(err, auth.ErrTokenWrongUse):
			writeError(w, http.StatusUnauthorized, CodeUnauthenticated,
				"The refresh token is not valid. Sign in again.", "", nil)
		default:
			s.log.Error("resolving refresh token failed", "error", err)
			writeError(w, http.StatusInternalServerError, CodeInternal,
				"The session could not be refreshed.", "", nil)
		}
		return
	}
	s.writeSession(w, r, user, http.StatusOK)
}

// handleLogout clears the session cookies. It succeeds even without a valid
// session, because the point is to end up signed out.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	var userID *int64
	if token := auth.CookieValue(r, auth.CookieAccess); token != "" {
		if user, _, err := s.auth.ResolveToken(r.Context(), token, auth.UseAccess); err == nil {
			userID = &user.UserID
		}
	}
	s.cookies.Clear(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"signed_out": true})

	s.audit.Write(r.Context(), audit.Entry{
		ActionID: model.AuditActionLogout, UserID: userID,
		TargetType: "AppUser", IsSuccess: true, ClientIP: ClientIP(r),
	})
}

// handleMe returns the signed-in operator.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user := UserFromContext(r.Context())
	writeJSON(w, http.StatusOK, toUserResponse(user))
}

// handleUpdateMe changes the username, the password, or both. A password change
// increments TokenVersion, which signs every session out — including this one,
// so a fresh session is issued in the same response.
func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	user := UserFromContext(r.Context())

	var req updateMeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Username == nil && req.NewPassword == nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"Supply a new username, a new password, or both.", "", nil)
		return
	}

	// Re-authenticating protects against a hijacked session being used to lock
	// the real operator out.
	ok, err := auth.VerifyPassword(user.PasswordHash, req.CurrentPassword)
	if err != nil {
		s.log.Error("verifying current password failed", "error", err, "user_id", user.UserID)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The change could not be completed.", "", nil)
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials,
			"The current password is not correct.", "current_password", nil)
		return
	}

	updated := user
	if req.Username != nil {
		updated, err = s.auth.ChangeUsername(r.Context(), user.UserID, *req.Username)
		if err != nil {
			s.writeCredentialPolicyError(w, err)
			return
		}
	}
	passwordChanged := false
	if req.NewPassword != nil {
		updated, err = s.auth.ChangePassword(r.Context(), user.UserID, req.CurrentPassword, *req.NewPassword)
		if err != nil {
			s.writeCredentialPolicyError(w, err)
			return
		}
		passwordChanged = true
	}

	action := model.AuditActionSettingUpdate
	if passwordChanged {
		action = model.AuditActionPasswordChange
	}
	s.audit.Write(r.Context(), audit.Entry{
		ActionID: action, UserID: &updated.UserID,
		TargetType: "AppUser", TargetID: itoa(updated.UserID),
		Request: map[string]any{
			"username_changed": req.Username != nil,
			"password_changed": passwordChanged,
		},
		IsSuccess: true, Duration: time.Since(start), ClientIP: ClientIP(r),
	})

	// Reissue so the caller is not signed out by their own password change.
	s.writeSession(w, r, updated, http.StatusOK)
}

// writeSession issues tokens, sets the cookies, and returns the session body.
func (s *Server) writeSession(w http.ResponseWriter, r *http.Request, user *model.AppUser, status int) {
	access, accessExpiry, refresh, refreshExpiry, err := s.auth.IssueSession(user)
	if err != nil {
		s.log.Error("issuing session failed", "error", err, "user_id", user.UserID)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The session could not be created.", "", nil)
		return
	}
	csrf, err := auth.NewCSRFToken()
	if err != nil {
		s.log.Error("generating CSRF token failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The session could not be created.", "", nil)
		return
	}

	s.cookies.SetSession(w, r, access, accessExpiry, refresh, refreshExpiry, csrf)
	writeJSON(w, status, sessionResponse{
		User:             toUserResponse(user),
		AccessExpiresAt:  model.FormatTime(accessExpiry),
		RefreshExpiresAt: model.FormatTime(refreshExpiry),
		CsrfToken:        csrf,
	})
}

// writeCredentialPolicyError maps the credential and account errors onto the
// envelope, keeping the field pointer accurate so the frontend can highlight
// the offending input.
func (s *Server) writeCredentialPolicyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong),
		errors.Is(err, auth.ErrPasswordWeak):
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			capitalise(err.Error())+".", "password", nil)
	case errors.Is(err, auth.ErrInvalidUsername):
		writeError(w, http.StatusUnprocessableEntity, CodeValidationFailed,
			capitalise(err.Error())+".", "username", nil)
	case errors.Is(err, auth.ErrUsernameTaken):
		writeError(w, http.StatusConflict, CodeConflict,
			"That username is already in use.", "username", nil)
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials,
			"The current password is not correct.", "current_password", nil)
	case errors.Is(err, auth.ErrSetupComplete):
		writeError(w, http.StatusConflict, CodeSetupComplete,
			"An operator account already exists. Sign in instead.", "", nil)
	default:
		s.log.Error("account operation failed", "error", err)
		writeError(w, http.StatusInternalServerError, CodeInternal,
			"The request could not be completed.", "", nil)
	}
}
