package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token uses. The use is carried inside the token so a refresh token can never
// be presented as an access token, or the other way round.
const (
	UseAccess  = "access"
	UseRefresh = "refresh"
)

// SecretFileMode is the permission mask for the persisted signing key (§18).
const SecretFileMode fs.FileMode = 0o600

// Errors returned by token handling.
var (
	ErrTokenInvalid    = errors.New("token is not valid")
	ErrTokenWrongUse   = errors.New("token was issued for a different purpose")
	ErrTokenSuperseded = errors.New("token was invalidated by a password change")
)

// Claims is the panel's JWT payload.
type Claims struct {
	jwt.RegisteredClaims
	Username string `json:"username"`
	// TokenVersion pins the token to a generation of the user's credentials.
	// Changing a password increments it, which invalidates every token already
	// issued without keeping any server-side session state (§18).
	TokenVersion int64  `json:"token_version"`
	TokenUse     string `json:"token_use"`
}

// Signer issues and verifies tokens with a single HMAC key.
type Signer struct {
	secret []byte
	issuer string
}

// NewSigner returns a signer over the given key.
func NewSigner(secret []byte) (*Signer, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("signing key must be at least 32 bytes, got %d", len(secret))
	}
	return &Signer{secret: secret, issuer: "gre-panel"}, nil
}

// LoadOrCreateSecret reads the persisted signing key, generating one with
// crypto/rand on first run. The file is created and kept at 0600, and an
// existing file with looser permissions is tightened rather than trusted.
func LoadOrCreateSecret(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		secret, decodeErr := hex.DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil || len(secret) < 32 {
			return nil, fmt.Errorf("signing key at %s is malformed; remove it to have a new one "+
				"generated, which will sign every operator out", path)
		}
		if err := os.Chmod(path, SecretFileMode); err != nil {
			return nil, fmt.Errorf("restricting permissions on %s: %w", path, err)
		}
		return secret, nil

	case errors.Is(err, fs.ErrNotExist):
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("generating signing key: %w", err)
		}
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("creating key directory: %w", err)
			}
		}
		// O_EXCL so two instances racing at first start cannot both write a key
		// and leave half the sessions unverifiable.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, SecretFileMode)
		if err != nil {
			if errors.Is(err, fs.ErrExist) {
				return LoadOrCreateSecret(path)
			}
			return nil, fmt.Errorf("creating signing key file: %w", err)
		}
		if _, err := f.WriteString(hex.EncodeToString(secret)); err != nil {
			f.Close()
			return nil, fmt.Errorf("writing signing key: %w", err)
		}
		if err := f.Close(); err != nil {
			return nil, fmt.Errorf("closing signing key file: %w", err)
		}
		return secret, nil

	default:
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
}

// Issue mints a token for a user.
func (s *Signer) Issue(userID int64, username string, tokenVersion int64, use string, ttl time.Duration) (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(ttl)
	jti, err := randomToken(16)
	if err != nil {
		return "", time.Time{}, err
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)), // tolerate small clock skew
			ExpiresAt: jwt.NewNumericDate(expires),
			ID:        jti,
		},
		Username:     username,
		TokenVersion: tokenVersion,
		TokenUse:     use,
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing token: %w", err)
	}
	return signed, expires, nil
}

// Parse verifies a token's signature, expiry, issuer, and intended use.
func (s *Signer) Parse(raw, wantUse string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		// Pinning the algorithm is what stops the "alg: none" and
		// RS256-verified-as-HS256 confusions.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return s.secret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithIssuer(s.issuer))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	if claims.TokenUse != wantUse {
		return nil, ErrTokenWrongUse
	}
	if _, err := strconv.ParseInt(claims.Subject, 10, 64); err != nil {
		return nil, ErrTokenInvalid
	}
	return claims, nil
}

// UserID returns the subject as an integer.
func (c *Claims) UserID() int64 {
	id, _ := strconv.ParseInt(c.Subject, 10, 64)
	return id
}

// randomToken returns n bytes of cryptographic randomness, base64url encoded.
func randomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
