// Package backup issues time-limited links to the panel's database file and
// restores a database uploaded in its place.
package backup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/drs/gre-panel/internal/db"
	"github.com/drs/gre-panel/internal/model"
)

// Window is how long a download link lives.
const Window = 15 * time.Minute

// tokenBytes is the size of the secret in a link. The link is the only thing
// standing between a stranger and every password hash in the database, so it is
// sized as a key rather than as an identifier.
const tokenBytes = 32

// ErrNoGrant is returned when a token matches nothing live.
var ErrNoGrant = errors.New("that download link is not valid")

// Grant is a live download link.
type Grant struct {
	ID        int64
	Token     string // only set when the grant is first issued
	ExpiresAt time.Time
	Created   time.Time
	Downloads int
}

// Remaining is how long the link has left, floored at zero.
func (g Grant) Remaining() time.Duration {
	d := time.Until(g.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue returns the live grant, creating one only if none is live.
//
// Asking twice inside the window returns the same link rather than a second
// one. That is what an operator means by asking again — they lost the first
// link, or they are checking. Minting a new token each time would leave the
// first one working until it expired, so every extra look would widen the
// window of things that can read the database, which is the opposite of what a
// 15-minute limit is for.
func Issue(ctx context.Context, database *db.DB, userID *int64, now time.Time) (Grant, error) {
	if existing, err := live(ctx, database, now); err == nil {
		return existing, nil
	} else if !errors.Is(err, ErrNoGrant) {
		return Grant{}, err
	}

	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return Grant{}, fmt.Errorf("generating a download token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	expires := now.Add(Window)
	stamp := model.FormatTime(now)
	res, err := database.Write.ExecContext(ctx,
		`INSERT INTO BackupGrant
			(TokenHash, ExpiresDate, CreatedByUserID, DownloadCount, CreatedDate, UpdatedDate, IsDeleted)
		 VALUES (?, ?, ?, 0, ?, ?, 0)`,
		hashToken(token), model.FormatTime(expires), userID, stamp, stamp)
	if err != nil {
		return Grant{}, fmt.Errorf("recording the download link: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Grant{}, fmt.Errorf("reading the new link id: %w", err)
	}
	return Grant{ID: id, Token: token, ExpiresAt: expires, Created: now}, nil
}

// live returns the newest unexpired grant, without its token: the token is not
// recoverable from the row, which is the point of storing only its hash.
func live(ctx context.Context, database *db.DB, now time.Time) (Grant, error) {
	var (
		g       Grant
		expires string
		created string
	)
	err := database.Read.QueryRowContext(ctx,
		`SELECT BackupGrantID, ExpiresDate, CreatedDate, DownloadCount
		   FROM BackupGrant
		  WHERE IsDeleted = 0 AND ExpiresDate > ?
		  ORDER BY ExpiresDate DESC
		  LIMIT 1`,
		model.FormatTime(now)).Scan(&g.ID, &expires, &created, &g.Downloads)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNoGrant
	}
	if err != nil {
		return Grant{}, fmt.Errorf("reading the live download link: %w", err)
	}
	if g.ExpiresAt, err = model.ParseTime(expires); err != nil {
		return Grant{}, fmt.Errorf("reading the link's expiry: %w", err)
	}
	if g.Created, err = model.ParseTime(created); err != nil {
		return Grant{}, fmt.Errorf("reading the link's creation time: %w", err)
	}
	return g, nil
}

// Live reports the current grant if there is one, for showing an operator that
// a link is already out and when it lapses.
func Live(ctx context.Context, database *db.DB, now time.Time) (Grant, error) {
	return live(ctx, database, now)
}

// Redeem checks a token and counts the download.
//
// The expiry is compared here, against the row, so a restart between issuing
// and downloading changes nothing: there is no timer to have been lost. A
// sweeper removes expired rows eventually, and this is what actually refuses
// them.
func Redeem(ctx context.Context, database *db.DB, token string, now time.Time) (Grant, error) {
	if token == "" {
		return Grant{}, ErrNoGrant
	}
	var (
		g       Grant
		expires string
	)
	err := database.Read.QueryRowContext(ctx,
		`SELECT BackupGrantID, ExpiresDate, DownloadCount
		   FROM BackupGrant
		  WHERE TokenHash = ? AND IsDeleted = 0`,
		hashToken(token)).Scan(&g.ID, &expires, &g.Downloads)
	if errors.Is(err, sql.ErrNoRows) {
		return Grant{}, ErrNoGrant
	}
	if err != nil {
		return Grant{}, fmt.Errorf("checking the download link: %w", err)
	}
	if g.ExpiresAt, err = model.ParseTime(expires); err != nil {
		return Grant{}, fmt.Errorf("reading the link's expiry: %w", err)
	}
	if !g.ExpiresAt.After(now) {
		return Grant{}, ErrNoGrant
	}

	if _, err := database.Write.ExecContext(ctx,
		`UPDATE BackupGrant
		    SET DownloadCount = DownloadCount + 1, LastDownloadDate = ?, UpdatedDate = ?
		  WHERE BackupGrantID = ?`,
		model.FormatTime(now), model.FormatTime(now), g.ID); err != nil {
		return Grant{}, fmt.Errorf("counting the download: %w", err)
	}
	g.Downloads++
	return g, nil
}

// Revoke ends every live link now.
func Revoke(ctx context.Context, database *db.DB, now time.Time) (int64, error) {
	res, err := database.Write.ExecContext(ctx,
		`UPDATE BackupGrant SET IsDeleted = 1, UpdatedDate = ? WHERE IsDeleted = 0`,
		model.FormatTime(now))
	if err != nil {
		return 0, fmt.Errorf("revoking download links: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Sweep deletes rows whose window has passed. It is housekeeping: Redeem
// already refuses an expired token, so a sweep that never ran would be a
// tidiness problem and not a security one.
func Sweep(ctx context.Context, database *db.DB, now time.Time) (int64, error) {
	res, err := database.Write.ExecContext(ctx,
		`DELETE FROM BackupGrant WHERE ExpiresDate <= ?`, model.FormatTime(now))
	if err != nil {
		return 0, fmt.Errorf("sweeping expired download links: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
