package authentication

import (
	"context"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

// Remembered devices (AUT-013). After a genuine second-factor sign-in, a user
// may opt to remember a browser or app. The device then holds a random bearer
// secret (an HttpOnly cookie, or a token the headless application stores); it is
// never derived from a browser fingerprint. A remembered device only skips the
// MFA prompt where policy allows it: never for privileged or protected accounts,
// phishing-resistant requirements, clients that demand MFA, or explicit
// acr_values requests. It adds no authentication factor, so tokens issued this
// way report single-factor assurance and resources requiring MFA still demand a
// step-up. Devices expire, can be listed and revoked, and are revoked with
// sessions on password changes and account-wide session revocation.

// DefaultRememberDeviceDays bounds device lifetime when the realm sets none.
const DefaultRememberDeviceDays = 30

// RememberDays returns the effective remembered-device lifetime in days.
func RememberDays(p realm.Policy) int {
	d := p.Login.RememberDeviceDays
	if d <= 0 {
		d = DefaultRememberDeviceDays
	}
	if d > 90 {
		d = 90
	}
	return d
}

// rememberedDevice validates a presented device secret for the user.
func (s *Service) rememberedDevice(ctx context.Context, q storage.Querier, realmID, userID, token string) string {
	if token == "" || !secret.HasPrefix(token, secret.PrefixRemember) || len(token) > 128 {
		return ""
	}
	var id string
	if err := q.QueryRow(ctx, `SELECT id FROM remembered_devices WHERE realm_id=$1 AND user_id=$2 AND token_digest=$3
		AND revoked_at IS NULL AND expires_at > $4`, realmID, userID, secret.Digest(token), s.d.Now()).Scan(&id); err != nil {
		return ""
	}
	return id
}

// rememberAllowed reports whether policy lets a remembered device stand in for
// the MFA prompt in this transaction.
func rememberAllowed(rlm *realm.Realm, t *Transaction, r *requirements, privileged, protected, clientRequiresMFA bool) bool {
	if !rlm.Policy.Login.RememberDevices || r.phishingResistant || privileged || protected || clientRequiresMFA {
		return false
	}
	if slices.ContainsFunc(t.ACRValues, func(a string) bool { return strings.Contains(a, "mfa") || strings.Contains(a, "phishing_resistant") }) {
		return false
	}
	if t.hasPrompt("login") || t.MaxAge != nil {
		return false // an explicit re-authentication request is never short-circuited
	}
	return true
}

// SetRememberDevice records the user's choice for this transaction.
func (s *Service) SetRememberDevice(ctx context.Context, realmID, id string, p Proof, remember bool) (*State, error) {
	return s.step(ctx, realmID, id, p, func(tx pgx.Tx, t *Transaction) (map[string]any, error) {
		rlm, err := s.Realms.ByID(ctx, tx, t.RealmID)
		if err != nil {
			return nil, err
		}
		if remember && !rlm.Policy.Login.RememberDevices {
			return nil, problem.ErrFeatureDisabled.WithDetail("remembered devices are not enabled")
		}
		t.Pending.RememberDevice = remember
		return nil, nil
	})
}

// issueRememberedDevice creates a device grant at completion when the user
// opted in and a genuine second factor was used in this transaction.
func (s *Service) issueRememberedDevice(ctx context.Context, tx pgx.Tx, t *Transaction, rlm *realm.Realm) (string, error) {
	if !t.Pending.RememberDevice || !rlm.Policy.Login.RememberDevices {
		return "", nil
	}
	strong := slices.ContainsFunc(t.Factors, func(f session.Factor) bool {
		return f.Type == "totp" || f.Type == "hotp" || f.Type == "hwk" || f.Type == "swk" || f.Type == "fed_mfa"
	})
	if !strong {
		return "", nil
	}
	plain := secret.Token(secret.PrefixRemember)
	id, now := ids.New("rmd"), s.d.Now()
	label := reqctx.TruncateUA(t.UserAgent)
	if len(label) > 120 {
		label = canonical.Truncate(label, 120)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO remembered_devices (id, realm_id, user_id, token_digest, label, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, t.RealmID, t.UserID, secret.Digest(plain), nilIfEmpty(label),
		now.Add(time.Duration(RememberDays(rlm.Policy))*24*time.Hour), now); err != nil {
		return "", err
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authentication.device.remembered", RealmID: t.RealmID, Actor: audit.Ref{Type: "user", ID: t.UserID},
		Subject: &audit.Ref{Type: "user", ID: t.UserID}, Target: &audit.Ref{Type: "remembered_device", ID: id},
		Metadata: map[string]any{"expires_days": RememberDays(rlm.Policy)}})
	return plain, err
}

// RememberedDevice is the safe view of a device grant.
type RememberedDevice struct {
	ID         string     `json:"id"`
	Label      string     `json:"label,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  time.Time  `json:"expires_at"`
}

// ListRememberedDevices lists a user's active device grants.
func (s *Service) ListRememberedDevices(ctx context.Context, realmID, userID string) ([]RememberedDevice, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, coalesce(label,''), created_at, last_used_at, expires_at FROM remembered_devices
		WHERE realm_id=$1 AND user_id=$2 AND revoked_at IS NULL AND expires_at > $3 ORDER BY created_at DESC`, realmID, userID, s.d.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RememberedDevice{}
	for rows.Next() {
		var d RememberedDevice
		if err := rows.Scan(&d.ID, &d.Label, &d.CreatedAt, &d.LastUsedAt, &d.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeRememberedDevices revokes one device (id) or all of a user's devices.
func (s *Service) RevokeRememberedDevices(ctx context.Context, q storage.Querier, realmID, userID, id string, actor audit.Ref) (int64, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	tag, err := q.Exec(ctx, `UPDATE remembered_devices SET revoked_at=$4 WHERE realm_id=$1 AND user_id=$2 AND ($3='' OR id=$3) AND revoked_at IS NULL`,
		realmID, userID, id, s.d.Now())
	if err != nil {
		return 0, err
	}
	if id != "" && tag.RowsAffected() == 0 {
		return 0, problem.ErrNotFound
	}
	if tag.RowsAffected() > 0 {
		_, err = s.d.Audit.Record(ctx, q, audit.Event{Type: "authentication.device.revoked", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"count": tag.RowsAffected(), "device_id": id}})
	}
	return tag.RowsAffected(), err
}
