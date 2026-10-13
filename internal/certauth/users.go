package certauth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// User certificates (PROV-016): a certificate signs a person in only when
// it chains to a user trust anchor and an explicit binding (issuer and
// subject names under that anchor) names the account, or the anchor maps
// certificate e-mail addresses to accounts that verified that address. A
// renewed certificate with the same names keeps working; a certificate from
// another authority with the same subject does not.

// Binding ties certificates (issuer and subject) to an account.
type Binding struct {
	ID          string     `json:"id"`
	UserID      string     `json:"user_id"`
	AnchorID    string     `json:"anchor_id"`
	IssuerDN    string     `json:"issuer_dn"`
	SubjectDN   string     `json:"subject_dn"`
	State       string     `json:"state"`
	CreatedByID string     `json:"created_by_id"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// BindingInput binds by names or by a sample certificate.
type BindingInput struct {
	AnchorID       string `json:"anchor_id"`
	IssuerDN       string `json:"issuer_dn"`
	SubjectDN      string `json:"subject_dn"`
	CertificatePEM string `json:"certificate_pem"`
}

const bindingCols = `id, user_id, anchor_id, issuer_dn, subject_dn, state, created_by_id, created_at, last_used_at`

func scanBinding(row pgx.Row) (*Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.UserID, &b.AnchorID, &b.IssuerDN, &b.SubjectDN, &b.State, &b.CreatedByID, &b.CreatedAt, &b.LastUsedAt)
	return &b, err
}

// Bind ties a certificate identity to an account.
func (s *Service) Bind(ctx context.Context, realmID, userID string, in BindingInput, actor audit.Ref) (*Binding, error) {
	verr := problem.ErrValidation
	a, err := s.Anchor(ctx, realmID, in.AnchorID)
	if err != nil || a.Purpose != PurposeUser || a.State != "active" {
		return nil, verr.WithField("anchor_id", "an active user trust anchor")
	}
	if in.CertificatePEM != "" {
		b, _ := pem.Decode([]byte(in.CertificatePEM))
		if b == nil || b.Type != "CERTIFICATE" {
			return nil, verr.WithField("certificate_pem", "a PEM certificate")
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, verr.WithField("certificate_pem", "a PEM certificate")
		}
		// The sample must be accepted by the anchor the binding names, not
		// merely by some user anchor of the realm.
		if err := s.VerifyAgainst(a, c, nil); err != nil {
			return nil, verr.WithField("certificate_pem", "not accepted by the anchor named in anchor_id: "+err.Error())
		}
		in.IssuerDN, in.SubjectDN = c.Issuer.String(), c.Subject.String()
	}
	in.IssuerDN, in.SubjectDN = strings.TrimSpace(in.IssuerDN), strings.TrimSpace(in.SubjectDN)
	if in.IssuerDN == "" || in.SubjectDN == "" || len(in.IssuerDN) > 1024 || len(in.SubjectDN) > 1024 {
		return nil, verr.WithField("subject_dn", "issuer_dn and subject_dn (RFC 4514), or certificate_pem")
	}
	var out *Binding
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM users WHERE realm_id=$1 AND id=$2 AND state NOT IN ('deleted','pending_deletion')`, realmID, userID).Scan(&ok); err != nil {
			return problem.ErrNotFound
		}
		id := ids.New("ucb")
		if _, err := tx.Exec(ctx, `INSERT INTO user_certificate_bindings (id, realm_id, user_id, anchor_id, issuer_dn, subject_dn, created_by_id, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, id, realmID, userID, a.ID, in.IssuerDN, in.SubjectDN, actor.ID, s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("this certificate identity is already bound to an account")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.certificate.bound", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Category: "security", Metadata: map[string]any{"binding_id": id, "anchor_id": a.ID,
				"issuer_dn": in.IssuerDN, "subject_dn": in.SubjectDN}}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET credential_revision=credential_revision+1 WHERE id=$1`, userID); err != nil {
			return err
		}
		var err error
		out, err = scanBinding(tx.QueryRow(ctx, `SELECT `+bindingCols+` FROM user_certificate_bindings WHERE id=$1`, id))
		return err
	})
	return out, err
}

// Bindings lists an account's active bindings.
func (s *Service) Bindings(ctx context.Context, realmID, userID string) ([]*Binding, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+bindingCols+` FROM user_certificate_bindings WHERE realm_id=$1 AND user_id=$2 AND state='active'
		ORDER BY created_at`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// Unbind ends a binding.
func (s *Service) Unbind(ctx context.Context, realmID, userID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE user_certificate_bindings SET state='revoked' WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND state='active'`,
			realmID, userID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET credential_revision=credential_revision+1 WHERE id=$1`, userID); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "credential.certificate.unbound", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Category: "security", Metadata: map[string]any{"binding_id": id}})
		return err
	})
}

// ResolveUser verifies a user certificate and names the account it stands
// for, with the anchor that accepted it.
func (s *Service) ResolveUser(ctx context.Context, q storage.Querier, realmID string, cert *x509.Certificate, intermediates []*x509.Certificate) (string, *Anchor, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	a, err := s.Verify(ctx, q, realmID, PurposeUser, cert, intermediates)
	if err != nil {
		return "", nil, err
	}
	var userID string
	err = q.QueryRow(ctx, `SELECT user_id FROM user_certificate_bindings WHERE anchor_id=$1 AND issuer_dn=$2 AND subject_dn=$3 AND state='active'`,
		a.ID, cert.Issuer.String(), cert.Subject.String()).Scan(&userID)
	if err == nil {
		_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE user_certificate_bindings SET last_used_at=$4 WHERE anchor_id=$1 AND issuer_dn=$2 AND subject_dn=$3`,
			a.ID, cert.Issuer.String(), cert.Subject.String(), s.d.Now())
		return userID, a, nil
	}
	if !storage.IsNoRows(err) {
		return "", nil, err
	}
	if a.MapSANEmail && len(cert.EmailAddresses) == 1 {
		if c, _, err := canonical.Email(cert.EmailAddresses[0]); err == nil {
			err := q.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2 AND verified_at IS NOT NULL`,
				realmID, c).Scan(&userID)
			if err == nil {
				return userID, a, nil
			}
		}
	}
	return "", a, ErrUnbound
}

// ErrUnbound reports a trusted certificate that names no account.
var ErrUnbound = errorString("the certificate is not bound to an account")

type errorString string

func (e errorString) Error() string { return string(e) }
