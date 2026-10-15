// Package certauth verifies X.509 certificates presented over TLS against a
// realm's trust anchors (TOK-019, MCH-014, PROV-016): certificate authorities
// trusted for client authentication or for user sign-in, with optional
// revocation lists. It decides whether a certificate chains to an anchor of
// the right purpose and is currently valid; which client or account a
// certificate stands for is decided by the caller's explicit registration.
package certauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
)

// Purposes of trust anchors.
const (
	PurposeClient = "client"
	PurposeUser   = "user"
)

// Errors returned by Verify.
var (
	ErrUntrusted = errors.New("certificate does not chain to a trusted anchor")
	ErrRevoked   = errors.New("certificate is revoked")
	ErrNoCRL     = errors.New("the anchor requires a current revocation list")
)

// Thumbprint is the base64url SHA-256 of the certificate (x5t#S256).
func Thumbprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ParseHeader decodes a certificate forwarded by a proxy as URL-escaped PEM.
func ParseHeader(v string) (*x509.Certificate, error) {
	if v == "" {
		return nil, errors.New("empty")
	}
	if u, err := url.QueryUnescape(v); err == nil {
		v = u
	}
	b, _ := pem.Decode([]byte(v))
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

// Anchor is a trusted certificate authority of a realm.
type Anchor struct {
	ID             string     `json:"id"`
	Purpose        string     `json:"purpose"`
	Name           string     `json:"name"`
	CertificatePEM string     `json:"certificate_pem"`
	Subject        string     `json:"subject"`
	Fingerprint    string     `json:"fingerprint"`
	NotAfter       time.Time  `json:"not_after"`
	Revocation     string     `json:"revocation"`
	CRLNextUpdate  *time.Time `json:"crl_next_update,omitempty"`
	MapSANEmail    bool       `json:"map_san_email"`
	MultiFactor    bool       `json:"multi_factor"`
	State          string     `json:"state"`
	CreatedByID    string     `json:"created_by_id"`
	CreatedAt      time.Time  `json:"created_at"`
	cert           *x509.Certificate
	crl            *x509.RevocationList
}

// AnchorInput adds an anchor.
type AnchorInput struct {
	Purpose        string `json:"purpose"`
	Name           string `json:"name"`
	CertificatePEM string `json:"certificate_pem"`
	// Revocation "crl" requires a current CRL (CRLPEM) from this authority:
	// certificates are refused once it is past its next update.
	Revocation string `json:"revocation"`
	CRLPEM     string `json:"crl_pem"`
	// MapSANEmail (user anchors) lets a certificate's e-mail address name
	// the account with that verified address, without a binding.
	MapSANEmail bool `json:"map_san_email"`
	// MultiFactor (user anchors) declares the certificate's key protected
	// by a second factor (for example a smart card with a PIN).
	MultiFactor bool `json:"multi_factor"`
}

// Service manages anchors and verifies certificates.
type Service struct{ d *runtime.Deps }

// New returns the service.
func New(d *runtime.Deps) *Service { return &Service{d: d} }

const anchorCols = `id, purpose, name, certificate_pem, subject, fingerprint, not_after, revocation, crl_der, crl_next_update, map_san_email, multi_factor,
	state, created_by_id, created_at`

func scanAnchor(row pgx.Row) (*Anchor, error) {
	var a Anchor
	var crl []byte
	if err := row.Scan(&a.ID, &a.Purpose, &a.Name, &a.CertificatePEM, &a.Subject, &a.Fingerprint, &a.NotAfter, &a.Revocation, &crl, &a.CRLNextUpdate,
		&a.MapSANEmail, &a.MultiFactor, &a.State, &a.CreatedByID, &a.CreatedAt); err != nil {
		return nil, err
	}
	if b, _ := pem.Decode([]byte(a.CertificatePEM)); b != nil {
		a.cert, _ = x509.ParseCertificate(b.Bytes)
	}
	if len(crl) > 0 {
		a.crl, _ = x509.ParseRevocationList(crl)
	}
	return &a, nil
}

func parseCRL(pemText string, ca *x509.Certificate) (*x509.RevocationList, []byte, error) {
	b, _ := pem.Decode([]byte(pemText))
	if b == nil || b.Type != "X509 CRL" {
		return nil, nil, errors.New("crl_pem must be a PEM X509 CRL")
	}
	crl, err := x509.ParseRevocationList(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		return nil, nil, errors.New("the CRL is not signed by this authority")
	}
	// Without a next update a list has no end to its validity, and
	// certificates could never be refused for a stale list (RFC 5280
	// requires the field).
	if crl.NextUpdate.IsZero() {
		return nil, nil, errors.New("the CRL has no next update (nextUpdate is required)")
	}
	return crl, b.Bytes, nil
}

// newerCRL reports whether next may replace current: the same list again
// (identical content), or a later one. With CRL numbers on both, the new
// number must be greater; otherwise its thisUpdate must be later.
func newerCRL(current *x509.RevocationList, currentDER []byte, next *x509.RevocationList, nextDER []byte) bool {
	if current == nil || bytes.Equal(currentDER, nextDER) {
		return true
	}
	if current.Number != nil && next.Number != nil {
		return next.Number.Cmp(current.Number) > 0
	}
	return next.ThisUpdate.After(current.ThisUpdate)
}

// AddAnchor trusts a certificate authority for one purpose.
func (s *Service) AddAnchor(ctx context.Context, realmID string, in AnchorInput, actor audit.Ref) (*Anchor, error) {
	verr := problem.ErrValidation
	if in.Purpose != PurposeClient && in.Purpose != PurposeUser {
		return nil, verr.WithField("purpose", "client or user")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return nil, verr.WithField("name", "required, at most 100 characters")
	}
	b, rest := pem.Decode([]byte(in.CertificatePEM))
	if b == nil || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, verr.WithField("certificate_pem", "exactly one PEM certificate")
	}
	ca, err := x509.ParseCertificate(b.Bytes)
	if err != nil || !ca.IsCA || !ca.BasicConstraintsValid {
		return nil, verr.WithField("certificate_pem", "a certificate authority certificate (basic constraints CA)")
	}
	now := s.d.Now()
	if !now.Before(ca.NotAfter) {
		return nil, verr.WithField("certificate_pem", "the authority certificate has expired")
	}
	if in.Revocation == "" {
		in.Revocation = "none"
	}
	var crlDER []byte
	var next *time.Time
	switch in.Revocation {
	case "none":
		if in.CRLPEM != "" {
			return nil, verr.WithField("revocation", "crl to use crl_pem")
		}
	case "crl":
		crl, der, err := parseCRL(in.CRLPEM, ca)
		if err != nil {
			return nil, verr.WithField("crl_pem", err.Error())
		}
		crlDER, next = der, &crl.NextUpdate
	default:
		return nil, verr.WithField("revocation", "none or crl")
	}
	if in.Purpose == PurposeClient && (in.MapSANEmail || in.MultiFactor) {
		return nil, verr.WithField("purpose", "map_san_email and multi_factor apply to user anchors")
	}
	id := ids.New("cta")
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO certificate_trust_anchors (id, realm_id, purpose, name, certificate_pem, subject, fingerprint, not_after,
			revocation, crl_der, crl_next_update, map_san_email, multi_factor, created_by_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
			id, realmID, in.Purpose, in.Name, string(pem.EncodeToMemory(b)), ca.Subject.String(), Thumbprint(ca), ca.NotAfter, in.Revocation, crlDER, next,
			in.MapSANEmail, in.MultiFactor, actor.ID, now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("this authority is already trusted for that purpose")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "certificate.trust_anchor.added", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "trust_anchor", ID: id}, Metadata: map[string]any{"purpose": in.Purpose, "subject": ca.Subject.String(),
				"fingerprint": Thumbprint(ca), "revocation": in.Revocation}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Anchor(ctx, realmID, id)
}

// UpdateCRL replaces an anchor's revocation list with a newer one (or the
// same list again). The comparison runs on the locked anchor, so two
// concurrent uploads cannot both replace a list with an older one.
func (s *Service) UpdateCRL(ctx context.Context, realmID, id, crlPEM string, actor audit.Ref) (*Anchor, error) {
	a, err := s.Anchor(ctx, realmID, id)
	if err != nil {
		return nil, err
	}
	crl, der, err := parseCRL(crlPEM, a.cert)
	if err != nil {
		return nil, problem.ErrValidation.WithField("crl_pem", err.Error())
	}
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := scanAnchor(tx.QueryRow(ctx, `SELECT `+anchorCols+` FROM certificate_trust_anchors WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if cur.crl != nil && !newerCRL(cur.crl, cur.crl.Raw, crl, der) {
			return problem.ErrValidation.WithField("crl_pem", "not newer than the current list: a greater CRL number (or, without numbers, a later thisUpdate) is required")
		}
		if _, err := tx.Exec(ctx, `UPDATE certificate_trust_anchors SET revocation='crl', crl_der=$3, crl_next_update=$4 WHERE realm_id=$1 AND id=$2`,
			realmID, id, der, crl.NextUpdate); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "certificate.trust_anchor.crl_updated", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "trust_anchor", ID: id}, Metadata: map[string]any{"revoked": len(crl.RevokedCertificateEntries), "next_update": crl.NextUpdate}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Anchor(ctx, realmID, id)
}

// RemoveAnchor stops trusting an authority at once.
func (s *Service) RemoveAnchor(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE certificate_trust_anchors SET state='revoked' WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "certificate.trust_anchor.removed", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "trust_anchor", ID: id}})
		return err
	})
}

// Anchor returns one anchor.
func (s *Service) Anchor(ctx context.Context, realmID, id string) (*Anchor, error) {
	a, err := scanAnchor(s.d.DB.Pool.QueryRow(ctx, `SELECT `+anchorCols+` FROM certificate_trust_anchors WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return a, err
}

// Anchors lists a realm's active anchors, optionally for one purpose.
func (s *Service) Anchors(ctx context.Context, q storage.Querier, realmID, purpose string) ([]*Anchor, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT `+anchorCols+` FROM certificate_trust_anchors WHERE realm_id=$1 AND state='active' AND ($2='' OR purpose=$2)
		ORDER BY created_at`, realmID, purpose)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Anchor{}
	for rows.Next() {
		a, err := scanAnchor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Verify checks that cert (with optional intermediates presented with it)
// chains to an active anchor of the purpose, is valid now, carries the
// key usage for client authentication, and is not revoked under the
// anchor's policy. Anchors are tried in the order they were added; the first
// one the certificate chains to decides. It returns the anchor.
func (s *Service) Verify(ctx context.Context, q storage.Querier, realmID, purpose string, cert *x509.Certificate, intermediates []*x509.Certificate) (*Anchor, error) {
	anchors, err := s.Anchors(ctx, q, realmID, purpose)
	if err != nil {
		return nil, err
	}
	for _, a := range anchors {
		if err := s.VerifyAgainst(a, cert, intermediates); !errors.Is(err, ErrUntrusted) {
			if err != nil {
				return nil, err
			}
			return a, nil
		}
	}
	return nil, ErrUntrusted
}

// VerifyAgainst checks cert against one anchor only: it must chain to it, be
// valid now with a key usage that allows client authentication, and, with
// revocation "crl", no certificate of the chain below the anchor may be
// revoked. ErrUntrusted means it does not chain to this anchor.
func (s *Service) VerifyAgainst(a *Anchor, cert *x509.Certificate, intermediates []*x509.Certificate) error {
	if a == nil || a.cert == nil || a.State != "active" {
		return ErrUntrusted
	}
	now := s.d.Now()
	pool := x509.NewCertPool()
	for _, ic := range intermediates {
		pool.AddCert(ic)
	}
	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	chains, err := cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || len(chains) == 0 {
		return ErrUntrusted
	}
	if a.Revocation != "crl" {
		return nil
	}
	if a.crl == nil || !crlCurrent(a.crl, now) {
		return ErrNoCRL
	}
	// One acceptable chain is enough; otherwise a revocation is reported
	// before an unknown revocation status.
	var refused error
	for _, chain := range chains {
		err := checkChainCRL(chain, a)
		if err == nil {
			return nil
		}
		if refused == nil || errors.Is(err, ErrRevoked) {
			refused = err
		}
	}
	return refused
}

// crlCurrent reports whether a revocation list is still current: its next
// update has not passed. A list without a next update is refused at upload.
func crlCurrent(crl *x509.RevocationList, now time.Time) bool {
	return !crl.NextUpdate.IsZero() && now.Before(crl.NextUpdate)
}

// checkChainCRL checks every certificate of a verified chain (leaf first,
// the anchor last) against the revocation list of its issuer, from the
// anchor down. The anchor's CRL (signed by the anchor, checked at upload)
// covers the certificates the anchor issued itself: an intermediate, or the
// leaf when the anchor issued it directly. A certificate issued by an
// intermediate needs that intermediate's CRL, which an anchor does not hold:
// its status is unknown and the certificate is refused (ErrNoCRL), as with a
// stale list. Trust the issuing CA itself as an anchor, with its CRL, in
// that case.
func checkChainCRL(chain []*x509.Certificate, a *Anchor) error {
	for i := len(chain) - 2; i >= 0; i-- {
		c, issuer := chain[i], chain[i+1]
		if !bytes.Equal(issuer.Raw, a.cert.Raw) {
			return ErrNoCRL
		}
		for _, rc := range a.crl.RevokedCertificateEntries {
			if rc.SerialNumber != nil && rc.SerialNumber.Cmp(c.SerialNumber) == 0 {
				return ErrRevoked
			}
		}
	}
	return nil
}
