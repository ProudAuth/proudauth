package passkey

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/storage"
)

// LoadMetadata loads the operator's FIDO metadata BLOB (PASS-009), verified
// against the FIDO Alliance root or the configured private root.
func (s *Service) LoadMetadata(cfg configuration.WebAuthnConfig) error {
	if cfg.MetadataFile == "" {
		return nil
	}
	blob, err := os.ReadFile(cfg.MetadataFile)
	if err != nil {
		return fmt.Errorf("webauthn.metadata_file: %w", err)
	}
	var opts []metadata.DecoderOption
	if cfg.MetadataRootFile != "" {
		raw, err := os.ReadFile(cfg.MetadataRootFile)
		if err != nil {
			return fmt.Errorf("webauthn.metadata_root_file: %w", err)
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("webauthn.metadata_root_file: not a PEM certificate")
		}
		opts = append(opts, metadata.WithRootCertificate(base64.StdEncoding.EncodeToString(block.Bytes)))
	}
	dec, err := metadata.NewDecoder(append(opts, metadata.WithIgnoreEntryParsingErrors())...)
	if err != nil {
		return err
	}
	payload, err := dec.DecodeBytes(blob)
	if err != nil {
		return fmt.Errorf("webauthn.metadata_file: %w", err)
	}
	md, err := dec.Parse(payload)
	if err != nil {
		return fmt.Errorf("webauthn.metadata_file: %w", err)
	}
	s.metadata = md.ToMap()
	return nil
}

// TrustedAuthenticator is an authenticator model a realm trusts (PASS-009):
// registrations claiming its AAGUID must carry an attestation chaining to
// one of its root certificates.
type TrustedAuthenticator struct {
	ID               string    `json:"id"`
	AAGUID           string    `json:"aaguid"`
	Description      string    `json:"description"`
	RootCertificates []string  `json:"root_certificates"`
	CreatedAt        time.Time `json:"created_at"`
}

// TrustedAuthenticatorInput adds one.
type TrustedAuthenticatorInput struct {
	AAGUID           string   `json:"aaguid"`
	Description      string   `json:"description"`
	RootCertificates []string `json:"root_certificates"` // PEM
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TrustedAuthenticators lists a realm's trusted authenticator models.
func (s *Service) TrustedAuthenticators(ctx context.Context, q storage.Querier, realmID string) ([]TrustedAuthenticator, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT id, aaguid::text, description, root_certificates, created_at FROM webauthn_trusted_authenticators
		WHERE realm_id=$1 ORDER BY created_at`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustedAuthenticator{}
	for rows.Next() {
		var t TrustedAuthenticator
		var roots [][]byte
		if err := rows.Scan(&t.ID, &t.AAGUID, &t.Description, &roots, &t.CreatedAt); err != nil {
			return nil, err
		}
		for _, r := range roots {
			t.RootCertificates = append(t.RootCertificates, certPEM(r))
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AddTrustedAuthenticator registers a trusted model.
func (s *Service) AddTrustedAuthenticator(ctx context.Context, realmID string, in TrustedAuthenticatorInput, actor audit.Ref) (*TrustedAuthenticator, error) {
	u, err := uuid.Parse(in.AAGUID)
	if err != nil || u == uuid.Nil || strings.ToLower(in.AAGUID) != u.String() {
		return nil, problem.ErrValidation.WithField("aaguid", "a lower-case, non-zero AAGUID")
	}
	if in.Description == "" || len(in.Description) > 200 {
		return nil, problem.ErrValidation.WithField("description", "1 to 200 characters")
	}
	if len(in.RootCertificates) == 0 || len(in.RootCertificates) > 10 {
		return nil, problem.ErrValidation.WithField("root_certificates", "1 to 10 PEM certificates")
	}
	var ders [][]byte
	now := s.d.Now()
	for _, p := range in.RootCertificates {
		block, rest := pem.Decode([]byte(p))
		if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) > 0 {
			return nil, problem.ErrValidation.WithField("root_certificates", "one PEM certificate per entry")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !c.IsCA || now.After(c.NotAfter) {
			return nil, problem.ErrValidation.WithField("root_certificates", "unexpired CA certificates")
		}
		ders = append(ders, block.Bytes)
	}
	id := ids.New("wta")
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM webauthn_trusted_authenticators WHERE realm_id=$1`, realmID).Scan(&n); err != nil {
			return err
		}
		if n >= 200 {
			return problem.ErrConflict.WithDetail("at most 200 trusted authenticators")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO webauthn_trusted_authenticators (id, realm_id, aaguid, description, root_certificates, created_by_id, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, realmID, u.String(), in.Description, ders, actor.ID, now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("this AAGUID is already trusted")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "webauthn.trusted_authenticator.added", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "webauthn_trusted_authenticator", ID: id}, Category: "security",
			Metadata: map[string]any{"aaguid": u.String(), "roots": len(ders)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	list, err := s.TrustedAuthenticators(ctx, nil, realmID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i], nil
		}
	}
	return nil, problem.ErrNotFound
}

// RemoveTrustedAuthenticator removes one. Credentials registered under it
// keep working; new registrations need other trusted metadata.
func (s *Service) RemoveTrustedAuthenticator(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var aaguid string
		if err := tx.QueryRow(ctx, `DELETE FROM webauthn_trusted_authenticators WHERE realm_id=$1 AND id=$2 RETURNING aaguid::text`, realmID, id).Scan(&aaguid); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "webauthn.trusted_authenticator.removed", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "webauthn_trusted_authenticator", ID: id}, Category: "security", Metadata: map[string]any{"aaguid": aaguid}})
		return err
	})
}

// trustProvider is the metadata a trusted-attestation registration is
// checked against: the operator's FIDO metadata, with the realm's own
// trusted authenticators taking precedence for their AAGUIDs. An entry must
// exist for the AAGUID, its status must not be compromised or revoked, and
// the attestation certificate must chain to its roots.
func (s *Service) trustProvider(ctx context.Context, q storage.Querier, realmID string) (metadata.Provider, map[uuid.UUID]string, error) {
	entries := map[uuid.UUID]*metadata.Entry{}
	source := map[uuid.UUID]string{}
	for k, v := range s.metadata {
		entries[k], source[k] = v, "fido_metadata"
	}
	list, err := s.TrustedAuthenticators(ctx, q, realmID)
	if err != nil {
		return nil, nil, err
	}
	for _, t := range list {
		u, _ := uuid.Parse(t.AAGUID)
		var roots []*x509.Certificate
		for _, p := range t.RootCertificates {
			block, _ := pem.Decode([]byte(p))
			if c, err := x509.ParseCertificate(block.Bytes); err == nil {
				roots = append(roots, c)
			}
		}
		entries[u] = &metadata.Entry{AaGUID: u, MetadataStatement: metadata.Statement{AaGUID: u, Description: t.Description,
			AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.BasicFull, metadata.AttCA, metadata.AnonCA},
			AttestationRootCertificates: roots, MultiDeviceCredentialSupport: metadata.MultiDeviceCredentialExplicit}}
		source[u] = "realm"
	}
	if len(entries) == 0 {
		return nil, nil, problem.ErrFeatureDisabled.WithDetail("trusted attestation is required but no trusted authenticator metadata is configured")
	}
	p, err := memory.New(memory.WithMetadata(entries), memory.WithValidateEntry(true), memory.WithValidateEntryPermitZeroAAGUID(false),
		memory.WithValidateTrustAnchor(true), memory.WithValidateStatus(true), memory.WithValidateAttestationTypes(true))
	return p, source, err
}

// checkModel applies the realm's authenticator allow and block lists. A
// zero AAGUID (an authenticator that does not name its model) is admitted
// by an allow list only when the list names it.
func checkModel(w realm.WebAuthnPolicy, aaguid string) error {
	if aaguid == "" {
		aaguid = uuid.Nil.String()
	}
	if len(w.AllowedAAGUIDs) > 0 && !slices.Contains(w.AllowedAAGUIDs, aaguid) {
		return ErrModelNotAllowed
	}
	if slices.Contains(w.BlockedAAGUIDs, aaguid) {
		return ErrModelNotAllowed
	}
	return nil
}

// ErrModelNotAllowed refuses an authenticator model the realm does not admit.
var ErrModelNotAllowed = problem.ErrValidation.WithDetail("this authenticator model is not allowed by realm policy").
	WithField("credential", "authenticator_not_allowed")

// ErrUntrustedAttestation refuses a registration without trusted attestation.
var ErrUntrustedAttestation = problem.ErrValidation.WithDetail("the authenticator did not provide trusted attestation, which realm policy requires").
	WithField("credential", "attestation_not_trusted")
