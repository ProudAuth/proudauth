// Package passkey runs WebAuthn registration and authentication ceremonies
// (PASS-001..PASS-007, MFA-007, SEC-012). Cryptographic verification of
// attestation and assertion responses is delegated to the go-webauthn library
// (ARC-009); this package owns ceremony binding, storage, policy and evidence.
//
// Ceremony binding: each ceremony row is bound to realm, kind, RP ID, the user
// (when known) and the authentication transaction (when inside one). Ceremonies
// expire after CeremonyTTL and are consumed atomically exactly once, so a
// replayed response or a response for another transaction fails.
package passkey

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/session"
	"github.com/proudauth/proudauth/internal/storage"
)

// CeremonyTTL bounds how long options remain usable.
const CeremonyTTL = 5 * time.Minute

// MaxCredentialsPerUser bounds enrolled authenticators (NFR-001).
const MaxCredentialsPerUser = 20

var (
	// ErrCeremony is returned for any invalid, expired, replayed or mismatched
	// ceremony response. Details are audited, not returned to the caller.
	ErrCeremony = problem.ErrInvalidProof.WithDetail("the passkey response could not be verified")
	// ErrCounterAnomaly rejects a device-bound authenticator whose signature
	// counter did not advance (possible cloned authenticator, PASS-007).
	ErrCounterAnomaly = problem.ErrInvalidProof.WithDetail("the authenticator reported an unexpected signature counter")
	// ErrSyncedNotAllowed rejects backup-eligible (synced) passkeys when realm
	// policy requires device-bound authenticators (PASS-006).
	ErrSyncedNotAllowed = problem.ErrValidation.WithDetail("synced passkeys are not allowed by realm policy").
				WithField("credential", "backup_eligible_not_allowed")
)

// Service runs ceremonies.
type Service struct {
	d *runtime.Deps
	// CustomHosts lists a realm's verified custom hosts (DEP-014): when the
	// origins are derived rather than configured, those under the RP ID are
	// accepted origins too.
	CustomHosts func(realmID string) []string
	// metadata is the operator's FIDO metadata (PASS-009), by AAGUID.
	metadata map[uuid.UUID]*metadata.Entry
}

// New builds the service.
func New(d *runtime.Deps) *Service { return &Service{d: d} }

// RelyingParty describes the effective RP configuration for a realm.
type RelyingParty struct {
	ID      string   `json:"rp_id"`
	Name    string   `json:"rp_name"`
	Origins []string `json:"origins"`
}

// RelyingPartyFor resolves the RP ID and allowed origins. Explicit realm policy
// wins; otherwise the login UI origin, otherwise the issuer origin. Changing the
// resolved RP ID orphans existing passkeys (PASS-008), so production realms
// should configure it explicitly.
func (s *Service) RelyingPartyFor(rlm *realm.Realm) (RelyingParty, error) {
	p := rlm.Policy.WebAuthn
	rp := RelyingParty{ID: p.RPID, Name: p.RPName, Origins: p.Origins}
	if rp.ID == "" || len(rp.Origins) == 0 {
		base := rlm.Policy.Interaction.LoginUIURL
		if base == "" {
			base = s.d.Cfg.Issuer(rlm.Name)
		}
		u, err := url.Parse(base)
		if err != nil || u.Host == "" {
			return rp, problem.ErrFeatureDisabled.WithDetail("passkeys require a configured relying party")
		}
		if rp.ID == "" {
			rp.ID = u.Hostname()
		}
		if len(rp.Origins) == 0 {
			rp.Origins = []string{u.Scheme + "://" + u.Host}
			if s.CustomHosts != nil {
				id := strings.ToLower(rp.ID)
				for _, h := range s.CustomHosts(rlm.ID) {
					if h == id || strings.HasSuffix(h, "."+id) {
						rp.Origins = append(rp.Origins, "https://"+h)
					}
				}
			}
		}
	}
	if rp.Name == "" {
		rp.Name = rlm.DisplayName
	}
	if rp.Name == "" {
		rp.Name = rlm.Name
	}
	return rp, nil
}

// relyingParty builds the WebAuthn configuration for a ceremony. mds, when
// set, makes registration verify attestation against trusted metadata.
func (s *Service) relyingParty(rlm *realm.Realm, requireUV bool, mds metadata.Provider) (*webauthn.WebAuthn, RelyingParty, error) {
	rp, err := s.RelyingPartyFor(rlm)
	if err != nil {
		return nil, rp, err
	}
	origins := rp.Origins
	if s.d.Cfg.WebAuthn.RelatedOrigins {
		// WebAuthn Level 3 related origins (PASS-010), only when the operator
		// allows them; a client resolves them through /.well-known/webauthn.
		origins = append(slices.Clone(origins), rlm.Policy.WebAuthn.RelatedOrigins...)
	}
	attestation := protocol.PreferNoAttestation
	switch rlm.Policy.WebAuthn.Attestation {
	case "indirect":
		attestation = protocol.PreferIndirectAttestation
	case "direct":
		attestation = protocol.PreferDirectAttestation
	case "enterprise":
		attestation = protocol.PreferEnterpriseAttestation
	}
	uv := protocol.VerificationPreferred
	switch rlm.Policy.WebAuthn.UserVerification {
	case "required":
		uv = protocol.VerificationRequired
	case "discouraged":
		uv = protocol.VerificationDiscouraged
	}
	if requireUV {
		uv = protocol.VerificationRequired
	}
	timeout := webauthn.TimeoutConfig{Enforce: false, Timeout: CeremonyTTL, TimeoutUVD: CeremonyTTL}
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  rp.ID,
		RPDisplayName:         rp.Name,
		RPOrigins:             origins,
		AttestationPreference: attestation,
		MDS:                   mds,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: uv,
		},
		Timeouts:  webauthn.TimeoutsConfig{Login: timeout, Registration: timeout},
		Filtering: &webauthn.FilteringConfig{ProhibitBackupEligibility: !rlm.Policy.WebAuthn.AllowSynced},
	})
	if err != nil {
		return nil, rp, problem.ErrFeatureDisabled.WithDetail("the passkey relying party configuration is invalid")
	}
	return wa, rp, nil
}

// ---------- accounts ----------

type credRow struct {
	id             string
	credentialID   []byte
	publicKey      []byte
	format         string
	aaguid         []byte
	signCount      uint32
	backupEligible bool
	backupState    bool
	userVerified   bool
	transports     []string
}

type account struct {
	userID  string
	handle  []byte
	name    string
	display string
	rows    []credRow
}

func (a *account) WebAuthnID() []byte          { return a.handle }
func (a *account) WebAuthnName() string        { return a.name }
func (a *account) WebAuthnDisplayName() string { return a.display }
func (a *account) WebAuthnCredentials() []webauthn.Credential {
	out := make([]webauthn.Credential, 0, len(a.rows))
	for _, r := range a.rows {
		var raw protocol.AuthenticatorFlags = protocol.FlagUserPresent
		if r.userVerified {
			raw |= protocol.FlagUserVerified
		}
		if r.backupEligible {
			raw |= protocol.FlagBackupEligible
		}
		if r.backupState {
			raw |= protocol.FlagBackupState
		}
		tr := make([]protocol.AuthenticatorTransport, 0, len(r.transports))
		for _, t := range r.transports {
			tr = append(tr, protocol.AuthenticatorTransport(t))
		}
		out = append(out, webauthn.Credential{ID: r.credentialID, PublicKey: r.publicKey, AttestationFormat: r.format,
			Transport: tr, Flags: webauthn.NewCredentialFlags(raw),
			Authenticator: webauthn.Authenticator{AAGUID: r.aaguid, SignCount: r.signCount}})
	}
	return out
}

func (a *account) row(credentialID []byte) *credRow {
	for i := range a.rows {
		if bytes.Equal(a.rows[i].credentialID, credentialID) {
			return &a.rows[i]
		}
	}
	return nil
}

func (a *account) descriptors() []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, 0, len(a.rows))
	for _, c := range a.WebAuthnCredentials() {
		out = append(out, c.Descriptor())
	}
	return out
}

// load reads a user's handle and active credentials. With create, a missing
// handle is generated (32 random bytes; never derived from user data).
func (s *Service) load(ctx context.Context, q storage.Querier, realmID, userID string, create bool) (*account, error) {
	a := &account{userID: userID}
	var display, username, email string
	err := q.QueryRow(ctx, `SELECT u.webauthn_user_handle, coalesce(u.display_name,''),
		coalesce((SELECT original_value FROM user_identifiers WHERE user_id=u.id AND type='username' LIMIT 1),''),
		coalesce((SELECT original_value FROM user_identifiers WHERE user_id=u.id AND type='email' ORDER BY is_primary DESC, created_at LIMIT 1),'')
		FROM users u WHERE u.realm_id=$1 AND u.id=$2`, realmID, userID).Scan(&a.handle, &display, &username, &email)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	if len(a.handle) == 0 && create {
		h := make([]byte, 32)
		if _, err := rand.Read(h); err != nil {
			return nil, err
		}
		if err := q.QueryRow(ctx, `UPDATE users SET webauthn_user_handle=coalesce(webauthn_user_handle, $3) WHERE realm_id=$1 AND id=$2
			RETURNING webauthn_user_handle`, realmID, userID, h).Scan(&a.handle); err != nil {
			return nil, err
		}
	}
	a.name = firstNonEmpty(email, username, userID)
	a.display = firstNonEmpty(display, username, email, userID)
	rows, err := q.Query(ctx, `SELECT id, credential_id, public_key, attestation_format, coalesce(aaguid,''::bytea), sign_count,
		backup_eligible, backup_state, user_verified, transports FROM webauthn_credentials
		WHERE realm_id=$1 AND user_id=$2 AND state='active' ORDER BY created_at`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r credRow
		var sc int64
		if err := rows.Scan(&r.id, &r.credentialID, &r.publicKey, &r.format, &r.aaguid, &sc, &r.backupEligible, &r.backupState,
			&r.userVerified, &r.transports); err != nil {
			return nil, err
		}
		r.signCount = uint32(sc)
		a.rows = append(a.rows, r)
	}
	return a, rows.Err()
}

// decoyIDLengths are credential ID lengths common among authenticators
// (password managers and platform authenticators at the short end, security
// keys' non-discoverable credentials at the long end).
var decoyIDLengths = []int{16, 20, 32, 48, 64}

// decoy returns a stable, non-existent account for an unknown identifier or
// an account without passkeys, so identified options do not reveal whether
// the account or its passkeys exist (SEC-005). Everything about it comes from
// one keyed HMAC of realm and identifier: the user handle, the number of
// credential descriptors (1 to 3) and each credential ID with its length (one
// of decoyIDLengths). Decoys carry no transports, like every identified allow
// list (BeginLogin). A real account with more than three passkeys is still
// told apart by the count.
func (s *Service) decoy(realmID, identifier string) *account {
	k := s.d.Keys.DeriveBytes(keys.PurposeLookup, "webauthn-decoy")
	mac := func(label string) []byte {
		h := hmac.New(sha256.New, k)
		h.Write([]byte(realmID + "|" + label + "|" + strings.ToLower(identifier)))
		return h.Sum(nil)
	}
	a := &account{handle: mac("handle"), name: identifier, display: identifier}
	shape := mac("shape")
	for i := range 1 + int(shape[0])%3 {
		id := append(mac(fmt.Sprintf("credential|%d|0", i)), mac(fmt.Sprintf("credential|%d|1", i))...)
		a.rows = append(a.rows, credRow{credentialID: id[:decoyIDLengths[int(shape[1+i])%len(decoyIDLengths)]]})
	}
	return a
}

// ---------- ceremonies ----------

func (s *Service) saveCeremony(ctx context.Context, tx pgx.Tx, realmID, kind, userID, transactionID, rpID string, sd *webauthn.SessionData) (string, error) {
	now := s.d.Now()
	sd.Expires = time.Time{} // expiry is enforced with the injected clock below
	raw, err := json.Marshal(sd)
	if err != nil {
		return "", err
	}
	if transactionID != "" {
		// A new ceremony supersedes earlier open ones for the same transaction.
		if _, err := tx.Exec(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$3 WHERE transaction_id=$1 AND kind=$2 AND consumed_at IS NULL`,
			transactionID, kind, now); err != nil {
			return "", err
		}
	}
	id := ids.New("wac")
	_, err = tx.Exec(ctx, `INSERT INTO webauthn_ceremonies (id, realm_id, kind, user_id, transaction_id, rp_id, session_data, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, realmID, kind, nilIfEmpty(userID), nilIfEmpty(transactionID), rpID, raw, now.Add(CeremonyTTL), now)
	return id, err
}

// consume atomically claims an open ceremony. For transaction ceremonies the
// latest open ceremony of the transaction is used; otherwise ceremonyID selects it.
func (s *Service) consume(ctx context.Context, tx pgx.Tx, realmID, kind, ceremonyID, transactionID, userID string) (*webauthn.SessionData, string, error) {
	now := s.d.Now()
	var raw []byte
	var rpID, boundUser string
	var expires time.Time
	var err error
	if ceremonyID == "" {
		if transactionID == "" {
			return nil, "", ErrCeremony
		}
		err = tx.QueryRow(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$4 WHERE id = (SELECT id FROM webauthn_ceremonies
			WHERE realm_id=$1 AND transaction_id=$2 AND kind=$3 AND consumed_at IS NULL ORDER BY created_at DESC LIMIT 1)
			RETURNING session_data, rp_id, coalesce(user_id,''), expires_at`, realmID, transactionID, kind, now).Scan(&raw, &rpID, &boundUser, &expires)
	} else {
		err = tx.QueryRow(ctx, `UPDATE webauthn_ceremonies SET consumed_at=$5 WHERE id=$1 AND realm_id=$2 AND kind=$3
			AND coalesce(transaction_id,'')=$4 AND consumed_at IS NULL
			RETURNING session_data, rp_id, coalesce(user_id,''), expires_at`, ceremonyID, realmID, kind, transactionID, now).Scan(&raw, &rpID, &boundUser, &expires)
	}
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, "", ErrCeremony
		}
		return nil, "", err
	}
	if !now.Before(expires) {
		return nil, "", ErrCeremony
	}
	if userID != "" && boundUser != "" && boundUser != userID {
		return nil, "", ErrCeremony
	}
	var sd webauthn.SessionData
	if err := json.Unmarshal(raw, &sd); err != nil {
		return nil, "", err
	}
	return &sd, boundUser, nil
}

// ---------- registration ----------

// RegistrationOptions are returned to the client to call navigator.credentials.create.
type RegistrationOptions struct {
	CeremonyID string                                      `json:"ceremony_id"`
	PublicKey  protocol.PublicKeyCredentialCreationOptions `json:"public_key"`
	ExpiresAt  time.Time                                   `json:"expires_at"`
}

// BeginRegistration starts enrollment for an authenticated user (PASS-001). The
// caller enforces recent authentication.
func (s *Service) BeginRegistration(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, userID, transactionID string, requireUV bool) (*RegistrationOptions, error) {
	wa, rp, err := s.relyingParty(rlm, requireUV, nil)
	if err != nil {
		return nil, err
	}
	a, err := s.load(ctx, tx, rlm.ID, userID, true)
	if err != nil {
		return nil, err
	}
	if len(a.rows) >= MaxCredentialsPerUser {
		return nil, problem.ErrConflict.WithDetailf("at most %d passkeys can be registered", MaxCredentialsPerUser)
	}
	// credProps reports whether a discoverable credential was created
	// (PASS-003). credProtect is requested only when the realm asks for it
	// (PASS-010); unrequested extension outputs fail the ceremony.
	exts := []webauthn.ExtensionOption{webauthn.WithExtensionCredProps()}
	if cp := rlm.Policy.WebAuthn.CredentialProtection; cp != "" {
		exts = append(exts, webauthn.WithExtensionCredentialProtectionPolicy(protocol.CredentialProtectionPolicy(cp), rlm.Policy.WebAuthn.EnforceCredentialProtection))
	}
	creation, sd, err := wa.BeginRegistration(a, webauthn.WithExclusions(a.descriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithExtensions(exts...))
	if err != nil {
		return nil, fmt.Errorf("passkey registration options: %w", err)
	}
	id, err := s.saveCeremony(ctx, tx, rlm.ID, "registration", userID, transactionID, rp.ID, sd)
	if err != nil {
		return nil, err
	}
	// Starting an enrollment is evidence too (MFA-012), like TOTP's.
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.webauthn.enrollment_started", RealmID: rlm.ID, Actor: audit.Ref{Type: "user", ID: userID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"ceremony_id": id, "transaction_id": transactionID}}); err != nil {
		return nil, err
	}
	return &RegistrationOptions{CeremonyID: id, PublicKey: creation.Response, ExpiresAt: s.d.Now().Add(CeremonyTTL)}, nil
}

// Credential is the safe metadata of an enrolled passkey (PASS-004).
type Credential struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	BackupEligible bool   `json:"backup_eligible"`
	BackupState    bool   `json:"synced"`
	UserVerified   bool   `json:"user_verified"`
	Discoverable   bool   `json:"discoverable"`
	AAGUID         string `json:"aaguid,omitempty"`
	// AttestationTrusted: the attestation chained to trusted metadata
	// (PASS-009); otherwise the AAGUID is self-reported.
	AttestationTrusted bool       `json:"attestation_trusted"`
	AttestationFormat  string     `json:"attestation_format,omitempty"`
	Transports         []string   `json:"transports"`
	CreatedAt          time.Time  `json:"created_at"`
	LastUsedAt         *time.Time `json:"last_used_at,omitempty"`
}

// FinishRegistration verifies the attestation response and stores the credential.
// The returned factor proves possession of the new authenticator.
func (s *Service) FinishRegistration(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, userID, ceremonyID, transactionID string,
	response []byte, name string, actor audit.Ref) (*Credential, session.Factor, error) {
	sd, _, err := s.consume(ctx, tx, rlm.ID, "registration", ceremonyID, transactionID, userID)
	if err != nil {
		return nil, session.Factor{}, err
	}
	// Trusted attestation (PASS-009) is verified against metadata during the
	// ceremony; the provider records where each AAGUID's trust came from.
	var mds metadata.Provider
	var sources map[uuid.UUID]string
	if rlm.Policy.WebAuthn.RequireTrustedAttestation {
		if mds, sources, err = s.trustProvider(ctx, tx, rlm.ID); err != nil {
			return nil, session.Factor{}, err
		}
	}
	wa, rp, err := s.relyingParty(rlm, sd.UserVerification == protocol.VerificationRequired, mds)
	if err != nil {
		return nil, session.Factor{}, err
	}
	if sd.RelyingPartyID != "" && sd.RelyingPartyID != rp.ID {
		return nil, session.Factor{}, s.fail(ctx, tx, rlm.ID, userID, actor, "mfa.webauthn.enrollment_failed", "rp_id_changed", ErrCeremony)
	}
	a, err := s.load(ctx, tx, rlm.ID, userID, false)
	if err != nil {
		return nil, session.Factor{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, session.Factor{}, s.fail(ctx, tx, rlm.ID, userID, actor, "mfa.webauthn.enrollment_failed", "malformed_response", ErrCeremony, err)
	}
	cred, err := wa.CreateCredential(a, *sd, parsed)
	if err != nil {
		reason, outErr := "verification_failed", ErrCeremony
		var pe *protocol.Error
		switch {
		case errors.As(err, &pe) && pe.Type == protocol.ErrPolicyRestriction.Type:
			reason, outErr = "synced_not_allowed", ErrSyncedNotAllowed
		case errors.As(err, &pe) && pe.Type == protocol.ErrMetadata.Type && mds != nil:
			reason, outErr = "attestation_not_trusted", ErrUntrustedAttestation
		}
		return nil, session.Factor{}, s.fail(ctx, tx, rlm.ID, userID, actor, "mfa.webauthn.enrollment_failed", reason, outErr, err)
	}
	aaguid := ""
	if len(cred.Authenticator.AAGUID) == 16 {
		aaguid = formatAAGUID(cred.Authenticator.AAGUID)
	}
	if err := checkModel(rlm.Policy.WebAuthn, aaguid); err != nil {
		return nil, session.Factor{}, s.fail(ctx, tx, rlm.ID, userID, actor, "mfa.webauthn.enrollment_failed", "authenticator_not_allowed", err)
	}
	// The library verified the chain to trusted roots; "none" and self
	// attestation carry no chain, so they are never trusted.
	trusted, source := false, ""
	if mds != nil {
		switch metadata.AuthenticatorAttestationType(cred.AttestationType) {
		case metadata.BasicFull, metadata.AttCA, metadata.AnonCA:
			u, _ := uuid.FromBytes(cred.Authenticator.AAGUID)
			trusted, source = true, sources[u]
		}
		if !trusted {
			return nil, session.Factor{}, s.fail(ctx, tx, rlm.ID, userID, actor, "mfa.webauthn.enrollment_failed", "attestation_not_trusted", ErrUntrustedAttestation)
		}
	}
	name = strings.TrimSpace(name)
	if len(name) > 64 {
		name = canonical.Truncate(name, 64)
	}
	if name == "" {
		name = "Passkey"
	}
	discoverable := cred.Extensions.RK != nil && *cred.Extensions.RK
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}
	now := s.d.Now()
	out := &Credential{ID: ids.New(ids.WebAuthn), Name: name, BackupEligible: cred.Flags.BackupEligible, BackupState: cred.Flags.BackupState,
		UserVerified: cred.Flags.UserVerified, Discoverable: discoverable, Transports: transports, CreatedAt: now}
	out.AAGUID, out.AttestationTrusted, out.AttestationFormat = aaguid, trusted, firstNonEmpty(cred.AttestationFormat, "none")
	_, err = tx.Exec(ctx, `INSERT INTO webauthn_credentials (id, realm_id, user_id, credential_id, public_key, attestation_type, attestation_format,
		aaguid, rp_id, sign_count, backup_eligible, backup_state, user_verified, transports, discoverable, name, last_used_at, created_at,
		attestation_trusted, attestation_source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17,$18,$19)`,
		out.ID, rlm.ID, userID, cred.ID, cred.PublicKey, cred.AttestationType, firstNonEmpty(cred.AttestationFormat, "none"),
		cred.Authenticator.AAGUID, rp.ID, int64(cred.Authenticator.SignCount), cred.Flags.BackupEligible, cred.Flags.BackupState,
		cred.Flags.UserVerified, transports, discoverable, name, now, trusted, nilIfEmpty(source))
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, session.Factor{}, problem.ErrConflict.WithDetail("this authenticator is already registered")
		}
		return nil, session.Factor{}, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.webauthn.enrolled", RealmID: rlm.ID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "webauthn_credential", ID: out.ID},
		Metadata: map[string]any{"backup_eligible": out.BackupEligible, "user_verified": out.UserVerified, "discoverable": discoverable,
			"attestation_format": firstNonEmpty(cred.AttestationFormat, "none"), "aaguid": out.AAGUID, "rp_id": rp.ID,
			"attestation_trusted": trusted, "attestation_source": source}}); err != nil {
		return nil, session.Factor{}, err
	}
	return out, factorFor(out.ID, cred.Flags.BackupEligible, cred.Flags.UserVerified, now), nil
}

// ---------- authentication ----------

// AssertionOptions are returned to the client to call navigator.credentials.get.
type AssertionOptions struct {
	PublicKey protocol.PublicKeyCredentialRequestOptions `json:"public_key"`
	ExpiresAt time.Time                                  `json:"expires_at"`
}

// BeginLogin starts an authentication ceremony bound to a transaction. With no
// user and no identifier it is a discoverable (username-less) ceremony
// (PASS-003). A sign-in that identified an account before primary
// authentication passes its identifier: the allow list then contains the
// account's credentials without their stored transports, and an unknown
// identifier or an account without passkeys receives a stable decoy of the
// same shape, so neither the number of descriptors (up to three), the
// transports nor the credential ID lengths reveal whether the account or its
// passkeys exist (SEC-005). Transports are hints; without them the browser
// offers every way to reach the authenticator. A second-factor ceremony
// (userID without identifier, after primary authentication) keeps them.
func (s *Service) BeginLogin(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, transactionID, userID, identifier string, requireUV bool) (*AssertionOptions, error) {
	wa, rp, err := s.relyingParty(rlm, requireUV, nil)
	if err != nil {
		return nil, err
	}
	var assertion *protocol.CredentialAssertion
	var sd *webauthn.SessionData
	bound := ""
	switch {
	case userID != "":
		a, err := s.load(ctx, tx, rlm.ID, userID, false)
		if err != nil {
			return nil, err
		}
		if len(a.rows) == 0 || len(a.handle) == 0 {
			a = s.decoy(rlm.ID, firstNonEmpty(identifier, userID))
		} else {
			bound = userID
			if identifier != "" {
				for i := range a.rows {
					a.rows[i].transports = nil
				}
			}
		}
		assertion, sd, err = wa.BeginLogin(a)
		if err != nil {
			return nil, fmt.Errorf("passkey assertion options: %w", err)
		}
	case identifier != "":
		assertion, sd, err = wa.BeginLogin(s.decoy(rlm.ID, identifier))
		if err != nil {
			return nil, fmt.Errorf("passkey assertion options: %w", err)
		}
	default:
		assertion, sd, err = wa.BeginDiscoverableLogin()
		if err != nil {
			return nil, fmt.Errorf("passkey assertion options: %w", err)
		}
	}
	if _, err := s.saveCeremony(ctx, tx, rlm.ID, "authentication", bound, transactionID, rp.ID, sd); err != nil {
		return nil, err
	}
	return &AssertionOptions{PublicKey: assertion.Response, ExpiresAt: s.d.Now().Add(CeremonyTTL)}, nil
}

// FinishLogin verifies an assertion for the transaction's open ceremony. When
// expectedUserID is set (identified user or second factor), the credential must
// belong to that user. It returns the authenticated user and the factor.
func (s *Service) FinishLogin(ctx context.Context, tx pgx.Tx, rlm *realm.Realm, transactionID, expectedUserID string, response []byte, actor audit.Ref) (string, session.Factor, error) {
	sd, boundUser, err := s.consume(ctx, tx, rlm.ID, "authentication", "", transactionID, "")
	if err != nil {
		return "", session.Factor{}, err
	}
	failUser := firstNonEmpty(expectedUserID, boundUser)
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, failUser, actor, "mfa.webauthn.failed", "malformed_response", ErrCeremony, err)
	}
	wa, rp, err := s.relyingParty(rlm, sd.UserVerification == protocol.VerificationRequired, nil)
	if err != nil {
		return "", session.Factor{}, err
	}
	if sd.RelyingPartyID != "" && sd.RelyingPartyID != rp.ID {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, failUser, actor, "mfa.webauthn.failed", "rp_id_changed", ErrCeremony)
	}
	// Resolve the credential owner inside this realm only (DOM-007).
	var owner string
	if err := tx.QueryRow(ctx, `SELECT user_id FROM webauthn_credentials WHERE realm_id=$1 AND credential_id=$2 AND state='active'`,
		rlm.ID, []byte(parsed.RawID)).Scan(&owner); err != nil {
		if storage.IsNoRows(err) {
			return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, failUser, actor, "mfa.webauthn.failed", "unknown_credential", ErrCeremony)
		}
		return "", session.Factor{}, err
	}
	if (expectedUserID != "" && owner != expectedUserID) || (boundUser != "" && owner != boundUser) {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, failUser, actor, "mfa.webauthn.failed", "credential_user_mismatch", ErrCeremony)
	}
	a, err := s.load(ctx, tx, rlm.ID, owner, false)
	if err != nil {
		return "", session.Factor{}, err
	}
	var cred *webauthn.Credential
	if len(sd.UserID) == 0 {
		_, cred, err = wa.ValidatePasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			if !bytes.Equal(userHandle, a.handle) {
				return nil, errors.New("user handle mismatch")
			}
			return a, nil
		}, *sd, parsed)
	} else {
		cred, err = wa.ValidateLogin(a, *sd, parsed)
	}
	if err != nil {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, owner, actor, "mfa.webauthn.failed", "verification_failed", ErrCeremony, err)
	}
	row := a.row(cred.ID)
	if row == nil {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, owner, actor, "mfa.webauthn.failed", "unknown_credential", ErrCeremony)
	}
	now := s.d.Now()
	if row.backupEligible && !rlm.Policy.WebAuthn.AllowSynced {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, owner, actor, "mfa.webauthn.failed", "synced_not_allowed", ErrCeremony)
	}
	// Authenticator model restrictions apply to enrolled passkeys too, so
	// blocking a model takes effect at the next sign-in (PASS-009).
	model := ""
	if len(row.aaguid) == 16 {
		model = formatAAGUID(row.aaguid)
	}
	if err := checkModel(rlm.Policy.WebAuthn, model); err != nil {
		return "", session.Factor{}, s.fail(ctx, tx, rlm.ID, owner, actor, "mfa.webauthn.failed", "authenticator_not_allowed", err)
	}
	// Signature counter policy (PASS-007, TEST-025): synced passkeys commonly
	// report 0 or non-monotonic counters, so for backup-eligible credentials an
	// anomaly is recorded as a risk signal only. A device-bound authenticator
	// whose counter fails to advance may be cloned and is rejected.
	if cred.Authenticator.CloneWarning {
		handling := "rejected_device_bound"
		if row.backupEligible {
			handling = "accepted_synced"
		}
		if _, err := tx.Exec(ctx, `UPDATE webauthn_credentials SET counter_anomalies=counter_anomalies+1, last_counter_anomaly_at=$2 WHERE id=$1`, row.id, now); err != nil {
			return "", session.Factor{}, err
		}
		outcome := audit.Success
		if !row.backupEligible {
			outcome = audit.Failure
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.webauthn.counter_anomaly", RealmID: rlm.ID, Actor: actor, Outcome: outcome,
			Subject: &audit.Ref{Type: "user", ID: owner}, Target: &audit.Ref{Type: "webauthn_credential", ID: row.id}, Category: "security",
			Metadata: map[string]any{"stored_counter": row.signCount, "presented_counter": parsed.Response.AuthenticatorData.Counter,
				"backup_eligible": row.backupEligible, "handling": handling}}); err != nil {
			return "", session.Factor{}, err
		}
		if !row.backupEligible {
			return "", session.Factor{}, &rejection{err: ErrCounterAnomaly}
		}
	}
	newCount := cred.Authenticator.SignCount
	if cred.Authenticator.CloneWarning {
		newCount = row.signCount // never move a counter backwards
	}
	if _, err := tx.Exec(ctx, `UPDATE webauthn_credentials SET sign_count=$2, backup_state=$3, user_verified=(user_verified OR $4), last_used_at=$5 WHERE id=$1`,
		row.id, int64(newCount), cred.Flags.BackupState, parsed.Response.AuthenticatorData.Flags.HasUserVerified(), now); err != nil {
		return "", session.Factor{}, err
	}
	uv := parsed.Response.AuthenticatorData.Flags.HasUserVerified()
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.webauthn.used", RealmID: rlm.ID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: owner}, Target: &audit.Ref{Type: "webauthn_credential", ID: row.id},
		Metadata: map[string]any{"user_verified": uv, "backup_eligible": row.backupEligible, "discoverable_ceremony": len(sd.UserID) == 0}}); err != nil {
		return "", session.Factor{}, err
	}
	return owner, factorFor(row.id, row.backupEligible, uv, now), nil
}

// rejection marks a policy rejection whose evidence must be committed even
// though the step fails.
type rejection struct{ err error }

func (r *rejection) Error() string { return r.err.Error() }
func (r *rejection) Unwrap() error { return r.err }

// IsProofFailure reports whether err is a failed passkey proof whose audit
// evidence should be committed with the failure count (rather than rolled back).
func IsProofFailure(err error) bool {
	var r *rejection
	return errors.As(err, &r)
}

func (s *Service) fail(ctx context.Context, tx pgx.Tx, realmID, userID string, actor audit.Ref, typ, reason string, out error, cause ...error) error {
	if len(cause) > 0 && cause[0] != nil {
		// Verification details help operators diagnose RP/origin misconfiguration;
		// they contain no secrets and are not returned to the client.
		var pe *protocol.Error
		if errors.As(cause[0], &pe) {
			s.d.Log.Debug("passkey ceremony failed", "type", typ, "reason", reason, "error", pe.Type, "details", pe.Details, "info", pe.DevInfo)
		} else {
			s.d.Log.Debug("passkey ceremony failed", "type", typ, "reason", reason, "error", cause[0].Error())
		}
	}
	ev := audit.Event{Type: typ, RealmID: realmID, Actor: actor, Outcome: audit.Failure, ReasonCode: reason}
	if userID != "" {
		ev.Subject = &audit.Ref{Type: "user", ID: userID}
	}
	if _, err := s.d.Audit.Record(ctx, tx, ev); err != nil {
		return err
	}
	return &rejection{err: out}
}

// factorFor maps a credential to an RFC 8176 method: device-bound authenticators
// are "hwk"; synced (backup-eligible) passkeys are software-protected key
// material and are reported as "swk". User verification is recorded so a UV
// passkey satisfies multi-factor requirements on its own (MFA-007).
func factorFor(id string, backupEligible, uv bool, at time.Time) session.Factor {
	t := "hwk"
	if backupEligible {
		t = "swk"
	}
	return session.Factor{Type: t, At: at, CredentialID: id, UserVerified: uv}
}

// ---------- management ----------

// List returns a user's active passkeys.
func (s *Service) List(ctx context.Context, realmID, userID string) ([]Credential, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, coalesce(name,''), backup_eligible, backup_state, user_verified, discoverable,
		coalesce(aaguid,''::bytea), transports, created_at, last_used_at, attestation_trusted, coalesce(attestation_format,'none') FROM webauthn_credentials
		WHERE realm_id=$1 AND user_id=$2 AND state='active' ORDER BY created_at`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var c Credential
		var aaguid []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.BackupEligible, &c.BackupState, &c.UserVerified, &c.Discoverable, &aaguid, &c.Transports,
			&c.CreatedAt, &c.LastUsedAt, &c.AttestationTrusted, &c.AttestationFormat); err != nil {
			return nil, err
		}
		if len(aaguid) == 16 {
			c.AAGUID = formatAAGUID(aaguid)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Rename changes the display name of a passkey.
func (s *Service) Rename(ctx context.Context, realmID, userID, id, name string, actor audit.Ref) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return problem.ErrValidation.WithField("name", "must be 1..64 characters")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE webauthn_credentials SET name=$4 WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND state='active'`, realmID, userID, id, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "mfa.webauthn.renamed", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "webauthn_credential", ID: id}})
		return err
	})
}

// Cleanup deletes expired ceremonies (retention worker).
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM webauthn_ceremonies WHERE expires_at < $1`, s.d.Now().Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func formatAAGUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// RemoveTx revokes one of a user's passkeys, refusing to remove the last
// viable sign-in method (FED-011, PASS-005).
func (s *Service) RemoveTx(ctx context.Context, tx pgx.Tx, userID, id string) error {
	var others int
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND state='active' AND id<>$2)
		+ (SELECT count(*) FROM credentials WHERE user_id=$1 AND type='password' AND state='active')
		+ (SELECT count(*) FROM external_identities WHERE user_id=$1)`, userID, id).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return problem.ErrLastMethod
	}
	tag, err := tx.Exec(ctx, `UPDATE webauthn_credentials SET state='revoked' WHERE id=$1 AND user_id=$2 AND state='active'`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return problem.ErrNotFound
	}
	return nil
}
