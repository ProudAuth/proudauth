package federation

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/storage"
)

// RequestTTL bounds the upstream round trip.
const RequestTTL = 10 * time.Minute

// FailureConnectionDisabled is the outcome of an upstream round trip that
// returns after its connection was disabled: the answer is not used.
const FailureConnectionDisabled = "connection_disabled"

// Request is a pending upstream authorization request.
type Request struct {
	ID            string
	ProviderID    string
	Purpose       string
	TransactionID string
	UserID        string
	SessionID     string
	Nonce         string
	Verifier      string
	RedirectURI   string
}

// BeginTx stores a new upstream request and returns the authorization URL. The
// state value is a random bearer secret whose digest is the lookup key.
func (s *Service) BeginTx(ctx context.Context, tx pgx.Tx, realmID, realmName string, p *Provider, purpose, transactionID, userID, sessionID, loginHint string) (string, error) {
	if p.State != "active" {
		return "", problem.ErrFeatureDisabled.WithDetail("this sign-in connection is disabled")
	}
	if p.Kind == KindSAML {
		// A SAML connection sends an AuthnRequest instead (FED-014).
		if s.SAML == nil {
			return "", problem.ErrFeatureDisabled.WithDetail("SAML is not enabled")
		}
		return s.SAML.BeginTx(ctx, tx, realmID, realmName, p, purpose, transactionID, userID, sessionID)
	}
	state := secret.Token("")
	nonce := secret.Token("")
	verifier := secret.Token("") + secret.Token("")
	req, err := s.AuthorizeURL(ctx, p, realmName, state, nonce, verifier, loginHint)
	if err != nil {
		return "", err
	}
	id := ids.New("fdr")
	ct, kv, err := s.d.Keys.Encrypt(keys.PurposeData, []byte(verifier), []byte("federation-verifier:"+id))
	if err != nil {
		return "", err
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `INSERT INTO federation_requests (id, realm_id, provider_id, purpose, transaction_id, user_id, session_id, state_digest,
		nonce, verifier_ciphertext, key_version, redirect_uri, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		id, realmID, p.ID, purpose, nilIfEmpty(transactionID), nilIfEmpty(userID), nilIfEmpty(sessionID), secret.Digest(state), nonce, ct, kv,
		req.RedirectURI, now.Add(RequestTTL), now); err != nil {
		return "", err
	}
	return req.URL, nil
}

// ConsumeTx claims the request identified by state for the named connection,
// exactly once and before expiry (FED-007).
func (s *Service) ConsumeTx(ctx context.Context, tx pgx.Tx, realmID, alias, state string) (*Request, *Provider, error) {
	if state == "" || len(state) > 512 {
		return nil, nil, ErrUpstreamResponse
	}
	r := &Request{}
	var ct []byte
	var tid, uid, sid *string
	var expires time.Time
	err := tx.QueryRow(ctx, `UPDATE federation_requests f SET consumed_at=$4 FROM identity_providers p
		WHERE f.state_digest=$1 AND f.realm_id=$2 AND p.id=f.provider_id AND p.realm_id=f.realm_id AND p.alias=$3 AND f.consumed_at IS NULL
		RETURNING f.id, f.provider_id, f.purpose, f.transaction_id, f.user_id, f.session_id, f.nonce, f.verifier_ciphertext, f.redirect_uri, f.expires_at`,
		secret.Digest(state), realmID, alias, s.d.Now()).Scan(&r.ID, &r.ProviderID, &r.Purpose, &tid, &uid, &sid, &r.Nonce, &ct, &r.RedirectURI, &expires)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, nil, ErrUpstreamResponse
		}
		return nil, nil, err
	}
	if !s.d.Now().Before(expires) {
		return nil, nil, ErrUpstreamResponse
	}
	if tid != nil {
		r.TransactionID = *tid
	}
	if uid != nil {
		r.UserID = *uid
	}
	if sid != nil {
		r.SessionID = *sid
	}
	v, err := s.d.Keys.Decrypt(keys.PurposeData, ct, []byte("federation-verifier:"+r.ID))
	if err != nil {
		return nil, nil, err
	}
	r.Verifier = string(v)
	p, err := s.Get(ctx, tx, realmID, r.ProviderID)
	if err != nil {
		return nil, nil, err
	}
	return r, p, nil
}

// Resolution is the outcome of mapping an upstream identity to a local account.
type Resolution struct {
	UserID string
	// Created is true when the account was provisioned just in time (REG-009).
	Created bool
	// Linked is true when a new link was created during this login.
	Linked bool
	// Candidate is set when a local account with the same verified email exists
	// and the policy requires proof of control of it before linking (FED-005).
	Candidate *Candidate
	// Denied is a stable reason code when sign-in cannot proceed.
	Denied string
}

// Candidate describes a pending link awaiting local proof.
type Candidate struct {
	ProviderID    string `json:"provider_id"`
	UserID        string `json:"user_id"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Tenant        string `json:"tenant,omitempty"`
}

func emailAllowed(p *Provider, email string) bool {
	if len(p.Config.AllowedEmailDomains) == 0 {
		return true
	}
	c, _, err := canonical.Email(email)
	if err != nil {
		return false
	}
	return slices.Contains(p.Config.AllowedEmailDomains, canonical.EmailDomain(c))
}

// ResolveTx maps a validated upstream identity to a local account.
func (s *Service) ResolveTx(ctx context.Context, tx pgx.Tx, realmID string, p *Provider, up *Upstream) (*Resolution, error) {
	now := s.d.Now()
	var extID, userID string
	err := tx.QueryRow(ctx, `SELECT id, user_id FROM external_identities WHERE realm_id=$1 AND provider_id=$2 AND upstream_issuer=$3 AND upstream_subject=$4`,
		realmID, p.ID, up.Issuer, up.Subject).Scan(&extID, &userID)
	if err == nil {
		if _, err := tx.Exec(ctx, `UPDATE external_identities SET last_used_at=$2, email_hint=$3, email_verified=$4, upstream_tenant=$5 WHERE id=$1`,
			extID, now, nilIfEmpty(up.Email), up.EmailVerified, nilIfEmpty(up.Tenant)); err != nil {
			return nil, err
		}
		if err := s.applyMapping(ctx, tx, realmID, userID, p, up, false); err != nil {
			return nil, err
		}
		return &Resolution{UserID: userID}, nil
	}
	if !storage.IsNoRows(err) {
		return nil, err
	}
	// No link yet. Look for a local account with the same verified email. Only a
	// verified upstream email is considered; an unverified one is never used to
	// find or claim an account (FED-004, USR-021).
	if up.Email != "" && up.EmailVerified {
		c, _, cerr := canonical.Email(up.Email)
		if cerr == nil {
			var existing string
			err := tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2 AND verified_at IS NOT NULL`,
				realmID, c).Scan(&existing)
			if err == nil {
				cand := &Candidate{ProviderID: p.ID, UserID: existing, Issuer: up.Issuer, Subject: up.Subject, Email: up.Email,
					EmailVerified: up.EmailVerified, Tenant: up.Tenant}
				switch {
				case p.LinkingPolicy == LinkTrustedEmail && emailAllowed(p, up.Email):
					if err := s.LinkTx(ctx, tx, realmID, p, cand, "trusted_verified_email", audit.Ref{Type: "identity_provider", ID: p.ID}); err != nil {
						return nil, err
					}
					if err := s.applyMapping(ctx, tx, realmID, existing, p, up, false); err != nil {
						return nil, err
					}
					return &Resolution{UserID: existing, Linked: true}, nil
				case p.LinkingPolicy == LinkCreateOnly:
					return &Resolution{Denied: "account_conflict"}, nil
				default:
					return &Resolution{Candidate: cand}, nil
				}
			}
			if !storage.IsNoRows(err) {
				return nil, err
			}
		}
	}
	if !p.JIT {
		return &Resolution{Denied: "no_linked_account"}, nil
	}
	if up.Email != "" && !emailAllowed(p, up.Email) {
		return &Resolution{Denied: "email_domain_not_allowed"}, nil
	}
	// Just-in-time provisioning from an explicitly trusted connection (REG-009).
	in := identity.CreateInput{CreatedVia: "federation", State: identity.StateActive}
	if up.Email != "" {
		verified, err := s.jitEmailVerified(ctx, realmID, p, up)
		if err != nil {
			return nil, err
		}
		in.Email = up.Email
		in.EmailVerified = verified
		if verified {
			in.VerificationSource = "federation:" + p.Alias
		} else if c, _, cerr := canonical.Email(up.Email); cerr == nil {
			// An unverified address that another account has verified is not
			// copied: the new account would otherwise send its mail to that
			// account's owner.
			var held bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2
				AND verified_at IS NOT NULL)`, realmID, c).Scan(&held); err != nil {
				return nil, err
			}
			if held {
				in.Email, in.EmailVerified = "", false
			} else if up.EmailVerified {
				// The upstream vouched for an address outside its organization's
				// verified domains: the account keeps it, as SCIM does, but
				// proves it before signing in (TEN-007, REG-009).
				in.RequiredActions = []string{identity.ActionVerifyEmail}
			}
		}
	}
	if in.Email == "" {
		in.IsGuest = false
		in.Username = "" // identity requires an identifier: fall back to a generated username
		if login, _ := up.Claims["login"].(string); login != "" {
			if u, err := canonical.Username(p.Alias + "-" + login); err == nil {
				in.Username = u
			}
		}
		if in.Username == "" {
			// Upstream subjects (SAML NameIDs in particular) may hold characters
			// a username cannot; they become dashes, and a clash gets a suffix below.
			in.Username = strings.Map(func(r rune) rune {
				if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
					return r
				}
				return '-'
			}, strings.ToLower(p.Alias+"-"+up.Subject))
			if len(in.Username) > 64 {
				in.Username = canonical.Truncate(in.Username, 64)
			}
		}
		// A taken username gets a random suffix: a failed insert would abort
		// the transaction (and the login with it).
		base := in.Username
		for i := 0; ; i++ {
			var taken bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identifiers WHERE realm_id=$1 AND type='username' AND canonical_value=$2)`,
				realmID, in.Username).Scan(&taken); err != nil {
				return nil, err
			}
			if !taken {
				break
			}
			if i == 3 {
				return &Resolution{Denied: "account_conflict"}, nil
			}
			in.Username = canonical.Truncate(base, 57) + "-" + hex.EncodeToString(secret.Random(3))
		}
	}
	m := s.mapped(p, up)
	in.DisplayName, in.GivenName, in.FamilyName, in.Locale, in.Zoneinfo = m["display_name"], m["given_name"], m["family_name"], m["locale"], m["zoneinfo"]
	u, err := s.Users.CreateTx(ctx, tx, realmID, in)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return &Resolution{Denied: "account_conflict"}, nil
		}
		return nil, err
	}
	cand := &Candidate{ProviderID: p.ID, UserID: u.ID, Issuer: up.Issuer, Subject: up.Subject, Email: up.Email, EmailVerified: up.EmailVerified, Tenant: up.Tenant}
	if err := s.LinkTx(ctx, tx, realmID, p, cand, "jit", audit.Ref{Type: "identity_provider", ID: p.ID}); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.created", RealmID: realmID, Actor: audit.Ref{Type: "identity_provider", ID: p.ID},
		Subject: &audit.Ref{Type: "user", ID: u.ID}, Metadata: map[string]any{"created_via": "federation", "provider": p.Alias, "email_verified": in.EmailVerified}}); err != nil {
		return nil, err
	}
	if p.OrganizationID != "" {
		if err := s.jitMembership(ctx, tx, realmID, p, u.ID); err != nil {
			return nil, err
		}
	}
	// Realms that review registrations review just-in-time accounts too
	// (REG-008): the account exists but cannot sign in until approved, so a
	// connection cannot be used to bypass the queue.
	var settings []byte
	if err := tx.QueryRow(ctx, `SELECT settings FROM realms WHERE id=$1`, realmID).Scan(&settings); err != nil {
		return nil, err
	}
	if realm.ParsePolicy(settings).Registration.RequireApproval {
		if _, err := tx.Exec(ctx, `INSERT INTO registration_approvals (id, realm_id, user_id, expires_at) VALUES ($1,$2,$3,$4)`,
			ids.New(ids.RegApproval), realmID, u.ID, now.Add(14*24*time.Hour)); err != nil {
			return nil, err
		}
	}
	return &Resolution{UserID: u.ID, Created: true, Linked: true}, nil
}

// jitEmailVerified decides whether a just-in-time account starts with its
// upstream email verified (REG-009). A realm connection believes its upstream
// (the adapter has already discarded assertions it does not trust). An
// organization's connection speaks for that organization only, so its
// assertion counts only inside the organization's verified domains (TEN-010,
// TEN-011), the rule SCIM provisioning follows: otherwise one tenant could
// mint verified addresses in another tenant's domain, or in a public one,
// and the domain's real owner would then meet a conflict or a takeover.
func (s *Service) jitEmailVerified(ctx context.Context, realmID string, p *Provider, up *Upstream) (bool, error) {
	if !up.EmailVerified || p.OrganizationID == "" {
		return up.EmailVerified, nil
	}
	c, _, err := canonical.Email(up.Email)
	if err != nil {
		return false, nil
	}
	return s.Orgs.DomainCovered(ctx, realmID, p.OrganizationID, canonical.EmailDomain(c))
}

// jitMembership adds a just-in-time member to the connection's organization with
// the configured default role (TEN-015, TEN-016).
func (s *Service) jitMembership(ctx context.Context, tx pgx.Tx, realmID string, p *Provider, userID string) error {
	var orgState string
	if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, p.OrganizationID).Scan(&orgState); err != nil || orgState != "active" {
		return nil
	}
	m, err := s.Orgs.CreateMembershipTx(ctx, tx, realmID, p.OrganizationID, userID, "jit", p.ID, "active")
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil
		}
		return err
	}
	roleID := p.JITDefaultRoleID
	if roleID == "" {
		r, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", authorization.RoleOrgMember)
		if err != nil {
			return err
		}
		roleID = r.ID
	}
	if _, err := s.Authz.AssignTx(ctx, tx, realmID, nil, authorization.AssignInput{RoleID: roleID, SkipCeiling: true,
		Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID},
		Scope:   authorization.Scope{Type: authorization.ScopeOrganization, ID: p.OrganizationID}, Source: "jit"},
		audit.Ref{Type: "identity_provider", ID: p.ID}); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.added", RealmID: realmID, OrgID: p.OrganizationID,
		Actor: audit.Ref{Type: "identity_provider", ID: p.ID}, Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "membership", ID: m.ID},
		Metadata: map[string]any{"source": "jit", "provider": p.Alias, "role_id": roleID}})
	return err
}

// LinkTx creates an external identity link. A subject already linked to another
// account is a conflict, never a silent re-link (DB-003).
func (s *Service) LinkTx(ctx context.Context, tx pgx.Tx, realmID string, p *Provider, c *Candidate, provenance string, actor audit.Ref) error {
	var owner string
	err := tx.QueryRow(ctx, `SELECT user_id FROM external_identities WHERE provider_id=$1 AND upstream_issuer=$2 AND upstream_subject=$3`,
		p.ID, c.Issuer, c.Subject).Scan(&owner)
	if err == nil {
		if owner == c.UserID {
			return nil
		}
		return problem.ErrConflict.WithDetail("this external account is already linked to another account")
	}
	if !storage.IsNoRows(err) {
		return err
	}
	id := ids.New(ids.ExternalIdent)
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `INSERT INTO external_identities (id, realm_id, user_id, provider_id, upstream_issuer, upstream_subject, email_hint,
		email_verified, upstream_tenant, linking_provenance, mapping_revision, last_used_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`,
		id, realmID, c.UserID, p.ID, c.Issuer, c.Subject, nilIfEmpty(c.Email), c.EmailVerified, nilIfEmpty(c.Tenant), provenance, p.MappingRevision, now); err != nil {
		if storage.IsUniqueViolation(err) {
			return problem.ErrConflict.WithDetail("this external account is already linked to another account")
		}
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.identity.linked", RealmID: realmID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: c.UserID}, Target: &audit.Ref{Type: "external_identity", ID: id}, Category: "security",
		Metadata: map[string]any{"provider": p.Alias, "provenance": provenance, "upstream_issuer": c.Issuer}})
	return err
}

func (s *Service) mapped(p *Provider, up *Upstream) map[string]string {
	out := map[string]string{}
	set := func(field string, fm FieldMapping) {
		if fm.Claim == "" {
			return
		}
		if v, ok := up.Claims[fm.Claim].(string); ok {
			out[field] = strings.TrimSpace(v)
		}
	}
	m := p.ClaimMapping
	set("display_name", m.DisplayName)
	set("given_name", m.GivenName)
	set("family_name", m.FamilyName)
	set("locale", m.Locale)
	set("zoneinfo", m.Zoneinfo)
	return out
}

// applyMapping refreshes provider-authoritative ("sync") profile fields. It
// never touches roles, memberships or administrator metadata (FED-008).
func (s *Service) applyMapping(ctx context.Context, tx pgx.Tx, realmID, userID string, p *Provider, up *Upstream, created bool) error {
	vals := s.mapped(p, up)
	cols := map[string]FieldMapping{"display_name": p.ClaimMapping.DisplayName, "given_name": p.ClaimMapping.GivenName,
		"family_name": p.ClaimMapping.FamilyName, "locale": p.ClaimMapping.Locale, "zoneinfo": p.ClaimMapping.Zoneinfo}
	changed := []string{}
	for col, fm := range cols {
		v, ok := vals[col]
		if !ok || (fm.Mode != "sync" && !created) || len(v) > 200 {
			continue
		}
		tag, err := tx.Exec(ctx, `UPDATE users SET `+col+`=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND id=$2 AND coalesce(`+col+`,'') <> $3`,
			realmID, userID, v, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			changed = append(changed, col)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	slices.Sort(changed)
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "user.profile.synced", RealmID: realmID, Actor: audit.Ref{Type: "identity_provider", ID: p.ID},
		Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"fields": changed, "mapping_revision": p.MappingRevision}})
	return err
}

// LinkedIdentity is the safe view of a link (USR-010).
type LinkedIdentity struct {
	ID          string     `json:"id"`
	ProviderID  string     `json:"provider_id"`
	Provider    string     `json:"provider"`
	DisplayName string     `json:"provider_display_name"`
	EmailHint   string     `json:"email_hint,omitempty"`
	Provenance  string     `json:"provenance"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// Linked lists a user's external identities.
func (s *Service) Linked(ctx context.Context, realmID, userID string) ([]LinkedIdentity, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT e.id, e.provider_id, p.alias, p.display_name, coalesce(e.email_hint,''), e.linking_provenance, e.created_at, e.last_used_at
		FROM external_identities e JOIN identity_providers p ON p.id=e.provider_id WHERE e.realm_id=$1 AND e.user_id=$2 ORDER BY e.created_at`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LinkedIdentity{}
	for rows.Next() {
		var l LinkedIdentity
		if err := rows.Scan(&l.ID, &l.ProviderID, &l.Provider, &l.DisplayName, &l.EmailHint, &l.Provenance, &l.CreatedAt, &l.LastUsedAt); err != nil {
			return nil, err
		}
		if l.EmailHint != "" {
			l.EmailHint = identity.Mask("email", l.EmailHint)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Unlink removes a link unless it is the account's last viable sign-in method
// (FED-011).
func (s *Service) Unlink(ctx context.Context, realmID, userID, linkID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, userID); err != nil {
			return err
		}
		var providerID string
		if err := tx.QueryRow(ctx, `SELECT provider_id FROM external_identities WHERE realm_id=$1 AND user_id=$2 AND id=$3`, realmID, userID, linkID).Scan(&providerID); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		var other, pwd, passkeys int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM external_identities WHERE user_id=$1 AND id<>$2),
			(SELECT count(*) FROM credentials WHERE user_id=$1 AND type='password' AND state='active'),
			(SELECT count(*) FROM webauthn_credentials WHERE user_id=$1 AND state='active')`, userID, linkID).Scan(&other, &pwd, &passkeys); err != nil {
			return err
		}
		if other+pwd+passkeys == 0 {
			return problem.ErrLastMethod
		}
		if _, err := tx.Exec(ctx, `DELETE FROM external_identities WHERE id=$1`, linkID); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "federation.identity.unlinked", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "external_identity", ID: linkID}, Category: "security",
			Metadata: map[string]any{"provider_id": providerID}})
		return err
	})
}

// PendingLink is a validated upstream identity awaiting confirmation by the
// account that started a self-service link (USR-010).
type PendingLink struct {
	RequestID string    `json:"request_id"`
	UserID    string    `json:"user_id"`
	Candidate Candidate `json:"candidate"`
	ExpiresAt time.Time `json:"expires_at"`
}

// StorePendingLinkTx records a validated link result and returns a one-time
// confirmation code delivered only to the browser that completed the upstream
// login. Confirmation requires both that code and the initiating account's
// token, so neither an attacker's browser nor an attacker's account alone can
// bind someone else's upstream identity.
func (s *Service) StorePendingLinkTx(ctx context.Context, tx pgx.Tx, realmID string, r *Request, up *Upstream) (string, error) {
	code := secret.Token(secret.PrefixLink)
	c := Candidate{ProviderID: r.ProviderID, UserID: r.UserID, Issuer: up.Issuer, Subject: up.Subject, Email: up.Email, EmailVerified: up.EmailVerified, Tenant: up.Tenant}
	raw, _ := json.Marshal(c)
	ct, kv, err := s.d.Keys.Encrypt(keys.PurposeData, raw, []byte("federation-link:"+r.ID))
	if err != nil {
		return "", err
	}
	// Reuse the consumed request row: the confirmation is keyed by a new digest.
	if _, err := tx.Exec(ctx, `INSERT INTO federation_requests (id, realm_id, provider_id, purpose, user_id, session_id, state_digest, nonce,
		verifier_ciphertext, key_version, redirect_uri, expires_at, created_at) VALUES ($1,$2,$3,'link',$4,$5,$6,'',$7,$8,'',$9,$10)`,
		r.ID+"_c", realmID, r.ProviderID, r.UserID, nilIfEmpty(r.SessionID), secret.Digest(code), ct, kv, s.d.Now().Add(RequestTTL), s.d.Now()); err != nil {
		return "", err
	}
	return code, nil
}

// ConfirmLink completes a self-service link for the authenticated user.
func (s *Service) ConfirmLink(ctx context.Context, realmID, userID, code string, actor audit.Ref) (*LinkedIdentity, error) {
	var out *LinkedIdentity
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var id, providerID, owner string
		var ct []byte
		var expires time.Time
		err := tx.QueryRow(ctx, `UPDATE federation_requests SET consumed_at=$3 WHERE state_digest=$1 AND realm_id=$2 AND purpose='link'
			AND consumed_at IS NULL AND nonce='' RETURNING id, provider_id, user_id, verifier_ciphertext, expires_at`,
			secret.Digest(code), realmID, s.d.Now()).Scan(&id, &providerID, &owner, &ct, &expires)
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrInvalidProof
			}
			return err
		}
		if owner != userID || !s.d.Now().Before(expires) {
			return problem.ErrInvalidProof
		}
		raw, err := s.d.Keys.Decrypt(keys.PurposeData, ct, []byte("federation-link:"+strings.TrimSuffix(id, "_c")))
		if err != nil {
			return err
		}
		var c Candidate
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		p, err := s.Get(ctx, tx, realmID, providerID)
		if err != nil {
			return err
		}
		if err := s.LinkTx(ctx, tx, realmID, p, &c, "user_linked", actor); err != nil {
			return err
		}
		out = &LinkedIdentity{ProviderID: p.ID, Provider: p.Alias, DisplayName: p.DisplayName, Provenance: "user_linked", CreatedAt: s.d.Now()}
		if c.Email != "" {
			out.EmailHint = identity.Mask("email", c.Email)
		}
		return tx.QueryRow(ctx, `SELECT id FROM external_identities WHERE provider_id=$1 AND upstream_issuer=$2 AND upstream_subject=$3`, p.ID, c.Issuer, c.Subject).Scan(&out.ID)
	})
	return out, err
}

// Cleanup removes expired requests.
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM federation_requests WHERE expires_at < $1`, s.d.Now().Add(-time.Hour))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
