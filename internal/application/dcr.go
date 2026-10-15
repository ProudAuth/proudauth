package application

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/storage"
)

// Dynamic client registration (APP-016, APP-017, ADV-003; RFC 7591 and
// RFC 7592). Registration is restricted: an administrator issues initial
// access tokens that bound what a registered client may receive, open
// registration (when a realm allows it) yields OpenID Connect scopes only,
// privileged scopes are never granted, redirect URIs follow the ordinary
// exact-match rules, metadata URLs are never fetched (keys are registered
// inline), and registered clients are always third-party clients that ask
// for consent. A registration access token lets the registrant read,
// update, rotate and delete its own client and nothing else.

// RegistrationGrant names the scopes of one resource that clients registered
// with an initial access token may receive.
type RegistrationGrant struct {
	ResourceID string   `json:"resource_id"`
	Scopes     []string `json:"scopes"`
}

// RegistrationToken is an initial access token (administrators) or a
// registration access token (one client's registrant).
type RegistrationToken struct {
	ID            string              `json:"id"`
	Kind          string              `json:"kind"`
	ClientRef     string              `json:"client_ref,omitempty"`
	Description   string              `json:"description,omitempty"`
	AllowedScopes []RegistrationGrant `json:"allowed_scopes"`
	ProjectID     string              `json:"project_id,omitempty"`
	MaxUses       *int                `json:"max_uses,omitempty"`
	Uses          int                 `json:"uses"`
	ExpiresAt     *time.Time          `json:"expires_at,omitempty"`
	State         string              `json:"state"`
	CreatedByID   string              `json:"created_by_id,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	LastUsedAt    *time.Time          `json:"last_used_at,omitempty"`
}

const regTokenCols = `id, kind, coalesce(client_ref,''), coalesce(description,''), allowed_scopes, coalesce(project_id,''), max_uses, uses,
	expires_at, state, coalesce(created_by_id,''), created_at, last_used_at`

func scanRegToken(row pgx.Row) (*RegistrationToken, error) {
	var t RegistrationToken
	var scopes []byte
	if err := row.Scan(&t.ID, &t.Kind, &t.ClientRef, &t.Description, &scopes, &t.ProjectID, &t.MaxUses, &t.Uses, &t.ExpiresAt, &t.State,
		&t.CreatedByID, &t.CreatedAt, &t.LastUsedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(scopes, &t.AllowedScopes)
	if t.AllowedScopes == nil {
		t.AllowedScopes = []RegistrationGrant{}
	}
	return &t, nil
}

// InitialTokenInput creates an initial access token.
type InitialTokenInput struct {
	Description      string              `json:"description"`
	AllowedScopes    []RegistrationGrant `json:"allowed_scopes"`
	ProjectID        string              `json:"project_id"`
	MaxUses          int                 `json:"max_uses"`
	ExpiresInSeconds int                 `json:"expires_in_seconds"`
}

// CreateInitialAccessToken issues an initial access token (ADV-003 initial
// registration authority). The plaintext is returned once.
func (s *Service) CreateInitialAccessToken(ctx context.Context, realmID string, in InitialTokenInput, actor audit.Ref) (string, *RegistrationToken, error) {
	verr := problem.ErrValidation
	if len(in.Description) > 200 {
		return "", nil, verr.WithField("description", "at most 200 characters")
	}
	if in.MaxUses == 0 {
		in.MaxUses = 1
	}
	if in.MaxUses < 1 || in.MaxUses > 1000 {
		return "", nil, verr.WithField("max_uses", "1..1000")
	}
	if in.ExpiresInSeconds == 0 {
		in.ExpiresInSeconds = 7 * 24 * 3600
	}
	if in.ExpiresInSeconds < 60 || in.ExpiresInSeconds > 90*24*3600 {
		return "", nil, verr.WithField("expires_in_seconds", "60 seconds to 90 days")
	}
	if in.AllowedScopes == nil {
		in.AllowedScopes = []RegistrationGrant{}
	}
	if len(in.AllowedScopes) > 20 {
		return "", nil, verr.WithField("allowed_scopes", "at most 20 resources")
	}
	plain := secret.Token(secret.PrefixInitialAccess)
	var out *RegistrationToken
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		for i, g := range in.AllowedScopes {
			res, err := s.Resource(ctx, tx, realmID, g.ResourceID)
			if err != nil || res.State != "active" || res.Kind != KindBusiness {
				return verr.WithField("allowed_scopes", "unknown or inactive business resource "+g.ResourceID)
			}
			declared, err := s.ScopesForResource(ctx, tx, realmID, res.ID)
			if err != nil {
				return err
			}
			for _, name := range g.Scopes {
				i := slices.IndexFunc(declared, func(sc Scope) bool { return sc.Name == name })
				if i < 0 {
					return verr.WithField("allowed_scopes", "scope "+name+" is not declared by "+res.Audience)
				}
				if declared[i].Sensitivity == "privileged" {
					// Default denial (APP-016): registration never reaches a
					// privileged scope; an administrator grants it later.
					return verr.WithField("allowed_scopes", "privileged scope "+name+" cannot be granted through registration")
				}
			}
			in.AllowedScopes[i].ResourceID = res.ID
		}
		if in.ProjectID != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT true FROM projects WHERE realm_id=$1 AND id=$2`, realmID, in.ProjectID).Scan(&ok); err != nil {
				return verr.WithField("project_id", "unknown project")
			}
		}
		id := ids.New("crt")
		scopes, _ := json.Marshal(in.AllowedScopes)
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO client_registration_tokens (id, realm_id, kind, token_digest, description, allowed_scopes, project_id,
			max_uses, expires_at, created_by_id, created_at) VALUES ($1,$2,'initial',$3,$4,$5,$6,$7,$8,$9,$10)`, id, realmID, secret.Digest(plain),
			nilIfEmpty(in.Description), scopes, nilIfEmpty(in.ProjectID), in.MaxUses, now.Add(time.Duration(in.ExpiresInSeconds)*time.Second), actor.ID, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client_registration.initial_token.created", RealmID: realmID, Actor: actor,
			Category: "configuration", Target: &audit.Ref{Type: "registration_token", ID: id},
			Metadata: map[string]any{"max_uses": in.MaxUses, "allowed_scopes": in.AllowedScopes, "project_id": in.ProjectID}}); err != nil {
			return err
		}
		var err error
		out, err = scanRegToken(tx.QueryRow(ctx, `SELECT `+regTokenCols+` FROM client_registration_tokens WHERE id=$1`, id))
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return plain, out, nil
}

// ListInitialAccessTokens lists a realm's initial access tokens.
func (s *Service) ListInitialAccessTokens(ctx context.Context, realmID string) ([]*RegistrationToken, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+regTokenCols+` FROM client_registration_tokens WHERE realm_id=$1 AND kind='initial'
		ORDER BY created_at DESC LIMIT 200`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*RegistrationToken{}
	now := s.d.Now()
	for rows.Next() {
		t, err := scanRegToken(rows)
		if err != nil {
			return nil, err
		}
		// A token past its expiry is refused at registration; it is reported
		// as such rather than as active.
		if t.State == "active" && t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
			t.State = "expired"
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeInitialAccessToken ends an initial access token; clients already
// registered with it are unaffected.
func (s *Service) RevokeInitialAccessToken(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE client_registration_tokens SET state='revoked' WHERE realm_id=$1 AND id=$2 AND kind='initial' AND state='active'`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "client_registration.initial_token.revoked", RealmID: realmID, Actor: actor,
			Category: "configuration", Target: &audit.Ref{Type: "registration_token", ID: id}})
		return err
	})
}

// RegistrationError is an RFC 7591 error response.
type RegistrationError struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *RegistrationError) Error() string { return e.Code + ": " + e.Description }

func badMetadata(d string) *RegistrationError {
	return &RegistrationError{Status: 400, Code: "invalid_client_metadata", Description: d}
}

// ErrRegistrationToken reports a missing or invalid initial or registration
// access token (401 invalid_token).
var ErrRegistrationToken = &RegistrationError{Status: 401, Code: "invalid_token", Description: "a valid access token is required"}

// RegistrationMetadata is the client metadata a registrant may send. Unknown
// members are ignored (RFC 7591 §2).
type RegistrationMetadata struct {
	RedirectURIs            []string        `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string        `json:"post_logout_redirect_uris"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method"`
	GrantTypes              []string        `json:"grant_types"`
	ResponseTypes           []string        `json:"response_types"`
	ClientName              string          `json:"client_name"`
	Scope                   string          `json:"scope"`
	Contacts                []string        `json:"contacts"`
	JWKS                    json.RawMessage `json:"jwks"`
	JWKSURI                 string          `json:"jwks_uri"`
	SoftwareID              string          `json:"software_id"`
	SoftwareVersion         string          `json:"software_version"`
	SoftwareStatement       string          `json:"software_statement"`
	ClientID                string          `json:"client_id"`
	// RotateSecret (extension, management updates only) issues a new client
	// secret; the previous one stays valid for an hour.
	RotateSecret bool `json:"rotate_secret"`
	ProtocolOptions
}

// RegistrationContext carries the realm's policy for a registration.
type RegistrationContext struct {
	Open            bool
	RequireApproval bool
	OpenScopes      []string
	InitialToken    string
	ClientIP        string
	ManagementURI   func(clientID string) string
}

// Registration is a registered client as the registrant sees it.
type Registration struct {
	Client             *Client
	Secret             string
	SecretExpiresAt    int64
	AccessToken        string
	ApprovalState      string
	SoftwareID         string
	SoftwareVersion    string
	GrantedScopes      []string
	RegistrationClient string
}

// toInput maps metadata onto a client registration, refusing what dynamic
// registration does not offer.
func (m *RegistrationMetadata) toInput() (*ClientInput, *RegistrationError) {
	if m.SoftwareStatement != "" {
		return nil, &RegistrationError{Status: 400, Code: "unapproved_software_statement", Description: "software statements are not accepted; use an initial access token"}
	}
	if m.JWKSURI != "" {
		// Unrestricted metadata fetching is not offered (ADV-003).
		return nil, badMetadata("jwks_uri is not accepted: register keys inline as jwks")
	}
	if len(m.ResponseTypes) == 0 {
		m.ResponseTypes = []string{"code"}
	}
	if len(m.ResponseTypes) != 1 || m.ResponseTypes[0] != "code" {
		return nil, badMetadata("response_types must be [code]")
	}
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{GrantAuthorizationCode}
	}
	for _, g := range m.GrantTypes {
		if g != GrantAuthorizationCode && g != GrantRefreshToken {
			return nil, badMetadata("grant_types: only authorization_code and refresh_token can be registered")
		}
	}
	if !slices.Contains(m.GrantTypes, GrantAuthorizationCode) {
		return nil, badMetadata("grant_types must include authorization_code")
	}
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(m.RedirectURIs) == 0 || len(m.RedirectURIs) > 20 {
		return nil, &RegistrationError{Status: 400, Code: "invalid_redirect_uri", Description: "1 to 20 redirect_uris are required"}
	}
	name := strings.TrimSpace(m.ClientName)
	if name == "" {
		name = "Registered client"
	}
	if len(m.SoftwareID) > 200 || len(m.SoftwareVersion) > 100 || len(m.Contacts) > 10 {
		return nil, badMetadata("software_id, software_version or contacts too long")
	}
	in := &ClientInput{Name: name, AuthMethod: m.TokenEndpointAuthMethod, GrantTypes: m.GrantTypes, RedirectURIs: m.RedirectURIs,
		PostLogoutRedirects: m.PostLogoutRedirectURIs, Contacts: m.Contacts, JWKS: m.JWKS, SecurityProfile: "third_party",
		ConsentMode: "required", SubjectType: "public", DynamicallyRegistered: true, ProtocolOptions: m.ProtocolOptions}
	switch m.TokenEndpointAuthMethod {
	case "none":
		in.Type = TypePublicBrowser
		native := true
		for _, r := range m.RedirectURIs {
			u, err := url.Parse(r)
			if err != nil || (u.Scheme == "https" || (u.Scheme == "http" && !isLoopbackIP(u.Hostname()))) {
				native = false
			}
		}
		if native {
			in.Type = TypeNative
		}
	case "client_secret_basic", "client_secret_post":
		in.Type = TypeConfidential
	case "private_key_jwt":
		in.Type = TypeConfidential
		if len(m.JWKS) == 0 {
			return nil, badMetadata("private_key_jwt requires jwks")
		}
	default:
		return nil, badMetadata("token_endpoint_auth_method must be client_secret_basic, client_secret_post, private_key_jwt or none")
	}
	return in, nil
}

func asRegistrationError(err error) error {
	if pe, ok := problem.As(err); ok && pe.Status == 422 {
		code := "invalid_client_metadata"
		for f := range pe.Fields {
			if f == "redirect_uris" || f == "post_logout_redirect_uris" {
				code = "invalid_redirect_uri"
			}
		}
		d := pe.Detail
		for f, msg := range pe.Fields {
			d = strings.TrimSpace(d + " " + f + ": " + msg)
		}
		return &RegistrationError{Status: 400, Code: code, Description: d}
	}
	return err
}

// Register creates a client from registration metadata (RFC 7591).
func (s *Service) Register(ctx context.Context, realmID string, m RegistrationMetadata, rc RegistrationContext) (*Registration, error) {
	in, rerr := m.toInput()
	if rerr != nil {
		return nil, rerr
	}
	var out *Registration
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var iat *RegistrationToken
		if rc.InitialToken != "" {
			t, err := scanRegToken(tx.QueryRow(ctx, `SELECT `+regTokenCols+` FROM client_registration_tokens WHERE realm_id=$1 AND kind='initial'
				AND token_digest=$2 FOR UPDATE`, realmID, secret.Digest(rc.InitialToken)))
			if err != nil || t.State != "active" || (t.ExpiresAt != nil && !s.d.Now().Before(*t.ExpiresAt)) {
				return ErrRegistrationToken
			}
			state := "active"
			if t.MaxUses != nil && t.Uses+1 >= *t.MaxUses {
				state = "exhausted"
			}
			if _, err := tx.Exec(ctx, `UPDATE client_registration_tokens SET uses=uses+1, state=$2, last_used_at=$3 WHERE id=$1`, t.ID, state, s.d.Now()); err != nil {
				return err
			}
			iat = t
			in.ProjectID = t.ProjectID
		} else if !rc.Open {
			return ErrRegistrationToken
		}
		c, plain, err := s.CreateClientTx(ctx, tx, realmID, *in, audit.Ref{Type: "registration", ID: "dynamic"})
		if err != nil {
			return asRegistrationError(err)
		}
		requested := strings.Fields(m.Scope)
		granted := []string{}
		// OpenID Connect scopes any registered client may use.
		ui, err := s.ResourceByKind(ctx, tx, realmID, KindUserInfo)
		if err != nil {
			return err
		}
		uiScopes := filterScopes(rc.OpenScopes, requested)
		if len(uiScopes) > 0 {
			if err := s.SetResourceGrantTx(ctx, tx, realmID, c.Ref, ui.ID, uiScopes, []string{"user"}, ExchangePolicy{}, audit.Ref{Type: "registration", ID: "dynamic"}); err != nil {
				return err
			}
			granted = append(granted, uiScopes...)
		}
		if iat != nil {
			for _, g := range iat.AllowedScopes {
				declared, err := s.ScopesForResource(ctx, tx, realmID, g.ResourceID)
				if err != nil {
					return err
				}
				// Re-checked at use: a scope that became privileged since the
				// token was issued is not granted (default denial).
				allowed := slices.DeleteFunc(slices.Clone(g.Scopes), func(name string) bool {
					i := slices.IndexFunc(declared, func(sc Scope) bool { return sc.Name == name })
					return i < 0 || declared[i].Sensitivity == "privileged"
				})
				scopes := filterScopes(allowed, requested)
				if len(scopes) == 0 {
					continue
				}
				if err := s.SetResourceGrantTx(ctx, tx, realmID, c.Ref, g.ResourceID, scopes, []string{"user"}, ExchangePolicy{}, audit.Ref{Type: "registration", ID: "dynamic"}); err != nil {
					return err
				}
				granted = append(granted, scopes...)
			}
		}
		rat := secret.Token(secret.PrefixRegistration)
		if _, err := tx.Exec(ctx, `INSERT INTO client_registration_tokens (id, realm_id, kind, token_digest, client_ref, created_at)
			VALUES ($1,$2,'registration',$3,$4,$5)`, ids.New("crt"), realmID, secret.Digest(rat), c.Ref, s.d.Now()); err != nil {
			return err
		}
		approval := "approved"
		// Open registrations need an administrator's approval unless the
		// realm decided otherwise; token-based ones only when required.
		if rc.RequireApproval {
			approval = "pending"
			if _, err := tx.Exec(ctx, `UPDATE clients SET state='suspended' WHERE id=$1`, c.Ref); err != nil {
				return err
			}
			c.State = "suspended"
		}
		iatID := ""
		if iat != nil {
			iatID = iat.ID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO client_registrations (client_ref, realm_id, initial_token_id, software_id, software_version, approval_state,
			registered_from, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, c.Ref, realmID, nilIfEmpty(iatID), nilIfEmpty(m.SoftwareID),
			nilIfEmpty(m.SoftwareVersion), approval, nilIfEmpty(rc.ClientIP), s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.registered", RealmID: realmID, Actor: audit.Ref{Type: "registration", ID: firstOf(iatID, "open")},
			Category: "configuration", Target: &audit.Ref{Type: "client", ID: c.Ref}, Metadata: map[string]any{"client_id": c.ClientID, "client_type": c.Type,
				"initial_token_id": iatID, "software_id": m.SoftwareID, "approval_state": approval, "granted_scopes": granted}}); err != nil {
			return err
		}
		out = &Registration{Client: c, Secret: plain, AccessToken: rat, ApprovalState: approval, SoftwareID: m.SoftwareID,
			SoftwareVersion: m.SoftwareVersion, GrantedScopes: granted}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// filterScopes returns allowed scopes that were requested, or all allowed
// scopes when none were requested.
func filterScopes(allowed, requested []string) []string {
	if len(requested) == 0 {
		return slices.Clone(allowed)
	}
	out := []string{}
	for _, sc := range allowed {
		if slices.Contains(requested, sc) {
			out = append(out, sc)
		}
	}
	return out
}

func firstOf(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// AuthenticateRegistration resolves a registration access token to the one
// client it manages (RFC 7592).
func (s *Service) AuthenticateRegistration(ctx context.Context, realmID, clientID, token string) (*Client, error) {
	if !strings.HasPrefix(token, secret.PrefixRegistration) {
		return nil, ErrRegistrationToken
	}
	var ref string
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT t.client_ref FROM client_registration_tokens t JOIN clients c ON c.id=t.client_ref
		WHERE t.realm_id=$1 AND t.kind='registration' AND t.state='active' AND t.token_digest=$2 AND c.client_id=$3 AND c.state <> 'decommissioned'`,
		realmID, secret.Digest(token), clientID).Scan(&ref); err != nil {
		return nil, ErrRegistrationToken
	}
	_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE client_registration_tokens SET last_used_at=$2 WHERE token_digest=$1`, secret.Digest(token), s.d.Now())
	return s.ClientByRef(ctx, nil, realmID, ref)
}

// RegistrationOf returns how a client was registered.
func (s *Service) RegistrationOf(ctx context.Context, q storage.Querier, c *Client) (*Registration, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r := &Registration{Client: c}
	if err := q.QueryRow(ctx, `SELECT approval_state, coalesce(software_id,''), coalesce(software_version,'') FROM client_registrations WHERE client_ref=$1`,
		c.Ref).Scan(&r.ApprovalState, &r.SoftwareID, &r.SoftwareVersion); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT g.allowed_scopes FROM client_resource_grants g WHERE g.client_ref=$1`, c.Ref)
	if err == nil {
		for rows.Next() {
			var scopes []string
			if rows.Scan(&scopes) == nil {
				r.GrantedScopes = append(r.GrantedScopes, scopes...)
			}
		}
		rows.Close()
	}
	return r, nil
}

// UpdateRegistration replaces a registered client's metadata (RFC 7592).
// The client type, its scopes and its approval are not the registrant's to
// change, and neither is anything an administrator controls (see
// keepAdministratorSettings): those keep their current values. The
// registration access token is rotated, and rotate_secret=true issues a new
// secret (the previous ones stay valid for at most an hour). It is one
// transaction: when any part fails (the metadata, the secret limit), nothing
// changes and the registration access token presented stays valid.
func (s *Service) UpdateRegistration(ctx context.Context, realmID string, c *Client, m RegistrationMetadata, rotateSecret bool) (*Registration, error) {
	if m.ClientID != c.ClientID {
		return nil, badMetadata("client_id must match the registered client")
	}
	in, rerr := m.toInput()
	if rerr != nil {
		return nil, rerr
	}
	if in.Type != c.Type {
		return nil, badMetadata("the client type (public or confidential) cannot change; register a new client")
	}
	keepAdministratorSettings(in, c)
	var out *Registration
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		out = nil // a retried transaction starts clean (DB-014)
		updated, err := s.UpdateClientTx(ctx, tx, realmID, c.Ref, 0, *in, audit.Ref{Type: "registration", ID: c.ClientID})
		if err != nil {
			return asRegistrationError(err)
		}
		secretPlain := ""
		rotated := rotateSecret && strings.HasPrefix(updated.AuthMethod, "client_secret")
		if rotated {
			// Before the registration access token is replaced: a refused
			// rotation (limits.client_secrets_max) rolls back the whole update.
			if secretPlain, _, err = s.IssueSecretTx(ctx, tx, realmID, c.Ref, time.Hour, audit.Ref{Type: "registration", ID: c.ClientID}); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE client_registration_tokens SET state='revoked' WHERE client_ref=$1 AND kind='registration' AND state='active'`, c.Ref); err != nil {
			return err
		}
		rat := secret.Token(secret.PrefixRegistration)
		if _, err := tx.Exec(ctx, `INSERT INTO client_registration_tokens (id, realm_id, kind, token_digest, client_ref, created_at)
			VALUES ($1,$2,'registration',$3,$4,$5)`, ids.New("crt"), realmID, secret.Digest(rat), c.Ref, s.d.Now()); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE client_registrations SET software_id=$2, software_version=$3 WHERE client_ref=$1`, c.Ref,
			nilIfEmpty(m.SoftwareID), nilIfEmpty(m.SoftwareVersion)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.registration.updated", RealmID: realmID, Actor: audit.Ref{Type: "registration", ID: c.ClientID},
			Category: "configuration", Target: &audit.Ref{Type: "client", ID: c.Ref}, Metadata: map[string]any{"secret_rotated": rotated}}); err != nil {
			return err
		}
		if updated, err = s.ClientByRef(ctx, tx, realmID, c.Ref); err != nil {
			return err
		}
		reg, err := s.RegistrationOf(ctx, tx, updated)
		if err != nil {
			return err
		}
		reg.AccessToken, reg.Secret = rat, secretPlain
		out = reg
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// keepAdministratorSettings carries over what a registrant's update does
// not control. A registrant's PUT replaces the RFC 7591 metadata it
// registered (client_name, redirect and post-logout redirect URIs, grant
// types, authentication method within the same client type, contacts and
// the protocol options: client_uri, logo_uri, policy_uri, tos_uri,
// front-channel logout, response signing and encryption, certificate-bound
// tokens). Everything else is set by registration policy or by an
// administrator through the client API and keeps its current value: the
// description, security profile, first-party status and consent settings,
// offline access and remember-me, the default resource, environment,
// project and owner, subject type and sector (a pairwise subject stays
// pairwise), the login UI and back-channel logout URIs, allowed origins,
// claim mappings and the token policy.
func keepAdministratorSettings(in *ClientInput, c *Client) {
	in.ClientID, in.ProjectID, in.OwnerUserID = c.ClientID, c.ProjectID, c.OwnerUserID
	in.Description, in.SecurityProfile, in.FirstParty = c.Description, c.SecurityProfile, c.FirstParty
	in.ConsentMode, in.ConsentTermsVersion = c.ConsentMode, c.ConsentTermsVersion
	in.AllowOfflineAccess, in.AllowRememberMe = c.AllowOfflineAccess, c.AllowRememberMe
	in.DefaultResourceID, in.ServicePrincipalID, in.Environment = c.DefaultResourceID, c.ServicePrincipalID, c.Environment
	in.SubjectType, in.SectorIdentifier = c.SubjectType, c.SectorIdentifier
	in.LoginUIURL, in.BackchannelLogoutURI = c.LoginUIURL, c.BackchannelLogoutURI
	in.Origins = slices.Clone(c.Origins)
	in.IDTokenClaims, in.AccessTokenClaims, in.TokenPolicy = c.IDTokenClaims, c.AccessTokenClaims, c.TokenPolicy
}

// DeleteRegistration decommissions a registered client at its registrant's
// request: its grants and tokens end and its registration tokens stop
// working.
func (s *Service) DeleteRegistration(ctx context.Context, realmID string, c *Client) error {
	if err := s.SetClientState(ctx, realmID, c.Ref, "decommissioned", audit.Ref{Type: "registration", ID: c.ClientID}, "registrant_deleted"); err != nil {
		return err
	}
	_, err := s.d.DB.Pool.Exec(ctx, `UPDATE client_registration_tokens SET state='revoked' WHERE client_ref=$1 AND state='active'`, c.Ref)
	return err
}

// PendingRegistration is a registration awaiting an administrator.
type PendingRegistration struct {
	ClientRef       string    `json:"client_ref"`
	ClientID        string    `json:"client_id"`
	Name            string    `json:"name"`
	ClientType      string    `json:"client_type"`
	ApprovalState   string    `json:"approval_state"`
	InitialTokenID  string    `json:"initial_token_id,omitempty"`
	SoftwareID      string    `json:"software_id,omitempty"`
	SoftwareVersion string    `json:"software_version,omitempty"`
	RedirectURIs    []string  `json:"redirect_uris"`
	CreatedAt       time.Time `json:"created_at"`
}

// ListRegistrations lists dynamically registered clients, optionally by
// approval state.
func (s *Service) ListRegistrations(ctx context.Context, realmID, state string) ([]*PendingRegistration, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT r.client_ref, c.client_id, c.name, c.client_type, r.approval_state, coalesce(r.initial_token_id,''),
		coalesce(r.software_id,''), coalesce(r.software_version,''), coalesce((SELECT array_agg(u.uri ORDER BY u.uri) FROM client_redirect_uris u
			WHERE u.client_ref=c.id AND u.purpose='redirect'), '{}'), r.created_at
		FROM client_registrations r JOIN clients c ON c.id=r.client_ref WHERE r.realm_id=$1 AND ($2='' OR r.approval_state=$2)
		ORDER BY r.created_at DESC LIMIT 500`, realmID, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*PendingRegistration{}
	for rows.Next() {
		var p PendingRegistration
		if err := rows.Scan(&p.ClientRef, &p.ClientID, &p.Name, &p.ClientType, &p.ApprovalState, &p.InitialTokenID, &p.SoftwareID, &p.SoftwareVersion,
			&p.RedirectURIs, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// DecideRegistration approves (activates) or rejects (decommissions) a
// pending registration, in one transaction with the client's state.
func (s *Service) DecideRegistration(ctx context.Context, realmID, clientRef string, approve bool, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT approval_state FROM client_registrations WHERE realm_id=$1 AND client_ref=$2 FOR UPDATE`,
			realmID, clientRef).Scan(&state); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if state != "pending" {
			return problem.ErrConflict.WithDetail("the registration is " + state)
		}
		next, decision := "active", "approved"
		if !approve {
			next, decision = "decommissioned", "rejected"
		}
		if err := s.setClientStateTx(ctx, tx, realmID, clientRef, next, actor, "registration_"+decision, true); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE client_registrations SET approval_state=$2, decided_by_id=$3, decided_at=$4 WHERE client_ref=$1`,
			clientRef, decision, actor.ID, s.d.Now()); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.registration." + decision, RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: clientRef}})
		return err
	})
}
