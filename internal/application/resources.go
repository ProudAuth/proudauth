package application

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

const resourceCols = `id, realm_id, coalesce(project_id,''), name, audience, coalesce(description,''), kind, token_format, verification_mode,
	access_token_ttl_seconds, requires_organization, impersonation_enabled, impersonation_policy, signing_algorithm, state, version, created_at`

func scanResource(row pgx.Row) (*Resource, error) {
	var r Resource
	var ip []byte
	if err := row.Scan(&r.ID, &r.RealmID, &r.ProjectID, &r.Name, &r.Audience, &r.Description, &r.Kind, &r.TokenFormat, &r.VerificationMode,
		&r.AccessTokenTTL, &r.RequiresOrganization, &r.ImpersonationEnabled, &ip, &r.SigningAlgorithm, &r.State, &r.Version, &r.CreatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(ip, &r.ImpersonationPolicy)
	return &r, nil
}

// ResourceInput creates or updates a resource.
type ResourceInput struct {
	ProjectID            string              `json:"project_id"`
	Name                 string              `json:"name"`
	Audience             string              `json:"audience"`
	Description          string              `json:"description"`
	TokenFormat          string              `json:"token_format"`
	VerificationMode     string              `json:"verification_mode"`
	AccessTokenTTL       int                 `json:"access_token_ttl_seconds"`
	RequiresOrganization *bool               `json:"requires_organization"`
	ImpersonationEnabled bool                `json:"impersonation_enabled"`
	ImpersonationPolicy  ImpersonationPolicy `json:"impersonation_policy"`
	Scopes               []ScopeInput        `json:"scopes"`
	// SigningAlgorithm pins the JWS algorithm of access tokens for this
	// resource (TOK-005). Issuance fails closed when the realm's active key
	// does not match; the value must be in security.allowed_algorithms.
	SigningAlgorithm string `json:"signing_algorithm"`
	Kind             string `json:"-"`
}

// checkAlgorithm validates a resource's pinned algorithm against the
// operator allowlist. Only asymmetric algorithms are ever accepted.
func (s *Service) checkAlgorithm(alg string) *problem.Error {
	if alg == "" {
		return nil
	}
	if strings.HasPrefix(alg, "HS") || alg == "none" || !slices.Contains(s.d.Cfg.Security.AllowedAlgorithms, alg) {
		return problem.ErrValidation.WithField("signing_algorithm", "must be one of security.allowed_algorithms (asymmetric only)")
	}
	return nil
}

const scopeCols = `id, coalesce(resource_id,''), name, coalesce(description,''), coalesce(consent_text,''), sensitivity, is_default, kind,
	required_permissions, coalesce(step_up_acr,''), coalesce(max_auth_age_seconds,0)`

// ScopeInput declares a scope.
type ScopeInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	ConsentText string `json:"consent_text"`
	Sensitivity string `json:"sensitivity"`
	IsDefault   bool   `json:"is_default"`
	// RequiredPermissions limits the scope to subjects holding all of these
	// permissions in the token's organization or realm context (TOK-008).
	RequiredPermissions []string `json:"required_permissions"`
	// StepUpACR is the assurance a session must reach before the scope is
	// granted, and MaxAuthAgeSeconds how recent its authentication must be
	// (AUT-010). Requests for the scope step up the existing session.
	StepUpACR         string `json:"step_up_acr,omitempty"`
	MaxAuthAgeSeconds int    `json:"max_auth_age_seconds,omitempty"`
}

// StepUpACRs are the assurance levels a scope may require.
var StepUpACRs = []string{"urn:proudauth:acr:mfa", "urn:proudauth:acr:phishing_resistant"}

func (in *ResourceInput) normalize(maxTTL int) *problem.Error {
	v := problem.ErrValidation
	if in.Name == "" || len(in.Name) > 200 {
		return v.WithField("name", "required")
	}
	// Audiences are stable registered identifiers, not arbitrary user-controlled URLs (APP-006).
	if in.Audience == "" || len(in.Audience) > 512 || strings.ContainsAny(in.Audience, " \t\r\n*") {
		return v.WithField("audience", "required stable identifier without whitespace or wildcards")
	}
	if u, err := url.Parse(in.Audience); err != nil || (u.Scheme != "https" && u.Scheme != "urn" && u.Scheme != "http") {
		return v.WithField("audience", "must be an https URI or URN")
	}
	if in.TokenFormat == "" {
		in.TokenFormat = "jwt"
	}
	if in.TokenFormat != "jwt" && in.TokenFormat != "opaque" {
		return v.WithField("token_format", "jwt or opaque")
	}
	if in.VerificationMode == "" {
		in.VerificationMode = ModeOffline
	}
	switch in.VerificationMode {
	case ModeOffline, ModeBoundedOnline, ModeStrictOnline:
	default:
		return v.WithField("verification_mode", "offline, bounded_online or strict_online")
	}
	if in.TokenFormat == "opaque" && in.VerificationMode == ModeOffline {
		return v.WithField("verification_mode", "opaque tokens require online verification")
	}
	if in.AccessTokenTTL == 0 {
		in.AccessTokenTTL = 300
	}
	if in.AccessTokenTTL < 30 || in.AccessTokenTTL > maxTTL {
		return v.WithField("access_token_ttl_seconds", "outside operator bounds")
	}
	// Impersonation requires the strict-online contract (IMP-010).
	if in.ImpersonationEnabled && in.VerificationMode != ModeStrictOnline {
		return v.WithField("impersonation_enabled", "support access requires strict_online verification (IMP-010)")
	}
	if in.ImpersonationEnabled && in.ImpersonationPolicy.ContractVersion == "" {
		return v.WithField("impersonation_policy.contract_version", "record the validated support contract version (INT-010)")
	}
	for _, sc := range in.Scopes {
		if !validScopeName(sc.Name) {
			return v.WithField("scopes", "invalid scope name "+sc.Name)
		}
	}
	return nil
}

func validScopeName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == '"' || r == '\\' || r > 0x7e {
			return false
		}
	}
	return true
}

// CreateResource registers a resource server and its scopes.
func (s *Service) CreateResource(ctx context.Context, realmID string, in ResourceInput, actor audit.Ref) (*Resource, error) {
	var out *Resource
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.CreateResourceTx(ctx, tx, realmID, in, actor)
		return err
	})
	return out, err
}

// CreateResourceTx creates a resource inside tx.
func (s *Service) CreateResourceTx(ctx context.Context, tx pgx.Tx, realmID string, in ResourceInput, actor audit.Ref) (*Resource, error) {
	if perr := in.normalize(int(s.d.Cfg.Tokens.MaxAccessTokenTTL.Seconds())); perr != nil {
		return nil, perr
	}
	if in.SigningAlgorithm == "" {
		// A new resource pins the realm's algorithm, that of its active key
		// (TOK-005); keys.signing_algorithm applies while it has none.
		in.SigningAlgorithm = s.d.Cfg.Keys.SigningAlgorithm
		var alg string
		err := tx.QueryRow(ctx, `SELECT algorithm FROM signing_keys WHERE realm_id=$1 AND state='active' AND purpose='token'`, realmID).Scan(&alg)
		switch {
		case err == nil:
			in.SigningAlgorithm = alg
		case !errors.Is(err, pgx.ErrNoRows):
			return nil, err
		}
	}
	if perr := s.checkAlgorithm(in.SigningAlgorithm); perr != nil {
		return nil, perr
	}
	if in.Kind == "" {
		in.Kind = KindBusiness
	}
	requiresOrg := in.Kind == KindBusiness
	if in.RequiresOrganization != nil {
		requiresOrg = *in.RequiresOrganization
	}
	ip, _ := json.Marshal(in.ImpersonationPolicy)
	id := ids.New(ids.Resource)
	now := s.d.Now()
	_, err := tx.Exec(ctx, `INSERT INTO api_resources (id, realm_id, project_id, name, audience, description, kind, token_format, verification_mode,
		access_token_ttl_seconds, requires_organization, impersonation_enabled, impersonation_policy, signing_algorithm, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`, id, realmID, nilIfEmpty(in.ProjectID), in.Name, in.Audience,
		nilIfEmpty(in.Description), in.Kind, in.TokenFormat, in.VerificationMode, in.AccessTokenTTL, requiresOrg, in.ImpersonationEnabled, ip,
		in.SigningAlgorithm, now)
	if err != nil {
		if storage.IsUniqueViolation(err) {
			return nil, problem.ErrConflict.WithDetail("audience already registered")
		}
		if storage.IsForeignKeyViolation(err) {
			return nil, problem.ErrValidation.WithField("project_id", "unknown project")
		}
		return nil, err
	}
	for _, sc := range in.Scopes {
		if err := s.createScopeTx(ctx, tx, realmID, id, sc, "resource"); err != nil {
			return nil, err
		}
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "resource.created", RealmID: realmID, Actor: actor,
		Target: &audit.Ref{Type: "api_resource", ID: id}, Metadata: map[string]any{"audience": in.Audience, "verification_mode": in.VerificationMode,
			"impersonation_enabled": in.ImpersonationEnabled}}); err != nil {
		return nil, err
	}
	return s.Resource(ctx, tx, realmID, id)
}

func (s *Service) createScopeTx(ctx context.Context, tx pgx.Tx, realmID, resourceID string, sc ScopeInput, kind string) error {
	if !validScopeName(sc.Name) {
		return problem.ErrValidation.WithField("name", "invalid scope name")
	}
	if sc.Sensitivity == "" {
		sc.Sensitivity = "normal"
	}
	if len(sc.RequiredPermissions) > 10 {
		return problem.ErrValidation.WithField("required_permissions", "at most 10 permissions")
	}
	for _, p := range sc.RequiredPermissions {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM permissions WHERE realm_id=$1 AND name=$2)`, realmID, p).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return problem.ErrValidation.WithField("required_permissions", "unknown permission "+p)
		}
	}
	if sc.RequiredPermissions == nil {
		sc.RequiredPermissions = []string{}
	}
	if sc.StepUpACR != "" && !slices.Contains(StepUpACRs, sc.StepUpACR) {
		return problem.ErrValidation.WithField("step_up_acr", "urn:proudauth:acr:mfa or urn:proudauth:acr:phishing_resistant")
	}
	if sc.MaxAuthAgeSeconds < 0 || sc.MaxAuthAgeSeconds > 86400 || (sc.MaxAuthAgeSeconds > 0 && sc.MaxAuthAgeSeconds < 60) {
		return problem.ErrValidation.WithField("max_auth_age_seconds", "between 60 and 86400 seconds")
	}
	_, err := tx.Exec(ctx, `INSERT INTO scopes (id, realm_id, resource_id, name, description, consent_text, sensitivity, is_default, kind, required_permissions,
		step_up_acr, max_auth_age_seconds)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, ids.New(ids.Scope), realmID, nilIfEmpty(resourceID), sc.Name, nilIfEmpty(sc.Description),
		nilIfEmpty(sc.ConsentText), sc.Sensitivity, sc.IsDefault, kind, sc.RequiredPermissions, nilIfEmpty(sc.StepUpACR), nilIfZero(sc.MaxAuthAgeSeconds))
	if storage.IsUniqueViolation(err) {
		return problem.ErrConflict.WithDetail("scope " + sc.Name + " already exists in this realm")
	}
	return err
}

// CreateOIDCScopeTx creates a protocol scope (openid, profile, ...).
func (s *Service) CreateOIDCScopeTx(ctx context.Context, tx pgx.Tx, realmID, resourceID string, sc ScopeInput) error {
	return s.createScopeTx(ctx, tx, realmID, resourceID, sc, "oidc")
}

// AddScope adds a scope to an existing resource.
func (s *Service) AddScope(ctx context.Context, realmID, resourceID string, sc ScopeInput, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.Resource(ctx, tx, realmID, resourceID); err != nil {
			return err
		}
		if err := s.createScopeTx(ctx, tx, realmID, resourceID, sc, "resource"); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "scope.created", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "api_resource", ID: resourceID}, Metadata: map[string]any{"scope": sc.Name}})
		return err
	})
}

// DeleteScope removes a scope definition.
func (s *Service) DeleteScope(ctx context.Context, realmID, scopeID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var name, kind string
		if err := tx.QueryRow(ctx, `DELETE FROM scopes WHERE realm_id=$1 AND id=$2 RETURNING name, kind`, realmID, scopeID).Scan(&name, &kind); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if kind == "oidc" {
			return problem.ErrValidation.WithDetail("protocol scopes cannot be deleted")
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "scope.deleted", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "scope", ID: scopeID}, Metadata: map[string]any{"scope": name}})
		return err
	})
}

// Resource loads a resource with its scopes.
func (s *Service) Resource(ctx context.Context, q storage.Querier, realmID, id string) (*Resource, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := scanResource(q.QueryRow(ctx, `SELECT `+resourceCols+` FROM api_resources WHERE realm_id=$1 AND id=$2`, realmID, id))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	r.Scopes, err = s.ScopesForResource(ctx, q, realmID, r.ID)
	return r, err
}

// ResourceByAudience loads a resource by its audience.
func (s *Service) ResourceByAudience(ctx context.Context, q storage.Querier, realmID, audience string) (*Resource, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := scanResource(q.QueryRow(ctx, `SELECT `+resourceCols+` FROM api_resources WHERE realm_id=$1 AND audience=$2`, realmID, audience))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	r.Scopes, err = s.ScopesForResource(ctx, q, realmID, r.ID)
	return r, err
}

// ResourceByKind loads a built-in resource (account, admin, userinfo).
func (s *Service) ResourceByKind(ctx context.Context, q storage.Querier, realmID, kind string) (*Resource, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := scanResource(q.QueryRow(ctx, `SELECT `+resourceCols+` FROM api_resources WHERE realm_id=$1 AND kind=$2 ORDER BY created_at LIMIT 1`, realmID, kind))
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	r.Scopes, err = s.ScopesForResource(ctx, q, realmID, r.ID)
	return r, err
}

// ListResources lists resources.
func (s *Service) ListResources(ctx context.Context, realmID, after string, limit int) ([]*Resource, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+resourceCols+` FROM api_resources WHERE realm_id=$1 AND ($2='' OR id > $2) ORDER BY id LIMIT $3`,
		realmID, after, limit)
	if err != nil {
		return nil, err
	}
	var out []*Resource
	for rows.Next() {
		r, err := scanResource(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	rows.Close()
	for _, r := range out {
		if r.Scopes, err = s.ScopesForResource(ctx, s.d.DB.Pool, realmID, r.ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// UpdateResource updates mutable fields of a business resource.
func (s *Service) UpdateResource(ctx context.Context, realmID, id string, expectedVersion int64, in ResourceInput, actor audit.Ref) (*Resource, error) {
	var out *Resource
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.UpdateResourceTx(ctx, tx, realmID, id, expectedVersion, in, actor)
		return err
	})
	return out, err
}

// UpdateResourceTx is UpdateResource inside tx.
func (s *Service) UpdateResourceTx(ctx context.Context, tx pgx.Tx, realmID, id string, expectedVersion int64, in ResourceInput, actor audit.Ref) (*Resource, error) {
	var out *Resource
	err := func() error {
		cur, err := scanResource(tx.QueryRow(ctx, `SELECT `+resourceCols+` FROM api_resources WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && expectedVersion != cur.Version {
			return problem.ErrPrecondition
		}
		if cur.Kind != KindBusiness {
			return problem.ErrValidation.WithDetail("built-in resources cannot be modified")
		}
		in.Audience = cur.Audience // audiences are stable (APP-006)
		if perr := in.normalize(int(s.d.Cfg.Tokens.MaxAccessTokenTTL.Seconds())); perr != nil {
			return perr
		}
		requiresOrg := cur.RequiresOrganization
		if in.RequiresOrganization != nil {
			requiresOrg = *in.RequiresOrganization
		}
		if in.SigningAlgorithm == "" {
			in.SigningAlgorithm = cur.SigningAlgorithm
		}
		if perr := s.checkAlgorithm(in.SigningAlgorithm); perr != nil {
			return perr
		}
		ip, _ := json.Marshal(in.ImpersonationPolicy)
		if _, err := tx.Exec(ctx, `UPDATE api_resources SET name=$3, description=$4, token_format=$5, verification_mode=$6,
			access_token_ttl_seconds=$7, requires_organization=$8, impersonation_enabled=$9, impersonation_policy=$10, signing_algorithm=$12,
			version=version+1, updated_at=$11
			WHERE realm_id=$1 AND id=$2`, realmID, id, in.Name, nilIfEmpty(in.Description), in.TokenFormat, in.VerificationMode,
			in.AccessTokenTTL, requiresOrg, in.ImpersonationEnabled, ip, s.d.Now(), in.SigningAlgorithm); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "resource.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "api_resource", ID: id}, Metadata: map[string]any{"verification_mode": in.VerificationMode,
				"impersonation_enabled": in.ImpersonationEnabled, "token_format": in.TokenFormat}}); err != nil {
			return err
		}
		out, err = s.Resource(ctx, tx, realmID, id)
		return err
	}()
	return out, err
}

// SetResourceState disables or re-enables a resource (emergency control).
func (s *Service) SetResourceState(ctx context.Context, realmID, id, state string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE api_resources SET state=$3, version=version+1 WHERE realm_id=$1 AND id=$2 AND kind='business'`, realmID, id, state)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "resource." + state, RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "api_resource", ID: id}})
		return err
	})
}

// ImpersonationResources lists resources that opted into support access.
func (s *Service) ImpersonationResources(ctx context.Context, realmID string) (int, error) {
	var n int
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM api_resources WHERE realm_id=$1 AND impersonation_enabled AND verification_mode='strict_online' AND state='active'`, realmID).Scan(&n)
	return n, err
}

// ScopesForResource returns scopes declared for a resource.
func (s *Service) ScopesForResource(ctx context.Context, q storage.Querier, realmID, resourceID string) ([]Scope, error) {
	rows, err := q.Query(ctx, `SELECT `+scopeCols+`
		FROM scopes WHERE realm_id=$1 AND resource_id=$2 ORDER BY name`, realmID, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scope{}
	for rows.Next() {
		var sc Scope
		if err := rows.Scan(&sc.ID, &sc.ResourceID, &sc.Name, &sc.Description, &sc.ConsentText, &sc.Sensitivity, &sc.IsDefault, &sc.Kind, &sc.RequiredPermissions,
			&sc.StepUpACR, &sc.MaxAuthAgeSeconds); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// ScopesByName resolves scope names to definitions (unknown names are omitted).
func (s *Service) ScopesByName(ctx context.Context, q storage.Querier, realmID string, names []string) (map[string]Scope, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	out := map[string]Scope{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT `+scopeCols+`
		FROM scopes WHERE realm_id=$1 AND name = ANY($2)`, realmID, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sc Scope
		if err := rows.Scan(&sc.ID, &sc.ResourceID, &sc.Name, &sc.Description, &sc.ConsentText, &sc.Sensitivity, &sc.IsDefault, &sc.Kind, &sc.RequiredPermissions,
			&sc.StepUpACR, &sc.MaxAuthAgeSeconds); err != nil {
			return nil, err
		}
		out[sc.Name] = sc
	}
	return out, rows.Err()
}

// ---------- client/resource grant policy ----------

// SetResourceGrant allows a client to request a resource with a scope ceiling.
func (s *Service) SetResourceGrant(ctx context.Context, realmID, clientRef, resourceID string, scopes, subjectTypes []string, ex ExchangePolicy, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.SetResourceGrantTx(ctx, tx, realmID, clientRef, resourceID, scopes, subjectTypes, ex, actor)
	})
}

// SetResourceGrantTx is SetResourceGrant inside tx.
func (s *Service) SetResourceGrantTx(ctx context.Context, tx pgx.Tx, realmID, clientRef, resourceID string, scopes, subjectTypes []string, ex ExchangePolicy, actor audit.Ref) error {
	declared, err := s.ScopesForResource(ctx, tx, realmID, resourceID)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(declared))
	for _, d := range declared {
		names = append(names, d.Name)
	}
	for _, sc := range scopes {
		if !slices.Contains(names, sc) {
			return problem.ErrValidation.WithField("allowed_scopes", "scope "+sc+" is not declared by the resource")
		}
	}
	if err := CheckExchangePolicy(names, ex, func(aud string) (bool, error) {
		_, err := s.ResourceByAudience(ctx, tx, realmID, aud)
		if problem.Is(err, problem.ErrNotFound) {
			return false, nil
		}
		return err == nil, err
	}); err != nil {
		return err
	}
	if len(subjectTypes) == 0 {
		subjectTypes = []string{"user"}
	}
	exj, _ := json.Marshal(ex)
	_, err = tx.Exec(ctx, `INSERT INTO client_resource_grants (id, realm_id, client_ref, resource_id, allowed_scopes, subject_types, exchange_policy)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (client_ref, resource_id) DO UPDATE SET allowed_scopes=EXCLUDED.allowed_scopes, subject_types=EXCLUDED.subject_types,
		exchange_policy=EXCLUDED.exchange_policy`, ids.New(ids.ClientGrant), realmID, clientRef, resourceID, nonNilStrings(scopes), subjectTypes, exj)
	if err != nil {
		if storage.IsForeignKeyViolation(err) {
			return problem.ErrValidation.WithDetail("unknown client or resource in this realm")
		}
		return err
	}
	// The exchange policy is part of what the grant allows (TOK-016), so the
	// evidence records it with the scopes and subject types.
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.resource_grant.set", RealmID: realmID, Actor: actor,
		Target: &audit.Ref{Type: "client", ID: clientRef}, Metadata: map[string]any{"resource_id": resourceID, "allowed_scopes": scopes, "subject_types": subjectTypes,
			"exchange_policy": ex}})
	return err
}

// CheckExchangePolicy validates a grant's token-exchange policy (TOK-016),
// for the API and configuration imports alike: the scope ceiling
// (max_scopes) names scopes the resource declares, as allowed_scopes must,
// and every accepted source audience (accept_from_audiences) is a resource
// registered in the realm. known reports whether an audience is registered.
func CheckExchangePolicy(declared []string, ex ExchangePolicy, known func(audience string) (bool, error)) error {
	for _, sc := range ex.MaxScopes {
		if !slices.Contains(declared, sc) {
			return problem.ErrValidation.WithField("exchange_policy", "max_scopes: scope "+sc+" is not declared by the resource")
		}
	}
	for _, aud := range ex.AcceptFromAudiences {
		ok, err := known(aud)
		if err != nil {
			return err
		}
		if !ok {
			return problem.ErrValidation.WithField("exchange_policy", "accept_from_audiences: "+aud+" is not a resource audience in this realm")
		}
	}
	return nil
}

// RemoveResourceGrant removes a client's access to a resource.
func (s *Service) RemoveResourceGrant(ctx context.Context, realmID, clientRef, resourceID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM client_resource_grants WHERE realm_id=$1 AND client_ref=$2 AND resource_id=$3`, realmID, clientRef, resourceID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.resource_grant.removed", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "client", ID: clientRef}, Metadata: map[string]any{"resource_id": resourceID}})
		return err
	})
}

// ResourceGrants lists a client's resource grants.
func (s *Service) ResourceGrants(ctx context.Context, q storage.Querier, clientRef string) ([]ResourceGrant, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT id, client_ref, resource_id, allowed_scopes, subject_types, exchange_policy FROM client_resource_grants WHERE client_ref=$1`, clientRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResourceGrant{}
	for rows.Next() {
		var g ResourceGrant
		var ex []byte
		if err := rows.Scan(&g.ID, &g.ClientRef, &g.ResourceID, &g.AllowedScopes, &g.SubjectTypes, &ex); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(ex, &g.ExchangePolicy)
		out = append(out, g)
	}
	return out, rows.Err()
}

// ResourceGrant returns one client/resource grant.
func (s *Service) ResourceGrant(ctx context.Context, q storage.Querier, clientRef, resourceID string) (*ResourceGrant, error) {
	gs, err := s.ResourceGrants(ctx, q, clientRef)
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		if g.ResourceID == resourceID {
			gg := g
			return &gg, nil
		}
	}
	return nil, problem.ErrNotFound
}

// ETag is a content tag of the grant's editable state, used for conditional
// updates since grants carry no version column (API-010).
func (g *ResourceGrant) ETag() string {
	b, _ := json.Marshal(struct {
		A []string       `json:"a"`
		S []string       `json:"s"`
		E ExchangePolicy `json:"e"`
	}{g.AllowedScopes, g.SubjectTypes, g.ExchangePolicy})
	sum := sha256.Sum256(b)
	return `W/"g` + hex.EncodeToString(sum[:8]) + `"`
}

// SetResourceGrantIf is SetResourceGrant guarded by an If-Match tag: the
// update applies only if the grant still has that state (API-010).
func (s *Service) SetResourceGrantIf(ctx context.Context, realmID, clientRef, resourceID, ifMatch string, scopes, subjectTypes []string,
	ex ExchangePolicy, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if ifMatch != "" {
			if _, err := tx.Exec(ctx, `SELECT 1 FROM client_resource_grants WHERE client_ref=$1 AND resource_id=$2 FOR UPDATE`, clientRef, resourceID); err != nil {
				return err
			}
			cur, err := s.ResourceGrant(ctx, tx, clientRef, resourceID)
			if err != nil || cur.ETag() != ifMatch {
				return problem.ErrPrecondition
			}
		}
		return s.SetResourceGrantTx(ctx, tx, realmID, clientRef, resourceID, scopes, subjectTypes, ex, actor)
	})
}

// AddResourceServerClient authorizes a client to introspect tokens for a resource (TOK-009).
func (s *Service) AddResourceServerClient(ctx context.Context, realmID, resourceID, clientRef string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.AddResourceServerClientTx(ctx, tx, realmID, resourceID, clientRef, actor)
	})
}

// AddResourceServerClientTx is AddResourceServerClient inside tx.
func (s *Service) AddResourceServerClientTx(ctx context.Context, tx pgx.Tx, realmID, resourceID, clientRef string, actor audit.Ref) error {
	_, err := tx.Exec(ctx, `INSERT INTO resource_server_clients (realm_id, resource_id, client_ref) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`,
		realmID, resourceID, clientRef)
	if err != nil {
		if storage.IsForeignKeyViolation(err) {
			return problem.ErrValidation.WithDetail("unknown resource or client")
		}
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "resource.introspector.added", RealmID: realmID, Actor: actor,
		Target: &audit.Ref{Type: "api_resource", ID: resourceID}, Metadata: map[string]any{"client_ref": clientRef}})
	return err
}

// IntrospectableResources returns resource IDs the client may introspect.
func (s *Service) IntrospectableResources(ctx context.Context, clientRef string) (map[string]bool, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT resource_id FROM resource_server_clients WHERE client_ref=$1`, clientRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ---------- projects ----------

// CreateProject creates a project (APP-001).
func (s *Service) CreateProject(ctx context.Context, realmID string, p Project, actor audit.Ref) (*Project, error) {
	if p.Name == "" || len(p.Name) > 200 {
		return nil, problem.ErrValidation.WithField("name", "required")
	}
	if p.Environment == "" {
		p.Environment = "production"
	}
	switch p.Environment {
	case "production", "staging", "development":
	default:
		return nil, problem.ErrValidation.WithField("environment", "production, staging or development")
	}
	if len(p.Description) > 2000 {
		return nil, problem.ErrValidation.WithField("description", "too long")
	}
	p.ID = ids.New(ids.Project)
	p.RealmID = realmID
	p.State = "active"
	p.Version = 1
	p.CreatedAt = s.d.Now()
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO projects (id, realm_id, owner_organization_id, name, description, environment, owner_user_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)`, p.ID, realmID, nilIfEmpty(p.OwnerOrganizationID), p.Name, nilIfEmpty(p.Description),
			p.Environment, nilIfEmpty(p.OwnerUserID), p.CreatedAt)
		if err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("project name already exists")
			}
			if storage.IsForeignKeyViolation(err) {
				return problem.ErrValidation.WithField("owner_organization_id", "unknown organization")
			}
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "project.created", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "project", ID: p.ID}, Metadata: map[string]any{"name": p.Name}})
		return err
	})
	return &p, err
}

// Project loads a project.
func (s *Service) Project(ctx context.Context, realmID, id string) (*Project, error) {
	var p Project
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT id, realm_id, coalesce(owner_organization_id,''), name, coalesce(description,''), environment, state,
		coalesce(owner_user_id,''), version, created_at FROM projects WHERE realm_id=$1 AND id=$2`, realmID, id).Scan(&p.ID, &p.RealmID,
		&p.OwnerOrganizationID, &p.Name, &p.Description, &p.Environment, &p.State, &p.OwnerUserID, &p.Version, &p.CreatedAt)
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return &p, err
}

// ListProjects lists projects.
func (s *Service) ListProjects(ctx context.Context, realmID, after string, limit int) ([]Project, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, realm_id, coalesce(owner_organization_id,''), name, coalesce(description,''), environment, state,
		coalesce(owner_user_id,''), version, created_at FROM projects WHERE realm_id=$1 AND ($2='' OR id > $2) ORDER BY id LIMIT $3`, realmID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		var p Project
		if err := rows.Scan(&p.ID, &p.RealmID, &p.OwnerOrganizationID, &p.Name, &p.Description, &p.Environment, &p.State, &p.OwnerUserID, &p.Version, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProjectOwnerChange transfers project ownership (APP-001). Empty values
// leave the current owner; "-" clears the organization owner.
type ProjectOwnerChange struct {
	OwnerUserID         string
	OwnerOrganizationID string
	Reason              string
}

// TransferProject changes a project's accountable owners with an audited reason.
func (s *Service) TransferProject(ctx context.Context, realmID, id string, expectedVersion int64, ch ProjectOwnerChange, actor audit.Ref) (*Project, error) {
	if len(ch.Reason) < 3 {
		return nil, problem.ErrValidation.WithField("reason", "a reason is required for an ownership transfer")
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var ver int64
		var curUser, curOrg string
		if err := tx.QueryRow(ctx, `SELECT version, coalesce(owner_user_id,''), coalesce(owner_organization_id,'') FROM projects
			WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).Scan(&ver, &curUser, &curOrg); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && ver != expectedVersion {
			return problem.ErrPrecondition
		}
		newUser, newOrg := curUser, curOrg
		if ch.OwnerUserID != "" {
			var state string
			if err := tx.QueryRow(ctx, `SELECT state FROM users WHERE realm_id=$1 AND id=$2`, realmID, ch.OwnerUserID).Scan(&state); err != nil || state != "active" {
				return problem.ErrValidation.WithField("owner_user_id", "an active user in this realm is required")
			}
			newUser = ch.OwnerUserID
		}
		switch ch.OwnerOrganizationID {
		case "":
		case "-":
			newOrg = ""
		default:
			var state string
			if err := tx.QueryRow(ctx, `SELECT state FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, ch.OwnerOrganizationID).Scan(&state); err != nil || state != "active" {
				return problem.ErrValidation.WithField("owner_organization_id", "an active organization in this realm is required")
			}
			newOrg = ch.OwnerOrganizationID
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET owner_user_id=$3, owner_organization_id=$4, version=version+1, updated_at=$5 WHERE realm_id=$1 AND id=$2`,
			realmID, id, nilIfEmpty(newUser), nilIfEmpty(newOrg), s.d.Now()); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "project.ownership_transferred", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "project", ID: id}, Metadata: map[string]any{"previous_owner_user_id": curUser, "owner_user_id": newUser,
				"previous_owner_organization_id": curOrg, "owner_organization_id": newOrg, "reason": ch.Reason}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Project(ctx, realmID, id)
}

// ProjectApplications lists the clients and API resources attached to a project.
func (s *Service) ProjectApplications(ctx context.Context, realmID, projectID string) ([]*Client, []*Resource, error) {
	if _, err := s.Project(ctx, realmID, projectID); err != nil {
		return nil, nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+clientCols+` FROM clients WHERE realm_id=$1 AND project_id=$2 ORDER BY id LIMIT 500`, realmID, projectID)
	if err != nil {
		return nil, nil, err
	}
	clients := []*Client{}
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		clients = append(clients, c)
	}
	rows.Close()
	var resIDs []string
	rrows, err := s.d.DB.Pool.Query(ctx, `SELECT id FROM api_resources WHERE realm_id=$1 AND project_id=$2 ORDER BY id LIMIT 500`, realmID, projectID)
	if err != nil {
		return nil, nil, err
	}
	for rrows.Next() {
		var id string
		if err := rrows.Scan(&id); err != nil {
			rrows.Close()
			return nil, nil, err
		}
		resIDs = append(resIDs, id)
	}
	rrows.Close()
	resources := []*Resource{}
	for _, id := range resIDs {
		r, err := s.Resource(ctx, nil, realmID, id)
		if err != nil {
			return nil, nil, err
		}
		resources = append(resources, r)
	}
	return clients, resources, nil
}

// UpdateProject edits a project.
func (s *Service) UpdateProject(ctx context.Context, realmID, id string, expectedVersion int64, name, description, state string, actor audit.Ref) (*Project, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var ver int64
		if err := tx.QueryRow(ctx, `SELECT version FROM projects WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).Scan(&ver); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && ver != expectedVersion {
			return problem.ErrPrecondition
		}
		if state != "" && state != "active" && state != "suspended" && state != "archived" {
			return problem.ErrValidation.WithField("state", "active, suspended or archived")
		}
		if _, err := tx.Exec(ctx, `UPDATE projects SET name=coalesce(nullif($3,''), name), description=coalesce(nullif($4,''), description),
			state=coalesce(nullif($5,''), state), version=version+1, updated_at=$6 WHERE realm_id=$1 AND id=$2`, realmID, id, name, description, state, s.d.Now()); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "project.updated", RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "project", ID: id}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Project(ctx, realmID, id)
}

// transferOwnerTx moves the recorded owner of a project, client or other
// owned object to another live account of the realm, with its own evidence
// (APP-001, APP-014, USR-020). An empty owner clears it.
func (s *Service) transferOwnerTx(ctx context.Context, tx pgx.Tx, realmID, table, kind, id, owner string, actor audit.Ref) error {
	if owner != "" {
		var live bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 AND state IN ('active','recovery_restricted'))`,
			realmID, owner).Scan(&live); err != nil {
			return err
		}
		if !live {
			return problem.ErrValidation.WithField("owner_user_id", "an active account of this realm is required")
		}
	}
	var previous *string
	if err := tx.QueryRow(ctx, `SELECT owner_user_id FROM `+table+` WHERE realm_id=$1 AND id=$2`, realmID, id).Scan(&previous); err != nil {
		return err
	}
	// The version moves, so an update prepared before the transfer cannot
	// silently restore the previous owner (API-010).
	if _, err := tx.Exec(ctx, `UPDATE `+table+` SET owner_user_id=$3, version=version+1, updated_at=now() WHERE realm_id=$1 AND id=$2`,
		realmID, id, nilIfEmpty(owner)); err != nil {
		return err
	}
	prev := ""
	if previous != nil {
		prev = *previous
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: kind + ".ownership_transferred", RealmID: realmID, Actor: actor, Category: "configuration",
		Target: &audit.Ref{Type: kind, ID: id}, Metadata: map[string]any{"previous_owner_user_id": prev, "owner_user_id": owner}})
	return err
}

// OwnedKinds maps the owned-object kinds to their table and the permission
// needed to change their owner (DOM-009, APP-014, MCH-007). Pre-action hooks,
// webhook subscriptions and authorization policies have an accountable owner
// too: they move with the others. A plugin's hooks and subscriptions keep
// their plugin (plugin_id): only the accountable owner changes, which is no
// part of the reviewed package.
var OwnedKinds = []struct{ Kind, Table, Permission string }{
	{"project", "projects", "realm.projects.write"},
	{"client", "clients", "realm.clients.write"},
	{"service_principal", "service_principals", "realm.service_principals.write"},
	{"resource", "api_resources", "realm.resources.write"},
	{"identity_provider", "identity_providers", "realm.identity_providers.write"},
	{"hook", "hooks", "realm.hooks.write"},
	{"webhook", "webhook_subscriptions", "realm.webhooks.write"},
	{"authorization_policy", "policies", "realm.policies.write"},
}

// ObjectOwnerChange is the result of TransferObjectOwner.
type ObjectOwnerChange struct {
	Kind                string `json:"kind"`
	ID                  string `json:"id"`
	OwnerUserID         string `json:"owner_user_id"`
	PreviousOwnerUserID string `json:"previous_owner_user_id"`
	Version             int64  `json:"version"`
}

// TransferObjectOwner sets the accountable owner of one owned object (kind as
// in OwnedKinds) to an active account of the realm: the owner change path
// for objects without a dedicated one (hooks, webhook subscriptions,
// authorization policies), also for ownerless ones. expectedVersion, when
// not 0, must match (If-Match). Audited as <kind>.ownership_transferred.
func (s *Service) TransferObjectOwner(ctx context.Context, realmID, kind, id, owner string, expectedVersion int64, actor audit.Ref) (*ObjectOwnerChange, error) {
	table := ""
	for _, k := range OwnedKinds {
		if k.Kind == kind {
			table = k.Table
		}
	}
	if table == "" {
		return nil, problem.ErrNotFound
	}
	if owner == "" {
		return nil, problem.ErrValidation.WithField("owner_user_id", "an active account of this realm is required")
	}
	var out *ObjectOwnerChange
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var ver int64
		var prev string
		if err := tx.QueryRow(ctx, `SELECT version, coalesce(owner_user_id,'') FROM `+table+` WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id).
			Scan(&ver, &prev); err != nil {
			if storage.IsNoRows(err) {
				return problem.ErrNotFound
			}
			return err
		}
		if expectedVersion != 0 && ver != expectedVersion {
			return problem.ErrPrecondition
		}
		if err := s.transferOwnerTx(ctx, tx, realmID, table, kind, id, owner, actor); err != nil {
			return err
		}
		out = &ObjectOwnerChange{Kind: kind, ID: id, OwnerUserID: owner, PreviousOwnerUserID: prev, Version: ver + 1}
		return nil
	})
	return out, err
}

// TransferOwnership moves every object fromUser owns to toUser (USR-020
// offboarding). Each move is audited as <kind>.ownership_transferred.
func (s *Service) TransferOwnership(ctx context.Context, realmID, fromUser, toUser string, actor audit.Ref) (map[string]int, error) {
	out := map[string]int{}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		for k := range out {
			delete(out, k)
		}
		for _, k := range OwnedKinds {
			rows, err := tx.Query(ctx, `SELECT id FROM `+k.Table+` WHERE realm_id=$1 AND owner_user_id=$2 FOR UPDATE`, realmID, fromUser)
			if err != nil {
				return err
			}
			var ids []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, id)
			}
			rows.Close()
			for _, id := range ids {
				if err := s.transferOwnerTx(ctx, tx, realmID, k.Table, k.Kind, id, toUser, actor); err != nil {
					return err
				}
			}
			if len(ids) > 0 {
				out[k.Kind] = len(ids)
			}
		}
		return nil
	})
	return out, err
}
