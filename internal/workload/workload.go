// Package workload federates external workload identities (MCH-011..MCH-013,
// ADV-004): a workload presents a JWT from an issuer the realm trusts and
// receives a narrowly scoped local token for the service principal of the
// client the trust belongs to. Trust is explicit per client: the issuer, its
// keys, the exact audience, a subject pattern and claim constraints. A token
// from a trusted issuer that matches no trust is refused; nothing maps an
// external workload to a human account.
package workload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
)

// Profiles are reviewed presets for common workload identity sources
// (MCH-012, MCH-013); generic requires every rule explicitly.
const (
	ProfileGeneric       = "generic"
	ProfileGitHubActions = "github_actions"
	ProfileKubernetes    = "kubernetes"
	ProfileSPIFFE        = "spiffe"
)

// GitHubActionsIssuer is the issuer of GitHub Actions OIDC tokens.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

// SupportedAlgorithms are the assertion signature algorithms accepted at all.
var SupportedAlgorithms = []string{"RS256", "PS256", "ES256", "ES384", "EdDSA"}

// clockSkew tolerates small clock differences with the issuer.
const clockSkew = time.Minute

// Trust is one client's trust in an external workload issuer.
type Trust struct {
	ID                   string              `json:"id"`
	ClientRef            string              `json:"client_id"`
	Name                 string              `json:"name"`
	Profile              string              `json:"profile"`
	Issuer               string              `json:"issuer"`
	JWKSURI              string              `json:"jwks_uri,omitempty"`
	JWKS                 json.RawMessage     `json:"jwks,omitempty"`
	Audience             string              `json:"audience"`
	Subject              string              `json:"subject"`
	ClaimConstraints     map[string][]string `json:"claim_constraints"`
	Algorithms           []string            `json:"algorithms"`
	MaxAssertionLifetime int                 `json:"max_assertion_lifetime_seconds"`
	RequireJTI           bool                `json:"require_jti"`
	State                string              `json:"state"`
	Version              int64               `json:"version"`
	CreatedByID          string              `json:"created_by_id"`
	CreatedAt            time.Time           `json:"created_at"`
	UpdatedAt            time.Time           `json:"updated_at"`
	LastUsedAt           *time.Time          `json:"last_used_at,omitempty"`
}

// Input creates or replaces a trust.
type Input struct {
	Name                 string              `json:"name"`
	Profile              string              `json:"profile"`
	Issuer               string              `json:"issuer"`
	JWKSURI              string              `json:"jwks_uri"`
	JWKS                 json.RawMessage     `json:"jwks"`
	Audience             string              `json:"audience"`
	Subject              string              `json:"subject"`
	ClaimConstraints     map[string][]string `json:"claim_constraints"`
	Algorithms           []string            `json:"algorithms"`
	MaxAssertionLifetime int                 `json:"max_assertion_lifetime_seconds"`
	RequireJTI           *bool               `json:"require_jti"`
	State                string              `json:"state"`
}

// Service manages trusts and verifies workload assertions.
type Service struct {
	d    *runtime.Deps
	Apps *application.Service
	// Egress is the outbound policy for fetching issuers' key sets.
	Egress egress.Policy

	cache egress.FetchCache[jose.JSONWebKeySet]
}

// NewService returns the workload federation service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

const cols = `id, client_ref, name, profile, issuer, coalesce(jwks_uri,''), jwks, audience, subject, claim_constraints, algorithms,
	max_assertion_lifetime, require_jti, state, version, created_by_id, created_at, updated_at, last_used_at`

func scan(row pgx.Row) (*Trust, error) {
	var t Trust
	var jwks, cc []byte
	if err := row.Scan(&t.ID, &t.ClientRef, &t.Name, &t.Profile, &t.Issuer, &t.JWKSURI, &jwks, &t.Audience, &t.Subject, &cc, &t.Algorithms,
		&t.MaxAssertionLifetime, &t.RequireJTI, &t.State, &t.Version, &t.CreatedByID, &t.CreatedAt, &t.UpdatedAt, &t.LastUsedAt); err != nil {
		return nil, err
	}
	if len(jwks) > 0 && string(jwks) != "null" {
		t.JWKS = jwks
	}
	_ = json.Unmarshal(cc, &t.ClaimConstraints)
	if t.ClaimConstraints == nil {
		t.ClaimConstraints = map[string][]string{}
	}
	return &t, nil
}

var (
	k8sSubject  = regexp.MustCompile(`^system:serviceaccount:[a-z0-9]([-a-z0-9]*[a-z0-9])?:[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
	githubRepo  = regexp.MustCompile(`^repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:.+$`)
	claimPath   = regexp.MustCompile(`^[A-Za-z0-9_.:-]+(/[A-Za-z0-9_.:-]+){0,4}$`)
	spiffeIDRe  = regexp.MustCompile(`^spiffe://([a-z0-9._-]+)(/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+$`)
	reservedKey = map[string]bool{"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true}
)

// normalize applies the profile and validates the trust (MCH-011): every
// trust names an issuer, keys, an exact audience and a subject that cannot
// match the whole issuer.
func (in *Input) normalize(prod bool) *problem.Error {
	verr := problem.ErrValidation
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		return verr.WithField("name", "required, at most 100 characters")
	}
	if in.Profile == "" {
		in.Profile = ProfileGeneric
	}
	if in.State == "" {
		in.State = "active"
	}
	if in.State != "active" && in.State != "disabled" {
		return verr.WithField("state", "active or disabled")
	}
	if in.ClaimConstraints == nil {
		in.ClaimConstraints = map[string][]string{}
	}
	requireJTI := false
	switch in.Profile {
	case ProfileGitHubActions:
		// Fixed issuer and keys; tokens carry a jti. The subject names the
		// repository, so a pattern can never cover every repository.
		if in.Issuer == "" {
			in.Issuer = GitHubActionsIssuer
		}
		if in.JWKSURI == "" && len(in.JWKS) == 0 {
			in.JWKSURI = strings.TrimSuffix(in.Issuer, "/") + "/.well-known/jwks"
		}
		if len(in.Algorithms) == 0 {
			in.Algorithms = []string{"RS256"}
		}
		requireJTI = true
		if !githubRepo.MatchString(strings.TrimSuffix(in.Subject, "*")) || strings.Contains(strings.SplitN(in.Subject, ":", 3)[1], "*") {
			return verr.WithField("subject", "must name the repository (repo:<owner>/<repo>:...); a trailing * may cover refs or environments only")
		}
	case ProfileKubernetes:
		// One service account in one namespace: a cluster's tokens are not
		// all authorized for every local service principal.
		if !k8sSubject.MatchString(in.Subject) {
			return verr.WithField("subject", "must be one service account: system:serviceaccount:<namespace>:<name> (no wildcards)")
		}
		if len(in.Algorithms) == 0 {
			in.Algorithms = []string{"RS256", "ES256"}
		}
	case ProfileSPIFFE:
		// A SPIFFE ID, or a path prefix ending in /* within one trust domain.
		if !spiffeIDRe.MatchString(strings.TrimSuffix(in.Subject, "/*")) {
			return verr.WithField("subject", "must be a SPIFFE ID (spiffe://<trust domain>/<path>), optionally ending in /*")
		}
		if in.Issuer == "" {
			// JWT-SVIDs need not carry iss: the trust domain stands for it.
			in.Issuer = "spiffe://" + spiffeIDRe.FindStringSubmatch(strings.TrimSuffix(in.Subject, "/*"))[1]
		}
		if len(in.Algorithms) == 0 {
			in.Algorithms = []string{"RS256", "ES256", "PS256"}
		}
	case ProfileGeneric:
		if in.Subject == "" || in.Subject == "*" || strings.Count(in.Subject, "*") > 1 || (strings.Contains(in.Subject, "*") && !strings.HasSuffix(in.Subject, "*")) {
			return verr.WithField("subject", "an exact subject, or a non-empty prefix followed by a single trailing *")
		}
	default:
		return verr.WithField("profile", "generic, github_actions, kubernetes or spiffe")
	}
	if in.RequireJTI == nil {
		in.RequireJTI = &requireJTI
	}
	if in.Profile != ProfileSPIFFE || !strings.HasPrefix(in.Issuer, "spiffe://") {
		u, err := url.Parse(in.Issuer)
		if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && (prod || u.Scheme != "http")) {
			return verr.WithField("issuer", "an https URL")
		}
	}
	if (in.JWKSURI == "") == (len(in.JWKS) == 0) {
		return verr.WithField("jwks", "give exactly one of jwks_uri or jwks")
	}
	if in.JWKSURI != "" {
		u, err := url.Parse(in.JWKSURI)
		if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && (prod || u.Scheme != "http")) {
			return verr.WithField("jwks_uri", "an https URL")
		}
		if !egress.HostAllowed(u.Hostname()) {
			return verr.WithField("jwks_uri", "outside the deployment's destination residency policy")
		}
	}
	if len(in.JWKS) > 0 {
		var set jose.JSONWebKeySet
		if json.Unmarshal(in.JWKS, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 20 {
			return verr.WithField("jwks", "a JSON Web Key Set with 1 to 20 public keys")
		}
		for _, k := range set.Keys {
			if !k.IsPublic() || !k.Valid() {
				return verr.WithField("jwks", "public keys only")
			}
		}
	}
	in.Audience = strings.TrimSpace(in.Audience)
	if in.Audience == "" || len(in.Audience) > 512 {
		return verr.WithField("audience", "required: the exact audience the workload requests for this realm (at most 512 characters)")
	}
	if len(in.Subject) > 512 {
		return verr.WithField("subject", "at most 512 characters")
	}
	if len(in.Algorithms) == 0 {
		return verr.WithField("algorithms", "one or more of "+strings.Join(SupportedAlgorithms, ", "))
	}
	for _, a := range in.Algorithms {
		if !slices.Contains(SupportedAlgorithms, a) {
			return verr.WithField("algorithms", "one or more of "+strings.Join(SupportedAlgorithms, ", "))
		}
	}
	if in.MaxAssertionLifetime == 0 {
		in.MaxAssertionLifetime = 3600
	}
	if in.MaxAssertionLifetime < 60 || in.MaxAssertionLifetime > 86400 {
		return verr.WithField("max_assertion_lifetime_seconds", "60..86400")
	}
	if len(in.ClaimConstraints) > 20 {
		return verr.WithField("claim_constraints", "at most 20 claims")
	}
	for k, vals := range in.ClaimConstraints {
		if !claimPath.MatchString(k) || reservedKey[k] {
			return verr.WithField("claim_constraints", "claim names (nested with /) other than iss, sub, aud, exp, nbf, iat and jti: "+k)
		}
		if len(vals) == 0 || len(vals) > 50 {
			return verr.WithField("claim_constraints", "each claim needs 1 to 50 accepted values: "+k)
		}
	}
	return nil
}

// checkClient requires a client that may use the grant and has a service
// principal to act as.
func (s *Service) checkClient(ctx context.Context, q storage.Querier, realmID, clientRef string) (*application.Client, error) {
	c, err := s.Apps.ClientByRef(ctx, q, realmID, clientRef)
	if err != nil {
		return nil, problem.ErrNotFound
	}
	if c.ServicePrincipalID == "" || !c.AllowsGrant(application.GrantJWTBearer) {
		return nil, problem.ErrConflict.WithDetail("workload federation needs a client with a service principal and the " + application.GrantJWTBearer + " grant")
	}
	return c, nil
}

// Create adds a trust to a client.
func (s *Service) Create(ctx context.Context, realmID, clientRef string, in Input, actor audit.Ref) (*Trust, error) {
	if perr := in.normalize(s.d.Cfg.Mode == "production"); perr != nil {
		return nil, perr
	}
	var out *Trust
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.checkClient(ctx, tx, realmID, clientRef); err != nil {
			return err
		}
		id := ids.New("wlt")
		cc, _ := json.Marshal(in.ClaimConstraints)
		var jwks any
		if len(in.JWKS) > 0 {
			jwks = []byte(in.JWKS)
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO workload_trusts (id, realm_id, client_ref, name, profile, issuer, jwks_uri, jwks, audience, subject,
			claim_constraints, algorithms, max_assertion_lifetime, require_jti, state, created_by_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$17)`, id, realmID, clientRef, in.Name, in.Profile, in.Issuer,
			nilIfEmpty(in.JWKSURI), jwks, in.Audience, in.Subject, cc, in.Algorithms, in.MaxAssertionLifetime, *in.RequireJTI, in.State, actor.ID, now); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.workload_trust.created", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: clientRef}, Metadata: map[string]any{"trust_id": id, "profile": in.Profile, "issuer": in.Issuer,
				"subject": in.Subject, "audience": in.Audience}}); err != nil {
			return err
		}
		var err error
		out, err = s.get(ctx, tx, realmID, clientRef, id)
		return err
	})
	return out, err
}

// Update replaces a trust (If-Match version).
func (s *Service) Update(ctx context.Context, realmID, clientRef, id string, version int64, in Input, actor audit.Ref) (*Trust, error) {
	if perr := in.normalize(s.d.Cfg.Mode == "production"); perr != nil {
		return nil, perr
	}
	var out *Trust
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.checkClient(ctx, tx, realmID, clientRef); err != nil {
			return err
		}
		cc, _ := json.Marshal(in.ClaimConstraints)
		var jwks any
		if len(in.JWKS) > 0 {
			jwks = []byte(in.JWKS)
		}
		tag, err := tx.Exec(ctx, `UPDATE workload_trusts SET name=$5, profile=$6, issuer=$7, jwks_uri=$8, jwks=$9, audience=$10, subject=$11,
			claim_constraints=$12, algorithms=$13, max_assertion_lifetime=$14, require_jti=$15, state=$16, version=version+1, updated_at=$17
			WHERE realm_id=$1 AND client_ref=$2 AND id=$3 AND version=$4`, realmID, clientRef, id, version, in.Name, in.Profile, in.Issuer,
			nilIfEmpty(in.JWKSURI), jwks, in.Audience, in.Subject, cc, in.Algorithms, in.MaxAssertionLifetime, *in.RequireJTI, in.State, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			if _, err := s.get(ctx, tx, realmID, clientRef, id); err != nil {
				return err
			}
			return problem.ErrPrecondition
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.workload_trust.updated", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: clientRef}, Metadata: map[string]any{"trust_id": id, "profile": in.Profile, "issuer": in.Issuer,
				"subject": in.Subject, "audience": in.Audience, "state": in.State}}); err != nil {
			return err
		}
		out, err = s.get(ctx, tx, realmID, clientRef, id)
		return err
	})
	return out, err
}

// Delete removes a trust; tokens already issued expire on their own.
func (s *Service) Delete(ctx context.Context, realmID, clientRef, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM workload_trusts WHERE realm_id=$1 AND client_ref=$2 AND id=$3`, realmID, clientRef, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `DELETE FROM workload_assertion_jtis WHERE trust_id=$1`, id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "client.workload_trust.deleted", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: clientRef}, Metadata: map[string]any{"trust_id": id}})
		return err
	})
}

// Get returns one trust.
func (s *Service) Get(ctx context.Context, realmID, clientRef, id string) (*Trust, error) {
	return s.get(ctx, s.d.DB.Pool, realmID, clientRef, id)
}

func (s *Service) get(ctx context.Context, q storage.Querier, realmID, clientRef, id string) (*Trust, error) {
	t, err := scan(q.QueryRow(ctx, `SELECT `+cols+` FROM workload_trusts WHERE realm_id=$1 AND client_ref=$2 AND id=$3`, realmID, clientRef, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return t, err
}

// List returns a client's trusts.
func (s *Service) List(ctx context.Context, realmID, clientRef string) ([]*Trust, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+cols+` FROM workload_trusts WHERE realm_id=$1 AND client_ref=$2 ORDER BY created_at, id LIMIT 200`, realmID, clientRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Trust{}
	for rows.Next() {
		t, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Verified is an accepted workload assertion. Its jti, if any, is not spent
// yet: the caller spends it with Consume in the transaction that issues the
// token.
type Verified struct {
	Trust   *Trust
	Subject string
	Expiry  time.Time
	// JTI is the assertion's jti ("" when it has none); JTIExpiry is how
	// long its replay record is kept.
	JTI       string
	JTIExpiry time.Time
}

// RejectedError explains a refused assertion for the audit trail; callers
// return only a generic invalid_grant to the presenter.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string { return "workload assertion rejected: " + e.Reason }

func reject(format string, args ...any) error {
	return &RejectedError{Reason: fmt.Sprintf(format, args...)}
}

// Verify checks an assertion against the client's active trusts (ADV-004):
// a JWS (never unsigned, never encrypted) from a trusted issuer, signed by
// one of its keys with an allowed algorithm, for the exact audience, within
// its lifetime, for a matching subject and claims, and not replayed. The
// first trust that accepts it wins; the reasons others refused are combined.
// Verify only reads the replay records; the jti is spent by Consume, once
// the request is otherwise accepted.
func (s *Service) Verify(ctx context.Context, realmID string, c *application.Client, assertion string) (*Verified, error) {
	if len(assertion) > 16<<10 {
		return nil, reject("assertion too large")
	}
	algs := make([]jose.SignatureAlgorithm, 0, len(SupportedAlgorithms))
	for _, a := range SupportedAlgorithms {
		algs = append(algs, jose.SignatureAlgorithm(a))
	}
	sig, err := jose.ParseSigned(assertion, algs)
	if err != nil || len(sig.Signatures) != 1 {
		return nil, reject("not a signed JWT with a supported algorithm")
	}
	var unverified struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if json.Unmarshal(sig.UnsafePayloadWithoutVerification(), &unverified) != nil || unverified.Subject == "" {
		return nil, reject("malformed claims or no subject")
	}
	issuer := unverified.Issuer
	if issuer == "" && strings.HasPrefix(unverified.Subject, "spiffe://") {
		if m := spiffeIDRe.FindStringSubmatch(unverified.Subject); m != nil {
			issuer = "spiffe://" + m[1]
		}
	}
	if issuer == "" {
		return nil, reject("no issuer")
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+cols+` FROM workload_trusts WHERE realm_id=$1 AND client_ref=$2 AND issuer=$3 AND state='active'
		ORDER BY created_at, id`, realmID, c.Ref, issuer)
	if err != nil {
		return nil, err
	}
	var trusts []*Trust
	for rows.Next() {
		t, err := scan(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		trusts = append(trusts, t)
	}
	rows.Close()
	if len(trusts) == 0 {
		return nil, reject("issuer %q is not trusted for this client", issuer)
	}
	var reasons []string
	for _, t := range trusts {
		v, err := s.verifyWith(ctx, t, sig)
		if err == nil {
			_, _ = s.d.DB.Pool.Exec(ctx, `UPDATE workload_trusts SET last_used_at=$2 WHERE id=$1`, t.ID, s.d.Now())
			return v, nil
		}
		var re *RejectedError
		if !errors.As(err, &re) {
			return nil, err
		}
		reasons = append(reasons, t.ID+": "+re.Reason)
	}
	return nil, reject("%s", strings.Join(reasons, "; "))
}

func (s *Service) verifyWith(ctx context.Context, t *Trust, sig *jose.JSONWebSignature) (*Verified, error) {
	h := sig.Signatures[0].Header
	if !slices.Contains(t.Algorithms, h.Algorithm) {
		return nil, reject("algorithm %s not allowed", h.Algorithm)
	}
	set, err := s.keys(ctx, t, h.KeyID)
	if err != nil {
		return nil, reject("issuer keys unavailable")
	}
	var payload []byte
	verified := false
	candidates := set.Keys
	if h.KeyID != "" {
		candidates = set.Key(h.KeyID)
	}
	for _, k := range candidates {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if p, err := sig.Verify(k.Key); err == nil {
			payload, verified = p, true
			break
		}
	}
	if !verified {
		return nil, reject("signature does not verify with the issuer's keys")
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil, reject("malformed claims")
	}
	now := s.d.Now()
	num := func(k string) (time.Time, bool) {
		f, ok := claims[k].(float64)
		if !ok {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	exp, ok := num("exp")
	if !ok {
		return nil, reject("no exp")
	}
	if !now.Before(exp.Add(clockSkew)) {
		return nil, reject("expired")
	}
	start := now
	if iat, ok := num("iat"); ok {
		if iat.After(now.Add(clockSkew)) {
			return nil, reject("issued in the future")
		}
		start = iat
	}
	if nbf, ok := num("nbf"); ok {
		if nbf.After(now.Add(clockSkew)) {
			return nil, reject("not yet valid")
		}
		if nbf.Before(start) {
			start = nbf
		}
	}
	if exp.Sub(start) > time.Duration(t.MaxAssertionLifetime)*time.Second {
		return nil, reject("lifetime exceeds %d seconds", t.MaxAssertionLifetime)
	}
	if !audienceContains(claims["aud"], t.Audience) {
		return nil, reject("audience does not match")
	}
	sub, _ := claims["sub"].(string)
	if !subjectMatches(t.Subject, sub) {
		return nil, reject("subject %q does not match", sub)
	}
	for path, accepted := range t.ClaimConstraints {
		v, ok := lookup(claims, path)
		if !ok || !slices.Contains(accepted, v) {
			return nil, reject("claim %s does not match", path)
		}
	}
	jti, _ := claims["jti"].(string)
	if jti == "" && t.RequireJTI {
		return nil, reject("no jti")
	}
	if jti != "" {
		if len(jti) > 256 {
			return nil, reject("jti too long")
		}
		// An early, read-only check: a replay is refused before anything
		// else is decided. Consume is what makes the use exclusive.
		var used bool
		if err := s.d.DB.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workload_assertion_jtis WHERE trust_id=$1 AND jti=$2 AND expires_at >= $3)`,
			t.ID, jti, now).Scan(&used); err != nil {
			return nil, err
		}
		if used {
			return nil, reject("replayed jti")
		}
	}
	return &Verified{Trust: t, Subject: sub, Expiry: exp, JTI: jti, JTIExpiry: exp.Add(clockSkew)}, nil
}

// Consume spends a verified assertion's jti (replay control, ADV-004). It
// runs in the transaction that issues the token, after every other check,
// so a request refused for its scope, resource or organization does not use
// up the assertion. The insert is the exclusive use: of two concurrent
// requests with one jti, the second waits for the first transaction and is
// refused ("replayed jti") once it commits, and takes the jti only if the
// first rolled back. A record whose own expiry has passed is replaced.
func (s *Service) Consume(ctx context.Context, tx pgx.Tx, v *Verified) error {
	if v == nil || v.JTI == "" {
		return nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO workload_assertion_jtis (trust_id, jti, expires_at) VALUES ($1,$2,$3)
		ON CONFLICT (trust_id, jti) DO UPDATE SET expires_at=EXCLUDED.expires_at WHERE workload_assertion_jtis.expires_at < $4`,
		v.Trust.ID, v.JTI, v.JTIExpiry, s.d.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return reject("%s: replayed jti", v.Trust.ID)
	}
	return nil
}

// PruneJTIs deletes replay records past their expiry; the worker's
// retention task runs it, so records of trusts no longer used do not
// accumulate.
func (s *Service) PruneJTIs(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `DELETE FROM workload_assertion_jtis WHERE expires_at < $1`, s.d.Now())
	return tag.RowsAffected(), err
}

func audienceContains(v any, want string) bool {
	switch a := v.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// subjectMatches compares exactly, or as a prefix when the pattern ends in *.
func subjectMatches(pattern, sub string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return p != "" && strings.HasPrefix(sub, p) && len(sub) > len(p)
	}
	return sub == pattern
}

// lookup reads a string (or number/boolean, as text) claim at a /-separated
// path into nested objects.
func lookup(claims map[string]any, path string) (string, bool) {
	var cur any = claims
	for _, part := range strings.Split(path, "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		if cur, ok = m[part]; !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case bool:
		return fmt.Sprint(v), true
	case float64:
		return fmt.Sprint(int64(v)), float64(int64(v)) == v
	}
	return "", false
}

// keys returns the trust's key set: inline, or fetched from jwks_uri through
// the egress policy and kept for five minutes (a kid that is not found
// refetches at most once a minute).
func (s *Service) keys(ctx context.Context, t *Trust, kid string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if len(t.JWKS) > 0 {
		err := json.Unmarshal(t.JWKS, &set)
		return set, err
	}
	set, err := s.cache.Load(ctx, t.JWKSURI, egress.FetchOptions[jose.JSONWebKeySet]{
		TTL: 5 * time.Minute, RetryAfter: time.Minute, Timeout: s.Egress.Timeout, Now: s.d.Now,
		Usable: func(set jose.JSONWebKeySet) bool { return kid == "" || len(set.Key(kid)) > 0 },
		Fetch:  func(ctx context.Context) (jose.JSONWebKeySet, error) { return s.fetchKeys(ctx, t.JWKSURI) },
	})
	if err != nil && errors.Is(err, errKeySourceUnavailable) && len(set.Keys) > 0 {
		return set, nil // preserve the declared last-good transport/status fallback
	}
	return set, err
}

var errKeySourceUnavailable = errors.New("jwks: source unavailable")

func (s *Service) fetchKeys(ctx context.Context, uri string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return set, err
	}
	client := s.Egress.Client()
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return set, fmt.Errorf("%w: %v", errKeySourceUnavailable, err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return set, fmt.Errorf("%w: status %d", errKeySourceUnavailable, res.StatusCode)
	}
	body, err := s.Egress.ReadLimited(res.Body)
	if err != nil {
		return set, err
	}
	if err := json.Unmarshal(body, &set); err != nil || len(set.Keys) == 0 {
		return set, errors.New("jwks: not a key set")
	}
	return set, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
