package federation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/proudbase/proudauth/internal/egress"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/token"
)

var allowedAlgs = []string{"RS256", "PS256", "ES256", "EdDSA"}

// ErrUpstream is returned when the upstream provider is unreachable or returns an
// unusable response (FED-012). It never carries upstream secrets.
var ErrUpstream = problem.ErrUpstreamUnavailable

// ErrUpstreamResponse is returned when an upstream response fails validation.
var ErrUpstreamResponse = problem.ErrInvalidProof.WithDetail("the identity provider response could not be validated")

const (
	discoTTL      = time.Hour
	jwksTTL       = time.Hour
	jwksMinRetry  = time.Minute
	clockSkew     = 60 * time.Second
	maxIDTokenLen = 16 << 10
)

type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

func (s *Service) forget(providerID string) {
	s.disco.ForgetPrefix(providerID + "|")
	s.jwks.ForgetPrefix(providerID + "|")
}

// fetchJSON performs an egress-controlled GET (FED-017): dial-time address
// checks, no redirects, TLS verification, size and time limits.
func (s *Service) fetchJSON(ctx context.Context, raw string, out any) error {
	if err := s.Egress.ValidateURLContext(ctx, raw); err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	client := s.Egress.Client()
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer res.Body.Close()
	body, err := s.Egress.ReadLimited(res.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrUpstream, res.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: invalid JSON", ErrUpstream)
	}
	return nil
}

// endpoints resolves discovery merged with explicit configuration. The
// discovered issuer must equal the configured issuer exactly (OIDC Discovery §4.3).
func (s *Service) endpoints(ctx context.Context, p *Provider, issuer string) (discovery, error) {
	cfg := p.Config
	explicit := discovery{Issuer: issuer, AuthorizationEndpoint: cfg.AuthorizationEndpoint, TokenEndpoint: cfg.TokenEndpoint,
		JWKSURI: cfg.JWKSURI, EndSessionEndpoint: cfg.EndSessionEndpoint}
	if !isOIDC(p) || (explicit.AuthorizationEndpoint != "" && explicit.TokenEndpoint != "" && explicit.JWKSURI != "") {
		return explicit, nil
	}
	u := cfg.DiscoveryURL
	if u == "" {
		u = strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	}
	doc, err := s.disco.Load(ctx, p.ID+"|"+issuer+"|"+u, egress.FetchOptions[discovery]{
		TTL: discoTTL, RetryAfter: jwksMinRetry, Timeout: s.Egress.Timeout, Now: s.d.Now,
		Fetch: func(ctx context.Context) (discovery, error) {
			var doc discovery
			if err := s.fetchJSON(ctx, u, &doc); err != nil {
				return discovery{}, err
			}
			if doc.Issuer != issuer {
				return discovery{}, fmt.Errorf("%w: discovery issuer mismatch", ErrUpstream)
			}
			for _, ep := range []string{doc.AuthorizationEndpoint, doc.TokenEndpoint, doc.JWKSURI} {
				if pu, err := url.Parse(ep); err != nil || pu.Scheme != "https" {
					return discovery{}, fmt.Errorf("%w: discovery endpoint is not https", ErrUpstream)
				}
			}
			return doc, nil
		},
	})
	if err != nil {
		return discovery{}, err
	}
	out := doc
	if explicit.AuthorizationEndpoint != "" {
		out.AuthorizationEndpoint = explicit.AuthorizationEndpoint
	}
	if explicit.TokenEndpoint != "" {
		out.TokenEndpoint = explicit.TokenEndpoint
	}
	if explicit.JWKSURI != "" {
		out.JWKSURI = explicit.JWKSURI
	}
	if explicit.EndSessionEndpoint != "" {
		out.EndSessionEndpoint = explicit.EndSessionEndpoint
	}
	return out, nil
}

// key returns the upstream verification key for kid; an unknown kid triggers at
// most one refresh per minute (key rotation without amplification).
func (s *Service) key(ctx context.Context, p *Provider, jwksURI, kid, alg string) (*jose.JSONWebKey, error) {
	find := func(set jose.JSONWebKeySet) *jose.JSONWebKey {
		var match []jose.JSONWebKey
		for _, k := range set.Keys {
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if !k.IsPublic() {
				continue
			}
			if (kid == "" || k.KeyID == kid) && (k.Algorithm == "" || k.Algorithm == alg) {
				match = append(match, k)
			}
		}
		if len(match) == 1 {
			return &match[0]
		}
		return nil
	}
	set, err := s.jwks.Load(ctx, p.ID+"|"+jwksURI, egress.FetchOptions[jose.JSONWebKeySet]{
		TTL: jwksTTL, RetryAfter: jwksMinRetry, Timeout: s.Egress.Timeout, Now: s.d.Now,
		Usable: func(set jose.JSONWebKeySet) bool { return find(set) != nil },
		Fetch: func(ctx context.Context) (jose.JSONWebKeySet, error) {
			var set jose.JSONWebKeySet
			err := s.fetchJSON(ctx, jwksURI, &set)
			return set, err
		},
	})
	if err != nil {
		return nil, err
	}
	if k := find(set); k != nil {
		return k, nil
	}
	return nil, ErrUpstreamResponse
}

// AuthorizationRequest is what the callback needs to finish the exchange.
type AuthorizationRequest struct {
	URL         string
	RedirectURI string
}

// RedirectURI is the connection's registered callback URL.
func (s *Service) RedirectURI(realmName string, p *Provider) string {
	return strings.TrimSuffix(s.d.Cfg.Server.PublicOrigin, "/") + "/api/v1/realms/" + realmName + "/federation/" + p.Alias + "/callback"
}

// AuthorizeURL builds the upstream authorization request with state, nonce and
// PKCE S256 (FED-007). loginHint is passed only as a hint (OIDC-011).
func (s *Service) AuthorizeURL(ctx context.Context, p *Provider, realmName, state, nonce, verifier, loginHint string) (*AuthorizationRequest, error) {
	issuer := p.Issuer
	if p.Config.MultiTenantIssuer {
		// Multi-tenant issuers publish discovery under a tenant-independent path;
		// the explicit endpoints are required for them.
		issuer = strings.ReplaceAll(p.Issuer, "{tenant}", "common")
	}
	ep, err := s.endpoints(ctx, p, issuer)
	if err != nil {
		return nil, err
	}
	if ep.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("%w: no authorization endpoint", ErrUpstream)
	}
	redirect := s.RedirectURI(realmName, p)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {p.Config.ClientID}, "redirect_uri": {redirect},
		"scope": {strings.Join(p.Config.Scopes, " ")}, "state": {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	if isOIDC(p) {
		q.Set("nonce", nonce)
	}
	if loginHint != "" && isOIDC(p) {
		q.Set("login_hint", loginHint)
	}
	u, err := url.Parse(ep.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid authorization endpoint", ErrUpstream)
	}
	existing := u.Query()
	for k, v := range q {
		existing[k] = v
	}
	u.RawQuery = existing.Encode()
	return &AuthorizationRequest{URL: u.String(), RedirectURI: redirect}, nil
}

// Upstream is a validated upstream identity.
type Upstream struct {
	Issuer        string         `json:"issuer"`
	Subject       string         `json:"subject"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified"`
	Tenant        string         `json:"tenant,omitempty"`
	MFA           bool           `json:"mfa"`
	Claims        map[string]any `json:"claims,omitempty"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
}

// Exchange redeems the authorization code and validates the result. Upstream
// tokens are discarded after use (FED-010).
func (s *Service) Exchange(ctx context.Context, p *Provider, code, verifier, redirectURI, nonce string) (*Upstream, error) {
	if code == "" || len(code) > 2048 {
		return nil, ErrUpstreamResponse
	}
	issuer := p.Issuer
	if p.Config.MultiTenantIssuer {
		issuer = strings.ReplaceAll(p.Issuer, "{tenant}", "common")
	}
	ep, err := s.endpoints(ctx, p, issuer)
	if err != nil {
		return nil, err
	}
	secretValue, err := s.clientSecret(p)
	if err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
	if p.Config.ClientAuth == "client_secret_post" || secretValue == "" {
		form.Set("client_id", p.Config.ClientID)
		if secretValue != "" {
			form.Set("client_secret", secretValue)
		}
	}
	if err := s.Egress.ValidateURL(ep.TokenEndpoint); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if p.Config.ClientAuth != "client_secret_post" && secretValue != "" {
		req.SetBasicAuth(url.QueryEscape(p.Config.ClientID), url.QueryEscape(secretValue))
	}
	res, err := s.Egress.Client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	defer res.Body.Close()
	body, err := s.Egress.ReadLimited(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, err)
	}
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr)
	if res.StatusCode >= 500 {
		return nil, fmt.Errorf("%w: token endpoint status %d", ErrUpstream, res.StatusCode)
	}
	if res.StatusCode != http.StatusOK || tr.Error != "" {
		return nil, ErrUpstreamResponse
	}
	if a, ok := adapterFor(p.Adapter); ok && !a.OIDC {
		up, err := a.Identity(ctx, s, p, tr.AccessToken)
		if err == nil {
			normalize(p, up, nil)
		}
		return up, err
	}
	if tr.IDToken == "" {
		return nil, ErrUpstreamResponse
	}
	return s.validateIDToken(ctx, p, ep, tr.IDToken, nonce)
}

// validateIDToken checks signature, issuer, audience, azp, nonce and time
// claims with protocol-specific rules (FED-007, TOK-005).
func (s *Service) validateIDToken(ctx context.Context, p *Provider, ep discovery, raw, nonce string) (*Upstream, error) {
	if len(raw) > maxIDTokenLen {
		return nil, ErrUpstreamResponse
	}
	algs := p.Config.Algorithms
	if len(algs) == 0 {
		algs = allowedAlgs
	}
	sigAlgs := make([]jose.SignatureAlgorithm, 0, len(algs))
	for _, a := range algs {
		sigAlgs = append(sigAlgs, jose.SignatureAlgorithm(a))
	}
	jws, err := jose.ParseSigned(raw, sigAlgs)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, ErrUpstreamResponse
	}
	hdr := jws.Signatures[0].Header
	if typ, _ := hdr.ExtraHeaders["typ"].(string); typ != "" && !strings.EqualFold(typ, "JWT") {
		return nil, ErrUpstreamResponse // e.g. an access token (at+jwt) presented as an ID token
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrUpstreamResponse
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || token.RejectDuplicateKeys(payloadRaw) != nil {
		return nil, ErrUpstreamResponse
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, ErrUpstreamResponse
	}
	expectedIssuer := p.Issuer
	tenant := ""
	if p.Config.TenantClaim != "" {
		tenant, _ = claims[p.Config.TenantClaim].(string)
		if len(p.Config.AllowedTenants) > 0 && !slices.Contains(p.Config.AllowedTenants, tenant) {
			return nil, problem.ErrForbidden.WithDetail("this identity provider tenant is not allowed").WithExtension("reason", "upstream_tenant_not_allowed")
		}
	}
	if p.Config.MultiTenantIssuer {
		if tenant == "" {
			return nil, ErrUpstreamResponse
		}
		expectedIssuer = strings.ReplaceAll(p.Issuer, "{tenant}", tenant)
	}
	if iss, _ := claims["iss"].(string); iss != expectedIssuer {
		return nil, ErrUpstreamResponse
	}
	k, err := s.key(ctx, p, ep.JWKSURI, hdr.KeyID, hdr.Algorithm)
	if err != nil {
		return nil, err
	}
	if _, err := jws.Verify(k); err != nil {
		return nil, ErrUpstreamResponse
	}
	clientID := p.Config.ClientID
	var aud []string
	switch v := claims["aud"].(type) {
	case string:
		aud = []string{v}
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok {
				aud = append(aud, s)
			}
		}
	}
	if !slices.Contains(aud, clientID) {
		return nil, ErrUpstreamResponse
	}
	if azp, ok := claims["azp"].(string); (len(aud) > 1 || ok) && azp != clientID {
		return nil, ErrUpstreamResponse
	}
	if got, _ := claims["nonce"].(string); got == "" || got != nonce {
		return nil, ErrUpstreamResponse
	}
	now := s.d.Now()
	num := func(name string) (time.Time, bool) {
		f, ok := claims[name].(float64)
		if !ok {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	exp, ok := num("exp")
	if !ok || !now.Before(exp.Add(clockSkew)) {
		return nil, ErrUpstreamResponse
	}
	if iat, ok := num("iat"); !ok || iat.After(now.Add(clockSkew)) || now.Sub(iat) > 24*time.Hour {
		return nil, ErrUpstreamResponse
	}
	if nbf, ok := num("nbf"); ok && nbf.After(now.Add(clockSkew)) {
		return nil, ErrUpstreamResponse
	}
	sub, _ := claims["sub"].(string)
	if sub == "" || len(sub) > 255 {
		return nil, ErrUpstreamResponse
	}
	up := &Upstream{Issuer: expectedIssuer, Subject: sub, Tenant: tenant, Claims: profileClaims(claims)}
	up.Email, _ = claims["email"].(string)
	switch v := claims["email_verified"].(type) {
	case bool:
		up.EmailVerified = v
	case string:
		up.EmailVerified = v == "true"
	}
	if p.TrustUpstreamMFA {
		// Only configured semantics are trusted (FED-009).
		if amr, ok := claims["amr"].([]any); ok {
			for _, m := range amr {
				if m == "mfa" {
					up.MFA = true
				}
			}
		}
		if acr, _ := claims["acr"].(string); acr != "" && slices.Contains(p.Config.TrustedACRValues, acr) {
			up.MFA = true
		}
	}
	normalize(p, up, claims)
	return up, nil
}

// profileClaims keeps only claims usable by the claim mapping.
func profileClaims(c map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range c {
		switch k {
		case "name", "given_name", "family_name", "nickname", "preferred_username", "locale", "zoneinfo", "login":
			if s, ok := v.(string); ok && len(s) <= 200 {
				out[k] = s
			}
		}
	}
	return out
}

// githubIdentity resolves the user from GitHub's REST API. GitHub is OAuth 2.0,
// not OIDC: the subject is the immutable numeric account ID (never the mutable
// login), and the email is used only when GitHub reports it verified (FED-002).
func (s *Service) githubIdentity(ctx context.Context, p *Provider, accessToken string) (*Upstream, error) {
	if accessToken == "" {
		return nil, ErrUpstreamResponse
	}
	get := func(path string, out any) error {
		u := strings.TrimSuffix(p.Config.APIBaseURL, "/") + path
		if err := s.Egress.ValidateURL(u); err != nil {
			return fmt.Errorf("%w: %v", ErrUpstream, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "application/vnd.github+json")
		res, err := s.Egress.Client().Do(req)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUpstream, err)
		}
		defer res.Body.Close()
		body, err := s.Egress.ReadLimited(io.Reader(res.Body))
		if err != nil {
			return fmt.Errorf("%w: %v", ErrUpstream, err)
		}
		if res.StatusCode != http.StatusOK {
			return ErrUpstreamResponse
		}
		return json.Unmarshal(body, out)
	}
	var user struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := get("/user", &user); err != nil {
		return nil, err
	}
	if user.ID <= 0 {
		return nil, ErrUpstreamResponse
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := get("/user/emails", &emails); err != nil && !errors.Is(err, ErrUpstreamResponse) {
		return nil, err
	}
	up := &Upstream{Issuer: p.Issuer, Subject: strconv.FormatInt(user.ID, 10), Claims: map[string]any{"login": user.Login}}
	if user.Name != "" {
		up.Claims["name"] = user.Name
	}
	for _, e := range emails {
		if e.Primary && e.Verified {
			up.Email, up.EmailVerified = e.Email, true
		}
	}
	return up, nil
}

// Diagnostics is a redacted connection test result (no secrets, no tokens).
type Diagnostics struct {
	OK                    bool     `json:"ok"`
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	JWKSURI               string   `json:"jwks_uri,omitempty"`
	SigningKeys           int      `json:"signing_keys"`
	SupportsS256          bool     `json:"supports_pkce_s256"`
	Problems              []string `json:"problems"`
}

// Test fetches discovery and keys through the egress policy and reports
// configuration problems without changing any state.
func (s *Service) Test(ctx context.Context, p *Provider) *Diagnostics {
	if p.Kind == KindSAML {
		// Nothing is fetched for a SAML connection: its metadata was uploaded.
		return s.testSAML(ctx, p)
	}
	s.forget(p.ID)
	d := &Diagnostics{Issuer: p.Issuer, Problems: []string{}}
	issuer := p.Issuer
	if p.Config.MultiTenantIssuer {
		issuer = strings.ReplaceAll(p.Issuer, "{tenant}", "common")
	}
	ep, err := s.endpoints(ctx, p, issuer)
	if err != nil {
		d.Problems = append(d.Problems, redact(err))
		return d
	}
	d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI = ep.AuthorizationEndpoint, ep.TokenEndpoint, ep.JWKSURI
	d.SupportsS256 = slices.Contains(ep.CodeChallengeMethods, "S256") || !isOIDC(p)
	if isOIDC(p) && len(ep.CodeChallengeMethods) > 0 && !d.SupportsS256 {
		d.Problems = append(d.Problems, "provider does not advertise PKCE S256")
	}
	if isOIDC(p) {
		var set jose.JSONWebKeySet
		if err := s.fetchJSON(ctx, ep.JWKSURI, &set); err != nil {
			d.Problems = append(d.Problems, redact(err))
		} else {
			for _, k := range set.Keys {
				if k.IsPublic() && (k.Use == "" || k.Use == "sig") {
					d.SigningKeys++
				}
			}
			if d.SigningKeys == 0 {
				d.Problems = append(d.Problems, "no public signing keys published")
			}
		}
	}
	if !p.HasClientSecret {
		d.Problems = append(d.Problems, "no client secret configured (public client)")
	}
	d.OK = len(d.Problems) == 0 || (len(d.Problems) == 1 && !p.HasClientSecret)
	return d
}

func redact(err error) string {
	msg := err.Error()
	if len(msg) > 200 {
		msg = canonical.Truncate(msg, 200)
	}
	return msg
}

// ErrNoUpstreamLogout reports a connection without an end-session endpoint.
var ErrNoUpstreamLogout = errors.New("federation: the identity provider offers no logout endpoint")

// UpstreamLogoutURL returns the upstream RP-initiated logout URL for a
// connection (FED-013): its end-session endpoint with this deployment's
// client_id, the return URI and state. Upstream tokens are never stored, so
// no id_token_hint is sent; the upstream may ask the user to confirm. A
// multi-tenant connection needs an explicitly configured endpoint.
func (s *Service) UpstreamLogoutURL(ctx context.Context, p *Provider, returnURI, state string) (string, error) {
	endpoint := p.Config.EndSessionEndpoint
	if endpoint == "" && isOIDC(p) && !p.Config.MultiTenantIssuer {
		ep, err := s.endpoints(ctx, p, p.Issuer)
		if err != nil {
			return "", err
		}
		endpoint = ep.EndSessionEndpoint
	}
	if endpoint == "" {
		return "", ErrNoUpstreamLogout
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" && !s.Egress.AllowPrivate {
		return "", ErrNoUpstreamLogout
	}
	q := u.Query()
	q.Set("client_id", p.Config.ClientID)
	q.Set("post_logout_redirect_uri", returnURI)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
