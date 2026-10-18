package oauth

import (
	"context"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/session"
)

// AuthorizeRequest holds authorization parameters.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	ResponseMode        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
	ACRValues           string
	LoginHint           string
	UILocales           string
	Organization        string
	Resources           []string
	RequestURI          string
	Request             string
	Intent              string
	Claims              string
	// DPoPJKT is the dpop_jkt parameter (RFC 9449 §10): the JWK SHA-256
	// thumbprint of the DPoP key the authorization code is bound to.
	DPoPJKT string
}

// ParseAuthorize extracts parameters, rejecting duplicated single-valued
// parameters (SEC-004).
func ParseAuthorize(v url.Values) (AuthorizeRequest, *Error) {
	for k, vals := range v {
		if k != "resource" && len(vals) > 1 {
			return AuthorizeRequest{}, ErrInvalidRequest("parameter " + k + " must not repeat")
		}
	}
	r := AuthorizeRequest{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), ResponseType: v.Get("response_type"),
		ResponseMode: v.Get("response_mode"), Scope: v.Get("scope"), State: v.Get("state"), Nonce: v.Get("nonce"),
		CodeChallenge: v.Get("code_challenge"), CodeChallengeMethod: v.Get("code_challenge_method"), Prompt: v.Get("prompt"),
		MaxAge: v.Get("max_age"), ACRValues: v.Get("acr_values"), LoginHint: v.Get("login_hint"), UILocales: v.Get("ui_locales"),
		Organization: v.Get("organization"), Resources: v["resource"], RequestURI: v.Get("request_uri"), Request: v.Get("request"),
		Intent: v.Get("intent"), Claims: v.Get("claims"), DPoPJKT: v.Get("dpop_jkt"),
	}
	if len(r.State) > 1024 || len(r.Nonce) > 512 || len(r.Scope) > 2048 || len(r.LoginHint) > 512 || len(r.Resources) > 5 {
		return r, ErrInvalidRequest("parameter too long")
	}
	return r, nil
}

// Resolved is a validated authorization request.
type Resolved struct {
	Client      *application.Client
	Scopes      []string
	ResourceIDs []string
	Prompt      []string
	MaxAge      *int
	ACRValues   []string
	// ClaimsRequest is the validated OIDC claims parameter (OIDC-008).
	ClaimsRequest string
	OrgID         string
}

// ResolveScopes validates requested scopes and resources against registrations and
// the client's grant ceiling (TOK-007, TOK-008, APP-007). Requesting a scope never
// grants it: unknown or disallowed scopes are rejected. A resource requested
// without any of its scopes is requested with its default scopes
// (withDefaultScopes).
func (s *Service) ResolveScopes(ctx context.Context, rlm *realm.Realm, c *application.Client, scope string, audiences []string, subjectType string) ([]string, []string, *Error) {
	requested := dedupe(strings.Fields(scope))
	if len(requested) > 50 {
		return nil, nil, ErrInvalidScope("too many scopes")
	}
	defs, err := s.Apps.ScopesByName(ctx, nil, rlm.ID, requested)
	if err != nil {
		return nil, nil, ErrServerError
	}
	grants, err := s.Apps.ResourceGrants(ctx, nil, c.Ref)
	if err != nil {
		return nil, nil, ErrServerError
	}
	grantFor := map[string]application.ResourceGrant{}
	for _, g := range grants {
		if slices.Contains(g.SubjectTypes, subjectType) {
			grantFor[g.ResourceID] = g
		}
	}
	var resourceIDs []string
	for _, aud := range audiences {
		res, err := s.Apps.ResourceByAudience(ctx, nil, rlm.ID, aud)
		if err != nil || res.State != "active" {
			return nil, nil, ErrInvalidTarget("unknown resource " + aud)
		}
		if _, ok := grantFor[res.ID]; !ok {
			return nil, nil, ErrInvalidTarget("client is not allowed to request " + aud)
		}
		if !slices.Contains(resourceIDs, res.ID) {
			resourceIDs = append(resourceIDs, res.ID)
		}
	}
	openid := false
	for _, name := range requested {
		def, ok := defs[name]
		if !ok {
			return nil, nil, ErrInvalidScope("unknown scope " + name)
		}
		if def.Kind == "oidc" {
			if name == "openid" {
				openid = true
			}
			if subjectType != "user" {
				return nil, nil, ErrInvalidScope("OpenID scopes require a user subject")
			}
			if name == "offline_access" && !c.AllowOfflineAccess {
				return nil, nil, ErrInvalidScope("offline_access is not permitted for this client")
			}
			continue
		}
		if len(audiences) == 0 && !slices.Contains(resourceIDs, def.ResourceID) {
			if _, ok := grantFor[def.ResourceID]; !ok {
				return nil, nil, ErrInvalidScope("client is not allowed to request " + name)
			}
			resourceIDs = append(resourceIDs, def.ResourceID)
		}
		if !slices.Contains(resourceIDs, def.ResourceID) {
			return nil, nil, ErrInvalidScope("scope " + name + " does not belong to the requested resource")
		}
		if !slices.Contains(grantFor[def.ResourceID].AllowedScopes, name) {
			return nil, nil, ErrInvalidScope("client is not allowed scope " + name)
		}
	}
	for _, name := range requested {
		if def := defs[name]; def.Kind == "oidc" && name != "openid" && name != "offline_access" && !openid {
			return nil, nil, ErrInvalidScope(name + " requires openid")
		}
	}
	if openid && subjectType == "user" {
		if ui, err := s.Apps.ResourceByKind(ctx, nil, rlm.ID, application.KindUserInfo); err == nil && !slices.Contains(resourceIDs, ui.ID) {
			resourceIDs = append(resourceIDs, ui.ID)
		}
	}
	if len(resourceIDs) == 0 {
		if c.DefaultResourceID != "" {
			if _, ok := grantFor[c.DefaultResourceID]; ok {
				resourceIDs = append(resourceIDs, c.DefaultResourceID)
			}
		}
	}
	if len(resourceIDs) == 0 {
		return nil, nil, ErrInvalidTarget("no resource requested")
	}
	requested, err = s.withDefaultScopes(ctx, rlm.ID, requested, defs, resourceIDs, grantFor)
	if err != nil {
		return nil, nil, ErrServerError
	}
	return requested, resourceIDs, nil
}

// withDefaultScopes applies default grants (APP-007): a resource of the
// request for which no scope was requested (one named by `resource`, or the
// client's default resource) is requested with its declared default scopes
// instead, as far as the client's resource grant lists them. From here on they
// are requested scopes like any other: consent, step-up, the organization
// ceiling and the subject's permissions apply at authorization and at every
// issuance, so a default scope is never granted where a requested one would
// not be. A resource with a requested scope gets no defaults, and protocol
// (OIDC) scopes are never added by default.
func (s *Service) withDefaultScopes(ctx context.Context, realmID string, requested []string, defs map[string]application.Scope, resourceIDs []string,
	grantFor map[string]application.ResourceGrant) ([]string, error) {
	for _, resID := range resourceIDs {
		if slices.ContainsFunc(requested, func(name string) bool { return defs[name].ResourceID == resID }) {
			continue
		}
		declared, err := s.Apps.ScopesForResource(ctx, s.d.DB.Pool, realmID, resID)
		if err != nil {
			return nil, err
		}
		for _, sc := range declared {
			if sc.IsDefault && sc.Kind != "oidc" && slices.Contains(grantFor[resID].AllowedScopes, sc.Name) && !slices.Contains(requested, sc.Name) {
				requested = append(requested, sc.Name)
			}
		}
	}
	return requested, nil
}

// validateInteractive validates an authorization request up to (and including)
// redirect URI matching. Errors before the redirect is trusted are local only.
func (s *Service) validateInteractive(ctx context.Context, rlm *realm.Realm, req AuthorizeRequest) (*Resolved, *Error, bool) {
	if !rlm.Active() {
		return nil, oerr(400, "invalid_request", "identity domain unavailable"), false
	}
	c, err := s.Apps.ClientByClientID(ctx, nil, rlm.ID, req.ClientID)
	// A SAML application's backing client is driven only by the SAML profile
	// (APP-018); it is not an OAuth client.
	if err != nil || !c.Active() || c.Protocol == application.ProtocolSAML {
		return nil, oerr(400, "invalid_client", "unknown or inactive client"), false
	}
	if !application.MatchRedirect(c.RedirectURIs, req.RedirectURI, c.Type) {
		return nil, oerr(400, "invalid_request", "redirect_uri is not registered for this client"), false
	}
	res := &Resolved{Client: c}
	// From here on the redirect is trusted, so errors may be returned to it.
	if req.Request != "" {
		return nil, oerr(400, "request_not_supported", "request objects are not supported"), true
	}
	if req.ResponseType != "code" {
		return nil, oerr(400, "unsupported_response_type", "only response_type=code is supported"), true
	}
	if !ValidResponseMode(req.ResponseMode) {
		return nil, ErrInvalidRequest("unsupported response_mode: query, query.jwt or jwt"), true
	}
	if !grantAllowed(rlm, c, application.GrantAuthorizationCode) {
		return nil, ErrUnauthorizedClient("client may not use the authorization code grant"), true
	}
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return nil, ErrInvalidRequest("PKCE with code_challenge_method=S256 is required"), true
	}
	if len(req.CodeChallenge) != 43 || strings.Trim(req.CodeChallenge, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return nil, ErrInvalidRequest("code_challenge must be a base64url SHA-256 digest"), true
	}
	if req.DPoPJKT != "" && !validJKT(req.DPoPJKT) {
		return nil, ErrInvalidRequest("dpop_jkt must be the base64url SHA-256 JWK thumbprint of the DPoP key"), true
	}
	claimACR, coe := parseClaimsParameter(req.Claims)
	if coe != nil {
		return nil, coe, true
	}
	res.ClaimsRequest = req.Claims
	prompts := strings.Fields(req.Prompt)
	for _, p := range prompts {
		if p != "none" && p != "login" && p != "consent" && p != "select_account" && p != "create" {
			return nil, ErrInvalidRequest("unsupported prompt value"), true
		}
	}
	if slices.Contains(prompts, "none") && len(prompts) > 1 {
		return nil, ErrInvalidRequest("prompt=none cannot be combined"), true
	}
	res.Prompt = prompts
	if req.MaxAge != "" {
		n, err := strconv.Atoi(req.MaxAge)
		if err != nil || n < 0 {
			return nil, ErrInvalidRequest("invalid max_age"), true
		}
		res.MaxAge = &n
	}
	res.ACRValues = strings.Fields(req.ACRValues)
	for _, a := range claimACR {
		if !slices.Contains(res.ACRValues, a) {
			res.ACRValues = append(res.ACRValues, a)
		}
	}
	for _, a := range res.ACRValues {
		if session.ACRRank(a) == 0 {
			return nil, ErrInvalidRequest("unsupported acr value " + a), true
		}
	}
	scopes, resources, oe := s.ResolveScopes(ctx, rlm, c, req.Scope, req.Resources, "user")
	if oe != nil {
		return nil, oe, true
	}
	res.Scopes, res.ResourceIDs = scopes, resources
	if req.Organization != "" {
		org, err := s.Orgs.Resolve(ctx, rlm.ID, req.Organization)
		if err != nil {
			// Do not reveal organization existence before authentication (DOM-008).
			return nil, ErrInvalidRequest("organization cannot be used"), true
		}
		res.OrgID = org.ID
	}
	if c.TokenPolicy.RequirePAR && req.RequestURI == "" {
		return nil, ErrInvalidRequest("this client must use pushed authorization requests"), true
	}
	return res, nil, true
}

// AuthorizeResult is the outcome of an authorization request.
type AuthorizeResult struct {
	LocalError        *Error
	Redirect          string
	TransactionCookie string
	TransactionID     string
	SessionCookie     string
	// SessionID is the session a silent completion used (OIDC-014 browser
	// state).
	SessionID string
}

// Authorize handles the browser authorization endpoint (OIDC-001). It starts a
// transaction, reusing an SSO session only when policy allows (SES-014), and either
// completes silently, returns an error to the validated redirect, or hands the
// browser to the configured login interface with a transaction cookie.
func (s *Service) Authorize(ctx context.Context, rlm *realm.Realm, req AuthorizeRequest, sessionCookie, clientIP, ua string) *AuthorizeResult {
	if req.RequestURI != "" {
		par, oe := s.consumePAR(ctx, rlm, req.ClientID, req.RequestURI)
		if oe != nil {
			return &AuthorizeResult{LocalError: oe}
		}
		req = par
	}
	res, oe, redirectTrusted := s.validateInteractive(ctx, rlm, req)
	if oe != nil {
		if !redirectTrusted {
			return &AuthorizeResult{LocalError: oe}
		}
		return &AuthorizeResult{Redirect: s.respond(ctx, rlm, req, nil, map[string]string{"error": oe.Code,
			"error_description": oe.Description, "state": req.State, "iss": rlm.Issuer})}
	}
	var reuse *session.Session
	if sessionCookie != "" {
		if sess, err := s.Sessions.ByCookie(ctx, rlm.ID, sessionCookie); err == nil {
			reuse = sess
		}
	}
	intent := "login"
	if slices.Contains(res.Prompt, "create") || req.Intent == "register" {
		intent = "register"
		reuse = nil
	}
	started, err := s.Auth.Start(ctx, authentication.StartInput{RealmID: rlm.ID, Client: res.Client, Mode: "browser", Intent: intent,
		RedirectURI: req.RedirectURI, ResponseMode: req.ResponseMode, Scopes: res.Scopes, ResourceIDs: res.ResourceIDs, State: req.State, Nonce: req.Nonce,
		CodeChallenge: req.CodeChallenge, ChallengeMethod: req.CodeChallengeMethod, Prompt: res.Prompt, MaxAge: res.MaxAge,
		ACRValues: res.ACRValues, LoginHint: req.LoginHint, UILocales: req.UILocales, OrgID: res.OrgID, ClientIP: clientIP, UserAgent: ua,
		ReuseSession: reuse, ClaimsRequest: res.ClaimsRequest, DPoPJKT: req.DPoPJKT})
	if err != nil {
		return &AuthorizeResult{Redirect: s.respond(ctx, rlm, req, res.Client, map[string]string{"error": "server_error", "state": req.State, "iss": rlm.Issuer})}
	}
	proof := authentication.Proof{Continuation: started.Continuation}
	if started.Transaction.UserID != "" {
		st, err := s.Auth.Resume(ctx, rlm.ID, started.Transaction.ID, proof)
		if err == nil && st.RedirectTo != "" {
			res := &AuthorizeResult{Redirect: st.RedirectTo, SessionCookie: st.SessionCookie}
			if st.Completion != nil {
				res.SessionID = st.Completion.SessionID
			}
			return res
		}
		if slices.Contains(res.Prompt, "none") {
			code := "interaction_required"
			if err == nil && len(st.NextActions) > 0 {
				switch st.NextActions[0].Type {
				case "consent":
					code = "consent_required"
				case "select_organization":
					code = "account_selection_required"
				case "totp", "hotp", "webauthn", "recovery_code", "password", "identify":
					code = "login_required"
				}
			}
			_, _ = s.Auth.Cancel(ctx, rlm.ID, started.Transaction.ID, proof)
			return &AuthorizeResult{Redirect: s.respond(ctx, rlm, req, res.Client, map[string]string{"error": code, "state": req.State, "iss": rlm.Issuer})}
		}
	} else if slices.Contains(res.Prompt, "none") {
		_, _ = s.Auth.Cancel(ctx, rlm.ID, started.Transaction.ID, proof)
		return &AuthorizeResult{Redirect: s.respond(ctx, rlm, req, res.Client, map[string]string{"error": "login_required", "state": req.State, "iss": rlm.Issuer})}
	}
	ui := res.Client.LoginUIURL
	if ui == "" {
		ui = rlm.Policy.Interaction.LoginUIURL
	}
	if ui == "" {
		return &AuthorizeResult{LocalError: oerr(500, "temporarily_unavailable", "no interaction surface is configured for this realm or client")}
	}
	return &AuthorizeResult{Redirect: authentication.BuildRedirect(ui, map[string]string{"transaction_id": started.Transaction.ID, "realm": rlm.Name}),
		TransactionCookie: started.Continuation, TransactionID: started.Transaction.ID}
}

// StartHeadless validates an authorization request submitted by a registered client
// to the headless transaction API and returns the continuation once (AUT-001). It is
// a project-specific interaction API, not a new OAuth grant: completion still yields
// an authorization code redeemable only with the PKCE verifier.
func (s *Service) StartHeadless(ctx context.Context, rlm *realm.Realm, req AuthorizeRequest, clientIP, ua string) (*authentication.Started, error) {
	if req.RequestURI != "" {
		par, oe := s.consumePAR(ctx, rlm, req.ClientID, req.RequestURI)
		if oe != nil {
			return nil, problem.ErrBadRequest.WithDetail(oe.Description)
		}
		req = par
	}
	res, oe, _ := s.validateInteractive(ctx, rlm, req)
	if oe != nil {
		return nil, problem.ErrBadRequest.WithDetail(oe.Code + ": " + oe.Description)
	}
	prompt := res.Prompt
	if slices.Contains(prompt, "none") {
		return nil, problem.ErrBadRequest.WithDetail("prompt=none requires the browser authorization endpoint")
	}
	intent := "login"
	if req.Intent == "register" || slices.Contains(prompt, "create") {
		intent = "register"
	}
	return s.Auth.Start(ctx, authentication.StartInput{RealmID: rlm.ID, Client: res.Client, Mode: "headless", Intent: intent,
		RedirectURI: req.RedirectURI, ResponseMode: req.ResponseMode, Scopes: res.Scopes, ResourceIDs: res.ResourceIDs, State: req.State, Nonce: req.Nonce,
		CodeChallenge: req.CodeChallenge, ChallengeMethod: req.CodeChallengeMethod, Prompt: prompt, MaxAge: res.MaxAge,
		ACRValues: res.ACRValues, LoginHint: req.LoginHint, UILocales: req.UILocales, OrgID: res.OrgID, ClientIP: clientIP, UserAgent: ua,
		ClaimsRequest: res.ClaimsRequest, DPoPJKT: req.DPoPJKT})
}

// validJKT reports whether s has the form of a JWK SHA-256 thumbprint
// (RFC 7638): 43 base64url characters without padding.
func validJKT(s string) bool {
	return len(s) == 43 && strings.Trim(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

var _ = secret.Digest
