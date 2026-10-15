package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/worker"
)

// Regression fixtures for security fixes (QA-008) in token scope policy,
// authentication flows, factor enrollment, profile visibility and support
// access. Each test names the CHANGELOG "Security fixes" entry it guards.

// TestAutomationCredentialStepUpScopes covers QA-008 and AUT-010 (CHANGELOG
// "Scope step-up bypass"): API keys and personal access tokens carry no
// authentication event, so a scope with a step-up policy (stronger or fresher
// authentication) is refused at creation with 403 grant_ceiling_exceeded,
// even from an MFA session, and introspection leaves such scopes out of
// credentials minted before the policy applied; a credential left without
// scopes is inactive.
func TestAutomationCredentialStepUpScopes(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	for _, sc := range []struct {
		resource string
		body     map[string]any
	}{
		{f.Orders, map[string]any{"name": "orders:approve", "step_up_acr": "urn:proudauth:acr:mfa"}},
		{f.Orders, map[string]any{"name": "orders:export", "max_auth_age_seconds": 300}},
		{f.Orders, map[string]any{"name": "orders:annotate"}},
		{f.Billing, map[string]any{"name": "billing:approve", "step_up_acr": "urn:proudauth:acr:mfa"}},
		{f.Billing, map[string]any{"name": "billing:export"}},
	} {
		f.must(f.AdminAPI("POST", "/resources/"+sc.resource+"/scopes", sc.body), 201, "scope "+sc.body["name"].(string))
	}
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token") // an MFA session
	pat := func(scopes ...string) *Resp {
		return h.API("POST", "/me/personal-tokens", alice, map[string]any{"name": "ci", "audience": f.OrdersAud, "scopes": scopes,
			"organization_id": f.Acme, "ttl_days": 30})
	}
	bot := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "step-up-bot", "allowed_organization_ids": []string{f.Acme}}), 201, "sp").Str("id")
	apiKey := func(scopes ...string) *Resp {
		return f.AdminAPI("POST", "/api-keys", map[string]any{"service_principal_id": bot, "name": "sync", "audience": f.BillingAud, "scopes": scopes,
			"organization_id": f.Acme})
	}
	refused := func(r *Resp, what string) {
		t.Helper()
		if r.Status != 403 || r.Str("code") != "grant_ceiling_exceeded" {
			t.Fatalf("%s: %d %s", what, r.Status, r.Raw)
		}
	}
	refused(pat("orders:read", "orders:approve"), "personal token with a step-up assurance scope")
	refused(pat("orders:export"), "personal token with a maximum authentication age scope")
	refused(apiKey("billing:read", "billing:approve"), "API key with a step-up scope")

	// Credentials created before their scope gained a step-up policy.
	mixedPAT := pat("orders:read", "orders:annotate")
	mustStatus(t, mixedPAT, 201, "personal token")
	onlyPAT := pat("orders:annotate")
	mustStatus(t, onlyPAT, 201, "personal token with one scope")
	mixedKey := apiKey("billing:read", "billing:export")
	mustStatus(t, mixedKey, 201, "API key")
	onlyKey := apiKey("billing:export")
	mustStatus(t, onlyKey, 201, "API key with one scope")
	introspectPAT := func(tok string) *Resp { return h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, tok) }
	introspectKey := func(tok string) *Resp { return h.Introspect("billing-rs", f.Clients["billing-rs"].Secret, tok) }
	if in := introspectPAT(mixedPAT.Str("token")); in.Get("active") != true || in.Str("scope") != "orders:read orders:annotate" {
		t.Fatalf("personal token before the policy: %s", in.Raw)
	}
	// There is no API to change a declared scope: the fixture applies the
	// policy in storage, as an upgrade finds credentials minted before the fix.
	for name, acr := range map[string]string{"orders:annotate": "urn:proudauth:acr:mfa", "billing:export": "urn:proudauth:acr:phishing_resistant"} {
		if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE scopes SET step_up_acr=$3 WHERE realm_id=$1 AND name=$2`, h.Realm.ID, name, acr); err != nil {
			t.Fatal(err)
		}
	}
	if in := introspectPAT(mixedPAT.Str("token")); in.Get("active") != true || in.Str("scope") != "orders:read" {
		t.Fatalf("personal token kept a step-up scope: %s", in.Raw)
	}
	if in := introspectPAT(onlyPAT.Str("token")); in.Get("active") != false {
		t.Fatalf("personal token with only a step-up scope stayed active: %s", in.Raw)
	}
	if in := introspectKey(mixedKey.Str("api_key")); in.Get("active") != true || in.Str("scope") != "billing:read" {
		t.Fatalf("API key kept a step-up scope: %s", in.Raw)
	}
	if in := introspectKey(onlyKey.Str("api_key")); in.Get("active") != false {
		t.Fatalf("API key with only a step-up scope stayed active: %s", in.Raw)
	}
}

// exchangeFor exchanges a subject access token at the token endpoint as the
// orders-rs service, for one target audience and optional scopes.
func exchangeFor(f *Fixture, subject, audience, scope string) *Resp {
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subject},
		"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {audience}}
	if scope != "" {
		form.Set("scope", scope)
	}
	return f.H.TokenRequest(form, "orders-rs", f.Clients["orders-rs"].Secret)
}

// TestExchangeScopeRequiredPermissions covers QA-008 and TOK-008 (CHANGELOG
// "Token exchange ignored the organization's scope policy"): an exchanged
// token never carries a scope whose required_permissions the subject lacks in
// the token's organization. Naming such a scope is refused with invalid_scope;
// a default (scope-less) exchange leaves it out.
func TestExchangeScopeRequiredPermissions(t *testing.T) {
	f := NewFixture(t)
	f.must(f.AdminAPI("POST", "/resources/"+f.Billing+"/scopes", map[string]any{"name": "billing:statements",
		"required_permissions": []string{"billing.read"}}), 201, "scope with subject policy")
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["orders-rs"].Ref+"/resource-grants/"+f.Billing, map[string]any{
		"allowed_scopes": []string{"billing:read", "billing:statements"}, "subject_types": []string{"service_principal", "user"},
		"exchange_policy": map[string]any{"accept_from_audiences": []string{f.OrdersAud}}}), 204, "exchange grant")
	// bob holds no billing.read in Acme; alice does (billing-viewer).
	bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	alice := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	for _, scope := range []string{"billing:statements", "billing:read billing:statements"} {
		if ex := exchangeFor(f, bob, f.BillingAud, scope); ex.Status != 400 || ex.Str("error") != "invalid_scope" {
			t.Fatalf("exchange for %q without the required permission: %d %s", scope, ex.Status, ex.Raw)
		}
	}
	ex := exchangeFor(f, bob, f.BillingAud, "")
	if ex.Status != 200 || ex.Str("scope") != "billing:read" || jwtPayload(ex.Str("access_token"))["scope"] != "billing:read" {
		t.Fatalf("default exchange kept a scope the subject does not qualify for: %d %s", ex.Status, ex.Raw)
	}
	if ex := exchangeFor(f, alice, f.BillingAud, "billing:statements"); ex.Status != 200 || ex.Str("scope") != "billing:statements" {
		t.Fatalf("exchange for a qualified subject: %d %s", ex.Status, ex.Raw)
	}
	if ex := exchangeFor(f, alice, f.BillingAud, ""); ex.Status != 200 || ex.Str("scope") != "billing:read billing:statements" {
		t.Fatalf("default exchange for a qualified subject: %d %s", ex.Status, ex.Raw)
	}
}

// TestExchangeLimitedToUserConsent covers QA-008 and TOK-008 (CHANGELOG "Token
// exchange beyond the user's consent"): for a subject token issued to a
// client with consent_mode required, exchanged scopes are limited to the
// user's live consent for that client. A requested scope outside it is
// refused with invalid_scope, the default ceiling is narrowed to it, and a
// revoked consent leaves nothing to exchange.
func TestExchangeLimitedToUserConsent(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	created := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "consent-app", "name": "Consent App", "client_type": "confidential",
		"first_party": false, "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://consent.test/cb"}}), 201, "third-party client")
	if created.Str("client.consent_mode") != "required" {
		t.Fatalf("third-party client consent mode: %s", created.Raw)
	}
	f.must(f.AdminAPI("PUT", "/clients/"+created.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{
		"allowed_scopes": []string{"orders:read", "orders:write"}, "subject_types": []string{"user"}}), 204, "client grant")
	// The exchanging service may turn an Orders token into an Orders token
	// with either scope.
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["orders-rs"].Ref+"/resource-grants/"+f.Orders, map[string]any{
		"allowed_scopes": []string{"orders:read", "orders:write"}, "subject_types": []string{"user"},
		"exchange_policy": map[string]any{"accept_from_audiences": []string{f.OrdersAud}}}), 204, "exchange grant")
	lr := h.Login(LoginOpts{ClientID: "consent-app", ClientSecret: created.Str("client_secret"), RedirectURI: "https://consent.test/cb", Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	subject := lr.Tokens.Str("access_token")
	// Without consent governance the ceiling is the whole grant.
	first := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	if ex := exchangeFor(f, first, f.OrdersAud, ""); ex.Status != 200 || ex.Str("scope") != "orders:read orders:write" {
		t.Fatalf("default exchange of a first-party token: %d %s", ex.Status, ex.Raw)
	}
	if ex := exchangeFor(f, subject, f.OrdersAud, ""); ex.Status != 200 || ex.Str("scope") != "orders:read" {
		t.Fatalf("default exchange was not narrowed to the user's consent: %d %s", ex.Status, ex.Raw)
	}
	for _, scope := range []string{"orders:write", "orders:read orders:write"} {
		if ex := exchangeFor(f, subject, f.OrdersAud, scope); ex.Status != 400 || ex.Str("error") != "invalid_scope" {
			t.Fatalf("exchange for %q beyond the user's consent: %d %s", scope, ex.Status, ex.Raw)
		}
	}
	if ex := exchangeFor(f, subject, f.OrdersAud, "orders:read"); ex.Status != 200 || ex.Str("scope") != "orders:read" {
		t.Fatalf("exchange within the user's consent: %d %s", ex.Status, ex.Raw)
	}
	// The consent is checked live: once revoked, nothing is exchanged.
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	consents := f.must(h.API("GET", "/me/consents", bob, nil), 200, "my consents").Get("items").([]any)
	if len(consents) != 1 {
		t.Fatalf("consents: %v", consents)
	}
	mustStatus(t, h.API("DELETE", "/me/consents/"+consents[0].(map[string]any)["id"].(string), bob, nil), 204, "revoke consent")
	if ex := exchangeFor(f, subject, f.OrdersAud, ""); ex.Status != 400 {
		t.Fatalf("exchange after the consent was revoked: %d %s", ex.Status, ex.Raw)
	}
}

// TestFlowChallengeNotAnsweredByEnrollment covers QA-008, AUT-012, AUT-014 and
// SEC-014 (CHANGELOG "Authentication flow rules could be weakened or answered
// by the attacker"): a flow challenge is answered before any factor can be
// enrolled in the transaction, so whoever holds only the password cannot
// answer it with their own new TOTP. It is answered by an emailed code to the
// verified primary address or an already enrolled factor, never by a
// remembered device; with no way to answer it the transaction stops with
// authentication_policy_denied.
func TestFlowChallengeNotAnsweredByEnrollment(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Login.RememberDevices = true })
	h := f.H
	f.EnrollTOTP("alice")
	step := func(tx, cont, path string, body any, device string) *Resp {
		t.Helper()
		if body == nil {
			body = map[string]any{}
		}
		hdr := map[string]string{"X-Transaction-Token": cont}
		if device != "" {
			hdr["X-Remembered-Device"] = device
		}
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/" + path, JSON: body, Headers: hdr})
	}
	login := func(user, device string) (string, string, *Resp) {
		t.Helper()
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme})
		tx := start.Str("transaction_id")
		step(tx, cont, "identify", map[string]any{"identifier": user + "@example.test"}, device)
		return tx, cont, step(tx, cont, "password", map[string]any{"password": h.passwords[user+"@example.test"]}, device)
	}
	// alice remembers a device while no flow rule applies; it skips her TOTP.
	tx, cont, _ := login("alice", "")
	mustStatus(t, step(tx, cont, "remember-device", map[string]any{"remember": true}, ""), 200, "remember the device")
	done := step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("alice@example.test")}, "")
	device := done.Str("one_time.remembered_device_token")
	if device == "" || done.Str("redirect_to") == "" {
		t.Fatalf("no remembered device: %s", done.Raw)
	}
	if _, _, st := login("alice", device); st.Str("redirect_to") == "" {
		t.Fatalf("remembered device did not skip the MFA prompt: %s", st.Raw)
	}

	// MFA is required and web sign-ins are challenged, with no provider and
	// no emailed code.
	no := false
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.MFA.Requirement = realm.MFARequired
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "challenge web sign-ins", When: realm.AuthFlowCondition{Clients: []string{"web-bff"}}, Outcome: "challenge"}}
		p.AuthFlow.EmailCodeAlternative = &no
	}), 200, "challenge policy")
	// bob has only a password: nothing can answer the challenge, and the
	// enrollment the realm requires is not offered in its place.
	tx, cont, st := login("bob", "")
	if st.Str("error") != "authentication_policy_denied" || hasAction(st, "enroll_totp") {
		t.Fatalf("unanswerable challenge did not stop the sign-in: %s", st.Raw)
	}
	if r := step(tx, cont, "totp/enroll", nil, ""); r.Status == 200 || r.Str("one_time.totp.secret") != "" {
		t.Fatalf("factor enrolled in a transaction stopped by its challenge: %d %s", r.Status, r.Raw)
	}
	// alice's remembered device does not answer the challenge; her enrolled
	// TOTP does.
	tx, cont, st = login("alice", device)
	if st.Str("redirect_to") != "" || !hasAction(st, "totp") {
		t.Fatalf("remembered device answered the challenge: %s", st.Raw)
	}
	if done := step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("alice@example.test")}, device); done.Str("redirect_to") == "" {
		t.Fatalf("enrolled TOTP did not answer the challenge: %d %s", done.Status, done.Raw)
	}

	// With the emailed code offered, bob answers the challenge first; only
	// then may he enroll the factor the realm requires.
	yes := true
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.AuthFlow.EmailCodeAlternative = &yes }), 200, "emailed code alternative")
	tx, cont, st = login("bob", "")
	if !hasAction(st, "challenge") || hasAction(st, "enroll_totp") || hasAction(st, "enroll_webauthn") {
		t.Fatalf("challenge not asked before enrollment: %s", st.Raw)
	}
	if r := step(tx, cont, "totp/enroll", nil, ""); r.Status == 200 || r.Str("one_time.totp.secret") != "" {
		t.Fatalf("factor enrolled before the challenge was answered: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, step(tx, cont, "challenge/send", nil, ""), 200, "send challenge code")
	code := CodeFrom(h.Mail("bob@example.test", "login_code"))
	st = step(tx, cont, "challenge", map[string]any{"code": code}, "")
	if st.Status != 200 || !hasAction(st, "enroll_totp") {
		t.Fatalf("after the emailed-code challenge: %d %s", st.Status, st.Raw)
	}
	if st = h.Drive(tx, cont, st, LoginOpts{Identifier: "bob@example.test"}); st.Str("redirect_to") == "" {
		t.Fatalf("sign-in after the challenge and enrollment: %d %s", st.Status, st.Raw)
	}
}

// TestRiskHookFailureKeepsOtherLevels covers QA-008, AUT-012 and AUT-014
// (CHANGELOG "Authentication flow rules could be weakened or answered by the
// attacker"): when one authentication.risk hook fails, every other hook is
// still called and their highest level counts as a lower bound
// (risk: at_least_<level>): it satisfies rules up to that level, and a rule
// above it treats the signal as missing.
func TestRiskHookFailureKeepsOtherLevels(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	risk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.URL.Path]++
		mu.Unlock()
		if r.URL.Path == "/down" {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"level":"medium","reasons":["new_country"]}`))
	}))
	defer risk.Close()
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	ctx := context.Background()
	// Hooks are called in name order: the failing one comes first.
	f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "a-risk-down", "kind": "authentication.risk", "url": risk.URL + "/down",
		"allow_private_network": true}), 201, "failing risk hook")
	f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "b-risk-medium", "kind": "authentication.risk", "url": risk.URL + "/medium",
		"allow_private_network": true}), 201, "risk hook")
	login := func() *Resp {
		t.Helper()
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme})
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		return h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	}
	lastDecision := func() map[string]any {
		t.Helper()
		var meta []byte
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata FROM audit_events WHERE type='authentication.flow.evaluated' ORDER BY seq DESC LIMIT 1`).Scan(&meta); err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		_ = json.Unmarshal(meta, &m)
		return m
	}
	// Both rules skip a missing signal: only a known level can deny.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{
			{Name: "high risk denied", When: realm.AuthFlowCondition{RiskAtLeast: "high"}, Outcome: "deny", OnMissingSignal: "skip"},
			{Name: "medium risk denied", When: realm.AuthFlowCondition{RiskAtLeast: "medium"}, Outcome: "deny", OnMissingSignal: "skip"},
		}
	}), 200, "risk policy")
	if st := login(); st.Str("error") != "authentication_policy_denied" {
		t.Fatalf("a failing hook discarded the other hook's level: %d %s", st.Status, st.Raw)
	}
	mu.Lock()
	down, medium := calls["/down"], calls["/medium"]
	mu.Unlock()
	if down == 0 || medium == 0 {
		t.Fatalf("not every risk hook was called: %v", calls)
	}
	d := lastDecision()
	signals, _ := d["signals"].(map[string]any)
	if d["rule"] != "medium risk denied" || signals["risk"] != "at_least_medium" || !strings.Contains(jsonString(signals["risk_reasons"]), "new_country") {
		t.Fatalf("decision with a partial risk signal: %v", d)
	}
	// A lower bound below a rule's level is a missing signal for that rule.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "high risk denied", When: realm.AuthFlowCondition{RiskAtLeast: "high"}, Outcome: "deny",
			OnMissingSignal: "skip"}}
	}), 200, "high-risk policy")
	if st := login(); st.Status != 200 || st.Str("redirect_to") == "" {
		t.Fatalf("a lower bound below the rule's level matched it: %d %s", st.Status, st.Raw)
	}
	if d := lastDecision(); !strings.Contains(jsonString(d["missing_signals"]), "risk") {
		t.Fatalf("the partial risk signal was not reported missing for the high-risk rule: %v", d)
	}
}

// TestFactorEnrollmentNeedsExistingFactor covers QA-008 and MFA-006
// (CHANGELOG "A second factor could be added without proving the first"): on
// an account that already has a TOTP factor, a password-only session (one
// created before the factor, or one that skipped MFA through a remembered
// device) cannot enroll TOTP or a passkey (403 step_up_required with a
// reauthenticate obligation); a session that completed MFA can. TestPasskeys
// covers an account whose existing factor is a passkey.
func TestFactorEnrollmentNeedsExistingFactor(t *testing.T) {
	f := NewFixture(t, passkeyPolicy, func(p *realm.Policy) { p.Login.RememberDevices = true })
	h := f.H
	before := f.AccountToken("bob").Tokens.Str("access_token") // password only, before the factor
	f.EnrollTOTP("bob")
	// A remembered device skips the TOTP prompt without proving the factor.
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	step := func(tx, cont, path string, body any, device string) *Resp {
		t.Helper()
		hdr := map[string]string{"X-Transaction-Token": cont}
		if device != "" {
			hdr["X-Remembered-Device"] = device
		}
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + tx + "/" + path, JSON: body, Headers: hdr})
	}
	start, _, cont := h.StartTx(cli)
	tx := start.Str("transaction_id")
	step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}, "")
	step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}, "")
	mustStatus(t, step(tx, cont, "remember-device", map[string]any{"remember": true}, ""), 200, "remember the device")
	done := step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("bob@example.test")}, "")
	device := done.Str("one_time.remembered_device_token")
	if device == "" {
		t.Fatalf("no remembered device: %s", done.Raw)
	}
	start, verifier, cont := h.StartTx(cli)
	tx = start.Str("transaction_id")
	step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}, device)
	st := step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}, device)
	u, _ := url.Parse(st.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("remembered device did not skip the MFA prompt: %s", st.Raw)
	}
	remembered := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
		"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {h.Realm.Issuer + "/account"}}, "", "")
	mustStatus(t, remembered, 200, "token through the remembered device")

	enrollments := []struct {
		path string
		body any
	}{
		{"/me/totp/enroll", nil},
		{"/me/totp/activate", map[string]any{"code": "000000"}},
		{"/me/webauthn/registration-options", map[string]any{}},
		{"/me/webauthn/registration-complete", map[string]any{"ceremony_id": "wrc_unknown", "credential": map[string]any{}}},
	}
	for name, tok := range map[string]string{"session older than the factor": before, "remembered-device session": remembered.Str("access_token")} {
		for _, e := range enrollments {
			r := h.API("POST", e.path, tok, e.body)
			if r.Status != 403 || r.Str("code") != "step_up_required" || !strings.Contains(string(r.Raw), `"required_profile":"mfa"`) {
				t.Fatalf("%s reached %s without proving the existing factor: %d %s", name, e.path, r.Status, r.Raw)
			}
		}
	}
	// A session that proved the existing factor may add another.
	mfa := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/webauthn/registration-options", mfa, map[string]any{}), 200, "passkey enrollment from an MFA session")
	mustStatus(t, h.API("POST", "/me/totp/enroll", mfa, nil), 201, "TOTP enrollment from an MFA session")
}

// TestProfileAttributeVisibility covers QA-008, USR-002, USR-007 and USR-013
// (CHANGELOG "Profile attribute visibility was not enforced"): self-service
// responses (GET and PATCH /me) and the self-service data export include only
// attributes the schema defines with visibility self; administrator views
// (user, user list, update response) include self, admin and undefined
// attributes but never internal ones.
func TestProfileAttributeVisibility(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	bob := f.Users["bob"]
	// Stored before the schema defines it.
	f.must(f.AdminAPI("PATCH", "/users/"+bob, map[string]any{"profile": map[string]any{"legacy_code": "L-1"}}), 200, "undefined attribute")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{
			{Name: "department", Type: "string", UserEditable: true},
			{Name: "employee_id", Type: "string", Visibility: "admin"},
			{Name: "risk_score", Type: "number", Visibility: "internal"},
		}
	}), 200, "schema")
	upd := f.must(f.AdminAPI("PATCH", "/users/"+bob, map[string]any{"profile": map[string]any{"department": "sales", "employee_id": "E-7",
		"risk_score": 0.9}}), 200, "admin edit")
	adminView := func(what string, v any) {
		t.Helper()
		prof, _ := v.(map[string]any)
		if prof["department"] != "sales" || prof["employee_id"] != "E-7" || prof["legacy_code"] != "L-1" {
			t.Fatalf("%s lacks attributes administrators may see: %v", what, v)
		}
		if _, ok := prof["risk_score"]; ok {
			t.Fatalf("%s exposes an internal attribute: %v", what, v)
		}
	}
	adminView("admin update response", upd.Get("profile"))
	adminView("admin user view", f.must(f.AdminAPI("GET", "/users/"+bob, nil), 200, "user").Get("profile"))
	list := f.must(f.AdminAPI("GET", "/users?q="+url.QueryEscape("bob@example.test"), nil), 200, "user list")
	found := false
	for _, it := range list.Get("items").([]any) {
		if m := it.(map[string]any); m["id"] == bob {
			found = true
			adminView("admin user list", m["profile"])
		}
	}
	if !found {
		t.Fatalf("bob not in the user list: %s", list.Raw)
	}

	selfView := func(what string, v any, department string) {
		t.Helper()
		prof, _ := v.(map[string]any)
		if prof["department"] != department || len(prof) != 1 {
			t.Fatalf("%s: want only the self-visible attribute, got %v", what, v)
		}
	}
	tok := f.AccountToken("bob").Tokens.Str("access_token")
	selfView("GET /me", f.must(h.API("GET", "/me", tok, nil), 200, "me").Get("profile"), "sales")
	selfView("PATCH /me", f.must(h.API("PATCH", "/me", tok, map[string]any{"profile": map[string]any{"department": "support"}}), 200, "self edit").Get("profile"), "support")
	job := f.must(h.API("POST", "/me/exports", tok, nil), 202, "export").Str("job_id")
	runWorker(t, worker.New(h.App, "test"))
	if st := f.must(h.API("GET", "/jobs/"+job, tok, nil), 200, "job"); st.Str("state") != "succeeded" {
		t.Fatalf("export job: %s", st.Raw)
	}
	dl := f.must(h.API("POST", "/jobs/"+job+"/downloads", tok, nil), 201, "download token")
	data := f.must(h.API("POST", "/job-downloads", tok, map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	var export struct {
		Profile struct {
			Profile map[string]any `json:"profile"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(data.Raw, &export); err != nil {
		t.Fatalf("export: %v", err)
	}
	selfView("self-service export", export.Profile.Profile, "support")
	for _, leak := range []string{"E-7", "employee_id", "risk_score", "legacy_code"} {
		if strings.Contains(string(data.Raw), leak) {
			t.Fatalf("export contains %q", leak)
		}
	}
}

// TestSupportWritesNeedAllowlist covers QA-008, IMP-011 and IMP-013
// (CHANGELOG "Support writes through the decision API"): an allowlisted_write
// support token may perform through /authorization/check only the writes the
// resource lists in impersonation_policy.write_actions; any other write, also
// one with a read-only suffix, is denied with
// SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED although the customer holds the
// permission, and a read-only support token performs no writes.
func TestSupportWritesNeedAllowlist(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	for _, p := range []string{"orders.update", "orders.cancel"} {
		f.must(f.AdminAPI("POST", "/permissions", map[string]any{"name": p}), 201, "permission "+p)
	}
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "orders-operator",
		"permissions": []string{"orders.read", "orders.update", "orders.cancel"}}), 201, "role").Str("id")
	dave := f.CreateUser("dave")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": dave, "role_ids": []string{f.Roles["member"], role}}), 201, "member dave")
	cur := f.must(f.AdminAPI("GET", "/resources/"+f.Orders, nil), 200, "resource")
	mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resources/" + f.Orders, Token: f.AdminToken, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")},
		JSON: map[string]any{"name": "Orders API", "verification_mode": "strict_online", "impersonation_enabled": true,
			"impersonation_policy": map[string]any{"allowed_scopes": []string{"orders:read"}, "write_scopes": []string{"orders:write"},
				"write_actions": []string{"orders.update"}, "contract_version": "support-contract-1", "support_client_ids": []string{"support-bff"}}}}),
		200, "write allowlist")

	s := f.support(t)
	req := s.request(dave, f.Acme, map[string]any{"mode": "allowlisted_write", "scopes": []string{"orders:read", "orders:write"}})
	mustStatus(t, req, 201, "write support request")
	mustStatus(t, f.AdminAPI("POST", "/impersonation-requests/"+req.Str("id")+"/approve", nil), 204, "second operator approves")
	out := h.API("POST", "/impersonation-requests/"+req.Str("id")+"/issue", s.samTok, nil)
	mustStatus(t, out, 201, "issue write support token")
	write := out.Str("access_token")
	if in := h.Introspect("orders-rs", f.Clients["orders-rs"].Secret, write); in.Str("support_mode") != "allowlisted_write" {
		t.Fatalf("support token mode: %s", in.Raw)
	}
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	expect := func(subject, action string, allowed bool, reason string) {
		t.Helper()
		d := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": subject, "action": action,
			"resource": map[string]any{"type": "order", "org_id": f.Acme}})
		mustStatus(t, d, 200, "decision "+action)
		if d.Get("allowed") != allowed || (reason != "" && d.Str("reason_code") != reason) {
			t.Fatalf("%s: %s (want allowed=%v %s)", action, d.Raw, allowed, reason)
		}
	}
	expect(write, "orders.read", true, "")
	expect(write, "orders.update", true, "")
	expect(write, "orders.cancel", false, "SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED")
	expect(write, "orders.cancel.view", false, "SUPPORT_ACCESS_WRITE_NOT_ALLOWLISTED")
	// The customer may cancel: the refusal above is the allowlist's.
	expect(f.LoginWeb("dave", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token"), "orders.cancel", true, "")
	readOnly := s.issue(t, dave, f.Acme).Str("access_token")
	expect(readOnly, "orders.read", true, "")
	expect(readOnly, "orders.update", false, "SUPPORT_ACCESS_READ_ONLY")
}
