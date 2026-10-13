package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/authentication"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/realm"
)

// TestAuthenticationFlowPolicy covers AUT-012 (an ordered, bounded flow
// definition with recorded, explainable decisions), AUT-014 (risk signals
// from hooks; a missing signal never satisfies a stricter rule) and SEC-014
// (optional challenge providers with an accessible emailed-code alternative).
func TestAuthenticationFlowPolicy(t *testing.T) {
	var mu sync.Mutex
	riskBody, riskStatus := `{"level":"low"}`, 200
	var riskRequest []byte
	risk := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		riskRequest, _ = io.ReadAll(r.Body)
		w.WriteHeader(riskStatus)
		_, _ = w.Write([]byte(riskBody))
	}))
	defer risk.Close()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ok := r.Form.Get("secret") == "provider-secret" && r.Form.Get("response") == "human" && r.Form.Get("remoteip") == ""
		w.Header().Set("Content-Type", "application/json")
		if ok {
			_, _ = w.Write([]byte(`{"success":true}`))
		} else {
			_, _ = w.Write([]byte(`{"success":false}`))
		}
	}))
	defer provider.Close()
	authentication.ChallengeHTTPClient = provider.Client()
	defer func() { authentication.ChallengeHTTPClient = nil }()

	h := NewHarness(t, allowPrivate, func(c *configuration.Config) {
		c.Security.ChallengeProviders = []configuration.ChallengeProviderConfig{{Name: "bot-check", VerifyURL: provider.URL, SiteKey: "site-123",
			Secret: "provider-secret"}}
	})
	f := fixtureOn(t, h)
	ctx := context.Background()
	yes := true

	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "x", Outcome: "maybe"}}
	}), 422, "unknown outcome")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "x", Outcome: "deny", When: realm.AuthFlowCondition{Networks: []string{"not-a-cidr"}}}}
	}), 422, "bad network")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{
			{Name: "high risk", When: realm.AuthFlowCondition{RiskAtLeast: "high"}, Outcome: "deny", OnMissingSignal: "skip"},
			{Name: "new device", When: realm.AuthFlowCondition{NewDevice: &yes, Clients: []string{"web-bff"}}, Outcome: "challenge"},
		}
		p.AuthFlow.ChallengeProvider = "unconfigured"
	}), 422, "unknown challenge provider")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{
			{Name: "high risk", When: realm.AuthFlowCondition{RiskAtLeast: "high"}, Outcome: "deny", OnMissingSignal: "skip"},
			{Name: "new device", When: realm.AuthFlowCondition{NewDevice: &yes, Clients: []string{"web-bff"}}, Outcome: "challenge"},
		}
		p.AuthFlow.ChallengeProvider = "bot-check"
	}), 200, "flow policy")

	login := func() (string, string, *Resp) {
		t.Helper()
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme})
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		return tx, cont, h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	}
	challengeOf := func(st *Resp) map[string]any {
		for _, a := range st.Get("next_actions").([]any) {
			if m := a.(map[string]any); m["type"] == "challenge" {
				return m["options"].(map[string]any)
			}
		}
		return nil
	}

	// No risk hook: the risk rule is skipped (on_missing_signal skip); a new
	// device is challenged, with the provider and the emailed code offered.
	tx, cont, st := login()
	opts := challengeOf(st)
	if opts == nil {
		t.Fatalf("no challenge: %s", st.Raw)
	}
	if opts["provider"] == nil || opts["provider"].(map[string]any)["site_key"] != "site-123" || opts["email_code"] == nil {
		t.Fatalf("challenge not offered: %s", st.Raw)
	}
	mustStatus(t, h.Step(tx, cont, "challenge", map[string]any{"provider_response": "bot"}), 400, "failed provider challenge")
	done := h.Step(tx, cont, "challenge", map[string]any{"provider_response": "human"})
	if done.Status != 200 || done.Str("redirect_to") == "" {
		t.Fatalf("provider challenge: %d %s", done.Status, done.Raw)
	}

	// The accessible alternative: a code sent to the verified email.
	tx, cont, _ = login()
	mustStatus(t, h.Step(tx, cont, "challenge", map[string]any{"code": "123456"}), 409, "code before sending")
	mustStatus(t, h.Step(tx, cont, "challenge/send", nil), 200, "send code")
	code := CodeFrom(h.Mail("bob@example.test", "login_code"))
	mustStatus(t, h.Step(tx, cont, "challenge", map[string]any{"code": code, "provider_response": "human"}), 422, "both answers")
	if done := h.Step(tx, cont, "challenge", map[string]any{"code": code}); done.Status != 200 || done.Str("redirect_to") == "" {
		t.Fatalf("emailed-code challenge: %d %s", done.Status, done.Raw)
	}

	// A risk hook reporting high risk denies; the decision is explained.
	f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "risk", "kind": "authentication.risk", "url": risk.URL + "/risk",
		"allow_private_network": true}), 201, "risk hook")
	mu.Lock()
	riskBody = `{"level":"high","reasons":["impossible_travel"]}`
	mu.Unlock()
	if _, _, st := login(); st.Str("error") != "authentication_policy_denied" {
		t.Fatalf("high risk not denied: %s", st.Raw)
	}
	var meta string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE type='authentication.flow.evaluated' ORDER BY seq DESC LIMIT 1`).Scan(&meta)
	if !strings.Contains(meta, `"rule": "high risk"`) && !strings.Contains(meta, `"rule":"high risk"`) || !strings.Contains(meta, "impossible_travel") {
		t.Fatalf("decision not explained: %s", meta)
	}
	// The risk service receives privacy-reviewed input only (ADV-012): IDs,
	// the method, a truncated network, the remembered-device flag and the
	// failure count; no identifiers, credentials or full addresses.
	mu.Lock()
	sent := riskRequest
	mu.Unlock()
	var hookReq struct {
		HookKind       string         `json:"hook_kind"`
		Authentication map[string]any `json:"authentication"`
	}
	if err := json.Unmarshal(sent, &hookReq); err != nil || hookReq.HookKind != "authentication.risk" || hookReq.Authentication["user_id"] == nil {
		t.Fatalf("risk hook request: %s", sent)
	}
	for k := range hookReq.Authentication {
		if !slices.Contains([]string{"user_id", "client_id", "organization_id", "method", "network", "known_device", "failed_attempts"}, k) {
			t.Errorf("risk hook request carries %q: %s", k, sent)
		}
	}
	if n, _ := hookReq.Authentication["network"].(string); n != "" && !strings.HasSuffix(n, "/24") && !strings.HasSuffix(n, "/48") {
		t.Errorf("risk hook request network is not truncated: %q", n)
	}
	if strings.Contains(string(sent), "@") {
		t.Errorf("risk hook request contains an email address: %s", sent)
	}

	// A failing risk hook leaves the signal missing: with on_missing_signal
	// apply the restrictive rule applies, and an allow rule never matches.
	mu.Lock()
	riskStatus, riskBody = 500, `{}`
	mu.Unlock()
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{
			{Name: "low risk passes", When: realm.AuthFlowCondition{RiskAtLeast: "low"}, Outcome: "allow"},
			{Name: "medium risk denied", When: realm.AuthFlowCondition{RiskAtLeast: "medium"}, Outcome: "deny"},
		}
	}), 200, "missing-signal policy")
	if _, _, st := login(); st.Str("error") != "authentication_policy_denied" {
		t.Fatalf("missing risk signal satisfied the policy: %s", st.Raw)
	}
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE type='authentication.flow.evaluated' ORDER BY seq DESC LIMIT 1`).Scan(&meta)
	if !strings.Contains(meta, "risk") || !strings.Contains(meta, "unavailable") {
		t.Fatalf("missing signal not recorded: %s", meta)
	}

	// Review lets the sign-in through and raises a security alert.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "review everything", Outcome: "review"}}
	}), 200, "review policy")
	if _, _, st := login(); st.Status != 200 || st.Str("redirect_to") == "" {
		t.Fatalf("review blocked the sign-in: %s", st.Raw)
	}
	var alerts int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_type='security.alert' AND payload::text LIKE '%authentication_review%'`).Scan(&alerts)
	if alerts == 0 {
		t.Fatal("review raised no security alert")
	}

	// require_mfa: a single-factor account must enroll a second factor.
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
		p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "orders need mfa", When: realm.AuthFlowCondition{Resources: []string{f.OrdersAud}}, Outcome: "require_mfa"}}
	}), 200, "mfa policy")
	if _, _, st := login(); !hasAction(st, "enroll_totp") {
		t.Fatalf("require_mfa did not ask for a factor: %s", st.Raw)
	}
}

// TestRequiredActionPermissions covers AUT-018: adding or removing a forced
// credential change or factor enrollment needs credential authority, every
// change is audited, and completing actions at sign-in is recorded.
func TestRequiredActionPermissions(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "action-setter",
		"permissions": []string{"realm.users.required_actions", "realm.users.read"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	f.EnrollTOTP("carol")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	set := func(tok string, actions ...string) int {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/users/" + f.Users["bob"] + "/required-actions", Token: tok,
			JSON: map[string]any{"actions": actions}}).Status
	}
	if s := set(carol, "accept_terms"); s != 204 {
		t.Fatalf("terms acceptance with the base permission: %d", s)
	}
	if s := set(carol, "accept_terms", "update_password"); s != 403 {
		t.Fatalf("forced password change without credential authority: %d", s)
	}
	if s := set(carol); s != 204 {
		t.Fatalf("removing terms acceptance: %d", s)
	}
	if s := set(f.AdminToken, "update_password"); s != 204 {
		t.Fatalf("administrator: %d", s)
	}
	if s := set(carol); s != 403 {
		t.Fatalf("waiving a forced password change without credential authority: %d", s)
	}
	if r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/user-bulk-operations", Token: carol, JSON: map[string]any{"action": "add_required_action",
		"required_action": "configure_totp", "user_ids": []string{f.Users["bob"]}, "reason": "bulk enrollment"}}); r.Status != 403 {
		t.Fatalf("bulk factor enrollment without credential authority: %d", r.Status)
	}
	// Completing the forced change at sign-in is evidence of its own.
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
		Organization: f.Acme})
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if !hasAction(st, "update_password") {
		t.Fatalf("forced password change not asked: %s", st.Raw)
	}
	if done := h.Step(tx, cont, "password/update", map[string]any{"new_password": "a-completely-new-passphrase-42"}); done.Str("redirect_to") == "" {
		t.Fatalf("sign-in after the forced change: %s", done.Raw)
	}
	var actions string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT metadata->>'actions' FROM audit_events WHERE type='user.required_actions.completed'
		AND subject_id=$1`, f.Users["bob"]).Scan(&actions)
	if !strings.Contains(actions, "update_password") {
		t.Fatalf("completed actions not audited: %q", actions)
	}
}

// TestOperatorMFAFloor covers MFA-005: the operator's floor cannot be lowered
// by realm policy and applies at sign-in to policies saved before it.
func TestOperatorMFAFloor(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Security.MFAFloor.Require = "all" })
	f := fixtureOn(t, h)
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.MFA.Requirement = realm.MFAOptional }), 422, "realm below the floor")
	// The fixture realm was created with optional MFA: sign-in still needs a factor.
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
		Organization: f.Acme})
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if !hasAction(st, "enroll_totp") || st.Str("redirect_to") != "" {
		t.Fatalf("sign-in below the operator floor: %s", st.Raw)
	}
}

// TestVerifiedContactUpdate covers AUT-018: an administrator can require an
// account to re-confirm its already verified address at the next sign-in.
func TestVerifiedContactUpdate(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/required-actions", map[string]any{"actions": []string{"verify_contact"}}), 204, "require")
	verifiedAt := func() time.Time {
		var at time.Time
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT verified_at FROM user_identifiers WHERE user_id=$1 AND type='email'
			AND canonical_value='bob@example.test'`, f.Users["bob"]).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	before := verifiedAt()
	h.Clock.Advance(time.Minute)
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
		Organization: f.Acme})
	tx := start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if !hasAction(st, "verify_contact") || st.Str("redirect_to") != "" {
		t.Fatalf("verify_contact not required: %s", st.Raw)
	}
	mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "verify_contact"}), 200, "send")
	code := CodeFrom(h.Mail("bob@example.test", "email_verification"))
	done := h.Step(tx, cont, "otp/verify", map[string]any{"code": code})
	if done.Status != 200 || done.Str("redirect_to") == "" {
		t.Fatalf("after re-confirmation: %d %s", done.Status, done.Raw)
	}
	u := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "user")
	if strings.Contains(jsonString(u.Get("required_actions")), "verify_contact") {
		t.Fatalf("action not cleared: %s", u.Raw)
	}
	// The re-confirmation is the address's latest proof of control.
	if after := verifiedAt(); !after.After(before) {
		t.Fatalf("verified_at not refreshed by the re-confirmation: %s then %s", before, after)
	}
}
