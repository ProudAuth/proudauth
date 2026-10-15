package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// autWeb drives the web client's browser sign-in: the authorization
// endpoint, then the login UI's calls to the transaction API with the
// transaction cookie, Origin and CSRF token.
type autWeb struct {
	f                   *Fixture
	b                   *browser
	verifier, challenge string
}

func newAutWeb(f *Fixture) *autWeb {
	v, c := PKCE()
	return &autWeb{f: f, b: newBrowser(f.H), verifier: v, challenge: c}
}

func withLoginUI(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" }

// authorize calls the authorization endpoint for web-bff in Acme.
func (w *autWeb) authorize(extra url.Values) *Resp {
	q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
		"state": {"s1"}, "nonce": {"n1"}, "code_challenge": {w.challenge}, "code_challenge_method": {"S256"}, "resource": {w.f.OrdersAud},
		"organization": {w.f.Acme}}
	for k, v := range extra {
		q[k] = v
	}
	return w.b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil)
}

// interaction follows a redirect to the login UI and returns the transaction,
// its current state and the headers its steps need.
func (w *autWeb) interaction(t *testing.T, r *Resp) (string, *Resp, map[string]string) {
	t.Helper()
	loc, _ := url.Parse(r.Header.Get("Location"))
	if r.Status != 302 || loc == nil || loc.Host != "login.test" {
		t.Fatalf("expected the login UI: %d %s", r.Status, r.Header.Get("Location"))
	}
	tx := loc.Query().Get("transaction_id")
	view := w.b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, nil)
	mustStatus(t, view, 200, "view transaction")
	return tx, view, map[string]string{"Origin": w.f.H.Base, "X-CSRF-Token": view.Str("csrf_token")}
}

func (w *autWeb) step(tx, name string, hdr map[string]string, body any) *Resp {
	return w.b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/"+name, body, hdr)
}

// signIn signs a fixture user in with a password at the login UI.
func (w *autWeb) signIn(t *testing.T, r *Resp, user string) *Resp {
	t.Helper()
	tx, _, hdr := w.interaction(t, r)
	w.step(tx, "identify", hdr, map[string]any{"identifier": user + "@example.test"})
	return w.step(tx, "password", hdr, map[string]any{"password": w.f.H.passwords[user+"@example.test"]})
}

// tokens redeems the code in a redirect to the web client.
func (w *autWeb) tokens(t *testing.T, redirect string) *Resp {
	t.Helper()
	u, _ := url.Parse(redirect)
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("no code in %q", redirect)
	}
	tok := w.f.redeem(u.Query().Get("code"), w.verifier, webRedirect)
	mustStatus(t, tok, 200, "token exchange")
	return tok
}

// sessionCookie returns the browser's session handle.
func (w *autWeb) sessionCookie() string {
	for _, c := range w.b.client.Jar.Cookies(mustURL(w.f.H.Base + "/realms/main/")) {
		if c.Name == "pa_sid" {
			return c.Value
		}
	}
	return ""
}

// nextAction returns the next action of a type, or nil.
func nextAction(st *Resp, typ string) map[string]any {
	acts, _ := st.Get("next_actions").([]any)
	for _, a := range acts {
		if m, ok := a.(map[string]any); ok && m["type"] == typ {
			return m
		}
	}
	return nil
}

// TestTransactionCreationValidatesFirst covers AUT-001: the transaction API
// starts a short-lived transaction only after the client, redirect, request
// parameters and client policy validate; a refused request stores no
// transaction and hands out no continuation.
func TestTransactionCreationValidatesFirst(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	count := func() int {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM auth_transactions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	_, challenge := PKCE()
	request := func(mut func(map[string]any)) *Resp {
		b := map[string]any{"client_id": "web-bff", "redirect_uri": webRedirect, "scope": "orders:read", "resource": []string{f.OrdersAud},
			"organization": f.Acme, "code_challenge": challenge, "code_challenge_method": "S256", "state": "s1"}
		if mut != nil {
			mut(b)
		}
		return h.API("POST", "/auth/transactions", "", b)
	}
	refused := func(what string, r *Resp) {
		t.Helper()
		if r.Status != 400 || r.Str("transaction_id") != "" || r.Str("continuation_token") != "" {
			t.Fatalf("%s: transaction started: %d %s", what, r.Status, r.Raw)
		}
	}
	before := count()
	for what, mut := range map[string]func(map[string]any){
		"unknown client":         func(b map[string]any) { b["client_id"] = "no-such-client" },
		"unregistered redirect":  func(b map[string]any) { b["redirect_uri"] = "https://evil.test/callback" },
		"missing PKCE":           func(b map[string]any) { delete(b, "code_challenge"); delete(b, "code_challenge_method") },
		"plain PKCE":             func(b map[string]any) { b["code_challenge_method"] = "plain" },
		"unsupported prompt":     func(b map[string]any) { b["prompt"] = "bogus" },
		"invalid max_age":        func(b map[string]any) { b["max_age"] = "-5" },
		"unknown acr value":      func(b map[string]any) { b["acr_values"] = "urn:example:certified" },
		"unknown organization":   func(b map[string]any) { b["organization"] = "no-such-org" },
		"prompt=none (headless)": func(b map[string]any) { b["prompt"] = "none" },
	} {
		refused(what, request(mut))
	}
	// Client policy: a client that must push its requests cannot start one directly.
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE clients SET token_policy = token_policy || '{"require_par": true}'::jsonb WHERE client_id='web-bff'`); err != nil {
		t.Fatal(err)
	}
	refused("client requires PAR", request(nil))
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE clients SET token_policy = token_policy - 'require_par' WHERE client_id='web-bff'`); err != nil {
		t.Fatal(err)
	}
	if n := count(); n != before {
		t.Fatalf("refused requests stored %d transactions", n-before)
	}
	// A valid request starts exactly one short-lived transaction with its first actions.
	ok := request(nil)
	mustStatus(t, ok, 201, "valid request")
	if ok.Str("transaction_id") == "" || ok.Str("continuation_token") == "" || nextAction(&Resp{Body: ok.Get("state").(map[string]any)}, "identify") == nil {
		t.Fatalf("start: %s", ok.Raw)
	}
	exp, err := time.Parse(time.RFC3339Nano, ok.Str("state.expires_at"))
	if err != nil || exp.Sub(h.Clock.Now()) <= 0 || exp.Sub(h.Clock.Now()) > h.Cfg.Tokens.TransactionTTL+time.Second {
		t.Fatalf("transaction lifetime: expires %s (%v)", ok.Str("state.expires_at"), err)
	}
	if n := count(); n != before+1 {
		t.Fatalf("a valid request stored %d transactions", n-before)
	}
}

// TestStructuredNextActions covers AUT-002: every transaction state lists
// machine-readable next actions (type, required flag, fields to submit,
// options) for identification, password, emailed code, TOTP, organization
// choice and consent.
func TestStructuredNextActions(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.EnrollTOTP("bob")
	action := func(st *Resp, typ string) map[string]any {
		t.Helper()
		acts, _ := st.Get("next_actions").([]any)
		for _, a := range acts {
			m, _ := a.(map[string]any)
			if _, ok := m["required"].(bool); !ok || m["type"] == nil {
				t.Fatalf("action without a type or required flag: %v", a)
			}
		}
		a := nextAction(st, typ)
		if a == nil {
			t.Fatalf("no %s action: %d %s", typ, st.Status, st.Raw)
		}
		return a
	}
	fields := func(a map[string]any) string {
		out := []string{}
		for _, x := range a["fields"].([]any) {
			out = append(out, x.(string))
		}
		return strings.Join(out, ",")
	}
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}})
	mustStatus(t, start, 201, "start")
	tx := start.Str("transaction_id")
	if a := action(&Resp{Body: start.Get("state").(map[string]any)}, "identify"); a["required"] != true || fields(a) != "identifier" {
		t.Fatalf("identify action: %v", a)
	}
	st := h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	if a := action(st, "password"); fields(a) != "password" {
		t.Fatalf("password action: %v", a)
	}
	if a := action(st, "email_otp"); fields(a) != "code" || a["options"].(map[string]any)["send_required"] != true {
		t.Fatalf("email code action: %v", a)
	}
	st = h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	if a := action(st, "totp"); fields(a) != "code" || st.Str("status") != "pending" {
		t.Fatalf("TOTP action: %s", st.Raw)
	}
	st = h.Step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("bob@example.test")})
	a := action(st, "select_organization")
	ids := map[string]bool{}
	for _, o := range a["options"].(map[string]any)["organizations"].([]any) {
		ids[o.(map[string]any)["organization_id"].(string)] = true
	}
	if a["required"] != true || len(ids) != 2 || !ids[f.Acme] || !ids[f.Globex] {
		t.Fatalf("organization choice: %v", a)
	}
	done := h.Step(tx, cont, "organization", map[string]any{"organization_id": f.Acme})
	if done.Str("redirect_to") == "" || done.Str("status") != "completed" || len(done.Get("next_actions").([]any)) != 0 {
		t.Fatalf("completion: %s", done.Raw)
	}
	// Consent names the scopes to approve.
	start, _, cont = h.StartTx(LoginOpts{ClientID: "partner-app", RedirectURI: "https://partner.test/cb", Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, Prompt: "consent"})
	mustStatus(t, start, 201, "start partner")
	tx = start.Str("transaction_id")
	h.Step(tx, cont, "identify", map[string]any{"identifier": "alice@example.test"})
	st = h.Step(tx, cont, "password", map[string]any{"password": h.passwords["alice@example.test"]})
	a = action(st, "consent")
	scopes, _ := a["options"].(map[string]any)["scopes"].([]any)
	if a["required"] != true || fields(a) != "approve,scopes" || len(scopes) != 1 || scopes[0].(map[string]any)["name"] != "orders:read" {
		t.Fatalf("consent action: %v", a)
	}
}

// TestNoIssuanceWhileRequirementsRemain covers AUT-006: a transaction issues
// no authorization code while email verification, a second factor, terms
// acceptance or an account-state check is outstanding, whichever step the
// client submits instead, and completes once every requirement is met.
func TestNoIssuanceWhileRequirementsRemain(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	codes := func(tx string) int {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_codes WHERE transaction_id=$1`, tx).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	noGrant := func(what, tx string, st *Resp) {
		t.Helper()
		if st.Str("redirect_to") != "" || codes(tx) != 0 {
			t.Fatalf("%s: issued before the requirements were met: %d %s", what, st.Status, st.Raw)
		}
	}
	// Steps a client might submit to skip ahead.
	skip := func(tx, cont string) {
		t.Helper()
		noGrant("consent", tx, h.Step(tx, cont, "consent", map[string]any{"approve": true}))
		noGrant("organization", tx, h.Step(tx, cont, "organization", map[string]any{"organization_id": f.Acme}))
		noGrant("resume", tx, h.Step(tx, cont, "resume", nil))
	}
	signIn := func(user string) (string, string, *Resp) {
		t.Helper()
		start, _, cont := h.StartTx(acct)
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": user})
		return tx, cont, h.Step(tx, cont, "password", map[string]any{"password": h.passwords[user]})
	}
	completed := func(what, tx string, st *Resp) {
		t.Helper()
		if st.Str("redirect_to") == "" || codes(tx) != 1 {
			t.Fatalf("%s: not completed once met: %d %s", what, st.Status, st.Raw)
		}
	}

	t.Run("email verification", func(t *testing.T) {
		start, _, cont := h.StartTx(acct)
		tx := start.Str("transaction_id")
		reg := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": tx,
			"email": "nina@example.test", "password": "a brand new passphrase 2026"}, Headers: map[string]string{"X-Transaction-Token": cont}})
		mustStatus(t, reg, 201, "register")
		if !hasAction(reg, "verify_email") {
			t.Fatalf("verification not required: %s", reg.Raw)
		}
		noGrant("registration", tx, reg)
		skip(tx, cont)
		done := h.Step(tx, cont, "otp/verify", map[string]any{"code": CodeFrom(h.Mail("nina@example.test", "email_verification"))})
		completed("verified", tx, h.Drive(tx, cont, done, LoginOpts{Identifier: "nina@example.test"}))
	})
	t.Run("second factor", func(t *testing.T) {
		f.EnrollTOTP("alice")
		tx, cont, st := signIn("alice@example.test")
		if !hasAction(st, "totp") {
			t.Fatalf("second factor not required: %s", st.Raw)
		}
		noGrant("password", tx, st)
		skip(tx, cont)
		completed("second factor", tx, h.Step(tx, cont, "totp", map[string]any{"code": h.TOTPNow("alice@example.test")}))
	})
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.Registration.TermsVersion = "2026-10" }), 200, "terms version")
	t.Run("terms acceptance", func(t *testing.T) {
		tx, cont, st := signIn("bob@example.test")
		if !hasAction(st, "accept_terms") {
			t.Fatalf("terms not required: %s", st.Raw)
		}
		noGrant("password", tx, st)
		skip(tx, cont)
		mustStatus(t, h.Step(tx, cont, "terms", map[string]any{"version": "2025-01"}), 422, "outdated terms version")
		completed("terms", tx, h.Step(tx, cont, "terms", map[string]any{"version": "2026-10"}))
	})
	t.Run("account state", func(t *testing.T) {
		tx, cont, st := signIn("carol@example.test")
		if !hasAction(st, "accept_terms") {
			t.Fatalf("terms not required: %s", st.Raw)
		}
		// The account is suspended before the last step.
		mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend")
		noGrant("terms after suspension", tx, h.Step(tx, cont, "terms", map[string]any{"version": "2026-10"}))
		skip(tx, cont)
	})
}

// TestSessionHandleRotation covers AUT-007: the browser session handle is
// minted by the server when authentication succeeds (a planted handle is
// never adopted), the pre-authentication transaction handle ends with the
// transaction, and a step-up that adds a factor to the session rotates the
// session's handle so the earlier one stops working.
func TestSessionHandleRotation(t *testing.T) {
	f := NewFixture(t, withLoginUI)
	h := f.H
	ctx := context.Background()
	w := newAutWeb(f)
	realmURL := mustURL(h.Base + "/realms/main/")
	planted := secret.PrefixSession + strings.Repeat("A", 43)
	w.b.client.Jar.SetCookies(realmURL, []*http.Cookie{{Name: "pa_sid", Value: planted, Path: "/realms/main/"}})
	sessionOf := func(cookie string) string {
		var id string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM sessions WHERE cookie_digest=$1 AND state='active'`, secret.Digest(cookie)).Scan(&id)
		return id
	}

	tx, _, hdr := w.interaction(t, w.authorize(nil))
	w.step(tx, "identify", hdr, map[string]any{"identifier": "alice@example.test"})
	done := w.step(tx, "password", hdr, map[string]any{"password": h.passwords["alice@example.test"]})
	w.tokens(t, done.Str("redirect_to"))
	first := w.sessionCookie()
	if first == "" || first == planted || sessionOf(first) == "" {
		t.Fatalf("sign-in kept or did not replace the planted handle: %q", first)
	}
	// The pre-authentication handle is spent with its transaction.
	if again := w.step(tx, "identify", hdr, map[string]any{"identifier": "alice@example.test"}); again.Status < 400 {
		t.Fatalf("completed transaction handle still usable: %d %s", again.Status, again.Raw)
	}

	// Step-up: MFA is requested and alice enrolls TOTP in the transaction,
	// which adds the factor to her existing session.
	sess := sessionOf(first)
	h.Clock.Advance(time.Minute)
	tx, view, hdr := w.interaction(t, w.authorize(url.Values{"acr_values": {"urn:proudauth:acr:mfa"}, "state": {"s2"}}))
	if nextAction(view, "enroll_totp") == nil {
		t.Fatalf("step-up not requested: %s", view.Raw)
	}
	en := w.step(tx, "totp/enroll", hdr, nil)
	mustStatus(t, en, 200, "enroll TOTP")
	h.seeds["alice@example.test"] = en.Str("one_time.totp.secret")
	up := w.step(tx, "totp/activate", hdr, map[string]any{"code": h.TOTPNow("alice@example.test")})
	if !strings.Contains(up.Str("redirect_to"), "state=s2") {
		t.Fatalf("step-up: %d %s", up.Status, up.Raw)
	}
	second := w.sessionCookie()
	if second == "" || second == first {
		t.Fatal("the session handle was not rotated on step-up")
	}
	if got := sessionOf(second); got != sess {
		t.Fatalf("step-up should rotate the handle of the same session: %q, want %q", got, sess)
	}
	if sessionOf(first) != "" {
		t.Fatal("the pre-step-up handle still resolves to the session")
	}
	old := newBrowser(h)
	old.client.Jar.SetCookies(realmURL, []*http.Cookie{{Name: "pa_sid", Value: first, Path: "/realms/main/"}})
	silent := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"openid orders:read"},
		"state": {"s3"}, "code_challenge": {w.challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme},
		"prompt": {"none"}}
	if loc, _ := url.Parse(old.do("GET", "/realms/main/oauth/authorize?"+silent.Encode(), nil, nil).Header.Get("Location")); loc.Query().Get("error") != "login_required" {
		t.Fatalf("the old handle still signs in: %s", loc)
	}
	if loc, _ := url.Parse(w.authorize(url.Values{"prompt": {"none"}}).Header.Get("Location")); loc.Query().Get("code") == "" {
		t.Fatalf("the rotated handle does not sign in: %s", loc)
	}
}

// TestTransactionRestartAndExpiry covers AUT-008: expired, cancelled,
// completed and failure-invalidated transactions cannot be resumed by any
// step, each ends with an explicit outcome, and restarting means starting a
// new transaction.
func TestTransactionRestartAndExpiry(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	begin := func() (string, string) {
		t.Helper()
		start, _, cont := h.StartTx(cli)
		mustStatus(t, start, 201, "start")
		return start.Str("transaction_id"), cont
	}
	view := func(tx, cont string) *Resp {
		return h.Do(Req{Method: "GET", Path: "/api/v1/realms/main/auth/transactions/" + tx, Headers: map[string]string{"X-Transaction-Token": cont}})
	}
	dead := func(what, tx, cont string) {
		t.Helper()
		for step, body := range map[string]any{"identify": map[string]any{"identifier": "alice@example.test"},
			"password": map[string]any{"password": h.passwords["alice@example.test"]}, "consent": map[string]any{"approve": true}} {
			if r := h.Step(tx, cont, step, body); r.Status != 400 || r.Str("code") != "transaction_invalid" || r.Str("redirect_to") != "" {
				t.Fatalf("%s transaction resumed by %s: %d %s", what, step, r.Status, r.Raw)
			}
		}
	}

	t.Run("expired", func(t *testing.T) {
		tx, cont := begin()
		mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": "alice@example.test"}), 200, "identify")
		h.Clock.Advance(h.Cfg.Tokens.TransactionTTL + time.Second)
		if r := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["alice@example.test"]}); r.Status != 410 || r.Str("code") != "transaction_expired" {
			t.Fatalf("expired transaction resumed: %d %s", r.Status, r.Raw)
		}
		if r := view(tx, cont); r.Status != 410 {
			t.Fatalf("expired transaction viewable as live: %d %s", r.Status, r.Raw)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		tx, cont := begin()
		c := h.Step(tx, cont, "cancel", nil)
		if c.Str("status") != "cancelled" || !strings.HasPrefix(c.Str("redirect_to"), "http://127.0.0.1/callback?") ||
			!strings.Contains(c.Str("redirect_to"), "error=access_denied") {
			t.Fatalf("cancellation outcome: %s", c.Raw)
		}
		dead("cancelled", tx, cont)
	})
	t.Run("completed", func(t *testing.T) {
		tx, cont := begin()
		st := h.Drive(tx, cont, view(tx, cont), LoginOpts{Identifier: "alice@example.test"})
		if st.Str("redirect_to") == "" {
			t.Fatalf("sign-in: %s", st.Raw)
		}
		dead("completed", tx, cont)
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM authorization_codes WHERE transaction_id=$1`, tx).Scan(&n)
		if n != 1 {
			t.Fatalf("%d codes for one transaction", n)
		}
	})
	t.Run("too many failures", func(t *testing.T) {
		tx, cont := begin()
		h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		for i := 0; i < 5; i++ {
			if r := h.Step(tx, cont, "password", map[string]any{"password": "not bob's passphrase 2026"}); r.Status != 401 {
				t.Fatalf("failure %d: %d %s", i, r.Status, r.Raw)
			}
		}
		if v := view(tx, cont); v.Str("status") != "failed" || v.Str("error") != "too_many_failures" {
			t.Fatalf("failure-invalidated transaction: %s", v.Raw)
		}
		if r := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}); r.Status != 400 || r.Str("redirect_to") != "" {
			t.Fatalf("right password resumed a failed transaction: %d %s", r.Status, r.Raw)
		}
	})
	// Restarting is an explicit new transaction.
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "bob@example.test"})
	if lr.Tokens.Str("access_token") == "" {
		t.Fatal("a new transaction could not sign in")
	}
}

// TestIdentifierFirstDiscovery covers AUT-009: identifying an account routes
// it by verified email domain without revealing whether the account exists
// or which organizations it belongs to; the account's organizations appear
// only after it authenticates.
func TestIdentifierFirstDiscovery(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	web := LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}}
	identify := func(who string) (string, string, string, *Resp) {
		t.Helper()
		start, verifier, cont := h.StartTx(web)
		mustStatus(t, start, 201, "start")
		tx := start.Str("transaction_id")
		st := h.Step(tx, cont, "identify", map[string]any{"identifier": who})
		mustStatus(t, st, 200, "identify "+who)
		return tx, cont, verifier, st
	}
	sameAnswer := func(known, unknown *Resp) {
		t.Helper()
		for _, k := range []string{"status", "next_actions", "user", "error", "notice", "completed_factors"} {
			if jsonString(known.Get(k)) != jsonString(unknown.Get(k)) {
				t.Fatalf("identify differs for an existing account (%s): %s vs %s", k, known.Raw, unknown.Raw)
			}
		}
		for _, leak := range []string{f.Acme, f.Globex, "Acme", "Globex", f.Users["bob"]} {
			if strings.Contains(string(known.Raw), leak) {
				t.Fatalf("identify disclosed %q: %s", leak, known.Raw)
			}
		}
	}
	_, _, _, known := identify("bob@example.test")
	_, _, _, unknown := identify("nobody@example.test")
	sameAnswer(known, unknown)
	tx, cont, _, _ := identify("bob@example.test")
	if st := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]}); nextAction(st, "select_organization") == nil {
		t.Fatalf("organization choice after authentication: %s", st.Raw)
	}

	// Globex verifies the domain: its addresses are routed to Globex.
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	ch := f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/domains", map[string]any{"domain": "example.test"}), 201, "add domain")
	organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify domain")
	_, _, _, known = identify("bob@example.test")
	_, _, _, unknown = identify("nobody@example.test")
	sameAnswer(known, unknown)
	tx, cont, verifier, _ := identify("bob@example.test")
	done := h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	u, _ := url.Parse(done.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("the routed sign-in did not bind the domain's organization: %s", done.Raw)
	}
	tok := f.redeem(u.Query().Get("code"), verifier, webRedirect)
	mustStatus(t, tok, 200, "token")
	if org := jwtPayload(tok.Str("access_token"))["org_id"]; org != f.Globex {
		t.Fatalf("routed organization: %v", org)
	}
}

// TestAccountSelectionKeepsSubject covers AUT-011: with an SSO session,
// prompt=select_account lets the person continue as the signed-in account or
// switch, and the code always belongs to the account that was chosen and
// authenticated; organization choices list only the account's own
// organizations and bind the chosen one into the token.
func TestAccountSelectionKeepsSubject(t *testing.T) {
	f := NewFixture(t, withLoginUI)
	h := f.H
	w := newAutWeb(f)
	w.tokens(t, w.signIn(t, w.authorize(nil), "alice").Str("redirect_to"))
	subject := func(tok *Resp) any { return jwtPayload(tok.Str("access_token"))["sub"] }

	// Continue as the signed-in account.
	tx, view, hdr := w.interaction(t, w.authorize(url.Values{"prompt": {"select_account"}, "state": {"keep"}}))
	sel := nextAction(view, "select_account")
	if sel == nil {
		t.Fatalf("no account choice: %s", view.Raw)
	}
	if hint, _ := sel["options"].(map[string]any)["current_account"].(map[string]any)["email_hint"].(string); hint == "" || hint == "alice@example.test" {
		t.Fatalf("current account must be shown masked: %q", hint)
	}
	kept := w.step(tx, "account", hdr, map[string]any{"continue": true})
	if !strings.Contains(kept.Str("redirect_to"), "state=keep") {
		t.Fatalf("continue: %s", kept.Raw)
	}
	if sub := subject(w.tokens(t, kept.Str("redirect_to"))); sub != f.Users["alice"] {
		t.Fatalf("continuing issued a code for %v", sub)
	}

	// Switch: the session's identity is dropped; the code is for whoever signs in.
	tx, _, hdr = w.interaction(t, w.authorize(url.Values{"prompt": {"select_account"}, "state": {"switch"}}))
	sw := w.step(tx, "account", hdr, map[string]any{"continue": false})
	if nextAction(sw, "identify") == nil || sw.Str("redirect_to") != "" || sw.Get("user") != nil || len(sw.Get("completed_factors").([]any)) != 0 {
		t.Fatalf("switching kept the signed-in identity: %s", sw.Raw)
	}
	w.step(tx, "identify", hdr, map[string]any{"identifier": "bob@example.test"})
	done := w.step(tx, "password", hdr, map[string]any{"password": h.passwords["bob@example.test"]})
	if !strings.Contains(done.Str("redirect_to"), "state=switch") {
		t.Fatalf("switch: %s", done.Raw)
	}
	if sub := subject(w.tokens(t, done.Str("redirect_to"))); sub != f.Users["bob"] {
		t.Fatalf("switching issued a code for %v", sub)
	}

	// Organization choice: only the account's own organizations, bound into the token.
	other := f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "initech", "display_name": "Initech"}), 201, "org without bob").Str("id")
	start, verifier, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud}})
	htx := start.Str("transaction_id")
	h.Step(htx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
	st := h.Step(htx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	orgs := nextAction(st, "select_organization")
	if orgs == nil {
		t.Fatalf("no organization choice: %s", st.Raw)
	}
	listed := map[string]bool{}
	for _, o := range orgs["options"].(map[string]any)["organizations"].([]any) {
		listed[o.(map[string]any)["organization_id"].(string)] = true
	}
	if len(listed) != 2 || !listed[f.Acme] || !listed[f.Globex] {
		t.Fatalf("organization options: %v", listed)
	}
	mustStatus(t, h.Step(htx, cont, "organization", map[string]any{"organization_id": other}), 403, "organization without membership")
	chosen := h.Step(htx, cont, "organization", map[string]any{"organization_id": f.Globex})
	u, _ := url.Parse(chosen.Str("redirect_to"))
	if u == nil || u.Query().Get("code") == "" {
		t.Fatalf("organization choice: %s", chosen.Raw)
	}
	tok := f.redeem(u.Query().Get("code"), verifier, webRedirect)
	mustStatus(t, tok, 200, "token")
	if claims := jwtPayload(tok.Str("access_token")); claims["sub"] != f.Users["bob"] || claims["org_id"] != f.Globex {
		t.Fatalf("token after organization choice: sub=%v org=%v", claims["sub"], claims["org_id"])
	}
}

// TestReauthenticationSemantics covers AUT-017: an SSO session never
// satisfies a client's request for fresh authentication (prompt=login,
// max_age), and reusing or refreshing a session keeps the genuine
// authentication time rather than minting a new one.
func TestReauthenticationSemantics(t *testing.T) {
	f := NewFixture(t, withLoginUI)
	h := f.H
	w := newAutWeb(f)
	first := w.tokens(t, w.signIn(t, w.authorize(nil), "alice").Str("redirect_to"))
	authTime, _ := jwtPayload(first.Str("id_token"))["auth_time"].(float64)
	if authTime == 0 {
		t.Fatalf("no auth_time: %v", jwtPayload(first.Str("id_token")))
	}
	h.Clock.Advance(2 * time.Minute)

	// Silent reuse of the session keeps the original authentication time.
	r := w.authorize(url.Values{"prompt": {"none"}, "state": {"silent"}})
	reused := w.tokens(t, r.Header.Get("Location"))
	if at := jwtPayload(reused.Str("id_token"))["auth_time"]; at != authTime {
		t.Fatalf("session reuse changed auth_time: %v, want %v", at, authTime)
	}
	// So does refreshing.
	ref := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, ref, 200, "refresh")
	if at := jwtPayload(ref.Str("id_token"))["auth_time"]; at != authTime {
		t.Fatalf("refresh changed the ID token's auth_time: %v, want %v", at, authTime)
	}
	if at := jwtPayload(ref.Str("access_token"))["auth_time"]; at != authTime {
		t.Fatalf("refresh changed the access token's auth_time: %v, want %v", at, authTime)
	}

	// A request for fresh authentication is not satisfied by the session.
	for what, extra := range map[string]url.Values{"prompt=login": {"prompt": {"login"}}, "max_age": {"max_age": {"60"}}} {
		if loc, _ := url.Parse(w.authorize(extra).Header.Get("Location")); loc.Host != "login.test" {
			t.Fatalf("%s completed from the session: %s", what, loc)
		}
	}
	if loc, _ := url.Parse(w.authorize(url.Values{"prompt": {"none"}, "max_age": {"60"}}).Header.Get("Location")); loc.Query().Get("error") != "login_required" {
		t.Fatalf("max_age with prompt=none: %s", loc)
	}
	// Authenticating again records the new, genuine time.
	fresh := w.tokens(t, w.signIn(t, w.authorize(url.Values{"max_age": {"60"}}), "alice").Str("redirect_to"))
	if at, _ := jwtPayload(fresh.Str("id_token"))["auth_time"].(float64); at < authTime+120 {
		t.Fatalf("fresh authentication time %v not after %v", at, authTime)
	}
}

// TestOTPVerifierStorage covers PWDLESS-007: a sign-in code is stored only as
// a keyed verifier bound to its challenge, never as the code or an unkeyed
// digest of it, and the challenge's online attempt budget burns it so even
// the right code fails after too many guesses.
func TestOTPVerifierStorage(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Security.OTPMaxAttempts = 3 })
	fixtureOn(t, h)
	ctx := context.Background()
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	tx := start.Str("transaction_id")
	mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": "alice@example.test"}), 200, "identify")
	send := func() string {
		t.Helper()
		h.Clock.Advance(2 * time.Second) // past the send cooldown
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send code")
		return CodeFrom(h.Mail("alice@example.test", "login_code"))
	}
	code := send()
	var id, purpose, stored string
	var version, maxAttempts int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id, purpose, verifier, key_version, max_attempts FROM challenges WHERE transaction_id=$1
		AND consumed_at IS NULL AND superseded_at IS NULL`, tx).Scan(&id, &purpose, &stored, &version, &maxAttempts); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(code))
	for _, unkeyed := range []string{code, hex.EncodeToString(sum[:]), base64.RawURLEncoding.EncodeToString(sum[:]), base64.StdEncoding.EncodeToString(sum[:])} {
		if strings.Contains(stored, unkeyed) {
			t.Fatalf("stored verifier %q contains the code or its unkeyed digest", stored)
		}
	}
	if !h.App.D.Keys.VerifyMAC(keys.PurposeOTP, version, stored, "challenge", id, purpose, code) {
		t.Fatal("the stored verifier is not the keyed MAC of the code")
	}
	if keys.NewRandom().VerifyMAC(keys.PurposeOTP, version, stored, "challenge", id, purpose, code) {
		t.Fatal("the verifier can be reproduced without the server's key")
	}
	if h.App.D.Keys.VerifyMAC(keys.PurposeOTP, version, stored, "challenge", "chl_other", purpose, code) {
		t.Fatal("the verifier is not bound to its challenge")
	}

	// Online guessing: the challenge allows max_attempts tries in all.
	if maxAttempts != 3 {
		t.Fatalf("max_attempts %d, want the configured 3", maxAttempts)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < maxAttempts; i++ {
		if r := h.Step(tx, cont, "otp/verify", map[string]any{"code": wrong}); r.Status == 200 {
			t.Fatalf("wrong code accepted: %s", r.Raw)
		}
	}
	if r := h.Step(tx, cont, "otp/verify", map[string]any{"code": code}); r.Status == 200 || r.Str("redirect_to") != "" {
		t.Fatalf("the right code was accepted after the attempt budget was spent: %s", r.Raw)
	}
	var attempts int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT attempts FROM challenges WHERE id=$1`, id).Scan(&attempts)
	if attempts != maxAttempts {
		t.Fatalf("attempts %d, want %d", attempts, maxAttempts)
	}
	// A new code is a new challenge with its own budget: no permanent lockout.
	if done := h.Step(tx, cont, "otp/verify", map[string]any{"code": send()}); done.Str("redirect_to") == "" {
		t.Fatalf("a fresh code did not sign in: %d %s", done.Status, done.Raw)
	}
}
