// Package e2e runs the identity provider in-process against PostgreSQL and drives it
// through its public HTTP contracts, the way independent applications would (§33.1).
package e2e

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/proudauth/proudauth/internal/worker"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/httpapi"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/server"
	"github.com/proudauth/proudauth/internal/testutil"
)

// Harness is a running identity provider.
type Harness struct {
	t         testing.TB
	App       *httpapi.App
	Srv       *httptest.Server
	Base      string
	Clock     *clock.Fake
	Realm     *realm.Realm
	Cfg       *configuration.Config
	HTTP      *http.Client
	seeds     map[string]string // username -> TOTP seed
	passwords map[string]string
}

// Option mutates configuration before the server starts.
type Option func(*configuration.Config)

// NewHarness starts a fresh database and server.
func NewHarness(t testing.TB, opts ...Option) *Harness {
	t.Helper()
	return newHarnessWithKeyring(t, keys.NewRandom(), opts...)
}

func newHarnessWithKeyring(t testing.TB, keyring *keys.Keyring, opts ...Option) *Harness {
	t.Helper()
	db := testutil.NewDB(t)
	srv := httptest.NewUnstartedServer(nil)
	cfg := configuration.Defaults()
	cfg.Mode = configuration.ModeDevelopment
	cfg.Server.PublicOrigin = "http://" + srv.Listener.Addr().String()
	cfg.Storage.DatabaseURL = "test"
	cfg.Keys.RootKeys = []configuration.KeyRef{{Version: 1, Ref: "test"}}
	cfg.Delivery.Email.Adapter = "dev_sink"
	cfg.Security.Password.ArgonMemoryKiB = 8 * 1024
	cfg.Security.Password.ArgonTime = 1
	cfg.Security.MinAuthResponse = 0
	cfg.Sessions.CookieInsecureDev = true
	cfg.Impersonation.Enabled = true
	cfg.Security.RateLimits.TokenPerClient = 10000
	cfg.Security.RateLimits.LoginPerIP = 10000
	cfg.Security.RateLimits.StartPerNetwork = 10000
	// Every test request comes from the loopback address: one network.
	cfg.Security.RateLimits.TokenFailuresPerNetwork = 10000
	cfg.Security.RateLimits.PARFailuresPerNetwork = 10000
	cfg.Security.RateLimits.DevicePerNetwork = 10000
	cfg.Security.RateLimits.SendPerIP = 10000
	cfg.Security.RateLimits.SignupPerIP = 10000
	cfg.Security.RateLimits.SendCooldown = time.Second
	cfg.Security.RateLimits.SendPerIdentifier = 50
	for _, o := range opts {
		o(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	clk := clock.NewFake(time.Now())
	log := observability.NewLogger(io.Discard, "error", "json")
	if v := os.Getenv("PROUDAUTH_TEST_LOG"); v != "" {
		level := slog.LevelWarn
		if v == "debug" {
			level = slog.LevelDebug
		}
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level, ReplaceAttr: observability.Redact}))
	}
	deps := runtime.New(db, &cfg, clk, keyring, log)
	app, err := httpapi.Build(deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.KeyMgr.RSABits = 2048
	server.RegisterModules(app)
	srv.Config.Handler = app.Handler()
	srv.Start()
	t.Cleanup(srv.Close)
	h := &Harness{t: t, App: app, Srv: srv, Base: srv.URL, Clock: clk, Cfg: &cfg, seeds: map[string]string{}, passwords: map[string]string{},
		HTTP: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 30 * time.Second}}
	return h
}

// CreateRealm provisions the realm named "main" with a policy.
func (h *Harness) CreateRealm(mutate func(*realm.Policy)) *realm.Realm {
	h.t.Helper()
	p := realm.DefaultPolicy()
	p.Impersonation.Enabled = true
	if mutate != nil {
		mutate(&p)
	}
	r, err := h.App.Provision.CreateRealm(context.Background(), "main", "Main", p, audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		h.t.Fatalf("create realm: %v", err)
	}
	h.Realm = r
	return r
}

// Resp is a decoded HTTP response.
type Resp struct {
	Status int
	Body   map[string]any
	Raw    []byte
	Header http.Header
}

// Str returns a string field (dotted path).
func (r *Resp) Str(path string) string {
	v := r.Get(path)
	s, _ := v.(string)
	return s
}

// Get returns a field by dotted path.
func (r *Resp) Get(path string) any {
	var cur any = r.Body
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// Req is an HTTP request description.
type Req struct {
	Method  string
	Path    string
	Token   string
	JSON    any
	Form    url.Values
	Headers map[string]string
	Basic   [2]string
	RawBody []byte // sent verbatim (signature tests)
}

// Do performs a request against the server.
func (h *Harness) Do(rq Req) *Resp {
	h.t.Helper()
	var body io.Reader
	ct := ""
	if rq.JSON != nil {
		b, _ := json.Marshal(rq.JSON)
		body = bytes.NewReader(b)
		ct = "application/json"
	} else if rq.Form != nil {
		body = strings.NewReader(rq.Form.Encode())
		ct = "application/x-www-form-urlencoded"
	} else if rq.RawBody != nil {
		body = bytes.NewReader(rq.RawBody)
		ct = "application/json"
	}
	u := rq.Path
	if !strings.HasPrefix(u, "http") {
		u = h.Base + rq.Path
	}
	req, err := http.NewRequest(rq.Method, u, body)
	if err != nil {
		h.t.Fatal(err)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if rq.Token != "" {
		req.Header.Set("Authorization", "Bearer "+rq.Token)
	}
	if rq.Basic[0] != "" {
		req.SetBasicAuth(url.QueryEscape(rq.Basic[0]), url.QueryEscape(rq.Basic[1]))
	}
	for k, v := range rq.Headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v // the virtual host, e.g. a custom domain
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := h.HTTP.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := &Resp{Status: res.StatusCode, Raw: raw, Header: res.Header}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

// API calls a realm API path relative to /api/v1/realms/main.
func (h *Harness) API(method, path, token string, body any) *Resp {
	h.t.Helper()
	return h.Do(Req{Method: method, Path: "/api/v1/realms/main" + path, Token: token, JSON: body})
}

// Deliver runs notification delivery and returns the latest code-like token sent
// to a recipient for a template.
func (h *Harness) Deliver() {
	h.t.Helper()
	if _, err := h.App.Notify.DeliverDue(context.Background(), "test", 100, time.Minute); err != nil {
		h.t.Fatal(err)
	}
}

// Mail returns the newest dev-sink message body for a recipient and template.
func (h *Harness) Mail(recipient, template string) string {
	h.t.Helper()
	h.Deliver()
	var body string
	err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT body_text FROM dev_mailbox WHERE realm_id=$1 AND lower(recipient)=lower($2)
		AND template=$3 ORDER BY created_at DESC, id DESC LIMIT 1`, h.Realm.ID, recipient, template).Scan(&body)
	if err != nil {
		return ""
	}
	return body
}

// CodeFrom extracts a 6-digit code or pa_ token from a message body.
func CodeFrom(body string) string {
	for _, f := range strings.FieldsFunc(body, func(r rune) bool { return r == ' ' || r == '\n' || r == ':' || r == '.' && false }) {
		f = strings.Trim(f, ".,")
		if len(f) == 6 && strings.Trim(f, "0123456789") == "" {
			return f
		}
		if strings.HasPrefix(f, "pa_") {
			return f
		}
	}
	return ""
}

// PKCE returns a verifier and S256 challenge.
func PKCE() (string, string) {
	v := base64.RawURLEncoding.EncodeToString(secret.Random(32))
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

// TOTPNow returns the current TOTP code for a user, advancing the clock one step
// first so codes are never replayed within a step.
func (h *Harness) TOTPNow(user string) string {
	h.t.Helper()
	seed := h.seeds[user]
	if seed == "" {
		h.t.Fatalf("no TOTP seed for %s", user)
	}
	h.Clock.Advance(31 * time.Second)
	code, err := credential.TOTPCode(seed, credential.TOTPStep(h.Clock.Now()))
	if err != nil {
		h.t.Fatal(err)
	}
	return code
}

// LoginOpts configures a login.
type LoginOpts struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scope        string
	Resources    []string
	Organization string
	SelectOrg    string
	Identifier   string
	Password     string
	Prompt       string
	MaxAge       string
	ACR          string
	ExpectFail   bool
	UseRecovery  string
	// HOTPCode answers an hotp step (MFA-013).
	HOTPCode string
	// ResponseMode requests a response mode (ADV-002 JARM).
	ResponseMode string
	Nonce        string
	Claims       string
}

// LoginResult is the outcome of a full login.
type LoginResult struct {
	Tokens       *Resp
	Code         string
	Verifier     string
	State        *Resp
	TxID         string
	Continuation string
}

// StartTx starts a headless transaction.
func (h *Harness) StartTx(o LoginOpts) (*Resp, string, string) {
	h.t.Helper()
	verifier, challenge := PKCE()
	if o.RedirectURI == "" {
		o.RedirectURI = "http://127.0.0.1/callback"
	}
	res := h.API("POST", "/auth/transactions", "", map[string]any{"client_id": o.ClientID, "redirect_uri": o.RedirectURI,
		"scope": o.Scope, "state": "st-" + secret.Numeric(6), "nonce": o.Nonce, "code_challenge": challenge, "code_challenge_method": "S256",
		"resource": o.Resources, "organization": o.Organization, "prompt": o.Prompt, "max_age": o.MaxAge, "acr_values": o.ACR, "claims": o.Claims, "response_mode": o.ResponseMode})
	return res, verifier, res.Str("continuation_token")
}

// Step posts a transaction step.
func (h *Harness) Step(txID, cont, step string, body any) *Resp {
	h.t.Helper()
	if body == nil {
		body = map[string]any{}
	}
	return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + txID + "/" + step, JSON: body,
		Headers: map[string]string{"X-Transaction-Token": cont}})
}

// Drive completes the transaction's next actions with known credentials.
func (h *Harness) Drive(txID, cont string, st *Resp, o LoginOpts) *Resp {
	h.t.Helper()
	for i := 0; i < 20; i++ {
		if st.Status >= 400 {
			return st
		}
		if s := st.Str("status"); s != "pending" {
			return st
		}
		actions, _ := st.Get("next_actions").([]any)
		if len(actions) == 0 {
			return st
		}
		types := []string{}
		for _, a := range actions {
			types = append(types, a.(map[string]any)["type"].(string))
		}
		has := func(t string) bool {
			for _, x := range types {
				if x == t {
					return true
				}
			}
			return false
		}
		switch {
		case has("identify"):
			st = h.Step(txID, cont, "identify", map[string]any{"identifier": o.Identifier})
		case has("password"):
			pw := o.Password
			if pw == "" {
				pw = h.passwords[o.Identifier]
			}
			st = h.Step(txID, cont, "password", map[string]any{"password": pw})
		case has("verify_email"):
			if r := h.Step(txID, cont, "otp/send", map[string]any{"purpose": "verify_email"}); r.Status != 200 {
				return r
			}
			email := h.emailOf(o.Identifier)
			code := CodeFrom(h.Mail(email, "email_verification"))
			st = h.Step(txID, cont, "otp/verify", map[string]any{"code": code})
		case has("enroll_totp"):
			en := h.Step(txID, cont, "totp/enroll", nil)
			if en.Status != 200 {
				return en
			}
			seed := en.Str("one_time.totp.secret")
			h.seeds[o.Identifier] = seed
			st = h.Step(txID, cont, "totp/activate", map[string]any{"code": h.TOTPNow(o.Identifier)})
		case has("hotp") && o.HOTPCode != "":
			st = h.Step(txID, cont, "hotp", map[string]any{"code": o.HOTPCode})
		case has("totp") && o.UseRecovery == "":
			st = h.Step(txID, cont, "totp", map[string]any{"code": h.TOTPNow(o.Identifier)})
		case has("recovery_code"):
			st = h.Step(txID, cont, "recovery-code", map[string]any{"code": o.UseRecovery})
		case has("accept_terms"):
			v := actions[0].(map[string]any)["options"].(map[string]any)["version"]
			st = h.Step(txID, cont, "terms", map[string]any{"version": v})
		case has("select_organization"):
			st = h.Step(txID, cont, "organization", map[string]any{"organization_id": o.SelectOrg})
		case has("consent"):
			st = h.Step(txID, cont, "consent", map[string]any{"approve": true})
		default:
			return st
		}
	}
	return st
}

func (h *Harness) emailOf(identifier string) string {
	if strings.Contains(identifier, "@") {
		return identifier
	}
	var email string
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT i2.original_value FROM user_identifiers i JOIN user_identifiers i2 ON i2.user_id=i.user_id
		WHERE i.canonical_value=$1 AND i.type='username' AND i2.type='email' LIMIT 1`, strings.ToLower(identifier)).Scan(&email)
	return email
}

// Login runs a complete authorization-code + PKCE login and token exchange.
func (h *Harness) Login(o LoginOpts) *LoginResult {
	h.t.Helper()
	if o.RedirectURI == "" {
		o.RedirectURI = "http://127.0.0.1/callback"
	}
	start, verifier, cont := h.StartTx(o)
	if start.Status != 201 {
		h.t.Fatalf("start transaction: %d %s", start.Status, start.Raw)
	}
	txID := start.Str("transaction_id")
	st := &Resp{Status: 200, Body: start.Get("state").(map[string]any)}
	st = h.Drive(txID, cont, st, o)
	res := &LoginResult{State: st, Verifier: verifier, TxID: txID, Continuation: cont}
	redirect := st.Str("redirect_to")
	if redirect == "" {
		if o.ExpectFail {
			return res
		}
		h.t.Fatalf("login did not complete: %d %s", st.Status, st.Raw)
	}
	u, _ := url.Parse(redirect)
	res.Code = u.Query().Get("code")
	if res.Code == "" {
		if o.ExpectFail {
			return res
		}
		h.t.Fatalf("no code in redirect %s", redirect)
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {res.Code}, "code_verifier": {verifier}, "redirect_uri": {o.RedirectURI}}
	for _, r := range o.Resources[:min(1, len(o.Resources))] {
		form.Add("resource", r)
	}
	rq := Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form}
	if o.ClientSecret != "" {
		rq.Basic = [2]string{o.ClientID, o.ClientSecret}
	} else {
		form.Set("client_id", o.ClientID)
	}
	res.Tokens = h.Do(rq)
	if res.Tokens.Status != 200 && !o.ExpectFail {
		h.t.Fatalf("token exchange: %d %s", res.Tokens.Status, res.Tokens.Raw)
	}
	return res
}

// AuthorizeHeadless completes an authorization request built by a client
// library (for example golang.org/x/oauth2's AuthCodeURL) through the headless
// interaction API, the way a login UI would: the request's own parameters
// (client_id, redirect_uri, scope, state, nonce and the PKCE challenge) start
// the transaction, the known credentials of o drive it, and the parsed
// redirect back to the client is returned (code, state, iss). The token
// exchange is left to the library.
func (h *Harness) AuthorizeHeadless(authURL string, o LoginOpts) url.Values {
	h.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		h.t.Fatalf("authorization URL: %v", err)
	}
	if want := h.Realm.Issuer + "/oauth/authorize"; u.Scheme+"://"+u.Host+u.Path != want {
		h.t.Fatalf("authorization URL %s does not target %s", authURL, want)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		h.t.Fatalf("response_type %q, want code", q.Get("response_type"))
	}
	body := map[string]any{}
	for _, k := range []string{"client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age", "acr_values", "login_hint"} {
		if v := q.Get(k); v != "" {
			body[k] = v
		}
	}
	if res := q["resource"]; len(res) > 0 {
		body["resource"] = res
	}
	start := h.API("POST", "/auth/transactions", "", body)
	if start.Status != 201 {
		h.t.Fatalf("start transaction: %d %s", start.Status, start.Raw)
	}
	st := h.Drive(start.Str("transaction_id"), start.Str("continuation_token"), &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, o)
	redirect := st.Str("redirect_to")
	if redirect == "" {
		h.t.Fatalf("authorization did not complete: %d %s", st.Status, st.Raw)
	}
	back, err := url.Parse(redirect)
	if err != nil || !strings.HasPrefix(redirect, q.Get("redirect_uri")) {
		h.t.Fatalf("redirect %q is not to %q", redirect, q.Get("redirect_uri"))
	}
	return back.Query()
}

// TokenRequest posts to the token endpoint with optional client authentication.
func (h *Harness) TokenRequest(form url.Values, clientID, clientSecret string) *Resp {
	rq := Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form}
	if clientSecret != "" {
		rq.Basic = [2]string{clientID, clientSecret}
	} else if clientID != "" {
		form.Set("client_id", clientID)
	}
	return h.Do(rq)
}

// Introspect calls introspection as a resource-server client.
func (h *Harness) Introspect(clientID, secret, token string) *Resp {
	return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/introspect", Form: url.Values{"token": {token}}, Basic: [2]string{clientID, secret}})
}

// SetPassword remembers a password for later logins.
func (h *Harness) SetPassword(identifier, pw string) { h.passwords[identifier] = pw }

// Seed returns a stored TOTP seed.
func (h *Harness) Seed(identifier string) string { return h.seeds[identifier] }

// Fatalf reports a failure.
func (h *Harness) Fatalf(format string, args ...any) { h.t.Helper(); h.t.Fatalf(format, args...) }

func mustStatus(t testing.TB, r *Resp, want int, what string) {
	t.Helper()
	if r.Status != want {
		t.Fatalf("%s: status %d (want %d): %s", what, r.Status, want, r.Raw)
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var _ = fmt.Sprintf

func jsonDecoder(res *http.Response) *json.Decoder { return json.NewDecoder(res.Body) }

func base64URL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

const cryptoSHA256 = crypto.SHA256

func jwtPayload(tok string) map[string]any {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return map[string]any{}
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if aud, ok := m["aud"].([]any); ok && len(aud) == 1 {
		m["aud"] = aud[0]
	}
	return m
}

// runWorker runs every worker task once and fails the test on any task error.
func runWorker(t testing.TB, w *worker.Worker) {
	t.Helper()
	for name, err := range w.RunOnce(context.Background()) {
		if err != nil {
			t.Fatalf("worker task %s: %v", name, err)
		}
	}
}
