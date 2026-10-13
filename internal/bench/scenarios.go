package bench

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Scenarios lists the available scenarios by name.
func Scenarios() map[string]func() Scenario {
	return map[string]func() Scenario{
		// Workloads (NFR-003).
		"client-credentials": func() Scenario { return &clientCredentials{} },
		"introspection":      func() Scenario { return &introspection{} },
		"password-login":     func() Scenario { return &passwordLogin{} },
		"passkey-assertion":  func() Scenario { return &passkeyAssertion{} },
		"scim":               func() Scenario { return &scimLifecycle{} },
		"email-delivery":     func() Scenario { return &emailDelivery{} },
		"webhook-delivery":   func() Scenario { return &webhookDelivery{} },
		"webhook-retry":      func() Scenario { return &webhookDelivery{retry: true} },
		"refresh":            func() Scenario { return &refresh{} },
		"policy":             func() Scenario { return &policy{} },
		"audit-query":        func() Scenario { return &auditQuery{} },
		"import":             func() Scenario { return &importDryRun{} },
		"mixed":              func() Scenario { return newMixed() },
		"mixed-extended":     func() Scenario { return newExtendedMixed() },
		"mixed-email":        func() Scenario { return newEmailMixed() },
		"mixed-delivery":     func() Scenario { return newDeliveryMixed() },
		// Adversarial resource use (NFR-006).
		"unknown-key":          func() Scenario { return &unknownKey{} },
		"failed-password":      func() Scenario { return &failedPassword{} },
		"otp-guess":            func() Scenario { return &otpGuess{} },
		"complex-filter":       func() Scenario { return &complexFilter{} },
		"complex-group-filter": func() Scenario { return &complexFilter{groups: true} },
		"complex-audit-filter": func() Scenario { return &complexAuditFilter{} },
		"metadata-fetch":       func() Scenario { return &metadataFetch{} },
		"oversized-input":      func() Scenario { return &oversized{} },
		"notification-flood":   func() Scenario { return &notificationFlood{} },
		// Data-consistency stress (NFR-007).
		"refresh-race": func() Scenario { return &refreshRace{} },
	}
}

func (e *Env) tokenPath() string { return "/realms/" + e.Client.Realm + "/oauth/token" }

// target returns the seeded user adversarial scenarios attack; workloads
// draw from the other users, so a lock on it does not skew them.
func (e *Env) target() int { return e.Seed.Spec.Users - 1 }

// policySubjects is how many members of the large organization the policy
// scenario signs in as its subjects (users 0 to policySubjects-1).
const policySubjects = 8

// nextUser returns the user for the next sign-in of a workload. Users are
// taken in turn from a random starting point instead of being drawn at
// random: the password step allows login_per_identifier attempts per
// account (10 per 15 minutes by default), and with random draws a long run
// (a soak run of mixed signs in tens of thousands of times) makes some
// accounts exceed it by chance and fail with 429, which says nothing about
// the server (NFR-005). In turn, no account gets another sign-in before every
// other one had as many. The policy scenario's subjects, which it signs in
// again whenever their tokens are renewed, and the account the adversarial
// scenarios attack (the last one) are left out.
func (e *Env) nextUser() int {
	n, lo := e.Seed.Spec.Users-1, min(policySubjects, e.Seed.Spec.LargeOrgUsers)
	if n-lo < lo {
		lo = 0 // a tiny dataset: every user but the attacked one
	}
	if n <= lo {
		return 0
	}
	e.userOnce.Do(func() { e.userNext.Store(mrand.Uint64()) })
	return lo + int(e.userNext.Add(1)%uint64(n-lo))
}

func (e *Env) machineToken(ctx context.Context, c SeedClient, audience, scope string) (*Response, error) {
	return e.Client.Do(ctx, Request{Method: "POST", Path: e.tokenPath(), Basic: [2]string{c.ClientID, c.Secret},
		Form: url.Values{"grant_type": {"client_credentials"}, "resource": {audience}, "scope": {scope}}})
}

// login runs a headless password sign-in of seeded user i and redeems the code.
func (e *Env) login(ctx context.Context, i int, scope string) (*Response, string) {
	return e.loginPassword(ctx, e.Seed.UserEmail(i), e.Seed.UserPassword(i), e.Seed.Audience, scope)
}

func (e *Env) loginPassword(ctx context.Context, identifier, password, audience, scope string) (*Response, string) {
	d := e.Seed
	verifier, challenge := PKCE()
	start, err := e.Client.API(ctx, "POST", "/auth/transactions", "", map[string]any{"client_id": d.Web.ClientID, "redirect_uri": d.RedirectURI,
		"scope": scope, "state": "bench", "code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{audience}})
	if err != nil || start.Status != 201 {
		return nil, outcomeOf(start, err)
	}
	tx, cont := start.Str("transaction_id"), start.Str("continuation_token")
	step := func(name string, body any) (*Response, error) {
		return e.Client.Do(ctx, Request{Method: "POST", Path: "/api/v1/realms/" + e.Client.Realm + "/auth/transactions/" + tx + "/" + name, JSON: body,
			Headers: map[string]string{"X-Transaction-Token": cont}})
	}
	if r, err := step("identify", map[string]any{"identifier": identifier}); err != nil || r.Status != 200 {
		return nil, outcomeOf(r, err)
	}
	r, err := step("password", map[string]any{"password": password})
	if err != nil || r.Status != 200 {
		return nil, outcomeOf(r, err)
	}
	redirect := r.Str("redirect_to")
	if redirect == "" {
		return nil, "unexpected_next_action"
	}
	u, _ := url.Parse(redirect)
	tok, err := e.Client.Do(ctx, Request{Method: "POST", Path: e.tokenPath(), Basic: [2]string{d.Web.ClientID, d.Web.Secret},
		Form: url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {d.RedirectURI}, "resource": {audience}}})
	if err != nil || tok.Status != 200 {
		return nil, outcomeOf(tok, err)
	}
	return tok, "ok"
}

// ---------- workloads ----------

type clientCredentials struct{}

func (s *clientCredentials) Name() string                        { return "client-credentials" }
func (s *clientCredentials) Prepare(context.Context, *Env) error { return nil }
func (s *clientCredentials) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	c := e.Seed.Machine[rnd.IntN(len(e.Seed.Machine))]
	return outcomeOf(e.machineToken(ctx, c, e.Seed.Audience, "bench:read"))
}

// introspection introspects machine tokens, one per machine client, which
// are renewed before they expire.
type introspection struct{ tokens []*renewable }

func (s *introspection) Name() string { return "introspection" }
func (s *introspection) Prepare(ctx context.Context, e *Env) error {
	s.tokens = nil
	for _, c := range e.Seed.Machine {
		t := &renewable{fetch: tokenFetch("machine token", func(ctx context.Context) (*Response, error) {
			return e.machineToken(ctx, c, e.Seed.Audience, "bench:read")
		})}
		if _, err := t.get(ctx); err != nil {
			return err
		}
		s.tokens = append(s.tokens, t)
	}
	return nil
}
func (s *introspection) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	tok, err := s.tokens[rnd.IntN(len(s.tokens))].get(ctx)
	if err != nil {
		return "token_renewal_failed"
	}
	r, err := e.Client.Do(ctx, Request{Method: "POST", Path: "/realms/" + e.Client.Realm + "/oauth/introspect",
		Basic: [2]string{e.Seed.ResourceSrv.ClientID, e.Seed.ResourceSrv.Secret}, Form: url.Values{"token": {tok}}})
	if err == nil && r.Status == 200 && r.Body["active"] != true {
		return "inactive"
	}
	return outcomeOf(r, err)
}

type passwordLogin struct{}

func (s *passwordLogin) Name() string                        { return "password-login" }
func (s *passwordLogin) Prepare(context.Context, *Env) error { return nil }
func (s *passwordLogin) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	_, out := e.login(ctx, e.nextUser(), "bench:read")
	return out
}

type refresh struct {
	mu     sync.Mutex
	tokens map[int]string
}

func (s *refresh) Name() string { return "refresh" }
func (s *refresh) Prepare(context.Context, *Env) error {
	s.tokens = map[int]string{}
	return nil
}
func (s *refresh) Op(ctx context.Context, e *Env, worker int, rnd *mrand.Rand) string {
	s.mu.Lock()
	rt := s.tokens[worker]
	s.mu.Unlock()
	if rt == "" {
		// Each worker signs in once (not measured separately) and then rotates
		// its refresh token.
		tok, out := e.login(ctx, e.nextUser(), "bench:read offline_access")
		if out != "ok" {
			return "setup_" + out
		}
		rt = tok.Str("refresh_token")
	}
	r, err := e.Client.Do(ctx, Request{Method: "POST", Path: e.tokenPath(), Basic: [2]string{e.Seed.Web.ClientID, e.Seed.Web.Secret},
		Form: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {e.Seed.Audience}}})
	if err == nil && r.Status == 200 {
		s.mu.Lock()
		s.tokens[worker] = r.Str("refresh_token")
		s.mu.Unlock()
	} else {
		s.mu.Lock()
		delete(s.tokens, worker)
		s.mu.Unlock()
	}
	return outcomeOf(r, err)
}

// policy checks decisions for large-organization users with the resource
// server's token; the resource server's token and the subjects' tokens are
// renewed (by client credentials and by signing in again) before they expire.
type policy struct {
	rsToken  *renewable
	subjects []*renewable
}

func (s *policy) Name() string { return "policy" }
func (s *policy) Prepare(ctx context.Context, e *Env) error {
	s.rsToken = &renewable{fetch: tokenFetch("resource server token", func(ctx context.Context) (*Response, error) {
		return e.machineToken(ctx, e.Seed.ResourceSrv, e.Seed.AdminAudience, "proudauth:admin")
	})}
	if _, err := s.rsToken.get(ctx); err != nil {
		return err
	}
	s.subjects = nil
	for i := 0; i < min(policySubjects, e.Seed.Spec.LargeOrgUsers); i++ {
		t := &renewable{fetch: func(ctx context.Context) (string, time.Duration, error) {
			tok, out := e.login(ctx, i, "bench:read")
			if out != "ok" {
				return "", 0, fmt.Errorf("policy subject sign-in: %s", out)
			}
			return tok.Str("access_token"), lifetime(tok), nil
		}}
		if _, err := t.get(ctx); err != nil {
			return err
		}
		s.subjects = append(s.subjects, t)
	}
	if len(s.subjects) == 0 {
		return fmt.Errorf("policy: the seed has no large-organization users")
	}
	return nil
}
func (s *policy) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	rsToken, err := s.rsToken.get(ctx)
	if err != nil {
		return "token_renewal_failed"
	}
	subject, err := s.subjects[rnd.IntN(len(s.subjects))].get(ctx)
	if err != nil {
		return "token_renewal_failed"
	}
	r, err := e.Client.API(ctx, "POST", "/authorization/check", rsToken, map[string]any{"subject_token": subject,
		"action": e.Seed.Prefix + "bench.read", "resource": map[string]any{"type": "document", "id": fmt.Sprintf("doc-%d", rnd.IntN(1000)),
			"org_id": e.Seed.LargeOrgID}})
	if err == nil && r.Status == 200 && r.Body["allowed"] != true {
		return "denied"
	}
	return outcomeOf(r, err)
}

type auditQuery struct{}

func (s *auditQuery) Name() string                        { return "audit-query" }
func (s *auditQuery) Prepare(context.Context, *Env) error { return nil }
func (s *auditQuery) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	filters := []string{"limit=50", "limit=50&type=authentication.succeeded", "limit=50&organization_id=" + e.Seed.LargeOrgID,
		"limit=50&category=security"}
	return outcomeOf(e.Client.API(ctx, "GET", "/audit-events?"+filters[rnd.IntN(len(filters))], e.adminToken(ctx), nil))
}

type importDryRun struct{}

func (s *importDryRun) Name() string                        { return "import" }
func (s *importDryRun) Prepare(context.Context, *Env) error { return nil }
func (s *importDryRun) Op(ctx context.Context, e *Env, worker int, rnd *mrand.Rand) string {
	users := make([]map[string]any, 100)
	base := rnd.IntN(1 << 30)
	for i := range users {
		users[i] = map[string]any{"source_id": fmt.Sprintf("dry-%d-%d", worker, base+i), "email": fmt.Sprintf("%sdry%d-%d@bench.test", e.Seed.Prefix, worker, base+i)}
	}
	return outcomeOf(e.Client.API(ctx, "POST", "/user-imports", e.adminToken(ctx), map[string]any{"source_system": "bench-dry", "users": users, "dry_run": true}))
}

// mixed draws operations from the other workloads with fixed weights.
type mixed struct {
	parts             []Scenario
	weights           []int
	name, description string
}

func newMixed() *mixed {
	return &mixed{parts: []Scenario{&clientCredentials{}, &introspection{}, &policy{}, &refresh{}, &passwordLogin{}, &auditQuery{}},
		weights: []int{40, 25, 15, 10, 5, 5}}
}
func newExtendedMixed() *mixed {
	return &mixed{name: "mixed-extended", parts: []Scenario{&clientCredentials{}, &introspection{}, &policy{}, &refresh{}, &passwordLogin{}, &auditQuery{}, &passkeyAssertion{}, &scimLifecycle{}, &importDryRun{}},
		weights:     []int{30, 20, 15, 10, 5, 5, 5, 5, 5},
		description: "weights: client-credentials 30, introspection 20, policy 15, refresh 10, password-login 5, audit-query 5, passkey-assertion 5, scim 5, import 5"}
}
func newEmailMixed() *mixed {
	return &mixed{name: "mixed-email", parts: []Scenario{&clientCredentials{}, &introspection{}, &policy{}, &refresh{}, &passwordLogin{}, &auditQuery{}, &passkeyAssertion{}, &scimLifecycle{}, &importDryRun{}, &emailDelivery{}},
		weights:     []int{25, 15, 15, 10, 5, 5, 5, 5, 5, 10},
		description: "weights: client-credentials 25, introspection 15, policy 15, refresh 10, password-login 5, audit-query 5, passkey-assertion 5, scim 5, import 5, email-delivery 10"}
}
func newDeliveryMixed() *mixed {
	return &mixed{name: "mixed-delivery", parts: []Scenario{&clientCredentials{}, &introspection{}, &policy{}, &refresh{}, &passwordLogin{}, &auditQuery{}, &passkeyAssertion{}, &scimLifecycle{}, &importDryRun{}, &emailDelivery{}, &webhookDelivery{}, &webhookDelivery{retry: true}},
		weights:     []int{25, 15, 10, 10, 5, 5, 5, 5, 5, 5, 5, 5},
		description: "weights: client-credentials 25, introspection 15, policy 10, refresh 10, password-login 5, audit-query 5, passkey-assertion 5, scim 5, import 5, email-delivery 5, webhook-delivery 5, webhook-retry 5"}
}
func (s *mixed) Name() string {
	if s.name != "" {
		return s.name
	}
	return "mixed"
}
func (s *mixed) Prepare(ctx context.Context, e *Env) error {
	for _, p := range s.parts {
		if err := p.Prepare(ctx, e); err != nil {
			return fmt.Errorf("%s: %w", p.Name(), err)
		}
	}
	return nil
}
func (s *mixed) Op(ctx context.Context, e *Env, worker int, rnd *mrand.Rand) string {
	n := rnd.IntN(100)
	for i, w := range s.weights {
		if n < w {
			return s.parts[i].Name() + ":" + s.parts[i].Op(ctx, e, worker, rnd)
		}
		n -= w
	}
	return "unreachable"
}
func (s *mixed) Notes() []string {
	text := s.description
	if text == "" {
		text = "weights: client-credentials 40, introspection 25, policy 15, refresh 10, password-login 5, audit-query 5"
	}
	notes := []string{text}
	for _, part := range s.parts {
		if n, ok := part.(interface{ Notes() []string }); ok {
			notes = append(notes, n.Notes()...)
		}
	}
	return notes
}
func (s *mixed) Close(ctx context.Context, e *Env) error {
	var errs []error
	for _, p := range s.parts {
		if c, ok := p.(interface {
			Close(context.Context, *Env) error
		}); ok {
			errs = append(errs, c.Close(ctx, e))
		}
	}
	return errors.Join(errs...)
}
func (s *mixed) Observations() map[string]any {
	out := map[string]any{}
	for _, p := range s.parts {
		if o := scenarioObservations(p); o != nil {
			out[p.Name()] = o
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ---------- adversarial (NFR-006) ----------

// unknownKey presents validly shaped tokens signed with keys the server does
// not know: key-refresh amplification must stay bounded.
type unknownKey struct{}

func (s *unknownKey) Name() string                        { return "unknown-key" }
func (s *unknownKey) Prepare(context.Context, *Env) error { return nil }
func (s *unknownKey) Adversarial() bool                   { return true }
func (s *unknownKey) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": fmt.Sprintf("unknown-%d", rnd.IntN(1<<20))})
	now := time.Now().Unix()
	pl, _ := json.Marshal(map[string]any{"iss": "x", "aud": e.Seed.Audience, "sub": "usr_x", "exp": now + 60, "iat": now})
	tok := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl) + "." + base64.RawURLEncoding.EncodeToString(b)
	r, err := e.Client.Do(ctx, Request{Method: "POST", Path: "/realms/" + e.Client.Realm + "/oauth/introspect",
		Basic: [2]string{e.Seed.ResourceSrv.ClientID, e.Seed.ResourceSrv.Secret}, Form: url.Values{"token": {tok}}})
	if err == nil && r.Status == 200 && r.Body["active"] == true {
		return "invariant_violation"
	}
	return outcomeOf(r, err)
}

// failedPassword guesses passwords for one account: the temporary lock and
// budgets must answer 401 then 429, never 200.
type failedPassword struct{}

func (s *failedPassword) Name() string                        { return "failed-password" }
func (s *failedPassword) Prepare(context.Context, *Env) error { return nil }
func (s *failedPassword) Adversarial() bool                   { return true }
func (s *failedPassword) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	d := e.Seed
	_, challenge := PKCE()
	start, err := e.Client.API(ctx, "POST", "/auth/transactions", "", map[string]any{"client_id": d.Web.ClientID, "redirect_uri": d.RedirectURI,
		"scope": "bench:read", "code_challenge": challenge, "code_challenge_method": "S256", "resource": []string{d.Audience}})
	if err != nil || start.Status != 201 {
		return "start_" + outcomeOf(start, err)
	}
	tx, cont := start.Str("transaction_id"), start.Str("continuation_token")
	path := "/api/v1/realms/" + e.Client.Realm + "/auth/transactions/" + tx + "/"
	hdr := map[string]string{"X-Transaction-Token": cont}
	if r, err := e.Client.Do(ctx, Request{Method: "POST", Path: path + "identify", JSON: map[string]any{"identifier": d.UserEmail(e.target())}, Headers: hdr}); err != nil || r.Status != 200 {
		return "identify_" + outcomeOf(r, err)
	}
	r, err := e.Client.Do(ctx, Request{Method: "POST", Path: path + "password", JSON: map[string]any{"password": fmt.Sprintf("guess-%d", rnd.Int())}, Headers: hdr})
	if err == nil && r.Status == 200 {
		return "invariant_violation"
	}
	return outcomeOf(r, err)
}

// oversized offers bodies above the request limit: 413 without work. The
// request declares its 2 MiB body and asks to continue (Expect:
// 100-continue), so the server has to refuse it from the declared length
// before any of the body is sent. Sending whole bodies instead measured the
// load generator: from one host at full concurrency the bodies filled its
// network buffers, most operations ended in transport errors when the server
// closed the connection, and on macOS the exhausted buffers stalled other
// local networking (Docker Desktop's port forwarding among it).
type oversized struct{ client *Client }

func (s *oversized) Name() string      { return "oversized-input" }
func (s *oversized) Adversarial() bool { return true }
func (s *oversized) Prepare(_ context.Context, e *Env) error {
	c, h := *e.Client, *e.Client.HTTP
	// Test and caller-provided clients may have a zero continue timeout,
	// which sends immediately. Preserve their TLS settings but wait for
	// the refusal, just as NewClient does.
	if h.Transport == nil {
		h.Transport = http.DefaultTransport
	}
	if tr, ok := h.Transport.(*http.Transport); ok {
		tr = tr.Clone()
		tr.ExpectContinueTimeout = 31 * time.Second
		h.Transport = tr
	}
	c.HTTP = &h
	s.client = &c
	return nil
}
func (s *oversized) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	return outcomeOf(s.client.Do(ctx, Request{Method: "POST", Path: "/api/v1/realms/" + e.Client.Realm + "/auth/transactions",
		HeaderOnlyBytes: (2 << 20) + 16}))
}
func (s *oversized) Notes() []string {
	return []string{"header-only oversized offer: the transport cannot send body bytes; a body read is invariant_violation_body_requested"}
}

// notificationFlood requests password resets for one identifier: send
// budgets must turn the flood into 429s, not mail.
type notificationFlood struct{}

func (s *notificationFlood) Name() string                        { return "notification-flood" }
func (s *notificationFlood) Prepare(context.Context, *Env) error { return nil }
func (s *notificationFlood) Adversarial() bool                   { return true }
func (s *notificationFlood) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	return outcomeOf(e.Client.API(ctx, "POST", "/password-resets", "", map[string]any{"identifier": e.Seed.UserEmail(e.target())}))
}
func (s *notificationFlood) Notes() []string {
	return []string{"202 responses are indistinguishable for known and unknown identifiers; count deliveries in the mail system to confirm the budget"}
}

// ---------- consistency stress (NFR-007) ----------

// refreshRace redeems one refresh token from 8 goroutines at once: exactly
// one must succeed; the family is then revoked (reuse detection). An attempt
// that was rate limited, failed in transport or hit a server error says
// nothing about the invariant, so a race without a success is reported as
// inconclusive_* rather than as a violation unless every attempt was
// rejected by the server; a race with one success and attempts that failed
// on the server or in transport is not ok either (one_success_with_*): the
// failed attempts were not shown to be refused, and the failures are a
// finding of their own (the server answered 500 when lock waits of the
// losing attempts were cancelled).
type refreshRace struct{}

func (s *refreshRace) Name() string                        { return "refresh-race" }
func (s *refreshRace) Prepare(context.Context, *Env) error { return nil }

// Adversarial: warm-up must not create and revoke refresh families or spend
// login budgets.
func (s *refreshRace) Adversarial() bool { return true }
func (s *refreshRace) Notes() []string {
	return []string{"invariant_violation_N_successes: N != 1 attempts succeeded although every attempt reached the token endpoint; " +
		"inconclusive_rate_limited / inconclusive_http_5xx / inconclusive_transport_error: no attempt succeeded and some were " +
		"rate limited, failed on the server or in transport, so the race did not test the invariant; " +
		"one_success_with_http_5xx / one_success_with_transport_error: one attempt succeeded and others failed on the server or in transport"}
}
func (s *refreshRace) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	tok, out := e.login(ctx, e.nextUser(), "bench:read offline_access")
	if out != "ok" {
		return "setup_" + out
	}
	rt := tok.Str("refresh_token")
	var wg sync.WaitGroup
	var mu sync.Mutex
	var tally raceTally
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.Client.Do(ctx, Request{Method: "POST", Path: e.tokenPath(), Basic: [2]string{e.Seed.Web.ClientID, e.Seed.Web.Secret},
				Form: url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "resource": {e.Seed.Audience}}})
			mu.Lock()
			tally.add(r, err)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return tally.outcome()
}

// raceTally counts the attempts of one refresh race by result.
type raceTally struct {
	wins, rejected, rateLimited, serverErrors, transportErrors int
}

func (t *raceTally) add(r *Response, err error) {
	switch {
	case err != nil || r == nil:
		t.transportErrors++
	case r.Status == 200:
		t.wins++
	case r.Status == 429:
		t.rateLimited++
	case r.Status >= 500:
		t.serverErrors++
	default:
		t.rejected++ // invalid_grant: the expected answer for every loser
	}
}

// outcome classifies the race. More than one success always violates the
// invariant; no success is a violation only when every attempt was answered
// and rejected by the server; one success is ok when every other attempt was
// refused or rate limited.
func (t raceTally) outcome() string {
	switch {
	case t.wins > 1:
		return fmt.Sprintf("invariant_violation_%d_successes", t.wins)
	case t.wins == 1 && t.serverErrors > 0:
		return "one_success_with_http_5xx"
	case t.wins == 1 && t.transportErrors > 0:
		return "one_success_with_transport_error"
	case t.wins == 1:
		return "ok"
	case t.rateLimited > 0:
		return "inconclusive_rate_limited"
	case t.serverErrors > 0:
		return "inconclusive_http_5xx"
	case t.transportErrors > 0:
		return "inconclusive_transport_error"
	default:
		return "invariant_violation_0_successes"
	}
}
