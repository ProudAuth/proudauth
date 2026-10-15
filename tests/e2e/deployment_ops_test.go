package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/httpapi"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/provision"
	"github.com/proudauth/proudauth/internal/restore"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/server"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
	"github.com/proudauth/proudauth/internal/worker"
)

// replica starts another identity-server process over db with the key
// hierarchy kr, the way a second replica behind the load balancer, a restart
// or a restored deployment runs: its own runtime, caches and key manager, with
// the harness's configuration and clock. The returned harness drives it and
// shares the harness's remembered passwords and TOTP seeds.
func replica(t *testing.T, h *Harness, db *storage.DB, kr *keys.Keyring) *Harness {
	t.Helper()
	deps := runtime.New(db, h.Cfg, h.Clock, kr, observability.NewLogger(io.Discard, "error", "json"))
	app, err := httpapi.Build(deps, nil)
	if err != nil {
		t.Fatal(err)
	}
	app.KeyMgr.RSABits = 2048
	server.RegisterModules(app)
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	n := *h
	n.App, n.Srv, n.Base = app, srv, srv.URL
	return &n
}

// snapshotDatabase takes a physical copy of the harness database (a backup)
// and returns a connection to the copy, dropped when the test ends.
func snapshotDatabase(t *testing.T, h *Harness, suffix string) *storage.DB {
	t.Helper()
	ctx := context.Background()
	var name string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	adminURL := testutil.DatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	copyName := name + "_" + suffix
	var cerr error
	for i := 0; i < 50; i++ {
		h.App.D.DB.Pool.Reset() // a template must have no open connections
		if _, cerr = admin.Exec(ctx, "CREATE DATABASE "+copyName+" TEMPLATE "+name); cerr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if cerr != nil {
		t.Fatalf("snapshot database: %v", cerr)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+copyName+" WITH (FORCE)")
	})
	db, err := storage.Open(ctx, testutil.DSNFor(adminURL, copyName), storage.Options{MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func probe(h *Harness, path string) (int, map[string]any) {
	r := h.Do(Req{Method: "GET", Path: path})
	return r.Status, r.Body
}

// TestBootstrapIsOperatorOnly covers DEP-007: the first administrator is
// created only through the local operator channel, without any password,
// with a one-time setup token that expires (lifetime bounded to 1m..24h) and
// with MFA enrollment required at first sign-in; a second bootstrap is
// refused unless it is an audited break-glass action, and the public setup
// endpoint accepts nothing but a valid, unexpired, unused token.
func TestBootstrapIsOperatorOnly(t *testing.T) {
	h := NewHarness(t)
	h.CreateRealm(nil)
	ctx := context.Background()
	p := h.App.Provision
	for _, ttl := range []time.Duration{30 * time.Second, 25 * time.Hour} {
		if _, err := p.BootstrapAdmin(ctx, "main", "early@example.test", "early", ttl, false, "op"); err == nil {
			t.Fatalf("setup token lifetime %s accepted", ttl)
		}
	}
	res, err := p.BootstrapAdmin(ctx, "main", "admin@example.test", "root-admin", 10*time.Minute, false, "op")
	if err != nil {
		t.Fatal(err)
	}
	if res.SetupToken == "" || !res.ExpiresAt.Equal(h.Clock.Now().Add(10*time.Minute)) {
		t.Fatalf("bootstrap must return an expiring one-time token: %+v", res)
	}
	q := h.App.D.DB.Pool
	var passwords int
	var required []string
	if err := q.QueryRow(ctx, `SELECT (SELECT count(*) FROM credentials WHERE user_id=$1), required_actions FROM users WHERE id=$1`, res.UserID).
		Scan(&passwords, &required); err != nil {
		t.Fatal(err)
	}
	if passwords != 0 || !slices.Contains(required, identity.ActionConfigureTOTP) {
		t.Fatalf("bootstrap administrator: %d credentials, required actions %v", passwords, required)
	}
	// The token is printed to the operator, never mailed.
	if h.Mail("admin@example.test", "account_setup") != "" {
		t.Fatal("bootstrap setup token was sent by email")
	}
	var actor string
	if err := q.QueryRow(ctx, `SELECT actor_id FROM audit_events WHERE type='bootstrap.admin_created' AND realm_id=$1`, h.Realm.ID).Scan(&actor); err != nil || actor != "local:op" {
		t.Fatalf("bootstrap not audited as an operator action: %q %v", actor, err)
	}

	// Setup is closed after initialization.
	if _, err := p.BootstrapAdmin(ctx, "main", "second@example.test", "second", time.Hour, false, "op"); !errors.Is(err, provision.ErrAlreadyBootstrapped) {
		t.Fatalf("repeated bootstrap: %v", err)
	}
	var users int
	_ = q.QueryRow(ctx, `SELECT count(*) FROM users WHERE realm_id=$1`, h.Realm.ID).Scan(&users)
	if users != 1 {
		t.Fatalf("refused bootstrap created an account: %d users", users)
	}
	setup := func(token string) *Resp {
		return h.API("POST", "/account-setup", "", map[string]any{"setup_token": token, "password": "an administrator passphrase 2026"})
	}
	for _, tok := range []string{"", "pa_guessed_setup_token"} {
		if r := setup(tok); r.Status == 200 {
			t.Fatalf("anonymous setup accepted token %q", tok)
		}
	}
	mustStatus(t, setup(res.SetupToken), 200, "account setup")
	if r := setup(res.SetupToken); r.Status != 400 {
		t.Fatalf("setup token reused: %d %s", r.Status, r.Raw)
	}

	// Break-glass re-bootstrap is possible only for the operator, is audited
	// as an emergency, and its token expires.
	glass, err := p.BootstrapAdmin(ctx, "main", "glass@example.test", "glass", time.Minute, true, "op")
	if err != nil {
		t.Fatal(err)
	}
	var category string
	if err := q.QueryRow(ctx, `SELECT category FROM audit_events WHERE type='bootstrap.break_glass_admin_created'`).Scan(&category); err != nil || category != "emergency" {
		t.Fatalf("break-glass bootstrap not audited as an emergency: %q %v", category, err)
	}
	h.Clock.Advance(2 * time.Minute)
	if r := setup(glass.SetupToken); r.Status != 400 {
		t.Fatalf("expired setup token accepted: %d %s", r.Status, r.Raw)
	}
}

// TestRestartKeepsKeyIdentity covers DEP-008: signing keys are persisted
// (encrypted under the configured root keys), so a restarted process keeps
// the issuer's key identity, publishes the same JWKS and honours tokens and
// sessions issued before the restart. A process started with other root keys
// fails closed (unready, no token issued) instead of creating a new key.
func TestRestartKeepsKeyIdentity(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	countKeys := func() int {
		var n int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE realm_id=$1`, h.Realm.ID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	kids := func(n *Harness) []string {
		r := n.Do(Req{Method: "GET", Path: "/realms/main/jwks"})
		mustStatus(t, r, 200, "jwks")
		var out []string
		for _, k := range r.Get("keys").([]any) {
			out = append(out, k.(map[string]any)["kid"].(string))
		}
		slices.Sort(out)
		return out
	}
	active, err := h.App.KeyMgr.Active(ctx, h.Realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	keysBefore, jwksBefore := countKeys(), kids(h)
	lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read")
	at, rt := lr.Tokens.Str("access_token"), lr.Tokens.Str("refresh_token")

	// Restart: a new process with the same configured root keys.
	restarted := replica(t, h, h.App.D.DB, h.App.D.Keys)
	if k, err := restarted.App.KeyMgr.Active(ctx, h.Realm.ID); err != nil || k.KID != active.KID {
		t.Fatalf("restart changed the signing key: %v %v", k, err)
	}
	if got := kids(restarted); !slices.Equal(got, jwksBefore) {
		t.Fatalf("JWKS changed across a restart: %v -> %v", jwksBefore, got)
	}
	if in := restarted.Introspect("orders-rs", f.Clients["orders-rs"].Secret, at); in.Status != 200 || in.Get("active") != true {
		t.Fatalf("token issued before the restart rejected: %d %s", in.Status, in.Raw)
	}
	next := restarted.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, next, 200, "refresh after restart")
	if kid := jwtHeaderKID(t, next.Str("access_token")); kid != active.KID {
		t.Fatalf("restarted process signed with %q, want %q", kid, active.KID)
	}
	if n := countKeys(); n != keysBefore {
		t.Fatalf("restart created signing keys: %d -> %d", keysBefore, n)
	}

	// Other root keys: the stored key cannot be used, and no new identity is
	// created in its place.
	wrong := replica(t, h, h.App.D.DB, keys.NewRandom())
	if _, err := wrong.App.KeyMgr.Active(ctx, h.Realm.ID); err == nil {
		t.Fatal("active signing key usable under other root keys")
	}
	if st, body := probe(wrong, "/health/ready"); st != 503 {
		t.Fatalf("process with the wrong keys is ready: %d %v", st, body)
	}
	if r := wrong.TokenRequest(url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}},
		f.Clients["batch"].ID, f.Clients["batch"].Secret); r.Status == 200 {
		t.Fatal("process with the wrong keys issued a token")
	}
	if n := countKeys(); n != keysBefore {
		t.Fatalf("wrong root keys created signing keys: %d -> %d", keysBefore, n)
	}
	if k, err := restarted.App.KeyMgr.Active(ctx, h.Realm.ID); err != nil || k.KID != active.KID {
		t.Fatalf("active key changed after a start with the wrong keys: %v %v", k, err)
	}
}

func jwtHeaderKID(t *testing.T, tok string) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", tok)
	}
	raw, err := base64URL(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var hdr struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil {
		t.Fatal(err)
	}
	return hdr.KID
}

// TestHealthContracts covers DEP-009: liveness answers without touching any
// dependency, while readiness takes the instance out of traffic (503) when
// it is draining, its database is unreachable, the schema is behind the
// binary or its signing keys are unusable, and returns to ready once the
// dependency recovers, so no restart is needed.
func TestHealthContracts(t *testing.T) {
	h := NewHarness(t)
	h.CreateRealm(nil)
	ctx := context.Background()
	expect := func(n *Harness, what string, ready int, status string) {
		t.Helper()
		if st, body := probe(n, "/health/live"); st != 200 {
			t.Fatalf("%s: liveness %d %v", what, st, body)
		}
		if st, body := probe(n, "/health/ready"); st != ready || body["status"] != status {
			t.Fatalf("%s: readiness %d %v, want %d %s", what, st, body, ready, status)
		}
	}
	expect(h, "healthy", 200, "ready")

	h.App.Draining.Store(true)
	expect(h, "draining", 503, "draining")
	h.App.Draining.Store(false)

	// Schema behind the binary: the newest migration is not recorded.
	var newest string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT max(name) FROM schema_migrations`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	hide := func(from, to string) {
		t.Helper()
		if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE schema_migrations SET name=$2 WHERE name=$1`, from, to); err != nil {
			t.Fatal(err)
		}
	}
	hide(newest, newest+".hidden")
	expect(h, "schema behind", 503, "unavailable")
	hide(newest+".hidden", newest)
	expect(h, "schema current again", 200, "ready")

	// Database unreachable: a replica whose connection pool is gone.
	db, err := storage.Open(ctx, h.App.D.DB.Pool.Config().ConnString(), storage.Options{MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	cut := replica(t, h, db, h.App.D.Keys)
	expect(cut, "replica", 200, "ready")
	db.Close()
	expect(cut, "database unreachable", 503, "unavailable")

	// Signing keys unusable: a replica with other root keys.
	expect(replica(t, h, h.App.D.DB, keys.NewRandom()), "signing key unusable", 503, "degraded")
	expect(h, "other replicas unaffected", 200, "ready")
}

// TestClockHealth covers OPS-011: an instance whose clock disagrees with the
// database beyond observability.max_clock_skew leaves rotation through
// readiness (reason clock_skew), the skew is exported as a metric and in the
// operator status for alerting, and database sessions and the service clock
// use UTC instants.
func TestClockHealth(t *testing.T) {
	h := NewHarness(t)
	h.CreateRealm(nil)
	ctx := context.Background()
	if st, body := probe(h, "/health/ready"); st != 200 {
		t.Fatalf("ready with the default skew bound: %d %v", st, body)
	}
	bound := h.Cfg.Observability.MaxClockSkew
	h.Cfg.Observability.MaxClockSkew = time.Nanosecond // any measurable disagreement is excessive
	st, body := probe(h, "/health/ready")
	h.Cfg.Observability.MaxClockSkew = bound
	if st != 503 || body["reason"] != "clock_skew" {
		t.Fatalf("excessive skew not reported: %d %v", st, body)
	}
	if st, _ := probe(h, "/health/live"); st != 200 {
		t.Fatal("clock skew must not fail liveness")
	}
	if st, _ := probe(h, "/health/ready"); st != 200 {
		t.Fatal("readiness did not recover")
	}

	env := &server.Env{Cfg: h.Cfg, Log: h.App.D.Log, DB: h.App.D.DB, Keys: h.App.D.Keys, Deps: h.App.D, Metrics: h.App.Metrics}
	internal := httptest.NewServer(server.InternalHandler(env, h.App))
	defer internal.Close()
	get := func(path string) []byte {
		res, err := http.Get(internal.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, res.StatusCode, b)
		}
		return b
	}
	if m := get("/metrics"); !bytes.Contains(m, []byte("proudauth_clock_skew_milliseconds")) {
		t.Fatal("clock skew metric not exported")
	}
	var status map[string]any
	if err := json.Unmarshal(get("/status"), &status); err != nil {
		t.Fatal(err)
	}
	if _, ok := status["clock_skew_ms"].(float64); !ok {
		t.Fatalf("operator status lacks clock_skew_ms: %v", status)
	}

	var tz, now string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT current_setting('TimeZone'), now()::text`).Scan(&tz, &now); err != nil {
		t.Fatal(err)
	}
	if tz != "UTC" || !strings.HasSuffix(now, "+00") {
		t.Fatalf("database session not in UTC: %s %s", tz, now)
	}
	if loc := h.App.D.Now().Location(); loc != time.UTC {
		t.Fatalf("service clock in %v", loc)
	}
}

// TestReplicasShareOneTimeState covers DEP-010: with two server replicas on
// one database, a refresh token, an authorization code and an invitation
// are each consumed exactly once even when requests race across replicas,
// and workers of two processes deliver a notification burst exactly once.
func TestReplicasShareOneTimeState(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	nodes := []*Harness{h, replica(t, h, h.App.D.DB, h.App.D.Keys)}
	race := func(n int, call func(node *Harness) *Resp) (ok int) {
		results := make([]*Resp, n)
		var wg sync.WaitGroup
		for i := range results {
			wg.Add(1)
			go func(i int) { defer wg.Done(); results[i] = call(nodes[i%len(nodes)]) }(i)
		}
		wg.Wait()
		for _, r := range results {
			if r.Status == 200 {
				ok++
			}
		}
		return ok
	}
	web := f.Clients["web"]

	rt := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	if ok := race(6, func(n *Harness) *Resp {
		return n.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, "web-bff", web.Secret)
	}); ok != 1 {
		t.Fatalf("refresh token rotated %d times across replicas", ok)
	}

	code, verifier := f.codeFor(t, "bob")
	if ok := race(6, func(n *Harness) *Resp {
		return n.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {webRedirect}},
			"web-bff", web.Secret)
	}); ok != 1 {
		t.Fatalf("authorization code redeemed %d times across replicas", ok)
	}

	alice := f.AccountToken("alice").Tokens.Str("access_token")
	f.CreateUser("dave")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "dave@example.test",
		"role_ids": []string{f.Roles["orders-viewer"]}}), 201, "invite")
	secret := invitationFromMail(h.Mail("dave@example.test", "invitation"))
	dave := f.AccountToken("dave").Tokens.Str("access_token")
	if ok := race(6, func(n *Harness) *Resp {
		return n.API("POST", "/invitations/accept", dave, map[string]any{"invitation": secret})
	}); ok != 1 {
		t.Fatalf("invitation accepted %d times across replicas", ok)
	}
	var members int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Acme, f.Users["dave"]).Scan(&members)
	if members != 1 {
		t.Fatalf("%d memberships from one invitation", members)
	}

	// Worker ownership: workers of two processes (two per replica) race for
	// one burst in small batches.
	const burst = 60
	for i := 0; i < burst; i++ {
		if _, err := h.App.Notify.EnqueueTx(ctx, h.App.D.DB.Pool, notification.Message{RealmID: h.Realm.ID, Template: notification.TplRecovery,
			Recipient: "burst@example.test", Mandatory: true, Data: map[string]string{"realm": "main"}}); err != nil {
			t.Fatal(err)
		}
	}
	h.Clock.Advance(time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int, n *Harness) {
			defer wg.Done()
			for {
				sent, err := n.App.Notify.DeliverDue(ctx, fmt.Sprintf("worker-%d", i), 3, time.Minute)
				if err != nil {
					t.Errorf("deliver: %v", err)
					return
				}
				if sent == 0 {
					return
				}
			}
		}(i, nodes[i%len(nodes)])
	}
	wg.Wait()
	var delivered, accepted, retried int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM dev_mailbox WHERE recipient='burst@example.test'`).Scan(&delivered)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='accepted'), count(*) FILTER (WHERE attempts <> 1)
		FROM notification_jobs WHERE realm_id=$1 AND template=$2`, h.Realm.ID, notification.TplRecovery).Scan(&accepted, &retried)
	if delivered != burst || accepted != burst || retried != 0 {
		t.Fatalf("burst of %d: %d messages sent, %d jobs accepted, %d claimed more than once", burst, delivered, accepted, retried)
	}
}

// TestNotificationLeases covers DEP-011 for message delivery: a message
// claimed by a worker that crashed stays with that worker until its bounded
// lease expires, is then delivered once by another worker, and is not sent
// again.
func TestNotificationLeases(t *testing.T) {
	h := NewHarness(t)
	h.CreateRealm(nil)
	ctx := context.Background()
	if _, err := h.App.Notify.EnqueueTx(ctx, h.App.D.DB.Pool, notification.Message{RealmID: h.Realm.ID, Template: notification.TplRecovery,
		Recipient: "lease@example.test", Mandatory: true, Data: map[string]string{"realm": "main"}}); err != nil {
		t.Fatal(err)
	}
	h.Clock.Advance(time.Second)
	const lease = time.Minute
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE notification_jobs SET state='attempted', attempts=1, lease_owner='crashed', lease_expires_at=$2
		WHERE realm_id=$1 AND state='queued'`, h.Realm.ID, h.Clock.Now().Add(lease)); err != nil {
		t.Fatal(err)
	}
	sent := func() int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM dev_mailbox WHERE recipient='lease@example.test'`).Scan(&n)
		return n
	}
	if n, err := h.App.Notify.DeliverDue(ctx, "worker-b", 10, lease); err != nil || n != 0 || sent() != 0 {
		t.Fatalf("leased message taken over before its lease expired: %d %v", n, err)
	}
	h.Clock.Advance(lease + time.Second)
	if n, err := h.App.Notify.DeliverDue(ctx, "worker-b", 10, lease); err != nil || n != 1 {
		t.Fatalf("expired lease not reclaimed: %d %v", n, err)
	}
	h.Clock.Advance(time.Hour)
	if n, err := h.App.Notify.DeliverDue(ctx, "worker-b", 10, lease); err != nil || n != 0 || sent() != 1 {
		t.Fatalf("delivered message sent again: %d %v (%d sent)", n, err, sent())
	}
}

// TestWorkerPoolBoundsAndTenantShares covers DEP-015 for background jobs: a
// worker runs at most workers.concurrency jobs at once, and at most
// workers.max_jobs_per_organization of one organization, so a tenant's
// expensive jobs cannot occupy the whole pool while another tenant's job
// waits.
func TestWorkerPoolBoundsAndTenantShares(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Workers.Concurrency = 3
		c.Workers.MaxJobsPerOrganization = 1
	})
	f := fixtureOn(t, h)
	ctx := context.Background()
	svc := jobs.NewService(h.App.D)
	requester := audit.Ref{Type: "operator", ID: "local:test"}
	for i := 0; i < 4; i++ {
		if _, err := svc.Create(ctx, jobs.Spec{RealmID: h.Realm.ID, OrganizationID: f.Acme, Type: "test.expensive", Requester: requester}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.Create(ctx, jobs.Spec{RealmID: h.Realm.ID, OrganizationID: f.Globex, Type: "test.expensive", Requester: requester}); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	running, maxRunning := 0, 0
	perOrg, maxPerOrg := map[string]int{}, 0
	w := worker.New(h.App, "pool")
	w.Handlers = map[string]jobs.Handler{"test.expensive": func(ctx context.Context, j *jobs.Job, _ func(map[string]any) error) (map[string]any, []byte, error) {
		mu.Lock()
		running++
		perOrg[j.OrganizationID]++
		maxRunning = max(maxRunning, running)
		maxPerOrg = max(maxPerOrg, perOrg[j.OrganizationID])
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		running--
		perOrg[j.OrganizationID]--
		mu.Unlock()
		return map[string]any{"ok": true}, nil, nil
	}}
	for i := 0; i < 10; i++ {
		n, err := w.RunJobs(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	var done int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE type='test.expensive' AND state='succeeded'`).Scan(&done)
	if done != 6 || maxRunning > 3 || maxPerOrg != 1 {
		t.Fatalf("jobs done %d, max running %d (bound 3), max per organization %d (bound 1)", done, maxRunning, maxPerOrg)
	}
	if maxRunning < 2 {
		t.Fatalf("the second organization's job waited behind the first's: max running %d", maxRunning)
	}
}

// TestRestoreDrill covers OPS-005, OPS-006 and OPS-014: a backup is restored
// with the protected keys recorded for it (same key-hierarchy fingerprint),
// the revocation log is reconciled before traffic, and a restored instance is
// verified with synthetic accounts: identities, memberships, credentials and
// the policy revision are intact, the signing key is usable, and security
// state changed after the backup (a deleted account, signed-out sessions, a
// revoked invitation) does not reappear. The same backup restored without its
// keys is detected by the fingerprint and cannot sign or become ready.
func TestRestoreDrill(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	f.CreateUser("dave")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.Users["dave"]}), 201, "dave member")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	inv := h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "erin@example.test", "role_ids": []string{f.Roles["orders-viewer"]}})
	mustStatus(t, inv, 201, "invite erin")
	erinInvitation := invitationFromMail(h.Mail("erin@example.test", "invitation"))
	bobRefresh := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
	var policyRevision int64
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT policy_revision FROM realms WHERE id=$1`, h.Realm.ID).Scan(&policyRevision); err != nil {
		t.Fatal(err)
	}
	active, err := h.App.KeyMgr.Active(ctx, h.Realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := h.App.D.Keys.Fingerprint() // recorded with the backup
	since := h.Clock.Now().Add(-time.Second)
	backup := snapshotDatabase(t, h, "drill")

	// After the backup: an account is deleted, a user signs out everywhere and
	// an invitation is revoked; the revocation log is exported independently.
	f.must(f.AdminAPI("DELETE", "/users/"+f.Users["dave"], nil), 204, "delete dave")
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/me/sessions/revoke-all", bob, nil), 200, "bob signs out everywhere")
	mustStatus(t, h.API("POST", "/organizations/"+f.Acme+"/invitations/"+inv.Str("invitation.id")+"/revoke", alice, nil), 204, "revoke invitation")
	var log bytes.Buffer
	if _, err := restore.Export(ctx, h.App.D.DB, since, &log); err != nil {
		t.Fatal(err)
	}

	// Restore with the same keys and reconcile before reopening traffic.
	if _, err := restore.Reconcile(ctx, backup, &log, restore.Options{}, h.Clock.Now(), nil); err != nil {
		t.Fatal(err)
	}
	restored := replica(t, h, backup, h.App.D.Keys)
	if restored.App.D.Keys.Fingerprint() != fingerprint {
		t.Fatal("fingerprint differs for the same keys")
	}
	if k, err := restored.App.KeyMgr.Active(ctx, h.Realm.ID); err != nil || k.KID != active.KID {
		t.Fatalf("restored signing key not usable: %v %v", k, err)
	}
	if st, body := probe(restored, "/health/ready"); st != 200 {
		t.Fatalf("restored instance not ready: %d %v", st, body)
	}
	rf := *f
	rf.H = restored
	lr := rf.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read")
	at := lr.Tokens.Str("access_token")
	if claims := jwtPayload(at); claims["sub"] != f.Users["alice"] || claims["org_id"] != f.Acme {
		t.Fatalf("restored identity or membership wrong: %v", claims)
	}
	if in := restored.Introspect("orders-rs", f.Clients["orders-rs"].Secret, at); in.Status != 200 || in.Get("active") != true {
		t.Fatalf("token from the restored instance not active: %d %s", in.Status, in.Raw)
	}
	var revision int64
	_ = backup.Pool.QueryRow(ctx, `SELECT policy_revision FROM realms WHERE id=$1`, h.Realm.ID).Scan(&revision)
	if revision != policyRevision {
		t.Fatalf("policy revision %d after restore, %d at backup", revision, policyRevision)
	}
	// Security state does not reappear.
	if r := restored.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "dave@example.test", ExpectFail: true}); r.Tokens != nil && r.Tokens.Status == 200 {
		t.Fatal("account deleted after the backup signed in on the restored instance")
	}
	if r := restored.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {bobRefresh}}, "web-bff", f.Clients["web"].Secret); r.Status == 200 {
		t.Fatal("refresh token signed out after the backup works on the restored instance")
	}
	if r := restored.API("POST", "/invitations/inspect", "", map[string]any{"invitation": erinInvitation}); r.Status == 200 {
		t.Fatalf("invitation revoked after the backup is open again on the restored instance: %s", r.Raw)
	}

	// The same backup without its keys (OPS-005).
	other := keys.NewRandom()
	if other.Fingerprint() == fingerprint {
		t.Fatal("fingerprint does not distinguish key hierarchies")
	}
	keyless := replica(t, h, backup, other)
	if _, err := keyless.App.KeyMgr.Active(ctx, h.Realm.ID); err == nil {
		t.Fatal("signing key usable without the backed-up keys")
	}
	if st, _ := probe(keyless, "/health/ready"); st != 503 {
		t.Fatal("restore without its keys reports ready")
	}
}
