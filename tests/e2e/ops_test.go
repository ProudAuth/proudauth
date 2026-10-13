package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/proudbase/proudauth/internal/jobs"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/configuration"
	"github.com/proudbase/proudauth/internal/webhooks"
	"github.com/proudbase/proudauth/internal/worker"
)

func allowPrivate(c *configuration.Config) { c.Delivery.AllowPrivateWebhooks = true }

func newOpsFixture(t *testing.T) *Fixture {
	t.Helper()
	h := NewHarness(t, allowPrivate)
	return fixtureOn(t, h)
}

type received struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (rc *received) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	rc.reqs = append(rc.reqs, r)
	rc.body = append(rc.body, b)
	rc.mu.Unlock()
	w.WriteHeader(200)
}

// TestWebhooksAndBackchannelLogout covers EXT-001 (a subscription registers
// its destination and event types, returns its signing secret, and pausing
// and resuming keep its settings), EXT-003 and EXT-004 (receivers verify the
// signature over the exact body, timestamp and event ID; a tampered body, a
// stale timestamp and a wrong key fail; re-running dispatch sends no
// duplicate) and EXT-006 (a private destination is refused at registration
// and again at connection time).
func TestWebhooksAndBackchannelLogout(t *testing.T) {
	f := newOpsFixture(t)
	rc := &received{}
	srv := httptest.NewServer(http.HandlerFunc(rc.handler))
	defer srv.Close()
	sub := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "membership sync", "destination_url": srv.URL + "/hooks",
		"event_types": []string{"organization.membership.removed", "session.revoked"}, "allow_private_network": true}), 201, "webhook")
	sec := sub.Str("signing_secret")
	// PATCH is partial: pausing and resuming keeps the private-network opt-in
	// and payload form instead of resetting them.
	subID := sub.Str("subscription.id")
	paused := f.must(f.AdminAPI("PATCH", "/webhooks/"+subID, map[string]any{"state": "paused"}), 200, "pause")
	if paused.Get("allow_private_network") != true || paused.Str("state") != "paused" {
		t.Fatalf("partial update reset fields: %s", paused.Raw)
	}
	f.must(f.AdminAPI("PATCH", "/webhooks/"+subID, map[string]any{"state": "active"}), 200, "resume")
	// EXT-007: a subscription that did not opt in is refused a private
	// destination at registration, even though the operator allows private
	// webhooks...
	if r := f.AdminAPI("POST", "/webhooks", map[string]any{"name": "public only", "destination_url": srv.URL + "/public",
		"event_types": []string{"organization.membership.removed"}}); r.Status != 422 || !strings.Contains(string(r.Raw), "destination_url") {
		t.Fatalf("private destination without opt-in accepted: %d %s", r.Status, r.Raw)
	}
	// ...and never reaches one at delivery time either, should the destination
	// become private after registration (DNS change, opt-in withdrawn).
	public := f.must(f.AdminAPI("POST", "/webhooks", map[string]any{"name": "public only", "destination_url": srv.URL + "/public",
		"event_types": []string{"organization.membership.removed"}, "allow_private_network": true}), 201, "public webhook")
	if _, err := f.H.App.D.DB.Pool.Exec(context.Background(), `UPDATE webhook_subscriptions SET allow_private_network=false WHERE id=$1`,
		public.Str("subscription.id")); err != nil {
		t.Fatal(err)
	}
	w := worker.New(f.H.App, "test")
	f.must(f.AdminAPI("DELETE", "/organizations/"+f.Globex+"/members/"+f.MemberGlobex["bob"], nil), 204, "remove member")
	for i := 0; i < 3; i++ {
		runWorker(t, w)
	}
	dl := f.must(f.AdminAPI("GET", "/webhooks/"+public.Str("subscription.id")+"/deliveries", nil), 200, "deliveries")
	if len(dl.Get("items").([]any)) == 0 {
		t.Fatal("no delivery recorded for the public-only subscription")
	}
	for _, it := range dl.Get("items").([]any) {
		if d := it.(map[string]any); d["state"] == "delivered" || d["last_response_category"] != "egress_denied" {
			t.Fatalf("subscription without allow_private_network reached a private address: %v", d)
		}
	}
	// EXT-005: the destination's backlog is observable.
	bl := f.must(f.AdminAPI("GET", "/webhooks/"+public.Str("subscription.id")+"/backlog", nil), 200, "backlog")
	if bl.Get("retrying").(float64)+bl.Get("dead_letter").(float64) == 0 || bl.Str("last_failure_category") != "egress_denied" || bl.Get("delivered").(float64) != 0 {
		t.Fatalf("backlog: %s", bl.Raw)
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var found bool
	for i, r := range rc.reqs {
		var env map[string]any
		_ = json.Unmarshal(rc.body[i], &env)
		if env["event_type"] != "organization.membership.removed" {
			continue
		}
		found = true
		// TEST-054: receiver-side verification of the exact body, timestamp and id.
		if err := webhooks.VerifySignature(sec, r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"),
			rc.body[i], f.H.Clock.Now(), 5*time.Minute); err != nil {
			t.Fatalf("signature: %v", err)
		}
		if webhooks.VerifySignature(sec, r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"),
			append(rc.body[i], ' '), f.H.Clock.Now(), 5*time.Minute) == nil {
			t.Fatal("tampered body verified")
		}
		if webhooks.VerifySignature(sec, r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"),
			rc.body[i], f.H.Clock.Now().Add(time.Hour), 5*time.Minute) == nil {
			t.Fatal("replayed (stale) delivery verified")
		}
		if webhooks.VerifySignature("whsec_d3Jvbmc", r.Header.Get("Webhook-Id"), r.Header.Get("Webhook-Timestamp"), r.Header.Get("Webhook-Signature"),
			rc.body[i], f.H.Clock.Now(), 5*time.Minute) == nil {
			t.Fatal("wrong key verified")
		}
		data := env["data"].(map[string]any)
		if data["user_id"] != f.Users["bob"] || env["event_id"] == "" {
			t.Fatalf("envelope: %v", env)
		}
	}
	if !found {
		t.Fatal("membership removal not delivered")
	}
	// Re-running dispatch does not duplicate deliveries (stable event IDs, EXT-002).
	before := len(rc.reqs)
	rc.mu.Unlock()
	runWorker(t, w)
	rc.mu.Lock()
	if len(rc.reqs) != before {
		t.Fatalf("duplicate deliveries after re-run: %d -> %d", before, len(rc.reqs))
	}
}

// TestBackchannelLogoutDelivery covers SES-005's notification half: logging
// out of all devices delivers a signed back-channel logout token to a
// participating application.
func TestBackchannelLogoutDelivery(t *testing.T) {
	f := newOpsFixture(t)
	rc := &received{}
	srv := httptest.NewServer(http.HandlerFunc(rc.handler))
	defer srv.Close()
	// A development client may use a plain-HTTP back-channel endpoint; client
	// environments are fixed at registration (APP-015).
	dev := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "dev-bff", "name": "Dev BFF", "client_type": "confidential", "first_party": true,
		"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{webRedirect},
		"backchannel_logout_uri": srv.URL + "/logout", "environment": "development"}), 201, "development client")
	f.must(f.AdminAPI("PUT", "/clients/"+dev.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}}), 204, "grant")
	lr := f.H.Login(LoginOpts{ClientID: "dev-bff", ClientSecret: dev.Str("client_secret"), RedirectURI: webRedirect, Scope: "orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
	mustStatus(t, lr.Tokens, 200, "development client login")
	acct := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, f.H.API("POST", "/me/sessions/revoke-all", acct, nil), 200, "logout all devices")
	w := worker.New(f.H.App, "test")
	runWorker(t, w)
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if len(rc.reqs) == 0 {
		t.Fatal("no back-channel logout delivered (SES-017)")
	}
	form, _ := url.ParseQuery(string(rc.body[0]))
	lt := form.Get("logout_token")
	parts := strings.Split(lt, ".")
	if len(parts) != 3 {
		t.Fatal("logout token must be a signed JWT")
	}
	if !strings.Contains(decodeSeg(parts[0]), "logout+jwt") || !strings.Contains(decodeSeg(parts[1]), "backchannel-logout") {
		t.Fatalf("logout token claims: %s %s", decodeSeg(parts[0]), decodeSeg(parts[1]))
	}
	_ = lr
}

// Requirements: MIG-015 (submitted import records are protected job input:
// never echoed by the jobs API and erased once the job finishes; downloads
// are requester-bound and single-use), PRV-008 (another user can neither see
// an export job nor obtain its download; the credential is single-use).
func TestExportsImportsAndJobs(t *testing.T) {
	f := newOpsFixture(t)
	w := worker.New(f.H.App, "test")
	ctx := context.Background()
	t.Run("USR-013 self export with protected download", func(t *testing.T) {
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		job := f.H.API("POST", "/me/exports", bob, nil)
		mustStatus(t, job, 202, "export")
		runWorker(t, w)
		st := f.H.API("GET", "/jobs/"+job.Str("job_id"), bob, nil)
		if st.Str("state") != "succeeded" {
			t.Fatalf("job: %s", st.Raw)
		}
		// TEST-069: another user cannot read the job or obtain a download.
		alice := f.AccountToken("alice").Tokens.Str("access_token")
		mustStatus(t, f.H.API("GET", "/jobs/"+job.Str("job_id"), alice, nil), 404, "foreign job")
		mustStatus(t, f.H.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", alice, nil), 404, "foreign download")
		dl := f.H.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", bob, nil)
		mustStatus(t, dl, 201, "download token")
		data := f.H.API("POST", "/job-downloads", bob, map[string]any{"download_token": dl.Str("download_token")})
		mustStatus(t, data, 200, "download")
		body := string(data.Raw)
		if !strings.Contains(body, "bob@example.test") || strings.Contains(body, "$argon2id$") || strings.Contains(body, "alice@") {
			t.Fatal("export must contain only the caller's data and never verifiers")
		}
		mustStatus(t, f.H.API("POST", "/job-downloads", bob, map[string]any{"download_token": dl.Str("download_token")}), 404, "download token reuse")
	})
	t.Run("MIG import: dry run, idempotency, unmapped roles, tombstones", func(t *testing.T) {
		users := []map[string]any{
			{"source_id": "k-1", "email": "imp1@example.test", "email_verified": true, "username": "imp1", "memberships": []map[string]any{{"organization": "acme", "roles": []string{"member"}}}},
			{"source_id": "k-2", "email": "imp2@example.test", "memberships": []map[string]any{{"organization": "acme", "roles": []string{"superadmin"}}}},
			{"source_id": "k-3", "email": "imp3@example.test", "password_hash": "$2a$10$bcrypt-unsupported"},
		}
		dry := f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "keycloak-26", "users": users, "dry_run": true}), 202, "dry run")
		runWorker(t, w)
		res := f.must(f.AdminAPI("GET", "/jobs/"+dry.Str("job_id"), nil), 200, "dry job")
		counts := res.Get("result.counts").(map[string]any)
		if counts["valid"] != float64(1) || counts["error"] != float64(2) {
			t.Fatalf("dry run counts: %s", res.Raw)
		}
		var n int
		_ = f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM user_identifiers WHERE canonical_value='imp1@example.test'`).Scan(&n)
		if n != 0 {
			t.Fatal("dry run mutated state")
		}
		run := func() *Resp {
			j := f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "keycloak-26", "users": users[:1], "trust_email_verification": true,
				"verification_reason": "source verified addresses (ticket 77)"}), 202, "import")
			runWorker(t, w)
			return f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
		}
		first := run()
		if first.Get("result.counts").(map[string]any)["imported"] != float64(1) {
			t.Fatalf("import: %s", first.Raw)
		}
		// Imported records (contact data, password verifiers) are protected job
		// input: never echoed by the jobs API and erased once the job finishes.
		if strings.Contains(string(first.Raw), "imp1@example.test") || first.Get("input.users") != nil {
			t.Fatalf("job API exposes imported records: %s", first.Raw)
		}
		var stored int
		_ = f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE type='user.import' AND (input_ciphertext IS NOT NULL OR input::text LIKE '%imp1@%')`).Scan(&stored)
		if stored != 0 {
			t.Fatal("finished import jobs retain record data")
		}
		// Malformed records are rejected before queuing.
		f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "x", "users": []map[string]any{{"source_id": 7}}}), 400, "typed records")
		second := run()
		if second.Get("result.counts").(map[string]any)["already_imported"] != float64(1) {
			t.Fatalf("source-qualified idempotency: %s", second.Raw)
		}
		// Deleted identities are not resurrected by a later import (MIG-017).
		uid := first.Get("result.results").([]any)[0].(map[string]any)["user_id"].(string)
		f.must(f.AdminAPI("DELETE", "/users/"+uid, nil), 204, "delete imported user")
		j := f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "other-export", "users": users[:1]}), 202, "reimport")
		runWorker(t, w)
		again := f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
		if again.Get("result.counts").(map[string]any)["skipped_deleted"] != float64(1) {
			t.Fatalf("tombstone ignored: %s", again.Raw)
		}
	})
	t.Run("OSS-008 configuration export round trip and atomic import", func(t *testing.T) {
		job := f.must(f.AdminAPI("POST", "/configuration/exports", nil), 202, "config export")
		runWorker(t, w)
		dl := f.must(f.AdminAPI("POST", "/jobs/"+job.Str("job_id")+"/downloads", nil), 201, "download token")
		data := f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
		var doc map[string]any
		if err := json.Unmarshal(data.Raw, &doc); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data.Raw), "pa_cs_") || doc["format"] != "proudauth.realm-config.v1" {
			t.Fatalf("export: %s", data.Raw)
		}
		// Re-importing the export is a no-op.
		plan := f.must(f.AdminAPI("POST", "/configuration/validate", doc), 200, "validate export")
		if len(plan.Get("create").([]any)) != 0 || len(plan.Get("errors").([]any)) != 0 || len(plan.Get("update").([]any)) != 0 ||
			len(plan.Get("drift").([]any)) != 0 {
			t.Fatalf("export does not round-trip: %s", plan.Raw)
		}
		// Existing objects that differ from the document are reported as drift
		// (SDK-012), never rewritten.
		drifted, _ := json.Marshal(doc)
		var dd map[string]any
		_ = json.Unmarshal(drifted, &dd)
		for _, c := range dd["clients"].([]any) {
			if m := c.(map[string]any); m["client_id"] == "web-bff" {
				m["redirect_uris"] = []string{"https://app.test/elsewhere"}
			}
		}
		for _, r := range dd["roles"].([]any) {
			if m := r.(map[string]any); m["name"] == "orders-viewer" {
				m["permissions"] = []string{"orders.read", "orders.refund"}
			}
		}
		dp := f.must(f.AdminAPI("POST", "/configuration/validate", dd), 200, "drift plan")
		if d := fmt.Sprint(dp.Get("drift")); !strings.Contains(d, "client web-bff: redirect_uris differ") || !strings.Contains(d, "role orders-viewer: permissions differ") {
			t.Fatalf("drift not reported: %s", dp.Raw)
		}
		// A new client, permission and role are created together; secrets are
		// returned once.
		spName := ""
		for _, c := range doc["clients"].([]any) {
			if m := c.(map[string]any); m["client_id"] == "batch-job" {
				spName, _ = m["service_principal"].(string)
			}
		}
		if spName == "" {
			t.Fatal("machine client exported without its service principal reference")
		}
		doc["clients"] = append(doc["clients"].([]any), map[string]any{"client_id": "imported-svc", "name": "Imported", "client_type": "machine",
			"environment": "development", "service_principal": spName})
		doc["permissions"] = append(doc["permissions"].([]any), map[string]any{"name": "orders.export"})
		doc["roles"] = append(doc["roles"].([]any), map[string]any{"boundary_type": "organization", "name": "orders-exporter", "permissions": []string{"orders.export"}})
		doc["policy"] = map[string]any{"password": map[string]any{"min_length": 14}}
		// A grant restated without its exchange policy (and with other
		// subject types) is updated but keeps the policy.
		grants := doc["client_resource_grants"].(map[string]any)
		ors, _ := grants["orders-rs"].(map[string]any)
		if ors == nil || ors[f.BillingAud] == nil {
			t.Fatalf("export lacks the exchange grant: %v", grants["orders-rs"])
		}
		prev := ors[f.BillingAud].(map[string]any)
		other := []string{"user", "service_principal"}
		if st, _ := prev["subject_types"].([]any); len(st) == 2 {
			other = []string{"user"}
		}
		ors[f.BillingAud] = map[string]any{"scopes": prev["scopes"], "subject_types": other}
		f.ReloginAdmin()
		// A policy change without the reviewed revision is refused.
		mustStatus(t, f.AdminAPI("POST", "/configuration/imports", doc), 422, "policy change without expected_policy_revision")
		doc["expected_policy_revision"] = f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings").Get("policy_revision")
		out := f.must(f.AdminAPI("POST", "/configuration/imports", doc), 200, "import")
		if !strings.Contains(fmt.Sprint(out.Get("applied")), "grant orders-rs -> "+f.BillingAud) {
			t.Fatalf("grant not updated by the import: %s", out.Raw)
		}
		if out.Str("client_secrets.imported-svc") == "" || len(out.Get("applied").([]any)) < 4 {
			t.Fatalf("import result: %s", out.Raw)
		}
		// Grants the import did not restate keep their exchange policy (TOK-016).
		ex := f.must(f.AdminAPI("GET", "/clients/"+f.Clients["orders-rs"].Ref+"/resource-grants/"+f.Billing, nil), 200, "exchange grant")
		if !strings.Contains(string(ex.Raw), "accept_from_audiences") {
			t.Fatalf("exchange policy lost by the import: %s", ex.Raw)
		}
		settings := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
		if settings.Get("policy.password.min_length") != float64(14) || settings.Get("policy.login.password") != true {
			t.Fatalf("policy merge lost fields or did not apply: %s", settings.Raw)
		}
		// Atomicity: a later failure rolls back earlier creations in the same import.
		bad := map[string]any{"format": "proudauth.realm-config.v1",
			"clients":   []map[string]any{{"client_id": "half-applied", "name": "Half", "client_type": "machine", "environment": "development", "service_principal": spName}},
			"roles":     []map[string]any{{"boundary_type": "organization", "name": "broken", "permissions": []string{"does.not.exist"}}},
			"resources": []any{}, "permissions": []any{}, "client_resource_grants": map[string]any{}}
		if r := f.AdminAPI("POST", "/configuration/imports", bad); r.Status < 400 {
			t.Fatalf("broken import succeeded: %s", r.Raw)
		}
		f.must(f.AdminAPI("GET", "/clients/half-applied", nil), 404, "partial import rolled back")
		// Stale reviewed documents are refused.
		f.must(f.AdminAPI("POST", "/configuration/imports", map[string]any{"policy": map[string]any{}, "expected_policy_revision": 1}), 422, "stale revision")
		// A list in the document replaces the current list whole: a changed
		// list is detected as a change and validation never mutates the live
		// policy.
		identifiers := map[string]any{"policy": map[string]any{"login": map[string]any{"identifiers": []string{"username"}}}}
		checked := f.must(f.AdminAPI("POST", "/configuration/validate", identifiers), 200, "validate list change")
		if !strings.Contains(jsonString(checked.Get("update")), "realm policy") {
			t.Fatalf("list change not detected: %s", checked.Raw)
		}
		if s := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings"); jsonString(s.Get("policy.login.identifiers")) != `["email","username"]` {
			t.Fatalf("validation mutated the live policy: %s", s.Get("policy.login.identifiers"))
		}
	})
	t.Run("TEST-064 organization deletion races issuance and acceptance", func(t *testing.T) {
		alice := f.AccountToken("alice").Tokens.Str("access_token")
		f.CreateUser("gina")
		f.must(f.H.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "gina@example.test"}), 201, "invite")
		secret := invitationFromMail(f.H.Mail("gina@example.test", "invitation"))
		lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
		del := f.must(f.AdminAPI("DELETE", "/organizations/"+f.Acme, nil), 202, "delete org")
		gina := f.AccountToken("gina").Tokens.Str("access_token")
		if r := f.H.API("POST", "/invitations/accept", gina, map[string]any{"invitation": secret}); r.Status == 200 {
			t.Fatal("invitation accepted into a deleting organization")
		}
		r := f.H.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {lr.Tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
		mustStatus(t, r, 400, "refresh into deleted organization")
		// TEST-058: the deletion job is idempotent when retried after completion.
		runWorker(t, w)
		runWorker(t, w)
		if err := f.H.App.Orgs.FinishDeletion(ctx, f.H.Realm.ID, f.Acme); err != nil {
			t.Fatalf("retried deletion step: %v", err)
		}
		job := f.must(f.AdminAPI("GET", "/jobs/"+del.Str("job_id"), nil), 200, "deletion job")
		if job.Str("state") != "succeeded" {
			t.Fatalf("deletion job: %s", job.Raw)
		}
	})
}

var secretPatterns = regexp.MustCompile(`pa_(rt|ac|at|it|inv|tx|ses|cs|key|pat|lnk|dc)_[A-Za-z0-9_-]{20,}|\$argon2id\$|otpauth://|whsec_[A-Za-z0-9+/]{20,}`)

// Requirements: AUD-003 (no token, verifier, OTP seed or signing secret in
// audit or outbox records; TEST-057).
func TestAuditEvidenceAndRedaction(t *testing.T) {
	f := newOpsFixture(t)
	ctx := context.Background()
	f.LoginWeb("alice", f.Acme, f.OrdersAud, "openid orders:read orders:write")
	f.AccountToken("bob")
	f.must(f.AdminAPI("POST", "/clients/"+f.Clients["web"].Ref+"/credentials", map[string]any{}), 201, "rotate secret")
	// TEST-057: no secret-bearing value may appear in audit or outbox storage.
	rows, err := f.H.App.D.DB.Pool.Query(ctx, `SELECT metadata::text FROM audit_events UNION ALL SELECT payload::text FROM outbox_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		if m := secretPatterns.FindString(s); m != "" {
			t.Fatalf("secret material in evidence: %s", m)
		}
	}
	// AUD-008: seal batches and verify the chain; then detect tampering.
	f.H.Clock.Advance(5 * time.Second)
	time.Sleep(2100 * time.Millisecond)
	if _, err := audit.SealBatch(ctx, f.H.App.D.DB, 10000, nil); err != nil {
		t.Fatal(err)
	}
	rep := f.must(f.AdminAPI("GET", "/audit-integrity", nil), 200, "integrity")
	if rep.Get("ok") != true || rep.Get("events_checked").(float64) == 0 {
		t.Fatalf("chain verification: %s", rep.Raw)
	}
	// Normal application access cannot edit history (AUD-007).
	if _, err := f.H.App.D.DB.Pool.Exec(ctx, `UPDATE audit_events SET outcome='failure' WHERE seq=(SELECT min(seq) FROM audit_events)`); err == nil {
		t.Fatal("audit history editable")
	}
	// An operator bypassing the guard is detected by the verification tool.
	_, _ = f.H.App.D.DB.Pool.Exec(ctx, `ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only`)
	_, _ = f.H.App.D.DB.Pool.Exec(ctx, `UPDATE audit_events SET reason_code='TAMPERED' WHERE seq=(SELECT min(seq) FROM audit_events WHERE batch_id IS NOT NULL)`)
	_, _ = f.H.App.D.DB.Pool.Exec(ctx, `ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only`)
	rep2, err := audit.VerifyChain(ctx, f.H.App.D.DB.Pool)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.OK {
		t.Fatal("tampering not detected")
	}
	// AUD-006: organization admins see only their organization's events.
	carol := f.AccountToken("carol").Tokens.Str("access_token")
	ev := f.H.API("GET", "/organizations/"+f.Globex+"/audit-events", carol, nil)
	mustStatus(t, ev, 200, "org audit")
	for _, it := range ev.Get("items").([]any) {
		if org := it.(map[string]any)["org_id"]; org != f.Globex {
			t.Fatalf("foreign organization event visible: %v", org)
		}
	}
	mustStatus(t, f.H.API("GET", "/organizations/"+f.Acme+"/audit-events", carol, nil), 404, "other tenant audit")
}

func decodeSeg(s string) string {
	b, _ := base64URL(s)
	return string(b)
}

// TestJobAuthorityRechecked covers INT-006: an export runs, and its result
// can be fetched, only while the requester still holds the permission the
// job needed; revoking it after enqueueing closes both paths.
func TestJobAuthorityRechecked(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	w := worker.New(h.App, "test")
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "config-exporter",
		"permissions": []string{"realm.configuration.export"}}), 201, "role").Str("id")
	assign := func() string {
		return f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}),
			201, "assign").Str("id")
	}
	revoke := func(id string) { mustStatus(t, f.AdminAPI("DELETE", "/role-assignments/"+id, nil), 204, "revoke") }

	// Revoked before the job runs: the job fails.
	a1 := assign()
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	job := h.API("POST", "/configuration/exports", carol, nil)
	mustStatus(t, job, 202, "export")
	revoke(a1)
	runWorker(t, w)
	if st := f.must(f.AdminAPI("GET", "/jobs/"+job.Str("job_id"), nil), 200, "job"); st.Str("state") == "succeeded" {
		t.Fatalf("export ran after its requester lost the permission: %s", st.Raw)
	}

	// Revoked after the job ran: the result cannot be fetched.
	a2 := assign()
	job = h.API("POST", "/configuration/exports", carol, nil)
	mustStatus(t, job, 202, "export")
	runWorker(t, w)
	if st := f.must(f.AdminAPI("GET", "/jobs/"+job.Str("job_id"), nil), 200, "job"); st.Str("state") != "succeeded" {
		t.Fatalf("export: %s", st.Raw)
	}
	revoke(a2)
	mustStatus(t, h.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", carol, nil), 403, "download after losing the permission")

	// Revoked after the download credential was issued: redeeming it is
	// refused too, and the refusal does not spend the credential.
	a3 := assign()
	job = h.API("POST", "/configuration/exports", carol, nil)
	mustStatus(t, job, 202, "export")
	runWorker(t, w)
	dl := h.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", carol, nil)
	mustStatus(t, dl, 201, "download token")
	revoke(a3)
	redeem := map[string]any{"download_token": dl.Str("download_token")}
	mustStatus(t, h.API("POST", "/job-downloads", carol, redeem), 403, "redeem after losing the permission")
	assign()
	data := h.API("POST", "/job-downloads", carol, redeem)
	mustStatus(t, data, 200, "redeem with the permission")
	if ct, cd := data.Header.Get("Content-Type"), data.Header.Get("Content-Disposition"); ct != "application/json" || !strings.Contains(cd, `"export.json"`) {
		t.Fatalf("configuration export served as %q / %q", ct, cd)
	}
}

// TestServicePrincipalJobDownload: a service principal holding the export
// permission downloads its own job result, and the download is audited with
// the service principal, not a user, as the actor.
func TestServicePrincipalJobDownload(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "config-exporter",
		"permissions": []string{"realm.configuration.export"}}), 201, "role").Str("id")
	sp := f.Clients["orders-rs"].SP
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "service_principal", "id": sp}}), 201, "assign")
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	job := h.API("POST", "/configuration/exports", svc, nil)
	mustStatus(t, job, 202, "export")
	runWorker(t, worker.New(h.App, "test"))
	dl := h.API("POST", "/jobs/"+job.Str("job_id")+"/downloads", svc, nil)
	mustStatus(t, dl, 201, "download token")
	mustStatus(t, h.API("POST", "/job-downloads", svc, map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	var actorType, actorID string
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT actor_type, actor_id FROM audit_events WHERE type='job.result.downloaded' AND target_id=$1`,
		job.Str("job_id")).Scan(&actorType, &actorID); err != nil {
		t.Fatal(err)
	}
	if actorType != "service_principal" || actorID != sp {
		t.Fatalf("download audited as %s %s", actorType, actorID)
	}
}

// TestConditionalSettingsUpdates covers API-010/DB-010 for settings without a
// version column: reads return an entity tag and a stale If-Match is refused.
func TestConditionalSettingsUpdates(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	put := func(path, etag string, body any) *Resp {
		return h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main" + path, Token: f.AdminToken, JSON: body, Headers: map[string]string{"If-Match": etag}})
	}
	grantPath := "/clients/" + f.Clients["web"].Ref + "/resource-grants/" + f.Orders
	g := f.must(f.AdminAPI("GET", grantPath, nil), 200, "grant")
	tag := g.Header.Get("ETag")
	body := map[string]any{"allowed_scopes": []string{"orders:read"}, "subject_types": []string{"user"}}
	mustStatus(t, put(grantPath, tag, body), 204, "fresh If-Match")
	mustStatus(t, put(grantPath, tag, map[string]any{"allowed_scopes": []string{"orders:read", "orders:write"}}), 412, "stale grant If-Match")

	cur := f.must(f.AdminAPI("GET", "/notification-settings", nil), 200, "settings")
	patch := func(etag, name string) *Resp {
		return h.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/notification-settings", Token: f.AdminToken, JSON: map[string]any{"sender_name": name},
			Headers: map[string]string{"If-Match": etag}})
	}
	mustStatus(t, patch(cur.Header.Get("ETag"), "Example"), 204, "fresh settings If-Match")
	mustStatus(t, patch(cur.Header.Get("ETag"), "Other"), 412, "stale settings If-Match")

	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "editable", "permissions": []string{"realm.users.read"}}), 201, "role")
	edit := func(etag string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/roles/" + role.Str("id") + "/permissions", Token: f.AdminToken,
			JSON: map[string]any{"add": []string{"realm.clients.read"}}, Headers: map[string]string{"If-Match": etag}})
	}
	mustStatus(t, edit(`W/"v1"`), 200, "fresh role If-Match")
	mustStatus(t, edit(`W/"v1"`), 412, "stale role If-Match")
}

// TestAuditCorrections covers AUD-007: evidence is corrected by a new event
// linked to the original, never by editing it.
func TestAuditCorrections(t *testing.T) {
	f := NewFixture(t)
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=user.created&limit=1", nil), 200, "events")
	orig := ev.Get("items").([]any)[0].(map[string]any)
	id := orig["id"].(string)
	mustStatus(t, f.AdminAPI("POST", "/audit-events/"+id+"/corrections", map[string]any{"reason": "x"}), 422, "reason required")
	mustStatus(t, f.AdminAPI("POST", "/audit-events/evt_missing/corrections", map[string]any{"reason": "ticket 12: wrong actor recorded"}), 404, "unknown event")
	c := f.must(f.AdminAPI("POST", "/audit-events/"+id+"/corrections", map[string]any{"reason": "ticket 12: imported with the wrong actor",
		"correction": map[string]any{"actor": "migration-tool"}}), 201, "correction")
	if c.Str("corrects_event_id") != id || c.Str("event_id") == "" {
		t.Fatalf("correction: %s", c.Raw)
	}
	linked := f.must(f.AdminAPI("GET", "/audit-events?type=audit.correction&target_id="+id, nil), 200, "linked corrections")
	if len(linked.Get("items").([]any)) != 1 {
		t.Fatalf("correction not linked to the original: %s", linked.Raw)
	}
	again := f.must(f.AdminAPI("GET", "/audit-events?type=user.created&limit=1", nil), 200, "original")
	if fmt.Sprint(again.Get("items").([]any)[0]) != fmt.Sprint(orig) {
		t.Fatal("the original event changed")
	}
}

// TestConfigImportAuthority covers ARC-008: importing configuration needs the
// authority each change needs through the API, not only the import permission.
func TestConfigImportAuthority(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "importer",
		"permissions": []string{"realm.configuration.import"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	doc := map[string]any{"format": "proudauth.realm-config.v1", "clients": []map[string]any{{"client_id": "imported-web", "name": "Imported",
		"client_type": "confidential", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://imported.test/cb"}}}}
	mustStatus(t, h.API("POST", "/configuration/imports", carol, doc), 403, "client creation with the import permission only")
	// Validation and dry runs report what the import would refuse: a plan
	// never says "ok" for it.
	for _, path := range []string{"/configuration/validate", "/configuration/imports?dry_run=true"} {
		r := h.API("POST", path, carol, doc)
		if errs := jsonString(r.Get("errors")); !strings.Contains(errs, "client imported-web: requires realm.clients.write") {
			t.Fatalf("%s did not report the missing authority: %d %s", path, r.Status, r.Raw)
		}
	}
	policy := map[string]any{"policy": map[string]any{"password": map[string]any{"min_length": 15}}}
	if r := f.must(f.AdminAPI("POST", "/configuration/validate", policy), 200, "validate policy change"); !strings.Contains(jsonString(r.Get("errors")), "expected_policy_revision") {
		t.Fatalf("validation accepted a policy change without the reviewed revision: %s", r.Raw)
	}
	writer := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "client-writer",
		"permissions": []string{"realm.clients.write"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": writer, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	mustStatus(t, h.API("POST", "/configuration/imports", carol, doc), 200, "with client authority")
}

// TestForgedJobMetadata covers TEST-063: a queued job that names an arbitrary
// requester, subject or tenant gains nothing — the worker acts only with the
// authority its requester holds when it runs.
func TestForgedJobMetadata(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	svc := jobs.NewService(h.App.D)
	bob := audit.Ref{Type: "user", ID: f.Users["bob"]} // an ordinary member
	var ids []string
	for _, sp := range []jobs.Spec{
		{RealmID: h.Realm.ID, Type: "user.bulk", Requester: bob, Input: map[string]any{"action": "suspend", "user_ids": []string{f.Users["alice"]}, "reason": "forged"}},
		{RealmID: h.Realm.ID, Type: "audit.export", Requester: bob, Input: map[string]any{}},
		{RealmID: h.Realm.ID, Type: "config.export", Requester: bob},
		{RealmID: h.Realm.ID, Type: "user.export", Requester: bob, Input: map[string]any{"user_id": f.Users["alice"]}},
	} {
		var id string
		if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			var err error
			id, err = svc.CreateTx(ctx, tx, sp)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	runWorker(t, worker.New(h.App, "test"))
	for _, id := range ids {
		j, err := svc.Get(ctx, h.Realm.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State != "dead_letter" || j.HasProtectedResult {
			t.Fatalf("forged %s job: %s %s", j.Type, j.State, j.LastError)
		}
	}
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["alice"]).Scan(&state)
	if state != "active" {
		t.Fatalf("forged bulk job changed an account: %s", state)
	}
}

// TestRealmDataExport covers OSS-008 and MIG-014: the realm's identities,
// organizations, memberships, groups, policies and configuration export as
// versioned NDJSON with stable IDs, and no credential secret leaves.
func TestRealmDataExport(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	f.EnrollTOTP("bob")
	allowPrivate(h.App.D.Cfg)
	hook := f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "export-owner", "kind": "authorization.decision",
		"url": "http://127.0.0.1:9/decide", "allow_private_network": true, "owner_user_id": f.Users["alice"]}), 201, "hook").Str("id")
	job := f.must(f.AdminAPI("POST", "/data-exports", nil), 202, "export")
	runWorker(t, worker.New(h.App, "test"))
	st := f.must(f.AdminAPI("GET", "/jobs/"+job.Str("job_id"), nil), 200, "job")
	if st.Str("state") != "succeeded" {
		t.Fatalf("export job: %s", st.Raw)
	}
	dl := f.must(f.AdminAPI("POST", "/jobs/"+job.Str("job_id")+"/downloads", nil), 201, "download token")
	data := f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	if ct, cd := data.Header.Get("Content-Type"), data.Header.Get("Content-Disposition"); ct != "application/x-ndjson" || !strings.Contains(cd, `"export.ndjson"`) {
		t.Fatalf("realm export served as %q / %q", ct, cd)
	}
	if secretPatterns.Match(data.Raw) {
		t.Fatal("realm export contains secret material")
	}
	kinds := map[string]int{}
	var bob map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data.Raw)), "\n") {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("not NDJSON: %v %q", err, line)
		}
		kinds[rec.Kind]++
		if rec.Kind == "header" && !strings.Contains(string(rec.Data), `"proudauth.realm-export.v1"`) {
			t.Fatalf("header: %s", rec.Data)
		}
		if rec.Kind == "user" {
			var u map[string]any
			_ = json.Unmarshal(rec.Data, &u)
			if u["id"] == f.Users["bob"] {
				bob = u
			}
		}
		// Accountable owners (DOM-009) leave with the objects they own.
		if rec.Kind == "hook" {
			var hk map[string]any
			_ = json.Unmarshal(rec.Data, &hk)
			if hk["id"] == hook && hk["owner_user_id"] != f.Users["alice"] {
				t.Fatalf("hook exported without its owner: %s", rec.Data)
			}
		}
		if rec.Kind == "authorization_policy" && !strings.Contains(string(rec.Data), `"owner_user_id"`) {
			t.Fatalf("policy exported without its owner column: %s", rec.Data)
		}
	}
	if kinds["hook"] == 0 {
		t.Fatalf("hook section empty: %v", kinds)
	}
	for _, k := range []string{"header", "configuration", "user", "organization", "membership", "role_assignment"} {
		if kinds[k] == 0 {
			t.Fatalf("section %s missing: %v", k, kinds)
		}
	}
	if bob == nil || !strings.Contains(fmt.Sprint(bob["identifiers"]), "bob@example.test") || bob["credentials"].(map[string]any)["totp"] != true {
		t.Fatalf("bob's record: %v", bob)
	}
	// The permission is privileged and checked again when the job runs.
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/data-exports", carol, nil), 403, "export without realm.data.export")
}

// TestConfigReconcile covers SDK-012: with mode=reconcile an import brings
// existing clients, resources and role permissions to the document's state,
// through the same checks as the API; without it differences are only drift.
func TestConfigReconcile(t *testing.T) {
	f := NewFixture(t)
	w := worker.New(f.H.App, "test")
	job := f.must(f.AdminAPI("POST", "/configuration/exports", nil), 202, "export")
	runWorker(t, w)
	dl := f.must(f.AdminAPI("POST", "/jobs/"+job.Str("job_id")+"/downloads", nil), 201, "download token")
	data := f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	var doc map[string]any
	if err := json.Unmarshal(data.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "policy")
	for _, c := range doc["clients"].([]any) {
		if m := c.(map[string]any); m["client_id"] == "partner-app" {
			m["name"] = "Partner App (reconciled)"
		}
	}
	for _, r := range doc["roles"].([]any) {
		if m := r.(map[string]any); m["name"] == "orders-viewer" {
			m["permissions"] = []string{"orders.read", "billing.read"}
		}
	}
	plan := f.must(f.AdminAPI("POST", "/configuration/validate", doc), 200, "plan")
	if len(plan.Get("drift").([]any)) != 2 || len(plan.Get("update").([]any)) != 0 {
		t.Fatalf("without reconcile differences are drift: %s", plan.Raw)
	}
	out := f.must(f.AdminAPI("POST", "/configuration/imports?mode=reconcile", doc), 200, "reconcile")
	applied := fmt.Sprint(out.Get("applied"))
	if !strings.Contains(applied, "client partner-app") || !strings.Contains(applied, "role orders-viewer") {
		t.Fatalf("reconcile: %s", out.Raw)
	}
	after := f.must(f.AdminAPI("POST", "/configuration/validate", doc), 200, "plan after")
	if len(after.Get("drift").([]any)) != 0 {
		t.Fatalf("drift after reconcile: %s", after.Raw)
	}
	var name string
	_ = f.H.App.D.DB.Pool.QueryRow(context.Background(), `SELECT name FROM clients WHERE client_id='partner-app'`).Scan(&name)
	if name != "Partner App (reconciled)" {
		t.Fatalf("client not reconciled: %q", name)
	}
}

// TestConfigImportResourceAndExchange covers SDK-012 and TOK-016 details: a
// reconcile changes only the resource members a document states (an omitted
// impersonation_enabled keeps support access on), an imported exchange
// policy is validated like the grant API validates it and compared as sets,
// and the grant evidence records the exchange policy.
func TestConfigImportResourceAndExchange(t *testing.T) {
	f := NewFixture(t)
	ctx := context.Background()
	doc := map[string]any{"format": "proudauth.realm-config.v1", "resources": []map[string]any{{"audience": f.OrdersAud, "name": "Orders API (renamed)"}}}
	plan := f.must(f.AdminAPI("POST", "/configuration/validate?mode=reconcile", doc), 200, "plan")
	if u := jsonString(plan.Get("update")); !strings.Contains(u, "resource "+f.OrdersAud) || len(plan.Get("errors").([]any)) != 0 {
		t.Fatalf("plan: %s", plan.Raw)
	}
	f.must(f.AdminAPI("POST", "/configuration/imports?mode=reconcile", doc), 200, "reconcile")
	res := f.must(f.AdminAPI("GET", "/resources/"+f.Orders, nil), 200, "resource")
	if res.Str("name") != "Orders API (renamed)" || res.Get("impersonation_enabled") != true || res.Str("verification_mode") != "strict_online" ||
		!strings.Contains(jsonString(res.Get("impersonation_policy")), "support-contract-1") {
		t.Fatalf("reconcile changed members the document omits: %s", res.Raw)
	}

	// The exchange policy is validated by the grant API and by imports alike.
	web := f.Clients["web"].Ref
	bad := map[string]any{"allowed_scopes": []string{"billing:read"}, "subject_types": []string{"user"},
		"exchange_policy": map[string]any{"accept_from_audiences": []string{f.OrdersAud}, "max_scopes": []string{"billing:nope"}}}
	mustStatus(t, f.AdminAPI("PUT", "/clients/"+web+"/resource-grants/"+f.Billing, bad), 422, "undeclared max_scopes through the API")
	grantDoc := func(ex map[string]any) map[string]any {
		return map[string]any{"format": "proudauth.realm-config.v1", "client_resource_grants": map[string]any{
			"web-bff": map[string]any{f.BillingAud: map[string]any{"scopes": []string{"billing:read"}, "exchange_policy": ex}}}}
	}
	for _, ex := range []map[string]any{{"max_scopes": []string{"billing:nope"}}, {"accept_from_audiences": []string{"https://nowhere.test"}}} {
		r := f.must(f.AdminAPI("POST", "/configuration/validate", grantDoc(ex)), 200, "validate exchange policy")
		if !strings.Contains(jsonString(r.Get("errors")), "exchange_policy") {
			t.Fatalf("invalid exchange policy %v not reported: %s", ex, r.Raw)
		}
		mustStatus(t, f.AdminAPI("POST", "/configuration/imports", grantDoc(ex)), 422, "invalid exchange policy imported")
	}
	// Set comparison: the same audiences in another order are no change.
	mustStatus(t, f.AdminAPI("PUT", "/clients/"+web+"/resource-grants/"+f.Billing, map[string]any{"allowed_scopes": []string{"billing:read"},
		"subject_types": []string{"user"}, "exchange_policy": map[string]any{"accept_from_audiences": []string{f.OrdersAud, f.BillingAud}}}), 204, "grant")
	same := f.must(f.AdminAPI("POST", "/configuration/validate", grantDoc(map[string]any{"accept_from_audiences": []string{f.BillingAud, f.OrdersAud}})), 200, "same set")
	if !strings.Contains(fmt.Sprint(same.Get("unchanged")), "grant web-bff -> "+f.BillingAud) {
		t.Fatalf("reordered exchange audiences reported as a change: %s", same.Raw)
	}
	var meta string
	if err := f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata::text FROM audit_events WHERE type='client.resource_grant.set' AND target_id=$1
		ORDER BY seq DESC LIMIT 1`, web).Scan(&meta); err != nil || !strings.Contains(meta, "accept_from_audiences") {
		t.Fatalf("grant evidence without the exchange policy: %s %v", meta, err)
	}
}

// TestConfigClientProtocolOptions covers APP-019 for protocol options:
// front-channel logout and other per-client protocol settings round-trip
// through export, drift detection and reconcile, and SAML backing clients
// stay out of the document.
func TestConfigClientProtocolOptions(t *testing.T) {
	f := NewFixture(t)
	ctx := context.Background()
	if _, err := f.H.App.D.DB.Pool.Exec(ctx, `UPDATE clients SET protocol_options='{"frontchannel_logout_uri":"https://app.test/fc"}' WHERE client_id='web-bff'`); err != nil {
		t.Fatal(err)
	}
	w := worker.New(f.H.App, "test")
	job := f.must(f.AdminAPI("POST", "/configuration/exports", nil), 202, "export")
	runWorker(t, w)
	dl := f.must(f.AdminAPI("POST", "/jobs/"+job.Str("job_id")+"/downloads", nil), 201, "download token")
	data := f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
	var doc map[string]any
	if err := json.Unmarshal(data.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc, "policy")
	var web map[string]any
	for _, c := range doc["clients"].([]any) {
		if m := c.(map[string]any); m["client_id"] == "web-bff" {
			web = m
		}
	}
	if web == nil || web["frontchannel_logout_uri"] != "https://app.test/fc" {
		t.Fatalf("protocol options not exported: %v", web)
	}
	if strings.Contains(string(data.Raw), "client_secret\"") {
		t.Fatal("client secret in the exported document")
	}
	plan := f.must(f.AdminAPI("POST", "/configuration/validate", doc), 200, "plan")
	if len(plan.Get("drift").([]any)) != 0 {
		t.Fatalf("exported document drifts: %s", plan.Raw)
	}
	web["frontchannel_logout_uri"] = "https://app.test/fc2"
	plan = f.must(f.AdminAPI("POST", "/configuration/validate", doc), 200, "plan with change")
	if !strings.Contains(fmt.Sprint(plan.Get("drift")), "web-bff") {
		t.Fatalf("protocol option change not detected: %s", plan.Raw)
	}
	f.must(f.AdminAPI("POST", "/configuration/imports?mode=reconcile", doc), 200, "reconcile")
	var po string
	_ = f.H.App.D.DB.Pool.QueryRow(ctx, `SELECT protocol_options::text FROM clients WHERE client_id='web-bff'`).Scan(&po)
	if !strings.Contains(po, "https://app.test/fc2") {
		t.Fatalf("protocol options not reconciled: %s", po)
	}
}
