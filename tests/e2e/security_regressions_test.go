package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/storage"
)

// Regression fixtures for entries under "Security fixes" in CHANGELOG.md
// (QA-008): each test reproduces the condition the fix closed.

// TestTokenEndpointLimiterFailsClosed covers QA-008 and SEC-006: when the
// token request budget cannot be consulted (its counters are unreachable),
// the token endpoint refuses with 503 temporarily_unavailable instead of
// issuing unbudgeted tokens, and issues again once the limiter is back.
func TestTokenEndpointLimiterFailsClosed(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	batch := f.Clients["batch"]
	mustStatus(t, f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme), 200, "token with a working limiter")

	// A limiter whose counters sit behind a closed pool: every budget check
	// fails as it would with the database unreachable.
	pool, err := pgxpool.NewWithConfig(context.Background(), h.App.D.DB.Pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	deps := *h.App.D
	deps.DB = &storage.DB{Pool: pool}
	working := h.App.OAuth.Limiter
	h.App.OAuth.Limiter = ratelimit.New(&deps)
	t.Cleanup(func() { h.App.OAuth.Limiter = working })

	r := f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme)
	if r.Status != 503 || r.Str("error") != "temporarily_unavailable" || r.Str("access_token") != "" {
		t.Fatalf("token request with an unavailable limiter: %d %s", r.Status, r.Raw)
	}
	h.App.OAuth.Limiter = working
	mustStatus(t, f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme), 200, "token once the limiter is back")
}

// TestConfigImportSecretsNotReplayed covers QA-008 and API-006 (with
// API-005): a configuration import sent with an Idempotency-Key returns the
// generated client secrets once; the response is not kept in
// idempotency_records, and a retry with the same key gets 409 with
// original_status instead of the secrets (and does not import again).
func TestConfigImportSecretsNotReplayed(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	doc := map[string]any{"format": "proudauth.realm-config.v1", "clients": []map[string]any{{"client_id": "imported-idem", "name": "Imported",
		"client_type": "confidential", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://imported.test/cb"}}}}
	importDoc := func() *Resp {
		t.Helper()
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/configuration/imports", Token: f.AdminToken, JSON: doc,
			Headers: map[string]string{"Idempotency-Key": "import-secrets-1"}})
	}
	first := importDoc()
	mustStatus(t, first, 200, "import")
	secret := first.Str("client_secrets.imported-idem")
	if secret == "" {
		t.Fatalf("import returned no generated secret: %s", first.Raw)
	}
	var status *int
	var stored, containsSecret bool
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT status_code, response_body IS NOT NULL, contains_secret FROM idempotency_records
		WHERE realm_id=$1 AND route LIKE '%/configuration/imports'`, h.Realm.ID).Scan(&status, &stored, &containsSecret); err != nil {
		t.Fatalf("idempotency record: %v", err)
	}
	if status == nil || *status != 200 || stored || !containsSecret {
		t.Fatalf("idempotency record: status %v, response stored %v, contains_secret %v", status, stored, containsSecret)
	}
	var leaked int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM idempotency_records WHERE response_body::text LIKE '%' || $1 || '%'`, secret).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("generated client secret stored for replay")
	}
	retry := importDoc()
	if retry.Status != 409 || retry.Get("original_status") != float64(200) || retry.Header.Get("Idempotent-Replayed") == "true" ||
		strings.Contains(string(retry.Raw), secret) || retry.Get("client_secrets") != nil {
		t.Fatalf("retry of a secret-bearing import: %d %s", retry.Status, retry.Raw)
	}
	var n int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM clients WHERE realm_id=$1 AND client_id='imported-idem'`, h.Realm.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("imported client registered %d times", n)
	}
}

// TestConsentRevocationStaysInRealm covers QA-008 and APP-013:
// DELETE /users/{user}/consents/{id} acts only on the realm in its path, so
// an administrator of one realm who knows another realm's user and consent
// IDs cannot revoke that consent (404), while the same request against a
// consent of their own realm succeeds.
func TestConsentRevocationStaysInRealm(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	other, err := h.App.Provision.CreateRealm(ctx, "other", "Other", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatalf("second realm: %v", err)
	}
	victim, err := h.App.Provision.BootstrapAdmin(ctx, "other", "victim@other.test", "victim", time.Hour, false, "tester")
	if err != nil {
		t.Fatalf("second realm user: %v", err)
	}
	var otherClient string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM clients WHERE realm_id=$1 ORDER BY id LIMIT 1`, other.ID).Scan(&otherClient); err != nil {
		t.Fatalf("second realm client: %v", err)
	}
	consent := func(realmID, userID, clientRef string) string {
		t.Helper()
		id := ids.New(ids.Consent)
		if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO consents (id, realm_id, user_id, client_ref, scopes) VALUES ($1,$2,$3,$4,$5)`,
			id, realmID, userID, clientRef, []string{"openid"}); err != nil {
			t.Fatalf("consent: %v", err)
		}
		return id
	}
	live := func(id string) bool {
		t.Helper()
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM consents WHERE id=$1 AND revoked_at IS NULL`, id).Scan(&n)
		return n == 1
	}
	foreign := consent(other.ID, victim.UserID, otherClient)
	// The bootstrap administrator holds realm.users.write in "main" only.
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+victim.UserID+"/consents/"+foreign, nil), 404, "another realm's consent through this realm's path")
	if r := h.Do(Req{Method: "DELETE", Path: "/api/v1/realms/other/users/" + victim.UserID + "/consents/" + foreign, Token: f.AdminToken}); r.Status < 400 {
		t.Fatalf("another realm's path with this realm's token: %d %s", r.Status, r.Raw)
	}
	if !live(foreign) {
		t.Fatal("another realm's consent was revoked")
	}
	own := consent(h.Realm.ID, f.Users["bob"], f.Clients["partner"].Ref)
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+f.Users["bob"]+"/consents/"+own, nil), 204, "own realm's consent")
	if live(own) {
		t.Fatal("own realm's consent not revoked")
	}
}

// TestOrgTemplateAndMailServerRemovalNeedMFA covers QA-008 and MFA-003 (with
// TEN-017 and TEN-022): where the realm waives MFA for organization
// administration, applying an organization template and removing the
// organization's mail server still need an MFA session; a single-factor
// owner may only dry-run the template.
func TestOrgTemplateAndMailServerRemovalNeedMFA(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.MFA.OrgAdminMFAOptional = true })
	h := f.H
	f.must(f.AdminAPI("POST", "/organization-templates", map[string]any{"name": "mfa-check", "document": map[string]any{
		"roles": []map[string]any{{"name": "mfa-check-role", "permissions": []string{"orders.read"}}}}}), 201, "save template")
	smtp := "/organizations/" + f.Acme + "/notification-settings/smtp"
	f.must(f.AdminAPI("PUT", smtp, map[string]any{"host": "smtp.acme.test", "port": 587, "tls_mode": "starttls", "username": "mailer",
		"password": "acme-smtp-secret-123"}), 200, "set mail server")
	apply := func(tok string, dry bool) *Resp {
		t.Helper()
		return h.API("POST", "/organizations/"+f.Acme+"/template-applications", tok, map[string]any{"template": "mfa-check", "dry_run": dry})
	}
	mfaRequired := func(r *Resp, what string) {
		t.Helper()
		if r.Status != 403 || r.Str("code") != "mfa_required" {
			t.Fatalf("%s from a single-factor session: %d %s", what, r.Status, r.Raw)
		}
	}

	alice := f.AccountToken("alice").Tokens.Str("access_token") // Acme owner, password only
	// The waiver is in effect: the single-factor owner passes the org.update check.
	if dry := f.must(apply(alice, true), 200, "dry run under the waiver"); len(dry.Get("create").([]any)) != 1 {
		t.Fatalf("dry-run plan: %s", dry.Raw)
	}
	mfaRequired(apply(alice, false), "applying a template")
	if dry := f.must(apply(alice, true), 200, "dry run after the refusal"); len(dry.Get("create").([]any)) != 1 {
		t.Fatalf("the refused application changed the organization: %s", dry.Raw)
	}
	mfaRequired(h.API("DELETE", smtp, alice, nil), "removing the mail server")
	f.must(f.AdminAPI("GET", smtp, nil), 200, "mail server still configured")

	f.EnrollTOTP("alice")
	alice = f.AccountToken("alice").Tokens.Str("access_token")
	if done := f.must(apply(alice, false), 200, "apply from an MFA session"); done.Get("applied") != true {
		t.Fatalf("apply: %s", done.Raw)
	}
	mustStatus(t, h.API("DELETE", smtp, alice, nil), 204, "remove the mail server from an MFA session")
}
