package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/federation"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
)

// gapSecretKeys are JSON member names that would carry secret material or
// its verifier. A read API may name a flag (has_client_secret) or a policy
// object (policy.password) but never return one of these as a string or a
// list of values.
var gapSecretKeys = map[string]bool{
	"verifier": true, "password": true, "password_hash": true, "secret_hash": true, "code_digest": true, "token_digest": true,
	"cookie_digest": true, "secret_digest": true, "secret_ciphertext": true, "private_ciphertext": true, "payload_ciphertext": true,
	"seed": true, "totp_secret": true, "totp_seed": true, "otpauth_uri": true, "refresh_token": true, "id_token": true,
	"access_token": true, "recovery_codes": true, "setup_token": true, "session_cookie": true, "client_secret": true, "secret": true,
}

// gapSecretMembers lists the paths of forbidden members that hold a value.
func gapSecretMembers(v any, path string, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if gapSecretKeys[strings.ToLower(k)] {
				switch vv := val.(type) {
				case string:
					if vv != "" {
						*out = append(*out, path+"."+k)
					}
				case []any:
					if len(vv) > 0 {
						*out = append(*out, path+"."+k)
					}
				}
			}
			gapSecretMembers(val, path+"."+k, out)
		}
	case []any:
		for i, val := range x {
			gapSecretMembers(val, fmt.Sprintf("%s[%d]", path, i), out)
		}
	}
}

// gapNoSecrets fails when a response body (JSON or NDJSON) carries a
// secret-shaped value, one of the known secrets or verifiers, or a member
// named like a secret.
func gapNoSecrets(t *testing.T, what string, raw []byte, needles map[string]string) {
	t.Helper()
	if m := secretPatterns.Find(raw); m != nil {
		t.Errorf("%s: secret-shaped value %.24q...", what, m)
	}
	for name, v := range needles {
		if v != "" && bytes.Contains(raw, []byte(v)) {
			t.Errorf("%s discloses %s", what, name)
		}
	}
	docs := [][]byte{raw}
	if !json.Valid(raw) {
		docs = bytes.Split(raw, []byte("\n"))
	}
	for _, d := range docs {
		if len(bytes.TrimSpace(d)) == 0 {
			continue
		}
		var v any
		if err := json.Unmarshal(d, &v); err != nil {
			t.Errorf("%s: not JSON: %.80s", what, d)
			continue
		}
		var found []string
		gapSecretMembers(v, "$", &found)
		if len(found) > 0 {
			t.Errorf("%s returns secret members %v", what, found)
		}
	}
}

// gapVerifyDomain verifies a domain for an organization with a stubbed DNS
// answer; the caller restores organization.TXTResolver.
func gapVerifyDomain(f *Fixture, org, domain string) {
	f.H.t.Helper()
	ch := f.must(f.AdminAPI("POST", "/organizations/"+org+"/domains", map[string]any{"domain": domain}), 201, "domain "+domain)
	organization.TXTResolver = func(context.Context, string) ([]string, error) { return []string{ch.Str("dns_record_value")}, nil }
	f.must(f.AdminAPI("POST", "/organizations/"+org+"/domains/"+ch.Str("domain.id")+"/verify", nil), 200, "verify "+domain)
}

// gapDownload runs the worker and fetches a job's protected result.
func gapDownload(t *testing.T, f *Fixture, w *worker.Worker, jobID string) *Resp {
	t.Helper()
	runWorker(t, w)
	if st := f.must(f.AdminAPI("GET", "/jobs/"+jobID, nil), 200, "job"); st.Str("state") != "succeeded" {
		t.Fatalf("job %s: %s", jobID, st.Raw)
	}
	dl := f.must(f.AdminAPI("POST", "/jobs/"+jobID+"/downloads", nil), 201, "download token")
	return f.must(f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 200, "download")
}

// TestAdminReadsDiscloseNoSecrets covers CRED-005: once a user has a
// password, an active TOTP with recovery codes, a live session, a refresh
// token and a pending password reset, no administrative read — user search
// and detail (full and support-masked), sessions, consents, linked and
// external identities, the credential inventory, audit and session events,
// organization member views, SCIM, and the realm, configuration and audit
// exports — returns the password, its verifier, the TOTP seed or its
// ciphertext, recovery codes, session or refresh secrets or their digests,
// or the reset code or its verifier.
func TestAdminReadsDiscloseNoSecrets(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	ctx := context.Background()
	bob := f.Users["bob"]
	bobEmail := "bob@example.test"
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()

	// bob is also managed by a SCIM connector (adopted through Acme's
	// verified domain), so the SCIM read API covers him.
	gapVerifyDomain(f, f.Acme, "example.test")
	conn := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "Okta"}), 201, "scim connector")
	scim := func(method, path string, body any) *Resp {
		rq := Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: map[string]string{"Authorization": "Bearer " + conn.Str("token")}}
		if body != nil {
			rq.JSON = body
		}
		return h.Do(rq)
	}
	adopted := scim("POST", "/Users", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "bob",
		"externalId": "okta-bob", "emails": []map[string]any{{"value": bobEmail, "primary": true}}, "active": true})
	if adopted.Status != 201 || adopted.Str("id") != bob {
		t.Fatalf("SCIM adoption of bob: %d %s", adopted.Status, adopted.Raw)
	}

	// The secrets: TOTP with recovery codes, a session with a refresh token,
	// a pending password reset.
	acct := f.AccountToken("bob").Tokens.Str("access_token")
	en := f.must(h.API("POST", "/me/totp/enroll", acct, nil), 201, "totp enroll")
	seed := en.Str("secret")
	h.seeds[bobEmail] = seed
	act := f.must(h.API("POST", "/me/totp/activate", acct, map[string]any{"code": h.TOTPNow(bobEmail)}), 200, "totp activate")
	codes, _ := act.Get("recovery_codes").([]any)
	if len(codes) == 0 {
		t.Fatalf("no recovery codes: %s", act.Raw)
	}
	web := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	if web.Tokens.Str("refresh_token") == "" {
		t.Fatalf("no refresh token issued: %s", web.Tokens.Raw)
	}
	// A browser session as well: its cookie is a reusable session secret.
	b := newBrowser(h)
	_, challenge := PKCE()
	q := url.Values{"client_id": {"web-bff"}, "redirect_uri": {webRedirect}, "response_type": {"code"}, "scope": {"orders:read"}, "state": {"s1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "resource": {f.OrdersAud}, "organization": {f.Acme}}
	loc, _ := url.Parse(b.do("GET", "/realms/main/oauth/authorize?"+q.Encode(), nil, nil).Header.Get("Location"))
	if done := b.drive(t, loc.Query().Get("transaction_id"), bobEmail); done.Str("redirect_to") == "" {
		t.Fatalf("browser sign-in: %s", done.Raw)
	}
	cookie := cookieValue(b, h, "/realms/main/oauth/authorize", "pa_sid")
	if cookie == "" {
		t.Fatal("precondition: no session cookie")
	}
	f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": bobEmail}), 202, "password reset")
	resetCode := CodeFrom(h.Mail(bobEmail, "password_reset"))
	if resetCode == "" {
		t.Fatal("no reset code mailed")
	}

	needles := map[string]string{"the password": h.passwords[bobEmail], "the TOTP seed": seed, "the refresh token": web.Tokens.Str("refresh_token"),
		"the access token": web.Tokens.Str("access_token"), "the account access token": acct, "the reset code": `"` + resetCode + `"`,
		"the session cookie": cookie}
	for i, c := range codes {
		needles[fmt.Sprintf("recovery code %d", i)] = c.(string)
	}
	collect := func(name, query string, args ...any) {
		rows, err := h.App.D.DB.Pool.Query(ctx, query, args...)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			if v != "" {
				needles[fmt.Sprintf("%s %d", name, n)] = v
				n++
			}
		}
		if n == 0 {
			t.Fatalf("precondition: no %s stored", name)
		}
	}
	collect("password verifier", `SELECT verifier FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, bob)
	collect("TOTP seed ciphertext", `SELECT replace(encode(secret_ciphertext,'base64'), E'\n', '') FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'`, bob)
	collect("recovery code digest", `SELECT code_digest FROM recovery_codes WHERE user_id=$1 AND state='active'`, bob)
	collect("refresh token digest", `SELECT token_digest FROM refresh_tokens WHERE realm_id=$1`, h.Realm.ID)
	collect("reset verifier", `SELECT verifier FROM challenges WHERE user_id=$1 AND purpose='password_reset' AND consumed_at IS NULL`, bob)
	collect("session cookie digest", `SELECT cookie_digest FROM sessions WHERE user_id=$1 AND state='active' AND cookie_digest IS NOT NULL`, bob)

	f.ReloginAdmin()
	membership := f.MemberAcme["bob"]
	paths := []string{
		"/users", "/users?q=" + url.QueryEscape(bobEmail), "/users/" + bob, "/users/" + bob + "/sessions", "/users/" + bob + "/consents",
		"/users/" + bob + "/consents?history=true", "/users/" + bob + "/linked-identities", "/users/" + bob + "/external-ids",
		"/users/" + bob + "/attribute-authority", "/subjects/" + bob + "/permissions", "/credential-inventory",
		"/audit-events", "/audit-events?subject_id=" + bob, "/session-events",
		"/organizations/" + f.Acme + "/members", "/organizations/" + f.Acme + "/members/" + membership,
		"/organizations/" + f.Acme + "/members/" + membership + "/permissions", "/organizations/" + f.Acme + "/audit-events",
	}
	for _, p := range paths {
		r := f.AdminAPI("GET", p, nil)
		if r.Status != 200 {
			t.Errorf("GET %s: %d %s", p, r.Status, r.Raw)
			continue
		}
		gapNoSecrets(t, "GET "+p, r.Raw, needles)
	}
	// The organization's own administrator and the support operator's
	// masked view.
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	for _, p := range []string{"/organizations/" + f.Acme + "/members", "/organizations/" + f.Acme + "/members/" + membership} {
		r := h.API("GET", p, alice, nil)
		mustStatus(t, r, 200, "organization owner reads "+p)
		gapNoSecrets(t, "GET "+p+" (organization owner)", r.Raw, needles)
	}
	sam := f.AdminTokenFor("sam").Tokens.Str("access_token")
	for _, p := range []string{"/users", "/users/" + bob} {
		r := h.API("GET", p, sam, nil)
		mustStatus(t, r, 200, "support operator reads "+p)
		gapNoSecrets(t, "GET "+p+" (support operator)", r.Raw, needles)
	}
	// No administrative API lists one user's factors; the account's own
	// factor list (metadata only) is checked as well.
	fresh := f.AccountToken("bob").Tokens.Str("access_token")
	needles["the fresh account token"] = fresh
	for _, p := range []string{"/me/credentials", "/me/sessions", "/me"} {
		r := h.API("GET", p, fresh, nil)
		mustStatus(t, r, 200, "bob reads "+p)
		gapNoSecrets(t, "GET "+p+" (account owner)", r.Raw, needles)
	}
	// SCIM reads.
	for _, p := range []string{"/Users", "/Users/" + bob, "/Users?filter=" + url.QueryEscape(`userName eq "bob"`)} {
		r := scim("GET", p, nil)
		mustStatus(t, r, 200, "SCIM GET "+p)
		gapNoSecrets(t, "SCIM GET "+p, r.Raw, needles)
	}
	// Exports: the realm's data, its configuration and its audit trail.
	w := worker.New(h.App, "test")
	for _, ex := range []struct{ path string }{{"/data-exports"}, {"/configuration/exports"}, {"/audit-exports"}} {
		job := f.must(f.AdminAPI("POST", ex.path, map[string]any{}), 202, "export "+ex.path)
		data := gapDownload(t, f, w, job.Str("job_id"))
		if ex.path == "/data-exports" && !bytes.Contains(data.Raw, []byte(bob)) {
			t.Fatal("the realm export does not contain bob: the sweep proves nothing")
		}
		gapNoSecrets(t, "export "+ex.path, data.Raw, needles)
	}
	// The secrets were live throughout: the refresh token still works.
	r := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {web.Tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	mustStatus(t, r, 200, "refresh after the sweep")
}

// TestCompromisedAccountRecovery covers MFA-008 and CRED-008 for the
// compromised-account path: an administrator marks the password
// compromised, which changes the credential's state, revokes every session
// and offline grant, records the audit event and outbox signal, and leaves
// a password reset as the only way back in.
func TestCompromisedAccountRecovery(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	bob, email := f.Users["bob"], "bob@example.test"
	acct := f.AccountToken("bob").Tokens.Str("access_token")
	web := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
	if web.Tokens.Str("refresh_token") == "" {
		t.Fatalf("no offline grant: %s", web.Tokens.Raw)
	}
	if n := len(f.must(f.AdminAPI("GET", "/users/"+bob+"/sessions", nil), 200, "sessions").Get("items").([]any)); n < 2 {
		t.Fatalf("precondition: %d sessions", n)
	}
	before := auditCount(t, h, "credential.password.compromised", "")
	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/credentials/password/compromised", map[string]any{"reason": "BREACH_CORPUS_MATCH"}), 204, "mark compromised")

	var state string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM credentials WHERE user_id=$1 AND type='password' ORDER BY updated_at DESC LIMIT 1`, bob).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "compromised" {
		t.Fatalf("password credential state %q", state)
	}
	if r := h.API("GET", "/me", acct, nil); r.Status != 401 {
		t.Fatalf("session survived the compromise: %d", r.Status)
	}
	if items := f.must(f.AdminAPI("GET", "/users/"+bob+"/sessions", nil), 200, "sessions").Get("items").([]any); len(items) != 0 {
		t.Fatalf("active sessions after the compromise: %d", len(items))
	}
	refresh := h.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {web.Tokens.Str("refresh_token")}}, "web-bff", f.Clients["web"].Secret)
	if refresh.Status != 400 || refresh.Str("error") != "invalid_grant" {
		t.Fatalf("offline grant survived the compromise: %d %s", refresh.Status, refresh.Raw)
	}
	var actorType, actorID, subject, reason string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT actor_type, actor_id, coalesce(subject_id,''), coalesce(reason_code,'') FROM audit_events
		WHERE type='credential.password.compromised' ORDER BY seq DESC LIMIT 1`).Scan(&actorType, &actorID, &subject, &reason); err != nil {
		t.Fatal(err)
	}
	if auditCount(t, h, "credential.password.compromised", "")-before != 1 || actorType != "user" || actorID != f.Users["admin"] || subject != bob ||
		reason != "BREACH_CORPUS_MATCH" {
		t.Fatalf("compromise evidence: actor %s %s, subject %s, reason %q", actorType, actorID, subject, reason)
	}
	var signals int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE event_type='security.credential_compromised' AND aggregate_id=$1`, bob).Scan(&signals)
	if signals != 1 {
		t.Fatalf("security.credential_compromised published %d times", signals)
	}
	// The compromised password never authenticates; marking again finds no
	// active password.
	if r := passwordStep(h, email, h.passwords[email]); r.Status != 401 || r.Str("code") != "invalid_credentials" {
		t.Fatalf("compromised password accepted: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+bob+"/credentials/password/compromised", map[string]any{"reason": "again"}), 404, "no active password left")
	// Recovery: a password reset to the verified address restores access.
	req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": email}), 202, "reset")
	pw := "bob recovered after the breach 2026"
	f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"),
		"code": CodeFrom(h.Mail(email, "password_reset")), "new_password": pw}), 200, "reset complete")
	h.SetPassword(email, pw)
	mustStatus(t, f.AccountToken("bob").Tokens, 200, "sign-in after recovery")
}

// TestLostContactAndFactorRecovery covers MFA-008 for the lost contact
// address and lost factor paths. Lost contact address: with administrator
// calls only (the owner does not sign in until she holds the setup link), the
// new address is added unverified with a reason, cannot become primary before
// the verification override (its own permission and reason, USR-005), then
// becomes primary; every step is audited with the administrator and the
// reason, the old address is told about the changes without learning the new
// address (USR-004), and assisted recovery delivers the single-use setup link
// to the new primary address and not to the lost one. Lost factor: reset_mfa
// revokes every factor and requires TOTP enrollment at the next sign-in.
// TestAdminIdentifierChangeGuards covers the refusals.
func TestLostContactAndFactorRecovery(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()

	t.Run("lost contact address", func(t *testing.T) {
		lena := f.CreateUser("lena")
		oldAddr, newAddr := "lena@example.test", "lena.new@example.test"
		const reason = "identity proofed by video call, ticket 9001"
		idents := "/users/" + lena + "/identifiers"
		count := func(q string, args ...any) int {
			t.Helper()
			h.Deliver()
			var n int
			if err := h.App.D.DB.Pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		mails := func(addr, tpl string) int {
			return count(`SELECT count(*) FROM dev_mailbox WHERE lower(recipient)=lower($1) AND template=$2`, addr, tpl)
		}
		var oldID string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT id FROM user_identifiers WHERE user_id=$1 AND type='email' AND is_primary`, lena).Scan(&oldID)
		noticesBefore := mails(oldAddr, "identifier_changed")

		mustStatus(t, f.AdminAPI("POST", idents, map[string]any{"type": "email", "value": newAddr}), 422, "add without a reason")
		carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
		if r := h.API("POST", idents, carol, map[string]any{"type": "email", "value": newAddr, "reason": reason}); r.Status != 403 || r.Str("code") != "forbidden" {
			t.Fatalf("add without the recovery permissions: %d %s", r.Status, r.Raw)
		}
		added := f.must(f.AdminAPI("POST", idents, map[string]any{"type": "email", "value": newAddr, "reason": reason}), 201, "add the new address")
		idf := added.Str("id")
		if added.Get("verified") != false || added.Get("is_primary") != false {
			t.Fatalf("an added address must start unverified and not primary: %s", added.Raw)
		}
		// USR-004: the old address hears of each change, never of the new
		// address itself; the new address gets no notice.
		notice := func(want int, about string) {
			t.Helper()
			if n := mails(oldAddr, "identifier_changed"); n != noticesBefore+want {
				t.Fatalf("change notices to the old address: %d, want %d", n, noticesBefore+want)
			}
			if body := h.Mail(oldAddr, "identifier_changed"); !strings.Contains(body, about) || strings.Contains(body, newAddr) {
				t.Fatalf("change notice: %q", body)
			}
			if n := mails(newAddr, "identifier_changed"); n != 0 {
				t.Fatalf("the new address received %d change notices", n)
			}
		}
		notice(1, "added an email address")
		promote := func(reason string) *Resp {
			return f.AdminAPI("POST", idents+"/"+idf+"/primary", map[string]any{"reason": reason})
		}
		mustStatus(t, promote(reason), 422, "unverified address made primary")
		mustStatus(t, f.AdminAPI("POST", "/users/"+lena+"/verification-overrides", map[string]any{"identifier_id": idf}), 422, "override without a reason")
		if r := h.API("POST", "/users/"+lena+"/verification-overrides", carol, map[string]any{"identifier_id": idf, "reason": reason}); r.Status != 403 {
			t.Fatalf("override without realm.users.verification.override: %d %s", r.Status, r.Raw)
		}
		mustStatus(t, f.AdminAPI("POST", "/users/"+lena+"/verification-overrides", map[string]any{"identifier_id": idf, "reason": reason}), 204, "override")
		var source string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(verification_source,'') FROM user_identifiers WHERE id=$1 AND verified_at IS NOT NULL`, idf).Scan(&source)
		if source != "admin_override" {
			t.Fatalf("new address not verified by the override: %q", source)
		}
		mustStatus(t, promote(""), 422, "primary change without a reason")
		mustStatus(t, promote(reason), 204, "new address becomes primary")
		mustStatus(t, promote(reason), 409, "already primary")
		notice(2, "primary contact")

		// Evidence: each step names the administrator, the identifier and the reason.
		for _, typ := range []string{"user.identifier.added", "user.identifier.verification_overridden", "user.identifier.primary_changed"} {
			var actor, why, ident string
			_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT actor_id, coalesce(metadata->>'reason',''), coalesce(metadata->>'identifier_id','') FROM audit_events
				WHERE type=$1 AND subject_id=$2 ORDER BY seq DESC LIMIT 1`, typ, lena).Scan(&actor, &why, &ident)
			if actor != f.Users["admin"] || why != reason || ident != idf {
				t.Fatalf("%s evidence: actor %q, reason %q, identifier %q", typ, actor, why, ident)
			}
		}
		var previous string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(metadata->>'previous_identifier_id','') FROM audit_events
			WHERE type='user.identifier.primary_changed' AND subject_id=$1`, lena).Scan(&previous)
		if oldID == "" || previous != oldID {
			t.Fatalf("primary change evidence names %q as the previous address, want %q", previous, oldID)
		}

		if n := count(`SELECT count(*) FROM sessions WHERE user_id=$1`, lena); n != 0 {
			t.Fatalf("the owner signed in before recovery: %d sessions", n)
		}
		oldBefore := mails(oldAddr, "account_setup")
		rec := f.must(f.AdminAPI("POST", "/users/"+lena+"/recovery-requests", map[string]any{"reason": "lost access to her old mailbox",
			"evidence_reference": "ticket 9001"}), 202, "assisted recovery")
		if rec.Str("status") != "recovery_started" || rec.Get("setup_token") != nil {
			t.Fatalf("assisted recovery: %s", rec.Raw)
		}
		if mails(newAddr, "account_setup") != 1 || mails(oldAddr, "account_setup") != oldBefore {
			t.Fatalf("setup link not sent to the new address only: new %d, old %d -> %d", mails(newAddr, "account_setup"), oldBefore,
				mails(oldAddr, "account_setup"))
		}
		pw := "lena chose a new passphrase 2026"
		f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": CodeFrom(h.Mail(newAddr, "account_setup")), "password": pw}), 200, "setup")
		h.SetPassword(newAddr, pw)
		lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: newAddr})
		mustStatus(t, lr.Tokens, 200, "sign-in with the new address")
		var evActor, evSubject string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT actor_id, subject_id FROM audit_events WHERE type='recovery.assisted' AND subject_id=$1`, lena).Scan(&evActor, &evSubject)
		if evActor != f.Users["admin"] || evSubject != lena {
			t.Fatalf("recovery.assisted evidence: %s -> %s", evActor, evSubject)
		}
	})

	t.Run("lost factor: reset_mfa", func(t *testing.T) {
		f.ReloginAdmin()
		mike := f.CreateUser("mike")
		email := "mike@example.test"
		f.EnrollTOTP("mike")
		count := func(q string) int {
			var n int
			if err := h.App.D.DB.Pool.QueryRow(ctx, q, mike).Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
		if count(`SELECT count(*) FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'`) != 1 ||
			count(`SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active'`) == 0 {
			t.Fatal("precondition: TOTP and recovery codes")
		}
		tok := f.AccountToken("mike").Tokens.Str("access_token")
		f.must(f.AdminAPI("POST", "/users/"+mike+"/recovery-requests", map[string]any{"reason": "lost phone, identity verified in person",
			"evidence_reference": "ticket 9002", "reset_mfa": true}), 202, "reset MFA")
		if n := count(`SELECT count(*) FROM credentials WHERE user_id=$1 AND type IN ('totp','hotp') AND state='active'`); n != 0 {
			t.Fatalf("%d second factors still active", n)
		}
		if n := count(`SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND state='active'`); n != 0 {
			t.Fatalf("%d recovery codes still active", n)
		}
		var actions []string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT required_actions FROM users WHERE id=$1`, mike).Scan(&actions)
		if !slices.Contains(actions, "configure_totp") {
			t.Fatalf("required actions after reset_mfa: %v", actions)
		}
		if r := h.API("GET", "/me", tok, nil); r.Status != 401 {
			t.Fatalf("session survived reset_mfa: %d", r.Status)
		}
		pw := "mike chose a new passphrase 2026"
		f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": CodeFrom(h.Mail(email, "account_setup")), "password": pw}), 200, "setup")
		h.SetPassword(email, pw)
		// The next sign-in must enroll a new TOTP; the old one is not offered.
		start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": email})
		st := h.Step(tx, cont, "password", map[string]any{"password": pw})
		if acts := actionTypes(st); !has(acts, "enroll_totp") || has(acts, "totp") || st.Str("redirect_to") != "" {
			t.Fatalf("sign-in after reset_mfa: %v %s", acts, st.Raw)
		}
	})
}

// TestDirectoryManagedPasswordReset covers MFA-008 for directory-managed
// accounts: ProudAuth does not reset a password an LDAP connector owns. The
// reset request still answers generically, but completing it is refused with
// 409 externally_managed, the account's state and sessions are untouched and
// no completion is recorded.
func TestDirectoryManagedPasswordReset(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	w := worker.New(h.App, "dir-worker")
	saved := organization.TXTResolver
	defer func() { organization.TXTResolver = saved }()
	// Acme's verified domain makes the directory's address verified, so a
	// reset code can be delivered at all.
	gapVerifyDomain(f, f.Acme, "corp.test")
	srv := corpDirectory(t)
	addPerson(srv, "jdoe", "Jane", "Doe", "jdoe@corp.test", "jdoe directory pass")
	cfg := map[string]any{"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase,
		"user_base_dn": "ou=people," + corpBase}
	orgPath := "/organizations/" + f.Acme + "/directory-connectors"
	created := f.must(f.AdminAPI("POST", orgPath, map[string]any{"name": "Acme LDAP", "kind": "ldap", "config": cfg, "credential": "service secret"}), 201, "connector")
	if run := f.dirRun(t, w, orgPath+"/"+created.Str("id"), map[string]any{"mode": "full"}); count(run, "create") != 1 {
		t.Fatalf("import: %s", run.Raw)
	}
	jdoe := userIDByUsername(t, h, "jdoe")
	req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "jdoe@corp.test"}), 202, "reset request")
	code := CodeFrom(h.Mail("jdoe@corp.test", "password_reset"))
	if code == "" {
		t.Fatal("precondition: the directory-managed account's verified address received no reset code")
	}
	r := h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": req.Str("reset_id"), "code": code, "new_password": "a local password 2026 jane"})
	if r.Status != 409 || r.Str("code") != "conflict" || !slices.Contains(toStrings(r.Get("externally_managed")), "password") ||
		r.Str("connector_id") != created.Str("id") {
		t.Fatalf("reset of a directory-managed password: %d %s", r.Status, r.Raw)
	}
	if n := auditCount(t, h, "recovery.password_reset.completed", ""); n != 0 {
		t.Fatalf("refused reset recorded as completed (%d)", n)
	}
	var local int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, jdoe).Scan(&local)
	if local != 0 {
		t.Fatal("a local password was stored for a directory-managed account")
	}
}

// TestSecurityAuditCoverage covers AUD-002: each security-relevant action
// writes exactly one audit event of its type, attributed to the acting
// principal and naming the affected account or object (as subject or
// target): password reset request and completion, assisted recovery,
// password change, compromise marking, TOTP enrollment, invitation creation
// and revocation, role creation and permission change, client creation,
// update and secret issuance, SCIM provisioning and directory provisioning.
func TestSecurityAuditCoverage(t *testing.T) {
	f := directoryHarness(t)
	h := f.H
	ctx := context.Background()
	admin := f.Users["admin"]
	lastSeq := func() int64 {
		var s int64
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(max(seq),0) FROM audit_events`).Scan(&s)
		return s
	}
	var resetID, resetCode, roleID, roleETag, clientRef, invitationID string
	clientBody := map[string]any{"client_id": "audit-probe", "name": "Audit probe", "client_type": "confidential",
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://probe.test/cb"}}
	scimConn := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "Okta"}), 201, "scim connector")
	srv := corpDirectory(t)
	addPerson(srv, "dirk", "Dirk", "Dir", "dirk@corp.test", "dirk directory pass")
	dirConn := f.must(f.AdminAPI("POST", "/directory-connectors", map[string]any{"name": "Corp LDAP", "kind": "ldap", "config": map[string]any{
		"endpoints": []string{srv.URL()}, "ca_certificates_pem": srv.CAPEM(), "bind_dn": "cn=svc," + corpBase, "user_base_dn": "ou=people," + corpBase},
		"credential": "service secret"}), 201, "directory connector")
	f.CreateUser("dana")
	alicePW := "alice changes her passphrase 2026"

	cases := []struct {
		event string
		// act performs the action and returns the expected actor type, actor
		// ID and affected subject or target ID.
		act func(t *testing.T) (actorType, actorID, object string)
	}{
		{"recovery.password_reset.requested", func(t *testing.T) (string, string, string) {
			r := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"}), 202, "reset")
			resetID, resetCode = r.Str("reset_id"), CodeFrom(h.Mail("bob@example.test", "password_reset"))
			return "anonymous", "public", f.Users["bob"]
		}},
		{"recovery.password_reset.completed", func(t *testing.T) (string, string, string) {
			f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": resetID, "code": resetCode,
				"new_password": "bob reset his passphrase 2026"}), 200, "reset complete")
			return "user", f.Users["bob"], f.Users["bob"]
		}},
		{"credential.password.changed", func(t *testing.T) (string, string, string) {
			tok := f.AccountToken("alice").Tokens.Str("access_token")
			f.must(h.API("POST", "/me/password", tok, map[string]any{"current_password": h.passwords["alice@example.test"], "new_password": alicePW}), 200, "change")
			h.SetPassword("alice@example.test", alicePW)
			return "user", f.Users["alice"], f.Users["alice"]
		}},
		{"mfa.totp.enrolled", func(t *testing.T) (string, string, string) {
			f.EnrollTOTP("dana")
			return "user", f.Users["dana"], f.Users["dana"]
		}},
		{"credential.password.compromised", func(t *testing.T) (string, string, string) {
			f.ReloginAdmin()
			mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/credentials/password/compromised", map[string]any{"reason": "phished"}), 204, "compromised")
			return "user", admin, f.Users["carol"]
		}},
		{"recovery.assisted", func(t *testing.T) (string, string, string) {
			f.must(f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/recovery-requests", map[string]any{"reason": "re-proofed after phishing",
				"evidence_reference": "incident 12"}), 202, "assisted recovery")
			return "user", admin, f.Users["carol"]
		}},
		{"invitation.created", func(t *testing.T) (string, string, string) {
			r := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/invitations", map[string]any{"email": "invitee@example.test"}), 201, "invite")
			invitationID = r.Str("invitation.id")
			return "user", admin, invitationID
		}},
		{"invitation.revoked", func(t *testing.T) (string, string, string) {
			mustStatus(t, f.AdminAPI("POST", "/organizations/"+f.Acme+"/invitations/"+invitationID+"/revoke", nil), 204, "revoke")
			return "user", admin, invitationID
		}},
		{"role.created", func(t *testing.T) (string, string, string) {
			r := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "audit-probe", "permissions": []string{"realm.users.read"}}),
				201, "role")
			roleID, roleETag = r.Str("id"), r.Header.Get("ETag")
			return "user", admin, roleID
		}},
		{"role.permissions.changed", func(t *testing.T) (string, string, string) {
			f.must(h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/roles/" + roleID + "/permissions", Token: f.AdminToken,
				JSON: map[string]any{"add": []string{"realm.audit.read"}}, Headers: map[string]string{"If-Match": roleETag}}), 200, "permissions")
			return "user", admin, roleID
		}},
		{"client.created", func(t *testing.T) (string, string, string) {
			r := f.must(f.AdminAPI("POST", "/clients", clientBody), 201, "client")
			clientRef = r.Str("client.id")
			return "user", admin, clientRef
		}},
		{"client.updated", func(t *testing.T) (string, string, string) {
			cur := f.must(f.AdminAPI("GET", "/clients/"+clientRef, nil), 200, "client")
			clientBody["name"] = "Audit probe (renamed)"
			f.must(h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/clients/" + clientRef, Token: f.AdminToken, JSON: clientBody,
				Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "update")
			return "user", admin, clientRef
		}},
		{"client.credential.issued", func(t *testing.T) (string, string, string) {
			f.must(f.AdminAPI("POST", "/clients/"+clientRef+"/credentials", map[string]any{}), 201, "secret")
			return "user", admin, clientRef
		}},
		{"scim.user.provisioned", func(t *testing.T) (string, string, string) {
			r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/scim/v2/Users", Headers: map[string]string{"Authorization": "Bearer " + scimConn.Str("token")},
				JSON: map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "scim.probe", "externalId": "okta-probe",
					"emails": []map[string]any{{"value": "probe@acme-corp.test", "primary": true}}, "active": true}})
			mustStatus(t, r, 201, "scim create")
			return "connector", scimConn.Str("connector.id"), r.Str("id")
		}},
		{"directory.user.provisioned", func(t *testing.T) (string, string, string) {
			run := f.dirRun(t, worker.New(h.App, "dir-worker"), "/directory-connectors/"+dirConn.Str("id"), map[string]any{"mode": "full"})
			if count(run, "create") != 1 {
				t.Fatalf("directory run: %s", run.Raw)
			}
			return "connector", dirConn.Str("id"), userIDByUsername(t, h, "dirk")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.event, func(t *testing.T) {
			from := lastSeq()
			wantType, wantActor, object := tc.act(t)
			if object == "" {
				t.Fatal("the action produced no object ID")
			}
			rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT actor_type, actor_id, coalesce(subject_id,''), coalesce(target_id,''), outcome
				FROM audit_events WHERE type=$1 AND seq > $2 ORDER BY seq`, tc.event, from)
			if err != nil {
				t.Fatal(err)
			}
			type row struct{ actorType, actorID, subject, target, outcome string }
			got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
				var x row
				err := r.Scan(&x.actorType, &x.actorID, &x.subject, &x.target, &x.outcome)
				return x, err
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("%d %s events, want exactly one", len(got), tc.event)
			}
			e := got[0]
			if e.actorType != wantType || e.actorID != wantActor || (e.subject != object && e.target != object) || e.outcome != "success" {
				t.Fatalf("%s: actor %s %s, subject %q, target %q, outcome %s; want actor %s %s about %s", tc.event, e.actorType, e.actorID,
					e.subject, e.target, e.outcome, wantType, wantActor, object)
			}
		})
	}
}

// TestNoCrossRealmConvergence covers DOM-006: a second realm holding an
// account with the same email address as main's alice stays a separate
// identity domain. A merge proposal naming the other realm's account is
// refused, main's administrator token is not accepted by the other realm's
// API, and a federated sign-in in the other realm presenting alice's
// verified address never links to, or reveals, main's account.
func TestNoCrossRealmConvergence(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	operator := audit.Ref{Type: "operator", ID: "test"}
	pol := realm.DefaultPolicy()
	pol.Registration.Mode = realm.RegistrationPublic
	other, err := h.App.Provision.CreateRealm(ctx, "other", "Other", pol, operator)
	if err != nil {
		t.Fatal(err)
	}
	var twin *identity.User
	if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		twin, err = h.App.Users.CreateTx(ctx, tx, other.ID, identity.CreateInput{Email: "alice@example.test", EmailVerified: true,
			VerificationSource: "test", DisplayName: "Alice (other realm)", State: identity.StateActive, CreatedVia: "admin"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	alice := f.Users["alice"]

	// Merging across realms is refused in both directions.
	f.ReloginAdmin()
	for _, p := range []struct{ target, source string }{{alice, twin.ID}, {twin.ID, alice}} {
		r := f.AdminAPI("POST", "/users/"+p.target+"/merges", map[string]any{"source_user_id": p.source, "reason": "same email in two realms (ticket 31)"})
		if r.Status != 404 && r.Status != 422 {
			t.Fatalf("cross-realm merge proposal %s <- %s: %d %s", p.target, p.source, r.Status, r.Raw)
		}
	}
	mustStatus(t, f.AdminAPI("GET", "/users/"+twin.ID, nil), 404, "the other realm's account seen from main")
	// main's administrator token carries no authority in the other realm.
	for _, p := range []string{"/users", "/users/" + twin.ID, "/settings"} {
		r := h.Do(Req{Method: "GET", Path: "/api/v1/realms/other" + p, Token: f.AdminToken})
		if r.Status != 401 && r.Status != 403 {
			t.Fatalf("main's admin token on the other realm's %s: %d %s", p, r.Status, r.Raw)
		}
		if bytes.Contains(r.Raw, []byte("alice@example.test")) {
			t.Fatalf("the other realm disclosed its account to main's administrator: %s", r.Raw)
		}
	}

	// A federated sign-in in the other realm with alice's verified address.
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	secret := "upstream-secret"
	if _, err := h.App.Federation.Create(ctx, other.ID, federation.Input{Alias: "corp", DisplayName: "Corp SSO", Issuer: idp.srv.URL,
		Config: federation.Config{ClientID: "proudauth-other"}, ClientSecret: &secret, JIT: true},
		authorization.Subject{Type: "operator", ID: "test"}, operator); err != nil {
		t.Fatal(err)
	}
	_, challenge := PKCE()
	start := h.Do(Req{Method: "POST", Path: "/api/v1/realms/other/auth/transactions", JSON: map[string]any{"client_id": "proudauth-cli",
		"redirect_uri": "http://127.0.0.1/callback", "scope": "proudauth:account", "resource": []string{other.Issuer + "/account"}, "state": "s-other",
		"code_challenge": challenge, "code_challenge_method": "S256"}})
	mustStatus(t, start, 201, "start in the other realm")
	tx, cont := start.Str("transaction_id"), start.Str("continuation_token")
	step := func(name string, body any) *Resp {
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/other/auth/transactions/" + tx + "/" + name, JSON: body,
			Headers: map[string]string{"X-Transaction-Token": cont}})
	}
	idp.next = map[string]any{"sub": "u-alice", "email": "alice@example.test", "email_verified": true, "name": "Alice"}
	st := step("federation/start", map[string]any{"provider": "corp"})
	mustStatus(t, st, 200, "federation start")
	mustStatus(t, h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}), 200, "callback")
	st = step("resume", map[string]any{})
	// The matching account is the other realm's own, and even it needs
	// proof of control before the upstream identity is linked.
	if st.Str("redirect_to") != "" || !has(actionTypes(st), "link_account") {
		t.Fatalf("the upstream identity was linked by email without proof: %s", st.Raw)
	}
	var mainLinks, foreignLinks int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE user_id=$1`, alice).Scan(&mainLinks)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM external_identities e JOIN users u ON u.id=e.user_id WHERE e.realm_id=$1 AND u.realm_id<>$1`,
		other.ID).Scan(&foreignLinks)
	if mainLinks != 0 || foreignLinks != 0 {
		t.Fatalf("cross-realm link: main alice has %d upstream links, %d links cross realms", mainLinks, foreignLinks)
	}
	if bytes.Contains(st.Raw, []byte(alice)) {
		t.Fatalf("the other realm's transaction names main's account: %s", st.Raw)
	}
	linked := f.must(f.AdminAPI("GET", "/users/"+alice+"/linked-identities", nil), 200, "main alice's links")
	if items, _ := linked.Get("items").([]any); len(items) != 0 {
		t.Fatalf("main alice gained a linked identity: %s", linked.Raw)
	}
}

// TestSameSubjectFromTwoIssuers covers DOM-002 on the identity-provider
// side: two upstream connections whose issuers present the same subject
// string create two distinct accounts, each sign-in returns to its own
// account, and neither account is linked to the other issuer.
func TestSameSubjectFromTwoIssuers(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	east, west := newFakeIdP(t, h.Clock.Now), newFakeIdP(t, h.Clock.Now)
	pool := east.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	pool.AddCert(west.srv.Certificate())
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = pool
	idps := map[string]*fakeIdP{"east": east, "west": west}
	for alias, idp := range idps {
		f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": alias, "display_name": alias, "issuer": idp.srv.URL,
			"client_secret": "upstream-secret", "config": map[string]any{"client_id": "proudauth-main"}, "jit_provisioning": true}), 201, "connection "+alias)
	}
	signIn := func(alias, email string) string {
		t.Helper()
		idps[alias].next = map[string]any{"sub": "shared-subject-42", "email": email, "email_verified": true, "name": "Shared " + alias}
		lo := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
		start, verifier, cont := h.StartTx(lo)
		tx := start.Str("transaction_id")
		st := h.Step(tx, cont, "federation/start", map[string]any{"provider": alias})
		mustStatus(t, st, 200, "federation start "+alias)
		mustStatus(t, h.Do(Req{Method: "GET", Path: idps[alias].browse(t, st.Str("external_redirect"))}), 200, "callback "+alias)
		st = h.Step(tx, cont, "resume", nil)
		u, _ := url.Parse(st.Str("redirect_to"))
		if u == nil || u.Query().Get("code") == "" {
			t.Fatalf("federated sign-in via %s did not complete: %s", alias, st.Raw)
		}
		tok := h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {"http://127.0.0.1/callback"}}, "proudauth-cli", "")
		mustStatus(t, tok, 200, "token "+alias)
		me := f.must(h.API("GET", "/me", tok.Str("access_token"), nil), 200, "me "+alias)
		return me.Str("id")
	}
	a := signIn("east", "shared@east.test")
	b := signIn("west", "shared@west.test")
	if a == "" || a == b {
		t.Fatalf("one subject string from two issuers became one account: %q %q", a, b)
	}
	if again := signIn("west", "shared@west.test"); again != b {
		t.Fatalf("the west identity moved to another account: %s, then %s", b, again)
	}
	rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT user_id, upstream_issuer FROM external_identities WHERE upstream_subject='shared-subject-42' ORDER BY upstream_issuer`)
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]string{}
	for rows.Next() {
		var user, iss string
		if err := rows.Scan(&user, &iss); err != nil {
			t.Fatal(err)
		}
		if prev, dup := links[iss]; dup && prev != user {
			t.Fatalf("issuer %s linked to two accounts", iss)
		}
		links[iss] = user
	}
	rows.Close()
	if len(links) != 2 || links[east.srv.URL] != a || links[west.srv.URL] != b {
		t.Fatalf("upstream links: %v (east %s, west %s)", links, a, b)
	}
}
