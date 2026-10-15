package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/worker"
)

// registerAccount starts a headless web transaction and submits a public
// registration for email with extra fields merged into the request.
func registerAccount(f *Fixture, email string, extra map[string]any) (r *Resp, tx, cont string) {
	f.H.t.Helper()
	start, _, cont := f.H.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud}})
	tx = start.Str("transaction_id")
	body := map[string]any{"transaction_id": tx, "email": email, "password": "a brand new passphrase 2026"}
	for k, v := range extra {
		body[k] = v
	}
	r = f.H.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: body, Headers: map[string]string{"X-Transaction-Token": cont}})
	return r, tx, cont
}

// emailIdentifiers counts the email identifiers holding an address: those
// verified and all of them.
func emailIdentifiers(t *testing.T, h *Harness, email string) (verified, total int) {
	t.Helper()
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE verified_at IS NOT NULL), count(*)
		FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2`, h.Realm.ID, email).Scan(&verified, &total); err != nil {
		t.Fatal(err)
	}
	return verified, total
}

// TestRegistrationVerification covers REG-004: a registered address stays
// unverified, and cannot be used to sign in, until the code sent to it for
// this registration is proven; a wrong code verifies nothing; and proving the
// address does not stand in for MFA.
func TestRegistrationVerification(t *testing.T) {
	f := NewFixture(t, func(p *realmPolicy) { p.MFA.Requirement = "required" })
	h := f.H
	r, tx, cont := registerAccount(f, "rhea@example.test", nil)
	mustStatus(t, r, 201, "register")
	if v, n := emailIdentifiers(t, h, "rhea@example.test"); v != 0 || n != 1 || r.Str("redirect_to") != "" {
		t.Fatalf("address treated as verified before proof: verified=%d total=%d %s", v, n, r.Raw)
	}
	// The unverified address is not a sign-in identifier: the right password
	// in another transaction does not reach the pending account.
	h.SetPassword("rhea@example.test", "a brand new passphrase 2026")
	if lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"},
		Identifier: "rhea@example.test", ExpectFail: true}); lr.Code != "" {
		t.Fatal("signed in through an unverified address")
	}
	code := CodeFrom(h.Mail("rhea@example.test", "email_verification"))
	if code == "" {
		t.Fatal("no verification code sent")
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if st := h.Step(tx, cont, "otp/verify", map[string]any{"code": wrong}); st.Status < 400 {
		t.Fatalf("wrong code accepted: %d %s", st.Status, st.Raw)
	}
	if v, _ := emailIdentifiers(t, h, "rhea@example.test"); v != 0 {
		t.Fatal("a wrong code verified the address")
	}
	st := h.Step(tx, cont, "otp/verify", map[string]any{"code": code})
	mustStatus(t, st, 200, "verify")
	if v, _ := emailIdentifiers(t, h, "rhea@example.test"); v != 1 {
		t.Fatal("proven address not marked verified")
	}
	if st.Str("redirect_to") != "" || !hasAction(st, "enroll_totp") {
		t.Fatalf("email verification stood in for the required MFA: %s", st.Raw)
	}
}

// TestRegistrationDuplicates covers REG-005: registering an address that
// already has a verified owner answers exactly like a fresh address, creates
// no second account and notifies the owner instead; two unfinished
// registrations of one fresh address end with a single verified owner,
// because the unique constraint refuses the second proof.
func TestRegistrationDuplicates(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	existing, _, _ := registerAccount(f, "bob@example.test", nil)
	fresh, _, _ := registerAccount(f, "nova@example.test", nil)
	if existing.Status != fresh.Status || jsonString(existing.Get("next_actions")) != jsonString(fresh.Get("next_actions")) {
		t.Fatalf("registration reveals the existing account: %d %s vs %d %s", existing.Status, existing.Raw, fresh.Status, fresh.Raw)
	}
	if v, n := emailIdentifiers(t, h, "bob@example.test"); v != 1 || n != 1 {
		t.Fatalf("registration of an owned address created another identity: verified=%d total=%d", v, n)
	}
	if h.Mail("bob@example.test", "registration_exists") == "" {
		t.Fatal("existing owner not notified")
	}

	r1, tx1, c1 := registerAccount(f, "twin@example.test", nil)
	mustStatus(t, r1, 201, "first registration")
	code1 := CodeFrom(h.Mail("twin@example.test", "email_verification"))
	h.Clock.Advance(2 * time.Second) // past the per-identifier send cooldown
	r2, tx2, c2 := registerAccount(f, "twin@example.test", nil)
	mustStatus(t, r2, 201, "second registration")
	code2 := CodeFrom(h.Mail("twin@example.test", "email_verification"))
	if code1 == "" || code2 == "" {
		t.Fatal("verification codes not sent")
	}
	mustStatus(t, h.Step(tx2, c2, "otp/verify", map[string]any{"code": code2}), 200, "second registration verifies first")
	if st := h.Step(tx1, c1, "otp/verify", map[string]any{"code": code1}); st.Status < 400 {
		t.Fatalf("a second account verified the same address: %d %s", st.Status, st.Raw)
	}
	if v, _ := emailIdentifiers(t, h, "twin@example.test"); v != 1 {
		t.Fatalf("verified owners of one address: %d", v)
	}
}

// TestTermsAcceptanceRecords covers REG-006: when onboarding requires terms,
// registration records the accepted version with its time, scope, client and
// provenance; an account that has not accepted the current version must
// accept it at sign-in before any code is issued (recorded as a required
// action), and a new version asks again.
func TestTermsAcceptanceRecords(t *testing.T) {
	f := NewFixture(t, func(p *realmPolicy) { p.Registration.TermsVersion = "2026-10" })
	h := f.H
	ctx := context.Background()
	type record struct {
		version, scope, provenance, client string
		at                                 time.Time
	}
	records := func(userID string) []record {
		t.Helper()
		rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT version, scope_type, provenance, coalesce(client_id,''), accepted_at FROM terms_acceptances
			WHERE user_id=$1 AND document='terms' ORDER BY accepted_at, id`, userID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []record
		for rows.Next() {
			var r record
			if err := rows.Scan(&r.version, &r.scope, &r.provenance, &r.client, &r.at); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	near := func(a time.Time) bool { d := a.Sub(h.Clock.Now()); return d < time.Second && d > -time.Second }

	r, _, _ := registerAccount(f, "tess@example.test", map[string]any{"terms_version": "2026-09"})
	if r.Status < 400 {
		t.Fatalf("registration with a stale terms version accepted: %d %s", r.Status, r.Raw)
	}
	r, _, _ = registerAccount(f, "tess@example.test", map[string]any{"terms_version": "2026-10"})
	mustStatus(t, r, 201, "register")
	var tess string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND canonical_value='tess@example.test'`,
		h.Realm.ID).Scan(&tess); err != nil {
		t.Fatal(err)
	}
	if got := records(tess); len(got) != 1 || got[0].version != "2026-10" || got[0].scope != "realm" || got[0].provenance != "registration" ||
		got[0].client != f.Clients["web"].Ref || !near(got[0].at) {
		t.Fatalf("registration acceptance record: %+v", got)
	}

	// Bob has not accepted the current terms: sign-in stops at accept_terms.
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: "bob@example.test"}
	signIn := func() (string, string, *Resp) {
		start, _, cont := h.StartTx(acct)
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		return tx, cont, h.Step(tx, cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
	}
	tx, cont, st := signIn()
	if !hasAction(st, "accept_terms") || st.Str("redirect_to") != "" {
		t.Fatalf("terms acceptance not required: %s", st.Raw)
	}
	if r := h.Step(tx, cont, "terms", map[string]any{"version": "2026-09"}); r.Status < 400 {
		t.Fatalf("stale terms version accepted at sign-in: %d %s", r.Status, r.Raw)
	}
	if len(records(f.Users["bob"])) != 0 {
		t.Fatal("refused acceptance recorded")
	}
	st = h.Drive(tx, cont, h.Step(tx, cont, "terms", map[string]any{"version": "2026-10"}), acct)
	if st.Str("redirect_to") == "" {
		t.Fatalf("sign-in did not complete after acceptance: %s", st.Raw)
	}
	if got := records(f.Users["bob"]); len(got) != 1 || got[0].version != "2026-10" || got[0].provenance != "required_action" ||
		got[0].client == "" || !near(got[0].at) {
		t.Fatalf("sign-in acceptance record: %+v", got)
	}

	mustStatus(t, f.SetPolicy(func(p *realmPolicy) { p.Registration.TermsVersion = "2027-01" }), 200, "new terms version")
	if _, _, st := signIn(); !hasAction(st, "accept_terms") || st.Str("redirect_to") != "" {
		t.Fatalf("new terms version not asked for: %s", st.Raw)
	}
}

// TestAbandonedOnboardingCleanup covers REG-011: a registration left
// unverified past the realm's configurable lifecycle.unverified_account_ttl_hours
// is deleted by the lifecycle job (and not before), and an authenticator
// enrollment that was started but never activated expires: the cleanup
// revokes it and its secret can no longer be activated.
func TestAbandonedOnboardingCleanup(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	mustStatus(t, f.SetPolicy(func(p *realmPolicy) { p.Lifecycle.UnverifiedAccountTTLHours = 2 }), 200, "unverified TTL")
	r, _, _ := registerAccount(f, "abby@example.test", nil)
	mustStatus(t, r, 201, "register")
	var abby string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND canonical_value='abby@example.test'`,
		h.Realm.ID).Scan(&abby); err != nil {
		t.Fatal(err)
	}
	state := func(id string) string {
		var s string
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	en := f.must(h.API("POST", "/me/totp/enroll", bob, nil), 201, "start an enrollment and abandon it")
	h.seeds["bob@example.test"] = en.Str("secret")

	h.Clock.Advance(time.Hour)
	runWorker(t, w)
	if s := state(abby); s != "pending_verification" {
		t.Fatalf("unverified registration removed before the configured TTL: %s", s)
	}
	h.Clock.Advance(90 * time.Minute)
	runWorker(t, w)
	if s := state(abby); s != "deleted" {
		t.Fatalf("abandoned registration not expired: %s", s)
	}
	if _, n := emailIdentifiers(t, h, "abby@example.test"); n != 0 {
		t.Fatal("expired registration keeps its address")
	}
	if s := state(f.Users["bob"]); s != "active" {
		t.Fatalf("verified account touched by the cleanup: %s", s)
	}
	var pending, revoked int
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='pending'), count(*) FILTER (WHERE state='revoked')
		FROM credentials WHERE user_id=$1 AND type='totp'`, f.Users["bob"]).Scan(&pending, &revoked); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || revoked != 1 {
		t.Fatalf("abandoned enrollment not expired: pending=%d revoked=%d", pending, revoked)
	}
	bob = f.AccountToken("bob").Tokens.Str("access_token")
	if r := h.API("POST", "/me/totp/activate", bob, map[string]any{"code": h.TOTPNow("bob@example.test")}); r.Status < 400 {
		t.Fatalf("abandoned enrollment secret activated: %d %s", r.Status, r.Raw)
	}
}
