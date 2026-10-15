package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/storage"
)

// txFault fails the n-th database transaction of one request, matched by
// the X-Request-Id the test sends, at one fault point (storage.SetFault,
// TEST-059).
type txFault struct {
	reqID string
	n     int32
	point string
	count atomic.Int32
	fired atomic.Bool
	index sync.Map // pgx.Tx -> int32
}

func (fl *txFault) hook(ctx context.Context, tx pgx.Tx, point string) error {
	if reqctx.From(ctx).RequestID != fl.reqID {
		return nil
	}
	var i int32
	if point == storage.FaultBegin {
		i = fl.count.Add(1)
		fl.index.Store(tx, i)
	} else if v, ok := fl.index.Load(tx); ok {
		i = v.(int32)
	}
	if i == fl.n && point == fl.point && fl.fired.CompareAndSwap(false, true) {
		return errors.New("injected database failure")
	}
	return nil
}

// faultRun is one attempt at a sensitive transition, prepared with a fresh
// proof.
type faultRun struct {
	do       func(reqID string) *Resp // performs the transition under reqID
	ok       func(*Resp) bool         // the response reports success
	consumed func() bool              // the proof is consumed
	effect   func() bool              // the transition's effect exists (token, password, membership)
}

// authorizeCode drives a sign-in up to the authorization code without
// redeeming it.
func authorizeCode(t *testing.T, h *Harness, o LoginOpts) (code, verifier string) {
	t.Helper()
	start, verifier, cont := h.StartTx(o)
	if start.Status != 201 {
		t.Fatalf("start transaction: %d %s", start.Status, start.Raw)
	}
	st := h.Drive(start.Str("transaction_id"), cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, o)
	u, err := url.Parse(st.Str("redirect_to"))
	if err != nil || u.Query().Get("code") == "" {
		t.Fatalf("no authorization code: %d %s", st.Status, st.Raw)
	}
	return u.Query().Get("code"), verifier
}

// TestTransactionFaultsLeaveNoPartialState covers TEST-059 and DB-009 for
// the database: refresh rotation, authorization-code exchange, password
// reset completion and invitation acceptance are run with every database
// transaction of the request failing in turn, at its start and at its
// commit (after all of its statements ran). Whatever fails, the outcome is
// all or nothing: a success response always comes with the proof consumed
// and the effect present, and a failure leaves the proof unconsumed (no
// refresh reuse, no code replay) and no effect, so a retry succeeds once.
func TestTransactionFaultsLeaveNoPartialState(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	db := h.App.D.DB
	exists := func(sql string, args ...any) bool {
		t.Helper()
		var b bool
		if err := db.Pool.QueryRow(ctx, sql, args...).Scan(&b); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return b
	}
	web := f.Clients["web"]
	tokenReq := func(form url.Values, reqID string) *Resp {
		return h.Do(Req{Method: "POST", Path: "/realms/main/oauth/token", Form: form, Basic: [2]string{"web-bff", web.Secret},
			Headers: map[string]string{"X-Request-Id": reqID}})
	}
	issued := func(r *Resp) bool {
		return r.Status == 200 && r.Str("access_token") != "" && r.Str("refresh_token") != ""
	}

	flows := []struct {
		name    string
		prepare func(i int) faultRun
	}{
		{"refresh rotation", func(i int) faultRun {
			rt := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
			d := secret.Digest(rt)
			return faultRun{
				do: func(id string) *Resp {
					return tokenReq(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, id)
				},
				ok: issued,
				consumed: func() bool {
					return exists(`SELECT consumed_at IS NOT NULL FROM refresh_tokens WHERE token_digest=$1`, d)
				},
				effect: func() bool {
					return exists(`SELECT EXISTS (SELECT 1 FROM refresh_tokens n JOIN refresh_tokens p ON p.id=n.parent_id WHERE p.token_digest=$1)`, d) ||
						!exists(`SELECT f.state='active' FROM refresh_families f JOIN refresh_tokens t ON t.family_id=f.id WHERE t.token_digest=$1`, d)
				},
			}
		}},
		{"authorization code exchange", func(i int) faultRun {
			o := LoginOpts{ClientID: "web-bff", ClientSecret: web.Secret, RedirectURI: webRedirect, Scope: "openid orders:read",
				Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"}
			code, verifier := authorizeCode(t, h, o)
			d := secret.Digest(code)
			return faultRun{
				do: func(id string) *Resp {
					return tokenReq(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier},
						"redirect_uri": {webRedirect}, "resource": {f.OrdersAud}}, id)
				},
				ok: issued,
				consumed: func() bool {
					return exists(`SELECT consumed_at IS NOT NULL FROM authorization_codes WHERE code_digest=$1`, d)
				},
				effect: func() bool {
					return exists(`SELECT EXISTS (SELECT 1 FROM refresh_families WHERE grant_id=(SELECT grant_id FROM authorization_codes WHERE code_digest=$1))`, d) ||
						!exists(`SELECT state='active' FROM authorization_grants WHERE id=(SELECT grant_id FROM authorization_codes WHERE code_digest=$1)`, d)
				},
			}
		}},
		{"password reset completion", func(i int) faultRun {
			const ident = "carol@example.test"
			h.Clock.Advance(2 * time.Second) // past the per-identifier send cooldown
			req := f.must(h.API("POST", "/password-resets", "", map[string]any{"identifier": ident}), 202, "request reset")
			resetID, code := req.Str("reset_id"), CodeFrom(h.Mail(ident, "password_reset"))
			var before string
			if err := db.Pool.QueryRow(ctx, `SELECT id FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, f.Users["carol"]).Scan(&before); err != nil {
				t.Fatal(err)
			}
			pw := fmt.Sprintf("Carol resets her password %d times", 100+i)
			return faultRun{
				do: func(id string) *Resp {
					return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/password-resets/complete", JSON: map[string]any{"reset_id": resetID,
						"code": code, "new_password": pw}, Headers: map[string]string{"X-Request-Id": id}})
				},
				ok:       func(r *Resp) bool { return r.Status == 200 },
				consumed: func() bool { return exists(`SELECT consumed_at IS NOT NULL FROM challenges WHERE id=$1`, resetID) },
				effect: func() bool {
					return exists(`SELECT EXISTS (SELECT 1 FROM credentials WHERE user_id=$1 AND type='password' AND state='active' AND id <> $2)`, f.Users["carol"], before)
				},
			}
		}},
		{"invitation acceptance", func(i int) faultRun {
			name := fmt.Sprintf("invitee%d", i)
			user := f.CreateUser(name)
			alice := f.AccountToken("alice").Tokens.Str("access_token")
			inv := f.must(h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": name + "@example.test",
				"role_ids": []string{f.Roles["orders-viewer"]}}), 201, "invite")
			invID, secretInv := inv.Str("invitation.id"), invitationFromMail(h.Mail(name+"@example.test", "invitation"))
			tok := f.AccountToken(name).Tokens.Str("access_token")
			return faultRun{
				do: func(id string) *Resp {
					return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/invitations/accept", Token: tok, JSON: map[string]any{"invitation": secretInv},
						Headers: map[string]string{"X-Request-Id": id}})
				},
				ok: func(r *Resp) bool { return r.Status == 200 },
				consumed: func() bool {
					return exists(`SELECT state <> 'pending_acceptance' AND state <> 'pending_delivery' AND state <> 'created' FROM invitations WHERE id=$1`, invID)
				},
				effect: func() bool {
					return exists(`SELECT EXISTS (SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active')`, f.Acme, user)
				},
			}
		}},
	}

	run := 0
	for _, fl := range flows {
		t.Run(fl.name, func(t *testing.T) {
			faulted := 0
			for n := int32(1); n <= 20; n++ {
				done := false
				for _, point := range []string{storage.FaultBegin, storage.FaultCommit} {
					run++
					fr := fl.prepare(run)
					plan := &txFault{reqID: fmt.Sprintf("fault-%d-%d-%s", run, n, point), n: n, point: point}
					clear := db.SetFault(plan.hook)
					r := fr.do(plan.reqID)
					clear()
					if !plan.fired.Load() {
						// The request has fewer than n transactions: an
						// undisturbed run, which must succeed completely.
						if !fr.ok(r) || !fr.consumed() || !fr.effect() {
							t.Fatalf("undisturbed run: %d %s", r.Status, r.Raw)
						}
						done = true
						break
					}
					faulted++
					where := fmt.Sprintf("transaction %d of %d at %s", n, plan.count.Load(), point)
					if fr.ok(r) {
						if !fr.consumed() || !fr.effect() {
							t.Fatalf("%s: success reported without the transition: %s", where, r.Raw)
						}
						t.Logf("%s: not on the critical path (succeeded completely)", where)
						continue
					}
					if strings.Contains(string(r.Raw), `"access_token"`) || strings.Contains(string(r.Raw), `"refresh_token"`) {
						t.Fatalf("%s: a failed response carries tokens: %s", where, r.Raw)
					}
					if fr.consumed() || fr.effect() {
						t.Fatalf("%s: failed (%d %s) but left the proof consumed=%v or the effect=%v", where, r.Status, r.Raw, fr.consumed(), fr.effect())
					}
					// The proof survived: a retry completes the transition once.
					if again := fr.do(fmt.Sprintf("retry-%d", run)); !fr.ok(again) || !fr.consumed() || !fr.effect() {
						t.Fatalf("%s: retry after the failure did not succeed: %d %s", where, again.Status, again.Raw)
					}
					t.Logf("%s: %d, nothing applied, retry succeeded", where, r.Status)
				}
				if done {
					break
				}
			}
			if faulted == 0 {
				t.Fatal("no transaction of the request was faulted")
			}
		})
	}
}

// TestSigningKeyOutageDuringIssuance covers TEST-059 and SEC-009 for the key
// provider: with no usable active signing key (none active, or the keyring
// cannot unwrap it) the authorization-code, refresh and client-credentials
// grants answer 503 temporarily_unavailable, readiness reports degraded,
// and the code or refresh token presented is not consumed, so the same
// request succeeds once the key is back. No replacement key is created.
func TestSigningKeyOutageDuringIssuance(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	db := h.App.D.DB.Pool
	web := f.Clients["web"]
	var activeKID string
	if err := db.QueryRow(ctx, `SELECT kid FROM signing_keys WHERE realm_id=$1 AND purpose='token' AND state='active'`, h.Realm.ID).Scan(&activeKID); err != nil {
		t.Fatal(err)
	}
	keyCount := func() (n int) {
		_ = db.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE realm_id=$1 AND purpose='token'`, h.Realm.ID).Scan(&n)
		return n
	}
	before := keyCount()
	outages := []struct {
		name       string
		start, end func()
	}{
		{"no active key", func() {
			if _, err := db.Exec(ctx, `UPDATE signing_keys SET state='retiring' WHERE kid=$1`, activeKID); err != nil {
				t.Fatal(err)
			}
		}, func() {
			if _, err := db.Exec(ctx, `UPDATE signing_keys SET state='active' WHERE kid=$1`, activeKID); err != nil {
				t.Fatal(err)
			}
		}},
		{"key provider unavailable", func() {
			h.App.D.Keys.SetFault(func(p keys.Purpose) error {
				if p == keys.PurposeSigningWrap {
					return errors.New("kms: connection refused")
				}
				return nil
			})
		}, func() { h.App.D.Keys.SetFault(nil) }},
	}
	type grant struct {
		name     string
		prepare  func() (form url.Values, consumed func() bool)
		clientID string
		secret   string
	}
	grants := []grant{
		{"authorization_code", func() (url.Values, func() bool) {
			code, verifier := authorizeCode(t, h, LoginOpts{ClientID: "web-bff", ClientSecret: web.Secret, RedirectURI: webRedirect, Scope: "openid orders:read",
				Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test"})
			return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {webRedirect},
				"resource": {f.OrdersAud}}, func() bool {
				var c bool
				_ = db.QueryRow(ctx, `SELECT consumed_at IS NOT NULL FROM authorization_codes WHERE code_digest=$1`, secret.Digest(code)).Scan(&c)
				return c
			}
		}, "web-bff", web.Secret},
		{"refresh_token", func() (url.Values, func() bool) {
			rt := f.LoginWeb("bob", f.Acme, f.OrdersAud, "openid orders:read").Tokens.Str("refresh_token")
			return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, func() bool {
				var c bool
				_ = db.QueryRow(ctx, `SELECT t.consumed_at IS NOT NULL OR f.state <> 'active' FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id
					WHERE t.token_digest=$1`, secret.Digest(rt)).Scan(&c)
				return c
			}
		}, "web-bff", web.Secret},
		{"client_credentials", func() (url.Values, func() bool) {
			return url.Values{"grant_type": {"client_credentials"}, "resource": {f.BillingAud}, "scope": {"billing:read"}, "organization": {f.Acme}},
				func() bool { return false }
		}, f.Clients["batch"].ID, f.Clients["batch"].Secret},
	}
	for _, o := range outages {
		for _, g := range grants {
			t.Run(o.name+"/"+g.name, func(t *testing.T) {
				form, consumed := g.prepare()
				o.start()
				h.App.KeyMgr.Invalidate(h.Realm.ID)
				r := h.TokenRequest(cloneForm(form), g.clientID, g.secret)
				st, body := probe(h, "/health/ready")
				o.end()
				h.App.KeyMgr.Invalidate(h.Realm.ID)
				if r.Status != 503 || r.Str("error") != "temporarily_unavailable" || r.Str("access_token") != "" {
					t.Fatalf("issuance during the outage: %d %s", r.Status, r.Raw)
				}
				if st != 503 || body["status"] != "degraded" {
					t.Fatalf("readiness during the outage: %d %v", st, body)
				}
				if consumed() {
					t.Fatal("the presented proof was consumed although no token was issued")
				}
				if again := h.TokenRequest(cloneForm(form), g.clientID, g.secret); again.Status != 200 || again.Str("access_token") == "" {
					t.Fatalf("the same request after the outage: %d %s", again.Status, again.Raw)
				}
			})
		}
	}
	if n := keyCount(); n != before {
		t.Fatalf("an outage created signing keys: %d before, %d after", before, n)
	}
}

func cloneForm(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = slices.Clone(vs)
	}
	return out
}

// TestDeliveryOutageDuringSensitiveFlows covers TEST-059 for email delivery
// (docs/plan.md §31.2 "Email/SMS delivery unavailable"): with the mail
// adapter failing, a password reset, an email verification and an
// invitation are each accepted as retryable work with the same answer as
// when mail works (a reset for an unknown address answers the same), the
// message is retried and ends failed, and nothing about the account changes:
// the password stays, the address stays unverified, no membership appears.
// When mail is back, a new message completes the flow.
func TestDeliveryOutageDuringSensitiveFlows(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	db := h.App.D.DB.Pool
	f.CreateUser("ivy") // set up while mail works
	mail := &failingMail{}
	h.App.Notify.DevSink, h.App.Notify.Email = false, mail
	mailUp := func() { h.App.Notify.DevSink = true }
	defer mailUp()
	// exhaust runs delivery until the message has used up its attempts
	// (5, with exponential backoff), stepping the clock by step.
	exhaust := func(template string, since time.Time, step time.Duration, rounds int) {
		t.Helper()
		for i := 0; i < rounds; i++ {
			h.Clock.Advance(step)
			if _, err := h.App.Notify.DeliverDue(ctx, "test", 100, time.Minute); err != nil {
				t.Fatal(err)
			}
		}
		var open, failed int
		_ = db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state IN ('queued','attempted','accepted')), count(*) FILTER (WHERE state IN ('failed','expired'))
			FROM notification_jobs WHERE realm_id=$1 AND template=$2 AND created_at >= $3`, h.Realm.ID, template, since).Scan(&open, &failed)
		if open != 0 || failed == 0 {
			t.Fatalf("%s delivery during the outage: %d open, %d failed", template, open, failed)
		}
	}
	keysOf := func(r *Resp) string {
		var k []string
		for key := range r.Body {
			k = append(k, key)
		}
		slices.Sort(k)
		return strings.Join(k, ",")
	}

	// First, while the sign-in transaction (transaction_ttl, 10 minutes) is
	// still open.
	t.Run("email verification", func(t *testing.T) {
		since := h.Clock.Now()
		r, tx, cont := registerAccount(f, "vera@example.test", nil)
		mustStatus(t, r, 201, "register while mail is down")
		exhaust("email_verification", since, time.Minute, 8)
		if v, n := emailIdentifiers(t, h, "vera@example.test"); v != 0 || n != 1 {
			t.Fatalf("address verified without proof: verified=%d total=%d", v, n)
		}
		if st := h.Step(tx, cont, "otp/verify", map[string]any{"code": "000000"}); st.Status < 400 {
			t.Fatalf("a guessed code verified the address: %d %s", st.Status, st.Raw)
		}
		// Mail is back: a resend proves the address.
		mailUp()
		defer func() { h.App.Notify.DevSink = false }()
		h.Clock.Advance(2 * time.Second)
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "verify_email"}), 200, "resend")
		code := CodeFrom(h.Mail("vera@example.test", "email_verification"))
		mustStatus(t, h.Step(tx, cont, "otp/verify", map[string]any{"code": code}), 200, "verify after the outage")
		if v, _ := emailIdentifiers(t, h, "vera@example.test"); v != 1 {
			t.Fatal("address not verified after the outage")
		}
	})

	t.Run("password reset", func(t *testing.T) {
		since := h.Clock.Now()
		var credBefore string
		_ = db.QueryRow(ctx, `SELECT id FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`, f.Users["bob"]).Scan(&credBefore)
		known := h.API("POST", "/password-resets", "", map[string]any{"identifier": "bob@example.test"})
		unknown := h.API("POST", "/password-resets", "", map[string]any{"identifier": "nobody@example.test"})
		if known.Status != 202 || unknown.Status != 202 || keysOf(known) != keysOf(unknown) {
			t.Fatalf("reset answers differ while mail is down: %d %s / %d %s", known.Status, known.Raw, unknown.Status, unknown.Raw)
		}
		exhaust("password_reset", since, 20*time.Minute, 8)
		if mail.sent == 0 {
			t.Fatal("the failing adapter was never called")
		}
		var credNow string
		var actions []string
		_ = db.QueryRow(ctx, `SELECT c.id, u.required_actions FROM credentials c JOIN users u ON u.id=c.user_id
			WHERE c.user_id=$1 AND c.type='password' AND c.state='active'`, f.Users["bob"]).Scan(&credNow, &actions)
		if credNow != credBefore || len(actions) != 0 {
			t.Fatalf("account changed by an undelivered reset: credential %s->%s, actions %v", credBefore, credNow, actions)
		}
		if lr := f.AccountToken("bob"); lr.Tokens.Status != 200 {
			t.Fatal("the password stopped working after an undelivered reset")
		}
	})

	t.Run("invitation", func(t *testing.T) {
		since := h.Clock.Now()
		alice := f.AccountToken("alice").Tokens.Str("access_token")
		inv := h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": "ivy@example.test",
			"role_ids": []string{f.Roles["orders-viewer"]}})
		mustStatus(t, inv, 201, "invite while mail is down")
		exhaust("invitation", since, 20*time.Minute, 8)
		var state string
		var members int
		_ = db.QueryRow(ctx, `SELECT state FROM invitations WHERE id=$1`, inv.Str("invitation.id")).Scan(&state)
		_ = db.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE organization_id=$1 AND user_id=$2`, f.Acme, f.Users["ivy"]).Scan(&members)
		if state != "pending_delivery" || members != 0 {
			t.Fatalf("undelivered invitation: state %s, %d memberships", state, members)
		}
	})
}
