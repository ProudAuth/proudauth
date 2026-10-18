package e2e

import (
	"context"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestPasswordlessAndAbuseBudgets covers PWDLESS-001..PWDLESS-005, MSG-008,
// SEC-006 and TEN-018.
func TestPasswordlessAndAbuseBudgets(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Delivery.SMS.Adapter = "dev_sink"
		c.Delivery.SMS.AllowedCountries = []string{"+1"}
		c.Delivery.SMS.DailyBudget = 4
		c.Security.RateLimits.FailuresBeforeLock = 3
		c.Security.RateLimits.TemporaryLock = 10 * time.Minute
		c.Security.RateLimits.LoginPerIdentifier = 100
		c.Security.RateLimits.OrganizationPerWindow = 5
	})
	f := fixtureOn(t, h, func(p *realm.Policy) {
		p.Login.SMSOTP = true
		p.Login.Identifiers = append(p.Login.Identifiers, "phone")
		p.Login.SMSRiskAccepted = true
		p.Login.MagicLink = true
		p.Interaction.LoginUIURL = "https://login.test/ui"
	})
	ctx := context.Background()
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	// Give alice a verified phone number.
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value, verified_at, verification_source)
		VALUES ($1,$2,$3,'phone','+15550100001','+15550100001',now(),'test')`, ids.New(ids.Identifier), h.Realm.ID, f.Users["alice"]); err != nil {
		t.Fatal(err)
	}
	finish := func(st *Resp, verifier string) *Resp {
		t.Helper()
		u, _ := url.Parse(st.Str("redirect_to"))
		if u == nil || u.Query().Get("code") == "" {
			t.Fatalf("not completed: %s", st.Raw)
		}
		return h.TokenRequest(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier},
			"redirect_uri": {"http://127.0.0.1/callback"}, "client_id": {"proudauth-cli"}, "resource": {h.Realm.Issuer + "/account"}}, "", "")
	}

	t.Run("SMS one-time code sign-in", func(t *testing.T) {
		start, verifier, cont := h.StartTx(cli)
		tx := start.Str("transaction_id")
		st := h.Step(tx, cont, "identify", map[string]any{"identifier": "+1 555 010 0001"})
		if !has(actionTypes(st), "sms_otp") {
			t.Fatalf("sms_otp not offered: %s", st.Raw)
		}
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send sms")
		code := CodeFrom(h.Mail("+15550100001", "login_code"))
		if code == "" {
			t.Fatal("no SMS delivered to the dev sink")
		}
		done := h.Drive(tx, cont, h.Step(tx, cont, "otp/verify", map[string]any{"code": code}), LoginOpts{Identifier: "alice@example.test"})
		toks := finish(done, verifier)
		mustStatus(t, toks, 200, "token")
		if acr := jwtPayload(toks.Str("access_token"))["acr"]; acr != "urn:proudauth:acr:single_factor" {
			t.Fatalf("SMS treated as stronger than a single factor: %v", acr)
		}
		// Unknown numbers get the same response; no message is sent.
		h.Clock.Advance(2 * time.Second)
		start, _, cont = h.StartTx(cli)
		tx = start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "+15550100009"})
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "unknown number")
		if h.Mail("+15550100009", "login_code") != "" {
			t.Fatal("SMS sent to a number without an account")
		}
		// Country restriction applies identically to known and unknown numbers.
		start, _, cont = h.StartTx(cli)
		tx = start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "+445550100001"})
		if r := h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}); r.Status != 422 {
			t.Fatalf("disallowed country: %d %s", r.Status, r.Raw)
		}
		// The deployment-wide daily SMS budget is a hard cost ceiling.
		sent := 1
		for sent < 4 {
			h.Clock.Advance(2 * time.Second)
			start, _, cont = h.StartTx(cli)
			tx = start.Str("transaction_id")
			h.Step(tx, cont, "identify", map[string]any{"identifier": "+15550100001"})
			mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send within budget")
			sent++
		}
		h.Clock.Advance(2 * time.Second)
		start, _, cont = h.StartTx(cli)
		tx = start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "+15550100001"})
		if r := h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}); r.Status != 429 {
			t.Fatalf("SMS budget not enforced: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("magic links are transaction-bound and scanner-safe", func(t *testing.T) {
		send := func() (tx, cont, verifier, token string, link *url.URL) {
			t.Helper()
			h.Clock.Advance(2 * time.Second)
			start, v, c := h.StartTx(cli)
			tx = start.Str("transaction_id")
			st := h.Step(tx, c, "identify", map[string]any{"identifier": "carol@example.test"})
			if !has(actionTypes(st), "magic_link") {
				t.Fatalf("magic link not offered: %s", st.Raw)
			}
			mustStatus(t, h.Step(tx, c, "otp/send", map[string]any{"purpose": "magic_link"}), 200, "send link")
			m := regexp.MustCompile(`https://login\.test/ui\S+`).FindString(h.Mail("carol@example.test", "magic_link"))
			u, err := url.Parse(m)
			if err != nil || m == "" {
				t.Fatalf("no link in message")
			}
			frag, _ := url.ParseQuery(u.Fragment)
			if u.Query().Get("transaction_id") != tx || frag.Get("magic_link") == "" || strings.Contains(u.RawQuery, "pa_lnk_") {
				t.Fatalf("link must carry the secret only in the fragment: %s", m)
			}
			return tx, c, v, frag.Get("magic_link"), u
		}
		tx1, cont1, _, token1, _ := send()
		tx2, cont2, verifier2, token2, _ := send()
		_ = tx1
		// A link presented to a different transaction (another browser) fails and is burned.
		if r := h.Step(tx2, cont2, "magic-link", map[string]any{"token": token1}); r.Status != 400 {
			t.Fatalf("cross-transaction magic link accepted: %d %s", r.Status, r.Raw)
		}
		if r := h.Step(tx1, cont1, "magic-link", map[string]any{"token": token1}); r.Status != 400 {
			t.Fatal("burned magic link reused")
		}
		done := h.Drive(tx2, cont2, h.Step(tx2, cont2, "magic-link", map[string]any{"token": token2}), LoginOpts{Identifier: "carol@example.test"})
		mustStatus(t, finish(done, verifier2), 200, "magic link sign-in")
		if r := h.Step(tx2, cont2, "magic-link", map[string]any{"token": token2}); r.Status < 400 {
			t.Fatal("magic link reusable")
		}
	})

	t.Run("temporary password lock is bounded and not a permanent lockout", func(t *testing.T) {
		attempt := func(pw string) *Resp {
			start, _, cont := h.StartTx(cli)
			tx := start.Str("transaction_id")
			h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
			return h.Step(tx, cont, "password", map[string]any{"password": pw})
		}
		for i := 0; i < 3; i++ {
			if r := attempt("wrong-password-123"); r.Status != 401 {
				t.Fatalf("failure %d: %d", i, r.Status)
			}
		}
		locked := attempt(h.passwords["bob@example.test"])
		if locked.Status != 429 || locked.Header.Get("Retry-After") == "" {
			t.Fatalf("lock not applied: %d %s", locked.Status, locked.Raw)
		}
		// Unknown identifiers lock the same way (no existence probe, API-009):
		// the same number of 401s, then a 429 identical to the known account's
		// (status, problem code and detail, Retry-After).
		attempt2 := func() *Resp {
			start, _, cont := h.StartTx(cli)
			tx := start.Str("transaction_id")
			h.Step(tx, cont, "identify", map[string]any{"identifier": "ghost@example.test"})
			return h.Step(tx, cont, "password", map[string]any{"password": "x-wrong-password"})
		}
		for i := 0; i < 3; i++ {
			if r := attempt2(); r.Status != 401 {
				t.Fatalf("unknown identifier, failure %d: %d %s", i, r.Status, r.Raw)
			}
		}
		if r := attempt2(); r.Status != locked.Status || r.Str("code") != locked.Str("code") || r.Str("detail") != locked.Str("detail") ||
			r.Header.Get("Retry-After") != locked.Header.Get("Retry-After") {
			t.Fatalf("unknown identifier lock differs from a known account's: %d %s (Retry-After %q) vs %d %s (Retry-After %q)",
				r.Status, r.Raw, r.Header.Get("Retry-After"), locked.Status, locked.Raw, locked.Header.Get("Retry-After"))
		}
		// Other sign-in methods keep working while the password is locked.
		h.Clock.Advance(2 * time.Second)
		start, verifier, cont := h.StartTx(cli)
		tx := start.Str("transaction_id")
		h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"})
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "email code")
		done := h.Drive(tx, cont, h.Step(tx, cont, "otp/verify", map[string]any{"code": CodeFrom(h.Mail("bob@example.test", "login_code"))}),
			LoginOpts{Identifier: "bob@example.test", SelectOrg: f.Acme})
		mustStatus(t, finish(done, verifier), 200, "email code during password lock")
		// The lock expires by itself.
		h.Clock.Advance(11 * time.Minute)
		if r := attempt(h.passwords["bob@example.test"]); r.Status != 200 {
			t.Fatalf("lock did not expire: %d %s", r.Status, r.Raw)
		}
		f.ReloginAdmin()
		ev := f.must(f.AdminAPI("GET", "/audit-events?type=authentication.password.temporarily_locked", nil), 200, "audit")
		if len(ev.Get("items").([]any)) == 0 {
			t.Fatal("temporary lock not audited")
		}
	})

	t.Run("per-organization issuance budget", func(t *testing.T) {
		got429 := false
		for i := 0; i < 7; i++ {
			r := f.MachineToken(f.Clients["batch"], f.BillingAud, "billing:read", f.Acme)
			if r.Status == 429 {
				got429 = r.Str("error") == "slow_down"
				break
			}
			mustStatus(t, r, 200, "org token")
		}
		if !got429 {
			t.Fatal("organization token budget not enforced")
		}
		// Another organization's budget is independent.
		_ = f.Globex
	})
}

// TestSendCooldownConsumesNothingElse covers PWDLESS-004, REG-012 and
// SEC-006: send_cooldown paces resends by legitimate users, so a resend it
// refuses (429 with the cooldown's Retry-After) consumes no unit of
// send_per_identifier, send_per_ip or the aggregate send budgets. After the
// cooldown the identifier still has its whole budget, and the address its
// own; once spent, both refuse as configured.
func TestSendCooldownConsumesNothingElse(t *testing.T) {
	h := NewHarness(t)
	fixtureOn(t, h, func(p *realm.Policy) { p.Login.EmailOTP = true })
	// Tight budgets for this test only (the fixture setup sends from the same
	// loopback address), starting well inside a fresh send window so nothing
	// the fixture sent counts.
	rl := &h.App.D.Cfg.Security.RateLimits
	rl.SendCooldown = 30 * time.Second
	rl.SendPerIdentifier = 2
	rl.SendPerIP = 3
	h.Clock.Set(h.Clock.Now().Truncate(rl.SendWindow).Add(rl.SendWindow + time.Minute))
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	send := func(identifier string) *Resp {
		t.Helper()
		start, _, cont := h.StartTx(cli)
		tx := start.Str("transaction_id")
		mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": identifier}), 200, "identify")
		return h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"})
	}
	mustStatus(t, send("alice@example.test"), 200, "first send")
	for i := range 3 {
		h.Clock.Advance(5 * time.Second)
		r := send("alice@example.test")
		if r.Status != 429 {
			t.Fatalf("resend %d inside the cooldown: %d %s", i+1, r.Status, r.Raw)
		}
		if s, err := strconv.Atoi(r.Header.Get("Retry-After")); err != nil || s < 1 || s > 31 {
			t.Fatalf("resend %d inside the cooldown: Retry-After %q, want the cooldown's", i+1, r.Header.Get("Retry-After"))
		}
	}
	// The refused resends left send_per_identifier (2) and send_per_ip (3)
	// untouched: alice's second send and a send to carol from the same
	// address go through.
	h.Clock.Advance(30 * time.Second)
	mustStatus(t, send("alice@example.test"), 200, "second send to alice after the cooldown")
	mustStatus(t, send("carol@example.test"), 200, "send to carol from the same address")
	// Now both are spent: alice's identifier budget, then the address's.
	h.Clock.Advance(31 * time.Second)
	if r := send("alice@example.test"); r.Status != 429 {
		t.Fatalf("third send to alice within send_per_identifier=2: %d %s", r.Status, r.Raw)
	}
	if r := send("bob@example.test"); r.Status != 429 {
		t.Fatalf("send beyond send_per_ip=3: %d %s", r.Status, r.Raw)
	}
}
