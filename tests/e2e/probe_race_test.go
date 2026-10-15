package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/authentication"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/realm"
)

// raceWithPendingWrite runs write while another transaction holds an
// uncommitted change made by stmt, the way an administrator's PATCH holds the
// row it updates; once write is seen waiting on that transaction, the change
// commits. It returns write's response.
func raceWithPendingWrite(t *testing.T, h *Harness, stmt string, args []any, write func() *Resp) *Resp {
	t.Helper()
	ctx := context.Background()
	tx, err := h.App.D.DB.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, stmt, args...); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Resp, 1)
	go func() { done <- write() }()
	deadline := time.Now().Add(15 * time.Second)
	for {
		var waiting int
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		select {
		case r := <-done:
			// The write finished without touching the row; commit and let the
			// caller judge the outcome.
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			return r
		case <-time.After(20 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatal("the write never reached the row the concurrent change holds")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		return r
	case <-time.After(30 * time.Second):
		t.Fatal("the write did not finish after the concurrent change committed")
	}
	return nil
}

// TestSCIMAdminRaceNeverLosesChanges covers TEST-050 and PROV-008: a SCIM
// PUT or PATCH whose If-Match was read before an administrator's change to
// the same account or group committed gets 412 instead of overwriting it, a
// SCIM write without If-Match applies on top of the administrator's change
// instead of reverting it, and concurrent SCIM and administration API
// writes never lose the administrator's change without a 412.
func TestSCIMAdminRaceNeverLosesChanges(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	token := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/provisioning-connectors", map[string]any{"name": "Race"}), 201, "connector").Str("token")
	scim := func(method, path string, body any, ifMatch string) *Resp {
		hdr := map[string]string{"Authorization": "Bearer " + token}
		if ifMatch != "" {
			hdr["If-Match"] = ifMatch
		}
		rq := Req{Method: method, Path: "/api/v1/realms/main/scim/v2" + path, Headers: hdr}
		if body != nil {
			rq.JSON = body
		}
		return h.Do(rq)
	}
	patch := func(attr, value string) map[string]any {
		return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": attr, "value": value}}}
	}
	u := scim("POST", "/Users", map[string]any{"userName": "race.user", "externalId": "race-1", "name": map[string]any{"givenName": "Race", "familyName": "User"},
		"displayName": "Race User", "emails": []map[string]any{{"value": "race.user@acme-corp.test", "primary": true}}, "active": true}, "")
	mustStatus(t, u, 201, "provision")
	id := u.Str("id")
	names := func(t *testing.T) (given, family, display string) {
		t.Helper()
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(given_name,''), coalesce(family_name,''), coalesce(display_name,'') FROM users WHERE id=$1`, id).
			Scan(&given, &family, &display); err != nil {
			t.Fatal(err)
		}
		return
	}
	adminEdit := `UPDATE users SET given_name=$2, version=version+1, updated_at=now() WHERE id=$1`

	t.Run("stale If-Match on PATCH", func(t *testing.T) {
		tag := scim("GET", "/Users/"+id, nil, "").Header.Get("ETag")
		r := raceWithPendingWrite(t, h, adminEdit, []any{id, "AdminGiven"}, func() *Resp {
			return scim("PATCH", "/Users/"+id, patch("displayName", "Scim Display"), tag)
		})
		if r.Status != 412 {
			t.Fatalf("SCIM PATCH with a tag read before a concurrent administrator change: %d %s", r.Status, r.Raw)
		}
		if given, _, display := names(t); given != "AdminGiven" || display == "Scim Display" {
			t.Fatalf("administrator change lost: given %q, display %q", given, display)
		}
	})

	t.Run("stale If-Match on PUT", func(t *testing.T) {
		tag := scim("GET", "/Users/"+id, nil, "").Header.Get("ETag")
		r := raceWithPendingWrite(t, h, `UPDATE users SET family_name=$2, version=version+1, updated_at=now() WHERE id=$1`, []any{id, "AdminFamily"}, func() *Resp {
			return scim("PUT", "/Users/"+id, map[string]any{"userName": "race.user", "externalId": "race-1", "displayName": "Put Display",
				"name": map[string]any{"givenName": "AdminGiven", "familyName": "User"}, "emails": []map[string]any{{"value": "race.user@acme-corp.test", "primary": true}},
				"active": true}, tag)
		})
		if r.Status != 412 {
			t.Fatalf("SCIM PUT with a tag read before a concurrent administrator change: %d %s", r.Status, r.Raw)
		}
		if _, family, display := names(t); family != "AdminFamily" || display == "Put Display" {
			t.Fatalf("administrator change lost: family %q, display %q", family, display)
		}
	})

	t.Run("PATCH without If-Match applies on top", func(t *testing.T) {
		r := raceWithPendingWrite(t, h, adminEdit, []any{id, "AdminGiven2"}, func() *Resp {
			return scim("PATCH", "/Users/"+id, patch("displayName", "Scim Display 2"), "")
		})
		mustStatus(t, r, 200, "unconditional SCIM PATCH")
		if given, _, display := names(t); given != "AdminGiven2" || display != "Scim Display 2" {
			t.Fatalf("SCIM PATCH reverted the administrator's change: given %q, display %q", given, display)
		}
	})

	t.Run("stale If-Match on a group", func(t *testing.T) {
		g := scim("POST", "/Groups", map[string]any{"displayName": "Race Team", "externalId": "race-grp"}, "")
		mustStatus(t, g, 201, "group")
		gid := g.Str("id")
		r := raceWithPendingWrite(t, h, `UPDATE groups SET name=$2, version=version+1, updated_at=now() WHERE id=$1`, []any{gid, "Renamed By Admin"}, func() *Resp {
			return scim("PATCH", "/Groups/"+gid, patch("displayName", "Scim Team"), g.Header.Get("ETag"))
		})
		if r.Status != 412 {
			t.Fatalf("SCIM group PATCH with a tag read before a concurrent rename: %d %s", r.Status, r.Raw)
		}
		var name string
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT name FROM groups WHERE id=$1`, gid).Scan(&name)
		if name != "Renamed By Admin" {
			t.Fatalf("administrator rename lost: %q", name)
		}
	})

	t.Run("concurrent SCIM and administration API writes", func(t *testing.T) {
		for i := range 6 {
			tag := scim("GET", "/Users/"+id, nil, "").Header.Get("ETag")
			adminGiven, scimDisplay := "Admin "+string(rune('A'+i)), "Scim "+string(rune('A'+i))
			var wg sync.WaitGroup
			var scimR, adminR *Resp
			wg.Add(2)
			go func() { defer wg.Done(); scimR = scim("PATCH", "/Users/"+id, patch("displayName", scimDisplay), tag) }()
			go func() {
				defer wg.Done()
				adminR = h.API("PATCH", "/users/"+id, f.AdminToken, map[string]any{"given_name": adminGiven})
			}()
			wg.Wait()
			if adminR.Status != 200 || (scimR.Status != 200 && scimR.Status != 412) {
				t.Fatalf("round %d: admin %d %s, SCIM %d %s", i, adminR.Status, adminR.Raw, scimR.Status, scimR.Raw)
			}
			given, _, display := names(t)
			if given != adminGiven {
				t.Fatalf("round %d: the administrator's change was lost (SCIM answered %d): given %q", i, scimR.Status, given)
			}
			if scimR.Status == 200 && display != scimDisplay {
				t.Fatalf("round %d: the SCIM change was acknowledged but lost: display %q", i, display)
			}
		}
	})
}

// TestIdentifierProbeResponses covers API-009 and SEC-005: once the
// deployment's daily SMS budget is spent, a number without an account gets
// the same 429 (body and Retry-After) as one with an account; and a
// temporary password lock reached through one identifier of an account does
// not reveal which other identifiers belong to it, while password guessing
// stays bounded per account.
func TestIdentifierProbeResponses(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Delivery.SMS.Adapter = "dev_sink"
		c.Delivery.SMS.AllowedCountries = []string{"+1"}
		c.Delivery.SMS.DailyBudget = 2
		c.Security.RateLimits.FailuresBeforeLock = 3
		c.Security.RateLimits.TemporaryLock = 10 * time.Minute
		c.Security.RateLimits.LoginPerIdentifier = 100
	})
	f := fixtureOn(t, h, func(p *realm.Policy) {
		p.Login.SMSOTP = true
		p.Login.Identifiers = append(p.Login.Identifiers, "phone")
		p.Login.SMSRiskAccepted = true
	})
	ctx := context.Background()
	cli := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value, verified_at, verification_source)
		VALUES ($1,$2,$3,'phone','+15550100001','+15550100001',now(),'test')`, ids.New(ids.Identifier), h.Realm.ID, f.Users["alice"]); err != nil {
		t.Fatal(err)
	}
	same := func(t *testing.T, what string, a, b *Resp) {
		t.Helper()
		if a.Status != b.Status || a.Str("code") != b.Str("code") || a.Str("detail") != b.Str("detail") || a.Header.Get("Retry-After") != b.Header.Get("Retry-After") {
			t.Fatalf("%s: %d %s (Retry-After %q) vs %d %s (Retry-After %q)", what, a.Status, a.Raw, a.Header.Get("Retry-After"),
				b.Status, b.Raw, b.Header.Get("Retry-After"))
		}
	}

	t.Run("daily SMS budget", func(t *testing.T) {
		send := func(number string) *Resp {
			h.Clock.Advance(2 * time.Second)
			start, _, cont := h.StartTx(cli)
			tx := start.Str("transaction_id")
			mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": number}), 200, "identify")
			return h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"})
		}
		for range 2 {
			mustStatus(t, send("+15550100001"), 200, "send within budget")
		}
		known := send("+15550100001")
		if known.Status != 429 || known.Header.Get("Retry-After") == "" {
			t.Fatalf("SMS budget not enforced: %d %s", known.Status, known.Raw)
		}
		same(t, "unknown number once the SMS budget is spent", send("+15550100009"), known)
		if h.Mail("+15550100009", "login_code") != "" {
			t.Fatal("SMS sent to a number without an account")
		}
	})

	t.Run("password lock across identifiers", func(t *testing.T) {
		attempt := func(identifier, password string) *Resp {
			start, _, cont := h.StartTx(cli)
			tx := start.Str("transaction_id")
			mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": identifier}), 200, "identify "+identifier)
			return h.Step(tx, cont, "password", map[string]any{"password": password})
		}
		const wrong = "not the right passphrase 2026"
		for range 3 {
			mustStatus(t, attempt("bob@example.test", wrong), 401, "failure")
		}
		locked := attempt("bob@example.test", h.passwords["bob@example.test"])
		if locked.Status != 429 || locked.Header.Get("Retry-After") == "" {
			t.Fatalf("lock not applied: %d %s", locked.Status, locked.Raw)
		}
		// bob's username answers like a username without an account: 401s
		// until its own failure budget is spent, then the same 429. Even the
		// right password is not checked while the account is locked.
		for i := range 3 {
			pw := wrong
			if i == 0 {
				pw = h.passwords["bob"]
			}
			k, u := attempt("bob", pw), attempt("ghostuser", wrong)
			if k.Status != 401 {
				t.Fatalf("attempt %d through another identifier of the locked account: %d %s", i, k.Status, k.Raw)
			}
			same(t, "locked account's other identifier vs unknown identifier", k, u)
		}
		k, u := attempt("bob", h.passwords["bob"]), attempt("ghostuser", wrong)
		same(t, "lock of another identifier vs unknown identifier", k, u)
		same(t, "lock of another identifier vs the locked identifier", k, locked)
		// The lock expires by itself.
		h.Clock.Advance(11 * time.Minute)
		mustStatus(t, attempt("bob", h.passwords["bob"]), 200, "after the lock expired")
	})
}

// TestExchangeActorPreservation covers AUD-005 (and MCH-017): the
// token.exchanged audit event names the service principal or agent the
// exchanging client acts as, keeps the whole delegation chain including the
// subject token's earlier actors, and the authorization.decision event for an
// exchanged or agent token keeps the chain and marks agents.
func TestExchangeActorPreservation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	exchange := func(clientID, secret, subject, aud, scope string) *Resp {
		t.Helper()
		r := h.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {subject},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "resource": {aud}, "scope": {scope}}, clientID, secret)
		mustStatus(t, r, 200, "exchange by "+clientID)
		return r
	}
	type event struct {
		actorType, actorID, subjectType, subjectID string
		meta                                       map[string]any
	}
	events := func(typ string) []event {
		t.Helper()
		rows, err := h.App.D.DB.Pool.Query(ctx, `SELECT actor_type, actor_id, coalesce(subject_type,''), coalesce(subject_id,''), metadata FROM audit_events
			WHERE realm_id=$1 AND type=$2 ORDER BY seq`, h.Realm.ID, typ)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []event
		for rows.Next() {
			var e event
			var meta []byte
			if err := rows.Scan(&e.actorType, &e.actorID, &e.subjectType, &e.subjectID, &meta); err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(meta, &e.meta)
			out = append(out, e)
		}
		return out
	}
	chainOf := func(meta map[string]any) []string {
		var subs []string
		list, _ := meta["actor_chain"].([]any)
		for _, x := range list {
			m, _ := x.(map[string]any)
			s, _ := m["sub"].(string)
			if m["agent"] == true {
				s += "(agent)"
			}
			subs = append(subs, s)
		}
		return subs
	}
	ordersSP, alice := f.Clients["orders-rs"].SP, f.Users["alice"]

	// Two hops: orders-rs (a service principal) and then web-bff (a client
	// without one).
	f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"user"}, "exchange_policy": map[string]any{"accept_from_audiences": []string{f.BillingAud}}}), 204, "grant")
	at := f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
	one := exchange("orders-rs", f.Clients["orders-rs"].Secret, at, f.BillingAud, "billing:read")
	two := exchange("web-bff", f.Clients["web"].Secret, one.Str("access_token"), f.OrdersAud, "orders:read")
	ex := events("token.exchanged")
	if len(ex) != 2 {
		t.Fatalf("token.exchanged events: %+v", ex)
	}
	if e := ex[0]; e.actorType != "service_principal" || e.actorID != ordersSP || e.subjectType != "user" || e.subjectID != alice ||
		strings.Join(chainOf(e.meta), ",") != ordersSP || e.meta["chain_depth"] != float64(1) {
		t.Fatalf("first exchange: %+v", e)
	}
	if e := ex[1]; e.actorType != "client" || e.actorID != f.Clients["web"].Ref || e.subjectID != alice ||
		strings.Join(chainOf(e.meta), ",") != "web-bff,"+ordersSP || e.meta["chain_depth"] != float64(2) {
		t.Fatalf("second exchange lost the earlier actor: %+v", e)
	}

	// An agent acting for alice.
	agent := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "triage-agent", "is_agent": true,
		"allowed_organization_ids": []string{f.Acme}}), 201, "agent").Str("id")
	cl := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "triage-bot", "name": "Triage agent", "client_type": "machine",
		"service_principal_id": agent, "grant_types": []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"}}), 201, "agent client")
	f.must(f.AdminAPI("PUT", "/clients/"+cl.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"},
		"subject_types": []string{"service_principal", "user"}, "exchange_policy": map[string]any{"accept_from_audiences": []string{f.BillingAud}}}), 204, "agent grant")
	billing := f.LoginWeb("alice", f.Acme, f.BillingAud, "billing:read").Tokens.Str("access_token")
	delegated := exchange("triage-bot", cl.Str("client_secret"), billing, f.OrdersAud, "orders:read")
	ex = events("token.exchanged")
	if e := ex[len(ex)-1]; e.actorType != "service_principal" || e.actorID != agent || e.subjectID != alice || e.meta["agent"] != true ||
		strings.Join(chainOf(e.meta), ",") != agent+"(agent)" {
		t.Fatalf("agent exchange: %+v", e)
	}

	// Decisions about these tokens keep the whole chain (orders.refund is
	// denied without fresh MFA, so every decision is recorded).
	svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
	decide := func(subject string) {
		t.Helper()
		r := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": subject, "action": "orders.refund",
			"resource": map[string]any{"type": "order", "id": "ord_acme_1", "org_id": f.Acme}})
		mustStatus(t, r, 200, "decision")
		if r.Get("allowed") != false {
			t.Fatalf("decision: %s", r.Raw)
		}
	}
	decide(two.Str("access_token"))
	decide(delegated.Str("access_token"))
	own := h.TokenRequest(url.Values{"grant_type": {"client_credentials"}, "resource": {f.OrdersAud}, "scope": {"orders:read"}, "organization": {f.Acme}},
		"triage-bot", cl.Str("client_secret"))
	mustStatus(t, own, 200, "agent token")
	decide(own.Str("access_token"))
	ds := events("authorization.decision")
	if len(ds) < 3 {
		t.Fatalf("decision events: %+v", ds)
	}
	ds = ds[len(ds)-3:]
	if e := ds[0]; e.actorType != "service_principal" || e.actorID != ordersSP || e.subjectType != "user" || e.subjectID != alice ||
		e.meta["actor"] != "web-bff" || strings.Join(chainOf(e.meta), ",") != "web-bff,"+ordersSP {
		t.Fatalf("decision about an exchanged token: %+v", e)
	}
	if e := ds[1]; e.subjectID != alice || e.meta["actor"] != agent || strings.Join(chainOf(e.meta), ",") != agent+"(agent)" {
		t.Fatalf("decision about an agent's delegated token: %+v", e)
	}
	if e := ds[2]; e.subjectType != "service_principal" || e.subjectID != agent || e.meta["subject_agent"] != true || e.meta["actor_chain"] != nil {
		t.Fatalf("decision about an agent's own token: %+v", e)
	}
}

// TestPasswordlessLinkPurpose covers PWDLESS-008 (with FED-005 and
// PWDLESS-006): a login code or magic link for an identifier without an
// account creates no account; linking an external identity to an existing
// account needs an emailed code or magic link sent for that link, whose
// message names the connection and the linking purpose, so a sign-in code or
// link requested before the link was pending does not complete it; and an SMS
// sign-in never completes a link.
func TestPasswordlessLinkPurpose(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) {
		c.Delivery.SMS.Adapter = "dev_sink"
		c.Delivery.SMS.AllowedCountries = []string{"+1"}
	})
	f := fixtureOn(t, h, func(p *realm.Policy) {
		p.Login.SMSOTP = true
		p.Login.Identifiers = append(p.Login.Identifiers, "phone")
		p.Login.SMSRiskAccepted = true
		p.Login.MagicLink = true
		p.Interaction.LoginUIURL = "https://login.test/ui"
	})
	ctx := context.Background()
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	provID := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "up", "display_name": "Upstream SSO", "issuer": idp.srv.URL,
		"client_secret": "upstream-secret", "config": map[string]any{"client_id": "proudauth-main"}}), 201, "connection").Str("id")
	acct := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}}
	start := func() (string, string) {
		h.Clock.Advance(2 * time.Second)
		st, _, cont := h.StartTx(acct)
		return st.Str("transaction_id"), cont
	}
	upstream := func(tx, cont, user string) *Resp {
		t.Helper()
		idp.next = map[string]any{"sub": "u-" + user, "email": user + "@example.test", "email_verified": true}
		st := h.Step(tx, cont, "federation/start", map[string]any{"provider": "up"})
		mustStatus(t, st, 200, "federation start")
		if cb := h.Do(Req{Method: "GET", Path: idp.browse(t, st.Str("external_redirect"))}); cb.Status >= 400 {
			t.Fatalf("callback: %d %s", cb.Status, cb.Raw)
		}
		r := h.Step(tx, cont, "resume", nil)
		if !has(actionTypes(r), "link_account") {
			t.Fatalf("no pending link for %s: %s", user, r.Raw)
		}
		return r
	}
	linked := func(user string) int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM external_identities WHERE user_id=$1 AND provider_id=$2`, f.Users[user], provID).Scan(&n)
		return n
	}
	accounts := func(email string) int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM user_identifiers WHERE realm_id=$1 AND canonical_value=$2`, h.Realm.ID, email).Scan(&n)
		return n
	}
	magicToken := func(body string) string {
		u, err := url.Parse(regexp.MustCompile(`https://login\.test/ui\S+`).FindString(body))
		if err != nil {
			return ""
		}
		frag, _ := url.ParseQuery(u.Fragment)
		return frag.Get("magic_link")
	}
	// issue creates a real secret for a challenge of the transaction, as
	// SendOTP and sendMagicLink do for an identifier without an account
	// (where nothing is sent), so the verification itself is exercised.
	issue := func(spec authentication.ChallengeSpec) (cid, plain string) {
		t.Helper()
		if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			var err error
			cid, plain, err = h.App.Auth.IssueChallengeTx(ctx, tx, spec)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return
	}

	t.Run("unknown identifiers get no account", func(t *testing.T) {
		tx, cont := start()
		mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": "nobody@example.test"}), 200, "identify")
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send")
		cid, code := issue(authentication.ChallengeSpec{RealmID: h.Realm.ID, Purpose: authentication.PurposeLoginOTP, TransactionID: tx,
			IdentifierType: "email", Identifier: "nobody@example.test"})
		if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE auth_transactions SET pending_state=jsonb_set(pending_state, '{login_otp_challenge}', to_jsonb($1::text))
			WHERE id=$2`, cid, tx); err != nil {
			t.Fatal(err)
		}
		if r := h.Step(tx, cont, "otp/verify", map[string]any{"code": code}); r.Status != 400 || r.Str("redirect_to") != "" {
			t.Fatalf("login code for an unknown identifier: %d %s", r.Status, r.Raw)
		}
		tx, cont = start()
		mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": "nobody2@example.test"}), 200, "identify")
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "magic_link"}), 200, "send link")
		_, link := issue(authentication.ChallengeSpec{RealmID: h.Realm.ID, Purpose: authentication.PurposeMagicLink, TransactionID: tx,
			IdentifierType: "email", Identifier: "nobody2@example.test", Kind: "link", TTL: authentication.MagicLinkTTL, MaxAttempts: 3})
		if r := h.Step(tx, cont, "magic-link", map[string]any{"token": link}); r.Status != 400 || r.Str("redirect_to") != "" {
			t.Fatalf("magic link for an unknown identifier: %d %s", r.Status, r.Raw)
		}
		if accounts("nobody@example.test")+accounts("nobody2@example.test") != 0 {
			t.Fatal("a passwordless challenge created an account")
		}
	})

	t.Run("emailed code names the link", func(t *testing.T) {
		tx, cont := start()
		mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": "alice@example.test"}), 200, "identify")
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "sign-in code")
		early := CodeFrom(h.Mail("alice@example.test", "login_code"))
		upstream(tx, cont, "alice")
		// A sign-in code requested before the link was pending is not proof for it.
		if r := h.Step(tx, cont, "otp/verify", map[string]any{"code": early}); r.Status != 409 || linked("alice") != 0 {
			t.Fatalf("sign-in code completed a link: %d %s", r.Status, r.Raw)
		}
		h.Clock.Advance(2 * time.Second)
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "link code")
		msg := h.Mail("alice@example.test", "account_link_code")
		if !strings.Contains(msg, "Upstream SSO") || !strings.Contains(strings.ToLower(msg), "link") {
			t.Fatalf("the code's message does not state the linking purpose: %q", msg)
		}
		done := h.Drive(tx, cont, h.Step(tx, cont, "otp/verify", map[string]any{"code": CodeFrom(msg)}), LoginOpts{Identifier: "alice@example.test"})
		if done.Str("redirect_to") == "" || linked("alice") != 1 {
			t.Fatalf("link with the emailed code: %s", done.Raw)
		}
	})

	t.Run("magic link names the link", func(t *testing.T) {
		tx, cont := start()
		mustStatus(t, h.Step(tx, cont, "identify", map[string]any{"identifier": "bob@example.test"}), 200, "identify")
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "magic_link"}), 200, "sign-in link")
		early := magicToken(h.Mail("bob@example.test", "magic_link"))
		upstream(tx, cont, "bob")
		if r := h.Step(tx, cont, "magic-link", map[string]any{"token": early}); r.Status != 400 || linked("bob") != 0 {
			t.Fatalf("sign-in link completed a link: %d %s", r.Status, r.Raw)
		}
		h.Clock.Advance(2 * time.Second)
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "magic_link"}), 200, "link")
		msg := h.Mail("bob@example.test", "account_link_magic_link")
		if !strings.Contains(msg, "Upstream SSO") || !strings.Contains(strings.ToLower(msg), "link") {
			t.Fatalf("the link's message does not state the linking purpose: %q", msg)
		}
		done := h.Drive(tx, cont, h.Step(tx, cont, "magic-link", map[string]any{"token": magicToken(msg)}), LoginOpts{Identifier: "bob@example.test"})
		if done.Str("redirect_to") == "" || linked("bob") != 1 {
			t.Fatalf("link with the magic link: %s", done.Raw)
		}
	})

	t.Run("SMS never completes a link", func(t *testing.T) {
		if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value, verified_at, verification_source)
			VALUES ($1,$2,$3,'phone','+15550100003','+15550100003',now(),'test')`, ids.New(ids.Identifier), h.Realm.ID, f.Users["carol"]); err != nil {
			t.Fatal(err)
		}
		tx, cont := start()
		upstream(tx, cont, "carol")
		st := h.Step(tx, cont, "identify", map[string]any{"identifier": "+15550100003"})
		mustStatus(t, st, 200, "identify by phone")
		if has(actionTypes(st), "link_account") {
			t.Fatalf("link still pending for an SMS sign-in: %s", st.Raw)
		}
		mustStatus(t, h.Step(tx, cont, "otp/send", map[string]any{"purpose": "login"}), 200, "send SMS")
		done := h.Drive(tx, cont, h.Step(tx, cont, "otp/verify", map[string]any{"code": CodeFrom(h.Mail("+15550100003", "login_code"))}),
			LoginOpts{Identifier: "carol@example.test"})
		if done.Status >= 400 {
			t.Fatalf("SMS sign-in: %d %s", done.Status, done.Raw)
		}
		if linked("carol") != 0 {
			t.Fatal("an SMS sign-in linked the external identity")
		}
	})
}
