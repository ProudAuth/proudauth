package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/token"
)

// TestHookBounds covers TEST-053 (EXT-009, EXT-011, EXT-012, EXT-017): a
// pre-action hook that exceeds its timeout_ms or crashes fails the way its
// kind declares (closed for registration eligibility, claims enrichment and
// authorization decisions; claims enrichment is skipped only with
// failure_mode skip), within its timeout, and its diagnostics say why. An
// answer outside the contract (a protected claim, more than 20 claims or
// 4 KiB of claims, more than five obligations) is refused as a whole and
// never raises authority: no protected claim of a hook ever reaches a token.
func TestHookBounds(t *testing.T) {
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	ep := newEndpoint(t)
	type answerFn = func(r *http.Request, body []byte) (int, http.Header, []byte)
	var mu sync.Mutex
	answers := map[string]answerFn{}
	ep.setAnswer(func(r *http.Request, body []byte) (int, http.Header, []byte) {
		mu.Lock()
		fn := answers[r.URL.Path]
		mu.Unlock()
		if fn == nil {
			return 404, nil, nil
		}
		return fn(r, body)
	})
	answer := func(name string, fn answerFn) {
		mu.Lock()
		answers["/"+name] = fn
		mu.Unlock()
	}
	jsonAnswer := func(v any) answerFn {
		b, _ := json.Marshal(v)
		return func(*http.Request, []byte) (int, http.Header, []byte) { return 200, nil, b }
	}
	// stall answers only after the caller gave up (or after 10 s).
	stall := func(r *http.Request, _ []byte) (int, http.Header, []byte) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		return 200, nil, []byte(`{"allow": true}`)
	}
	// crash drops the connection without an answer.
	crash := func(*http.Request, []byte) (int, http.Header, []byte) { panic(http.ErrAbortHandler) }

	// create registers a hook that is deleted when the subtest ends; it
	// returns the hook's ID and its configuration for updates.
	create := func(t *testing.T, name, kind string, extra map[string]any) (string, map[string]any) {
		t.Helper()
		body := map[string]any{"name": name, "kind": kind, "url": ep.srv.URL + "/" + name, "allow_private_network": true}
		for k, v := range extra {
			body[k] = v
		}
		r := f.AdminAPI("POST", "/hooks", body)
		mustStatus(t, r, 201, "hook "+name)
		id := r.Str("hook.id")
		t.Cleanup(func() {
			if r := f.AdminAPI("DELETE", "/hooks/"+id, nil); r.Status != 204 {
				t.Errorf("delete hook %s: %d %s", name, r.Status, r.Raw)
			}
		})
		return id, body
	}
	update := func(t *testing.T, id string, body map[string]any) {
		t.Helper()
		cur := f.AdminAPI("GET", "/hooks/"+id, nil)
		mustStatus(t, cur, 200, "get hook")
		mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/hooks/" + id, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}, JSON: body}), 200, "update hook")
	}
	// failures returns the recorded failures of a hook by error category
	// (EXT-017).
	failures := func(t *testing.T, id string) map[string]int {
		t.Helper()
		d := f.AdminAPI("GET", "/hooks/"+id+"/diagnostics", nil)
		mustStatus(t, d, 200, "diagnostics")
		out := map[string]int{}
		for _, it := range d.Get("invocations").([]any) {
			inv := it.(map[string]any)
			if inv["outcome"] != "ok" {
				cat, _ := inv["error_category"].(string)
				out[cat]++
				if lat, _ := inv["latency_ms"].(float64); lat > 5000 {
					t.Errorf("a failed call took %v ms, beyond any hook timeout", lat)
				}
			}
		}
		return out
	}
	register := func(t *testing.T, email string) *Resp {
		t.Helper()
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud}})
		mustStatus(t, start, 201, "start transaction")
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": start.Str("transaction_id"),
			"email": email, "password": "a brand new passphrase 2026"}, Headers: map[string]string{"X-Transaction-Token": cont}})
	}
	accounts := func(t *testing.T, email string) int {
		t.Helper()
		var n int
		if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM user_identifiers WHERE canonical_value=$1`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	batch := f.Clients["batch"]
	machine := func() *Resp { return f.MachineToken(batch, f.BillingAud, "billing:read", f.Acme) }

	t.Run("a hook that exceeds its timeout fails closed within it", func(t *testing.T) {
		id, _ := create(t, "slow-eligibility", "registration.eligibility", map[string]any{"timeout_ms": 200})
		answer("slow-eligibility", stall)
		began := time.Now()
		r := register(t, "slow@allowed.test")
		if took := time.Since(began); took > 5*time.Second {
			t.Fatalf("registration waited %v for a hook with a 200 ms timeout", took)
		}
		if r.Status != 503 {
			t.Fatalf("a timed-out eligibility hook must fail closed: %d %s", r.Status, r.Raw)
		}
		if n := accounts(t, "slow@allowed.test"); n != 0 {
			t.Fatalf("an account was created although the eligibility hook timed out: %d", n)
		}
		if got := failures(t, id); got["timeout"] != 1 || len(got) != 1 {
			t.Fatalf("diagnostics categories %v, want one timeout", got)
		}
	})

	t.Run("a crashing hook fails closed", func(t *testing.T) {
		id, _ := create(t, "crashing-eligibility", "registration.eligibility", nil)
		answer("crashing-eligibility", crash)
		if r := register(t, "crash@allowed.test"); r.Status != 503 {
			t.Fatalf("a crashing eligibility hook must fail closed: %d %s", r.Status, r.Raw)
		}
		if n := accounts(t, "crash@allowed.test"); n != 0 {
			t.Fatalf("an account was created although the eligibility hook crashed: %d", n)
		}
		if got := failures(t, id); got["unreachable"] != 1 || len(got) != 1 {
			t.Fatalf("diagnostics categories %v, want one unreachable", got)
		}
	})

	t.Run("registration works again without the failing hooks", func(t *testing.T) {
		mustStatus(t, register(t, "fine@allowed.test"), 201, "registration without hooks")
	})

	t.Run("a claims hook that exceeds its timeout fails issuance closed unless skipped", func(t *testing.T) {
		id, body := create(t, "slow-claims", "token.claims", map[string]any{"timeout_ms": 200, "client_ids": []string{"batch-job"}})
		answer("slow-claims", stall)
		if r := machine(); r.Status != 503 || r.Str("error") != "temporarily_unavailable" || r.Str("access_token") != "" {
			t.Fatalf("a timed-out claims hook must fail issuance closed: %d %s", r.Status, r.Raw)
		}
		if got := failures(t, id); got["timeout"] != 1 || len(got) != 1 {
			t.Fatalf("diagnostics categories %v, want one timeout", got)
		}
		body["failure_mode"] = "skip"
		update(t, id, body)
		r := machine()
		mustStatus(t, r, 200, "token with a skipped claims hook")
		if c := jwtPayload(r.Str("access_token")); c["sub"] != batch.SP || c["tenant_tier"] != nil {
			t.Fatalf("skip-mode token: %v", c)
		}
	})

	t.Run("protected claims are refused and never reach a token", func(t *testing.T) {
		id, body := create(t, "claims", "token.claims", map[string]any{"client_ids": []string{"batch-job", "web-bff"}})
		setClaims := func(c map[string]any) { answer("claims", jsonAnswer(map[string]any{"claims": c})) }
		setClaims(map[string]any{"tenant_tier": "gold"})
		r := machine()
		mustStatus(t, r, 200, "token with an ordinary hook claim")
		if c := jwtPayload(r.Str("access_token")); c["tenant_tier"] != "gold" || c["sub"] != batch.SP {
			t.Fatalf("claims hook: %v", c)
		}
		// Every reserved claim the server defines, roles, permissions and an
		// over-long claim name, each with a value a hostile hook might send.
		hostile := map[string]any{"roles": []string{"hook-injected-admin"}, "permissions": []string{"hook-injected:orders.refund"},
			strings.Repeat("x", 65): "hook-injected"}
		for k := range token.ReservedClaims {
			hostile[k] = "hook-injected"
		}
		hostile["aud"] = []string{"https://hook-injected.test"}
		hostile["exp"] = 4102444800
		hostile["scope"] = "billing:read billing:admin hook-injected"
		hostile["org_id"] = f.Globex
		hostile["act"] = map[string]any{"sub": "hook-injected"}
		hostile["cnf"] = map[string]any{"jkt": "hook-injected"}
		hostile["token_kind"] = "impersonation_access"
		hostile["support_mode"] = "write"
		names := make([]string, 0, len(hostile))
		for k := range hostile {
			names = append(names, k)
		}
		slices.Sort(names)
		for _, k := range names {
			setClaims(map[string]any{"tenant_tier": "gold", k: hostile[k]})
			if r := machine(); r.Status != 503 || r.Str("error") != "temporarily_unavailable" || r.Str("access_token") != "" {
				t.Errorf("claims hook setting %q: %d %s", k, r.Status, r.Raw)
			}
		}
		if got := failures(t, id); got["malformed_response"] != len(names) || len(got) != 1 {
			t.Fatalf("diagnostics categories %v, want %d malformed_response", got, len(names))
		}
		// With failure_mode skip the token is issued, but without anything
		// of the refused answer: the server's values stand.
		body["failure_mode"] = "skip"
		update(t, id, body)
		all := map[string]any{"tenant_tier": "gold"}
		for k, v := range hostile {
			all[k] = v
		}
		setClaims(all)
		untouched := func(what string, c map[string]any, sub, aud, scope, org, kind string) {
			t.Helper()
			raw, _ := json.Marshal(c)
			if strings.Contains(string(raw), "hook-injected") || c["tenant_tier"] != nil || c["roles"] != nil || c["permissions"] != nil ||
				c["act"] != nil || c["cnf"] != nil || c["support_mode"] != nil || c["exp"] == float64(4102444800) {
				t.Fatalf("%s carries hook claims: %s", what, raw)
			}
			if c["sub"] != sub || c["aud"] != aud || c["scope"] != scope || c["org_id"] != org || c["token_kind"] != kind || c["iss"] != h.Realm.Issuer {
				t.Fatalf("%s reserved claims changed: %s", what, raw)
			}
		}
		r = machine()
		mustStatus(t, r, 200, "skip-mode machine token")
		untouched("machine token", jwtPayload(r.Str("access_token")), batch.SP, f.BillingAud, "billing:read", f.Acme, "service_access")
		lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
		untouched("user token", jwtPayload(lr.Tokens.Str("access_token")), f.Users["bob"], f.OrdersAud, "orders:read", f.Acme, "user_access")
	})

	t.Run("more than 20 claims or 4 KiB of claims are refused", func(t *testing.T) {
		id, body := create(t, "sized-claims", "token.claims", map[string]any{"client_ids": []string{"batch-job"}})
		setClaims := func(c map[string]any) { answer("sized-claims", jsonAnswer(map[string]any{"claims": c})) }
		twenty := map[string]any{}
		for i := range 20 {
			twenty[fmt.Sprintf("claim_%02d", i)] = i
		}
		setClaims(twenty)
		r := machine()
		mustStatus(t, r, 200, "20 claims")
		if c := jwtPayload(r.Str("access_token")); c["claim_00"] != float64(0) || c["claim_19"] != float64(19) {
			t.Fatalf("20 claims not added: %v", c)
		}
		twenty["claim_20"] = 20
		setClaims(twenty)
		if r := machine(); r.Status != 503 {
			t.Fatalf("21 claims: %d %s", r.Status, r.Raw)
		}
		// {"big":"…"} serializes to 10 bytes plus the value.
		setClaims(map[string]any{"big": strings.Repeat("a", 4096-10)})
		r = machine()
		mustStatus(t, r, 200, "exactly 4 KiB of claims")
		if c := jwtPayload(r.Str("access_token")); len(fmt.Sprint(c["big"])) != 4086 {
			t.Fatalf("4 KiB claim not added")
		}
		setClaims(map[string]any{"big": strings.Repeat("a", 4096-9)})
		if r := machine(); r.Status != 503 {
			t.Fatalf("4 KiB + 1 byte of claims: %d %s", r.Status, r.Raw)
		}
		five := map[string]any{}
		for i := range 5 {
			five[fmt.Sprintf("part_%d", i)] = strings.Repeat("b", 1000)
		}
		setClaims(five)
		if r := machine(); r.Status != 503 {
			t.Fatalf("5000 bytes over five claims: %d %s", r.Status, r.Raw)
		}
		if got := failures(t, id); got["malformed_response"] != 3 || len(got) != 1 {
			t.Fatalf("diagnostics categories %v, want 3 malformed_response", got)
		}
		body["failure_mode"] = "skip"
		update(t, id, body)
		setClaims(twenty)
		r = machine()
		mustStatus(t, r, 200, "skip-mode token")
		if c := jwtPayload(r.Str("access_token")); c["claim_00"] != nil || c["claim_20"] != nil {
			t.Fatalf("an oversized answer was partly applied: %v", c)
		}
	})

	t.Run("authorization hooks: obligations are bounded, failures deny", func(t *testing.T) {
		svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		check := func() *Resp {
			t.Helper()
			r := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": "orders.read",
				"resource": map[string]any{"type": "order", "org_id": f.Acme}})
			mustStatus(t, r, 200, "authorization check")
			return r
		}
		hookObligations := func(r *Resp) int {
			n := 0
			list, _ := r.Get("obligations").([]any)
			for _, o := range list {
				if m, _ := o.(map[string]any); strings.HasPrefix(fmt.Sprint(m["ref"]), "hook-") {
					n++
				}
			}
			return n
		}
		if r := check(); r.Get("allowed") != true {
			t.Fatalf("baseline decision without hooks: %s", r.Raw)
		}
		id, body := create(t, "decisions", "authorization.decision", nil)
		obligations := func(allow bool, n int) answerFn {
			list := []map[string]any{}
			for i := range n {
				list = append(list, map[string]any{"type": "notify", "ref": fmt.Sprintf("hook-%d", i)})
			}
			return jsonAnswer(map[string]any{"allow": allow, "obligations": list})
		}
		answer("decisions", obligations(true, 5))
		if r := check(); r.Get("allowed") != true || hookObligations(r) != 5 {
			t.Fatalf("five obligations: %s", r.Raw)
		}
		answer("decisions", obligations(true, 6))
		if r := check(); r.Get("allowed") != false || r.Str("reason_code") != "HOOK_INVALID_RESPONSE" || hookObligations(r) != 0 {
			t.Fatalf("six obligations must deny: %s", r.Raw)
		}
		answer("decisions", obligations(false, 6))
		if r := check(); r.Get("allowed") != false || r.Str("reason_code") != "HOOK_INVALID_RESPONSE" || hookObligations(r) != 0 {
			t.Fatalf("a denial with six obligations: %s", r.Raw)
		}
		if got := failures(t, id); got["malformed_response"] != 2 || len(got) != 1 {
			t.Fatalf("diagnostics categories %v, want 2 malformed_response", got)
		}
		body["timeout_ms"] = 200
		update(t, id, body)
		answer("decisions", stall)
		began := time.Now()
		if r := check(); r.Get("allowed") != false || r.Str("reason_code") != "HOOK_UNAVAILABLE" {
			t.Fatalf("a timed-out authorization hook must deny: %s", r.Raw)
		}
		if took := time.Since(began); took > 5*time.Second {
			t.Fatalf("the decision waited %v for a hook with a 200 ms timeout", took)
		}
		answer("decisions", crash)
		if r := check(); r.Get("allowed") != false || r.Str("reason_code") != "HOOK_UNAVAILABLE" {
			t.Fatalf("a crashing authorization hook must deny: %s", r.Raw)
		}
		if got := failures(t, id); got["malformed_response"] != 2 || got["timeout"] != 1 || got["unreachable"] != 1 || len(got) != 3 {
			t.Fatalf("diagnostics categories %v", got)
		}
	})
}
