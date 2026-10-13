package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// hookServer is an operator hook endpoint whose behavior tests switch.
type hookServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	secrets map[string]string // path -> signing secret
	mode    string            // "", "down", "bad_claims"
	badSig  bool
}

func newHookServer(t *testing.T) *hookServer {
	hs := &hookServer{secrets: map[string]string{}}
	hs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		hs.mu.Lock()
		secret, mode := hs.secrets[r.URL.Path], hs.mode
		hs.mu.Unlock()
		// Verify the server's signature like a real hook would.
		key, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "hksec_"))
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(r.Header.Get("Webhook-Id") + "." + r.Header.Get("Webhook-Timestamp") + "."))
		mac.Write(body)
		if r.Header.Get("Webhook-Signature") != "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
			hs.mu.Lock()
			hs.badSig = true
			hs.mu.Unlock()
		}
		if mode == "down" {
			w.WriteHeader(500)
			return
		}
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		var out any
		switch in["hook_kind"] {
		case "registration.eligibility":
			reg := in["registration"].(map[string]any)
			out = map[string]any{"allow": reg["email_domain"] != "blocked.test", "reason_code": "DOMAIN_NOT_ELIGIBLE"}
		case "profile.validation":
			prof := in["profile"].(map[string]any)
			if name, _ := prof["display_name"].(string); strings.Contains(strings.ToLower(name), "admin") {
				out = map[string]any{"allow": false, "errors": map[string]any{"display_name": "may not impersonate staff"}}
			} else {
				out = map[string]any{"allow": true}
			}
		case "token.claims":
			if mode == "bad_claims" {
				out = map[string]any{"claims": map[string]any{"sub": "usr_attacker"}}
			} else {
				out = map[string]any{"claims": map[string]any{"tenant_tier": "gold"}}
			}
		case "authorization.decision":
			d := in["decision"].(map[string]any)
			ctx, _ := d["context"].(map[string]any)
			out = map[string]any{"allow": ctx["frozen"] != true, "reason_code": "ACCOUNT_FROZEN"}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(hs.srv.Close)
	return hs
}

// TestPreActionHooks covers EXT-009, EXT-011, EXT-012 and EXT-017.
func TestPreActionHooks(t *testing.T) {
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	hs := newHookServer(t)
	create := func(name, kind string, extra map[string]any) string {
		body := map[string]any{"name": name, "kind": kind, "url": hs.srv.URL + "/" + name, "allow_private_network": true}
		for k, v := range extra {
			body[k] = v
		}
		r := f.must(f.AdminAPI("POST", "/hooks", body), 201, "hook "+name)
		hs.mu.Lock()
		hs.secrets["/"+name] = r.Str("signing_secret")
		hs.mu.Unlock()
		return r.Str("hook.id")
	}
	register := func(email string) *Resp {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud}})
		return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": start.Str("transaction_id"),
			"email": email, "password": "a brand new passphrase 2026"}, Headers: map[string]string{"X-Transaction-Token": cont}})
	}

	t.Run("registration eligibility fails closed", func(t *testing.T) {
		id := create("eligibility", "registration.eligibility", nil)
		if r := register("eve@blocked.test"); r.Status != 403 {
			t.Fatalf("ineligible registration accepted: %d %s", r.Status, r.Raw)
		}
		if r := register("ok@allowed.test"); r.Status != 201 {
			t.Fatalf("eligible registration refused: %d %s", r.Status, r.Raw)
		}
		hs.mode = "down"
		if r := register("later@allowed.test"); r.Status != 503 {
			t.Fatalf("unreachable eligibility hook must fail closed: %d", r.Status)
		}
		hs.mode = ""
		st := f.must(f.AdminAPI("GET", "/hooks/"+id, nil), 200, "hook health")
		if st.Get("invocations").(float64) < 3 || st.Get("failures").(float64) < 1 || st.Str("last_error") == "" {
			t.Fatalf("hook diagnostics: %s", st.Raw)
		}
		// EXT-017: per-invocation diagnostics carry outcome, latency and a
		// coarse error category, never payloads.
		diag := f.must(f.AdminAPI("GET", "/hooks/"+id+"/diagnostics", nil), 200, "diagnostics")
		if diag.Get("recent_invocations").(float64) < 3 || diag.Get("recent_failures").(float64) < 1 || diag.Str("health") == "" {
			t.Fatalf("diagnostics: %s", diag.Raw)
		}
		if strings.Contains(string(diag.Raw), "blocked.test") || strings.Contains(string(diag.Raw), "allowed.test") {
			t.Fatal("diagnostics leaked hook payloads")
		}
		if !strings.Contains(string(diag.Raw), `"error_category":"status","status_code":500`) {
			t.Fatalf("failure category missing: %s", diag.Raw)
		}
		cur := f.must(f.AdminAPI("GET", "/hooks/"+id, nil), 200, "get")
		mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/hooks/" + id, Token: f.AdminToken, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")},
			JSON: map[string]any{"name": "eligibility", "kind": "registration.eligibility", "url": hs.srv.URL + "/eligibility", "allow_private_network": true, "state": "disabled"}}), 200, "disable")
	})

	t.Run("security hooks cannot be configured to fail open", func(t *testing.T) {
		f.must(f.AdminAPI("POST", "/hooks", map[string]any{"name": "lenient", "kind": "authorization.decision", "url": hs.srv.URL + "/x",
			"allow_private_network": true, "failure_mode": "skip"}), 422, "fail-open security hook")
	})

	t.Run("profile validation", func(t *testing.T) {
		create("profile", "profile.validation", nil)
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		if r := h.API("PATCH", "/me", bob, map[string]any{"display_name": "Real Admin"}); r.Status != 422 {
			t.Fatalf("profile hook bypassed: %d %s", r.Status, r.Raw)
		}
		if r := h.API("PATCH", "/me", bob, map[string]any{"display_name": "Bobby"}); r.Status != 200 {
			t.Fatalf("valid profile refused: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("claims enrichment cannot override reserved claims", func(t *testing.T) {
		id := create("claims", "token.claims", map[string]any{"client_ids": []string{"web-bff"}})
		lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
		claims := jwtPayload(lr.Tokens.Str("access_token"))
		if claims["tenant_tier"] != "gold" || claims["sub"] != f.Users["bob"] {
			t.Fatalf("claims hook: %v", claims)
		}
		hs.mode = "bad_claims"
		lr = f.H.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "orders:read",
			Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "bob@example.test", ExpectFail: true})
		if lr.Tokens == nil || lr.Tokens.Status == 200 {
			t.Fatal("token issued although the claims hook tried to override sub")
		}
		// With failure_mode=skip the token is issued without hook claims.
		cur := f.must(f.AdminAPI("GET", "/hooks/"+id, nil), 200, "get")
		mustStatus(t, h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/hooks/" + id, Token: f.AdminToken, Headers: map[string]string{"If-Match": cur.Header.Get("ETag")},
			JSON: map[string]any{"name": "claims", "kind": "token.claims", "url": hs.srv.URL + "/claims", "allow_private_network": true, "failure_mode": "skip",
				"client_ids": []string{"web-bff"}}}), 200, "skip mode")
		lr = f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
		claims = jwtPayload(lr.Tokens.Str("access_token"))
		if claims["sub"] != f.Users["bob"] || claims["tenant_tier"] != nil {
			t.Fatalf("skip-mode claims: %v", claims)
		}
		hs.mode = ""
	})

	t.Run("authorization hooks deny but never grant", func(t *testing.T) {
		create("decisions", "authorization.decision", nil)
		svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		bob := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		check := func(action string, ctx map[string]any) *Resp {
			return h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": bob, "action": action,
				"resource": map[string]any{"type": "order", "org_id": f.Acme}, "context": ctx})
		}
		if r := check("orders.read", map[string]any{"frozen": true}); r.Get("allowed") != false || r.Str("reason_code") != "ACCOUNT_FROZEN" {
			t.Fatalf("hook denial ignored: %s", r.Raw)
		}
		if r := check("orders.read", nil); r.Get("allowed") != true {
			t.Fatalf("hook allow path: %s", r.Raw)
		}
		if r := check("orders.refund", nil); r.Get("allowed") != false || r.Str("reason_code") != "NOT_PERMITTED" {
			t.Fatalf("hook granted beyond RBAC: %s", r.Raw)
		}
	})
	hs.mu.Lock()
	defer hs.mu.Unlock()
	if hs.badSig {
		t.Fatal("a hook request carried an invalid signature")
	}
}
