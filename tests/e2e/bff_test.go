package e2e

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth-sdk-go/oidcclient"
	"github.com/proudauth/proudauth/examples/backend-for-frontend/bff"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestBackendForFrontendExample covers SDK-004: the runnable
// backend-for-frontend example logs in with the code flow, PKCE and client
// authentication, keeps tokens server-side behind an opaque cookie, serializes
// concurrent refreshes and logs out with an origin check.
func TestBackendForFrontendExample(t *testing.T) {
	f := NewFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
	h := f.H
	svc := f.StartServices(t)
	bffSrv := httptest.NewUnstartedServer(nil)
	bffSrv.StartTLS()
	defer bffSrv.Close()
	reg := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "bff-example", "name": "BFF example", "client_type": "confidential",
		"first_party": true, "environment": "development", "redirect_uris": []string{bffSrv.URL + "/callback"},
		"post_logout_redirect_uris": []string{bffSrv.URL + "/"}}), 201, "client")
	f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+f.Orders, map[string]any{"allowed_scopes": []string{"orders:read"}}), 204, "grant")
	resources := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	for _, it := range resources.Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			f.must(f.AdminAPI("PUT", "/clients/"+reg.Str("client.id")+"/resource-grants/"+m["id"].(string), map[string]any{"allowed_scopes": []string{"openid", "profile", "email"}}), 204, "oidc")
		}
	}
	client, err := oidcclient.New(oidcclient.Config{Issuer: h.Realm.Issuer, ClientID: "bff-example", ClientSecret: reg.Str("client_secret"),
		RedirectURI: bffSrv.URL + "/callback", Scopes: []string{"openid", "orders:read"}, Resource: f.OrdersAud, Now: h.Clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	app := bff.New(client, svc.OrdersURL, bffSrv.URL, bffSrv.URL+"/")
	bffSrv.Config.Handler = app.Handler()

	jar, _ := cookiejar.New(nil)
	ua := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	get := func(u string) *http.Response {
		res, err := ua.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res
	}
	res := get(bffSrv.URL + "/login?organization=" + f.Acme)
	res = get(res.Header.Get("Location")) // IdP authorize -> login UI
	loc, _ := url.Parse(res.Header.Get("Location"))
	tx := loc.Query().Get("transaction_id")
	b := &browser{h: h, client: ua}
	st := b.do("GET", "/api/v1/realms/main/auth/transactions/"+tx, nil, nil)
	hdr := map[string]string{"Origin": h.Base, "X-CSRF-Token": st.Str("csrf_token")}
	b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/identify", map[string]any{"identifier": "bob@example.test"}, hdr)
	done := b.do("POST", "/api/v1/realms/main/auth/transactions/"+tx+"/password", map[string]any{"password": h.passwords["bob@example.test"]}, hdr)
	if done.Str("redirect_to") == "" {
		t.Fatalf("login: %s", done.Raw)
	}
	res = get(done.Str("redirect_to")) // BFF callback
	if res.StatusCode != http.StatusFound {
		t.Fatalf("callback: %d", res.StatusCode)
	}
	call := func() int {
		r, err := ua.Get(bffSrv.URL + "/api/orders")
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		return r.StatusCode
	}
	if s := call(); s != 200 {
		t.Fatalf("orders through BFF: %d", s)
	}
	// Tokens never reach the browser: only an opaque session cookie.
	for _, c := range jar.Cookies(mustURL(bffSrv.URL)) {
		if strings.HasPrefix(c.Value, "eyJ") || strings.HasPrefix(c.Value, "pa_") {
			t.Fatal("token stored in a browser cookie")
		}
	}
	// SES-009: concurrent requests across expiry share one serialized refresh.
	h.Clock.Advance(6 * time.Minute)
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i] = call() }(i)
	}
	wg.Wait()
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("serialized refresh failed: %v", codes)
		}
	}
	f.ReloginAdmin()
	reuse := f.must(f.AdminAPI("GET", "/audit-events?type=token.refresh.reuse_detected", nil), 200, "audit")
	if len(reuse.Get("items").([]any)) != 0 {
		t.Fatal("concurrent BFF requests triggered refresh reuse detection")
	}
	req, _ := http.NewRequest("POST", bffSrv.URL+"/logout", nil)
	req.Header.Set("Origin", "https://evil.test")
	if r, _ := ua.Do(req); r.StatusCode != 403 {
		t.Fatal("cross-site logout accepted")
	}
	req, _ = http.NewRequest("POST", bffSrv.URL+"/logout", nil)
	req.Header.Set("Origin", bffSrv.URL)
	if r, _ := ua.Do(req); r.StatusCode != 200 {
		t.Fatal("logout failed")
	}
	if s := call(); s != 401 {
		t.Fatalf("session survived logout: %d", s)
	}
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

func TestOIDCClientValidationFixtures(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	lr := f.H.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: "openid orders:read",
		Resources: []string{f.OrdersAud}, Organization: f.Acme, SelectOrg: f.Acme, Identifier: "alice@example.test", Nonce: "nonce-123"})
	idt, at := lr.Tokens.Str("id_token"), lr.Tokens.Str("access_token")
	c, _ := oidcclient.New(oidcclient.Config{Issuer: h.Realm.Issuer, ClientID: "web-bff", RedirectURI: webRedirect, Now: h.Clock.Now})
	if _, err := c.ValidateIDToken(ctx, idt, "nonce-123", at); err != nil {
		t.Fatalf("valid ID token rejected: %v", err)
	}
	wrongAud, _ := oidcclient.New(oidcclient.Config{Issuer: h.Realm.Issuer, ClientID: "partner-app", RedirectURI: "https://partner.test/cb", Now: h.Clock.Now})
	wrongIss, _ := oidcclient.New(oidcclient.Config{Issuer: h.Realm.Issuer + "x", ClientID: "web-bff", RedirectURI: webRedirect, Now: h.Clock.Now})
	parts := strings.Split(idt, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	cases := map[string]func() error{
		"wrong audience":           func() error { _, err := wrongAud.ValidateIDToken(ctx, idt, "nonce-123", ""); return err },
		"wrong issuer":             func() error { _, err := wrongIss.ValidateIDToken(ctx, idt, "nonce-123", ""); return err },
		"wrong nonce":              func() error { _, err := c.ValidateIDToken(ctx, idt, "other", ""); return err },
		"wrong at_hash":            func() error { _, err := c.ValidateIDToken(ctx, idt, "nonce-123", "different-access-token"); return err },
		"tampered signature":       func() error { _, err := c.ValidateIDToken(ctx, tampered, "nonce-123", ""); return err },
		"access token as ID token": func() error { _, err := c.ValidateIDToken(ctx, at, "", ""); return err },
		"unsigned": func() error {
			_, err := c.ValidateIDToken(ctx, unsigned(jwtPayload(idt), `{"alg":"none"}`), "nonce-123", "")
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	h.Clock.Advance(10 * time.Minute)
	if _, err := c.ValidateIDToken(ctx, idt, "nonce-123", ""); !errors.Is(err, oidcclient.ErrIDToken) {
		t.Fatal("expired ID token accepted")
	}
}
