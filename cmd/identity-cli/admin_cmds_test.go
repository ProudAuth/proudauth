package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestAdminCommandsCallAdministrationAPI covers SDK-003 for the CLI: the
// administration commands for users, organizations, invitations, clients,
// roles and assignments, client grants, sessions, support grants and
// permission inspection call the typed public administration API with the
// stored token. A realm role is assigned without a scope, so the server
// applies the request's realm (the realm's name is not its ID).
func TestAdminCommandsCallAdministrationAPI(t *testing.T) {
	useTempConfigDir(t)
	type call struct{ method, path, query, auth string }
	var mu sync.Mutex
	var calls []call
	bodies := map[string]map[string]any{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		calls = append(calls, call{r.Method, strings.TrimPrefix(r.URL.Path, "/api/v1/realms/main"), r.URL.RawQuery, r.Header.Get("Authorization")})
		if len(raw) > 0 {
			var m map[string]any
			_ = json.Unmarshal(raw, &m)
			bodies[r.Method+" "+r.URL.Path] = m
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()
	if err := saveCreds(&credentials{URL: srv.URL, Realm: "main", Audience: "admin", AccessToken: "at-admin", RefreshToken: "rt",
		Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = stdout; devnull.Close() })

	run := []struct {
		args []string
		want call
	}{
		{[]string{"users", "--q", "bob@example.test"}, call{"GET", "/users", "q=bob%40example.test", ""}},
		{[]string{"orgs"}, call{"GET", "/organizations", "", ""}},
		{[]string{"invite", "--org", "org_1", "--email", "new@example.test"}, call{"POST", "/organizations/org_1/invitations", "", ""}},
		{[]string{"revoke-sessions", "--user", "usr_1"}, call{"POST", "/users/usr_1/revoke-sessions", "", ""}},
		{[]string{"clients"}, call{"GET", "/clients", "", ""}},
		{[]string{"roles", "--boundary", "realm"}, call{"GET", "/roles", "boundary_type=realm", ""}},
		{[]string{"assign-role", "--role", "rol_admin", "--subject", "usr_1"}, call{"POST", "/role-assignments", "", ""}},
		{[]string{"assign-role", "--role", "rol_viewer", "--subject", "svc_1", "--org", "org_1"}, call{"POST", "/role-assignments", "", ""}},
		{[]string{"grant-scopes", "--client", "cli_1", "--resource", "res_1", "--scopes", "orders:read,orders:write"}, call{"PUT", "/clients/cli_1/resource-grants/res_1", "", ""}},
		{[]string{"sessions", "--user", "usr_1"}, call{"GET", "/users/usr_1/sessions", "", ""}},
		{[]string{"sessions", "--user", "usr_1", "--revoke", "ses_1"}, call{"DELETE", "/users/usr_1/sessions/ses_1", "", ""}},
		{[]string{"invitations", "--org", "org_1", "--state", "pending"}, call{"GET", "/organizations/org_1/invitations", "state=pending", ""}},
		{[]string{"invitations", "--org", "org_1", "--revoke", "inv_1"}, call{"POST", "/organizations/org_1/invitations/inv_1/revoke", "", ""}},
		{[]string{"support-grants", "--org", "org_1"}, call{"GET", "/impersonation-grants", "organization_id=org_1&state=active", ""}},
		{[]string{"support-grants", "--revoke", "img_1", "--reason", "ticket closed"}, call{"POST", "/impersonation-grants/img_1/revoke", "", ""}},
		{[]string{"permissions", "--subject", "usr_1", "--org", "org_1"}, call{"GET", "/subjects/usr_1/permissions", "organization_id=org_1", ""}},
	}
	for _, c := range run {
		mu.Lock()
		calls = nil
		mu.Unlock()
		if err := commands[c.args[0]].run(c.args[1:]); err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		mu.Lock()
		got := calls
		mu.Unlock()
		c.want.auth = "Bearer at-admin"
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%v: requests %+v, want %+v", c.args, got, c.want)
		}
	}
	grant := bodies["PUT /api/v1/realms/main/clients/cli_1/resource-grants/res_1"]
	if scopes, _ := json.Marshal(grant["allowed_scopes"]); string(scopes) != `["orders:read","orders:write"]` {
		t.Fatalf("grant-scopes body: %v", grant)
	}
	assign := func(args ...string) map[string]any {
		t.Helper()
		mu.Lock()
		bodies = map[string]map[string]any{}
		mu.Unlock()
		if err := commands["assign-role"].run(args); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		return bodies["POST /api/v1/realms/main/role-assignments"]
	}
	if scope, _ := assign("--role", "rol_admin", "--subject", "usr_1")["scope"].(map[string]any); scope["type"] != "" || scope["id"] != "" {
		t.Fatalf("realm role assignment must leave the scope to the server, sent %v", scope)
	}
	b := assign("--role", "rol_viewer", "--subject", "svc_1", "--org", "org_1")
	if s, _ := b["scope"].(map[string]any); s["type"] != "organization" || s["id"] != "org_1" {
		t.Fatalf("organization role scope: %v", b)
	}
	if subj, _ := b["subject"].(map[string]any); subj["type"] != "service_principal" || subj["id"] != "svc_1" {
		t.Fatalf("service principal subject: %v", b)
	}
}
