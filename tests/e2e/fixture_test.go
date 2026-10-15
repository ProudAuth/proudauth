package e2e

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/realm"
)

// Fixture is the §37.3 first implementation slice: one realm, two organizations, two
// resource audiences, three human users with different memberships, one
// organization administrator, one restricted support operator (not the deployment
// superuser) and one machine principal.
type Fixture struct {
	H            *Harness
	AdminToken   string
	Acme         string
	Globex       string
	Orders       string // resource IDs
	Billing      string
	OrdersAud    string
	BillingAud   string
	Users        map[string]string // name -> user ID
	Clients      map[string]Client
	Roles        map[string]string
	MemberAcme   map[string]string // name -> membership ID in acme
	MemberGlobex map[string]string
}

// Client holds client credentials.
type Client struct {
	Ref    string
	ID     string
	Secret string
	SP     string
}

const webRedirect = "https://app.test/callback"

// NewFixture builds the slice through the public APIs.
func NewFixture(t testing.TB, mutate ...func(*realm.Policy)) *Fixture {
	t.Helper()
	return fixtureOn(t, NewHarness(t), mutate...)
}

func fixtureOn(t testing.TB, h *Harness, mutate ...func(*realm.Policy)) *Fixture {
	t.Helper()
	h.CreateRealm(func(p *realm.Policy) {
		p.Registration.Mode = realm.RegistrationPublic
		p.Registration.AllowOrganizationCreation = true
		p.Login.EmailOTP = true
		for _, m := range mutate {
			m(p)
		}
	})
	f := &Fixture{H: h, Users: map[string]string{}, Clients: map[string]Client{}, Roles: map[string]string{}, MemberAcme: map[string]string{}, MemberGlobex: map[string]string{}}
	f.AdminToken = f.bootstrapAdmin()
	f.configure()
	return f
}

func (f *Fixture) bootstrapAdmin() string {
	h := f.H
	res, err := h.App.Provision.BootstrapAdmin(context.Background(), "main", "admin@example.test", "root-admin", time.Hour, false, "tester")
	if err != nil {
		h.Fatalf("bootstrap: %v", err)
	}
	f.Users["admin"] = res.UserID
	pw := "an administrator passphrase 2026"
	mustStatus(h.t, h.API("POST", "/account-setup", "", map[string]any{"setup_token": res.SetupToken, "password": pw}), 200, "account setup")
	h.SetPassword("root-admin", pw)
	lr := h.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:admin", Resources: []string{h.Realm.Issuer + "/admin"}, Identifier: "root-admin"})
	return lr.Tokens.Str("access_token")
}

// AdminAPI calls the admin API with the bootstrap administrator's token.
func (f *Fixture) AdminAPI(method, path string, body any) *Resp {
	f.H.t.Helper()
	return f.H.API(method, path, f.AdminToken, body)
}

func (f *Fixture) must(r *Resp, want int, what string) *Resp {
	f.H.t.Helper()
	mustStatus(f.H.t, r, want, what)
	return r
}

// CreateUser creates a user via the admin API and completes emailed account setup.
func (f *Fixture) CreateUser(name string) string {
	h := f.H
	email := name + "@example.test"
	r := f.must(f.AdminAPI("POST", "/users", map[string]any{"email": email, "username": name, "display_name": name}), 201, "create user "+name)
	id := r.Str("user.id")
	token := CodeFrom(h.Mail(email, "account_setup"))
	if token == "" {
		h.Fatalf("no setup mail for %s", name)
	}
	pw := name + " has a long passphrase 2026"
	f.must(h.API("POST", "/account-setup", "", map[string]any{"setup_token": token, "password": pw}), 200, "setup "+name)
	h.SetPassword(email, pw)
	h.SetPassword(name, pw)
	f.Users[name] = id
	return id
}

func (f *Fixture) configure() {
	h := f.H
	_ = h.Realm.Issuer
	f.OrdersAud, f.BillingAud = "https://orders.test", "https://billing.test"
	orders := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Orders API", "audience": f.OrdersAud, "verification_mode": "strict_online",
		"impersonation_enabled": true, "impersonation_policy": map[string]any{"allowed_scopes": []string{"orders:read"}, "write_scopes": []string{"orders:write"},
			"contract_version": "support-contract-1", "support_client_ids": []string{"support-bff"}},
		"scopes": []map[string]any{{"name": "orders:read"}, {"name": "orders:write"}}}), 201, "orders resource")
	f.Orders = orders.Str("id")
	billing := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Billing API", "audience": f.BillingAud, "verification_mode": "offline",
		"scopes": []map[string]any{{"name": "billing:read"}, {"name": "billing:admin", "sensitivity": "privileged"}}}), 201, "billing resource")
	f.Billing = billing.Str("id")
	for _, p := range []map[string]any{{"name": "orders.read"}, {"name": "orders.refund", "sensitivity": "privileged"}, {"name": "billing.read"}} {
		f.must(f.AdminAPI("POST", "/permissions", p), 201, "permission")
	}
	for name, perms := range map[string][]string{"orders-viewer": {"orders.read"}, "orders-refunder": {"orders.read", "orders.refund"}, "billing-viewer": {"billing.read"}} {
		r := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": name, "permissions": perms}), 201, "role "+name)
		f.Roles[name] = r.Str("id")
	}
	roles := f.must(f.AdminAPI("GET", "/roles?boundary_type=organization", nil), 200, "list roles")
	for _, it := range roles.Get("items").([]any) {
		m := it.(map[string]any)
		f.Roles[m["name"].(string)] = m["id"].(string)
	}
	realmRoles := f.must(f.AdminAPI("GET", "/roles?boundary_type=realm", nil), 200, "list realm roles")
	for _, it := range realmRoles.Get("items").([]any) {
		m := it.(map[string]any)
		f.Roles[m["name"].(string)] = m["id"].(string)
	}
	f.Acme = f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "acme", "display_name": "Acme Corp"}), 201, "acme").Str("id")
	f.Globex = f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "globex", "display_name": "Globex"}), 201, "globex").Str("id")
	for _, u := range []string{"alice", "bob", "carol", "sam"} {
		f.CreateUser(u)
	}
	add := func(org, user string, roles ...string) string {
		ids := []string{}
		for _, r := range roles {
			ids = append(ids, f.Roles[r])
		}
		return f.must(f.AdminAPI("POST", "/organizations/"+org+"/members", map[string]any{"user_id": f.Users[user], "role_ids": ids}), 201, "member "+user).Str("id")
	}
	f.MemberAcme["alice"] = add(f.Acme, "alice", "owner", "orders-refunder", "billing-viewer")
	f.MemberAcme["bob"] = add(f.Acme, "bob", "member", "orders-viewer")
	f.MemberGlobex["bob"] = add(f.Globex, "bob", "member", "orders-viewer")
	f.MemberGlobex["carol"] = add(f.Globex, "carol", "admin", "orders-viewer")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["support-operator"],
		"subject": map[string]any{"type": "user", "id": f.Users["sam"]}}), 201, "support operator")

	client := func(in map[string]any) Client {
		r := f.must(f.AdminAPI("POST", "/clients", in), 201, "client "+in["client_id"].(string))
		return Client{Ref: r.Str("client.id"), ID: r.Str("client.client_id"), Secret: r.Str("client_secret")}
	}
	grant := func(c Client, resource string, scopes []string, subjects []string, exchange map[string]any) {
		body := map[string]any{"allowed_scopes": scopes, "subject_types": subjects}
		if exchange != nil {
			body["exchange_policy"] = exchange
		}
		f.must(f.AdminAPI("PUT", "/clients/"+c.Ref+"/resource-grants/"+resource, body), 204, "grant")
	}
	userinfo := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	var userinfoID string
	for _, it := range userinfo.Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			userinfoID = m["id"].(string)
		}
	}
	web := client(map[string]any{"client_id": "web-bff", "name": "Customer web BFF", "client_type": "confidential", "first_party": true,
		"grant_types":   []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"redirect_uris": []string{webRedirect}, "post_logout_redirect_uris": []string{"https://app.test/bye"}, "allowed_origins": []string{"https://app.test"},
		"allow_offline_access": true, "allow_remember_me": true})
	grant(web, f.Orders, []string{"orders:read", "orders:write"}, []string{"user"}, nil)
	grant(web, f.Billing, []string{"billing:read"}, []string{"user"}, map[string]any{"accept_from_audiences": []string{f.OrdersAud}})
	grant(web, userinfoID, []string{"openid", "profile", "email"}, []string{"user"}, nil)
	f.Clients["web"] = web
	third := client(map[string]any{"client_id": "partner-app", "name": "Partner App", "client_type": "public_browser", "security_profile": "third_party",
		"redirect_uris": []string{"https://partner.test/cb"}, "allowed_origins": []string{"https://partner.test"}})
	grant(third, f.Orders, []string{"orders:read"}, []string{"user"}, nil)
	f.Clients["partner"] = third

	sp := func(name string, orgs []string) string {
		return f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": name, "allowed_organization_ids": orgs}), 201, "sp "+name).Str("id")
	}
	ordersSP := sp("orders-api", nil)
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": f.Roles["resource-server"], "subject": map[string]any{"type": "service_principal", "id": ordersSP}}), 201, "rs role")
	ordersRS := client(map[string]any{"client_id": "orders-rs", "name": "Orders resource server", "client_type": "machine", "service_principal_id": ordersSP,
		"grant_types": []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"}})
	ordersRS.SP = ordersSP
	f.must(f.AdminAPI("POST", "/resources/"+f.Orders+"/introspectors", map[string]any{"client": ordersRS.Ref}), 204, "introspector")
	grant(ordersRS, f.Billing, []string{"billing:read"}, []string{"service_principal", "user"}, map[string]any{"accept_from_audiences": []string{f.OrdersAud}})
	adminRes := ""
	for _, it := range userinfo.Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "admin" {
			adminRes = m["id"].(string)
		}
	}
	grant(ordersRS, adminRes, []string{"proudauth:admin"}, []string{"service_principal"}, nil)
	f.Clients["orders-rs"] = ordersRS
	billingSP := sp("billing-api", nil)
	billingRS := client(map[string]any{"client_id": "billing-rs", "name": "Billing resource server", "client_type": "machine", "service_principal_id": billingSP})
	billingRS.SP = billingSP
	f.must(f.AdminAPI("POST", "/resources/"+f.Billing+"/introspectors", map[string]any{"client": billingRS.Ref}), 204, "introspector")
	f.Clients["billing-rs"] = billingRS
	supportSP := sp("support-bff", nil)
	support := client(map[string]any{"client_id": "support-bff", "name": "Support console backend", "client_type": "machine", "service_principal_id": supportSP})
	f.Clients["support"] = support
	batchSP := sp("batch-job", []string{f.Acme})
	batch := client(map[string]any{"client_id": "batch-job", "name": "Nightly billing batch", "client_type": "machine", "service_principal_id": batchSP})
	batch.SP = batchSP
	grant(batch, f.Billing, []string{"billing:read"}, []string{"service_principal"}, nil)
	f.Clients["batch"] = batch
}

// LoginWeb logs a user into the web BFF for a resource and organization.
func (f *Fixture) LoginWeb(user, org, resource, scope string) *LoginResult {
	f.H.t.Helper()
	return f.H.Login(LoginOpts{ClientID: "web-bff", ClientSecret: f.Clients["web"].Secret, RedirectURI: webRedirect, Scope: scope,
		Resources: []string{resource}, Organization: org, SelectOrg: org, Identifier: user + "@example.test"})
}

// MachineToken obtains a client-credentials token.
func (f *Fixture) MachineToken(c Client, resource, scope, org string) *Resp {
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {resource}, "scope": {scope}}
	if org != "" {
		form.Set("organization", org)
	}
	return f.H.TokenRequest(form, c.ID, c.Secret)
}

// LoginAs returns an account-audience token for self-service.
func (f *Fixture) AccountToken(user string) *LoginResult {
	f.H.t.Helper()
	return f.H.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{f.H.Realm.Issuer + "/account"},
		Identifier: user + "@example.test"})
}

// AdminTokenFor logs a user into the admin API through the CLI client.
func (f *Fixture) AdminTokenFor(user string) *LoginResult {
	f.H.t.Helper()
	return f.H.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:admin", Resources: []string{f.H.Realm.Issuer + "/admin"},
		Identifier: user + "@example.test"})
}

type realmPolicy = realm.Policy

// ReloginAdmin obtains a fresh administrator token (after clock jumps).
func (f *Fixture) ReloginAdmin() {
	f.H.t.Helper()
	lr := f.H.Login(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:admin", Resources: []string{f.H.Realm.Issuer + "/admin"}, Identifier: "root-admin"})
	f.AdminToken = lr.Tokens.Str("access_token")
}

// EnrollTOTP enrolls a TOTP factor for a user through the self-service API, so
// later logins of that user complete a TOTP step (MFA sessions).
func (f *Fixture) EnrollTOTP(user string) {
	f.H.t.Helper()
	ident := user + "@example.test"
	tok := f.AccountToken(user).Tokens.Str("access_token")
	en := f.H.API("POST", "/me/totp/enroll", tok, nil)
	if en.Status != 201 {
		f.H.t.Fatalf("totp enroll: %d %s", en.Status, en.Raw)
	}
	f.H.seeds[ident] = en.Str("secret")
	if r := f.H.API("POST", "/me/totp/activate", tok, map[string]any{"code": f.H.TOTPNow(ident)}); r.Status != 200 {
		f.H.t.Fatalf("totp activate: %d %s", r.Status, r.Raw)
	}
}

// SetPolicy applies mut to the realm policy through the settings API.
func (f *Fixture) SetPolicy(mut func(*realm.Policy)) *Resp {
	f.H.t.Helper()
	cur := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
	var pol realm.Policy
	_ = json.Unmarshal([]byte(jsonString(cur.Get("policy"))), &pol)
	mut(&pol)
	return f.H.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/settings", Token: f.AdminToken, JSON: map[string]any{"policy": pol, "reason": "test"},
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
}
