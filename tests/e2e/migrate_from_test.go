package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/migrate"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/worker"
)

// MIG-018 first-party migration adapters, end to end: real Keycloak 26.8.0,
// ZITADEL v4.16.3 and SuperTokens core 12.0.7 exports (internal/migrate
// testdata) are converted, planned and imported through the authenticated
// import APIs exactly as identity-cli migrate-from does it, then migrated
// users sign in with their source passwords.

const migrationTestdata = "../../internal/migrate/testdata/"

// migrationFixture is a realm with only the bootstrap administrator, so the
// exports' users do not collide with fixture accounts by accident.
func migrationFixture(t *testing.T) (*Fixture, *worker.Worker) {
	t.Helper()
	h := NewHarness(t)
	h.CreateRealm(func(p *realm.Policy) { p.Login.EmailOTP = true })
	f := &Fixture{H: h, Users: map[string]string{}, Clients: map[string]Client{}, Roles: map[string]string{}, MemberAcme: map[string]string{}, MemberGlobex: map[string]string{}}
	f.AdminToken = f.bootstrapAdmin()
	return f, worker.New(h.App, "test")
}

// migrationApplier submits through the HTTP API with the administrator's
// token and runs the worker while it waits for jobs.
func migrationApplier(t *testing.T, f *Fixture, w *worker.Worker) *migrate.Applier {
	h := f.H
	return &migrate.Applier{
		Call: func(ctx context.Context, method, path string, body, out any, key string) error {
			rq := Req{Method: method, Path: "/api/v1/realms/main" + path, Token: f.AdminToken}
			if body != nil {
				rq.JSON = body
			}
			if key != "" {
				rq.Headers = map[string]string{"Idempotency-Key": key}
			}
			r := h.Do(rq)
			if r.Status >= 400 {
				return &migrate.APIError{Status: r.Status, Detail: string(r.Raw)}
			}
			if out != nil && len(r.Raw) > 0 {
				return json.Unmarshal(r.Raw, out)
			}
			return nil
		},
		Wait: func(context.Context) error { runWorker(t, w); return nil },
	}
}

func migrationExport(t *testing.T, file string) []byte {
	t.Helper()
	b, err := os.ReadFile(migrationTestdata + file)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func migrationPasswords(t *testing.T, source string) map[string]string {
	t.Helper()
	var all map[string]json.RawMessage
	if err := json.Unmarshal(migrationExport(t, "fixture-passwords.json"), &all); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	_ = json.Unmarshal(all[source], &out)
	return out
}

// signIn runs an interactive login and completes the required actions a
// migrated account may carry. It reports whether the login reached the
// authorization code, and the last state.
func signIn(h *Harness, identifier, password, newPassword string) (bool, *Resp) {
	h.t.Helper()
	o := LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}, Identifier: identifier, Password: password}
	start, _, cont := h.StartTx(o)
	if start.Status != 201 {
		h.t.Fatalf("start transaction: %s", start.Raw)
	}
	tx := start.Str("transaction_id")
	st := &Resp{Status: 200, Body: start.Get("state").(map[string]any)}
	for i := 0; i < 6; i++ {
		st = h.Drive(tx, cont, st, o)
		if st.Status >= 400 || st.Str("redirect_to") != "" || st.Str("status") != "pending" {
			break
		}
		actions, _ := st.Get("next_actions").([]any)
		if len(actions) == 0 {
			break
		}
		switch actions[0].(map[string]any)["type"] {
		case "complete_profile":
			st = h.Step(tx, cont, "profile", map[string]any{"fields": map[string]any{}})
		case "update_password":
			st = h.Step(tx, cont, "password/update", map[string]any{"new_password": newPassword})
		default:
			return false, st
		}
	}
	return strings.Contains(st.Str("redirect_to"), "code="), st
}

func importedUserID(t *testing.T, h *Harness, sourceSystem, sourceID string) string {
	t.Helper()
	var id string
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT local_id FROM import_mappings WHERE realm_id=$1 AND source_system=$2
		AND source_type='user' AND source_id=$3`, h.Realm.ID, sourceSystem, sourceID).Scan(&id); err != nil {
		t.Fatalf("no imported account for %s/%s: %v", sourceSystem, sourceID, err)
	}
	return id
}

type accountState struct {
	State     string
	Actions   []string
	Password  string // algorithm of the active password credential
	Verifiers int
}

func account(t *testing.T, h *Harness, userID string) accountState {
	t.Helper()
	var a accountState
	ctx := context.Background()
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT state, required_actions FROM users WHERE id=$1`, userID).Scan(&a.State, &a.Actions); err != nil {
		t.Fatal(err)
	}
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*), coalesce(max(algorithm),'') FROM credentials WHERE user_id=$1 AND type='password' AND state='active'`,
		userID).Scan(&a.Verifiers, &a.Password)
	return a
}

func importedCount(t *testing.T, h *Harness, sourceSystem string) int {
	t.Helper()
	var n int
	_ = h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT count(*) FROM import_mappings WHERE realm_id=$1 AND source_system=$2 AND source_type='user'`,
		h.Realm.ID, sourceSystem).Scan(&n)
	return n
}

// checkReportMatches compares the capability report's promises with what the
// server reported for the import (the report must describe what happened).
func checkReportMatches(t *testing.T, res *migrate.Result, out *migrate.ImportOutcome, conflicts int) {
	t.Helper()
	s := res.Report.Summary
	verified := 0
	for _, u := range res.Users {
		if u.Email != "" && u.EmailVerified {
			verified++
		}
	}
	for k, want := range map[string]int{"imported": s.UsersToImport - conflicts} {
		if out.Counts[k] != want {
			t.Errorf("counts[%s] = %d, report promised %d (%v)", k, out.Counts[k], want, out.Counts)
		}
	}
	if conflicts == 0 {
		for k, want := range map[string]int{"password_verifiers": s.PasswordsMigrated, "totp_factors": s.TOTPMigrated, "memberships": s.Memberships,
			"role_assignments": s.RoleAssignments, "suspended_accounts": s.SuspendedAccounts, "trusted_verified_emails": verified} {
			if out.Totals[k] != want {
				t.Errorf("totals[%s] = %d, report promised %d (%v)", k, out.Totals[k], want, out.Totals)
			}
		}
	}
}

func TestMigrateFromKeycloak(t *testing.T) {
	f, w := migrationFixture(t)
	h := f.H
	ctx := context.Background()
	pw := migrationPasswords(t, "keycloak")
	export := migrationExport(t, "keycloak/demo-realm-26.8.0.json")
	ap := migrationApplier(t, f, w)

	// The realm already has an "acme" organization and an account with
	// judy's email: neither may be merged by name (MIG-004).
	f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "acme", "display_name": "Acme (local)"}), 201, "local acme")
	f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "judy@globex.example", "send_setup_email": false}), 201, "local judy")

	// Adapters and the read-only plan endpoint.
	ads := f.must(f.AdminAPI("GET", "/migration-adapters", nil), 200, "adapters")
	if items := ads.Get("items").([]any); len(items) != 3 || items[0].(map[string]any)["tested_versions"].([]any)[0] != "26.8.0" {
		t.Fatalf("adapters: %s", ads.Raw)
	}
	// The ZITADEL export request is complete, with its duration "timeout".
	if cmd, _ := ads.Get("items").([]any)[1].(map[string]any)["export_command"].(string); !strings.Contains(cmd, `"responseOutput": true, "timeout": "60s"}`) {
		t.Fatalf("ZITADEL export command: %s", cmd)
	}
	// A major-only source version names the export's 26.8.0; another
	// version is refused on source_version.
	f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "keycloak", "source_version": "26", "exports": []json.RawMessage{export}}), 200, "plan with major version")
	if r := f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "keycloak", "source_version": "25", "exports": []json.RawMessage{export}}), 422,
		"plan with another version"); !strings.Contains(string(r.Raw), "or its major version 26") {
		t.Fatalf("version error: %s", r.Raw)
	}
	plan := f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "keycloak", "exports": []json.RawMessage{export}, "import_totp": true}), 200, "plan")
	if plan.Get("report.summary.users") != float64(12) || plan.Get("report.entities.password_credentials.unsupported") != float64(2) {
		t.Fatalf("plan report: %s", plan.Raw)
	}
	orgs := plan.Get("target.organizations").([]any)
	if orgs[0].(map[string]any)["slug"] != "acme" || orgs[0].(map[string]any)["status"] != "conflict" || orgs[1].(map[string]any)["status"] != "will_create" {
		t.Fatalf("plan organizations: %v", orgs)
	}
	if c := plan.Get("target.identifier_conflicts").([]any); len(c) != 1 || c[0] != "d1d40d5c-33d3-40a1-a275-9cb5707aa200" {
		t.Fatalf("identifier conflicts: %v", c)
	}
	if strings.Contains(string(plan.Raw), "$argon2id$") || strings.Contains(string(plan.Raw), "alice@acme.example") {
		t.Fatal("the plan response carries credentials or contact data")
	}
	f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "keycloak", "exports": []json.RawMessage{
		json.RawMessage(strings.Replace(string(export), `"keycloakVersion": "26.8.0"`, `"keycloakVersion": "24.0.5"`, 1))}}), 422, "untested version")

	// Without a reviewed mapping the auto-created acme collides with the
	// realm's own: nothing is written.
	res, err := migrate.Convert(migrate.Keycloak, [][]byte{export}, migrate.Options{ImportTOTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ap.Apply(ctx, res, migrate.ApplyOptions{ImportTOTP: true}); !errors.Is(err, migrate.ErrBlocked) || importedCount(t, h, "keycloak-demo") != 0 {
		t.Fatalf("conflicting organization did not block the import: %v", err)
	}

	// The reviewed mapping names the existing organization and translates
	// roles; a role that does not exist blocks the import too.
	mapping := &migrate.Mapping{Format: migrate.MappingFormat, MembershipRoles: []string{"member"},
		Organizations: map[string]*migrate.OrgTarget{"org:acme": {Slug: "acme"}},
		Roles: map[string]*migrate.RoleTarget{"realm-role:app-admin": {Roles: []string{"admin"}}, "realm-role:app-user": {Roles: []string{}},
			"client-role:billing-app:editor": {Organization: "acme", Roles: []string{"billing-editor"}}, "client-role:billing-app:viewer": nil,
			"group:/acme": nil, "group:/acme/admins": {Roles: []string{"admin"}}, "group:/globex": nil}}
	res, err = migrate.Convert(migrate.Keycloak, [][]byte{export}, migrate.Options{ImportTOTP: true, Mapping: mapping})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ap.Apply(ctx, res, migrate.ApplyOptions{ImportTOTP: true}); !errors.Is(err, migrate.ErrBlocked) || !strings.Contains(err.Error(), "billing-editor") {
		t.Fatalf("missing role did not block the import: %v", err)
	}
	f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "organization", "name": "billing-editor", "permissions": []string{"org.read"}}), 201, "role")

	// Dry run (MIG-003): the plan with the server's view, nothing written.
	dry, err := ap.Apply(ctx, res, migrate.ApplyOptions{DryRun: true, ImportTOTP: true, TrustEmailVerification: true, VerificationReason: "Keycloak verified emails by link"})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Counts["valid"] != 11 || dry.Counts["conflict"] != 1 || importedCount(t, h, "keycloak-demo") != 0 {
		t.Fatalf("dry run: %+v", dry)
	}
	if dry.Organizations[0].Status != "exists" || dry.Organizations[1].Status != "will_create" {
		t.Fatalf("dry-run organizations: %+v", dry.Organizations)
	}

	// The import. Judy's record conflicts with the local account, so the
	// realm does not hold what the export says: the import ends with a
	// reconciliation against the export's counts that does not match
	// (MIG-012), and the applier reports it.
	out, err := ap.Apply(ctx, res, migrate.ApplyOptions{ImportTOTP: true, TrustEmailVerification: true, VerificationReason: "Keycloak verified emails by link"})
	if !errors.Is(err, migrate.ErrNotReconciled) || !strings.Contains(err.Error(), "users expected 12, actual 11") {
		t.Fatalf("import with a conflicting record: %v", err)
	}
	if out.Reconciliation["reconciled"] != false || out.Expected["users"] != 12 || out.Expected["totp_factors"] != 1 {
		t.Fatalf("reconciliation of the import: %v %v", out.Expected, out.Reconciliation)
	}
	if out.Counts["imported"] != 11 || out.Counts["conflict"] != 1 || len(out.Records) != 1 || out.Records[0].SourceID != "d1d40d5c-33d3-40a1-a275-9cb5707aa200" {
		t.Fatalf("import: %+v", out)
	}
	checkReportMatches(t, res, out, 1)
	if out.Organizations[1].Status != "created" {
		t.Fatalf("globex not created: %+v", out.Organizations)
	}
	rec := f.must(f.AdminAPI("GET", "/user-imports/reconciliation?source_system=keycloak-demo&expected_users=11&expected_password_verifiers=8&expected_totp_factors=1", nil), 200, "reconcile")
	if rec.Get("reconciled") != true {
		t.Fatalf("reconciliation: %s", rec.Raw)
	}
	alice := importedUserID(t, h, "keycloak-demo", "6a3181ff-6cc9-467b-8d3e-bcb3ab9447e9")
	if m := f.must(f.AdminAPI("GET", "/users/"+alice, nil), 200, "alice"); m.Str("given_name") != "Alice" {
		t.Fatalf("alice: %s", m.Raw)
	}

	// Users sign in with their Keycloak passwords: argon2id (the Keycloak
	// 26 default), PBKDF2-SHA256 and PBKDF2-SHA512; each verifier is
	// rehashed to the deployment's Argon2id at the first sign-in.
	h.seeds["heidi@globex.example"] = res.Users[slices.IndexFunc(res.Users, func(u identity.ImportRecord) bool { return u.Username == "heidi" })].TOTPSecret
	for _, u := range []struct{ login, user, id string }{
		{"alice@acme.example", "alice", "6a3181ff-6cc9-467b-8d3e-bcb3ab9447e9"},
		{"bob", "bob", "4364124c-6323-456e-82f2-3f1845a34dab"},
		{"carol@acme.example", "carol", "dc7d0917-cb88-4c07-9f2b-d44f64aeaad0"},
		{"heidi@globex.example", "heidi", "30b20b81-fccf-4f5b-8f81-2489b88ecb79"},
		{"helpdesk@acme.example", "support", "99d7a4fc-0d1d-4ff0-a641-0e4bb90bb1d0"},
	} {
		if ok, _ := signIn(h, u.login, u.user+"-wrong-password", ""); ok {
			t.Fatalf("%s signed in with a wrong password", u.user)
		}
		ok, st := signIn(h, u.login, pw[u.user], "")
		if !ok {
			t.Fatalf("%s cannot sign in with the Keycloak password: %s", u.user, st.Raw)
		}
		if a := account(t, h, importedUserID(t, h, "keycloak-demo", u.id)); a.Password != "argon2id" || a.Verifiers != 1 {
			t.Fatalf("%s's verifier not rehashed: %+v", u.user, a)
		}
	}
	// Kevin's temporary Keycloak password still works once, then he must
	// set a new one (UPDATE_PASSWORD).
	if ok, st := signIn(h, "kevin", pw["kevin"], "kevin chose a new passphrase 2026"); !ok {
		t.Fatalf("kevin: %s", st.Raw)
	}
	if a := account(t, h, importedUserID(t, h, "keycloak-demo", "6ade59f3-5215-4a90-86ff-3c0a25af3faa")); slices.Contains(a.Actions, identity.ActionUpdatePassword) {
		t.Fatalf("kevin's update_password not completed: %+v", a)
	}

	// Verifiers outside the accepted bounds were not imported: the account
	// must reset its password (MIG-006).
	grace := importedUserID(t, h, "keycloak-demo", "d8ed763a-8c68-4dd2-a4c0-516d8144c48a")
	dave := importedUserID(t, h, "keycloak-demo", "c05776bd-a070-40d1-b3dc-91d40819baec")
	for name, id := range map[string]string{"grace": grace, "dave": dave} {
		if a := account(t, h, id); a.Verifiers != 0 || !slices.Contains(a.Actions, identity.ActionUpdatePassword) {
			t.Fatalf("%s: unsupported verifier imported or reset not required: %+v", name, a)
		}
	}
	if ok, _ := signIn(h, "dave", pw["dave"], ""); ok {
		t.Fatal("dave signed in with a PBKDF2 verifier below the floor")
	}
	reset := h.API("POST", "/password-resets", "", map[string]any{"identifier": "grace@acme.example"})
	code := CodeFrom(h.Mail("grace@acme.example", "password_reset"))
	f.must(h.API("POST", "/password-resets/complete", "", map[string]any{"reset_id": reset.Str("reset_id"), "code": code,
		"new_password": "grace recovered her account 2026"}), 200, "grace's reset")
	if ok, st := signIn(h, "grace@acme.example", "grace recovered her account 2026", ""); !ok {
		t.Fatalf("grace after the reset: %s", st.Raw)
	}
	if a := account(t, h, grace); slices.Contains(a.Actions, identity.ActionUpdatePassword) {
		t.Fatalf("grace's reset did not clear update_password: %+v", a)
	}
	// Erin was disabled in Keycloak: imported suspended.
	if a := account(t, h, importedUserID(t, h, "keycloak-demo", "faa4ad2f-1725-470f-ab22-84146222ea8d")); a.State != identity.StateSuspended {
		t.Fatalf("erin: %+v", a)
	}
	if ok, _ := signIn(h, "erin@acme.example", pw["erin"], ""); ok {
		t.Fatal("suspended erin signed in")
	}
	// Alice's memberships follow the mapping: acme with member, admin and
	// billing-editor.
	var roles []string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT array_agg(r.name ORDER BY r.name) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		WHERE ra.subject_id=$1 AND ra.scope_type='organization'`, alice).Scan(&roles)
	if !slices.Equal(roles, []string{"admin", "billing-editor", "member"}) {
		t.Fatalf("alice's roles: %v", roles)
	}

	// Re-running is idempotent: the organization created by the first run
	// is found by its external ID and every record is already imported.
	// Judy still conflicts, so the re-run does not reconcile either.
	again, err := ap.Apply(ctx, res, migrate.ApplyOptions{ImportTOTP: true, TrustEmailVerification: true, VerificationReason: "Keycloak verified emails by link"})
	if !errors.Is(err, migrate.ErrNotReconciled) {
		t.Fatalf("re-run: %v", err)
	}
	if again.Counts["already_imported"] != 11 || again.Counts["imported"] != 0 || again.Organizations[1].Status != "exists" || importedCount(t, h, "keycloak-demo") != 11 {
		t.Fatalf("re-run: %+v", again)
	}
	var orgCount, members int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE realm_id=$1 AND slug IN ('acme','globex')`, h.Realm.ID).Scan(&orgCount)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE realm_id=$1 AND source='import'`, h.Realm.ID).Scan(&members)
	if orgCount != 2 || members != res.Report.Summary.Memberships-1 {
		t.Fatalf("re-run duplicated data: %d organizations, %d memberships", orgCount, members)
	}
	// After the import the plan endpoint sees the records as imported.
	plan = f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "keycloak", "exports": []json.RawMessage{export}}), 200, "plan after import")
	if n := len(plan.Get("target.already_imported").([]any)); n != 11 {
		t.Fatalf("plan after the import: %d already imported", n)
	}
}

func TestMigrateFromZitadel(t *testing.T) {
	f, w := migrationFixture(t)
	h := f.H
	ctx := context.Background()
	pw := migrationPasswords(t, "zitadel")
	export := migrationExport(t, "zitadel/export-v4.16.3.json")
	ap := migrationApplier(t, f, w)

	// ZITADEL's export does not state its version: the plan needs it.
	f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "zitadel", "exports": []json.RawMessage{export}}), 422, "plan without version")
	plan := f.must(f.AdminAPI("POST", "/migration-plans", map[string]any{"source": "zitadel", "source_version": "v4.16.3", "exports": []json.RawMessage{export}}), 200, "plan")
	if plan.Get("report.entities.service_accounts.unsupported") != float64(3) {
		t.Fatalf("plan: %s", plan.Raw)
	}

	mapping := &migrate.Mapping{Organizations: map[string]*migrate.OrgTarget{"org:394589032694218757": nil},
		Roles: map[string]*migrate.RoleTarget{"org-member:ORG_OWNER": {Roles: []string{"owner"}}, "org-member:ORG_USER_MANAGER": {Roles: []string{"admin"}},
			"project-role:394589305978224645:portal.editor": {Roles: []string{"member"}}}}
	res, err := migrate.Convert(migrate.Zitadel, [][]byte{export}, migrate.Options{SourceVersion: "v4.16.3", ImportTOTP: true, Mapping: mapping})
	if err != nil {
		t.Fatal(err)
	}
	// Owner roles need explicit approval; the failed record leaves the
	// import short of the export, which the reconciliation reports.
	opts := migrate.ApplyOptions{ImportTOTP: true, TrustEmailVerification: true, VerificationReason: "ZITADEL verified emails by code"}
	out, err := ap.Apply(ctx, res, opts)
	if !errors.Is(err, migrate.ErrNotReconciled) || !strings.Contains(err.Error(), "users expected 8, actual 7") {
		t.Fatalf("import with a failed record: %v", err)
	}
	if out.Counts["error"] != 1 || !strings.Contains(out.Records[0].Error, "owner role requires explicit approval") {
		t.Fatalf("owner role without approval: %+v", out)
	}
	opts.AllowOwnerRoles = true
	out, err = ap.Apply(ctx, res, opts)
	if err != nil {
		t.Fatal(err)
	}
	if out.Reconciliation["reconciled"] != true || out.Expected["users"] != 8 || out.Expected["totp_factors"] != 1 {
		t.Fatalf("second run not reconciled: %v %v", out.Expected, out.Reconciliation)
	}
	if out.Counts["imported"] != 1 || out.Counts["already_imported"] != 7 || importedCount(t, h, "zitadel") != 8 {
		t.Fatalf("second run: %+v", out)
	}
	for _, o := range out.Organizations {
		if o.Status != "exists" {
			t.Fatalf("organizations created twice: %+v", out.Organizations)
		}
	}
	h.seeds["vera@acme.example"] = "LV422DWLOKNW5WT4HS5QD72Q5RHZMSUO"
	for _, u := range []struct{ login, user string }{{"zoe", "zoe"}, {"yusuf@acme.example", "yusuf"}, {"xena", "xena"}, {"vera@acme.example", "vera"}, {"tariq", "tariq"}} {
		if ok, st := signIn(h, u.login, pw[u.user], ""); !ok {
			t.Fatalf("%s cannot sign in with the ZITADEL password: %s", u.user, st.Raw)
		}
	}
	walt := importedUserID(t, h, "zitadel", "394589236285669381")
	if a := account(t, h, walt); a.Verifiers != 0 || !slices.Contains(a.Actions, identity.ActionUpdatePassword) {
		t.Fatalf("walt's md5crypt: %+v", a)
	}
	if ok, _ := signIn(h, "walt", pw["walt"], ""); ok {
		t.Fatal("walt signed in with an md5crypt verifier")
	}
	if a := account(t, h, importedUserID(t, h, "zitadel", "394589255512358917")); a.State != identity.StateSuspended {
		t.Fatalf("uma: %+v", a)
	}
	// Zoe owns acme (ORG_OWNER there); her ORG_OWNER of the excluded
	// default organization did not come over.
	zoe := importedUserID(t, h, "zitadel", "394589178924367877")
	var orgs []string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT array_agg(o.slug || ':' || r.name ORDER BY o.slug, r.name) FROM role_assignments ra JOIN roles r ON r.id=ra.role_id
		JOIN organizations o ON o.id=ra.scope_id WHERE ra.subject_id=$1`, zoe).Scan(&orgs)
	if !slices.Equal(orgs, []string{"acme:member", "acme:owner"}) {
		t.Fatalf("zoe's assignments: %v", orgs)
	}
	rec := f.must(f.AdminAPI("GET", "/user-imports/reconciliation?source_system=zitadel&expected_users=8&expected_totp_factors=1", nil), 200, "reconcile")
	if rec.Get("reconciled") != true || rec.Get("privileged_assignments.total") == float64(0) {
		t.Fatalf("reconciliation: %s", rec.Raw)
	}
}

func TestMigrateFromSuperTokens(t *testing.T) {
	f, w := migrationFixture(t)
	h := f.H
	ctx := context.Background()
	pw := migrationPasswords(t, "supertokens")
	export := migrationExport(t, "supertokens/export-core-12.0.7.json")
	ap := migrationApplier(t, f, w)

	mapping := &migrate.Mapping{Organizations: map[string]*migrate.OrgTarget{"tenant:public": {Slug: "northwind", DisplayName: "Northwind"}},
		MembershipRoles: []string{"member"},
		Roles:           map[string]*migrate.RoleTarget{"role:admin": {Roles: []string{"admin"}}, "role:editor": {Roles: []string{}}, "role:viewer": {Roles: []string{}}}}
	res, err := migrate.Convert(migrate.SuperTokens, [][]byte{export}, migrate.Options{ImportTOTP: true, KeepAttributes: true, Mapping: mapping})
	if err != nil {
		t.Fatal(err)
	}
	opts := migrate.ApplyOptions{ImportTOTP: true, TrustEmailVerification: true, VerificationReason: "SuperTokens email verification recipe"}
	out, err := ap.Apply(ctx, res, opts)
	if err != nil {
		t.Fatal(err)
	}
	if out.Counts["imported"] != 9 || out.Organizations[0].Status != "created" {
		t.Fatalf("import: %+v", out)
	}
	checkReportMatches(t, res, out, 0)
	// The import was reconciled against the export's own counts.
	for m, n := range map[string]int{"users": 9, "memberships": 9, "password_verifiers": 5, "totp_factors": 2} {
		if out.Expected[m] != n {
			t.Fatalf("expected %s = %d, want %d (%v)", m, out.Expected[m], n, out.Expected)
		}
	}
	if out.Reconciliation["reconciled"] != true {
		t.Fatalf("reconciliation: %v", out.Reconciliation)
	}

	h.seeds["amara@northwind.example"] = "KRUGS4ZANFZSAYJAORSXG5BAONSWG4TFOQQGW"
	h.seeds["jonas@northwind.example"] = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	for _, email := range []string{"amara@northwind.example", "chen@northwind.example", "ines@northwind.example", "jonas@northwind.example"} {
		if ok, st := signIn(h, email, pw[email], ""); !ok {
			t.Fatalf("%s cannot sign in with the SuperTokens password: %s", email, st.Raw)
		}
	}
	// The low-cost bcrypt and the Firebase scrypt hash force a reset.
	for _, id := range []string{"cfd03d15-b189-491c-956c-8e11c1d22ded", "95490144-582e-4cf5-8380-ae6d4b7c35fd"} {
		if a := account(t, h, importedUserID(t, h, "supertokens-public", id)); a.Verifiers != 0 || !slices.Contains(a.Actions, identity.ActionUpdatePassword) {
			t.Fatalf("%s: %+v", id, a)
		}
	}
	if ok, _ := signIn(h, "dina@northwind.example", pw["dina@northwind.example"], ""); ok {
		t.Fatal("dina signed in with a bcrypt cost below the floor")
	}
	// The external user ID mapping carries over as the source ID.
	chen := importedUserID(t, h, "supertokens-public", "legacy-1042")
	ext := f.must(f.AdminAPI("GET", "/external-ids/supertokens-public/legacy-1042", nil), 200, "external id")
	if !strings.Contains(string(ext.Raw), chen) {
		t.Fatalf("external id: %s", ext.Raw)
	}
	var meta string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT admin_metadata::text FROM users WHERE id=$1`, importedUserID(t, h, "supertokens-public", "bbbf64cd-3d33-400c-b93a-bbf0b89729d2")).Scan(&meta)
	if !strings.Contains(meta, `"plan": "enterprise"`) {
		t.Fatalf("amara's kept metadata: %s", meta)
	}
	// Idempotent re-run.
	again, err := ap.Apply(ctx, res, opts)
	if err != nil || again.Counts["already_imported"] != 9 || again.Organizations[0].Status != "exists" || importedCount(t, h, "supertokens-public") != 9 {
		t.Fatalf("re-run: %+v %v", again, err)
	}
	rec := f.must(f.AdminAPI("GET", "/user-imports/reconciliation?source_system=supertokens-public&expected_users=9&expected_memberships=9&expected_password_verifiers=5&expected_totp_factors=2", nil), 200, "reconcile")
	if rec.Get("reconciled") != true {
		t.Fatalf("reconciliation: %s", rec.Raw)
	}
	// An account deleted in ProudAuth is not recreated (MIG-017) and is
	// not expected by the next run's reconciliation.
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+importedUserID(t, h, "supertokens-public", "cfd03d15-b189-491c-956c-8e11c1d22ded"), nil), 204, "delete dina")
	again, err = ap.Apply(ctx, res, opts)
	if err != nil || again.Counts["skipped_deleted"] != 1 || again.Expected["users"] != 8 || again.Reconciliation["reconciled"] != true {
		t.Fatalf("re-run after a deletion: %v %v %v %v", err, again.Counts, again.Expected, again.Reconciliation)
	}
}

// TestMigrateFromImportRecordRules covers the import-record members the
// adapters rely on: required actions need the authority they need on an
// existing account (AUT-018), states are never more permissive than active,
// and bcrypt verifiers below the cost floor are refused (MIG-006).
func TestMigrateFromImportRecordRules(t *testing.T) {
	f, w := migrationFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "importer",
		"permissions": []string{"realm.users.import", "realm.users.read"}}), 201, "importer role").Str("id")
	f.CreateUser("ingrid")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["ingrid"]}}), 201, "assign")
	ingrid := f.AdminTokenFor("ingrid").Tokens.Str("access_token")
	reset := []map[string]any{{"source_id": "r-1", "email": "r1@example.org", "required_actions": []string{"update_password"}}}
	if r := h.API("POST", "/user-imports", ingrid, map[string]any{"source_system": "rules", "users": reset}); r.Status != 403 {
		t.Fatalf("update_password without credential authority: %d %s", r.Status, r.Raw)
	}
	job := func(token string, users []map[string]any) []any {
		t.Helper()
		j := h.API("POST", "/user-imports", token, map[string]any{"source_system": "rules", "users": users})
		mustStatus(t, j, 202, "import")
		runWorker(t, w)
		return f.must(h.API("GET", "/jobs/"+j.Str("job_id"), token, nil), 200, "job").Get("result.results").([]any)
	}
	low := "$2a$04$" + strings.Repeat("a", 53)
	res := job(ingrid, []map[string]any{
		{"source_id": "r-2", "email": "r2@example.org", "required_actions": []string{"accept_terms"}, "state": "suspended",
			"given_name": "Rita", "family_name": "Roe", "locale": "pt-BR", "admin_metadata": map[string]any{"migration": map[string]any{"source_attributes": map[string]any{"dept": "ops"}}}},
		{"source_id": "r-3", "email": "r3@example.org", "state": "deleted"},
		{"source_id": "r-4", "email": "r4@example.org", "required_actions": []string{"wire_money"}},
		{"source_id": "r-5", "email": "r5@example.org", "password_hash": low},
		{"source_id": "r-6", "email": "r6@example.org", "locale": "not a locale"},
	})
	status := func(i int) (string, string) {
		m := res[i].(map[string]any)
		e, _ := m["error"].(string)
		return m["status"].(string), e
	}
	if s, e := status(0); s != "imported" {
		t.Fatalf("r-2: %s %s", s, e)
	}
	for i, want := range map[int]string{1: "state must be active or suspended", 2: "unsupported required action", 3: "bcrypt cost 4 outside the accepted bounds", 4: "locale"} {
		if s, e := status(i); s != "error" || !strings.Contains(e, want) {
			t.Fatalf("record %d: %s %q (want %q)", i, s, e, want)
		}
	}
	rita := importedUserID(t, h, "rules", "r-2")
	a := account(t, h, rita)
	u := f.must(f.AdminAPI("GET", "/users/"+rita, nil), 200, "rita")
	if a.State != identity.StateSuspended || !slices.Equal(a.Actions, []string{identity.ActionAcceptTerms}) || u.Str("given_name") != "Rita" ||
		u.Str("locale") != "pt-BR" || !strings.Contains(string(u.Raw), `"dept":"ops"`) {
		t.Fatalf("imported profile: %+v %s", a, u.Raw)
	}
}
