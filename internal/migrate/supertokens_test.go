package migrate

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/identity"
)

const (
	stFixture = "testdata/supertokens/export-core-12.0.7.json"
	stCoreAPI = "testdata/supertokens/core-users-api-12.0.7.json"
)

// SuperTokens user IDs of the fixture (the IDs applications see).
const (
	stChen   = "legacy-1042" // external user ID mapping
	stInes   = "794ec33c-2124-4507-b88f-b3f88ba5ca56"
	stJonas  = "930ab6da-e620-4b29-883d-bdbf6772e608"
	stHugo   = "95490144-582e-4cf5-8380-ae6d4b7c35fd"
	stFatima = "b7cdd699-204b-4231-9e0d-efad65c41b50"
	stBilal  = "b9f72350-4ca4-4f27-8e76-3b198ffd40e7"
	stAmara  = "bbbf64cd-3d33-400c-b93a-bbf0b89729d2"
	stGwen   = "c871d0b4-b6d9-46f0-a29b-8289b8eed6e9" // passwordless phone only
	stDina   = "cfd03d15-b189-491c-956c-8e11c1d22ded"
	stEmeka  = "fd2ecb34-91d0-4a4e-8a81-c704e9ec880c"
)

func stMapping() *Mapping {
	return &Mapping{Organizations: map[string]*OrgTarget{"tenant:public": {Slug: "northwind", DisplayName: "Northwind"}},
		MembershipRoles: []string{"member"},
		Roles:           map[string]*RoleTarget{"role:admin": {Roles: []string{"admin"}}, "role:editor": {Roles: []string{"editor"}}, "role:viewer": {Roles: []string{}}}}
}

func TestSuperTokensConversion(t *testing.T) {
	pw := passwords(t, "supertokens")
	res := convert(t, SuperTokens, Options{ImportTOTP: true, Mapping: stMapping()}, stFixture)
	r := res.Report
	if res.SourceSystem != "supertokens-public" || r.Source.Version != "12.0.7" {
		t.Fatalf("source: %s %+v", res.SourceSystem, r.Source)
	}
	noSecrets(t, res)

	// emailpassword: bcrypt (the SuperTokens default) and argon2id verify.
	for id, email := range map[string]string{stAmara: "amara@northwind.example", stBilal: "bilal@northwind.example", stChen: "chen@northwind.example",
		stInes: "ines@northwind.example", stJonas: "jonas@northwind.example"} {
		rec := record(t, res, id)
		if rec.Email != email || !verifies(t, rec.PasswordHash, pw[email]) {
			t.Fatalf("%s: %+v", email, rec)
		}
	}
	// Low-cost bcrypt and Firebase scrypt force a reset.
	for _, id := range []string{stDina, stHugo} {
		rec := record(t, res, id)
		if rec.PasswordHash != "" || !slices.Contains(rec.RequiredActions, identity.ActionUpdatePassword) {
			t.Fatalf("%s: %+v", id, rec)
		}
	}
	if !strings.Contains(itemReasons(r, "password_credentials", stDina), "bcrypt cost 8 outside the accepted bounds") ||
		!strings.Contains(itemReasons(r, "password_credentials", stHugo), "FIREBASE_SCRYPT") {
		t.Fatalf("unsupported hashes not reported: %s / %s", itemReasons(r, "password_credentials", stDina), itemReasons(r, "password_credentials", stHugo))
	}
	entity(t, r, "password_credentials", 7, 5, 0, 2, 0)

	// The external user ID mapping is the ID applications know.
	if chen := record(t, res, stChen); !chen.EmailVerified {
		t.Fatalf("chen: %+v", chen)
	}
	// TOTP: the 30-second device comes over, the 60-second one does not.
	amara := record(t, res, stAmara)
	if amara.TOTPSecret != "KRUGS4ZANFZSAYJAORSXG5BAONSWG4TFOQQGW" || slices.Contains(amara.RequiredActions, identity.ActionConfigureTOTP) {
		t.Fatalf("amara's TOTP: %+v", amara)
	}
	if !strings.Contains(itemReasons(r, "totp_factors", stAmara), "period 60 s") {
		t.Fatal("60-second TOTP device not reported")
	}
	entity(t, r, "totp_factors", 3, 2, 0, 1, 0)
	// Linked login methods: one account, the third-party link reported.
	if !strings.Contains(itemReasons(r, "users", stInes), "identity provider link") {
		t.Fatalf("ines: %s", itemReasons(r, "users", stInes))
	}
	if f := record(t, res, stFatima); f.PasswordHash != "" || len(f.RequiredActions) != 0 {
		t.Fatalf("passwordless user: %+v", f)
	}
	if e := record(t, res, stEmeka); !e.EmailVerified || e.PasswordHash != "" {
		t.Fatalf("third-party user: %+v", e)
	}
	// A phone-only account has no importable identifier.
	if hasRecord(res, stGwen) {
		t.Fatal("phone-only user imported")
	}
	if !strings.Contains(itemReasons(r, "users", stGwen), "no importable email or username") {
		t.Fatalf("phone-only user not reported: %s", itemReasons(r, "users", stGwen))
	}
	entity(t, r, "users", 10, 3, 6, 1, 0) // bilal, fatima and jonas convert without loss

	// Tenants and roles through the mapping.
	if len(res.Organizations) != 1 || res.Organizations[0].Slug != "northwind" || res.Organizations[0].ExternalID != "supertokens-public:tenant:public" {
		t.Fatalf("organizations: %+v", res.Organizations)
	}
	if ms := amara.Memberships; len(ms) != 1 || !slices.Equal(ms[0].Roles, []string{"member", "admin", "editor"}) {
		t.Fatalf("amara's memberships: %+v", ms)
	}
	if ms := record(t, res, stBilal).Memberships; len(ms) != 1 || !slices.Equal(ms[0].Roles, []string{"member"}) {
		t.Fatalf("bilal's memberships (viewer mapped to no roles): %+v", ms)
	}
	entity(t, r, "role_assignments", 7, 4, 0, 0, 3)

	// Without the mapping the public tenant is not an organization.
	plain := convert(t, SuperTokens, Options{}, stFixture)
	if len(plain.Organizations) != 0 || plain.Report.Summary.UntranslatedRoleGrants != 7 {
		t.Fatalf("defaults: %+v %+v", plain.Organizations, plain.Report.Summary)
	}
	entity(t, plain.Report, "tenants", 1, 0, 0, 0, 1)
}

func TestSuperTokensCoreAPIList(t *testing.T) {
	// The core API list has no hashes: every password must be reset, and
	// the version must be given.
	res := convert(t, SuperTokens, Options{SourceVersion: "12.0.7"}, stCoreAPI)
	entity(t, res.Report, "password_credentials", 7, 0, 0, 7, 0)
	for _, rec := range res.Users {
		if rec.PasswordHash != "" {
			t.Fatalf("%s has a password from the core API", rec.SourceID)
		}
	}
	if rec := record(t, res, stChen); !slices.Contains(rec.RequiredActions, identity.ActionUpdatePassword) {
		t.Fatalf("chen: %+v", rec)
	}
	if !strings.Contains(strings.Join(res.Report.Notes, " "), "export SQL") {
		t.Fatalf("notes: %v", res.Report.Notes)
	}
}

func TestSuperTokensExportSQL(t *testing.T) {
	s := SuperTokensExportSQL
	for _, want := range []string{"READ ONLY", "proudauth.supertokens-export.v1", "emailpassword_users", "totp_user_devices", "userid_mapping", "user_roles"} {
		if !strings.Contains(s, want) {
			t.Fatalf("export SQL lacks %q", want)
		}
	}
	var code []string
	for _, line := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			code = append(code, line)
		}
	}
	for _, write := range []string{"INSERT ", "UPDATE ", "DELETE ", "DROP ", "TRUNCATE ", "ALTER ", "CREATE "} {
		if strings.Contains(strings.ToUpper(strings.Join(code, "\n")), write) {
			t.Fatalf("export SQL writes (%s)", write)
		}
	}
	// WebAuthn login methods (core 11+) are reported, not dropped.
	doc := `{"format":"proudauth.supertokens-export.v1","supertokens":{"core_version":"12.0.7","app_id":"public"},"users":[
	 {"supertokensUserId":"u-1","loginMethods":[{"recipeId":"webauthn","email":"pk@example.com","tenantIds":["public"],"isVerified":true,"webauthnCredentialIds":["a","b"]}]}]}`
	res, err := Convert(SuperTokens, [][]byte{[]byte(doc)}, Options{Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	entity(t, res.Report, "webauthn_credentials", 2, 0, 0, 2, 0)
	b, _ := json.Marshal(res.Users)
	if !strings.Contains(string(b), "pk@example.com") {
		t.Fatalf("webauthn user: %s", b)
	}
}
