package migrate

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/credential"
	"github.com/proudbase/proudauth/internal/identity"
)

const kcFixture = "testdata/keycloak/demo-realm-26.8.0.json"

// Keycloak user IDs of the fixture.
const (
	kcAlice   = "6a3181ff-6cc9-467b-8d3e-bcb3ab9447e9"
	kcBob     = "4364124c-6323-456e-82f2-3f1845a34dab"
	kcCarol   = "dc7d0917-cb88-4c07-9f2b-d44f64aeaad0"
	kcDave    = "c05776bd-a070-40d1-b3dc-91d40819baec"
	kcErin    = "faa4ad2f-1725-470f-ab22-84146222ea8d"
	kcFrank   = "f8d3832b-722e-4874-b0df-d5b13cfa78b2"
	kcGrace   = "d8ed763a-8c68-4dd2-a4c0-516d8144c48a"
	kcHeidi   = "30b20b81-fccf-4f5b-8f81-2489b88ecb79"
	kcIvan    = "1acfdce0-ec45-4060-85e6-9574ffe36721"
	kcJudy    = "d1d40d5c-33d3-40a1-a275-9cb5707aa200"
	kcKevin   = "6ade59f3-5215-4a90-86ff-3c0a25af3faa"
	kcService = "19d1f03c-eea1-4e18-a4d8-0ed6bcdeb1c5"
	kcSupport = "99d7a4fc-0d1d-4ff0-a641-0e4bb90bb1d0"
)

func kcMapping() *Mapping {
	return &Mapping{Format: MappingFormat, MembershipRoles: []string{"member"},
		Roles: map[string]*RoleTarget{
			"realm-role:app-admin":           {Roles: []string{"admin"}},
			"realm-role:app-user":            {Roles: []string{}},
			"client-role:billing-app:editor": {Organization: "acme", Roles: []string{"billing-editor"}},
			"client-role:billing-app:viewer": nil,
			"group:/acme/admins":             {Roles: []string{"admin"}},
			"group:/globex":                  {Roles: []string{"orders-viewer"}},
		}}
}

// TestKeycloakConversion covers MIG-001 (the capability report inventories
// the source before anything is written: users by source ID, password and
// OTP credentials, passkeys, recovery codes, federated links, service
// accounts, organizations, memberships, role grants, clients, identity
// providers and flows), MIG-005, MIG-006 and MIG-007.
func TestKeycloakConversion(t *testing.T) {
	pw := passwords(t, "keycloak")
	res := convert(t, Keycloak, Options{ImportTOTP: true, Mapping: kcMapping()}, kcFixture)
	r := res.Report
	if res.SourceSystem != "keycloak-demo" || r.Source.Version != "26.8.0" || r.Source.Realm != "demo" || r.Format != ReportFormat {
		t.Fatalf("source: %s %+v", res.SourceSystem, r.Source)
	}
	noSecrets(t, res)

	// Passwords (MIG-006): argon2 (the Keycloak 26 default) and PBKDF2
	// convert losslessly and verify; verifiers outside the bounds do not
	// come over and the account must reset its password.
	for id, user := range map[string]string{kcAlice: "alice", kcBob: "bob", kcCarol: "carol", kcErin: "erin", kcHeidi: "heidi", kcIvan: "ivan",
		kcKevin: "kevin", kcSupport: "support"} {
		rec := record(t, res, id)
		if !verifies(t, rec.PasswordHash, pw[user]) || verifies(t, rec.PasswordHash, pw[user]+"x") {
			t.Fatalf("%s: converted verifier %q does not verify the source password", user, rec.PasswordHash)
		}
	}
	if h := record(t, res, kcBob).PasswordHash; !strings.HasPrefix(h, "$pbkdf2-sha256$i=27500$") {
		t.Fatalf("bob: %s", h)
	}
	if h := record(t, res, kcCarol).PasswordHash; !strings.HasPrefix(h, "$pbkdf2-sha512$i=210000$") {
		t.Fatalf("carol: %s", h)
	}
	if h := record(t, res, kcAlice).PasswordHash; !strings.HasPrefix(h, "$argon2id$v=19$m=7168,t=5,p=1$") {
		t.Fatalf("alice: %s", h)
	}
	for _, id := range []string{kcDave, kcGrace} {
		rec := record(t, res, id)
		if rec.PasswordHash != "" || !slices.Contains(rec.RequiredActions, identity.ActionUpdatePassword) {
			t.Fatalf("%s: unsupported verifier imported or reset not required: %+v", id, rec)
		}
	}
	if s := itemReasons(r, "password_credentials", kcDave); !strings.Contains(s, "unsupported") || !strings.Contains(s, "1000") {
		t.Fatalf("dave's PBKDF2 (1000 iterations) not reported: %s", s)
	}
	if s := itemReasons(r, "password_credentials", kcGrace); !strings.Contains(s, "m=2097152") {
		t.Fatalf("grace's oversized argon2 not reported: %s", s)
	}
	entity(t, r, "password_credentials", 10, 8, 0, 2, 0)

	// TOTP (MIG-007): Keycloak keys the HMAC with the secret's UTF-8 bytes.
	heidi := record(t, res, kcHeidi)
	if heidi.TOTPSecret != base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("heidiSecretKey012345")) {
		t.Fatalf("heidi's seed: %q", heidi.TOTPSecret)
	}
	now := time.Now()
	code, err := credential.TOTPCode(heidi.TOTPSecret, credential.TOTPStep(now))
	if err != nil || code != keycloakTOTP([]byte("heidiSecretKey012345"), now) {
		t.Fatalf("converted seed computes %s, Keycloak computes %s (%v)", code, keycloakTOTP([]byte("heidiSecretKey012345"), now), err)
	}
	ivan := record(t, res, kcIvan)
	if ivan.TOTPSecret != "" || !slices.Contains(ivan.RequiredActions, identity.ActionConfigureTOTP) {
		t.Fatalf("ivan's SHA-256/8-digit OTP imported or re-enrollment not required: %+v", ivan)
	}
	entity(t, r, "totp_factors", 2, 1, 0, 1, 0)

	// Account state and required actions.
	erin := record(t, res, kcErin)
	if erin.State != identity.StateSuspended || !slices.Equal(erin.RequiredActions, []string{identity.ActionVerifyEmail}) {
		t.Fatalf("erin (disabled, VERIFY_EMAIL): %+v", erin)
	}
	if bob := record(t, res, kcBob); !slices.Equal(bob.RequiredActions, []string{identity.ActionCompleteProfile}) {
		t.Fatalf("bob (UPDATE_PROFILE): %+v", bob.RequiredActions)
	}
	kevin := record(t, res, kcKevin)
	if kevin.Email != "" || kevin.Username != "kevin" || !slices.Equal(kevin.RequiredActions, []string{identity.ActionUpdatePassword}) {
		t.Fatalf("kevin (no email, temporary password): %+v", kevin)
	}
	judy := record(t, res, kcJudy)
	if !slices.Equal(judy.RequiredActions, []string{identity.ActionAcceptTerms, identity.ActionConfigureTOTP}) || judy.PasswordHash != "" {
		t.Fatalf("judy: %+v", judy)
	}
	entity(t, r, "webauthn_credentials", 1, 0, 0, 1, 0)
	entity(t, r, "recovery_codes", 1, 0, 0, 1, 0)
	entity(t, r, "federated_identities", 1, 0, 0, 1, 0)
	if !strings.Contains(itemReasons(r, "users", kcFrank), "identity provider link") {
		t.Fatalf("frank's IdP link loss not reported: %s", itemReasons(r, "users", kcFrank))
	}

	// Identifiers: a reserved username is dropped, the email kept.
	support := record(t, res, kcSupport)
	if support.Username != "" || support.Email != "helpdesk@acme.example" || support.DisplayName != "Help Desk" {
		t.Fatalf("support: %+v", support)
	}
	if !strings.Contains(itemReasons(r, "users", kcSupport), "reserved username") {
		t.Fatalf("dropped username not reported")
	}
	alice := record(t, res, kcAlice)
	if alice.GivenName != "Alice" || alice.FamilyName != "Anders" || !alice.EmailVerified || alice.AdminMetadata != nil {
		t.Fatalf("alice: %+v", alice)
	}
	if !strings.Contains(itemReasons(r, "users", kcAlice), "attributes not kept: department, employee_id") {
		t.Fatalf("dropped attributes not reported: %s", itemReasons(r, "users", kcAlice))
	}

	// Service accounts are not users.
	if hasRecord(res, kcService) {
		t.Fatal("service account imported as a user")
	}
	entity(t, r, "service_accounts", 1, 0, 0, 1, 0)
	entity(t, r, "users", 12, 4, 8, 0, 0) // bob, erin, heidi and kevin convert without loss

	// Organizations and the reviewed role translation (MIG-005).
	if len(res.Organizations) != 2 || res.Organizations[0].Slug != "acme" || res.Organizations[0].ExternalID != "keycloak-demo:org:759f3c59-7f8d-474b-b508-e1d183f2d998" {
		t.Fatalf("organizations: %+v", res.Organizations)
	}
	ms := alice.Memberships
	if len(ms) != 1 || ms[0].Organization != "acme" || !slices.Equal(ms[0].Roles, []string{"member", "admin", "billing-editor"}) {
		t.Fatalf("alice's memberships: %+v", ms)
	}
	if carol := record(t, res, kcCarol); len(carol.Memberships) != 1 || !slices.Equal(carol.Memberships[0].Roles, []string{"member"}) {
		t.Fatalf("carol's memberships (viewer mapped to nothing, group /acme untranslated): %+v", carol.Memberships)
	}
	// Bob's /globex group grants orders-viewer in his organization.
	if bob := record(t, res, kcBob); len(bob.Memberships) != 1 || !slices.Equal(bob.Memberships[0].Roles, []string{"member", "orders-viewer"}) {
		t.Fatalf("bob's memberships: %+v", bob.Memberships)
	}
	// Dave belongs to no organization: his realm roles have no scope.
	if dave := record(t, res, kcDave); len(dave.Memberships) != 0 {
		t.Fatalf("dave: %+v", dave.Memberships)
	}
	if !strings.Contains(itemReasons(r, "role_assignments", kcCarol), "no reviewed translation for group:/acme") {
		t.Fatalf("untranslated group grant not reported: %s", itemReasons(r, "role_assignments", kcCarol))
	}
	if !strings.Contains(itemReasons(r, "role_assignments", kcCarol), "client-role:billing-app:viewer is mapped to no roles") {
		t.Fatalf("role mapped to nothing not reported: %s", itemReasons(r, "role_assignments", kcCarol))
	}
	if r.Summary.Users != 12 || r.Summary.UsersToImport != 12 || r.Summary.PasswordsMigrated != 8 || r.Summary.PasswordResetsRequired != 2 ||
		r.Summary.TOTPMigrated != 1 || r.Summary.MFAReenrollmentsRequired != 1 || r.Summary.SuspendedAccounts != 1 || r.Summary.Organizations != 2 {
		t.Fatalf("summary: %+v", r.Summary)
	}

	// Configuration that does not carry over is listed, never dropped.
	entity(t, r, "clients", 3, 0, 0, 2, 1)
	entity(t, r, "identity_providers", 1, 0, 0, 1, 0)
	entity(t, r, "authentication_flows", 1, 0, 0, 1, 0)
	if !strings.Contains(itemReasons(r, "clients", "billing-app"), "client secret cannot be carried over") {
		t.Fatalf("client secret not reported: %s", itemReasons(r, "clients", "billing-app"))
	}
	if !strings.Contains(itemReasons(r, "realm_policies", "passwordPolicy"), "length(12)") {
		t.Fatal("password policy not reported")
	}
}

// keycloakTOTP computes an RFC 6238 code the way Keycloak does (HmacSHA1
// over the stored secret's bytes, 6 digits, 30 s), independently of the
// converter.
func keycloakTOTP(key []byte, now time.Time) string {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], uint64(now.Unix()/30))
	m := hmac.New(sha1.New, key)
	m.Write(c[:])
	h := m.Sum(nil)
	o := h[len(h)-1] & 15
	v := binary.BigEndian.Uint32(h[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

func TestKeycloakOptionsAndVariants(t *testing.T) {
	// Without explicit authorization TOTP seeds stay behind and the
	// account enrolls again; attributes are kept only when asked.
	res := convert(t, Keycloak, Options{KeepAttributes: true}, kcFixture)
	heidi := record(t, res, kcHeidi)
	if heidi.TOTPSecret != "" || !slices.Contains(heidi.RequiredActions, identity.ActionConfigureTOTP) {
		t.Fatalf("heidi without --import-totp: %+v", heidi)
	}
	entity(t, res.Report, "totp_factors", 2, 0, 0, 1, 1)
	alice := record(t, res, kcAlice)
	md, _ := json.Marshal(alice.AdminMetadata)
	if !strings.Contains(string(md), `"department":"engineering"`) || !strings.Contains(string(md), `"source_system":"keycloak-demo"`) {
		t.Fatalf("kept attributes: %s", md)
	}
	// Without a mapping no role is translated; memberships carry no roles.
	if ms := alice.Memberships; len(ms) != 1 || len(ms[0].Roles) != 0 {
		t.Fatalf("roles translated without a mapping: %+v", ms)
	}
	if res.Report.Summary.UntranslatedRoleGrants != 9 {
		t.Fatalf("untranslated grants: %+v", res.Report.Summary)
	}

	// A directory export (realm file plus users file) converts the same.
	var realm map[string]any
	_ = json.Unmarshal(load(t, kcFixture), &realm)
	users := map[string]any{"realm": "demo", "users": realm["users"]}
	delete(realm, "users")
	rb, _ := json.Marshal(realm)
	ub, _ := json.Marshal(users)
	split, err := Convert(Keycloak, [][]byte{rb, ub}, Options{KeepAttributes: true, Now: fixedNow})
	if err != nil || len(split.Users) != len(res.Users) {
		t.Fatalf("directory export: %v %d", err, len(split.Users))
	}

	// Organizations excluded by the mapping are not created and their
	// memberships are reported; groups can become organizations.
	m := &Mapping{Organizations: map[string]*OrgTarget{"org:globex": nil, "group:/acme": {Slug: "acme-group", DisplayName: "Acme (group)"}}}
	res = convert(t, Keycloak, Options{Mapping: m}, kcFixture)
	var slugs []string
	for _, o := range res.Organizations {
		slugs = append(slugs, o.Slug)
	}
	if !slices.Equal(slugs, []string{"acme", "acme-group"}) {
		t.Fatalf("organizations: %v", slugs)
	}
	if bob := record(t, res, kcBob); len(bob.Memberships) != 0 {
		t.Fatalf("membership in an excluded organization: %+v", bob.Memberships)
	}
	if !strings.Contains(itemReasons(res.Report, "memberships", kcBob), "excluded by the mapping") {
		t.Fatal("excluded membership not reported")
	}
	// alice is in /acme/admins, so in the /acme group organization too.
	if alice := record(t, res, kcAlice); len(alice.Memberships) != 2 || alice.Memberships[1].Organization != "acme-group" {
		t.Fatalf("group organization membership: %+v", alice.Memberships)
	}

	// The template lists every key for review.
	tpl := Template(convert(t, Keycloak, Options{}, kcFixture), nil)
	if _, ok := tpl.Roles["realm-role:app-admin"]; !ok || tpl.Organizations["org:acme"].Slug != "acme" {
		t.Fatalf("template: %+v", tpl)
	}
	if _, ok := tpl.Roles["realm-role:default-roles-demo"]; ok {
		t.Fatal("template lists Keycloak's default role")
	}

	// Credential variants Keycloak can hold but ProudAuth refuses.
	for _, c := range []struct{ data, want string }{
		{`{"hashIterations":3,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["65536"],"type":["i"],"version":["1.3"],"parallelism":["1"]}}`, "argon2i is not supported"},
		{`{"hashIterations":3,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["65536"],"type":["id"],"version":["1.0"],"parallelism":["1"]}}`, "version 1.0"},
		{`{"hashIterations":1,"algorithm":"sha512-custom","additionalParameters":{}}`, "not supported"},
	} {
		p := kcPassword(kcCredential{Type: "password", SecretData: `{"value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","salt":"AAAAAAAAAAAAAAAAAAAAAA=="}`, CredentialData: c.data})
		if p.hash != "" || !strings.Contains(p.problem, c.want) {
			t.Fatalf("%s: %+v", c.want, p)
		}
	}
	for _, c := range []struct{ data, want string }{
		{`{"subType":"hotp","digits":6,"counter":0,"period":30,"algorithm":"HmacSHA1"}`, "OTP type hotp"},
		{`{"subType":"totp","digits":6,"counter":0,"period":60,"algorithm":"HmacSHA1"}`, "60 s"},
	} {
		o := kcOTP(kcCredential{Type: "otp", SecretData: `{"value":"abcdefghijklmnopqrst"}`, CredentialData: c.data})
		if o.seed != "" || !strings.Contains(o.problem, c.want) {
			t.Fatalf("%s: %+v", c.want, o)
		}
	}
	if o := kcOTP(kcCredential{Type: "otp", SecretData: `{"value":"JBSWY3DPEHPK3PXP"}`,
		CredentialData: `{"subType":"totp","digits":6,"period":30,"algorithm":"HmacSHA1","secretEncoding":"BASE32"}`}); o.seed != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("base32-encoded Keycloak secret: %+v", o)
	}
}
