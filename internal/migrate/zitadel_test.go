package migrate

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/identity"
)

const ztFixture = "testdata/zitadel/export-v4.16.3.json"

// ZITADEL IDs of the fixture.
const (
	ztAdmin  = "394589032694874117" // zitadel-admin, org Demo
	ztUma    = "394589255512358917"
	ztVera   = "394589254186958853"
	ztWalt   = "394589236285669381"
	ztXena   = "394589236252114949"
	ztYusuf  = "394589236218560517"
	ztZoe    = "394589178924367877"
	ztTariq  = "394589256787427333" // org Globex
	ztDemo   = "394589032694218757"
	ztAcme   = "394589153439776773"
	ztShop   = "394589278597808133" // project of Demo
	ztPortal = "394589305978224645" // project of Acme
)

func ztMapping() *Mapping {
	return &Mapping{
		Organizations: map[string]*OrgTarget{"org:" + ztDemo: nil, "org:" + ztAcme: {Slug: "acme-corp", DisplayName: "Acme Corporation"}},
		Roles: map[string]*RoleTarget{
			"org-member:ORG_OWNER":                        {Roles: []string{"owner"}},
			"org-member:ORG_USER_MANAGER":                 {Roles: []string{"admin"}},
			"project-role:" + ztShop + ":shop.admin":      {Organization: "acme-corp", Roles: []string{"shop-admin"}},
			"project-role:" + ztPortal + ":portal.editor": {Roles: []string{"editor"}},
		}}
}

func TestZitadelConversion(t *testing.T) {
	pw := passwords(t, "zitadel")
	res := convert(t, Zitadel, Options{SourceVersion: "v4.16.3", ImportTOTP: true, KeepAttributes: true, Mapping: ztMapping()}, ztFixture)
	r := res.Report
	if res.SourceSystem != "zitadel" || r.Source.Version != "v4.16.3" {
		t.Fatalf("source: %s %+v", res.SourceSystem, r.Source)
	}
	noSecrets(t, res)

	// Passwords: bcrypt (ZITADEL's default, cost 14), argon2id and PBKDF2
	// in passlib form convert; md5crypt does not.
	if h := record(t, res, ztZoe).PasswordHash; !strings.HasPrefix(h, "$2a$14$") || !verifies(t, h, pw["zoe"]) {
		t.Fatalf("zoe's bcrypt: %s", h)
	}
	if h := record(t, res, ztYusuf).PasswordHash; !verifies(t, h, pw["yusuf"]) {
		t.Fatalf("yusuf's argon2id: %s", h)
	}
	if h := record(t, res, ztXena).PasswordHash; !strings.HasPrefix(h, "$pbkdf2-sha256$i=29000$") || !verifies(t, h, pw["xena"]) {
		t.Fatalf("xena's passlib PBKDF2: %s", h)
	}
	walt := record(t, res, ztWalt)
	if walt.PasswordHash != "" || !slices.Contains(walt.RequiredActions, identity.ActionUpdatePassword) {
		t.Fatalf("walt's md5crypt imported or reset not required: %+v", walt)
	}
	if !strings.Contains(itemReasons(r, "password_credentials", ztWalt), "md5crypt") {
		t.Fatal("md5crypt not reported")
	}
	entity(t, r, "password_credentials", 8, 7, 0, 1, 0)

	vera := record(t, res, ztVera)
	if vera.TOTPSecret != "LV422DWLOKNW5WT4HS5QD72Q5RHZMSUO" {
		t.Fatalf("vera's TOTP: %q", vera.TOTPSecret)
	}
	entity(t, r, "phone_numbers", 1, 0, 0, 1, 0)
	if uma := record(t, res, ztUma); uma.State != identity.StateSuspended || uma.EmailVerified {
		t.Fatalf("uma (deactivated, unverified): %+v", uma)
	}
	zoe := record(t, res, ztZoe)
	if zoe.Locale != "de" || zoe.DisplayName != "Zoe Z." || zoe.Username != "zoe" {
		t.Fatalf("zoe's profile: %+v", zoe)
	}
	md, _ := json.Marshal(zoe.AdminMetadata)
	if !strings.Contains(string(md), `"cost_center":"CC-4410"`) {
		t.Fatalf("zoe's metadata: %s", md)
	}
	if admin := record(t, res, ztAdmin); admin.Username != "" || admin.Email != "zitadel-admin@demo.localhost" {
		t.Fatalf("a user name equal to the email is not a second identifier: %+v", admin)
	}
	entity(t, r, "service_accounts", 3, 0, 0, 3, 0)
	entity(t, r, "federated_identities", 1, 0, 0, 1, 0)

	// Organizations through the mapping: Demo excluded, Acme renamed,
	// Globex by default.
	var slugs []string
	for _, o := range res.Organizations {
		slugs = append(slugs, o.Slug)
	}
	if !slices.Equal(slugs, []string{"acme-corp", "globex"}) {
		t.Fatalf("organizations: %v", slugs)
	}
	// Zoe is ORG_OWNER of Acme (translated) and of Demo (excluded, so the
	// grant has no scope), has portal.editor in her organization and
	// shop.admin explicitly scoped to acme-corp.
	if len(zoe.Memberships) != 1 || zoe.Memberships[0].Organization != "acme-corp" ||
		!slices.Equal(slices.Sorted(slices.Values(zoe.Memberships[0].Roles)), []string{"editor", "owner", "shop-admin"}) {
		t.Fatalf("zoe's memberships: %+v", zoe.Memberships)
	}
	if s := itemReasons(r, "role_assignments", ztZoe); !strings.Contains(s, "org-member:ORG_OWNER: no organization to scope") {
		t.Fatalf("unscoped grant not reported: %s", s)
	}
	if v := record(t, res, ztVera); len(v.Memberships) != 1 || !slices.Equal(v.Memberships[0].Roles, []string{"admin"}) {
		t.Fatalf("vera's memberships: %+v", v.Memberships)
	}
	if s := itemReasons(r, "role_assignments", ztVera); !strings.Contains(s, "no reviewed translation for project-role:"+ztShop+":shop.viewer") {
		t.Fatalf("untranslated project role not reported: %s", s)
	}
	if tariq := record(t, res, ztTariq); len(tariq.Memberships) != 1 || tariq.Memberships[0].Organization != "globex" {
		t.Fatalf("tariq: %+v", tariq.Memberships)
	}
	if !strings.Contains(itemReasons(r, "memberships", ztAdmin), "excluded by the mapping") {
		t.Fatal("membership in the excluded organization not reported")
	}
	entity(t, r, "clients", 5, 0, 0, 1, 4)
	entity(t, r, "projects", 3, 0, 0, 2, 1)
	if len(r.Notes) == 0 || !strings.Contains(strings.Join(r.Notes, " "), "passkeys") {
		t.Fatalf("export limitations not noted: %v", r.Notes)
	}

	// The import-request shape of the same data converts identically.
	var exp map[string]any
	_ = json.Unmarshal(load(t, ztFixture), &exp)
	wrapped, _ := json.Marshal(map[string]any{"dataOrgs": exp, "timeout": "10m"})
	again, err := Convert(Zitadel, [][]byte{wrapped}, Options{SourceVersion: "4.16.3", Now: fixedNow})
	if err != nil || len(again.Users) != len(res.Users) {
		t.Fatalf("dataOrgs shape: %v", err)
	}
}

func TestZitadelPasswordFormats(t *testing.T) {
	for in, want := range map[string]string{
		"$2y$12$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234": "$2y$12$",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaA":             "",
		"$scrypt$ln=16,r=8,p=1$c2FsdA$aGFzaA":                          "",
		"$6$rounds=5000$salt$hash":                                     "",
		"$pbkdf2$100000$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2g":  "$pbkdf2-sha1$i=100000$",
	} {
		p := ztPassword(in)
		if want == "" && (p.hash != "" || p.problem == "") || want != "" && !strings.HasPrefix(p.hash, want) {
			t.Fatalf("%s: %+v", in, p)
		}
	}
}
