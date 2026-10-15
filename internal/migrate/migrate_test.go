package migrate

// The fixtures in testdata are real exports, trimmed:
//
//   - keycloak/demo-realm-26.8.0.json: `kc.sh export --file --realm demo
//     --users same_file` from Keycloak 26.8.0 (quay.io/keycloak/keycloak:26.8.0),
//     with built-in authentication flows and client scopes, localization texts
//     and the key providers (private keys) removed.
//   - zitadel/export-v4.16.3.json: the response of POST /admin/v1/export
//     {"withPasswords": true, "withOtp": true, "responseOutput": true} from
//     ZITADEL v4.16.3 (ghcr.io/zitadel/zitadel:v4.16.3, PostgreSQL 18), with
//     PasswordHasher.Verifiers argon2,pbkdf2,md5,scrypt so hashed imports of
//     those formats were accepted.
//   - supertokens/export-core-12.0.7.json: supertokens_export.sql run against
//     SuperTokens core 12.0.7 (plugin postgresql 9.5.5); every user in it
//     was accepted by that core's own bulk-import validation
//     (POST /bulk-import/users). supertokens/core-users-api-12.0.7.json is the
//     core's GET /users response for the same data.
//
// testdata/fixture-passwords.json lists the test passwords set in the
// sources.

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/identity"
)

var fixedNow = func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }

func load(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func passwords(t *testing.T, source string) map[string]string {
	t.Helper()
	var all map[string]json.RawMessage
	if err := json.Unmarshal(load(t, "testdata/fixture-passwords.json"), &all); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := json.Unmarshal(all[source], &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func convert(t *testing.T, source string, opts Options, files ...string) *Result {
	t.Helper()
	docs := make([][]byte, len(files))
	for i, f := range files {
		docs[i] = load(t, f)
	}
	if opts.Now == nil {
		opts.Now = fixedNow
	}
	res, err := Convert(source, docs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func record(t *testing.T, res *Result, sourceID string) identity.ImportRecord {
	t.Helper()
	for _, r := range res.Users {
		if r.SourceID == sourceID {
			return r
		}
	}
	t.Fatalf("no record for %s", sourceID)
	return identity.ImportRecord{}
}

func hasRecord(res *Result, sourceID string) bool {
	return slices.ContainsFunc(res.Users, func(r identity.ImportRecord) bool { return r.SourceID == sourceID })
}

var testHasher = &credential.Hasher{Params: credential.Params{Memory: 8 * 1024, Time: 1, Threads: 1}, MaxBytes: 1024}

// verifies reports whether a converted verifier verifies the password.
func verifies(t *testing.T, verifier, pw string) bool {
	t.Helper()
	if verifier == "" {
		return false
	}
	if err := credential.ValidateImportedHash(verifier); err != nil {
		t.Fatalf("converted verifier rejected by the import rules: %v", err)
	}
	_, err := testHasher.Verify(verifier, pw)
	return err == nil
}

func entity(t *testing.T, r *Report, name string, total, converted, loss, unsupported, ignored int) {
	t.Helper()
	got := r.Entity(name)
	want := EntityReport{Total: total, Converted: converted, ConvertedWithLoss: loss, Unsupported: unsupported, Ignored: ignored}
	if got.Total != want.Total || got.Converted != want.Converted || got.ConvertedWithLoss != want.ConvertedWithLoss ||
		got.Unsupported != want.Unsupported || got.Ignored != want.Ignored {
		got.Reasons = nil
		t.Errorf("entity %s: got %+v, want %+v", name, got, want)
	}
}

func itemReasons(r *Report, entity, sourceID string) string {
	var out []string
	for _, it := range r.Items {
		if it.Entity == entity && it.SourceID == sourceID {
			out = append(out, it.Outcome+": "+strings.Join(it.Reasons, "; "))
		}
	}
	return strings.Join(out, " | ")
}

// noSecrets checks that a report never carries credentials, seeds or
// contact data (it names records by source ID only).
func noSecrets(t *testing.T, res *Result) {
	t.Helper()
	b, _ := json.Marshal(res.Report)
	s := string(b)
	for _, u := range res.Users {
		for _, v := range []string{u.PasswordHash, u.TOTPSecret, u.Email} {
			if v != "" && strings.Contains(s, v) {
				t.Fatalf("report contains a credential or contact value of %s", u.SourceID)
			}
		}
	}
}

func TestAdaptersAndVersions(t *testing.T) {
	for _, src := range []string{Keycloak, Zitadel, SuperTokens} {
		a, ok := LookupAdapter(src)
		if !ok || len(a.TestedVersions) == 0 || a.SupportedVersions == "" || a.ExportCommand == "" {
			t.Fatalf("adapter %s incomplete: %+v", src, a)
		}
	}
	if _, err := Convert("auth0", [][]byte{[]byte(`{}`)}, Options{}); err == nil {
		t.Fatal("unknown source accepted")
	}
	// MIG-002: a version outside the declared range is refused, and an
	// export that does not state its version needs it explicitly.
	kc := strings.Replace(string(load(t, "testdata/keycloak/demo-realm-26.8.0.json")), `"keycloakVersion": "26.8.0"`, `"keycloakVersion": "25.0.6"`, 1)
	if _, err := Convert(Keycloak, [][]byte{[]byte(kc)}, Options{}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Keycloak 25 accepted: %v", err)
	}
	zt := load(t, "testdata/zitadel/export-v4.16.3.json")
	if _, err := Convert(Zitadel, [][]byte{zt}, Options{}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ZITADEL export without a version accepted: %v", err)
	}
	if _, err := Convert(Zitadel, [][]byte{zt}, Options{SourceVersion: "v2.71.0"}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("ZITADEL v2 accepted: %v", err)
	}
	st := load(t, "testdata/supertokens/export-core-12.0.7.json")
	if _, err := Convert(SuperTokens, [][]byte{st}, Options{SourceVersion: "11.0.0"}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("conflicting SuperTokens versions accepted: %v", err)
	}
	// A document of another product is refused, not guessed at.
	if _, err := Convert(Keycloak, [][]byte{zt}, Options{}); err == nil {
		t.Fatal("ZITADEL export accepted as Keycloak")
	}
	if _, err := Convert(SuperTokens, [][]byte{load(t, "testdata/keycloak/demo-realm-26.8.0.json")}, Options{SourceVersion: "12.0.7"}); err == nil {
		t.Fatal("Keycloak export accepted as SuperTokens")
	}
}

// TestSourceVersionForms: when the export states its version, the given
// version may be that version or a leading part of it (the major version);
// other versions and unsupported majors are refused with a message that says
// what is expected.
func TestSourceVersionForms(t *testing.T) {
	kc := load(t, "testdata/keycloak/demo-realm-26.8.0.json")
	st := load(t, "testdata/supertokens/export-core-12.0.7.json")
	zt := load(t, "testdata/zitadel/export-v4.16.3.json")
	for _, c := range []struct {
		source, version string
		doc             []byte
	}{
		{Keycloak, "26", kc}, {Keycloak, "26.8", kc}, {Keycloak, "26.8.0", kc}, {Keycloak, "v26.8.0", kc}, {Keycloak, "26.x", kc}, {Keycloak, " 26 ", kc},
		{SuperTokens, "12", st}, {SuperTokens, "core 12.0.7", st}, {SuperTokens, "12.0", st},
		{Zitadel, "v4", zt}, {Zitadel, "4", zt}, {Zitadel, "v4.x", zt}, {Zitadel, "v4.16.3", zt},
	} {
		res, err := Convert(c.source, [][]byte{c.doc}, Options{SourceVersion: c.version, Now: fixedNow})
		if err != nil {
			t.Fatalf("%s %q refused: %v", c.source, c.version, err)
		}
		if c.source != Zitadel && res.Source.Version != map[string]string{Keycloak: "26.8.0", SuperTokens: "12.0.7"}[c.source] {
			t.Fatalf("%s %q: reported version %s instead of the export's", c.source, c.version, res.Source.Version)
		}
	}
	for _, c := range []struct {
		source, version string
		doc             []byte
		msg             string
	}{
		{Keycloak, "25", kc, "give 26.8.0 or its major version 26"},
		{Keycloak, "2", kc, "give 26.8.0 or its major version 26"},
		{Keycloak, "26.9", kc, "states Keycloak version 26.8.0 but 26.9 was given"},
		{Keycloak, "26.8.1", kc, "give 26.8.0 or its major version 26"},
		{SuperTokens, "11", st, "give 12.0.7 or its major version 12"},
		{Zitadel, "v5", zt, "this release supports v4.x"},
		{Zitadel, "v", zt, "this release supports v4.x"},
	} {
		_, err := Convert(c.source, [][]byte{c.doc}, Options{SourceVersion: c.version, Now: fixedNow})
		if !errors.Is(err, ErrUnsupportedVersion) || !strings.Contains(err.Error(), c.msg) {
			t.Fatalf("%s %q: %v (want %q)", c.source, c.version, err, c.msg)
		}
	}
	// An export of an unsupported major is refused even when the given
	// version names it.
	old := []byte(strings.Replace(string(kc), `"keycloakVersion": "26.8.0"`, `"keycloakVersion": "25.0.6"`, 1))
	for _, v := range []string{"25", "25.0.6", "26"} {
		if _, err := Convert(Keycloak, [][]byte{old}, Options{SourceVersion: v}); !errors.Is(err, ErrUnsupportedVersion) || !strings.Contains(err.Error(), "this release supports 26.x") {
			t.Fatalf("Keycloak 25 with %q: %v", v, err)
		}
	}
}

// TestZitadelExportCommand: the reported export request carries every member
// of ZITADEL's documented admin export request, the duration "timeout"
// included (the same request as in docs/operations/migration-adapters.md).
func TestZitadelExportCommand(t *testing.T) {
	a, _ := LookupAdapter(Zitadel)
	for _, m := range []string{`"withPasswords": true`, `"withOtp": true`, `"responseOutput": true`, `"timeout": "60s"`, "POST /admin/v1/export"} {
		if !strings.Contains(a.ExportCommand, m) {
			t.Fatalf("export command without %s: %s", m, a.ExportCommand)
		}
	}
	body := a.ExportCommand[strings.Index(a.ExportCommand, "{") : strings.Index(a.ExportCommand, "}")+1]
	var req map[string]any
	if err := json.Unmarshal([]byte(body), &req); err != nil || len(req) != 4 {
		t.Fatalf("export request body %s: %v", body, err)
	}
	if d, err := time.ParseDuration(req["timeout"].(string)); err != nil || d <= 0 {
		t.Fatalf("timeout %v is not a duration: %v", req["timeout"], err)
	}
}

func TestMappingParsing(t *testing.T) {
	if _, err := ParseMapping([]byte(`{"format":"proudauth.migration-mapping.v1","organizations":{"org:a":{"slug":"Not A Slug"}}}`)); err == nil {
		t.Fatal("invalid slug accepted")
	}
	if _, err := ParseMapping([]byte(`{"roles":{"role:x":{"roles":["admin"],"grant_all":true}}}`)); err == nil {
		t.Fatal("unknown member accepted")
	}
	if _, err := ParseMapping([]byte(`{"format":"other"}`)); err == nil {
		t.Fatal("unknown format accepted")
	}
	m, err := ParseMapping([]byte(`{"organizations":{"org:a":null,"org:b":{"slug":"bee"}},"roles":{"role:x":null,"role:y":{"roles":["member"]}}}`))
	if err != nil || m.Organizations["org:a"] != nil || m.Organizations["org:b"].Slug != "bee" || m.Roles["role:x"] != nil {
		t.Fatalf("mapping: %+v %v", m, err)
	}
}

func TestBatches(t *testing.T) {
	recs := make([]identity.ImportRecord, 25)
	for i := range recs {
		recs[i] = identity.ImportRecord{SourceID: strings.Repeat("x", 1000) + string(rune('a'+i))}
	}
	a := &Applier{BatchSize: 10, BatchBytes: 5000}
	bs := a.batches(recs)
	total := 0
	for _, b := range bs {
		if len(b) > 10 {
			t.Fatalf("batch of %d records", len(b))
		}
		raw, _ := json.Marshal(b)
		if len(raw) > 5000+len(b) {
			t.Fatalf("batch of %d bytes", len(raw))
		}
		total += len(b)
	}
	if total != 25 || len(bs) < 5 {
		t.Fatalf("batches: %d records in %d batches", total, len(bs))
	}
}

// TestEveryAdapterReportsSessionsUnsupported covers SES-022 and MIG-010 for
// every registered adapter, including ones added later: sessions are never
// migrated (trust, secrets and expiry cannot be established across issuers,
// so users sign in again). Each adapter's published capabilities (GET
// /migration-adapters, identity-cli migrate-from --list) list sessions as
// unsupported and never as converted, and its conversion report counts them
// as unsupported. A new adapter must add its fixture here.
func TestEveryAdapterReportsSessionsUnsupported(t *testing.T) {
	fixtures := map[string]struct {
		opts Options
		file string
	}{
		Keycloak:    {Options{Mapping: kcMapping()}, kcFixture},
		Zitadel:     {Options{SourceVersion: "v4.16.3", Mapping: ztMapping()}, ztFixture},
		SuperTokens: {Options{Mapping: stMapping()}, stFixture},
	}
	if len(Adapters) == 0 {
		t.Fatal("no adapters registered")
	}
	mentions := func(list []string, w string) bool {
		return slices.ContainsFunc(list, func(s string) bool { return strings.Contains(strings.ToLower(s), w) })
	}
	for _, a := range Adapters {
		if !mentions(a.Unsupported, "sessions") {
			t.Errorf("%s: published capabilities do not list sessions as unsupported: %q", a.Source, a.Unsupported)
		}
		if mentions(a.Converts, "session") || mentions(a.ConvertsWithLoss, "session") {
			t.Errorf("%s: published capabilities claim to convert sessions", a.Source)
		}
		fx, ok := fixtures[a.Source]
		if !ok {
			t.Errorf("%s: no fixture; add one so its session report is checked", a.Source)
			continue
		}
		e := convert(t, a.Source, fx.opts, fx.file).Report.Entity("sessions")
		if e.Total == 0 || e.Unsupported != e.Total || e.Converted+e.ConvertedWithLoss+e.Ignored != 0 {
			t.Errorf("%s: sessions reported as %+v, want only unsupported items", a.Source, e)
		}
	}
}
