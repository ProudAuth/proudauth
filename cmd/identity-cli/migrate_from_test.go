package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/migrate"
)

// TestMigrateFromOffline plans a Keycloak export without a server: the
// capability report, the mapping template and the import documents are
// written with mode 0600 (the documents carry password verifiers).
func TestMigrateFromOffline(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	tpl := filepath.Join(dir, "mapping.json")
	docs := filepath.Join(dir, "docs")
	err := migrateFrom([]string{"keycloak", "--input", "../../internal/migrate/testdata/keycloak/demo-realm-26.8.0.json", "--offline",
		"--report", report, "--write-mapping-template", tpl, "--write-documents", docs, "--import-totp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{report, tpl, filepath.Join(docs, "user-import-001.json"), filepath.Join(docs, "organizations.json")} {
		st, err := os.Stat(f)
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, err, st)
		}
	}
	var r migrate.Report
	b, _ := os.ReadFile(report)
	if err := json.Unmarshal(b, &r); err != nil || r.Format != migrate.ReportFormat || r.Summary.Users != 12 || r.Import != nil {
		t.Fatalf("report: %v %+v", err, r.Summary)
	}
	if strings.Contains(string(b), "$argon2id$") {
		t.Fatal("the report carries password verifiers")
	}
	m, err := migrate.ParseMapping(mustRead(t, tpl))
	if err != nil || m.Roles["realm-role:app-admin"] == nil {
		t.Fatalf("template: %v %+v", err, m)
	}
	var doc struct {
		Format string `json:"format"`
		Users  []any  `json:"users"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join(docs, "user-import-001.json")), &doc); err != nil || doc.Format != "proudauth.user-import.v1" || len(doc.Users) != 12 {
		t.Fatalf("import document: %v %s %d", err, doc.Format, len(doc.Users))
	}

	for _, args := range [][]string{
		{"auth0", "--input", "x.json"},
		{"keycloak"},
		{"keycloak", "--input", "x.json", "--plan", "--apply"},
		{"keycloak", "--input", "x.json", "--offline", "--apply"},
		{"keycloak", "--input", "x.json", "--trust-email-verification", "--verification-reason", "short"},
		{"zitadel", "--input", "../../internal/migrate/testdata/zitadel/export-v4.16.3.json", "--offline", "--report", report},
	} {
		if err := migrateFrom(args); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
	if err := migrateFrom([]string{"--list"}); err != nil {
		t.Fatal(err)
	}
	var list bytes.Buffer
	if err := printAdapters(&list); err != nil || !strings.Contains(list.String(), `"responseOutput": true, "timeout": "60s"}`) {
		t.Fatalf("the ZITADEL export command lacks the timeout: %v\n%s", err, list.String())
	}

	// --batch-size outside 1..1000 is refused, not replaced.
	for _, n := range []string{"0", "-1", "1001", "5000"} {
		err := migrateFrom([]string{"keycloak", "--input", keycloakFixture, "--offline", "--report", report, "--batch-size", n})
		if err == nil || !strings.Contains(err.Error(), "--batch-size "+n+" is out of range: it must be between 1 and 1000") {
			t.Fatalf("--batch-size %s: %v", n, err)
		}
	}
	if err := migrateFrom([]string{"keycloak", "--input", keycloakFixture, "--offline", "--report", report, "--batch-size", "1000", "--write-documents", docs}); err != nil {
		t.Fatalf("--batch-size 1000: %v", err)
	}

	// --source-version may name the export's version by its major version;
	// another version or an unsupported major is refused.
	for _, v := range []string{"26", "26.8.0", "v26"} {
		if err := migrateFrom([]string{"keycloak", "--input", keycloakFixture, "--offline", "--report", report, "--source-version", v}); err != nil {
			t.Fatalf("--source-version %s: %v", v, err)
		}
	}
	if err := migrateFrom([]string{"keycloak", "--input", keycloakFixture, "--offline", "--report", report, "--source-version", "25"}); !errors.Is(err, migrate.ErrUnsupportedVersion) ||
		!strings.Contains(err.Error(), "give 26.8.0 or its major version 26") {
		t.Fatalf("--source-version 25: %v", err)
	}
	if err := migrateFrom([]string{"zitadel", "--input", "../../internal/migrate/testdata/zitadel/export-v4.16.3.json", "--offline", "--report", report, "--source-version", "v4"}); err != nil {
		t.Fatalf("ZITADEL --source-version v4: %v", err)
	}
}

const keycloakFixture = "../../internal/migrate/testdata/keycloak/demo-realm-26.8.0.json"

// TestMigrateFromApplyReconciles: --apply ends with a reconciliation that
// sends the converted export's expected counts; a reconciliation that does
// not match, or that fails, makes the command fail (non-zero exit) after the
// report is written. A dry run does not reconcile.
func TestMigrateFromApplyReconciles(t *testing.T) {
	useTempConfigDir(t)
	var (
		mu              sync.Mutex
		reconciliations []url.Values
		jobs            int
		status          = http.StatusOK
		answer          any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		p := strings.TrimPrefix(r.URL.Path, "/api/v1/realms/main")
		reply := func(code int, v any) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			_ = json.NewEncoder(w).Encode(v)
		}
		switch {
		case r.Method == "GET" && p == "/organizations":
			reply(200, map[string]any{"items": []any{}})
		case r.Method == "POST" && p == "/organizations":
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			reply(201, map[string]any{"id": "org_" + b["slug"].(string)})
		case r.Method == "POST" && p == "/user-imports":
			jobs++
			reply(202, map[string]any{"job_id": "job_" + strconv.Itoa(jobs)})
		case r.Method == "GET" && strings.HasPrefix(p, "/jobs/"):
			reply(200, map[string]any{"id": strings.TrimPrefix(p, "/jobs/"), "state": "succeeded", "result": map[string]any{"counts": map[string]int{"imported": 1}}})
		case r.Method == "GET" && p == "/user-imports/reconciliation":
			reconciliations = append(reconciliations, r.URL.Query())
			reply(status, answer)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			reply(400, map[string]any{"status": 400, "title": "unexpected"})
		}
	}))
	defer srv.Close()
	if err := saveCreds(&credentials{URL: srv.URL, Realm: "main", Audience: "admin", AccessToken: "at", RefreshToken: "rt", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	set := func(code int, v any) {
		mu.Lock()
		defer mu.Unlock()
		status, answer = code, v
	}
	requested := func() []url.Values {
		mu.Lock()
		defer mu.Unlock()
		return append([]url.Values{}, reconciliations...)
	}
	run := func(extra ...string) (*migrate.Report, error) {
		t.Helper()
		err := migrateFrom(append([]string{"keycloak", "--input", keycloakFixture, "--import-totp", "--report", report, "--batch-size", "5"}, extra...))
		var r migrate.Report
		if jerr := json.Unmarshal(mustRead(t, report), &r); jerr != nil || r.Import == nil {
			t.Fatalf("report: %v", jerr)
		}
		return &r, err
	}

	// A dry run does not reconcile.
	if _, err := run(); err != nil || len(requested()) != 0 {
		t.Fatalf("dry run: %v, %d reconciliations", err, len(requested()))
	}

	set(http.StatusOK, map[string]any{"source_system": "keycloak-demo", "users": 12, "mismatches": []any{}, "reconciled": true})
	r, err := run("--apply")
	if err != nil {
		t.Fatalf("reconciled import: %v", err)
	}
	if len(requested()) != 1 {
		t.Fatalf("%d reconciliation requests", len(requested()))
	}
	q := requested()[0]
	if q.Get("source_system") != "keycloak-demo" || q.Get("expected_users") != "12" || q.Get("expected_totp_factors") != "1" ||
		q.Get("expected_memberships") == "" || q.Get("expected_password_verifiers") == "" {
		t.Fatalf("reconciliation query: %v", q)
	}
	if r.Import.Expected["users"] != 12 || r.Import.Reconciliation["reconciled"] != true || len(r.Import.Jobs) != 3 {
		t.Fatalf("report import: %+v", r.Import)
	}

	// The realm differs from the export: the command fails, and the report
	// shows the mismatch.
	set(http.StatusOK, map[string]any{"users": 11, "mismatches": []any{map[string]any{"measure": "users", "expected": 12, "actual": 11}}, "reconciled": false})
	r, err = run("--apply")
	if !errors.Is(err, migrate.ErrNotReconciled) || !strings.Contains(err.Error(), "users expected 12, actual 11") {
		t.Fatalf("mismatch: %v", err)
	}
	if r.Import.Reconciliation["reconciled"] != false {
		t.Fatalf("report after a mismatch: %+v", r.Import.Reconciliation)
	}

	// The reconciliation request fails: the command fails too.
	set(http.StatusForbidden, map[string]any{"status": 403, "title": "Forbidden", "detail": "missing permission realm.users.import"})
	r, err = run("--apply")
	if err == nil || errors.Is(err, migrate.ErrNotReconciled) || !strings.Contains(err.Error(), "reconciliation: HTTP 403") {
		t.Fatalf("failed reconciliation: %v", err)
	}
	if r.Import.Reconciliation != nil || r.Import.Expected["users"] != 12 {
		t.Fatalf("report after a failed reconciliation: %+v", r.Import)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
