package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/testutil"
)

// TestSupportBundleIsSanitized covers OPS-010: support-bundle writes a
// private (0600), audited file for the operator to review, with the version,
// the redacted configuration, schema state, realm and signing-key metadata
// and backlog health, and without secrets, key material or tokens.
func TestSupportBundleIsSanitized(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	dsn := db.Pool.Config().ConnString()
	dbPassword := ""
	if u, err := url.Parse(dsn); err == nil && u.User != nil {
		dbPassword, _ = u.User.Password()
	}
	rootKey := hex.EncodeToString(secret.Random(32))
	keyFile := filepath.Join(dir, "root_key")
	if err := os.WriteFile(keyFile, []byte(rootKey), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	cfg := fmt.Sprintf(`mode: development
server:
  public_origin: "http://localhost:8080"
  metrics_token: "literal-metrics-token"
storage:
  database_url: %q
  migration_database_url: "postgres://owner:migration-owner-secret@db.invalid/proudauth"
keys:
  root_keys:
    - version: 1
      ref: "file:%s"
  active_version: 1
delivery:
  email:
    adapter: dev_sink
    smtp_password: "literal-smtp-secret"
`, dsn, keyFile)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// A realm with a signing key and a bootstrap administrator whose one-time
	// setup token exists in the database.
	app, env, err := localApp(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Provision.CreateRealm(ctx, "main", "Main", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"}); err != nil {
		t.Fatal(err)
	}
	boot, err := app.Provision.BootstrapAdmin(ctx, "main", "admin@example.test", "root-admin", time.Hour, false, "tester")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := env.Keys.Fingerprint()
	env.DB.Close()

	out := filepath.Join(dir, "support-bundle.json")
	if err := supportBundle([]string{"-config", cfgPath, "-out", out}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("bundle must be private: %v %v", err, st)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Version       string           `json:"version"`
		GoVersion     string           `json:"go_version"`
		OS            string           `json:"os"`
		Configuration map[string]any   `json:"configuration"`
		Migrations    []map[string]any `json:"migrations"`
		Realms        []struct {
			Name        string           `json:"name"`
			SigningKeys []map[string]any `json:"signing_keys"`
		} `json:"realms"`
		RowCounts   map[string]int `json:"row_counts"`
		Backlogs    map[string]int `json:"backlogs"`
		Fingerprint string         `json:"key_hierarchy_fingerprint"`
		Notice      string         `json:"notice"`
	}
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	// Version and configuration summaries, schema and health.
	if b.Version != version || b.GoVersion == "" || b.OS == "" || len(b.Configuration) == 0 || len(b.Migrations) == 0 ||
		b.RowCounts == nil || b.Backlogs == nil || b.Fingerprint != fingerprint || !strings.Contains(b.Notice, "Review") {
		t.Fatalf("bundle summary incomplete: %s", raw)
	}
	if len(b.Realms) != 1 || b.Realms[0].Name != "main" || len(b.Realms[0].SigningKeys) == 0 || b.Realms[0].SigningKeys[0]["kid"] == "" {
		t.Fatalf("realm and signing-key metadata missing: %s", raw)
	}
	// Never secrets, key material, tokens or sessions.
	leaks := map[string]string{
		"root key": rootKey, "migration database password": "migration-owner-secret", "SMTP password": "literal-smtp-secret",
		"metrics token": "literal-metrics-token", "setup token": boot.SetupToken, "private key ciphertext": "private_ciphertext",
		"PEM key": "PRIVATE KEY", "private JWK": `"d":`,
	}
	if dbPassword != "" {
		leaks["database password"] = dbPassword
	}
	for what, s := range leaks {
		if strings.Contains(string(raw), s) {
			t.Errorf("support bundle contains the %s", what)
		}
	}
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='operations.support_bundle.generated'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("support bundle generation not audited: %d %v", n, err)
	}
}

// TestSupportBundleNeedsOut: the support bundle is written only to a location
// the operator names (DEP-004); without -out the command refuses before it
// connects or writes anything.
func TestSupportBundleNeedsOut(t *testing.T) {
	err := supportBundle([]string{"-config", filepath.Join(t.TempDir(), "missing.yaml")})
	if err == nil || !strings.Contains(err.Error(), "-out is required") {
		t.Fatalf("support-bundle without -out: %v", err)
	}
}
