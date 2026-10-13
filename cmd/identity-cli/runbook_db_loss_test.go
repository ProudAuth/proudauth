package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/testutil"
	"github.com/proudbase/proudauth/internal/token"
)

// runbookCLI runs an identity-cli command as an operator would and returns
// what it printed on standard output.
func runbookCLI(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmd, ok := commands[name]
	if !ok {
		t.Fatalf("identity-cli has no command %q", name)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	runErr := cmd.run(args)
	os.Stdout = stdout
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return string(out), runErr
}

func runbookFingerprint(t *testing.T, doctor string) string {
	t.Helper()
	for _, line := range strings.Split(doctor, "\n") {
		if fp, ok := strings.CutPrefix(line, "key hierarchy fingerprint: "); ok {
			return strings.TrimSpace(fp)
		}
	}
	t.Fatalf("doctor printed no fingerprint:\n%s", doctor)
	return ""
}

// runbookConfig writes an operator configuration for a database.
func runbookConfig(t *testing.T, dir, name, dsn, keyFile string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	cfg := fmt.Sprintf(`mode: development
server:
  public_origin: "http://localhost:8080"
storage:
  database_url: %q
keys:
  root_keys:
    - version: 1
      ref: "file:%s"
  active_version: 1
delivery:
  email:
    adapter: dev_sink
`, dsn, keyFile)
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestDatabaseLossRunbookCommands covers OPS-016 (and OPS-005, OPS-006) for
// the "Database loss" runbook in docs/operations/incidents.md with the
// restore procedure of docs/operations/backup-restore.md, by running the
// identity-cli commands themselves: revocation-log exports what changed after
// the backup (a suspension and a compromised signing key); on the restored
// copy, maintenance -mode unavailable, doctor (same fingerprint as recorded
// for the backup), migrate (schema current), restore-begin, the ordering rule
// for a compromised active key (an emergency rotation before reconciling),
// restore-reconcile -log (marker cleared, changes re-applied), doctor and
// verify-audit, and maintenance -mode off. The synthetic sign-in and
// introspection of the verification step are covered by TestRestoreDrill
// (tests/e2e), which starts an instance on a reconciled copy.
func TestDatabaseLossRunbookCommands(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "root_key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(secret.Random(32))), 0o600); err != nil {
		t.Fatal(err)
	}
	prodCfg := runbookConfig(t, dir, "prod.yaml", db.Pool.Config().ConnString(), keyFile)

	// Production: a realm, its administrator and an ordinary account.
	app, env, err := localApp(prodCfg)
	if err != nil {
		t.Fatal(err)
	}
	rlm, err := app.Provision.CreateRealm(ctx, "main", "Main", realm.DefaultPolicy(), audit.Ref{Type: "operator", ID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Provision.BootstrapAdmin(ctx, "main", "admin@example.test", "root-admin", time.Hour, false, "tester"); err != nil {
		t.Fatal(err)
	}
	user, err := app.Provision.BootstrapAdmin(ctx, "main", "ops@example.test", "ops-admin", time.Hour, true, "tester")
	if err != nil {
		t.Fatal(err)
	}
	activeBefore, err := app.KeyMgr.Active(ctx, rlm.ID)
	if err != nil {
		t.Fatal(err)
	}
	env.DB.Close()
	doctor, err := runbookCLI(t, "doctor", "-config", prodCfg)
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, doctor)
	}
	recorded := runbookFingerprint(t, doctor) // recorded with the backup

	// The backup (a physical copy) and its point in time.
	var dbName string
	if err := db.Pool.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}
	adminURL := testutil.DatabaseURL(t)
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	backupName := dbName + "_bak"
	var cerr error
	for i := 0; i < 40; i++ {
		db.Pool.Reset()
		if _, cerr = admin.Exec(ctx, "CREATE DATABASE "+backupName+" TEMPLATE "+dbName); cerr == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if cerr != nil {
		t.Fatalf("backup: %v", cerr)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+backupName+" WITH (FORCE)") })
	backupAt := time.Now().UTC().Add(-time.Second)

	// After the backup: an account is suspended and the signing key is
	// rotated as compromised. The revocation log is exported regularly.
	app, env, err = localApp(prodCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.Users.SetState(ctx, rlm.ID, user.UserID, "suspended", audit.Ref{Type: "operator", ID: "test"}, "INC-12"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.KeyMgr.Rotate(ctx, rlm.ID, "RS256", token.RotationEmergency, audit.System, "INC-12 key exposure"); err != nil {
		t.Fatal(err)
	}
	env.DB.Close()
	logFile := filepath.Join(dir, "revocations.jsonl")
	if out, err := runbookCLI(t, "revocation-log", "-config", prodCfg, "-since", backupAt.Format(time.RFC3339), "-out", logFile); err != nil {
		t.Fatalf("revocation-log: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"key_compromised"`)) || !bytes.Contains(raw, []byte(`"user_state"`)) {
		t.Fatalf("revocation log misses the changes after the backup:\n%s", raw)
	}
	if st, _ := os.Stat(logFile); st.Mode().Perm() != 0o600 {
		t.Fatalf("revocation log mode %v", st.Mode().Perm())
	}

	// The database is lost; the backup is restored with the same keys.
	restored := runbookConfig(t, dir, "restored.yaml", testutil.DSNFor(adminURL, backupName), keyFile)
	bak, err := storage.Open(ctx, testutil.DSNFor(adminURL, backupName), storage.Options{MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer bak.Close()
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := bak.Pool.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Step 1: maintenance.
	out, err := runbookCLI(t, "maintenance", "-config", restored, "-mode", "unavailable", "-message", "Restoring after a database failure")
	if err != nil || !strings.Contains(out, `"unavailable"`) {
		t.Fatalf("maintenance unavailable: %v\n%s", err, out)
	}
	// Step 2: doctor with the same keys, migrate, mark the database.
	doctor, err = runbookCLI(t, "doctor", "-config", restored)
	if err != nil {
		t.Fatalf("doctor on the restored database: %v\n%s", err, doctor)
	}
	if fp := runbookFingerprint(t, doctor); fp != recorded {
		t.Fatalf("fingerprint %s differs from the one recorded for the backup (%s)", fp, recorded)
	}
	if out, err := runbookCLI(t, "migrate", "-config", restored); err != nil || !strings.Contains(out, "schema is current") {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	if out, err := runbookCLI(t, "restore-begin", "-config", restored); err != nil || !strings.Contains(out, `"restore_pending": true`) {
		t.Fatalf("restore-begin: %v\n%s", err, out)
	}
	if count(`SELECT count(*) FROM users WHERE id=$1 AND state='suspended'`, user.UserID) != 0 {
		t.Fatal("precondition: the backup predates the suspension")
	}
	// Ordering rule: the log compromises the key that is active in the
	// restored database, so an emergency rotation comes first (stand-in for
	// POST /signing-key-rotations on an isolated instance).
	rapp, renv, err := localApp(restored)
	if err != nil {
		t.Fatal(err)
	}
	if k, err := rapp.KeyMgr.Active(ctx, rlm.ID); err != nil || k.KID != activeBefore.KID {
		t.Fatalf("precondition: the compromised key is active in the backup: %v", err)
	}
	if _, err := rapp.KeyMgr.Rotate(ctx, rlm.ID, "RS256", token.RotationEmergency, audit.System, "INC-12 restore ordering rule"); err != nil {
		t.Fatal(err)
	}
	renv.DB.Close()
	// Reconcile with the collected log.
	out, err = runbookCLI(t, "restore-reconcile", "-config", restored, "-log", logFile)
	if err != nil {
		t.Fatalf("restore-reconcile: %v\n%s", err, out)
	}
	var rep struct {
		Applied              map[string]int `json:"applied"`
		RestoreMarkerCleared bool           `json:"restore_marker_cleared"`
	}
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&rep); err != nil || !rep.RestoreMarkerCleared || rep.Applied["key_compromised"] == 0 || rep.Applied["user_state"] == 0 {
		t.Fatalf("reconciliation report: %v\n%s", err, out)
	}
	if count(`SELECT count(*) FROM users WHERE id=$1 AND state='suspended'`, user.UserID) != 1 {
		t.Fatal("suspension after the backup not re-applied")
	}
	if count(`SELECT count(*) FROM signing_keys WHERE kid=$1 AND state='compromised'`, activeBefore.KID) != 1 ||
		count(`SELECT count(*) FROM signing_keys WHERE realm_id=$1 AND state='active'`, rlm.ID) != 1 {
		t.Fatal("compromised key not re-applied, or no active signing key left")
	}
	// Step 4: verify, then end maintenance.
	if out, err := runbookCLI(t, "doctor", "-config", restored); err != nil || !strings.Contains(out, "signing key ok") {
		t.Fatalf("doctor after reconciliation: %v\n%s", err, out)
	}
	if out, err := runbookCLI(t, "verify-audit", "-config", restored); err != nil {
		t.Fatalf("verify-audit: %v\n%s", err, out)
	}
	if out, err := runbookCLI(t, "maintenance", "-config", restored, "-mode", "off"); err != nil || !strings.Contains(out, `"off"`) {
		t.Fatalf("maintenance off: %v\n%s", err, out)
	}
	for _, typ := range []string{"operations.maintenance.changed", "operations.restore.begun", "operations.restore.reconciled"} {
		if count(`SELECT count(*) FROM audit_events WHERE type=$1`, typ) == 0 {
			t.Fatalf("%s not audited on the restored database", typ)
		}
	}
}
