package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/restore"
	"github.com/proudauth/proudauth/internal/testutil"
)

// TestRestoreBeginAndReconcileCommands covers TEST-060 and OPS-013 for the
// operator commands: restore-begin marks the database (audited as
// operations.restore.begun), -status only reads the marker, and
// restore-reconcile, here with an empty revocation log, clears it.
func TestRestoreBeginAndReconcileCommands(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "root_key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(secret.Random(32))), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
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
`, db.Pool.Config().ConnString(), keyFile)
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	pending := func() *restore.Marker {
		t.Helper()
		m, err := restore.Pending(ctx, db.Pool)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if pending() != nil {
		t.Fatal("a fresh database is marked as restored")
	}
	if err := restoreBegin([]string{"-config", cfgPath, "-status"}); err != nil || pending() != nil {
		t.Fatalf("-status set the marker: %v", err)
	}
	if err := restoreBegin([]string{"-config", cfgPath}); err != nil {
		t.Fatal(err)
	}
	m := pending()
	if m == nil || m.By != "local:"+operatorName() {
		t.Fatalf("marker after restore-begin: %+v", m)
	}
	var audited int
	_ = db.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='operations.restore.begun' AND actor_id=$1`, "local:"+operatorName()).Scan(&audited)
	if audited != 1 {
		t.Fatal("restore-begin not audited")
	}
	empty := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restoreReconcile([]string{"-config", cfgPath, "-log", empty}); err != nil {
		t.Fatal(err)
	}
	if pending() != nil {
		t.Fatal("restore-reconcile left the marker set")
	}
}
