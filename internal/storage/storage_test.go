package storage_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
	"github.com/proudauth/proudauth/migrations"
)

func TestMigrationsApplyAndAreIdempotent(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	ran, err := db.Migrate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ran) != 0 {
		t.Fatalf("second migrate must be a no-op, ran %v", ran)
	}
	ok, err := db.SchemaCurrent(ctx)
	if err != nil || !ok {
		t.Fatalf("schema current: %v %v", ok, err)
	}
}

func TestAuditEventsAreAppendOnly(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	_, err := db.Pool.Exec(ctx, `INSERT INTO audit_events (id, type, occurred_at, actor_type, actor_id, outcome, content_hash)
		VALUES ('evt_1', 'test', now(), 'system', 'system', 'success', 'h')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE audit_events SET outcome = 'failure' WHERE id = 'evt_1'`); err == nil {
		t.Fatal("audit update must be rejected (AUD-007)")
	}
	if _, err := db.Pool.Exec(ctx, `DELETE FROM audit_events WHERE id = 'evt_1'`); err == nil {
		t.Fatal("audit delete must be rejected (AUD-007)")
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE audit_events SET batch_id = 'aub_1' WHERE id = 'evt_1'`); err != nil {
		t.Fatalf("sealing must be allowed once: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `UPDATE audit_events SET batch_id = 'aub_2' WHERE id = 'evt_1'`); err == nil {
		t.Fatal("resealing must be rejected")
	}
}

// TestMixedVersionWindow covers TEST-061 and DEP-012 (the supported
// mixed-version window): an older binary keeps working while a
// newer release has applied only expand migrations, refuses to migrate a newer
// schema, and fails clearly once a contract migration has run.
func TestMixedVersionWindow(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	if _, err := db.Pool.Exec(ctx, `INSERT INTO schema_migrations (name, checksum, compat) VALUES ('9999_newer_expand.sql', 'x', 'expand')`); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.SchemaCurrent(ctx); err != nil || !ok {
		t.Fatalf("expand-only newer schema must stay compatible: %v %v", ok, err)
	}
	if _, err := db.Migrate(ctx); err == nil {
		t.Fatal("an older binary must not migrate a newer schema")
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO schema_migrations (name, checksum, compat) VALUES ('9999_newer_contract.sql', 'x', 'contract')`); err != nil {
		t.Fatal(err)
	}
	if ok, err := db.SchemaCurrent(ctx); ok || !errors.Is(err, storage.ErrSchemaIncompatible) {
		t.Fatalf("contract migration from a newer release must fail clearly: %v %v", ok, err)
	}
}

// TestMigrationSafetyGates covers OPS-008 and DEP-012 (contract changes are
// gated before they alter shared state): contract (destructive) migrations
// need a recorded backup reference, declared preconditions must hold, and a
// plan reports pending work without applying it.
func TestMigrationSafetyGates(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	src := fstest.MapFS{}
	entries, _ := fs.ReadDir(migrations.Files, ".")
	for _, e := range entries {
		b, _ := fs.ReadFile(migrations.Files, e.Name())
		src[e.Name()] = &fstest.MapFile{Data: b}
	}
	src["9990_contract_probe.sql"] = &fstest.MapFile{Data: []byte("-- proudauth:compat=contract\n" +
		"-- proudauth:precondition SELECT NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='contract_probe')\n" +
		"CREATE TABLE contract_probe (id int);\n")}
	restore := storage.SetMigrationFS(src)
	defer restore()

	_, plan, err := db.MigrateWith(ctx, storage.MigrateOptions{Plan: true})
	if err != nil || len(plan) != 1 || plan[0].Compat != "contract" || len(plan[0].Preconditions) != 1 || !plan[0].Preconditions[0].Held {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if _, err := db.Migrate(ctx); !errors.Is(err, storage.ErrBackupRequired) {
		t.Fatalf("contract migration ran without a backup reference: %v", err)
	}
	ran, _, err := db.MigrateWith(ctx, storage.MigrateOptions{BackupReference: "snap-2026-10-10"})
	if err != nil || len(ran) != 1 {
		t.Fatalf("migrate with backup: %v %v", ran, err)
	}
	var ref string
	_ = db.Pool.QueryRow(ctx, `SELECT backup_reference FROM schema_migrations WHERE name='9990_contract_probe.sql'`).Scan(&ref)
	if ref != "snap-2026-10-10" {
		t.Fatalf("backup reference not recorded: %q", ref)
	}
	src["9991_needs_condition.sql"] = &fstest.MapFile{Data: []byte("-- proudauth:precondition SELECT false\nCREATE TABLE never_created (id int);\n")}
	if _, err := db.Migrate(ctx); err == nil || !strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("failed precondition ignored: %v", err)
	}
}

// TestOutOfOrderMigrations covers OPS-008: a pending migration that sorts
// before the newest applied one (a backported fix, or a file merged after a
// later one shipped) is marked out of order in the plan and in the run's
// results, with the newest applied migration, so identity-cli migrate and
// the server warn about it. It still runs, in lexical order. A file with
// "-- proudauth:allow-out-of-order: <reason>" is not marked; a marker
// without a reason does not count.
func TestOutOfOrderMigrations(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	src := migrationSource(t)
	newest := ""
	for name := range src {
		newest = max(newest, name)
	}
	src["0050_backport.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE ooo_backport (id int);\n")}
	src["0051_reviewed.sql"] = &fstest.MapFile{Data: []byte("-- proudauth:allow-out-of-order: creates a table no later migration touches\nCREATE TABLE ooo_reviewed (id int);\n")}
	src["0052_no_reason.sql"] = &fstest.MapFile{Data: []byte("-- proudauth:allow-out-of-order:\nCREATE TABLE ooo_no_reason (id int);\n")}
	src["9990_next.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE ooo_next (id int);\n")}
	want := []string{"0050_backport.sql out-of-order", "0051_reviewed.sql", "0052_no_reason.sql out-of-order", "9990_next.sql"}
	marks := func(items []storage.MigrationPlanItem) []string {
		var out []string
		for _, m := range items {
			switch {
			case m.OutOfOrder && m.NewestApplied == newest:
				out = append(out, m.Name+" out-of-order")
			case !m.OutOfOrder && m.NewestApplied == "":
				out = append(out, m.Name)
			default:
				out = append(out, fmt.Sprintf("%s %v %q", m.Name, m.OutOfOrder, m.NewestApplied))
			}
		}
		return out
	}
	_, plan, err := db.MigrateWith(ctx, storage.MigrateOptions{Plan: true})
	if err != nil || !slices.Equal(marks(plan), want) {
		t.Fatalf("plan %v (newest applied %s): %v", marks(plan), newest, err)
	}
	ran, applied, err := db.MigrateWith(ctx, storage.MigrateOptions{})
	if err != nil || !slices.Equal(marks(applied), want) || len(ran) != 4 || ran[0] != "0050_backport.sql" {
		t.Fatalf("run %v, applied %v: %v", ran, marks(applied), err)
	}
	for _, m := range want {
		if n := recorded(t, db, strings.Fields(m)[0]); n != 1 {
			t.Fatalf("%s recorded %d times", m, n)
		}
	}
	if ran, applied, err := db.MigrateWith(ctx, storage.MigrateOptions{}); err != nil || len(ran) != 0 || len(applied) != 0 {
		t.Fatalf("second run: %v %v %v", ran, applied, err)
	}
}

// TestAssignmentRealmBoundary covers DB-001: the database itself refuses role
// assignments whose subject or scope lives in another realm.
func TestAssignmentRealmBoundary(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) error {
		_, err := db.Pool.Exec(ctx, sql, args...)
		return err
	}
	for _, r := range []string{"rlm_a", "rlm_b"} {
		if err := exec(`INSERT INTO realms (id, name, display_name, issuer) VALUES ($1, $1, $1, 'https://id.test/'||$1)`, r); err != nil {
			t.Fatal(err)
		}
		if err := exec(`INSERT INTO users (id, realm_id) VALUES ('usr_'||$1, $1)`, r); err != nil {
			t.Fatal(err)
		}
		if err := exec(`INSERT INTO roles (id, realm_id, boundary_type, name) VALUES ('rol_'||$1, $1, 'realm', 'r')`, r); err != nil {
			t.Fatal(err)
		}
	}
	assign := func(id, realm, role, subject, scope string) error {
		return exec(`INSERT INTO role_assignments (id, realm_id, role_id, subject_type, subject_id, scope_type, scope_id)
			VALUES ($1,$2,$3,'user',$4,'realm',$5)`, id, realm, role, subject, scope)
	}
	if err := assign("ras_ok", "rlm_a", "rol_rlm_a", "usr_rlm_a", "rlm_a"); err != nil {
		t.Fatalf("same-realm assignment rejected: %v", err)
	}
	if err := assign("ras_x1", "rlm_a", "rol_rlm_a", "usr_rlm_b", "rlm_a"); err == nil {
		t.Fatal("assignment to a user of another realm accepted")
	}
	if err := assign("ras_x2", "rlm_a", "rol_rlm_a", "usr_rlm_a", "rlm_b"); err == nil {
		t.Fatal("assignment scoped to another realm accepted")
	}
}
