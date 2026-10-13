package storage

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestRuntimeRoleSeparation covers OPS-013: a runtime role granted by
// GrantRuntime can read and write data but cannot change the schema, and
// CurrentRole reports a role's powers.
func TestRuntimeRoleSeparation(t *testing.T) {
	url := os.Getenv("PROUDAUTH_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("PROUDAUTH_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := Open(ctx, url, Options{MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.GrantRuntime(ctx, "Bad;Role"); err == nil {
		t.Fatal("invalid role name accepted")
	}
	_, _ = db.Pool.Exec(ctx, `DROP ROLE IF EXISTS proudauth_rt_test`)
	if _, err := db.Pool.Exec(ctx, `CREATE ROLE proudauth_rt_test`); err != nil {
		t.Skipf("cannot create roles here: %v", err)
	}
	defer func() {
		_, _ = db.Pool.Exec(ctx, `DROP OWNED BY proudauth_rt_test`)
		_, _ = db.Pool.Exec(ctx, `DROP ROLE IF EXISTS proudauth_rt_test`)
	}()
	if err := db.GrantRuntime(ctx, "proudauth_rt_test"); err != nil {
		t.Fatal(err)
	}
	// Neither directly nor through PUBLIC (the PostgreSQL 14 and earlier
	// default) can the runtime role create objects in public.
	var canCreate bool
	if err := db.Pool.QueryRow(ctx, `SELECT has_schema_privilege('proudauth_rt_test', 'public', 'CREATE')`).Scan(&canCreate); err != nil || canCreate {
		t.Fatalf("runtime role can create in public: %v %v", canCreate, err)
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE proudauth_rt_test`); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM realms`).Scan(&n); err != nil {
		t.Fatalf("runtime role cannot read: %v", err)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT ddl`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE realms ADD COLUMN pwned int`); err == nil {
		t.Fatal("runtime role can change the schema")
	}
	_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT ddl`)
	// The runtime role cannot delete audit evidence, not even with the
	// retention flag set (AUD-007).
	if _, err := tx.Exec(ctx, `SAVEPOINT audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL proudauth.audit_retention = 'on'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE true`); err == nil {
		t.Fatal("runtime role deleted audit events")
	}
	_, _ = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT audit`)
	rep, err := db.CurrentRole(ctx)
	if err != nil || rep.Role == "" {
		t.Fatalf("role report: %+v %v", rep, err)
	}
	// A migration plan is read-only, so it works with the runtime role.
	sep := "?"
	if strings.Contains(url, "?") {
		sep = "&"
	}
	rt, err := Open(ctx, url+sep+"options="+"-c%20role%3Dproudauth_rt_test", Options{MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if _, _, err := rt.MigrateWith(ctx, MigrateOptions{Plan: true}); err != nil {
		t.Fatalf("plan as the runtime role: %v", err)
	}
}
