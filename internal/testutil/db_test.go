package testutil

import (
	"context"
	"testing"
)

// TestNewDBClonesTheTemplate: two databases from NewDB both carry the whole
// migration set without replaying it, the template they came from exists under
// the digest of the embedded migrations, and NewDB's databases are migrated
// to the current schema.
func TestNewDBClonesTheTemplate(t *testing.T) {
	adminURL := DatabaseURL(t)
	ctx := context.Background()
	a := NewDB(t)
	b := NewDB(t)
	for _, db := range []interface {
		SchemaCurrent(context.Context) (bool, error)
	}{a, b} {
		ok, err := db.SchemaCurrent(ctx)
		if err != nil || !ok {
			t.Fatalf("cloned database is not at the current schema: %v %v", ok, err)
		}
	}
	ran, err := a.Migrate(ctx)
	if err != nil || len(ran) != 0 {
		t.Fatalf("a cloned database still had migrations to run: %v %v", ran, err)
	}
	digest, err := migrationDigest()
	if err != nil {
		t.Fatal(err)
	}
	tpl, err := ensureTemplate(ctx, adminURL)
	if err != nil || tpl != "pa_tpl_"+digest[:16] {
		t.Fatalf("template %q, %v; want pa_tpl_%s", tpl, err, digest[:16])
	}
	var exists bool
	if err := a.Pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", tpl).Scan(&exists); err != nil || !exists {
		t.Fatalf("template database %s missing: %v", tpl, err)
	}
}

func TestRequireDB(t *testing.T) {
	t.Setenv("PROUDAUTH_TEST_REQUIRE_DB", "")
	for _, c := range []struct {
		ci   string
		want bool
	}{{"", false}, {"false", false}, {"0", false}, {"true", true}, {"1", true}} {
		t.Setenv("CI", c.ci)
		if got := RequireDB(); got != c.want {
			t.Errorf("CI=%q: RequireDB() = %v, want %v", c.ci, got, c.want)
		}
	}
	t.Setenv("CI", "")
	t.Setenv("PROUDAUTH_TEST_REQUIRE_DB", "1")
	if !RequireDB() {
		t.Error("PROUDAUTH_TEST_REQUIRE_DB=1 must require a database")
	}
}
