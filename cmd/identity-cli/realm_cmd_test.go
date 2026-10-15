package main

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/testutil"
)

// TestRealmCreateIfMissing: the unattended Compose setup runs
// `realm-create -if-missing` on every start, configured by environment
// variables alone. Repeating it keeps the existing realm and its issuer;
// without the flag a duplicate realm is still an error.
func TestRealmCreateIfMissing(t *testing.T) {
	db := testutil.NewDB(t)
	t.Setenv("PROUDAUTH_CONFIG", "")
	t.Setenv("PROUDAUTH_MODE", "development")
	t.Setenv("PROUDAUTH_PUBLIC_ORIGIN", "http://localhost:8080")
	t.Setenv("PROUDAUTH_DATABASE_URL", db.Pool.Config().ConnString())
	t.Setenv("PROUDAUTH_ROOT_KEY", hex.EncodeToString(secret.Random(32)))
	t.Setenv("PROUDAUTH_EMAIL_ADAPTER", "dev_sink")
	create := commands["realm-create"].run

	if err := create([]string{"-if-missing"}); err != nil {
		t.Fatalf("first unattended run: %v", err)
	}
	app, env, err := localApp("")
	if err != nil {
		t.Fatal(err)
	}
	first, err := app.Realms.ByName(context.Background(), "main")
	env.DB.Close()
	if err != nil {
		t.Fatalf("default realm not created: %v", err)
	}

	if err := create([]string{"-if-missing"}); err != nil {
		t.Fatalf("repeated unattended run must succeed: %v", err)
	}
	app, env, err = localApp("")
	if err != nil {
		t.Fatal(err)
	}
	again, err := app.Realms.ByName(context.Background(), "main")
	env.DB.Close()
	if err != nil || again.ID != first.ID || again.Issuer != first.Issuer {
		t.Fatalf("existing realm changed: %+v -> %+v (%v)", first, again, err)
	}

	if err := create(nil); err == nil {
		t.Fatal("realm-create without -if-missing must refuse an existing realm")
	}
}
