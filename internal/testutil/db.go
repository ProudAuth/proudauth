// Package testutil provisions isolated PostgreSQL databases for integration tests.
//
// Tests use PROUDAUTH_TEST_DATABASE_URL (a role allowed to CREATE DATABASE). When it
// is unset the integration tests are skipped, never faked with an in-memory store,
// because transactional invariants must be proven on the real database (§33.1).
package testutil

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/storage"
)

var counter atomic.Int64

// DatabaseURL returns the admin URL or skips the test.
func DatabaseURL(t testing.TB) string {
	u := os.Getenv("PROUDAUTH_TEST_DATABASE_URL")
	if u == "" {
		t.Skip("PROUDAUTH_TEST_DATABASE_URL not set; skipping database integration test")
	}
	return u
}

// NewDB creates a fresh, migrated database and drops it when the test ends.
func NewDB(t testing.TB) *storage.DB {
	t.Helper()
	adminURL := DatabaseURL(t)
	ctx := context.Background()
	name := fmt.Sprintf("pa_test_%d_%d", time.Now().UnixNano()%1_000_000_000, counter.Add(1))
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close(ctx)
		t.Fatalf("create database: %v", err)
	}
	admin.Close(ctx)

	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := storage.Open(ctx, u.String(), storage.Options{MaxConns: 20})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		if os.Getenv("PROUDAUTH_TEST_KEEP_DB") != "" {
			return
		}
		c, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})
	return db
}

// DSNFor returns the URL of a named database on the admin server.
func DSNFor(adminURL, name string) string {
	u, _ := url.Parse(adminURL)
	u.Path = "/" + strings.TrimPrefix(name, "/")
	return u.String()
}
