// Package testutil provisions isolated PostgreSQL databases and fault-injecting
// network endpoints for integration tests.
//
// Tests use PROUDAUTH_TEST_DATABASE_URL (a role allowed to CREATE DATABASE). When it
// is unset the integration tests skip locally, never faked with an in-memory store,
// because transactional invariants must be proven on the real database (§33.1). In
// CI they fail instead, so a run cannot pass by skipping them (QA-001).
package testutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/migrations"
)

var counter atomic.Int64

// DatabaseURL returns the admin URL. Without it the test skips, except where
// RequireDB holds: there it fails, because database tests must run in CI, not
// skip (QA-001).
func DatabaseURL(t testing.TB) string {
	t.Helper()
	if u := os.Getenv("PROUDAUTH_TEST_DATABASE_URL"); u != "" {
		return u
	}
	if RequireDB() {
		t.Fatal("PROUDAUTH_TEST_DATABASE_URL is not set; database tests must run here, not skip")
	}
	t.Skip("PROUDAUTH_TEST_DATABASE_URL not set; skipping database integration test")
	return ""
}

// RequireDB reports whether a missing test database is a failure rather than a
// skip: under CI (set to anything but "false" or "0", as GitHub Actions does)
// or when PROUDAUTH_TEST_REQUIRE_DB is set.
func RequireDB() bool {
	if os.Getenv("PROUDAUTH_TEST_REQUIRE_DB") != "" {
		return true
	}
	ci := os.Getenv("CI")
	return ci != "" && ci != "false" && ci != "0"
}

// NewDB creates a fresh, migrated database and drops it when the test ends.
//
// The schema is cloned from a template database on the same server, migrated
// once per migration set: the template's name carries a digest of
// migrations/*.sql, so a changed migration builds a new template and the stale
// one is dropped. A test then pays one CREATE DATABASE ... TEMPLATE instead of
// replaying every migration. PROUDAUTH_TEST_NO_TEMPLATE=1 migrates each
// database directly, as the harness did before templates.
func NewDB(t testing.TB) *storage.DB {
	t.Helper()
	adminURL := DatabaseURL(t)
	ctx := context.Background()
	name := fmt.Sprintf("pa_test_%d_%d", time.Now().UnixNano()%1_000_000_000, counter.Add(1))
	useTemplate := os.Getenv("PROUDAUTH_TEST_NO_TEMPLATE") == ""
	if useTemplate {
		if err := cloneTemplate(ctx, adminURL, name); err != nil {
			t.Fatalf("create database from template: %v", err)
		}
	} else if err := createDatabase(ctx, adminURL, name, ""); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { dropDatabase(adminURL, name) })
	db, err := storage.Open(ctx, DSNFor(adminURL, name), storage.Options{MaxConns: 20})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	if !useTemplate {
		if _, err := db.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	return db
}

// DSNFor returns the URL of a named database on the admin server.
func DSNFor(adminURL, name string) string {
	u, _ := url.Parse(adminURL)
	u.Path = "/" + strings.TrimPrefix(name, "/")
	return u.String()
}

func dropDatabase(adminURL, name string) {
	if os.Getenv("PROUDAUTH_TEST_KEEP_DB") != "" {
		return
	}
	ctx := context.Background()
	c, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return
	}
	defer c.Close(ctx)
	_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
}

// createDatabase creates name, cloned from template when one is given. CREATE
// DATABASE refuses a template that still has a connection (SQLSTATE 55006),
// which happens for a moment after the template's own pool closed, so that
// case is retried.
func createDatabase(ctx context.Context, adminURL, name, template string) error {
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return fmt.Errorf("connect admin: %w", err)
	}
	defer admin.Close(ctx)
	stmt := "CREATE DATABASE " + name
	if template != "" {
		stmt += " TEMPLATE " + template
	}
	return retryInUse(ctx, func() error {
		_, err := admin.Exec(ctx, stmt)
		return err
	})
}

// retryInUse runs fn until it succeeds, fails for a reason other than
// "object in use", or has been retried for about five seconds.
func retryInUse(ctx context.Context, fn func() error) error {
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil || !isPgCode(err, "55006") || attempt >= 50 {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func isPgCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}

// templateFormat changes when the template's contents change for a reason
// other than the migration files themselves.
const templateFormat = "1"

// templateLockID serializes template builds across every test process on a
// server ("patmpl01" as a big-endian integer).
const templateLockID int64 = 0x7061746d706c3031

var (
	templateMu    sync.Mutex
	templateNames = map[string]string{} // admin URL -> template database name
	templateName  = regexp.MustCompile(`^pa_tpl_[0-9a-f]{16}$`)
)

// cloneTemplate creates name from the migration set's template, building the
// template first when this process has not seen it yet.
func cloneTemplate(ctx context.Context, adminURL, name string) error {
	for attempt := 0; attempt < 2; attempt++ {
		tpl, err := ensureTemplate(ctx, adminURL)
		if err != nil {
			return err
		}
		err = createDatabase(ctx, adminURL, name, tpl)
		if err == nil {
			return nil
		}
		// Another test process, with a different migration set, pruned our
		// template between two of our tests (SQLSTATE 3D000): build it again.
		if !isPgCode(err, "3D000") {
			return err
		}
		templateMu.Lock()
		delete(templateNames, adminURL)
		templateMu.Unlock()
	}
	return errors.New("the template database disappeared twice")
}

// ensureTemplate returns the name of the migrated template for the embedded
// migration set, building it when it does not exist on the server yet.
func ensureTemplate(ctx context.Context, adminURL string) (string, error) {
	templateMu.Lock()
	defer templateMu.Unlock()
	if n, ok := templateNames[adminURL]; ok {
		return n, nil
	}
	digest, err := migrationDigest()
	if err != nil {
		return "", err
	}
	name := "pa_tpl_" + digest[:16]
	admin, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		return "", fmt.Errorf("connect admin: %w", err)
	}
	defer admin.Close(ctx)
	// One builder at a time across every test process on this server.
	if _, err := admin.Exec(ctx, "SELECT pg_advisory_lock($1)", templateLockID); err != nil {
		return "", fmt.Errorf("template lock: %w", err)
	}
	defer func() { _, _ = admin.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", templateLockID) }()
	var exists bool
	if err := admin.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)", name).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		if err := buildTemplate(ctx, admin, adminURL, name, digest); err != nil {
			return "", err
		}
	}
	pruneTemplates(ctx, admin, name)
	templateNames[adminURL] = name
	return name, nil
}

// buildTemplate migrates a scratch database and renames it into place, so an
// interrupted build never leaves a half-migrated template under the final name.
func buildTemplate(ctx context.Context, admin *pgx.Conn, adminURL, name, digest string) error {
	scratch := name + "_build"
	if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)"); err != nil {
		return err
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+scratch); err != nil {
		return fmt.Errorf("create template: %w", err)
	}
	db, err := storage.Open(ctx, DSNFor(adminURL, scratch), storage.Options{MaxConns: 4})
	if err != nil {
		return fmt.Errorf("open template: %w", err)
	}
	_, err = db.Migrate(ctx)
	db.Close()
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
		return fmt.Errorf("migrate template: %w", err)
	}
	if err := retryInUse(ctx, func() error {
		_, err := admin.Exec(ctx, "ALTER DATABASE "+scratch+" RENAME TO "+name)
		return err
	}); err != nil {
		return fmt.Errorf("rename template: %w", err)
	}
	comment := "ProudAuth test template; migrations " + digest + "; built " + time.Now().UTC().Format(time.RFC3339)
	_, _ = admin.Exec(ctx, "COMMENT ON DATABASE "+name+" IS '"+strings.ReplaceAll(comment, "'", "''")+"'")
	return nil
}

// pruneTemplates drops the templates of other migration sets. A template that
// another process is cloning right now cannot be dropped and is left alone;
// a process whose template was pruned rebuilds it (cloneTemplate).
func pruneTemplates(ctx context.Context, admin *pgx.Conn, keep string) {
	rows, err := admin.Query(ctx, `SELECT datname FROM pg_database WHERE datname LIKE 'pa\_tpl\_%' AND datname <> $1`, keep)
	if err != nil {
		return
	}
	var stale []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil && templateName.MatchString(n) {
			stale = append(stale, n)
		}
	}
	rows.Close()
	for _, n := range stale {
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+n)
	}
}

// migrationDigest hashes the embedded migration files, names and contents, in
// name order.
func migrationDigest() (string, error) {
	entries, err := fs.ReadDir(migrations.Files, ".")
	if err != nil {
		return "", err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	h := sha256.New()
	fmt.Fprintf(h, "proudauth-test-template/%s\n", templateFormat)
	for _, n := range names {
		b, err := fs.ReadFile(migrations.Files, n)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\n%d\n", n, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
