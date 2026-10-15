package storage_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
)

// race runs fn for each of n contenders at the same time, each in its own
// transaction, and returns how many committed.
func race(t *testing.T, db *storage.DB, n int, fn func(tx pgx.Tx, i int) error) int {
	t.Helper()
	ctx := context.Background()
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tx, err := db.Pool.Begin(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			if err := fn(tx, i); err != nil {
				_ = tx.Rollback(ctx)
				errs[i] = err
				return
			}
			errs[i] = tx.Commit(ctx)
		}(i)
	}
	close(start)
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !storage.IsUniqueViolation(err) {
			t.Fatalf("contender failed for another reason: %v", err)
		}
	}
	return ok
}

func seed(t *testing.T, db *storage.DB, stmts ...string) {
	t.Helper()
	for _, s := range stmts {
		if _, err := db.Pool.Exec(context.Background(), s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

func seedUsers(t *testing.T, db *storage.DB, n int) {
	t.Helper()
	seed(t, db, `INSERT INTO realms (id, name, display_name, issuer) VALUES ('rlm_a', 'a', 'A', 'https://id.test/a')`)
	for i := 0; i < n; i++ {
		seed(t, db, fmt.Sprintf(`INSERT INTO users (id, realm_id) VALUES ('usr_%d', 'rlm_a')`, i))
	}
}

// TestIdentifierUniqueness covers DB-002: a verified email and a username
// belong to at most one account of a realm, enforced by the database even
// when account creation and identifier changes race; unverified claims never
// block the address's real owner.
func TestIdentifierUniqueness(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	seedUsers(t, db, 8)
	add := func(tx pgx.Tx, id, user, typ, value string, verified bool) error {
		_, err := tx.Exec(ctx, `INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value, verified_at)
			VALUES ($1, 'rlm_a', $2, $3, $4, $4, CASE WHEN $5 THEN now() END)`, id, user, typ, value, verified)
		return err
	}
	if n := race(t, db, 8, func(tx pgx.Tx, i int) error {
		return add(tx, fmt.Sprintf("idf_u%d", i), fmt.Sprintf("usr_%d", i), "username", "racer", false)
	}); n != 1 {
		t.Fatalf("%d accounts committed the same username", n)
	}
	if n := race(t, db, 8, func(tx pgx.Tx, i int) error {
		return add(tx, fmt.Sprintf("idf_e%d", i), fmt.Sprintf("usr_%d", i), "email", "shared@example.test", true)
	}); n != 1 {
		t.Fatalf("%d accounts committed the same verified email", n)
	}
	// Several accounts may hold unverified claims on one address; when their
	// identifier changes (verifications) race, exactly one wins.
	var owner string
	if err := db.Pool.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE canonical_value='shared@example.test'`).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	var claimants []string
	for i := 0; i < 8; i++ {
		u := fmt.Sprintf("usr_%d", i)
		if u == owner {
			continue
		}
		if _, err := db.Pool.Exec(ctx, `INSERT INTO user_identifiers (id, realm_id, user_id, type, original_value, canonical_value)
			VALUES ($1, 'rlm_a', $2, 'email', 'other@example.test', 'other@example.test')`, "idf_c"+u, u); err != nil {
			t.Fatalf("unverified claim refused: %v", err)
		}
		claimants = append(claimants, "idf_c"+u)
	}
	// Fix each contender's row before the race. Selecting OFFSET i from the
	// shrinking unverified set could select no row after another commit and
	// count a successful no-op transaction as another verified account.
	if n := race(t, db, len(claimants), func(tx pgx.Tx, i int) error {
		tag, err := tx.Exec(ctx, `UPDATE user_identifiers SET verified_at=now() WHERE id=$1 AND verified_at IS NULL`, claimants[i])
		if err == nil && tag.RowsAffected() != 1 {
			return fmt.Errorf("verification affected %d rows, want 1", tag.RowsAffected())
		}
		return err
	}); n != 1 {
		t.Fatalf("%d accounts verified the same email concurrently", n)
	}
	var verified int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM user_identifiers WHERE realm_id='rlm_a' AND type='email'
		AND canonical_value='other@example.test' AND verified_at IS NOT NULL`).Scan(&verified); err != nil || verified != 1 {
		t.Fatalf("persisted verified accounts: %d, error %v", verified, err)
	}
}

// TestExternalIdentityUniqueness covers DB-003: one connection's validated
// upstream subject maps to at most one local user, even when two sign-ins
// race to link it.
func TestExternalIdentityUniqueness(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	seedUsers(t, db, 4)
	seed(t, db, `INSERT INTO identity_providers (id, realm_id, alias, display_name, kind, issuer) VALUES ('idp_1', 'rlm_a', 'corp', 'Corp', 'oidc', 'https://up.test')`,
		`INSERT INTO identity_providers (id, realm_id, alias, display_name, kind, issuer) VALUES ('idp_2', 'rlm_a', 'other', 'Other', 'oidc', 'https://up.test')`)
	link := func(tx pgx.Tx, id, user, provider, subject string) error {
		_, err := tx.Exec(ctx, `INSERT INTO external_identities (id, realm_id, user_id, provider_id, upstream_issuer, upstream_subject, linking_provenance)
			VALUES ($1, 'rlm_a', $2, $3, 'https://up.test', $4, 'jit')`, id, user, provider, subject)
		return err
	}
	if n := race(t, db, 4, func(tx pgx.Tx, i int) error {
		return link(tx, fmt.Sprintf("ext_%d", i), fmt.Sprintf("usr_%d", i), "idp_1", "upstream-42")
	}); n != 1 {
		t.Fatalf("one upstream subject linked to %d local users", n)
	}
	// The same subject at another connection is a different identity domain.
	if n := race(t, db, 1, func(tx pgx.Tx, _ int) error { return link(tx, "ext_other", "usr_3", "idp_2", "upstream-42") }); n != 1 {
		t.Fatal("subject of another connection refused")
	}
}

// TestSingleLiveMembership covers DB-004: concurrent invitation acceptance,
// administrator assignment and import cannot give one user two live
// memberships in an organization; a removed membership does not block a new
// one.
func TestSingleLiveMembership(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	seedUsers(t, db, 1)
	seed(t, db, `INSERT INTO organizations (id, realm_id, slug, display_name) VALUES ('org_1', 'rlm_a', 'acme', 'Acme')`)
	sources := []string{"invitation", "admin", "import", "directory", "self_join", "invitation"}
	join := func(tx pgx.Tx, id, state, source string) error {
		_, err := tx.Exec(ctx, `INSERT INTO memberships (id, realm_id, organization_id, user_id, state, source) VALUES ($1, 'rlm_a', 'org_1', 'usr_0', $2, $3)`,
			id, state, source)
		return err
	}
	if n := race(t, db, len(sources), func(tx pgx.Tx, i int) error {
		state := "active"
		if i%2 == 1 {
			state = "invited"
		}
		return join(tx, fmt.Sprintf("mem_%d", i), state, sources[i])
	}); n != 1 {
		t.Fatalf("%d live memberships for one user in one organization", n)
	}
	seed(t, db, `UPDATE memberships SET state='removed' WHERE organization_id='org_1'`)
	if n := race(t, db, 1, func(tx pgx.Tx, _ int) error { return join(tx, "mem_again", "active", "admin") }); n != 1 {
		t.Fatal("a removed membership blocks rejoining")
	}
}

// TestRefreshSingleSuccessor covers DB-006 at the storage layer: a refresh
// token generation has at most one successor, so two rotations racing on the
// same token cannot both commit, whichever generation they claim.
func TestRefreshSingleSuccessor(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	seedUsers(t, db, 1)
	seed(t, db,
		`INSERT INTO clients (id, realm_id, client_id, name, client_type, token_endpoint_auth_method, grant_types)
			VALUES ('cli_1', 'rlm_a', 'web', 'Web', 'confidential', 'client_secret_basic', '{authorization_code,refresh_token}')`,
		`INSERT INTO authorization_grants (id, realm_id, subject_type, subject_id, client_ref, expires_at)
			VALUES ('gnt_1', 'rlm_a', 'user', 'usr_0', 'cli_1', now() + interval '1 day')`,
		`INSERT INTO refresh_families (id, realm_id, grant_id, client_ref, idle_expires_at, absolute_expires_at)
			VALUES ('rff_1', 'rlm_a', 'gnt_1', 'cli_1', now() + interval '1 hour', now() + interval '1 day')`,
		`INSERT INTO refresh_tokens (id, realm_id, family_id, generation, token_digest) VALUES ('rft_1', 'rlm_a', 'rff_1', 1, 'digest-1')`)
	if n := race(t, db, 6, func(tx pgx.Tx, i int) error {
		_, err := tx.Exec(ctx, `INSERT INTO refresh_tokens (id, realm_id, family_id, generation, token_digest, parent_id) VALUES ($1, 'rlm_a', 'rff_1', $2, $3, 'rft_1')`,
			fmt.Sprintf("rft_child_%d", i), 2+i%2, fmt.Sprintf("digest-child-%d", i))
		return err
	}); n != 1 {
		t.Fatalf("one refresh generation got %d successors", n)
	}
}

// TestHotPathsUseIndexes covers DB-011: sign-in lookups, token and session
// lookups and the retention sweeps are served by indexes on their scope or
// expiry; with sequential scans priced out, none of them falls back to
// scanning the whole table.
func TestHotPathsUseIndexes(t *testing.T) {
	db := testutil.NewDB(t)
	ctx := context.Background()
	queries := map[string]string{
		"login identifier":       `SELECT user_id FROM user_identifiers WHERE realm_id='r' AND type='email' AND canonical_value='x'`,
		"identifiers of a user":  `SELECT id FROM user_identifiers WHERE user_id='u'`,
		"memberships of a user":  `SELECT id FROM memberships WHERE realm_id='r' AND user_id='u'`,
		"live membership":        `SELECT id FROM memberships WHERE organization_id='o' AND user_id='u' AND state='active'`,
		"refresh token":          `SELECT id FROM refresh_tokens WHERE token_digest='d'`,
		"opaque access token":    `SELECT id FROM opaque_access_tokens WHERE token_digest='d'`,
		"external identity":      `SELECT user_id FROM external_identities WHERE provider_id='p' AND upstream_issuer='i' AND upstream_subject='s'`,
		"verified domain route":  `SELECT organization_id FROM organization_domains WHERE realm_id='r' AND domain='d' AND state='verified'`,
		"transaction challenges": `SELECT id FROM challenges WHERE transaction_id='t' AND consumed_at IS NULL AND superseded_at IS NULL`,
		"pending outbox":         `SELECT seq FROM outbox_events WHERE state='pending' ORDER BY seq LIMIT 10`,
		"due notifications":      `SELECT id FROM notification_jobs WHERE state IN ('queued','attempted') AND next_attempt_at <= now()`,
		"code expiry sweep":      `DELETE FROM authorization_codes WHERE expires_at < now()`,
		"opaque token sweep":     `DELETE FROM opaque_access_tokens WHERE expires_at < now()`,
		"DPoP proof sweep":       `DELETE FROM dpop_proof_jtis WHERE expires_at < now()`,
		"PAR sweep":              `DELETE FROM pushed_authorization_requests WHERE expires_at < now()`,
		"device code sweep":      `DELETE FROM device_codes WHERE expires_at < now() AND state IN ('expired','consumed','denied','pending')`,
		"idempotency sweep":      `DELETE FROM idempotency_records WHERE expires_at < now()`,
		"outbox pruning":         `DELETE FROM outbox_events WHERE state='dispatched' AND dispatched_at < now()`,
		"payload purge":          `SELECT id FROM notification_jobs WHERE payload_ciphertext IS NOT NULL AND updated_at < now()`,
	}
	conn, err := db.Pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET enable_seqscan = off`); err != nil {
		t.Fatal(err)
	}
	for name, q := range queries {
		rows, err := conn.Query(ctx, "EXPLAIN "+q)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var plan []string
		for rows.Next() {
			var line string
			_ = rows.Scan(&line)
			plan = append(plan, line)
		}
		rows.Close()
		if p := strings.Join(plan, "\n"); strings.Contains(p, "Seq Scan") || !strings.Contains(p, "Index") {
			t.Errorf("%s scans the table:\n%s", name, p)
		}
	}
}
