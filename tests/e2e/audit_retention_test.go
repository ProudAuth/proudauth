package e2e

import (
	"context"
	"fmt"
	"github.com/proudauth/proudauth/internal/worker"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
)

// TestAuditSignaturesAndRetention covers AUD-008 (signed, hash-linked batches
// that independent verifiers can check) and AUD-009 (retention that does not
// make the chain unverifiable).
func TestAuditSignaturesAndRetention(t *testing.T) {
	f := NewFixture(t)
	ctx := context.Background()
	db := f.H.App.D.DB
	kr := f.H.App.D.Keys
	time.Sleep(2100 * time.Millisecond) // sealing only takes events older than 2s
	if _, err := audit.SealBatch(ctx, db, 100000, audit.BatchSigner(kr)); err != nil {
		t.Fatal(err)
	}
	rep, err := audit.VerifyChainWith(ctx, db.Pool, audit.BatchVerifier(kr, true))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Signed == 0 {
		t.Fatalf("signed chain: %+v", rep)
	}
	// Retention prunes whole sealed batches and records it; verification stays green.
	err = db.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL proudauth.audit_retention = 'on'`); err != nil {
			return err
		}
		n, err := audit.PruneExpired(ctx, tx, audit.Retention{Default: time.Now().Add(time.Hour), Keep: []string{"emergency"}}, 100)
		if err == nil && n == 0 {
			t.Error("nothing pruned")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err = audit.VerifyChainWith(ctx, db.Pool, audit.BatchVerifier(kr, true))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Pruned == 0 {
		t.Fatalf("retention broke verification: %+v", rep)
	}
	// The prune ledger itself is append-only.
	if _, err := db.Pool.Exec(ctx, `DELETE FROM audit_prunes`); err == nil {
		t.Fatal("prune ledger is mutable")
	}
	// A forged signature (operator bypassing the guard) is detected.
	for _, sql := range []string{
		`ALTER TABLE audit_batches DISABLE TRIGGER audit_batches_append_only`,
		`UPDATE audit_batches SET signature='AAAA' WHERE sequence_number=1`,
		`ALTER TABLE audit_batches ENABLE TRIGGER audit_batches_append_only`,
	} {
		if _, err := db.Pool.Exec(ctx, sql); err != nil {
			t.Fatalf("prepare forged signature: %v", err)
		}
	}
	rep, err = audit.VerifyChainWith(ctx, db.Pool, audit.BatchVerifier(kr, true))
	if err != nil {
		t.Fatalf("verify forged signature: %v", err)
	}
	if rep.OK {
		t.Fatal("forged batch signature not detected")
	}
}

// TestAuditRetentionCategoriesAndHolds covers AUD-009: retention per category,
// legal holds that keep matching evidence, later passes recorded in the prune
// ledger, and a chain that still verifies.
func TestAuditRetentionCategoriesAndHolds(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "bob evidence")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["carol"]+"/suspend", map[string]any{"reason": "routine"}), 200, "carol evidence")
	hold := f.must(f.AdminAPI("POST", "/audit-legal-holds", map[string]any{"subject_id": f.Users["bob"], "reason": "litigation 2026-17"}), 201, "hold")
	mustStatus(t, f.AdminAPI("POST", "/audit-legal-holds", map[string]any{"reason": "x"}), 422, "hold without a reason")
	seal := func() {
		t.Helper()
		time.Sleep(2100 * time.Millisecond) // sealing only takes events older than 2s
		if _, err := audit.SealBatch(ctx, h.App.D.DB, 100000, audit.BatchSigner(h.App.D.Keys)); err != nil {
			t.Fatal(err)
		}
	}
	seal()
	prune := func(r audit.Retention) int {
		t.Helper()
		var n int
		err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL proudauth.audit_retention = 'on'`); err != nil {
				return err
			}
			var err error
			n, err = audit.PruneExpired(ctx, tx, r, 1000)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	count := func(subject string) int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE subject_id=$1 AND batch_id IS NOT NULL`, subject).Scan(&n)
		return n
	}
	future := time.Now().Add(24 * time.Hour)
	// Audit-administration evidence (the hold itself) is kept longer than the
	// default.
	prune(audit.Retention{Default: future, Categories: map[string]time.Time{"audit": time.Unix(0, 0)}, Keep: []string{"emergency"}})
	if count(f.Users["carol"]) != 0 {
		t.Fatal("expired evidence about carol survived retention")
	}
	if count(f.Users["bob"]) == 0 {
		t.Fatal("evidence under a legal hold was pruned")
	}
	var longer int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE category='audit' AND batch_id IS NOT NULL`).Scan(&longer)
	if longer == 0 {
		t.Fatal("a longer-retained category was pruned with the default")
	}
	mustStatus(t, f.AdminAPI("POST", "/audit-legal-holds/"+hold.Str("id")+"/release", nil), 204, "release")
	seal()
	prune(audit.Retention{Default: future, Keep: []string{"emergency", "audit"}})
	if count(f.Users["bob"]) != 0 {
		t.Fatal("released hold still keeps evidence")
	}
	var later int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_prune_log`).Scan(&later)
	if later == 0 {
		t.Fatal("second retention pass over pruned batches not recorded")
	}
	// AUD-009: an organization that keeps evidence longer keeps it past the
	// deployment's retention; other organizations' evidence goes.
	f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": f.CreateUser("dana")}), 201, "acme event")
	f.must(f.AdminAPI("POST", "/organizations/"+f.Globex+"/invitations", map[string]any{"email": "scope@example.test"}), 201, "globex event")
	seal()
	orgEvents := func(org string) int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE organization_id=$1 AND batch_id IS NOT NULL
			AND category NOT IN ('emergency','audit')`, org).Scan(&n)
		return n
	}
	prune(audit.Retention{Default: future, Keep: []string{"emergency", "audit"}, Orgs: map[string]time.Time{f.Acme: time.Now().AddDate(0, 0, -3650)}})
	if orgEvents(f.Acme) == 0 || orgEvents(f.Globex) != 0 {
		t.Fatalf("organization-scoped retention: acme %d globex %d", orgEvents(f.Acme), orgEvents(f.Globex))
	}
	// Imported history honours the same realm and organization overrides.
	f.must(f.AdminAPI("POST", "/audit-imports", map[string]any{"source_system": "legacy", "events": []map[string]any{
		{"source_event_id": "imp-acme", "occurred_at": time.Now().Add(-time.Hour), "type": "LOGIN", "organization": "acme"},
		{"source_event_id": "imp-globex", "occurred_at": time.Now().Add(-time.Hour), "type": "LOGIN", "organization": "globex"},
	}}), 200, "audit import")
	pruneImported := func(r audit.Retention) {
		t.Helper()
		if err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL proudauth.audit_retention = 'on'`); err != nil {
				return err
			}
			_, err := audit.PruneImported(ctx, tx, r, 1000)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	imported := func(id string) bool {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM imported_audit_events WHERE source_event_id=$1`, id).Scan(&n)
		return n > 0
	}
	decade := time.Now().AddDate(0, 0, -3650)
	pruneImported(audit.Retention{Default: future, Realms: map[string]time.Time{h.Realm.ID: decade}})
	if !imported("imp-acme") || !imported("imp-globex") {
		t.Fatal("realm-scoped retention ignored for imported history")
	}
	pruneImported(audit.Retention{Default: future, Orgs: map[string]time.Time{f.Acme: decade}})
	if !imported("imp-acme") || imported("imp-globex") {
		t.Fatalf("organization-scoped retention for imported history: acme %v globex %v", imported("imp-acme"), imported("imp-globex"))
	}
	rep, err := audit.VerifyChain(ctx, h.App.D.DB.Pool)
	if err != nil || !rep.OK {
		t.Fatalf("chain after category retention: %+v %v", rep, err)
	}
	// AUD-014: the scheduled check verifies recent batches and reports zero
	// problems; the backlog gauges are exported.
	if n, err := worker.New(h.App, "test").VerifyRecentAudit(ctx); err != nil || n == 0 {
		t.Fatalf("scheduled audit verification: %d %v", n, err)
	}
	var buf strings.Builder
	h.App.Metrics.Registry.WriteText(&buf)
	for _, m := range []string{"proudauth_audit_integrity_problems 0", "proudauth_audit_unsealed_events", "proudauth_jobs_failed_total"} {
		if !strings.Contains(buf.String(), m) {
			t.Fatalf("metric %q missing", m)
		}
	}
}

// TestAuditArchive covers AUD-008: sealed batches are written once to an
// independent archive that verifies without the database, and tampering with
// an archived file is detected.
func TestAuditArchive(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	dir := t.TempDir()
	time.Sleep(2100 * time.Millisecond)
	if _, err := audit.SealBatch(ctx, h.App.D.DB, 100000, audit.BatchSigner(h.App.D.Keys)); err != nil {
		t.Fatal(err)
	}
	n, err := audit.ArchiveBatches(ctx, h.App.D.DB, dir, 500)
	if err != nil || n == 0 {
		t.Fatalf("archive: %d %v", n, err)
	}
	if again, err := audit.ArchiveBatches(ctx, h.App.D.DB, dir, 500); err != nil || again != 0 {
		t.Fatalf("re-archiving: %d %v", again, err)
	}
	rep, err := audit.VerifyArchive(dir, audit.BatchVerifier(h.App.D.Keys, true))
	if err != nil || !rep.OK || rep.Signed == 0 || rep.Events == 0 {
		t.Fatalf("archive verification: %+v %v", rep, err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "batch-*.ndjson"))
	info, _ := os.Stat(files[0])
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("archived file is writable: %v", info.Mode())
	}
	_ = os.Chmod(files[0], 0o640)
	raw, _ := os.ReadFile(files[0])
	_ = os.WriteFile(files[0], []byte(strings.Replace(string(raw), `"outcome":"success"`, `"outcome":"failure"`, 1)), 0o640)
	if rep, _ := audit.VerifyArchive(dir, audit.BatchVerifier(h.App.D.Keys, true)); rep.OK {
		t.Fatal("tampered archive verified")
	}
	// Deleting an event line from a complete file is tampering, not pruning.
	_ = os.WriteFile(files[0], raw, 0o640)
	lines := strings.SplitAfter(string(raw), "\n")
	if len(lines) > 2 {
		_ = os.WriteFile(files[0], []byte(strings.Join(append(lines[:1], lines[2:]...), "")), 0o640)
		if rep, _ := audit.VerifyArchive(dir, nil); rep.OK || rep.Pruned != 0 {
			t.Fatalf("deleted event line verified: %+v", rep)
		}
	}
	_ = os.WriteFile(files[0], raw, 0o640)

	// Retention never removes evidence the archive does not hold yet.
	pruneAll := func(through int64) int {
		var n int
		err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL proudauth.audit_retention = 'on'`); err != nil {
				return err
			}
			var err error
			n, err = audit.PruneExpired(ctx, tx, audit.Retention{Default: time.Now().Add(time.Hour), Archiving: true, ArchivedThrough: through}, 1000)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Seal another batch that is not archived yet.
	f.must(f.AdminAPI("POST", "/users", map[string]any{"email": "late@example.test"}), 201, "new evidence")
	time.Sleep(2100 * time.Millisecond)
	if _, err := audit.SealBatch(ctx, h.App.D.DB, 100000, audit.BatchSigner(h.App.D.Keys)); err != nil {
		t.Fatal(err)
	}
	var archived, newest int64
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT last_sequence FROM audit_archive_state`).Scan(&archived)
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT max(sequence_number) FROM audit_batches`).Scan(&newest)
	if newest <= archived {
		t.Fatalf("expected an unarchived batch: archived %d newest %d", archived, newest)
	}
	if pruneAll(0) != 0 {
		t.Fatal("pruned with nothing archived")
	}
	// After a restore the database seals a different batch under a sequence
	// number the archive already holds: the archive forks instead of stopping.
	stale := filepath.Join(dir, fmt.Sprintf("batch-%012d.ndjson", newest))
	if err := os.WriteFile(stale, []byte(`{"record":"batch","sequence":`+fmt.Sprint(newest)+`}`+"\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	var forked []string
	if _, err := audit.ArchiveBatchesWith(ctx, h.App.D.DB, dir, 500, func(seq int64, sub string) { forked = append(forked, sub) }); err != nil {
		t.Fatalf("archive after a sequence collision: %v", err)
	}
	if len(forked) != 1 || !strings.HasPrefix(forked[0], fmt.Sprintf("fork-%012d-", newest)) {
		t.Fatalf("fork: %v", forked)
	}
	if _, err := os.Stat(filepath.Join(dir, forked[0], fmt.Sprintf("batch-%012d.ndjson", newest))); err != nil {
		t.Fatalf("forked batch not written: %v", err)
	}
	rep, _ = audit.VerifyArchive(dir, audit.BatchVerifier(h.App.D.Keys, true))
	if len(rep.Forks) != 1 || rep.LastSequence != newest {
		t.Fatalf("fork not verified: %+v", rep)
	}
	for _, p := range rep.Problems {
		if strings.HasPrefix(p, "fork-") {
			t.Fatalf("fork chain problem: %s", p)
		}
	}
	// Archived batches may now be pruned.
	if pruneAll(archived) == 0 {
		t.Fatal("archived batches not prunable")
	}
}
