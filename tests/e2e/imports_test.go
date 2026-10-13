package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/credential"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestImportAuthorityAndHashBounds covers MIG-005 (imports cannot grant beyond
// the requester's delegation ceiling), USR-005 (trusting upstream verification
// is an explicit override) and MIG-006 (imported verifier parameter ceilings).
func TestImportAuthorityAndHashBounds(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "importer",
		"permissions": []string{"realm.users.import", "realm.users.read", "realm.organizations.read"}}), 201, "importer role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	w := worker.New(h.App, "test")
	owner := []map[string]any{{"source_id": "o-1", "email": "own1@example.test", "memberships": []map[string]any{{"organization": "acme", "roles": []string{"owner"}}}}}

	if r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/user-imports", Token: carol, JSON: map[string]any{"source_system": "legacy", "users": owner,
		"trust_email_verification": true, "verification_reason": "upstream verified everything"}}); r.Status != 403 {
		t.Fatalf("trusting upstream verification without the override permission: %d", r.Status)
	}
	j := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/user-imports", Token: carol, JSON: map[string]any{"source_system": "legacy", "users": owner,
		"allow_owner_roles": true}})
	mustStatus(t, j, 202, "import")
	runWorker(t, w)
	res := f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
	item := res.Get("result.results").([]any)[0].(map[string]any)
	if item["status"] != "error" || !strings.Contains(item["error"].(string), "ceiling") {
		t.Fatalf("import granted an owner role beyond the requester's ceiling: %s", res.Raw)
	}

	huge := []map[string]any{{"source_id": "h-1", "email": "huge@example.test",
		"password_hash": "$argon2id$v=19$m=4194304,t=3,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"}}
	j = f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "legacy", "users": huge}), 202, "import")
	runWorker(t, w)
	res = f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
	if res.Get("result.results").([]any)[0].(map[string]any)["status"] != "error" {
		t.Fatalf("verifier with 4 GiB memory cost accepted: %s", res.Raw)
	}
}

// TestImportFactorsAndDeletionContinuity covers MIG-007 (TOTP seeds are
// imported only with explicit credential authority, re-encrypted and usable)
// and MIG-017 (an import never recreates an account deleted here).
func TestImportFactorsAndDeletionContinuity(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	seed := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	users := []map[string]any{{"source_id": "t-1", "email": "tina@example.test", "username": "tina", "totp_secret": seed}}
	run := func(body map[string]any) map[string]any {
		t.Helper()
		j := f.must(f.AdminAPI("POST", "/user-imports", body), 202, "import")
		runWorker(t, w)
		res := f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
		return res.Get("result.results").([]any)[0].(map[string]any)
	}
	if item := run(map[string]any{"source_system": "legacy", "users": users}); item["status"] != "error" {
		t.Fatalf("TOTP seed imported without authorization: %v", item)
	}
	item := run(map[string]any{"source_system": "legacy", "users": users, "import_totp": true})
	if item["status"] != "imported" {
		t.Fatalf("authorized TOTP import: %v", item)
	}
	tina := item["user_id"].(string)
	var ct []byte
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT secret_ciphertext FROM credentials WHERE user_id=$1 AND type='totp' AND state='active'`, tina).Scan(&ct)
	if len(ct) == 0 || strings.Contains(string(ct), seed) {
		t.Fatal("imported seed not stored encrypted")
	}
	code, _ := credential.TOTPCode(seed, credential.TOTPStep(h.Clock.Now()))
	var used bool
	err := h.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		_, used, err = h.App.Auth.VerifyTOTPTx(ctx, tx, tina, code)
		return err
	})
	if err != nil || !used {
		t.Fatalf("imported TOTP factor does not verify: %v %v", used, err)
	}
	// Deletion continuity: delete tina, then re-import the same source record
	// and a record with the same username under another source ID.
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+tina, nil), 204, "delete")
	if item := run(map[string]any{"source_system": "legacy", "users": []map[string]any{{"source_id": "t-1", "email": "tina2@example.test"}}}); item["status"] != "skipped_deleted" {
		t.Fatalf("deleted source record re-imported: %v", item)
	}
	if item := run(map[string]any{"source_system": "legacy", "users": []map[string]any{{"source_id": "t-9", "username": "tina"}}}); item["status"] != "skipped_deleted" {
		t.Fatalf("deleted username re-imported: %v", item)
	}
}

// TestMigrationPlanningAndReconciliation covers MIG-002 (declared import
// formats), MIG-003 (dry-run plan and conflicts), MIG-004 (matching
// identifiers never merge accounts), MIG-012 (reconciliation report) and
// MIG-016 (historical audit records stay apart from local evidence).
func TestMigrationPlanningAndReconciliation(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")

	formats := f.must(f.AdminAPI("GET", "/user-import-formats", nil), 200, "formats")
	if formats.Get("items").([]any)[0].(map[string]any)["format"] != "proudauth.user-import.v1" {
		t.Fatalf("formats: %s", formats.Raw)
	}
	users := []map[string]any{
		{"source_id": "m-1", "email": "mig1@example.test", "password_hash": "$legacy-sha256$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
			"memberships": []map[string]any{{"organization": "acme", "roles": []string{"member"}}}},
		{"source_id": "m-2", "email": "MIG1@example.test"},  // repeats m-1's email
		{"source_id": "m-3", "email": "alice@example.test"}, // belongs to an existing account
		{"source_id": "m-4", "email": "mig4@example.test", "memberships": []map[string]any{{"organization": "acme", "roles": []string{"owner"}}}},
	}
	f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"format": "keycloak.realm-export.v26", "source_system": "mig", "users": users}), 422, "unknown format")
	jobResult := func(body map[string]any) *Resp {
		t.Helper()
		j := f.must(f.AdminAPI("POST", "/user-imports", body), 202, "import")
		runWorker(t, w)
		return f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
	}
	dry := jobResult(map[string]any{"source_system": "mig", "users": users, "dry_run": true, "allow_owner_roles": true})
	results := dry.Get("result.results").([]any)
	status := func(i int) string { return results[i].(map[string]any)["status"].(string) }
	if status(0) != "valid" || status(1) != "conflict" || status(2) != "conflict" || status(3) != "valid" {
		t.Fatalf("dry run statuses: %s", dry.Raw)
	}
	plan := results[0].(map[string]any)["plan"].(map[string]any)
	mem := plan["memberships"].([]any)[0].(map[string]any)
	if plan["mapping"] != "mig/m-1" || plan["password_verifier"] != true || mem["privileged"] == true || mem["roles"].([]any)[0] != "member" {
		t.Fatalf("dry run plan: %v", plan)
	}
	if owner := results[3].(map[string]any)["plan"].(map[string]any)["memberships"].([]any)[0].(map[string]any); owner["privileged"] != true {
		t.Fatalf("owner role not reported as privileged: %v", owner)
	}
	totals := dry.Get("result.totals").(map[string]any)
	if totals["memberships"] != float64(2) || totals["privileged_memberships"] != float64(1) || totals["password_verifiers"] != float64(1) {
		t.Fatalf("dry run totals: %v", totals)
	}
	if !strings.Contains(results[2].(map[string]any)["error"].(string), "never merge") {
		t.Fatalf("existing-account conflict: %v", results[2])
	}

	real := jobResult(map[string]any{"source_system": "mig", "users": users, "allow_owner_roles": true})
	if c := real.Get("result.counts").(map[string]any); c["imported"] != float64(2) || c["conflict"] != float64(2) {
		t.Fatalf("import counts: %s", real.Raw)
	}
	rec := f.must(f.AdminAPI("GET", "/user-imports/reconciliation?source_system=mig&expected_users=2&expected_memberships=2&expected_privileged_assignments=1&expected_password_verifiers=1", nil), 200, "reconcile")
	if rec.Get("reconciled") != true || rec.Get("credentials.password_not_yet_rehashed") != float64(1) || rec.Get("credentials.without_sign_in_method") != float64(1) {
		t.Fatalf("reconciliation: %s", rec.Raw)
	}
	if item := rec.Get("privileged_assignments.items").([]any)[0].(map[string]any); item["source_id"] != "m-4" || item["role"] != "owner" {
		t.Fatalf("privileged assignment: %v", item)
	}
	rec = f.must(f.AdminAPI("GET", "/user-imports/reconciliation?source_system=mig&expected_users=3", nil), 200, "reconcile mismatch")
	if rec.Get("reconciled") != false || rec.Get("mismatches").([]any)[0].(map[string]any)["actual"] != float64(2) {
		t.Fatalf("mismatch not reported: %s", rec.Raw)
	}
	f.must(f.AdminAPI("GET", "/user-imports/reconciliation?source_system=never-imported", nil), 404, "unknown source")
	// A resumed job continues after its checkpoint and keeps the results
	// recorded before it (MIG-011).
	resumed := f.must(f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "mig-resume", "users": []map[string]any{
		{"source_id": "r-1", "email": "res1@example.test"}, {"source_id": "r-2", "email": "res2@example.test"}}}), 202, "resumable import")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE jobs SET checkpoint=$2 WHERE id=$1`, resumed.Str("job_id"),
		map[string]any{"next_index": 1, "counts": map[string]int{"imported": 1}, "results": []map[string]any{{"index": 0, "source_id": "r-1", "status": "imported", "user_id": "usr_before"}}}); err != nil {
		t.Fatal(err)
	}
	runWorker(t, w)
	rj := f.must(f.AdminAPI("GET", "/jobs/"+resumed.Str("job_id"), nil), 200, "resumed job")
	if rr := rj.Get("result.results").([]any); len(rr) != 2 || rr[0].(map[string]any)["user_id"] != "usr_before" || rj.Get("result.counts.imported") != float64(2) {
		t.Fatalf("resumed import lost earlier results: %s", rj.Raw)
	}
	// Only the owner grant is privileged: a member grant raises no alert signal.
	var memberSignal int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE type='role.assigned' AND metadata->>'role_name'='member'
		AND (metadata->>'privileged')::boolean`).Scan(&memberSignal)
	if memberSignal != 0 {
		t.Fatal("member grants are flagged privileged")
	}

	// Historical audit records (MIG-016).
	m1 := real.Get("result.results").([]any)[0].(map[string]any)["user_id"].(string)
	old := time.Date(2019, 3, 1, 12, 0, 0, 0, time.UTC)
	hist := []map[string]any{
		{"source_event_id": "ev-1", "occurred_at": old, "type": "LOGIN", "subject_source_id": "m-1", "outcome": "success",
			"actor": map[string]any{"type": "user", "id": "m-1", "display": "Mig One"}, "metadata": map[string]any{"ip": "198.51.100.7"}},
		{"source_event_id": "ev-2", "occurred_at": old.Add(time.Hour), "type": "UPDATE_PASSWORD", "subject_source_id": "unknown-user", "organization": "acme"},
		{"source_event_id": "ev-3", "occurred_at": time.Now().Add(48 * time.Hour), "type": "LOGIN"},
	}
	imp := f.must(f.AdminAPI("POST", "/audit-imports", map[string]any{"source_system": "mig", "events": hist}), 200, "audit import")
	if c := imp.Get("counts").(map[string]any); c["imported"] != float64(2) || c["error"] != float64(1) || imp.Str("batch_digest") == "" {
		t.Fatalf("audit import: %s", imp.Raw)
	}
	if again := f.must(f.AdminAPI("POST", "/audit-imports", map[string]any{"source_system": "mig", "events": hist[:1]}), 200, "re-import"); again.Get("counts.duplicate") != float64(1) {
		t.Fatalf("re-import not idempotent: %s", again.Raw)
	}
	list := f.must(f.AdminAPI("GET", "/imported-audit-events?source_system=mig&subject_id="+m1, nil), 200, "imported list")
	items := list.Get("items").([]any)
	if len(items) != 1 {
		t.Fatalf("imported events for subject: %s", list.Raw)
	}
	ev := items[0].(map[string]any)
	if ev["source"] != "import" || ev["verified"] != false || ev["source_subject_id"] != "m-1" || ev["content_hash"] == "" || ev["occurred_at"] != "2019-03-01T12:00:00Z" {
		t.Fatalf("imported event provenance: %v", ev)
	}
	// Imported records are not local evidence: the local log holds only the
	// witnessed import, never a relabelled LOGIN.
	var local, witnessed int
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE type='LOGIN'), count(*) FILTER (WHERE type='audit.history.imported') FROM audit_events`).Scan(&local, &witnessed)
	if local != 0 || witnessed != 2 {
		t.Fatalf("local evidence: %d relabelled, %d witnessed imports", local, witnessed)
	}
	// Deleting the account removes the source-supplied details.
	mustStatus(t, f.AdminAPI("DELETE", "/users/"+m1, nil), 204, "delete")
	var meta, actor string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata::text, coalesce(actor::text,'') FROM imported_audit_events WHERE source_event_id='ev-1'`).Scan(&meta, &actor)
	if meta != "{}" || strings.Contains(actor, "Mig One") {
		t.Fatalf("imported details kept after deletion: %s %s", meta, actor)
	}
	// History imported after the deletion keeps only its skeleton, and secret
	// members never reach storage.
	late := []map[string]any{
		{"source_event_id": "ev-5", "occurred_at": old, "type": "LOGIN", "subject_source_id": "m-1", "metadata": map[string]any{"city": "Utrecht"},
			"actor": map[string]any{"type": "user", "id": "m-1", "display": "Mig One"}},
		{"source_event_id": "ev-6", "occurred_at": old, "type": "API_KEY_CREATED", "metadata": map[string]any{"api_key": "abc123", "label": "ci"}},
	}
	f.must(f.AdminAPI("POST", "/audit-imports", map[string]any{"source_system": "mig", "events": late}), 200, "late import")
	var subject, redacted string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT coalesce(subject_id,''), metadata::text, coalesce(actor::text,''), coalesce(redacted_at::text,'')
		FROM imported_audit_events WHERE source_event_id='ev-5'`).Scan(&subject, &meta, &actor, &redacted)
	if subject != m1 || meta != "{}" || strings.Contains(actor, "Mig One") || redacted == "" {
		t.Fatalf("history about a deleted account stored in full: %s %s %s %s", subject, meta, actor, redacted)
	}
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata::text FROM imported_audit_events WHERE source_event_id='ev-6'`).Scan(&meta)
	if strings.Contains(meta, "abc123") || !strings.Contains(meta, "ci") {
		t.Fatalf("secret member stored: %s", meta)
	}
	// Importing history needs its own permission.
	alice := f.AdminTokenFor("alice").Tokens.Str("access_token")
	if r := h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/audit-imports", Token: alice, JSON: map[string]any{"source_system": "mig", "events": hist[:1]}}); r.Status != 403 {
		t.Fatalf("audit import without permission: %d", r.Status)
	}
}
