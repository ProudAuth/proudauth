package e2e

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/worker"
)

// TestImportVerificationTrust covers MIG-009: an imported email keeps its
// verified flag only when the import is explicitly trusted for that assertion
// (the verification override with a written reason); otherwise every imported
// email is unverified, in the dry-run plan and in the import. Provenance stays
// auditable: the identifier records import:<source_system> as its verification
// source, the job keeps the trust decision and reason, the job's creation is
// audited with the requester, and each account's user.imported event names the
// job and source system.
func TestImportVerificationTrust(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	verified := func(email string) (bool, string) {
		t.Helper()
		var ok bool
		var src string
		if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT verified_at IS NOT NULL, coalesce(verification_source,'') FROM user_identifiers
			WHERE type='email' AND canonical_value=$1`, email).Scan(&ok, &src); err != nil {
			t.Fatalf("identifier %s: %v", email, err)
		}
		return ok, src
	}
	run := func(body map[string]any) (string, *Resp) {
		t.Helper()
		j := f.must(f.AdminAPI("POST", "/user-imports", body), 202, "import")
		runWorker(t, w)
		return j.Str("job_id"), f.must(f.AdminAPI("GET", "/jobs/"+j.Str("job_id"), nil), 200, "job")
	}
	planOf := func(res *Resp, i int) map[string]any {
		return res.Get("result.results").([]any)[i].(map[string]any)["plan"].(map[string]any)
	}

	// Untrusted: the source's claim is not kept.
	claims := []map[string]any{{"source_id": "u-1", "email": "claims-verified@example.test", "email_verified": true}}
	if _, dry := run(map[string]any{"source_system": "untrusted-src", "users": claims, "dry_run": true}); planOf(dry, 0)["email_verified"] != false {
		t.Fatalf("untrusted dry run plans a verified email: %s", dry.Raw)
	}
	if _, res := run(map[string]any{"source_system": "untrusted-src", "users": claims}); res.Get("result.counts.imported") != float64(1) {
		t.Fatalf("untrusted import: %s", res.Raw)
	}
	if ok, _ := verified("claims-verified@example.test"); ok {
		t.Fatal("an untrusted import kept the source's verification flag")
	}

	// Trust needs a written reason.
	r := f.AdminAPI("POST", "/user-imports", map[string]any{"source_system": "trusted-src", "users": claims, "trust_email_verification": true,
		"verification_reason": "trust me"})
	if r.Status != 422 || !strings.Contains(string(r.Raw), "verification_reason") {
		t.Fatalf("trust without a reason: %d %s", r.Status, r.Raw)
	}

	// Trusted: only records that claim verification are verified.
	reason := "source verified every address by link (ticket 42)"
	trusted := []map[string]any{
		{"source_id": "t-1", "email": "trusted-yes@example.test", "email_verified": true},
		{"source_id": "t-2", "email": "trusted-no@example.test"},
	}
	_, dry := run(map[string]any{"source_system": "trusted-src", "users": trusted, "dry_run": true, "trust_email_verification": true,
		"verification_reason": reason})
	if planOf(dry, 0)["email_verified"] != true || planOf(dry, 1)["email_verified"] != false {
		t.Fatalf("trusted dry run plan: %s", dry.Raw)
	}
	jobID, res := run(map[string]any{"source_system": "trusted-src", "users": trusted, "trust_email_verification": true, "verification_reason": reason})
	if res.Get("result.counts.imported") != float64(2) || res.Get("result.totals.trusted_verified_emails") != float64(1) {
		t.Fatalf("trusted import: %s", res.Raw)
	}
	if ok, src := verified("trusted-yes@example.test"); !ok || src != "import:trusted-src" {
		t.Fatalf("trusted verification: verified=%v source=%q", ok, src)
	}
	if ok, _ := verified("trusted-no@example.test"); ok {
		t.Fatal("trust verified an email the source did not claim")
	}

	// Provenance: the decision, its reason and its requester stay on record.
	if res.Get("input.trust_email_verification") != true || res.Str("input.verification_reason") != reason || res.Str("requested_by_id") != f.Users["admin"] {
		t.Fatalf("job does not keep the trust decision: %s", res.Raw)
	}
	var creator string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT actor_id FROM audit_events WHERE type='job.created' AND target_id=$1`, jobID).Scan(&creator); err != nil ||
		creator != f.Users["admin"] {
		t.Fatalf("job creation not audited with its requester: %q %v", creator, err)
	}
	userID := res.Get("result.results").([]any)[0].(map[string]any)["user_id"].(string)
	var evJob, evSource string
	if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT metadata->>'job_id', metadata->>'source_system' FROM audit_events
		WHERE type='user.imported' AND subject_id=$1`, userID).Scan(&evJob, &evSource); err != nil || evJob != jobID || evSource != "trusted-src" {
		t.Fatalf("user.imported does not name the job and source: %q %q %v", evJob, evSource, err)
	}
}

// TestExportArtifactProtection covers MIG-015 for the realm data export (the
// migration exit artifact): the result is stored only encrypted, expires after
// privacy.export_retention and is then purged; downloading it needs a
// short-lived, single-use credential bound to the requester (another principal
// holding the same permission can neither obtain nor redeem one); every
// download is audited; and the archive is never sent by email.
func TestExportArtifactProtection(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	db := h.App.D.DB.Pool
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	mailBefore := count(`SELECT count(*) FROM notification_jobs`)
	job := f.must(f.AdminAPI("POST", "/data-exports", nil), 202, "export").Str("job_id")
	runWorker(t, w)
	st := f.must(f.AdminAPI("GET", "/jobs/"+job, nil), 200, "job")
	if st.Str("state") != "succeeded" || st.Get("has_protected_result") != true || strings.Contains(string(st.Raw), "bob@example.test") {
		t.Fatalf("export job: %s", st.Raw)
	}

	// Encrypted at rest: no identity data in any stored column.
	var plain string
	var ct []byte
	var expires time.Time
	if err := db.QueryRow(ctx, `SELECT coalesce(result::text,''), result_ciphertext, result_expires_at FROM jobs WHERE id=$1`, job).Scan(&plain, &ct, &expires); err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || bytes.Contains(ct, []byte("bob@example.test")) || bytes.Contains(ct, []byte("proudauth.realm-export.v1")) || strings.Contains(plain, "bob@example.test") {
		t.Fatalf("export result stored in clear (ciphertext %d bytes)", len(ct))
	}
	// Retention is set when the result is written.
	if d := expires.Sub(h.Clock.Now().Add(h.Cfg.Privacy.ExportRetention)); d < -time.Minute || d > time.Minute {
		t.Fatalf("result expires at %v, want about now + %v", expires, h.Cfg.Privacy.ExportRetention)
	}
	// The archive is delivered only through the download API, never by email.
	if n := count(`SELECT count(*) FROM notification_jobs`); n != mailBefore {
		t.Fatalf("the export queued %d notifications", n-mailBefore)
	}

	// Download authorization is bound to the requester, not to the permission.
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "data-exporter",
		"permissions": []string{"realm.data.export"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "user", "id": f.Users["carol"]}}), 201, "assign")
	carol := f.AdminTokenFor("carol").Tokens.Str("access_token")
	mustStatus(t, h.API("POST", "/jobs/"+job+"/downloads", carol, nil), 404, "download credential for another exporter's job")
	dl := f.must(f.AdminAPI("POST", "/jobs/"+job+"/downloads", nil), 201, "download credential")
	if dl.Get("expires_in") != float64(300) || !strings.HasPrefix(dl.Str("download_token"), "pa_") {
		t.Fatalf("download credential: %s", dl.Raw)
	}
	redeem := map[string]any{"download_token": dl.Str("download_token")}
	mustStatus(t, h.API("POST", "/job-downloads", carol, redeem), 404, "credential redeemed by another principal")
	if n := count(`SELECT count(*) FROM audit_events WHERE type='job.result.downloaded' AND target_id=$1`, job); n != 0 {
		t.Fatalf("%d downloads audited before any succeeded", n)
	}
	// The refused attempt did not spend the credential; the requester
	// redeems it once, and the download is audited.
	data := f.must(f.AdminAPI("POST", "/job-downloads", redeem), 200, "download")
	if !strings.Contains(string(data.Raw), "bob@example.test") {
		t.Fatal("download does not contain the export")
	}
	mustStatus(t, f.AdminAPI("POST", "/job-downloads", redeem), 404, "replayed download credential")
	var actor, category string
	if err := db.QueryRow(ctx, `SELECT actor_id, category FROM audit_events WHERE type='job.result.downloaded' AND target_id=$1`, job).Scan(&actor, &category); err != nil ||
		actor != f.Users["admin"] || category != "privacy" {
		t.Fatalf("download audit: actor %q category %q %v", actor, category, err)
	}
	// A credential is short-lived: unused, it expires after five minutes.
	dl = f.must(f.AdminAPI("POST", "/jobs/"+job+"/downloads", nil), 201, "download credential")
	h.Clock.Advance(6 * time.Minute)
	f.ReloginAdmin()
	mustStatus(t, f.AdminAPI("POST", "/job-downloads", map[string]any{"download_token": dl.Str("download_token")}), 404, "expired download credential")
	if n := count(`SELECT count(*) FROM audit_events WHERE type='job.result.downloaded' AND target_id=$1`, job); n != 1 {
		t.Fatalf("%d downloads audited, want 1", n)
	}

	// After the retention period the result is no longer downloadable and is purged.
	h.Clock.Advance(h.Cfg.Privacy.ExportRetention)
	f.ReloginAdmin()
	mustStatus(t, f.AdminAPI("POST", "/jobs/"+job+"/downloads", nil), 409, "download after retention")
	if _, err := w.Jobs.PurgeResults(ctx); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM jobs WHERE id=$1 AND result_ciphertext IS NOT NULL`, job); n != 0 {
		t.Fatal("expired export result kept after purge")
	}
}
