package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/identity"
)

// fakeAPI answers the requests the applier makes, like the realm API would.
type fakeAPI struct {
	t        *testing.T
	orgs     []map[string]any
	statuses map[string]string // job status per source ID (default imported, or valid in a dry run)
	failJobs bool
	jobs     map[string]map[string]any
	// reconcile answers GET /user-imports/reconciliation.
	reconcile  func(q url.Values) (map[string]any, error)
	reconciled []url.Values
	calls      int
}

func newFakeAPI(t *testing.T) *fakeAPI {
	return &fakeAPI{t: t, statuses: map[string]string{}, jobs: map[string]map[string]any{}}
}

func (f *fakeAPI) call(_ context.Context, method, path string, body, out any, _ string) error {
	f.calls++
	p, rawq, _ := strings.Cut(path, "?")
	q, _ := url.ParseQuery(rawq)
	var resp any
	switch {
	case method == "GET" && p == "/organizations":
		resp = map[string]any{"items": f.orgs}
	case method == "POST" && p == "/organizations":
		b := body.(map[string]any)
		id := "org_" + b["slug"].(string)
		f.orgs = append(f.orgs, map[string]any{"id": id, "slug": b["slug"], "external_id": b["external_id"]})
		resp = map[string]any{"id": id}
	case method == "POST" && p == "/user-imports":
		b := body.(map[string]any)
		counts, results := map[string]int{}, []map[string]any{}
		for _, u := range b["users"].([]identity.ImportRecord) {
			st := f.statuses[u.SourceID]
			if st == "" {
				st = "imported"
				if b["dry_run"] == true {
					st = "valid"
				}
			}
			counts[st]++
			results = append(results, map[string]any{"source_id": u.SourceID, "status": st})
		}
		id := fmt.Sprintf("job_%d", len(f.jobs)+1)
		job := map[string]any{"id": id, "state": "succeeded", "result": map[string]any{"counts": counts, "totals": map[string]int{}, "results": results}}
		if f.failJobs {
			job = map[string]any{"id": id, "state": "dead_letter", "last_error": "worker gave up"}
		}
		f.jobs[id] = job
		resp = map[string]any{"job_id": id}
	case method == "GET" && strings.HasPrefix(p, "/jobs/"):
		resp = f.jobs[strings.TrimPrefix(p, "/jobs/")]
	case method == "GET" && p == "/user-imports/reconciliation":
		f.reconciled = append(f.reconciled, q)
		r, err := f.reconcile(q)
		if err != nil {
			return err
		}
		resp = r
	default:
		f.t.Fatalf("unexpected request %s %s", method, path)
	}
	b, _ := json.Marshal(resp)
	return json.Unmarshal(b, out)
}

// holding answers the reconciliation like the server does for a realm that
// holds the given measures.
func holding(actual map[string]int) func(url.Values) (map[string]any, error) {
	return func(q url.Values) (map[string]any, error) {
		mismatches := []map[string]any{}
		for _, m := range []string{"users", "memberships", "privileged_assignments", "password_verifiers", "totp_factors"} {
			v := q.Get("expected_" + m)
			if v == "" {
				continue
			}
			want, err := strconv.Atoi(v)
			if err != nil {
				return nil, &APIError{Status: 422, Detail: m}
			}
			if actual[m] != want {
				mismatches = append(mismatches, map[string]any{"measure": m, "expected": want, "actual": actual[m]})
			}
		}
		return map[string]any{"source_system": q.Get("source_system"), "users": actual["users"], "mismatches": mismatches, "reconciled": len(mismatches) == 0}, nil
	}
}

// exportCounts counts the converted export as the reconciliation measures
// it, leaving out the given source IDs.
func exportCounts(res *Result, importTOTP bool, without ...string) map[string]int {
	c := map[string]int{"users": 0, "memberships": 0, "password_verifiers": 0, "totp_factors": 0}
	for _, u := range res.Users {
		if strings.Contains(strings.Join(without, " "), u.SourceID) {
			continue
		}
		c["users"]++
		c["memberships"] += len(u.Memberships)
		if u.PasswordHash != "" {
			c["password_verifiers"]++
		}
		if importTOTP && u.TOTPSecret != "" {
			c["totp_factors"]++
		}
	}
	return c
}

func keycloakResult(t *testing.T) *Result {
	return convert(t, Keycloak, Options{ImportTOTP: true}, "testdata/keycloak/demo-realm-26.8.0.json")
}

// TestApplyReconciles: a real import always ends with a reconciliation that
// carries the converted export's expected counts (MIG-012); a dry run does
// not reconcile.
func TestApplyReconciles(t *testing.T) {
	ctx := context.Background()
	res := keycloakResult(t)
	want := exportCounts(res, true)
	if want["users"] != 12 || want["memberships"] == 0 || want["password_verifiers"] == 0 || want["totp_factors"] != 1 {
		t.Fatalf("fixture counts: %v", want)
	}
	f := newFakeAPI(t)
	f.reconcile = holding(want)
	ap := &Applier{Call: f.call, Wait: func(context.Context) error { return nil }}

	if out, err := ap.Apply(ctx, res, ApplyOptions{DryRun: true, ImportTOTP: true}); err != nil || len(f.reconciled) != 0 || out.Expected != nil || out.Reconciliation != nil {
		t.Fatalf("dry run reconciled: %v %v", err, f.reconciled)
	}

	out, err := ap.Apply(ctx, res, ApplyOptions{ImportTOTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.reconciled) != 1 {
		t.Fatalf("reconciliation requests: %d", len(f.reconciled))
	}
	q := f.reconciled[0]
	for m, n := range want {
		if q.Get("expected_"+m) != strconv.Itoa(n) || out.Expected[m] != n {
			t.Fatalf("expected_%s = %q (outcome %d), want %d", m, q.Get("expected_"+m), out.Expected[m], n)
		}
	}
	if q.Get("source_system") != "keycloak-demo" || q.Has("expected_privileged_assignments") {
		t.Fatalf("reconciliation query: %v", q)
	}
	if out.Reconciliation["reconciled"] != true {
		t.Fatalf("reconciliation: %v", out.Reconciliation)
	}

	// Without --import-totp no seed is sent, so none is expected.
	f.reconcile = holding(exportCounts(res, false))
	if _, err := ap.Apply(ctx, res, ApplyOptions{}); err != nil || f.reconciled[1].Get("expected_totp_factors") != "0" {
		t.Fatalf("without TOTP: %v %v", err, f.reconciled[1])
	}
}

// TestApplyNotReconciled: an import after which the realm does not match the
// export is an error (ErrNotReconciled) naming every mismatch, with the
// server's answer kept in the outcome.
func TestApplyNotReconciled(t *testing.T) {
	ctx := context.Background()
	res := keycloakResult(t)
	conflicting := res.Users[0].SourceID
	f := newFakeAPI(t)
	f.statuses[conflicting] = "conflict"
	actual := exportCounts(res, true, conflicting)
	f.reconcile = holding(actual)
	ap := &Applier{Call: f.call, Wait: func(context.Context) error { return nil }}
	out, err := ap.Apply(ctx, res, ApplyOptions{ImportTOTP: true})
	if !errors.Is(err, ErrNotReconciled) || !strings.Contains(err.Error(), fmt.Sprintf("users expected 12, actual %d", actual["users"])) {
		t.Fatalf("mismatch not reported: %v", err)
	}
	if out == nil || out.Reconciliation["reconciled"] != false || out.Expected["users"] != 12 || out.Counts["conflict"] != 1 {
		t.Fatalf("outcome: %+v", out)
	}

	// A reconciled answer without mismatches but reconciled false is not
	// taken as success either.
	f.reconcile = func(url.Values) (map[string]any, error) { return map[string]any{"reconciled": false}, nil }
	if _, err := ap.Apply(ctx, res, ApplyOptions{ImportTOTP: true}); !errors.Is(err, ErrNotReconciled) {
		t.Fatalf("reconciled false accepted: %v", err)
	}
}

// TestApplySkippedDeleted: records the server skips because their account was
// deleted in ProudAuth (MIG-017) are not expected in the realm.
func TestApplySkippedDeleted(t *testing.T) {
	res := keycloakResult(t)
	deleted := res.Users[1].SourceID
	f := newFakeAPI(t)
	f.statuses[deleted] = "skipped_deleted"
	f.reconcile = holding(exportCounts(res, true, deleted))
	ap := &Applier{Call: f.call, Wait: func(context.Context) error { return nil }}
	out, err := ap.Apply(context.Background(), res, ApplyOptions{ImportTOTP: true})
	if err != nil || out.Expected["users"] != 11 || f.reconciled[0].Get("expected_users") != "11" {
		t.Fatalf("skipped_deleted expected: %v %v", err, out.Expected)
	}
}

// TestApplyReconciliationFailure: a reconciliation request that fails is an
// error, never a silent success.
func TestApplyReconciliationFailure(t *testing.T) {
	ctx := context.Background()
	res := keycloakResult(t)
	f := newFakeAPI(t)
	f.reconcile = func(url.Values) (map[string]any, error) {
		return nil, &APIError{Status: http.StatusForbidden, Detail: "missing permission realm.users.import"}
	}
	ap := &Applier{Call: f.call, Wait: func(context.Context) error { return nil }}
	out, err := ap.Apply(ctx, res, ApplyOptions{ImportTOTP: true})
	if err == nil || errors.Is(err, ErrNotReconciled) || !strings.Contains(err.Error(), "reconciliation: HTTP 403") {
		t.Fatalf("failed reconciliation: %v", err)
	}
	if out.Reconciliation != nil || out.Expected["users"] != 12 {
		t.Fatalf("outcome after a failed reconciliation: %+v", out)
	}

	// A run that stops part-way is reconciled too, and both errors are
	// reported.
	f.failJobs = true
	f.reconcile = holding(map[string]int{})
	_, err = ap.Apply(ctx, res, ApplyOptions{ImportTOTP: true})
	if err == nil || !strings.Contains(err.Error(), "job ended dead_letter") || !errors.Is(err, ErrNotReconciled) {
		t.Fatalf("partial run: %v", err)
	}
}

// TestApplyNothingImported: the reconciliation answers 404 while nothing was
// imported from the source system; that matches an export without users and
// is a mismatch for one with users.
func TestApplyNothingImported(t *testing.T) {
	ctx := context.Background()
	notFound := func(url.Values) (map[string]any, error) {
		return nil, &APIError{Status: http.StatusNotFound, Detail: "no users were imported from this source_system"}
	}
	empty := keycloakResult(t)
	empty.Users = nil
	f := newFakeAPI(t)
	f.reconcile = notFound
	ap := &Applier{Call: f.call, Wait: func(context.Context) error { return nil }}
	out, err := ap.Apply(ctx, empty, ApplyOptions{})
	if err != nil || len(f.reconciled) != 1 || out.Reconciliation["reconciled"] != true || len(out.Jobs) != 0 {
		t.Fatalf("export without users: %v %+v", err, out)
	}
	f.failJobs = true
	_, err = ap.Apply(ctx, keycloakResult(t), ApplyOptions{ImportTOTP: true})
	if !errors.Is(err, ErrNotReconciled) || !strings.Contains(err.Error(), "users expected 12, actual 0") {
		t.Fatalf("nothing imported: %v", err)
	}
}

// TestApplyBatchSize: a batch size outside 1..1000 is refused before any
// request instead of being replaced silently.
func TestApplyBatchSize(t *testing.T) {
	res := keycloakResult(t)
	for _, n := range []int{-1, 1001, 5000} {
		f := newFakeAPI(t)
		ap := &Applier{Call: f.call, BatchSize: n}
		if _, err := ap.Apply(context.Background(), res, ApplyOptions{DryRun: true}); err == nil || !strings.Contains(err.Error(), "1 to 1000") || f.calls != 0 {
			t.Fatalf("batch size %d: %v (%d requests)", n, err, f.calls)
		}
	}
	for _, n := range []int{1, 1000} {
		if err := CheckBatchSize(n); err != nil {
			t.Fatalf("batch size %d refused: %v", n, err)
		}
	}
	f := newFakeAPI(t)
	ap := &Applier{Call: f.call, BatchSize: 5, Wait: func(context.Context) error { return nil }}
	if out, err := ap.Apply(context.Background(), res, ApplyOptions{DryRun: true}); err != nil || len(out.Jobs) != 3 {
		t.Fatalf("batches of 5: %v %+v", err, out)
	}
}
