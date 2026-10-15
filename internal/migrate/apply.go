package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/identity"
)

// Caller performs one authenticated request against the realm API
// (/api/v1/realms/{realm}{path}) and decodes the JSON response into out. An
// error response is returned as an error carrying the HTTP status (APIError).
type Caller func(ctx context.Context, method, path string, body, out any, idempotencyKey string) error

// APIError is an error response of the API.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.Status, e.Detail) }

// Applier submits a conversion through the authenticated import APIs: the
// organizations API (with external IDs, so a re-run reuses what an earlier
// run created) and POST /user-imports jobs (import_mappings keyed by source
// system and source ID, so a re-run reports already_imported instead of
// duplicating). The importing administrator's permissions, delegation
// ceiling and MFA session apply to every step (MIG-005).
type Applier struct {
	Call Caller
	// Wait runs between job polls (default: one second). Tests run the
	// worker here.
	Wait func(ctx context.Context) error
	// BatchSize and BatchBytes bound one POST /user-imports request
	// (defaults DefaultBatchSize records and 192 KiB, below
	// limits.max_body_bytes). A BatchSize outside 1..MaxBatchSize is
	// refused (zero means the default).
	BatchSize  int
	BatchBytes int
	// Log receives progress lines.
	Log func(format string, args ...any)
}

// Batch sizes: POST /user-imports takes at most MaxBatchSize records per job.
const (
	DefaultBatchSize = 500
	MaxBatchSize     = 1000
)

// CheckBatchSize refuses a batch size outside 1..MaxBatchSize.
func CheckBatchSize(n int) error {
	if n < 1 || n > MaxBatchSize {
		return fmt.Errorf("batch size %d is out of range: use 1 to %d records per import job", n, MaxBatchSize)
	}
	return nil
}

// ApplyOptions are the import authorizations an operator gives explicitly.
type ApplyOptions struct {
	DryRun                 bool
	TrustEmailVerification bool
	VerificationReason     string
	AllowOwnerRoles        bool
	ImportTOTP             bool
}

// ErrBlocked reports conflicts that stop an import before anything is written.
var ErrBlocked = errors.New("migration blocked")

// ErrNotReconciled reports an import after which the realm does not hold what
// the converted export says it should: GET /user-imports/reconciliation with
// the export's expected counts listed mismatches (MIG-012).
var ErrNotReconciled = errors.New("import not reconciled")

// Apply submits the conversion (or, with DryRun, validates it without
// writing) and records the outcome in res.Report.Import. A real import ends
// with a reconciliation against the counts of the converted export, also when
// it stopped part-way; a failed reconciliation is returned as an error, and
// one with mismatches as ErrNotReconciled (with the outcome filled in).
func (a *Applier) Apply(ctx context.Context, res *Result, opts ApplyOptions) (*ImportOutcome, error) {
	if a.BatchSize != 0 {
		if err := CheckBatchSize(a.BatchSize); err != nil {
			return nil, err
		}
	}
	if a.Wait == nil {
		a.Wait = func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
				return nil
			}
		}
	}
	if a.Log == nil {
		a.Log = func(string, ...any) {}
	}
	out := &ImportOutcome{DryRun: opts.DryRun, Jobs: []string{}, Counts: map[string]int{}, Totals: map[string]int{}, Organizations: []OrgOutcome{}}
	res.Report.Import = out

	// Everything that would stop the import is found before anything is
	// written: organizations that collide by slug, organizations or roles
	// the mapping names that do not exist.
	blocked, err := a.resolveOrganizations(ctx, res, out)
	if err != nil {
		return out, err
	}
	missing, err := a.missingRoles(ctx, res)
	if err != nil {
		return out, err
	}
	for _, r := range missing {
		blocked = append(blocked, "organization role "+r+" does not exist (create it as a realm-wide organization role before the import)")
	}
	if len(blocked) > 0 && !opts.DryRun {
		return out, fmt.Errorf("%w: %s", ErrBlocked, strings.Join(blocked, "; "))
	}
	for _, b := range blocked {
		res.Report.Notes = append(res.Report.Notes, "blocks the import: "+b)
	}
	err = a.submit(ctx, res, out, opts)
	if opts.DryRun || ctx.Err() != nil {
		return out, err
	}
	return out, errors.Join(err, a.reconcile(ctx, res, opts, out))
}

// submit creates the missing organizations (not in a dry run) and submits
// the records in batches, waiting for each job.
func (a *Applier) submit(ctx context.Context, res *Result, out *ImportOutcome, opts ApplyOptions) error {
	orgIDs := map[string]string{}
	for i := range out.Organizations {
		oc := &out.Organizations[i]
		if oc.Status == "will_create" && !opts.DryRun {
			if err := a.createOrganization(ctx, res, oc); err != nil {
				return err
			}
		}
		if oc.ID != "" {
			orgIDs[oc.Slug] = oc.ID
		}
	}

	// Memberships name organizations by ID from here on; in a dry run,
	// organizations that do not exist yet cannot be validated.
	records := make([]identity.ImportRecord, 0, len(res.Users))
	pending := map[string]bool{}
	for _, rec := range res.Users {
		r := rec
		r.Memberships = nil
		for _, ms := range rec.Memberships {
			if id := orgIDs[ms.Organization]; id != "" {
				r.Memberships = append(r.Memberships, identity.ImportMembership{Organization: id, Roles: ms.Roles})
			} else {
				pending[ms.Organization] = true
			}
		}
		if r.Memberships == nil {
			r.Memberships = []identity.ImportMembership{}
		}
		if !opts.ImportTOTP {
			r.TOTPSecret = ""
		}
		records = append(records, r)
	}
	for slug := range pending {
		res.Report.Notes = append(res.Report.Notes, "memberships in "+slug+" are validated when the organization exists (it is created by the import)")
	}

	for i, batch := range a.batches(records) {
		body := map[string]any{"format": identity.ImportFormatV1, "source_system": res.SourceSystem, "users": batch, "dry_run": opts.DryRun,
			"allow_owner_roles": opts.AllowOwnerRoles, "import_totp": opts.ImportTOTP}
		if opts.TrustEmailVerification {
			body["trust_email_verification"], body["verification_reason"] = true, opts.VerificationReason
		}
		var started struct {
			JobID string `json:"job_id"`
		}
		key := newKey()
		if err := a.retry(ctx, func() error { return a.Call(ctx, "POST", "/user-imports", body, &started, key) }); err != nil {
			return fmt.Errorf("batch %d: %w", i+1, err)
		}
		out.Jobs = append(out.Jobs, started.JobID)
		a.Log("batch %d: %d records, job %s", i+1, len(batch), started.JobID)
		job, err := a.wait(ctx, started.JobID)
		if err != nil {
			return fmt.Errorf("batch %d (job %s): %w", i+1, started.JobID, err)
		}
		mergeJob(out, job)
	}
	return nil
}

// reconciledMeasures are the reconciliation measures the converted export
// determines. privileged_assignments is not among them: which roles are
// privileged is known only to the server (the reconciliation lists them for
// review).
var reconciledMeasures = []string{"users", "memberships", "password_verifiers", "totp_factors"}

// expectedCounts counts what the realm should hold for the converted export
// after the import: every record except those the server reported
// skipped_deleted (accounts deleted in ProudAuth are never recreated,
// MIG-017), their memberships, password verifiers and, with ImportTOTP, TOTP
// factors.
func expectedCounts(res *Result, opts ApplyOptions, out *ImportOutcome) map[string]int {
	skipped := map[string]bool{}
	for _, r := range out.Records {
		if r.Status == "skipped_deleted" {
			skipped[r.SourceID] = true
		}
	}
	exp := map[string]int{}
	for _, m := range reconciledMeasures {
		exp[m] = 0
	}
	for _, u := range res.Users {
		if skipped[u.SourceID] {
			continue
		}
		exp["users"]++
		exp["memberships"] += len(u.Memberships)
		if u.PasswordHash != "" {
			exp["password_verifiers"]++
		}
		if opts.ImportTOTP && u.TOTPSecret != "" {
			exp["totp_factors"]++
		}
	}
	return exp
}

// reconcile asks GET /user-imports/reconciliation with the expected counts of
// the converted export and records the answer in out.Reconciliation.
func (a *Applier) reconcile(ctx context.Context, res *Result, opts ApplyOptions, out *ImportOutcome) error {
	exp := expectedCounts(res, opts, out)
	out.Expected = exp
	q := url.Values{"source_system": {res.SourceSystem}}
	for _, m := range reconciledMeasures {
		q.Set("expected_"+m, strconv.Itoa(exp[m]))
	}
	var rec map[string]any
	err := a.retry(ctx, func() error { return a.Call(ctx, "GET", "/user-imports/reconciliation?"+q.Encode(), nil, &rec, "") })
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
		// 404: the realm holds no account imported under this source
		// system, so every measure is 0.
		mismatches := []any{}
		for _, m := range reconciledMeasures {
			if exp[m] != 0 {
				mismatches = append(mismatches, map[string]any{"measure": m, "expected": exp[m], "actual": 0})
			}
		}
		rec = map[string]any{"source_system": res.SourceSystem, "users": 0, "detail": "no users were imported from this source_system",
			"mismatches": mismatches, "reconciled": len(mismatches) == 0}
	} else if err != nil {
		return fmt.Errorf("reconciliation: %w", err)
	}
	out.Reconciliation = rec
	a.Log("reconciliation: reconciled %v", rec["reconciled"])
	if rec["reconciled"] == true {
		return nil
	}
	var diffs []string
	ms, _ := rec["mismatches"].([]any)
	for _, m := range ms {
		if mm, ok := m.(map[string]any); ok {
			diffs = append(diffs, fmt.Sprintf("%v expected %v, actual %v", mm["measure"], mm["expected"], mm["actual"]))
		}
	}
	if len(diffs) == 0 {
		diffs = append(diffs, "the server did not report the import reconciled")
	}
	return fmt.Errorf("%w with the converted export: %s", ErrNotReconciled, strings.Join(diffs, "; "))
}

// resolveOrganizations finds the target organizations without writing. An
// organization created by an earlier run is found by its external ID; an
// organization the reviewed mapping names is used by slug; an existing
// organization that only shares the proposed slug is a conflict (imports
// never merge by matching names, MIG-004); the rest will be created.
func (a *Applier) resolveOrganizations(ctx context.Context, res *Result, out *ImportOutcome) ([]string, error) {
	type org struct {
		ID         string `json:"id"`
		Slug       string `json:"slug"`
		ExternalID string `json:"external_id"`
	}
	bySlug, byExt := map[string]org{}, map[string]org{}
	err := a.list(ctx, "/organizations", func(raw json.RawMessage) error {
		var o org
		if err := json.Unmarshal(raw, &o); err != nil {
			return err
		}
		bySlug[o.Slug] = o
		if o.ExternalID != "" {
			byExt[o.ExternalID] = o
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing organizations: %w", err)
	}
	var blocked []string
	for _, t := range res.Organizations {
		oc := OrgOutcome{Slug: t.Slug}
		if o, ok := byExt[t.ExternalID]; ok && t.ExternalID != "" {
			oc.ID, oc.Status, oc.Detail = o.ID, "exists", "created by an earlier run (external ID "+t.ExternalID+")"
		} else if o, ok := bySlug[t.Slug]; ok {
			if t.FromMapping {
				oc.ID, oc.Status, oc.Detail = o.ID, "exists", "named by the mapping"
			} else {
				oc.Status = "conflict"
				oc.Detail = "an organization with this slug already exists and was not created by this migration; map " + t.SourceKey + " to it explicitly or to another slug"
				blocked = append(blocked, t.Slug+": "+oc.Detail)
			}
		} else if t.ExternalID == "" {
			oc.Status, oc.Detail = "conflict", "the mapping names this organization but it does not exist"
			blocked = append(blocked, t.Slug+": "+oc.Detail)
		} else {
			oc.Status = "will_create"
		}
		out.Organizations = append(out.Organizations, oc)
	}
	return blocked, nil
}

// createOrganization creates a target organization with its external ID.
func (a *Applier) createOrganization(ctx context.Context, res *Result, oc *OrgOutcome) error {
	var t *TargetOrganization
	for i := range res.Organizations {
		if res.Organizations[i].Slug == oc.Slug {
			t = &res.Organizations[i]
		}
	}
	var created struct {
		ID string `json:"id"`
	}
	body := map[string]any{"slug": t.Slug, "display_name": t.DisplayName, "external_id": t.ExternalID}
	key := newKey()
	if err := a.retry(ctx, func() error { return a.Call(ctx, "POST", "/organizations", body, &created, key) }); err != nil {
		return fmt.Errorf("creating organization %s: %w", t.Slug, err)
	}
	oc.ID, oc.Status = created.ID, "created"
	a.Log("organization %s created (%s)", t.Slug, created.ID)
	return nil
}

// missingRoles lists mapped organization roles that do not exist as
// realm-wide organization roles.
func (a *Applier) missingRoles(ctx context.Context, res *Result) ([]string, error) {
	want := map[string]bool{}
	for _, rec := range res.Users {
		for _, ms := range rec.Memberships {
			for _, r := range ms.Roles {
				want[strings.ToLower(r)] = true
			}
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	err := a.list(ctx, "/roles?boundary_type=organization", func(raw json.RawMessage) error {
		var r struct {
			Name           string `json:"name"`
			OrganizationID string `json:"organization_id"`
			ProjectID      string `json:"project_id"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if r.OrganizationID == "" && r.ProjectID == "" {
			delete(want, strings.ToLower(r.Name))
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing organization roles: %w", err)
	}
	out := make([]string, 0, len(want))
	for r := range want {
		out = append(out, r)
	}
	slices.Sort(out)
	return out, nil
}

// list iterates every page of a list endpoint.
func (a *Applier) list(ctx context.Context, path string, fn func(json.RawMessage) error) error {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	cursor := ""
	seen := map[string]bool{}
	for {
		p := path + sep + "limit=200"
		if cursor != "" {
			p += "&cursor=" + url.QueryEscape(cursor)
		}
		var page struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor string            `json:"next_cursor"`
		}
		if err := a.Call(ctx, "GET", p, nil, &page, ""); err != nil {
			return err
		}
		for _, it := range page.Items {
			if err := fn(it); err != nil {
				return err
			}
		}
		if page.NextCursor == "" || seen[page.NextCursor] {
			return nil
		}
		seen[page.NextCursor] = true
		cursor = page.NextCursor
	}
}

func (a *Applier) batches(records []identity.ImportRecord) [][]identity.ImportRecord {
	size, limit := a.BatchSize, a.BatchBytes
	if size == 0 { // Apply refuses other sizes outside 1..MaxBatchSize
		size = DefaultBatchSize
	}
	if limit <= 0 {
		limit = 192 << 10
	}
	var out [][]identity.ImportRecord
	var cur []identity.ImportRecord
	bytes := 0
	for _, r := range records {
		b, _ := json.Marshal(r)
		if len(cur) > 0 && (len(cur) >= size || bytes+len(b)+1 > limit) {
			out = append(out, cur)
			cur, bytes = nil, 0
		}
		cur = append(cur, r)
		bytes += len(b) + 1
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out
}

type jobView struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	LastError string `json:"last_error"`
	Result    struct {
		Counts  map[string]int  `json:"counts"`
		Totals  map[string]int  `json:"totals"`
		Results []RecordOutcome `json:"results"`
	} `json:"result"`
}

func (a *Applier) wait(ctx context.Context, id string) (*jobView, error) {
	for {
		var j jobView
		if err := a.Call(ctx, "GET", "/jobs/"+url.PathEscape(id), nil, &j, ""); err != nil {
			return nil, err
		}
		switch j.State {
		case "succeeded":
			return &j, nil
		case "dead_letter", "cancelled", "failed":
			return nil, fmt.Errorf("job ended %s: %s", j.State, j.LastError)
		}
		if err := a.Wait(ctx); err != nil {
			return nil, err
		}
	}
}

func mergeJob(out *ImportOutcome, j *jobView) {
	for k, v := range j.Result.Counts {
		out.Counts[k] += v
	}
	for k, v := range j.Result.Totals {
		out.Totals[k] += v
	}
	for _, r := range j.Result.Results {
		if r.Status != "imported" && r.Status != "valid" {
			out.Records = append(out.Records, RecordOutcome{SourceID: r.SourceID, Status: r.Status, UserID: r.UserID, Error: r.Error})
		}
	}
}

// retry repeats a request with the same idempotency key on transient
// failures (network errors and 5xx), so a retried create returns the first
// result instead of creating twice.
func (a *Applier) retry(ctx context.Context, f func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = f(); err == nil {
			return nil
		}
		var ae *APIError
		if errors.As(err, &ae) && ae.Status < 500 {
			return err
		}
		if werr := a.Wait(ctx); werr != nil {
			return werr
		}
	}
	return err
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "migrate-" + hex.EncodeToString(b)
}
