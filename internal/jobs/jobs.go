// Package jobs implements durable asynchronous jobs with leases, bounded retries,
// dead-lettering, progress and protected results (API-011, DEP-011, EXT-015/016).
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
)

// Job is an asynchronous unit of work.
type Job struct {
	ID                 string         `json:"id"`
	RealmID            string         `json:"realm_id,omitempty"`
	OrganizationID     string         `json:"organization_id,omitempty"`
	Type               string         `json:"type"`
	State              string         `json:"state"`
	Input              map[string]any `json:"input,omitempty"`
	Progress           map[string]any `json:"progress"`
	Result             map[string]any `json:"result,omitempty"`
	HasProtectedResult bool           `json:"has_protected_result"`
	DryRun             bool           `json:"dry_run"`
	RequestedByType    string         `json:"requested_by_type"`
	RequestedByID      string         `json:"requested_by_id"`
	Attempts           int            `json:"attempts"`
	LastError          string         `json:"last_error,omitempty"`
	CancelRequested    bool           `json:"cancel_requested"`
	CreatedAt          time.Time      `json:"created_at"`
	FinishedAt         *time.Time     `json:"finished_at,omitempty"`
	ResultExpiresAt    *time.Time     `json:"result_expires_at,omitempty"`
	checkpoint         map[string]any
	inputCT            []byte
	maxAttempts        int
	leaseGuard         func(context.Context, pgx.Tx) error
}

// Checkpoint returns the resumable checkpoint (MIG-011).
func (j *Job) Checkpoint() map[string]any { return j.checkpoint }

// LockLease fences a handler's database mutation against expiry or takeover.
// Call it inside the same transaction before changing domain rows. Ownership
// includes the attempt, so reusing a worker ID cannot revive an earlier claim.
func (j *Job) LockLease(ctx context.Context, tx pgx.Tx) error {
	if j.leaseGuard == nil {
		return ErrLeaseLost
	}
	return j.leaseGuard(ctx, tx)
}

// Service manages jobs.
type Service struct {
	d *runtime.Deps
	// OnDeadLetter, when set, observes jobs that end in dead_letter (AUD-014).
	OnDeadLetter func(jobType string)
}

// NewService returns the jobs service.
func NewService(d *runtime.Deps) *Service { return &Service{d: d} }

// Spec describes a new job.
type Spec struct {
	RealmID        string
	OrganizationID string
	Type           string
	Input          map[string]any
	DryRun         bool
	Requester      audit.Ref
	IdempotencyKey string
	MaxAttempts    int
	// ProtectedInput is encrypted at rest, available only to the handler through
	// Service.ProtectedInput, never returned by the API, and erased when the job
	// finishes.
	ProtectedInput map[string]any
}

// CreateTx enqueues a job in the caller's transaction. An idempotency key makes a
// retried request return the same job (API-005).
func (s *Service) CreateTx(ctx context.Context, tx pgx.Tx, sp Spec) (string, error) {
	if sp.MaxAttempts == 0 {
		sp.MaxAttempts = s.d.Cfg.Workers.MaxAttempts
	}
	if sp.MaxAttempts <= 0 {
		sp.MaxAttempts = 5
	}
	in, _ := json.Marshal(nonNil(sp.Input))
	id := ids.New(ids.Job)
	var key *string
	if sp.IdempotencyKey != "" {
		d := secret.Digest(sp.IdempotencyKey)
		key = &d
		var existing string
		if err := tx.QueryRow(ctx, `SELECT id FROM jobs WHERE requested_by_id=$1 AND type=$2 AND idempotency_key=$3`, sp.Requester.ID, sp.Type, d).Scan(&existing); err == nil {
			return existing, nil
		}
	}
	var pct []byte
	var pver *int
	if sp.ProtectedInput != nil {
		raw, err := json.Marshal(sp.ProtectedInput)
		if err != nil {
			return "", err
		}
		c, v, err := s.d.Keys.Encrypt(keys.PurposeData, raw, []byte("job-input:"+id))
		if err != nil {
			return "", err
		}
		pct, pver = c, &v
	}
	_, err := tx.Exec(ctx, `INSERT INTO jobs (id, realm_id, organization_id, type, input, dry_run, requested_by_type, requested_by_id, idempotency_key,
		max_attempts, run_after, created_at, updated_at, input_ciphertext, input_key_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$11,$12,$13)`, id, nilIfEmpty(sp.RealmID),
		nilIfEmpty(sp.OrganizationID), sp.Type, in, sp.DryRun, sp.Requester.Type, sp.Requester.ID, key, sp.MaxAttempts, s.d.Now(), pct, pver)
	if err != nil {
		return "", err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "job.created", RealmID: sp.RealmID, OrgID: sp.OrganizationID, Actor: sp.Requester,
		Target: &audit.Ref{Type: "job", ID: id}, Category: "operations", Metadata: map[string]any{"job_type": sp.Type, "dry_run": sp.DryRun}})
	return id, err
}

// Create enqueues a job in its own transaction.
func (s *Service) Create(ctx context.Context, sp Spec) (string, error) {
	var id string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var err error
		id, err = s.CreateTx(ctx, tx, sp)
		return err
	})
	return id, err
}

const jobCols = `id, coalesce(realm_id,''), coalesce(organization_id,''), type, state, input, progress, result, result_ciphertext IS NOT NULL,
	dry_run, requested_by_type, requested_by_id, attempts, coalesce(last_error,''), cancel_requested, created_at, finished_at, result_expires_at, checkpoint,
	input_ciphertext, max_attempts`

func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	var in, prog, res, cp []byte
	err := row.Scan(&j.ID, &j.RealmID, &j.OrganizationID, &j.Type, &j.State, &in, &prog, &res, &j.HasProtectedResult, &j.DryRun, &j.RequestedByType,
		&j.RequestedByID, &j.Attempts, &j.LastError, &j.CancelRequested, &j.CreatedAt, &j.FinishedAt, &j.ResultExpiresAt, &cp, &j.inputCT, &j.maxAttempts)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(in, &j.Input)
	_ = json.Unmarshal(prog, &j.Progress)
	if res != nil {
		_ = json.Unmarshal(res, &j.Result)
	}
	_ = json.Unmarshal(cp, &j.checkpoint)
	return &j, nil
}

// ProtectedInput decrypts a job's protected input (handlers only).
func (s *Service) ProtectedInput(j *Job) (map[string]any, error) {
	if len(j.inputCT) == 0 {
		return nil, fmt.Errorf("%w: protected input is no longer available", ErrPermanent)
	}
	raw, err := s.d.Keys.Decrypt(keys.PurposeData, j.inputCT, []byte("job-input:"+j.ID))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Get loads a job within a realm.
func (s *Service) Get(ctx context.Context, realmID, id string) (*Job, error) {
	j, err := scanJob(s.d.DB.Pool.QueryRow(ctx, `SELECT `+jobCols+` FROM jobs WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return j, err
}

// Cancel requests cancellation; running handlers observe it at checkpoints.
func (s *Service) Cancel(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE jobs SET cancel_requested=true, state=CASE WHEN state='queued' THEN 'cancelled' ELSE state END, updated_at=$3
			WHERE realm_id=$1 AND id=$2 AND state IN ('queued','running')`, realmID, id, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrConflict.WithDetail("job cannot be cancelled")
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "job.cancel_requested", RealmID: realmID, Actor: actor, Target: &audit.Ref{Type: "job", ID: id}, Category: "operations"})
		return err
	})
}

// Handler executes a job. It returns a non-secret result and optional protected
// (encrypted) result bytes for downloads.
type Handler func(ctx context.Context, j *Job, progress func(map[string]any) error) (result map[string]any, protected []byte, err error)

// ErrPermanent marks failures that must not be retried.
var ErrPermanent = errors.New("permanent job failure")

// ErrLeaseLost means this attempt no longer owns an unexpired running job.
var ErrLeaseLost = errors.New("job lease lost")

// RunOnce claims one due job of a registered type and runs it under a lease. A
// duplicate worker cannot claim a leased job, and handlers must be idempotent
// because a job may be retried after a crash (TEST-058).
func (s *Service) RunOnce(ctx context.Context, worker string, lease time.Duration, handlers map[string]Handler) (bool, error) {
	types := make([]string, 0, len(handlers))
	for t := range handlers {
		types = append(types, t)
	}
	now := s.d.Now()
	perOrg := s.d.Cfg.Workers.MaxJobsPerOrganization
	var j *Job
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if perOrg > 0 {
			// Claims are serialized while the per-organization bound applies:
			// two concurrent claims would otherwise each count the other's job
			// as not yet running and exceed the bound together (TEN-018,
			// DEP-015). The claim below runs in a new snapshot that sees every
			// claim committed before this lock was granted.
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('proudauth:jobs:claim'))`); err != nil {
				return err
			}
		}
		var err error
		j, err = scanJob(tx.QueryRow(ctx, `UPDATE jobs SET state='running', lease_owner=$1, lease_expires_at=$2, attempts=attempts+1, updated_at=$3
		WHERE id = (SELECT id FROM jobs j WHERE type = ANY($4) AND ((state='queued' AND run_after <= $3) OR (state='running' AND lease_expires_at < $3))
		-- Tenant fairness (TEN-018): an organization with $5 jobs running waits.
		AND (j.organization_id IS NULL OR $5 <= 0 OR (SELECT count(*) FROM jobs r WHERE r.organization_id=j.organization_id AND r.state='running'
			AND r.lease_expires_at >= $3) < $5)
		ORDER BY run_after LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+jobCols, worker, now.Add(lease), now, types, perOrg))
		return err
	})
	if err != nil {
		if storage.IsNoRows(err) {
			return false, nil
		}
		return false, err
	}
	claimID, claimAttempt := j.ID, j.Attempts
	j.leaseGuard = func(ctx context.Context, tx pgx.Tx) error {
		var owned bool
		err := tx.QueryRow(ctx, `SELECT true FROM jobs WHERE id=$1 AND state='running' AND lease_owner=$2
			AND attempts=$3 AND lease_expires_at>$4 FOR UPDATE`, claimID, worker, claimAttempt, s.d.Now()).Scan(&owned)
		if storage.IsNoRows(err) {
			return ErrLeaseLost
		}
		return err
	}
	finish := func(query string, args ...any) error {
		tag, err := s.d.DB.Pool.Exec(ctx, query, args...)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		return err
	}
	if j.CancelRequested {
		err := finish(`UPDATE jobs SET state='cancelled', finished_at=$2, lease_owner=NULL, lease_expires_at=NULL WHERE id=$1
			AND state='running' AND lease_owner=$3 AND attempts=$4 AND lease_expires_at>$2`, claimID, s.d.Now(), worker, claimAttempt)
		return true, err
	}
	progress := func(p map[string]any) error {
		b, _ := json.Marshal(p)
		var cancel bool
		err := s.d.DB.Pool.QueryRow(ctx, `UPDATE jobs SET progress=$2, checkpoint=$2, lease_expires_at=$3, updated_at=$4 WHERE id=$1 AND lease_owner=$5
			AND state='running' AND attempts=$6 AND lease_expires_at>$4
			RETURNING cancel_requested`, claimID, b, s.d.Now().Add(lease), s.d.Now(), worker, claimAttempt).Scan(&cancel)
		if err != nil {
			if storage.IsNoRows(err) {
				return ErrLeaseLost
			}
			return err
		}
		if cancel {
			return context.Canceled
		}
		return nil
	}
	res, protected, runErr := handlers[j.Type](ctx, j, progress)
	if runErr != nil {
		if errors.Is(runErr, ErrLeaseLost) {
			return true, ErrLeaseLost
		}
		if errors.Is(runErr, context.Canceled) {
			err := finish(`UPDATE jobs SET state='cancelled', finished_at=$2, lease_owner=NULL, lease_expires_at=NULL, input_ciphertext=NULL WHERE id=$1
				AND state='running' AND lease_owner=$3 AND attempts=$4 AND lease_expires_at>$2`, claimID, s.d.Now(), worker, claimAttempt)
			return true, err
		}
		state := "queued"
		if errors.Is(runErr, ErrPermanent) || claimAttempt >= j.maxAttempts {
			state = "dead_letter"
		}
		backoff := time.Duration(1<<min(j.Attempts, 8)) * 5 * time.Second
		err := finish(`UPDATE jobs SET state=$2::text, last_error=$3, run_after=$4, lease_owner=NULL, lease_expires_at=NULL, updated_at=$5::timestamptz,
			finished_at=CASE WHEN $2::text='dead_letter' THEN $5::timestamptz ELSE NULL END,
			input_ciphertext=CASE WHEN $2::text='dead_letter' THEN NULL ELSE input_ciphertext END WHERE id=$1
			AND state='running' AND lease_owner=$6 AND attempts=$7 AND lease_expires_at>$5`, claimID, state, truncate(runErr.Error(), 300), s.d.Now().Add(backoff), s.d.Now(), worker, claimAttempt)
		if err == nil && state == "dead_letter" && s.OnDeadLetter != nil {
			s.OnDeadLetter(j.Type)
		}
		return true, err
	}
	rb, _ := json.Marshal(res)
	var ct []byte
	var ver *int
	var expires *time.Time
	if protected != nil {
		c, v, err := s.d.Keys.Encrypt(keys.PurposeData, protected, []byte("job:"+j.ID))
		if err != nil {
			return true, err
		}
		ct, ver = c, &v
		e := s.d.Now().Add(s.d.Cfg.Privacy.ExportRetention)
		expires = &e
	}
	// A job of an organization that started being deleted while the job ran
	// stores no result: the deletion erases organization data and must not
	// be undone by a late write (TEN-024, PRV-005). The organization
	// deletion job itself is exempt.
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE jobs SET state='succeeded', result=$2, result_ciphertext=$3, key_version=$4, result_expires_at=$5,
		finished_at=$6, lease_owner=NULL, lease_expires_at=NULL, updated_at=$6, input_ciphertext=NULL WHERE id=$1
		AND state='running' AND lease_owner=$7 AND attempts=$8 AND lease_expires_at>$6
		AND (type = 'organization.delete' OR organization_id IS NULL OR organization_id = ''
			OR NOT EXISTS (SELECT 1 FROM organizations o WHERE o.id = jobs.organization_id AND o.state IN ('deleting','deleted')))`,
		claimID, rb, ct, ver, expires, s.d.Now(), worker, claimAttempt)
	if err == nil && tag.RowsAffected() == 0 {
		err = finish(`UPDATE jobs SET state='cancelled', last_error='organization deleted while the job ran', finished_at=$2,
			lease_owner=NULL, lease_expires_at=NULL, updated_at=$2, input_ciphertext=NULL, result_ciphertext=NULL WHERE id=$1
			AND state='running' AND lease_owner=$3 AND attempts=$4 AND lease_expires_at>$2`, claimID, s.d.Now(), worker, claimAttempt)
	}
	return true, err
}

// RequiredPermission is the realm permission a job's requester must still
// hold when the job runs and when its result is downloaded (INT-006): losing
// the permission after enqueueing never leaves a way to the data.
//
// Jobs whose authority depends on their input re-check it in their handler
// instead: user.bulk needs the permission of its action (identity.BulkActions,
// what enqueueing it required), organization.delete needs org.delete in the
// organization being deleted.
func RequiredPermission(jobType string) string {
	return map[string]string{
		"audit.export":  "realm.audit.export",
		"config.export": "realm.configuration.export",
		"realm.export":  "realm.data.export",
		"user.import":   "realm.users.import",
	}[jobType]
}

// IssueDownload creates a short-lived single-use download credential for a job's
// protected result, only for the requester (PRV-008, MIG-015).
func (s *Service) IssueDownload(ctx context.Context, realmID, jobID, requesterID string) (string, error) {
	j, err := s.Get(ctx, realmID, jobID)
	if err != nil {
		return "", err
	}
	if j.RequestedByID != requesterID {
		return "", problem.ErrNotFound
	}
	if j.State != "succeeded" || !j.HasProtectedResult || j.ResultExpiresAt == nil || s.d.Now().After(*j.ResultExpiresAt) {
		return "", problem.ErrConflict.WithDetail("no downloadable result")
	}
	tok := secret.Token(secret.PrefixDownload)
	_, err = s.d.DB.Pool.Exec(ctx, `INSERT INTO job_download_tokens (id, job_id, token_digest, requested_by_id, expires_at) VALUES ($1,$2,$3,$4,$5)`,
		ids.New(ids.DownloadToken), jobID, secret.Digest(tok), requesterID, s.d.Now().Add(5*time.Minute))
	return tok, err
}

// Downloaded is a protected job result released through a download
// credential, with the media type and file name it is served as.
type Downloaded struct {
	JobID       string
	JobType     string
	Data        []byte
	ContentType string
	Filename    string
}

// ResultMedia names the media type and file name of a job type's protected
// result: audit and realm exports are NDJSON (one record per line), every
// other result is a single JSON document.
func ResultMedia(jobType string) (contentType, filename string) {
	switch jobType {
	case "audit.export", "realm.export":
		return "application/x-ndjson", "export.ndjson"
	}
	return "application/json", "export.json"
}

// Download consumes a download credential and returns the decrypted result.
// The audit actor is the requester as authenticated (a user or a service
// principal). authorize, when set, runs before the credential is spent: the
// requester must still hold the authority the job needed when the result is
// redeemed, not only when the credential was issued (INT-006).
func (s *Service) Download(ctx context.Context, realmID, tok string, requester audit.Ref, authorize func(jobType string) error) (*Downloaded, error) {
	var out Downloaded
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var by string
		if err := tx.QueryRow(ctx, `UPDATE job_download_tokens SET consumed_at=$2 WHERE token_digest=$1 AND consumed_at IS NULL AND expires_at > $2
			RETURNING job_id, requested_by_id`, secret.Digest(tok), s.d.Now()).Scan(&out.JobID, &by); err != nil {
			return problem.ErrNotFound
		}
		if by != requester.ID {
			return problem.ErrNotFound
		}
		var ct []byte
		var realm string
		if err := tx.QueryRow(ctx, `SELECT coalesce(realm_id,''), type, result_ciphertext FROM jobs WHERE id=$1`, out.JobID).Scan(&realm, &out.JobType, &ct); err != nil ||
			ct == nil || realm != realmID {
			return problem.ErrNotFound
		}
		if authorize != nil {
			// Refusing rolls back, so the credential is not spent.
			if err := authorize(out.JobType); err != nil {
				return err
			}
		}
		pt, err := s.d.Keys.Decrypt(keys.PurposeData, ct, []byte("job:"+out.JobID))
		if err != nil {
			return err
		}
		out.Data = pt
		out.ContentType, out.Filename = ResultMedia(out.JobType)
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "job.result.downloaded", RealmID: realmID, Actor: requester,
			Target: &audit.Ref{Type: "job", ID: out.JobID}, Category: "privacy"})
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// PurgeResults deletes expired protected results (OPS-009, PRV-004).
func (s *Service) PurgeResults(ctx context.Context) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE jobs SET result_ciphertext=NULL WHERE result_ciphertext IS NOT NULL AND result_expires_at < $1`, s.d.Now())
	if err != nil {
		return 0, err
	}
	// Cancelled-while-queued jobs never ran; erase their protected input too.
	if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE jobs SET input_ciphertext=NULL WHERE input_ciphertext IS NOT NULL AND state IN ('cancelled','succeeded','failed','dead_letter')`); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), err
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
