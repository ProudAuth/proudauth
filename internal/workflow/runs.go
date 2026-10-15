package workflow

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// Run is one execution of a workflow revision for one subject.
type Run struct {
	ID               string         `json:"id"`
	WorkflowID       string         `json:"workflow_id"`
	OrganizationID   string         `json:"organization_id,omitempty"`
	Revision         int            `json:"revision"`
	DefinitionHash   string         `json:"definition_hash"`
	SchemaVersion    int            `json:"schema_version"`
	TriggerType      string         `json:"trigger_type"`
	TriggerEventType string         `json:"trigger_event_type,omitempty"`
	SubjectType      string         `json:"subject_type"`
	SubjectID        string         `json:"subject_id"`
	Input            map[string]any `json:"input"`
	InputVersion     int            `json:"input_version"`
	AccountableID    string         `json:"accountable_id"`
	StartedByID      string         `json:"started_by_id,omitempty"`
	Depth            int            `json:"depth"`
	State            string         `json:"state"`
	StepIndex        int            `json:"step_index"`
	Context          map[string]any `json:"context"`
	NextRunAt        time.Time      `json:"next_run_at"`
	CancelRequested  bool           `json:"cancel_requested"`
	ErrorCategory    string         `json:"error_category,omitempty"`
	LastError        string         `json:"last_error,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	FinishedAt       *time.Time     `json:"finished_at,omitempty"`
	Attempts         []Attempt      `json:"attempts,omitempty"`
	Approvals        []Approval     `json:"approvals,omitempty"`
	realmID          string
}

const runCols = `id, realm_id, workflow_id, coalesce(organization_id,''), revision_number, definition_hash, schema_version, trigger_type,
	coalesce(trigger_event_type,''), subject_type, subject_id, input, input_version, accountable_id, coalesce(started_by_id,''), depth, state,
	step_index, context, next_run_at, cancel_requested, coalesce(error_category,''), coalesce(last_error,''), created_at, updated_at, finished_at`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	var in, cx []byte
	err := row.Scan(&r.ID, &r.realmID, &r.WorkflowID, &r.OrganizationID, &r.Revision, &r.DefinitionHash, &r.SchemaVersion, &r.TriggerType,
		&r.TriggerEventType, &r.SubjectType, &r.SubjectID, &in, &r.InputVersion, &r.AccountableID, &r.StartedByID, &r.Depth, &r.State,
		&r.StepIndex, &cx, &r.NextRunAt, &r.CancelRequested, &r.ErrorCategory, &r.LastError, &r.CreatedAt, &r.UpdatedAt, &r.FinishedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(in, &r.Input)
	_ = json.Unmarshal(cx, &r.Context)
	if r.Context == nil {
		r.Context = map[string]any{}
	}
	return &r, nil
}

// Attempt is one attempt of one step (EXT-016).
type Attempt struct {
	ID                   string         `json:"id"`
	StepIndex            int            `json:"step_index"`
	StepID               string         `json:"step_id"`
	StepType             string         `json:"step_type"`
	Attempt              int            `json:"attempt"`
	IdempotencyKey       string         `json:"idempotency_key"`
	State                string         `json:"state"`
	Input                map[string]any `json:"input"`
	InputVersion         string         `json:"input_version"`
	Result               map[string]any `json:"result,omitempty"`
	ErrorCategory        string         `json:"error_category,omitempty"`
	Error                string         `json:"error,omitempty"`
	MaxAttempts          int            `json:"max_attempts"`
	BackoffMS            int64          `json:"backoff_ms"`
	Compensation         string         `json:"compensation"`
	CompensationState    string         `json:"compensation_state,omitempty"`
	CompensationAttempts int            `json:"compensation_attempts"`
	CompensationResult   map[string]any `json:"compensation_result,omitempty"`
	StartedAt            time.Time      `json:"started_at"`
	FinishedAt           *time.Time     `json:"finished_at,omitempty"`
	CompensatedAt        *time.Time     `json:"compensated_at,omitempty"`
}

const attemptCols = `id, step_index, step_id, step_type, attempt, idempotency_key, state, input, input_version, result, coalesce(error_category,''),
	coalesce(error,''), max_attempts, backoff_ms, compensation, coalesce(compensation_state,''), compensation_attempts, compensation_result,
	started_at, finished_at, compensated_at`

func scanAttempt(row pgx.Row) (*Attempt, error) {
	var a Attempt
	var in, res, comp []byte
	err := row.Scan(&a.ID, &a.StepIndex, &a.StepID, &a.StepType, &a.Attempt, &a.IdempotencyKey, &a.State, &in, &a.InputVersion, &res, &a.ErrorCategory,
		&a.Error, &a.MaxAttempts, &a.BackoffMS, &a.Compensation, &a.CompensationState, &a.CompensationAttempts, &comp, &a.StartedAt, &a.FinishedAt,
		&a.CompensatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(in, &a.Input)
	if res != nil {
		_ = json.Unmarshal(res, &a.Result)
	}
	if comp != nil {
		_ = json.Unmarshal(comp, &a.CompensationResult)
	}
	return &a, nil
}

// Approval is an approval step's decision record.
type Approval struct {
	ID          string     `json:"id"`
	RunID       string     `json:"run_id"`
	WorkflowID  string     `json:"workflow_id"`
	StepIndex   int        `json:"step_index"`
	SubjectID   string     `json:"subject_id"`
	ApproverIDs []string   `json:"approver_ids"`
	State       string     `json:"state"`
	DecidedByID string     `json:"decided_by_id,omitempty"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	Comment     string     `json:"comment,omitempty"`
	ExpiresAt   time.Time  `json:"expires_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

const approvalCols = `id, run_id, workflow_id, step_index, subject_id, approver_ids, state, coalesce(decided_by_id,''), decided_at, coalesce(comment,''),
	expires_at, created_at`

func scanApproval(row pgx.Row) (*Approval, error) {
	var a Approval
	err := row.Scan(&a.ID, &a.RunID, &a.WorkflowID, &a.StepIndex, &a.SubjectID, &a.ApproverIDs, &a.State, &a.DecidedByID, &a.DecidedAt, &a.Comment,
		&a.ExpiresAt, &a.CreatedAt)
	return &a, err
}

// GetRun returns a run with its attempts and approvals.
func (s *Service) GetRun(ctx context.Context, realmID, id string) (*Run, error) {
	r, err := scanRun(s.d.DB.Pool.QueryRow(ctx, `SELECT `+runCols+` FROM workflow_runs WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+attemptCols+` FROM workflow_step_attempts WHERE run_id=$1 ORDER BY step_index, attempt`, id)
	if err != nil {
		return nil, err
	}
	r.Attempts = []Attempt{}
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		r.Attempts = append(r.Attempts, *a)
	}
	rows.Close()
	r.Approvals, err = s.approvals(ctx, `run_id=$1`, id)
	return r, err
}

func (s *Service) approvals(ctx context.Context, where string, args ...any) ([]Approval, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+approvalCols+` FROM workflow_approvals WHERE `+where+` ORDER BY created_at, id LIMIT 500`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Approval{}
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// RunFilter narrows a run listing.
type RunFilter struct {
	WorkflowID string
	SubjectID  string
	State      string
	Limit      int
	// Before pages backwards from (BeforeAt, BeforeID).
	BeforeAt *time.Time
	BeforeID string
}

// RunStates are the run states.
var RunStates = []string{"pending", "running", "waiting", "awaiting_approval", "compensating", "succeeded", "failed", "compensated",
	"compensation_failed", "cancelled"}

// ListRuns lists runs, newest first, without attempts.
func (s *Service) ListRuns(ctx context.Context, realmID string, f RunFilter) ([]*Run, error) {
	if f.State != "" && !slices.Contains(RunStates, f.State) {
		return nil, problem.ErrValidation.WithField("state", "unknown run state")
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+runCols+` FROM workflow_runs WHERE realm_id=$1 AND ($2='' OR workflow_id=$2) AND ($3='' OR subject_id=$3)
		AND ($4='' OR state=$4) AND ($5::timestamptz IS NULL OR (created_at, id) < ($5, $6)) ORDER BY created_at DESC, id DESC LIMIT $7`,
		realmID, f.WorkflowID, f.SubjectID, f.State, f.BeforeAt, f.BeforeID, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Run{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CancelRun asks the worker to stop a run: what it already did is
// compensated like a failure, then the run ends cancelled.
func (s *Service) CancelRun(ctx context.Context, realmID, id string, actor audit.Ref) (*Run, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE workflow_runs SET cancel_requested=true, next_run_at=$3, updated_at=$3
			WHERE realm_id=$1 AND id=$2 AND state IN ('pending','running','waiting','awaiting_approval') AND NOT cancel_requested`, realmID, id, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workflow_runs WHERE realm_id=$1 AND id=$2)`, realmID, id).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return problem.ErrNotFound
			}
			return problem.ErrConflict.WithDetail("the run already finished or is being cancelled")
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.run.cancel_requested", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "workflow_run", ID: id}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, realmID, id)
}

// Diagnostics summarizes a workflow's recent runs and step outcomes
// (EXT-017): counts, failure categories and latency, never inputs, results
// or subjects.
type Diagnostics struct {
	Health            string         `json:"health"`
	Runs              map[string]int `json:"runs_by_state"`
	StepFailures      map[string]int `json:"step_failures_by_category"`
	RecentAttempts    int            `json:"recent_attempts"`
	RecentFailures    int            `json:"recent_failed_attempts"`
	RunDurationP50MS  int64          `json:"run_duration_p50_ms"`
	RunDurationP95MS  int64          `json:"run_duration_p95_ms"`
	PendingApprovals  int            `json:"pending_approvals"`
	OldestDueSeconds  int            `json:"oldest_due_seconds"`
	CompensationFails int            `json:"compensation_failures"`
}

// Diagnose reports a workflow's health over its last 500 runs.
func (s *Service) Diagnose(ctx context.Context, realmID, id string) (*Diagnostics, error) {
	if _, err := s.Get(ctx, realmID, id); err != nil {
		return nil, err
	}
	d := &Diagnostics{Runs: map[string]int{}, StepFailures: map[string]int{}}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT state, count(*) FROM (SELECT state FROM workflow_runs WHERE realm_id=$1 AND workflow_id=$2
		ORDER BY created_at DESC LIMIT 500) x GROUP BY state`, realmID, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			rows.Close()
			return nil, err
		}
		d.Runs[st] = n
	}
	rows.Close()
	rows, err = s.d.DB.Pool.Query(ctx, `SELECT a.state, coalesce(a.error_category,''), a.compensation_state FROM workflow_step_attempts a
		JOIN workflow_runs r ON r.id=a.run_id WHERE r.realm_id=$1 AND r.workflow_id=$2 ORDER BY a.started_at DESC LIMIT 1000`, realmID, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var st, cat string
		var comp *string
		if err := rows.Scan(&st, &cat, &comp); err != nil {
			rows.Close()
			return nil, err
		}
		d.RecentAttempts++
		if st == "failed" {
			d.RecentFailures++
			d.StepFailures[cat]++
		}
		if comp != nil && *comp == "failed" {
			d.CompensationFails++
		}
	}
	rows.Close()
	var p50, p95 *float64
	var oldest *time.Time
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY ms), percentile_cont(0.95) WITHIN GROUP (ORDER BY ms)
		FROM (SELECT extract(epoch FROM finished_at - created_at)*1000 AS ms FROM workflow_runs WHERE realm_id=$1 AND workflow_id=$2 AND finished_at IS NOT NULL
		ORDER BY finished_at DESC LIMIT 500) x`, realmID, id).Scan(&p50, &p95); err != nil {
		return nil, err
	}
	if p50 != nil {
		d.RunDurationP50MS, d.RunDurationP95MS = int64(*p50), int64(*p95)
	}
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM workflow_approvals WHERE realm_id=$1 AND workflow_id=$2 AND state='pending'),
		(SELECT min(next_run_at) FROM workflow_runs WHERE realm_id=$1 AND workflow_id=$2 AND state IN ('pending','running','compensating'))`,
		realmID, id).Scan(&d.PendingApprovals, &oldest); err != nil {
		return nil, err
	}
	if oldest != nil && oldest.Before(s.d.Now()) {
		d.OldestDueSeconds = int(s.d.Now().Sub(*oldest).Seconds())
	}
	finished := d.Runs["succeeded"] + d.Runs["failed"] + d.Runs["compensated"] + d.Runs["compensation_failed"] + d.Runs["cancelled"]
	switch {
	case finished == 0 && d.RecentAttempts == 0:
		d.Health = "unknown"
	case d.CompensationFails > 0 || d.Runs["compensation_failed"] > 0:
		d.Health = "attention_required"
	case d.RecentFailures*10 > d.RecentAttempts:
		d.Health = "degraded"
	default:
		d.Health = "healthy"
	}
	return d, nil
}
