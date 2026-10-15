package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/contracts"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/notification"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/webhooks"
)

// maxTransitions bounds the steps one claim advances, so a long workflow
// yields the worker to other runs.
const maxTransitions = 25

// maxCompensationAttempts bounds the retries of one compensation before the
// run ends compensation_failed and needs an operator.
const maxCompensationAttempts = 5

// withRun correlates everything a run records: audit events and outbox
// events it causes carry the run ID as request ID / correlation ID
// (API-012), which also lets the dispatcher recognize workflow-caused events.
func withRun(ctx context.Context, runID string) context.Context {
	info := reqctx.From(ctx)
	info.RequestID = runID
	return reqctx.With(ctx, info)
}

// stepError is a classified step failure.
type stepError struct {
	category  string
	msg       string
	permanent bool
}

func (e *stepError) Error() string { return e.category + ": " + e.msg }

func permanent(category, msg string) error {
	return &stepError{category: category, msg: msg, permanent: true}
}

// classify reduces an error to a stable category and decides whether a
// retry can help. Refusals (validation, authority, conflicts) are permanent;
// infrastructure errors are retried.
func classify(err error) (string, string, bool) {
	var se *stepError
	if errors.As(err, &se) {
		return se.category, se.msg, se.permanent
	}
	if pe, ok := problem.As(err); ok && pe.Status < 500 {
		msg := pe.Detail
		if msg == "" {
			msg = pe.Title
		}
		for k, v := range pe.Fields {
			msg += " (" + k + ": " + v + ")"
		}
		return pe.Code, canonical.Truncate(msg, 300), true
	}
	return "error", "internal error; retried", false
}

type executor struct {
	s      *Service
	worker string
	lease  time.Duration
}

// RunDue claims due runs under leases and advances each (EXT-015). A run is
// claimed by one worker at a time; every write it makes is conditional on
// still holding the lease, so a worker that lost its lease never applies an
// effect another worker may also apply (EXT-016). Runs of disabled workflows
// pause, except compensation and cancellation, which only remove access.
func (s *Service) RunDue(ctx context.Context, worker string, batch int, lease time.Duration, share int) (int, error) {
	// Runs are advanced one after another after the claim; a bounded batch
	// keeps the last one well inside its lease and the task's deadline.
	if batch <= 0 || batch > 50 {
		batch = 50
	}
	if share <= 0 || share > batch {
		share = batch
	}
	now := s.d.Now()
	rows, err := s.d.DB.Pool.Query(ctx, `UPDATE workflow_runs SET lease_owner=$1, lease_expires_at=$2
		WHERE id IN (SELECT id FROM (
			-- Fair share (TEN-018): one realm's backlog cannot starve the others.
			SELECT r.id, r.next_run_at, row_number() OVER (PARTITION BY r.realm_id ORDER BY r.next_run_at) AS rn
			FROM workflow_runs r JOIN workflows w ON w.id=r.workflow_id
			WHERE r.state IN ('pending','running','waiting','awaiting_approval','compensating') AND r.next_run_at <= $3
			AND (r.lease_expires_at IS NULL OR r.lease_expires_at < $3)
			AND (w.state='active' OR r.state='compensating' OR r.cancel_requested)) due
			WHERE rn <= $5 ORDER BY next_run_at LIMIT $4)
		-- Checked again on the row version the update finds (DEP-011): the
		-- window above reads this statement's snapshot, so a run another
		-- worker claimed, finished or parked for later since is skipped
		-- instead of being claimed and advanced early or twice.
		AND state IN ('pending','running','waiting','awaiting_approval','compensating') AND next_run_at <= $3
		AND (lease_expires_at IS NULL OR lease_expires_at < $3)
		RETURNING `+runCols, worker, now.Add(lease), now, batch, share)
	if err != nil {
		return 0, err
	}
	var runs []*Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		runs = append(runs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	ex := &executor{s: s, worker: worker, lease: lease}
	for _, r := range runs {
		ex.advance(ctx, r)
	}
	return len(runs), nil
}

// ReleaseLeases hands back the runs a stopping worker holds (OPS-012).
func (s *Service) ReleaseLeases(ctx context.Context, worker string) (int64, error) {
	tag, err := s.d.DB.Pool.Exec(ctx, `UPDATE workflow_runs SET lease_owner=NULL, lease_expires_at=NULL WHERE lease_owner=$1`, worker)
	return tag.RowsAffected(), err
}

func terminal(state string) bool {
	switch state {
	case "succeeded", "failed", "compensated", "compensation_failed", "cancelled":
		return true
	}
	return false
}

func (ex *executor) actor(r *Run) audit.Ref { return audit.Ref{Type: "user", ID: r.AccountableID} }

// lock renews the lease inside tx and fails when another worker took the run.
func (ex *executor) lock(ctx context.Context, tx pgx.Tx, r *Run) error {
	now := ex.s.d.Now()
	tag, err := tx.Exec(ctx, `UPDATE workflow_runs SET lease_expires_at=$3, updated_at=$4 WHERE id=$1 AND lease_owner=$2`, r.ID, ex.worker, now.Add(ex.lease), now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errLeaseLost
	}
	return nil
}

func (ex *executor) tx(ctx context.Context, r *Run, fn func(tx pgx.Tx) error) error {
	return ex.s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := ex.lock(ctx, tx, r); err != nil {
			return err
		}
		return fn(tx)
	})
}

// park releases the run until at.
func (ex *executor) park(ctx context.Context, r *Run, state string, at time.Time) {
	_, err := ex.s.d.DB.Pool.Exec(ctx, `UPDATE workflow_runs SET state=$3, next_run_at=$4, lease_owner=NULL, lease_expires_at=NULL, updated_at=$5
		WHERE id=$1 AND lease_owner=$2`, r.ID, ex.worker, state, at, ex.s.d.Now())
	if err != nil {
		ex.s.d.Log.Warn("workflow run could not be parked; its lease expires instead", "run_id", r.ID, "error", err)
	}
	r.State, r.NextRunAt = state, at
}

func (ex *executor) advance(ctx context.Context, r *Run) {
	ctx = withRun(ctx, r.ID)
	// The claim may be a while ago (earlier runs of the batch were slow):
	// continue only while the lease is still ours and unexpired.
	now := ex.s.d.Now()
	tag, err := ex.s.d.DB.Pool.Exec(ctx, `UPDATE workflow_runs SET lease_expires_at=$3 WHERE id=$1 AND lease_owner=$2 AND lease_expires_at > $4`,
		r.ID, ex.worker, now.Add(ex.lease), now)
	if err != nil || tag.RowsAffected() == 0 {
		return
	}
	def, _, derr := ex.s.definitionAt(ctx, ex.s.d.DB.Pool, r.realmID, r.WorkflowID, r.Revision)
	if derr != nil && !terminal(r.State) && r.State != "compensating" {
		if !ex.failRun(ctx, r, "definition_unavailable", "the run's revision cannot be read") {
			return
		}
	}
	for i := 0; i < maxTransitions; i++ {
		if r.CancelRequested && !terminal(r.State) && r.State != "compensating" {
			if !ex.failRun(ctx, r, "cancelled", "cancelled by an administrator") {
				return
			}
			continue
		}
		switch {
		case r.State == "compensating":
			ex.compensate(ctx, r, def)
			return
		case terminal(r.State):
			ex.park(ctx, r, r.State, r.NextRunAt)
			return
		case def == nil:
			return
		case r.StepIndex >= len(def.Steps):
			ex.finish(ctx, r)
			return
		}
		if !ex.step(ctx, r, def, def.Steps[r.StepIndex]) {
			return
		}
	}
	// Yield: due again at once, after other runs had their turn.
	ex.park(ctx, r, r.State, ex.s.d.Now())
}

// base is the attempt row a step is about to record.
type base struct {
	id, key, inputVersion string
	idx, attempt, max     int
	backoff               time.Duration
	st                    Step
	input                 map[string]any
}

func (ex *executor) newBase(r *Run, def *Definition, st Step, attempt int) base {
	max, backoff := def.Policy(st)
	hash := r.DefinitionHash
	if len(hash) > 16 {
		hash = hash[:16]
	}
	in := map[string]any{"subject_id": r.SubjectID}
	if r.OrganizationID != "" {
		in["organization_id"] = r.OrganizationID
	}
	b, _ := json.Marshal(st)
	var params map[string]any
	_ = json.Unmarshal(b, &params)
	delete(params, "id")
	delete(params, "type")
	delete(params, "retry")
	in["parameters"] = params
	return base{id: newID(prefixAttempt), key: r.ID + "." + st.ID, inputVersion: fmt.Sprintf("r%d:%s:i%d", r.Revision, hash, r.InputVersion),
		idx: r.StepIndex, attempt: attempt, max: max, backoff: backoff, st: st, input: in}
}

// insertAttempt records an attempt in tx.
func (ex *executor) insertAttempt(ctx context.Context, tx pgx.Tx, r *Run, b base, state string, result map[string]any, compState, errCat, errMsg string) error {
	in, _ := json.Marshal(b.input)
	var res []byte
	if result != nil {
		res, _ = json.Marshal(result)
	}
	now := ex.s.d.Now()
	var finished *time.Time
	if state != "started" {
		finished = &now
	}
	_, err := tx.Exec(ctx, `INSERT INTO workflow_step_attempts (id, realm_id, run_id, step_index, step_id, step_type, attempt, idempotency_key, state,
		input, input_version, result, error_category, error, max_attempts, backoff_ms, compensation, compensation_state, started_at, finished_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, b.id, r.realmID, r.ID, b.idx, b.st.ID, b.st.Type, b.attempt, b.key,
		state, in, b.inputVersion, res, nilIfEmpty(errCat), nilIfEmpty(errMsg), b.max, b.backoff.Milliseconds(), b.st.Compensation(), nilIfEmpty(compState), now, finished)
	return err
}

// succeedTx closes a started attempt (or records a new succeeded one) and
// advances the run, in the transaction that applied the effect.
func (ex *executor) succeedTx(ctx context.Context, tx pgx.Tx, r *Run, b base, existing bool, result map[string]any, compState string) error {
	if existing {
		res, _ := json.Marshal(result)
		tag, err := tx.Exec(ctx, `UPDATE workflow_step_attempts SET state='succeeded', result=$2, compensation_state=$3, finished_at=$4
			WHERE id=$1 AND state='started'`, b.id, res, compState, ex.s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errLeaseLost
		}
	} else if err := ex.insertAttempt(ctx, tx, r, b, "succeeded", result, compState, "", ""); err != nil {
		return err
	}
	cx := map[string]any{}
	for k, v := range r.Context {
		cx[k] = v
	}
	cx[b.st.ID] = summary(b.st, result)
	cb, _ := json.Marshal(cx)
	if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET step_index=$2, context=$3, state='running', error_category=NULL, last_error=NULL WHERE id=$1`,
		r.ID, b.idx+1, cb); err != nil {
		return err
	}
	if _, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.step.succeeded", RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
		Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID}, Category: "configuration",
		Metadata: map[string]any{"workflow_id": r.WorkflowID, "revision": r.Revision, "step_id": b.st.ID, "step_type": b.st.Type, "attempt": b.attempt,
			"idempotency_key": b.key, "compensation": b.st.Compensation(), "result": summary(b.st, result)}}); err != nil {
		return err
	}
	r.Context = cx
	return nil
}

// summary keeps the identifiers a later step or an operator needs.
func summary(st Step, result map[string]any) map[string]any {
	out := map[string]any{"type": st.Type}
	for k, v := range result {
		switch k {
		case "assignment_id", "already_assigned", "membership_id", "group_id", "organization_id", "added", "approval_id", "decided_by",
			"removed", "already_suspended", "sent", "status_code", "until", "removed_assignment_ids", "step_index":
			out[k] = v
		}
	}
	return out
}

// failRun moves the run to compensation in its own transaction and reports
// whether the caller may continue with the run.
func (ex *executor) failRun(ctx context.Context, r *Run, category, msg string) bool {
	err := ex.tx(ctx, r, func(tx pgx.Tx) error { return ex.failRunTx(ctx, tx, r, category, msg) })
	if err != nil {
		if !errors.Is(err, errLeaseLost) {
			ex.s.d.Log.Warn("workflow run could not be failed", "run_id", r.ID, "error", err)
			ex.park(ctx, r, r.State, ex.s.d.Now().Add(10*time.Second))
		}
		return false
	}
	return true
}

func (ex *executor) failRunTx(ctx context.Context, tx pgx.Tx, r *Run, category, msg string) error {
	now := ex.s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE workflow_step_attempts SET state='failed', error_category=$2, error=$3, finished_at=$4 WHERE run_id=$1 AND state='started'`,
		r.ID, category, canonical.Truncate(msg, 300), now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE workflow_approvals SET state='cancelled' WHERE run_id=$1 AND state='pending'`, r.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET state='compensating', error_category=$2, last_error=$3, next_run_at=$4 WHERE id=$1`,
		r.ID, category, canonical.Truncate(msg, 300), now); err != nil {
		return err
	}
	if _, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.run.failed", RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
		Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID}, Category: "configuration",
		Outcome: audit.Failure, ReasonCode: category, Metadata: map[string]any{"workflow_id": r.WorkflowID, "step_index": r.StepIndex}}); err != nil {
		return err
	}
	r.State, r.ErrorCategory, r.LastError = "compensating", category, msg
	return nil
}

// recordFailure records a failed attempt (closing a started one or adding a
// new row) and either schedules the retry or fails the run.
func (ex *executor) recordFailure(ctx context.Context, r *Run, b base, existing bool, cause error) bool {
	if errors.Is(cause, errLeaseLost) {
		return false
	}
	category, msg, perm := classify(cause)
	if !perm {
		ex.s.d.Log.Warn("workflow step failed", "run_id", r.ID, "step", b.st.ID, "attempt", b.attempt, "error", cause)
	}
	final := perm || b.attempt >= b.max
	retryAt := ex.s.d.Now().Add(backoff(b.backoff, b.attempt))
	err := ex.tx(ctx, r, func(tx pgx.Tx) error {
		if existing {
			if _, err := tx.Exec(ctx, `UPDATE workflow_step_attempts SET state='failed', error_category=$2, error=$3, finished_at=$4 WHERE id=$1 AND state='started'`,
				b.id, category, msg, ex.s.d.Now()); err != nil {
				return err
			}
		} else if err := ex.insertAttempt(ctx, tx, r, b, "failed", nil, "", category, msg); err != nil {
			return err
		}
		if _, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.step.failed", RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
			Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID}, Category: "configuration",
			Outcome: audit.Failure, ReasonCode: category, Metadata: map[string]any{"workflow_id": r.WorkflowID, "step_id": b.st.ID, "step_type": b.st.Type,
				"attempt": b.attempt, "max_attempts": b.max, "final": final}}); err != nil {
			return err
		}
		if final {
			return ex.failRunTx(ctx, tx, r, category, fmt.Sprintf("step %s failed after %d attempt(s): %s", b.st.ID, b.attempt, msg))
		}
		_, err := tx.Exec(ctx, `UPDATE workflow_runs SET state='running', error_category=$2, last_error=$3, next_run_at=$4, lease_owner=NULL,
			lease_expires_at=NULL WHERE id=$1`, r.ID, category, msg, retryAt)
		return err
	})
	if err != nil {
		if !errors.Is(err, errLeaseLost) {
			ex.s.d.Log.Warn("workflow step failure could not be recorded", "run_id", r.ID, "error", err)
			ex.park(ctx, r, r.State, ex.s.d.Now().Add(10*time.Second))
		}
		return false
	}
	if ex.s.Observe != nil {
		ex.s.Observe("step."+b.st.Type, "failed")
	}
	return final // a failed run continues into compensation; a retry waits
}

// backoff is base·2^(attempt-1) with up to 20% jitter, capped at six hours.
func backoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 30 * time.Second
	}
	const maxWait = 6 * time.Hour
	d := base << min(attempt-1, 12)
	if d > maxWait || d <= 0 {
		d = maxWait
	}
	// The cap holds with the jitter included.
	return min(d+time.Duration(rand.Int64N(int64(d/5)+1)), maxWait)
}

func (ex *executor) lastAttempt(ctx context.Context, r *Run, idx int) (*Attempt, error) {
	a, err := scanAttempt(ex.s.d.DB.Pool.QueryRow(ctx, `SELECT `+attemptCols+` FROM workflow_step_attempts WHERE run_id=$1 AND step_index=$2
		ORDER BY attempt DESC LIMIT 1`, r.ID, idx))
	if storage.IsNoRows(err) {
		return nil, nil
	}
	return a, err
}

// step executes or resumes the current step and reports whether the run may
// continue in this claim.
func (ex *executor) step(ctx context.Context, r *Run, def *Definition, st Step) bool {
	last, err := ex.lastAttempt(ctx, r, r.StepIndex)
	if err != nil {
		ex.s.d.Log.Warn("workflow attempt lookup failed", "run_id", r.ID, "error", err)
		ex.park(ctx, r, r.State, ex.s.d.Now().Add(10*time.Second))
		return false
	}
	n := 0
	if last != nil {
		n = last.Attempt
		if last.State == "started" {
			b := ex.newBase(r, def, st, last.Attempt)
			b.id, b.input = last.ID, last.Input
			switch st.Type {
			case StepWait:
				return ex.resumeWait(ctx, r, b, last)
			case StepApproval:
				return ex.resumeApproval(ctx, r, b, last)
			}
			// An endpoint call whose outcome was never recorded (a crash or
			// a lost lease). It is closed as interrupted and retried with the
			// same idempotency key, so the receiver deduplicates it.
			return ex.recordFailure(ctx, r, b, true, &stepError{category: "interrupted", msg: "the attempt's outcome was not recorded"})
		}
		if last.State == "succeeded" {
			// Defensive: the effect and the advance commit together, so a
			// succeeded attempt always advanced; never apply it twice.
			err := ex.tx(ctx, r, func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `UPDATE workflow_runs SET step_index=$2 WHERE id=$1`, r.ID, r.StepIndex+1)
				return err
			})
			if err != nil {
				return false
			}
			r.StepIndex++
			return true
		}
	}
	b := ex.newBase(r, def, st, n+1)
	if n >= b.max {
		return ex.failRun(ctx, r, "retries_exhausted", fmt.Sprintf("step %s failed after %d attempt(s)", st.ID, n))
	}
	switch st.Type {
	case StepWait:
		return ex.beginWait(ctx, r, b)
	case StepApproval:
		return ex.beginApproval(ctx, r, b)
	case StepCallWebhook:
		return ex.callEndpoint(ctx, r, b)
	}
	var result map[string]any
	var comp string
	err = ex.tx(ctx, r, func(tx pgx.Tx) error {
		org, err := ex.authorize(ctx, tx, r, st)
		if err != nil {
			return err
		}
		result, comp, err = ex.apply(ctx, tx, r, st, org)
		if err != nil {
			return err
		}
		return ex.succeedTx(ctx, tx, r, b, false, result, comp)
	})
	if err != nil {
		return ex.recordFailure(ctx, r, b, false, err)
	}
	r.StepIndex++
	if ex.s.Observe != nil {
		ex.s.Observe("step."+st.Type, "succeeded")
	}
	return true
}

// orgFor resolves the organization a step acts in: the group's, the pinned
// one, or the run's.
func (ex *executor) orgFor(ctx context.Context, tx pgx.Tx, r *Run, st Step) (string, error) {
	if st.GroupID != "" {
		org, err := ex.s.groupOrg(ctx, tx, r.realmID, st.GroupID)
		if err != nil {
			return "", permanent("group_missing", "the group no longer exists")
		}
		return org, nil
	}
	if st.OrganizationID != "" {
		return st.OrganizationID, nil
	}
	if st.orgScoped() && r.OrganizationID == "" {
		return "", permanent("organization_required", "the step acts in an organization but the run has none")
	}
	return r.OrganizationID, nil
}

// authorize re-checks, inside the effect's transaction, that the accountable
// publisher still holds the authority the step needs (AZ-006): a workflow
// stops when its publisher loses the authority, and never exceeds it.
func (ex *executor) authorize(ctx context.Context, tx pgx.Tx, r *Run, st Step) (string, error) {
	org, err := ex.orgFor(ctx, tx, r, st)
	if err != nil {
		return "", err
	}
	publisher := authorization.Subject{Type: authorization.SubjectUser, ID: r.AccountableID}
	if !ex.s.Authz.Check(ctx, tx, r.realmID, publisher, "realm.workflows.publish", realmScope(r.realmID)) {
		return "", permanent("publisher_lacks_authority", "the publisher no longer holds realm.workflows.publish")
	}
	if err := ex.s.checkStepAuthority(ctx, tx, r.realmID, publisher, st, org); err != nil {
		_, msg, _ := classify(err)
		return "", permanent("publisher_lacks_authority", msg)
	}
	return org, nil
}

func (ex *executor) subject(ctx context.Context, tx pgx.Tx, r *Run) (*identity.User, error) {
	u, err := ex.s.Users.User(ctx, tx, r.realmID, r.SubjectID)
	if err != nil {
		if problem.Is(err, problem.ErrNotFound) || storage.IsNoRows(err) {
			return nil, permanent("subject_missing", "the subject no longer exists")
		}
		return nil, err
	}
	if u.State == identity.StateDeleted || u.State == identity.StatePendingDeletion {
		return nil, permanent("subject_missing", "the subject is deleted or being deleted")
	}
	return u, nil
}

// apply performs one internal effect in tx and returns its result and
// compensation state.
func (ex *executor) apply(ctx context.Context, tx pgx.Tx, r *Run, st Step, org string) (map[string]any, string, error) {
	s := ex.s
	actor := ex.actor(r)
	publisher := authorization.Subject{Type: authorization.SubjectUser, ID: r.AccountableID}
	if st.Type == StepEnd {
		return map[string]any{"outcome": "succeeded"}, "not_needed", nil
	}
	u, err := ex.subject(ctx, tx, r)
	if err != nil {
		return nil, "", err
	}
	switch st.Type {
	case StepAssignRole:
		scope := realmScope(r.realmID)
		if st.Scope == "organization" {
			scope = orgScope(org)
		}
		var existing string
		err := tx.QueryRow(ctx, `SELECT id FROM role_assignments WHERE realm_id=$1 AND role_id=$2 AND subject_type='user' AND subject_id=$3
			AND scope_type=$4 AND scope_id=$5 LIMIT 1`, r.realmID, st.RoleID, u.ID, scope.Type, scope.ID).Scan(&existing)
		if err == nil {
			// Desired state already holds; the run created nothing to undo.
			return map[string]any{"assignment_id": existing, "already_assigned": true}, "not_needed", nil
		} else if !storage.IsNoRows(err) {
			return nil, "", err
		}
		in := authorization.AssignInput{RoleID: st.RoleID, Subject: authorization.Subject{Type: authorization.SubjectUser, ID: u.ID}, Scope: scope,
			Source: "workflow", Reason: stepReason(st.Reason, r.ID)}
		if st.ExpiresIn != "" {
			d, _ := time.ParseDuration(st.ExpiresIn)
			exp := s.d.Now().Add(d)
			in.ExpiresAt = &exp
		}
		// A role that requires an independent approver takes the decider of
		// the run's latest approval step (AZ-018); without one it fails.
		in.ApproverID = latestApprover(r)
		a, err := s.Authz.AssignTx(ctx, tx, r.realmID, &publisher, in, actor)
		if err != nil {
			return nil, "", err
		}
		res := map[string]any{"assignment_id": a.ID, "already_assigned": false}
		if a.ExpiresAt != nil {
			res["expires_at"] = a.ExpiresAt
		}
		return res, "pending", nil
	case StepAddToGroup:
		mid, err := ex.membership(ctx, tx, r, org, u.ID, true)
		if err != nil {
			return nil, "", err
		}
		var existed bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM group_memberships WHERE group_id=$1 AND membership_id=$2)`, st.GroupID, mid).Scan(&existed); err != nil {
			return nil, "", err
		}
		if err := s.Orgs.AddGroupMemberTx(ctx, tx, r.realmID, org, st.GroupID, mid, "workflow", actor); err != nil {
			return nil, "", err
		}
		res := map[string]any{"organization_id": org, "group_id": st.GroupID, "membership_id": mid, "added": !existed}
		if existed {
			return res, "not_needed", nil
		}
		return res, "pending", nil
	case StepRemove:
		reason := st.Reason
		if reason == "" {
			reason = "WORKFLOW"
		}
		switch st.Access {
		case "membership":
			var mid string
			err := tx.QueryRow(ctx, `SELECT id FROM memberships WHERE realm_id=$1 AND organization_id=$2 AND user_id=$3 AND state<>'removed'
				ORDER BY created_at DESC LIMIT 1`, r.realmID, org, u.ID).Scan(&mid)
			if storage.IsNoRows(err) {
				return map[string]any{"removed": false, "organization_id": org}, "not_needed", nil
			} else if err != nil {
				return nil, "", err
			}
			if err := s.Orgs.RemoveMemberTx(ctx, tx, r.realmID, org, mid, &publisher, actor, reason); err != nil {
				return nil, "", err
			}
			return map[string]any{"removed": true, "membership_id": mid, "organization_id": org}, "not_needed", nil
		case "role":
			scopeType, scopeID := "realm", r.realmID
			if st.Scope == "organization" {
				scopeType, scopeID = "organization", org
			}
			rows, err := tx.Query(ctx, `SELECT id FROM role_assignments WHERE realm_id=$1 AND role_id=$2 AND subject_type='user' AND subject_id=$3
				AND scope_type=$4 AND scope_id=$5`, r.realmID, st.RoleID, u.ID, scopeType, scopeID)
			if err != nil {
				return nil, "", err
			}
			var list []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return nil, "", err
				}
				list = append(list, id)
			}
			rows.Close()
			for _, id := range list {
				if err := s.Authz.UnassignTx(ctx, tx, r.realmID, id, &publisher, actor, false); err != nil {
					return nil, "", err
				}
			}
			if list == nil {
				list = []string{}
			}
			return map[string]any{"removed": len(list) > 0, "removed_assignment_ids": list}, "not_needed", nil
		default: // group
			mid, err := ex.membership(ctx, tx, r, org, u.ID, false)
			if err != nil {
				return nil, "", err
			}
			if mid == "" {
				return map[string]any{"removed": false, "group_id": st.GroupID}, "not_needed", nil
			}
			err = s.Orgs.RemoveGroupMemberTx(ctx, tx, r.realmID, org, st.GroupID, mid, actor)
			if problem.Is(err, problem.ErrNotFound) {
				return map[string]any{"removed": false, "group_id": st.GroupID}, "not_needed", nil
			} else if err != nil {
				return nil, "", err
			}
			return map[string]any{"removed": true, "group_id": st.GroupID, "membership_id": mid}, "not_needed", nil
		}
	case StepSuspend:
		if u.ID == r.AccountableID {
			return nil, "", permanent("self_action", "a workflow cannot suspend its accountable publisher")
		}
		if u.State == identity.StateSuspended {
			return map[string]any{"already_suspended": true}, "not_needed", nil
		}
		reason := st.Reason
		if reason == "" {
			reason = "WORKFLOW"
		}
		nu, err := s.Users.SetStateTx(ctx, tx, r.realmID, u.ID, identity.StateSuspended, actor, reason)
		if err != nil {
			return nil, "", err
		}
		// The suspension notice is queued with the change, as the
		// administration API does (MSG-002).
		if _, err := ex.notifyUserQueued(ctx, tx, r, nu, notification.TplAccountSuspended, nil); err != nil {
			return nil, "", err
		}
		return map[string]any{"already_suspended": false}, "not_needed", nil
	case StepNotify:
		var recipients []string
		if st.Recipient == "approvers" {
			var ap []string
			if err := tx.QueryRow(ctx, `SELECT approver_ids FROM workflow_approvals WHERE run_id=$1 ORDER BY step_index DESC LIMIT 1`, r.ID).Scan(&ap); err != nil {
				if storage.IsNoRows(err) {
					return nil, "", permanent("no_recipients", "the run has no approval step yet")
				}
				return nil, "", err
			}
			recipients = ap
		} else {
			recipients = []string{u.ID}
		}
		name, err := ex.workflowName(ctx, tx, r)
		if err != nil {
			return nil, "", err
		}
		sent := 0
		for _, id := range recipients {
			ru, err := s.Users.User(ctx, tx, r.realmID, id)
			if err != nil || ru.State != identity.StateActive && id != u.ID {
				continue
			}
			ok, err := ex.notifyNotice(ctx, tx, r, ru, name, st.Notice)
			if err != nil {
				return nil, "", err
			}
			if ok {
				sent++
			}
		}
		comp := "impossible"
		if sent == 0 {
			comp = "not_needed"
		}
		return map[string]any{"sent": sent, "notice": st.Notice}, comp, nil
	}
	return nil, "", permanent("unsupported_step", "unsupported step type "+st.Type)
}

// latestApprover is the decider of the run's latest approved approval step.
func latestApprover(r *Run) string {
	approver := ""
	latest := -1
	for _, v := range r.Context {
		m, ok := v.(map[string]any)
		if !ok || m["type"] != StepApproval {
			continue
		}
		d, _ := m["decided_by"].(string)
		idx := -1
		switch n := m["step_index"].(type) {
		case float64:
			idx = int(n)
		case int:
			idx = n
		}
		if d != "" && idx > latest {
			approver, latest = d, idx
		}
	}
	return approver
}

// membership finds the subject's membership in org (active only when
// required, otherwise "" when absent).
func (ex *executor) membership(ctx context.Context, tx pgx.Tx, r *Run, org, userID string, required bool) (string, error) {
	var mid string
	err := tx.QueryRow(ctx, `SELECT m.id FROM memberships m WHERE m.realm_id=$1 AND m.organization_id=$2 AND m.user_id=$3
		AND m.state=ANY($4) ORDER BY m.created_at DESC LIMIT 1`, r.realmID, org, userID, map[bool][]string{true: {"active"}, false: {"active", "suspended"}}[required]).Scan(&mid)
	if storage.IsNoRows(err) {
		if required {
			return "", permanent("not_a_member", "the subject has no active membership in the organization")
		}
		return "", nil
	}
	return mid, err
}

func (ex *executor) workflowName(ctx context.Context, tx pgx.Tx, r *Run) (string, error) {
	var name string
	err := tx.QueryRow(ctx, `SELECT name FROM workflows WHERE id=$1`, r.WorkflowID).Scan(&name)
	return name, err
}

func (ex *executor) realmName(ctx context.Context, q pgx.Tx, realmID string) string {
	if ex.s.Realms != nil {
		if rlm, err := ex.s.Realms.ByID(ctx, q, realmID); err == nil {
			if rlm.DisplayName != "" {
				return rlm.DisplayName
			}
			return rlm.Name
		}
	}
	return ""
}

// notifyNotice queues the workflow_notice template to a user's verified
// primary address and reports whether a message was queued.
func (ex *executor) notifyNotice(ctx context.Context, tx pgx.Tx, r *Run, u *identity.User, workflowName, notice string) (bool, error) {
	data := map[string]string{"workflow": workflowName, "notice": Notices[notice]}
	return ex.notifyUserQueued(ctx, tx, r, u, notification.TplWorkflowNotice, data)
}

func (ex *executor) notifyUserQueued(ctx context.Context, tx pgx.Tx, r *Run, u *identity.User, tpl string, data map[string]string) (bool, error) {
	e := u.PrimaryEmail()
	if e == nil || !e.Verified() {
		return false, nil
	}
	if data == nil {
		data = map[string]string{}
	}
	data["realm"] = ex.realmName(ctx, tx, r.realmID)
	data["time"] = notification.Timestamp(ex.s.d.Now())
	_, err := ex.s.Notify.EnqueueTx(ctx, tx, notification.Message{RealmID: r.realmID, Template: tpl, Recipient: e.Value, Mandatory: true,
		ReferenceType: "user", ReferenceID: u.ID, Data: data})
	return err == nil, err
}

// beginWait records the wait and parks the run until it ends.
func (ex *executor) beginWait(ctx context.Context, r *Run, b base) bool {
	d, _ := time.ParseDuration(b.st.Duration)
	until := ex.s.d.Now().Add(d)
	err := ex.tx(ctx, r, func(tx pgx.Tx) error {
		return ex.insertAttempt(ctx, tx, r, b, "started", map[string]any{"until": until}, "", "", "")
	})
	if err != nil {
		return ex.recordFailure(ctx, r, b, false, err)
	}
	ex.park(ctx, r, "waiting", until)
	return false
}

func (ex *executor) resumeWait(ctx context.Context, r *Run, b base, last *Attempt) bool {
	until, _ := time.Parse(time.RFC3339Nano, fmt.Sprint(last.Result["until"]))
	if ex.s.d.Now().Before(until) {
		ex.park(ctx, r, "waiting", until)
		return false
	}
	err := ex.tx(ctx, r, func(tx pgx.Tx) error {
		return ex.succeedTx(ctx, tx, r, b, true, last.Result, "not_needed")
	})
	if err != nil {
		return ex.recordFailure(ctx, r, b, true, err)
	}
	r.StepIndex++
	return true
}

// beginApproval opens the approval and notifies the approvers. The subject
// never approves their own access (AZ-018).
func (ex *executor) beginApproval(ctx context.Context, r *Run, b base) bool {
	d, _ := time.ParseDuration(b.st.ExpiresIn)
	expires := ex.s.d.Now().Add(d)
	approvalID := newID(prefixApproval)
	err := ex.tx(ctx, r, func(tx pgx.Tx) error {
		var eligible []string
		for _, a := range b.st.Approvers {
			if a == r.SubjectID {
				continue
			}
			u, err := ex.s.Users.User(ctx, tx, r.realmID, a)
			if err == nil && u.State == identity.StateActive {
				eligible = append(eligible, a)
			}
		}
		if len(eligible) == 0 {
			return permanent("no_eligible_approver", "no named approver is an active account other than the subject")
		}
		if err := ex.insertAttempt(ctx, tx, r, b, "started", map[string]any{"approval_id": approvalID, "expires_at": expires}, "", "", ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO workflow_approvals (id, realm_id, run_id, step_index, workflow_id, subject_id, approver_ids, state, expires_at, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8,$9)`, approvalID, r.realmID, r.ID, b.idx, r.WorkflowID, r.SubjectID, eligible, expires, ex.s.d.Now()); err != nil {
			return err
		}
		name, err := ex.workflowName(ctx, tx, r)
		if err != nil {
			return err
		}
		for _, a := range eligible {
			if u, err := ex.s.Users.User(ctx, tx, r.realmID, a); err == nil {
				if _, err := ex.notifyNotice(ctx, tx, r, u, name, "approval_requested"); err != nil {
					return err
				}
			}
		}
		_, err = ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.approval.requested", RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
			Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_approval", ID: approvalID}, Category: "configuration",
			Metadata: map[string]any{"run_id": r.ID, "workflow_id": r.WorkflowID, "approvers": eligible, "expires_at": expires}})
		return err
	})
	if err != nil {
		return ex.recordFailure(ctx, r, b, false, err)
	}
	ex.park(ctx, r, "awaiting_approval", expires)
	return false
}

func (ex *executor) resumeApproval(ctx context.Context, r *Run, b base, last *Attempt) bool {
	a, err := scanApproval(ex.s.d.DB.Pool.QueryRow(ctx, `SELECT `+approvalCols+` FROM workflow_approvals WHERE run_id=$1 AND step_index=$2`, r.ID, b.idx))
	if err != nil {
		return ex.recordFailure(ctx, r, b, true, permanent("approval_missing", "the approval record is missing"))
	}
	now := ex.s.d.Now()
	switch {
	case a.State == "approved":
		res := map[string]any{"approval_id": a.ID, "decided_by": a.DecidedByID, "step_index": b.idx}
		if err := ex.tx(ctx, r, func(tx pgx.Tx) error { return ex.succeedTx(ctx, tx, r, b, true, res, "not_needed") }); err != nil {
			return ex.recordFailure(ctx, r, b, true, err)
		}
		r.StepIndex++
		return true
	case a.State == "rejected":
		return ex.recordFailure(ctx, r, b, true, permanent("approval_rejected", "the approval was rejected"))
	case a.State == "pending" && !now.Before(a.ExpiresAt):
		err := ex.tx(ctx, r, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE workflow_approvals SET state='expired' WHERE id=$1 AND state='pending'`, a.ID); err != nil {
				return err
			}
			_, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.approval.expired", RealmID: r.realmID, OrgID: r.OrganizationID,
				Actor: audit.System, Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_approval", ID: a.ID},
				Category: "configuration", Metadata: map[string]any{"run_id": r.ID}})
			return err
		})
		if err != nil {
			return ex.recordFailure(ctx, r, b, true, err)
		}
		return ex.recordFailure(ctx, r, b, true, permanent("approval_expired", "no approver decided before the expiry"))
	case a.State == "pending":
		ex.park(ctx, r, "awaiting_approval", a.ExpiresAt)
		return false
	}
	return ex.recordFailure(ctx, r, b, true, permanent("approval_"+a.State, "the approval ended "+a.State))
}

// stepCall is the body of a call_webhook step (api/workflows/step-call.v1.json).
type stepCall struct {
	Type            string         `json:"type"`
	ContractVersion int            `json:"contract_version"`
	Action          string         `json:"action"`
	RealmID         string         `json:"realm_id"`
	OrganizationID  string         `json:"organization_id,omitempty"`
	WorkflowID      string         `json:"workflow_id"`
	Revision        int            `json:"revision"`
	RunID           string         `json:"run_id"`
	StepID          string         `json:"step_id"`
	Attempt         int            `json:"attempt"`
	IdempotencyKey  string         `json:"idempotency_key"`
	Subject         map[string]any `json:"subject"`
	Trigger         map[string]any `json:"trigger"`
	SentAt          time.Time      `json:"sent_at"`
}

func (ex *executor) callBody(r *Run, b base, action, key string, attempt int) []byte {
	trigger := map[string]any{"type": r.TriggerType}
	if r.TriggerEventType != "" {
		trigger["event_type"] = r.TriggerEventType
		if id, ok := r.Input["event_id"].(string); ok {
			trigger["event_id"] = id
		}
	}
	body, _ := json.Marshal(stepCall{Type: "workflow.step", ContractVersion: contracts.Default(contracts.WorkflowStepCall), Action: action, RealmID: r.realmID, OrganizationID: r.OrganizationID,
		WorkflowID: r.WorkflowID, Revision: r.Revision, RunID: r.ID, StepID: b.st.ID, Attempt: attempt, IdempotencyKey: key,
		Subject: map[string]any{"type": r.SubjectType, "id": r.SubjectID}, Trigger: trigger, SentAt: ex.s.d.Now()})
	return body
}

// callEndpoint records the attempt as started, calls the endpoint outside any
// transaction, then records the outcome. The Idempotency-Key is the same for
// every attempt of the step.
func (ex *executor) callEndpoint(ctx context.Context, r *Run, b base) bool {
	err := ex.tx(ctx, r, func(tx pgx.Tx) error {
		if _, err := ex.authorize(ctx, tx, r, b.st); err != nil {
			return err
		}
		if _, err := ex.subject(ctx, tx, r); err != nil {
			return err
		}
		return ex.insertAttempt(ctx, tx, r, b, "started", nil, "", "", "")
	})
	if err != nil {
		return ex.recordFailure(ctx, r, b, false, err)
	}
	timeout := 5 * time.Second
	if b.st.TimeoutMS > 0 {
		timeout = time.Duration(b.st.TimeoutMS) * time.Millisecond
	}
	res, callErr := ex.s.Webhooks.Call(ctx, r.realmID, b.st.SubscriptionID, b.id, b.key, ex.callBody(r, b, "execute", b.key, b.attempt), timeout)
	if callErr != nil {
		if errors.Is(callErr, webhooks.ErrCallFailed) {
			callErr = &stepError{category: res.Outcome, msg: fmt.Sprintf("endpoint answered %s", res.Outcome), permanent: res.Permanent}
		}
		return ex.recordFailure(ctx, r, b, true, callErr)
	}
	result := map[string]any{"status_code": res.Status}
	// Only a step that asked for a compensating call has anything to
	// compensate; otherwise the call is recorded as impossible to take back.
	comp := "impossible"
	if b.st.Compensation() == CompNotifyEndpoint {
		comp = "pending"
	}
	if err := ex.tx(ctx, r, func(tx pgx.Tx) error { return ex.succeedTx(ctx, tx, r, b, true, result, comp) }); err != nil {
		if errors.Is(err, errLeaseLost) {
			return false
		}
		// The call happened; recording failed. The attempt stays started and
		// is retried with the same idempotency key.
		ex.park(ctx, r, r.State, ex.s.d.Now().Add(10*time.Second))
		return false
	}
	r.StepIndex++
	return true
}

// finish ends a run whose steps all succeeded.
func (ex *executor) finish(ctx context.Context, r *Run) {
	err := ex.tx(ctx, r, func(tx pgx.Tx) error {
		now := ex.s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET state='succeeded', finished_at=$2, lease_owner=NULL, lease_expires_at=NULL WHERE id=$1`, r.ID, now); err != nil {
			return err
		}
		_, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.run.succeeded", RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
			Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID}, Category: "configuration",
			Metadata: map[string]any{"workflow_id": r.WorkflowID, "revision": r.Revision}})
		return err
	})
	if err == nil {
		r.State = "succeeded"
		if ex.s.Observe != nil {
			ex.s.Observe("run", "succeeded")
		}
	}
}

// compensate reverses, newest first, the effects the run can undo, records
// the ones it cannot, and ends the run (EXT-016).
func (ex *executor) compensate(ctx context.Context, r *Run, def *Definition) {
	rows, err := ex.s.d.DB.Pool.Query(ctx, `SELECT `+attemptCols+` FROM workflow_step_attempts WHERE run_id=$1 AND state='succeeded'
		AND compensation_state='pending' ORDER BY step_index DESC, attempt DESC`, r.ID)
	if err != nil {
		ex.park(ctx, r, r.State, ex.s.d.Now().Add(10*time.Second))
		return
	}
	var list []*Attempt
	for rows.Next() {
		a, err := scanAttempt(rows)
		if err != nil {
			rows.Close()
			ex.park(ctx, r, r.State, ex.s.d.Now().Add(10*time.Second))
			return
		}
		list = append(list, a)
	}
	rows.Close()
	for _, a := range list {
		var err error
		switch a.Compensation {
		case CompUndo:
			err = ex.tx(ctx, r, func(tx pgx.Tx) error {
				res, err := ex.undo(ctx, tx, r, a)
				if err != nil {
					return err
				}
				return ex.compensatedTx(ctx, tx, r, a, "done", res)
			})
		case CompNotifyEndpoint:
			st := Step{ID: a.StepID, Type: a.StepType}
			if def != nil && a.StepIndex < len(def.Steps) {
				st = def.Steps[a.StepIndex]
			}
			key := a.IdempotencyKey + ".compensate"
			b := base{st: st, attempt: a.CompensationAttempts + 1}
			res, callErr := ex.s.Webhooks.Call(ctx, r.realmID, st.SubscriptionID, a.ID+"c", key, ex.callBody(r, b, "compensate", key, a.CompensationAttempts+1), 5*time.Second)
			if callErr != nil {
				err = &stepError{category: res.Outcome, msg: "compensation call answered " + res.Outcome, permanent: res.Permanent}
				break
			}
			err = ex.tx(ctx, r, func(tx pgx.Tx) error {
				return ex.compensatedTx(ctx, tx, r, a, "done", map[string]any{"status_code": res.Status})
			})
		default:
			err = ex.tx(ctx, r, func(tx pgx.Tx) error { return ex.compensatedTx(ctx, tx, r, a, "not_needed", nil) })
		}
		if errors.Is(err, errLeaseLost) {
			return
		}
		if err != nil {
			category, msg, perm := classify(err)
			giveUp := perm || a.CompensationAttempts+1 >= maxCompensationAttempts
			terr := ex.tx(ctx, r, func(tx pgx.Tx) error {
				state := "pending"
				if giveUp {
					state = "failed"
				}
				res, _ := json.Marshal(map[string]any{"error_category": category, "error": msg})
				if _, err := tx.Exec(ctx, `UPDATE workflow_step_attempts SET compensation_attempts=compensation_attempts+1, compensation_state=$2,
					compensation_result=$3 WHERE id=$1`, a.ID, state, res); err != nil {
					return err
				}
				if !giveUp {
					return nil
				}
				_, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.step.compensation_failed", RealmID: r.realmID, OrgID: r.OrganizationID,
					Actor: ex.actor(r), Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID},
					Category: "configuration", Outcome: audit.Failure, ReasonCode: category, Metadata: map[string]any{"step_id": a.StepID, "attempt_id": a.ID}})
				return err
			})
			if terr != nil || !giveUp {
				ex.park(ctx, r, "compensating", ex.s.d.Now().Add(backoff(30*time.Second, a.CompensationAttempts+1)))
				return
			}
		}
	}
	// Every compensation is settled: decide the final state.
	err = ex.tx(ctx, r, func(tx pgx.Tx) error {
		var done, failed, impossible int
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE compensation_state='done'), count(*) FILTER (WHERE compensation_state='failed'),
			count(*) FILTER (WHERE compensation_state='impossible') FROM workflow_step_attempts WHERE run_id=$1 AND state='succeeded'`, r.ID).
			Scan(&done, &failed, &impossible); err != nil {
			return err
		}
		final := "failed"
		switch {
		case failed > 0:
			final = "compensation_failed"
		case r.CancelRequested:
			final = "cancelled"
		case done > 0:
			final = "compensated"
		}
		now := ex.s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE workflow_runs SET state=$2, finished_at=$3, lease_owner=NULL, lease_expires_at=NULL WHERE id=$1`, r.ID, final, now); err != nil {
			return err
		}
		outcome := audit.Failure
		if final == "cancelled" {
			outcome = audit.Success
		}
		if _, err := ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.run." + final, RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
			Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID}, Category: "configuration",
			Outcome: outcome, ReasonCode: r.ErrorCategory, Metadata: map[string]any{"workflow_id": r.WorkflowID, "compensated": done,
				"compensation_failed": failed, "not_compensable": impossible}}); err != nil {
			return err
		}
		r.State = final
		return nil
	})
	if err != nil && !errors.Is(err, errLeaseLost) {
		ex.park(ctx, r, "compensating", ex.s.d.Now().Add(10*time.Second))
		return
	}
	if err == nil && ex.s.Observe != nil {
		ex.s.Observe("run", r.State)
	}
}

func (ex *executor) compensatedTx(ctx context.Context, tx pgx.Tx, r *Run, a *Attempt, state string, res map[string]any) error {
	var rb []byte
	if res != nil {
		rb, _ = json.Marshal(res)
	}
	tag, err := tx.Exec(ctx, `UPDATE workflow_step_attempts SET compensation_state=$2, compensation_result=$3, compensated_at=$4,
		compensation_attempts=compensation_attempts+1 WHERE id=$1 AND compensation_state='pending'`, a.ID, state, rb, ex.s.d.Now())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil // already settled by an earlier pass
	}
	_, err = ex.s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.step.compensated", RealmID: r.realmID, OrgID: r.OrganizationID, Actor: ex.actor(r),
		Subject: &audit.Ref{Type: r.SubjectType, ID: r.SubjectID}, Target: &audit.Ref{Type: "workflow_run", ID: r.ID}, Category: "configuration",
		Metadata: map[string]any{"step_id": a.StepID, "step_type": a.StepType, "attempt_id": a.ID, "compensation": a.Compensation, "state": state}})
	return err
}

// undo reverses an effect the run created. Removing access is always within
// the run's authority, so the delegation ceiling is not re-checked; the
// last-owner rule still applies (TEN-006).
func (ex *executor) undo(ctx context.Context, tx pgx.Tx, r *Run, a *Attempt) (map[string]any, error) {
	switch a.StepType {
	case StepAssignRole:
		id, _ := a.Result["assignment_id"].(string)
		if id == "" || a.Result["already_assigned"] == true {
			return map[string]any{"removed": false}, nil
		}
		err := ex.s.Authz.UnassignTx(ctx, tx, r.realmID, id, nil, ex.actor(r), true)
		if problem.Is(err, problem.ErrNotFound) {
			return map[string]any{"removed": false, "reason": "already_removed"}, nil
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"removed": true, "assignment_id": id}, nil
	case StepAddToGroup:
		if a.Result["added"] != true {
			return map[string]any{"removed": false}, nil
		}
		org, _ := a.Result["organization_id"].(string)
		group, _ := a.Result["group_id"].(string)
		mid, _ := a.Result["membership_id"].(string)
		err := ex.s.Orgs.RemoveGroupMemberTx(ctx, tx, r.realmID, org, group, mid, ex.actor(r))
		if problem.Is(err, problem.ErrNotFound) {
			return map[string]any{"removed": false, "reason": "already_removed"}, nil
		}
		if err != nil {
			return nil, err
		}
		return map[string]any{"removed": true, "group_id": group, "membership_id": mid}, nil
	}
	return nil, permanent("not_compensable", "no undo for "+a.StepType)
}

// stepReason is the assignment reason: the run, and the step's reason code
// when the definition gives one.
func stepReason(code, runID string) string {
	if code == "" {
		return "workflow run " + runID
	}
	return code + ": workflow run " + runID
}
