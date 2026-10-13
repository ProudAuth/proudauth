package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/jobs"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// JobType is the job that executes synchronization and reconciliation runs.
const JobType = "directory.sync"

// Run is one synchronization or reconciliation run (PROV-012, PROV-017).
type Run struct {
	ID                   string         `json:"id"`
	ConnectorID          string         `json:"connector_id"`
	OrganizationID       string         `json:"organization_id,omitempty"`
	JobID                string         `json:"job_id,omitempty"`
	Mode                 string         `json:"mode"`
	DryRun               bool           `json:"dry_run"`
	Trigger              string         `json:"trigger"`
	State                string         `json:"state"`
	AllowMassDeprovision bool           `json:"allow_mass_deprovision"`
	RequestedByType      string         `json:"requested_by_type"`
	RequestedByID        string         `json:"requested_by_id"`
	Reason               string         `json:"reason,omitempty"`
	CursorBefore         string         `json:"cursor_before,omitempty"`
	CursorAfter          string         `json:"cursor_after,omitempty"`
	Endpoint             string         `json:"endpoint,omitempty"`
	Counts               map[string]int `json:"counts"`
	Error                string         `json:"error,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	StartedAt            *time.Time     `json:"started_at,omitempty"`
	FinishedAt           *time.Time     `json:"finished_at,omitempty"`
}

const runCols = `id, connector_id, coalesce(organization_id,''), coalesce(job_id,''), mode, dry_run, trigger, state, allow_mass_deprovision,
	requested_by_type, requested_by_id, coalesce(reason,''), coalesce(cursor_before,''), coalesce(cursor_after,''), coalesce(endpoint,''), counts,
	coalesce(error,''), created_at, started_at, finished_at`

func scanRun(row pgx.Row) (*Run, error) {
	var r Run
	var counts []byte
	if err := row.Scan(&r.ID, &r.ConnectorID, &r.OrganizationID, &r.JobID, &r.Mode, &r.DryRun, &r.Trigger, &r.State, &r.AllowMassDeprovision,
		&r.RequestedByType, &r.RequestedByID, &r.Reason, &r.CursorBefore, &r.CursorAfter, &r.Endpoint, &counts, &r.Error, &r.CreatedAt,
		&r.StartedAt, &r.FinishedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(counts, &r.Counts)
	if r.Counts == nil {
		r.Counts = map[string]int{}
	}
	return &r, nil
}

// RunRequest asks for a run.
type RunRequest struct {
	Mode   string `json:"mode"`
	DryRun bool   `json:"dry_run"`
	// AllowMassDeprovision overrides the deletion threshold for this run; it
	// requires a reason and is recorded as an operator action.
	AllowMassDeprovision bool   `json:"allow_mass_deprovision"`
	Reason               string `json:"reason"`
}

// RequestRun queues a run of a connector as a job. At most one run of a
// connector is queued or running at a time.
func (s *Service) RequestRun(ctx context.Context, realmID, orgID, id string, in RunRequest, trigger string, requester audit.Ref) (*Run, error) {
	var out *Run
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		c, err := s.load(ctx, tx, realmID, orgID, id, true)
		if err != nil {
			return err
		}
		var rerr error
		out, rerr = s.requestRunTx(ctx, tx, c, in, trigger, requester)
		return rerr
	})
	return out, err
}

func (s *Service) requestRunTx(ctx context.Context, tx pgx.Tx, c *Connector, in RunRequest, trigger string, requester audit.Ref) (*Run, error) {
	if c.State != "active" {
		return nil, problem.ErrConflict.WithDetail("the connector is disabled")
	}
	switch {
	case c.Kind == KindLDAP && in.Mode == "":
		in.Mode = "incremental"
	case c.Kind == KindOutbound && in.Mode == "":
		in.Mode = "reconcile"
	}
	if (c.Kind == KindLDAP && in.Mode != "full" && in.Mode != "incremental") || (c.Kind == KindOutbound && in.Mode != "reconcile") {
		return nil, problem.ErrValidation.WithField("mode", "full or incremental for directories, reconcile for outbound connectors")
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if len(in.Reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "at most 500 characters")
	}
	if in.AllowMassDeprovision {
		// Overriding the deletion safety is a deliberate, attributable
		// decision for one full, applied run (PROV-012).
		if c.Kind != KindLDAP || in.Mode != "full" || in.DryRun {
			return nil, problem.ErrValidation.WithField("allow_mass_deprovision", "only for an applied full directory synchronization")
		}
		if len(in.Reason) < 10 {
			return nil, problem.ErrValidation.WithField("reason", "explain the mass deprovisioning (at least 10 characters)")
		}
	}
	if c.Kind == KindOutbound {
		if issue := c.outboundIssue(); issue != "" {
			return nil, problem.ErrConflict.WithDetail("the outbound connector has no usable configuration (" + issue + "); update it first")
		}
	}
	// A run whose job ended without finishing it (the module was switched
	// off while it was queued, the job was cancelled, the worker gave up)
	// can never run: it is closed here instead of blocking the connector.
	if _, err := s.closeOrphanedRuns(ctx, tx, c.ID); err != nil {
		return nil, err
	}
	var active string
	if tx.QueryRow(ctx, `SELECT id FROM directory_sync_runs WHERE connector_id=$1 AND state IN ('queued','running')`, c.ID).Scan(&active) == nil {
		return nil, problem.ErrConflict.WithDetail("a run of this connector is already queued or running").WithExtension("run_id", active)
	}
	id := ids.New("dsr")
	jobID, err := s.Jobs.CreateTx(ctx, tx, jobs.Spec{RealmID: c.RealmID, OrganizationID: c.OrganizationID, Type: JobType, DryRun: in.DryRun,
		Input: map[string]any{"run_id": id, "connector_id": c.ID}, Requester: requester, MaxAttempts: 2})
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO directory_sync_runs (id, realm_id, organization_id, connector_id, job_id, mode, dry_run, trigger,
		allow_mass_deprovision, requested_by_type, requested_by_id, reason, cursor_before, created_at) VALUES ($1,$2,nullif($3,''),$4,$5,$6,$7,$8,$9,$10,$11,nullif($12,''),nullif($13,''),$14)`,
		id, c.RealmID, c.OrganizationID, c.ID, jobID, in.Mode, in.DryRun, trigger, in.AllowMassDeprovision, requester.Type, requester.ID, in.Reason,
		c.cursor, s.d.Now()); err != nil {
		return nil, err
	}
	if trigger == "manual" {
		action := "run_" + in.Mode
		if in.DryRun {
			action += "_dry_run"
		}
		if in.AllowMassDeprovision {
			action = "mass_deprovision_authorized"
		}
		if err := s.recordOperatorAction(ctx, tx, c, action, requester); err != nil {
			return nil, err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.sync.requested", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: requester,
			Category: "operations", Target: &audit.Ref{Type: "connector", ID: c.ID}, ReasonCode: map[bool]string{true: "MASS_DEPROVISION_OVERRIDE"}[in.AllowMassDeprovision],
			Metadata: map[string]any{"run_id": id, "mode": in.Mode, "dry_run": in.DryRun, "allow_mass_deprovision": in.AllowMassDeprovision}}); err != nil {
			return nil, err
		}
	}
	return scanRun(tx.QueryRow(ctx, `SELECT `+runCols+` FROM directory_sync_runs WHERE id=$1`, id))
}

// closeOrphanedRuns ends queued or running runs whose job can no longer
// execute them — the job ended (succeeded, failed, cancelled or
// dead-lettered) or is gone — so a lost job never keeps a connector from
// running again. connectorID "" closes them for every connector. A queued
// run ends cancelled, a running one failed; both carry the reason.
func (s *Service) closeOrphanedRuns(ctx context.Context, q storage.Querier, connectorID string) (int, error) {
	rows, err := q.Query(ctx, `UPDATE directory_sync_runs r SET
			state=CASE WHEN r.state='running' THEN 'failed' ELSE 'cancelled' END,
			error=CASE WHEN r.state='running' THEN 'the run''s job ended before the run finished'
				ELSE 'the run''s job ended before the run started (for example, the directory integration was disabled while it was queued)' END,
			finished_at=$2::timestamptz, started_at=coalesce(r.started_at, CASE WHEN r.state='running' THEN $2::timestamptz END)
		WHERE r.state IN ('queued','running') AND ($1::text='' OR r.connector_id=$1::text)
			AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.id=r.job_id AND j.state IN ('queued','running'))
		RETURNING r.mode, r.state`, connectorID, s.d.Now())
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var mode, state string
		if err := rows.Scan(&mode, &state); err != nil {
			return n, err
		}
		s.m.runs.Inc(mode, state)
		n++
	}
	return n, rows.Err()
}

// Runs lists a connector's latest runs.
func (s *Service) Runs(ctx context.Context, realmID, orgID, id string, limit int) ([]*Run, error) {
	if _, err := s.Get(ctx, realmID, orgID, id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+runCols+` FROM directory_sync_runs WHERE connector_id=$1 ORDER BY created_at DESC, id DESC LIMIT $2`, id, limit)
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

// GetRun returns one run of a connector.
func (s *Service) GetRun(ctx context.Context, realmID, orgID, id, runID string) (*Run, error) {
	if _, err := s.Get(ctx, realmID, orgID, id); err != nil {
		return nil, err
	}
	r, err := scanRun(s.d.DB.Pool.QueryRow(ctx, `SELECT `+runCols+` FROM directory_sync_runs WHERE connector_id=$1 AND id=$2`, id, runID))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return r, err
}

// Findings pages a run's findings, optionally of one kind.
func (s *Service) Findings(ctx context.Context, realmID, orgID, id, runID, kind string, after, limit int) ([]Finding, error) {
	if _, err := s.GetRun(ctx, realmID, orgID, id, runID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT seq, kind, coalesce(reason,''), coalesce(external_id,''), coalesce(source_dn,''), coalesce(local_id,''),
		attributes, applied, detail FROM directory_sync_findings WHERE run_id=$1 AND ($2='' OR kind=$2) AND seq>$3 ORDER BY seq LIMIT $4`, runID, kind, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		var detail []byte
		if err := rows.Scan(&f.Seq, &f.Kind, &f.Reason, &f.ExternalID, &f.SourceDN, &f.LocalID, &f.Attributes, &f.Applied, &detail); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &f.Detail)
		out = append(out, f)
	}
	return out, rows.Err()
}

// RunJob is the job handler for directory.sync. Failures end the run in
// state failed rather than retrying the job: the next scheduled or requested
// run starts from the last committed cursor, and every entry is applied in
// its own transaction, idempotently, so an interrupted run is safe to repeat
// (PROV-012 safe resumability).
func (s *Service) RunJob(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	runID, _ := j.Input["run_id"].(string)
	run, err := scanRun(s.d.DB.Pool.QueryRow(ctx, `SELECT `+runCols+` FROM directory_sync_runs WHERE id=$1`, runID))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: run not found", jobs.ErrPermanent)
	}
	if run.State != "queued" && run.State != "running" {
		return map[string]any{"run_id": run.ID, "state": run.State}, nil, nil
	}
	c, err := s.byID(ctx, nil, run.ConnectorID)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: connector not found", jobs.ErrPermanent)
	}
	r := newRunCtx(run.ID, run.DryRun, run.Mode == "full" || run.Mode == "reconcile")
	r.job = j
	if !s.active() {
		// directory.enabled is false: the run ends now, with a reason,
		// instead of staying queued and blocking the connector's next run
		// once the module is enabled again.
		err := s.finishRun(ctx, c, run, r, "cancelled", "the directory integration is disabled (directory.enabled: false)", "")
		return map[string]any{"run_id": run.ID, "state": "cancelled"}, nil, err
	}
	if !s.requesterMayManage(ctx, c, run.RequestedByType, run.RequestedByID) {
		err := s.finishRun(ctx, c, run, r, "cancelled", "the requester no longer holds the authority to manage this connector", "")
		return map[string]any{"run_id": run.ID, "state": "cancelled"}, nil, err
	}
	if c.State != "active" || !s.organizationActive(ctx, nil, c) {
		err := s.finishRun(ctx, c, run, r, "cancelled", "the connector or its organization is not active", "")
		return map[string]any{"run_id": run.ID, "state": "cancelled"}, nil, err
	}
	if c.Kind == KindOutbound {
		if issue := c.outboundIssue(); issue != "" {
			err := s.finishRun(ctx, c, run, r, "cancelled", "the outbound connector has no usable configuration ("+issue+")", "")
			return map[string]any{"run_id": run.ID, "state": "cancelled"}, nil, err
		}
	}
	now := s.d.Now()
	if err := s.runTx(ctx, r, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE directory_sync_runs SET state='running', started_at=coalesce(started_at,$2) WHERE id=$1`, run.ID, now)
		return err
	}); err != nil {
		return nil, nil, err
	}
	var state, cursor, failure string
	switch c.Kind {
	case KindLDAP:
		state, cursor, err = s.syncLDAP(ctx, c, run, r, progress)
	case KindOutbound:
		state, err = s.reconcileOutbound(ctx, c, run, r, progress)
	}
	if err != nil {
		if errors.Is(err, jobs.ErrLeaseLost) {
			return nil, nil, err
		}
		if errors.Is(err, context.Canceled) {
			state, failure = "cancelled", "cancelled"
		} else {
			state, failure = "failed", publicError(err)
			s.d.Log.Warn("directory run failed", "connector_id", c.ID, "run_id", run.ID, "error", err)
		}
	}
	err = s.finishRun(ctx, c, run, r, state, failure, cursor)
	return map[string]any{"run_id": run.ID, "state": state, "counts": r.counts}, nil, err
}

// publicError is the client-safe summary of a run failure: categories and
// host names, never credentials or directory responses verbatim.
func publicError(err error) string {
	var te *transportError
	switch {
	case errors.Is(err, errUnavailable):
		if errors.As(err, &te) {
			return "no configured directory endpoint is reachable (last: " + hostOf(te.endpoint) + ", " + te.category + ")"
		}
		return "no configured directory endpoint is reachable"
	case strings.HasPrefix(err.Error(), "service bind refused"):
		return "the directory refused the service account bind; check bind_dn and the credential"
	case strings.HasPrefix(err.Error(), "service credential unavailable"):
		return "the connector credential is not available"
	}
	if pe, ok := problem.As(err); ok && pe.Status < 500 {
		return pe.Detail
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		return "directory error " + strconv.Itoa(int(le.ResultCode)) + " (" + ldap.LDAPResultCodeMap[le.ResultCode] + ")"
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if strings.Contains(strings.ToLower(msg), "password") {
		return "run failed"
	}
	return msg
}

// finishRun records the outcome, findings and connector evidence
// (PROV-018), and audits the outcome.
func (s *Service) finishRun(ctx context.Context, c *Connector, run *Run, r *runCtx, state, failure, cursor string) error {
	ctx = context.WithoutCancel(ctx)
	now := s.d.Now()
	counts, _ := json.Marshal(r.counts)
	err := s.runTx(ctx, r, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM directory_sync_findings WHERE run_id=$1`, run.ID); err != nil {
			return err
		}
		for _, f := range r.items {
			detail, _ := json.Marshal(f.Detail)
			if f.Detail == nil {
				detail = []byte("{}")
			}
			if _, err := tx.Exec(ctx, `INSERT INTO directory_sync_findings (run_id, seq, kind, reason, external_id, source_dn, local_id, attributes, applied, detail)
				VALUES ($1,$2,$3,nullif($4,''),nullif($5,''),nullif($6,''),nullif($7,''),$8,$9,$10)`, run.ID, f.Seq, f.Kind, f.Reason, f.ExternalID,
				clip(f.SourceDN, 1024), f.LocalID, f.Attributes, f.Applied, detail); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE directory_sync_runs SET state=$2, counts=$3, error=nullif($4,''), cursor_after=nullif($5,''), finished_at=$6,
			started_at=coalesce(started_at,$6), endpoint=nullif($7,''), mode=$8 WHERE id=$1`, run.ID, state, counts, failure, cursor, now, run.Endpoint, run.Mode); err != nil {
			return err
		}
		ok := state == "succeeded"
		stats, _ := json.Marshal(map[string]any{"last_run_id": run.ID, "last_run_mode": run.Mode, "last_run_state": state, "last_counts": r.counts})
		if run.DryRun {
			// A dry run is evidence of a plan, not of synchronization.
			_, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET stats = stats || $2 WHERE id=$1`, c.ID, stats)
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE provisioning_connectors SET last_sync_at=$2,
			last_success_at=CASE WHEN $3 THEN $2 ELSE last_success_at END,
			last_error=CASE WHEN $3 THEN NULL ELSE nullif($4,'') END,
			consecutive_failures=CASE WHEN $3 THEN 0 WHEN $5 THEN consecutive_failures+1 ELSE consecutive_failures END,
			cursor=CASE WHEN nullif($6,'') IS NOT NULL THEN $6 ELSE cursor END,
			stats = stats || $7 WHERE id=$1`, c.ID, now, ok, failure, state == "failed", cursor, stats); err != nil {
			return err
		}
		outcome := audit.Success
		if state == "failed" || state == "refused" {
			outcome = audit.Failure
		}
		ev := audit.Event{Type: "directory.sync.completed", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(), Category: "operations",
			Target: &audit.Ref{Type: "connector", ID: c.ID}, Outcome: outcome,
			Metadata: map[string]any{"run_id": run.ID, "mode": run.Mode, "state": state, "counts": r.counts, "trigger": run.Trigger}}
		if state == "refused" {
			ev.ReasonCode = "DELETION_THRESHOLD_EXCEEDED"
		}
		_, err := s.d.Audit.Record(ctx, tx, ev)
		return err
	})
	if err != nil {
		s.d.Log.Error("recording a directory run failed", "run_id", run.ID, "error", err)
		return err
	}
	s.m.runs.Inc(run.Mode, state)
	for k, n := range r.counts {
		s.m.changes.Add(uint64(n), k)
	}
	return nil
}

// cursorState is the change cursor of a directory (PROV-012). A USN is
// meaningful only on the server that issued it, so the server identity
// travels with it; a different server forces a full run.
type cursorState struct {
	Server string `json:"server,omitempty"`
	USN    int64  `json:"usn,omitempty"`
	TS     string `json:"modify_timestamp,omitempty"`
}

// timestampOverlap re-reads changes this close to the cursor: replicas and
// clocks may commit a change with a slightly earlier timestamp after the
// previous run read past it. Re-applying an entry is idempotent.
const timestampOverlap = 5 * time.Minute

const generalizedTime = "20060102150405Z"

// parseGeneralized reads an LDAP generalized time, with or without the
// fractional seconds Active Directory adds ("20261011120000.0Z").
func parseGeneralized(v string) (time.Time, error) {
	if t, err := time.Parse(generalizedTime, v); err == nil {
		return t, nil
	}
	return time.Parse("20060102150405.0Z", v)
}

// defaultMaxEntriesPerRun applies when directory.max_entries_per_run is 0.
const defaultMaxEntriesPerRun = 100000

// maxEntriesLimit is the operator's bound on the entries one run processes
// (directory.max_entries_per_run).
func (s *Service) maxEntriesLimit() int {
	if n := s.d.Cfg.Directory.MaxEntriesPerRun; n > 0 {
		return n
	}
	return defaultMaxEntriesPerRun
}

// maxEntries is a connector's effective run bound: its own max_entries can
// only lower the operator's limit, never raise it.
func (s *Service) maxEntries(cfg *LDAPConfig) int {
	limit := s.maxEntriesLimit()
	if cfg != nil && cfg.MaxEntries > 0 && cfg.MaxEntries < limit {
		return cfg.MaxEntries
	}
	return limit
}

// syncLDAP runs one full or incremental synchronization.
func (s *Service) syncLDAP(ctx context.Context, c *Connector, run *Run, r *runCtx, progress func(map[string]any) error) (state, cursor string, err error) {
	cfg := c.ldap
	maxEntries := s.maxEntries(cfg)
	var prev cursorState
	_ = json.Unmarshal([]byte(c.cursor), &prev)
	mode := run.Mode
	var next cursorState
	var endpoint string
	processed := 0
	err = s.withDirectory(ctx, c, true, func(cn *conn) error {
		// A transport failure mid-search restarts the scan on the next
		// endpoint; entries already applied are applied again, idempotently.
		// Deletion must use only the endpoint that completes its scan. A
		// partial earlier endpoint cannot keep an absent membership alive.
		r.mu.Lock()
		clear(r.seen)
		r.mu.Unlock()
		processed = 0
		endpoint = hostOf(cn.endpoint)
		server, usn, _ := cn.rootDSE()
		filter := cfg.UserFilter
		if mode == "incremental" {
			switch {
			case cfg.ChangeTracking == "usn" && prev.USN > 0 && prev.Server != "" && prev.Server == server:
				filter = "(&" + cfg.UserFilter + "(uSNChanged>=" + strconv.FormatInt(prev.USN+1, 10) + "))"
			case cfg.ChangeTracking == "modify_timestamp" && prev.TS != "":
				t, perr := parseGeneralized(prev.TS)
				if perr != nil {
					mode = "full"
					break
				}
				filter = "(&" + cfg.UserFilter + "(modifyTimestamp>=" + t.Add(-timestampOverlap).UTC().Format(generalizedTime) + "))"
			default:
				// No usable cursor (first run, change tracking off, or a
				// different domain controller): a full run is the only safe
				// incremental (PROV-012).
				mode = "full"
			}
			if mode == "full" {
				r.full = true
				r.counts["incremental_promoted_to_full"] = 1
			}
		}
		next = cursorState{Server: server, USN: usn, TS: prev.TS}
		attrs := userAttributes(cfg)
		maxTS := prev.TS
		return cn.searchPaged(cfg.UserBaseDN, scopeOf(cfg.UserScope), filter, attrs, cfg.PageSize, func(entries []*ldap.Entry) error {
			for _, e := range entries {
				processed++
				if processed > maxEntries {
					return problem.ErrValidation.WithDetail(fmt.Sprintf("the directory returned more than %d entries; narrow user_filter, or raise max_entries "+
						"(at most directory.max_entries_per_run)", maxEntries))
				}
				ev := readEntry(cfg, e)
				if ev.modified > maxTS {
					maxTS = ev.modified
				}
				if err := s.applyOne(ctx, c, r, ev); err != nil {
					return err
				}
			}
			next.TS = maxTS
			if progress != nil {
				return progress(map[string]any{"run_id": run.ID, "processed": processed, "counts": r.counts})
			}
			return nil
		})
	})
	r.counts["entries_seen"] = processed
	if endpoint != "" {
		run.Endpoint = endpoint
		run.Mode = mode
	}
	if err != nil {
		return "failed", "", err
	}
	state = "succeeded"
	if r.full {
		refused, derr := s.deprovisionMissing(ctx, c, run, r)
		if derr != nil {
			return "failed", "", derr
		}
		if refused {
			state = "refused"
		}
	}
	if len(c.GroupRoleMappings) > 0 && c.OrganizationID != "" {
		if gerr := s.withDirectory(ctx, c, true, func(cn *conn) error { return s.syncGroups(ctx, cn, c, r) }); gerr != nil {
			return "failed", "", gerr
		}
	}
	if run.DryRun || cfg.ChangeTracking == "none" {
		return state, "", nil
	}
	b, _ := json.Marshal(next)
	return state, string(b), nil
}

// applyOne applies an entry in its own transaction. A failing entry is
// reported and does not stop the run.
func (s *Service) applyOne(ctx context.Context, c *Connector, r *runCtx, ev entry) error {
	err := s.runTx(ctx, r, func(tx pgx.Tx) error {
		_, err := s.applyEntry(ctx, tx, r, c, ev)
		if err == nil && r.dry {
			return errDryRun
		}
		return err
	})
	if err == nil || errors.Is(err, errDryRun) {
		return nil
	}
	if errors.Is(err, jobs.ErrLeaseLost) {
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	s.d.Log.Warn("directory entry not applied", "connector_id", c.ID, "error", err)
	r.add(Finding{Kind: FindError, Reason: "apply_failed", ExternalID: ev.ext, SourceDN: ev.dn})
	return nil
}

// deprovisionMissing handles linked accounts a complete full run did not
// see (PROV-012). More than the threshold refuses every deprovisioning in
// the run — an emptied search base looks exactly like a mass deletion —
// unless the run carries an explicit, audited override.
func (s *Service) deprovisionMissing(ctx context.Context, c *Connector, run *Run, r *runCtx) (refused bool, err error) {
	cfg := c.ldap
	// Links of erased accounts (source state 'deleted') have nothing left
	// to deprovision and do not count towards the threshold.
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+linkCols+` FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User'
		AND link_kind='directory' AND coalesce(source_state,'active') <> 'deleted' ORDER BY external_id`, c.ID)
	if err != nil {
		return false, err
	}
	var all, missing []*link
	for rows.Next() {
		l, err := scanLink(rows)
		if err != nil {
			rows.Close()
			return false, err
		}
		all = append(all, l)
		if !r.seen[l.ExternalID] && l.SourceState != "missing" {
			missing = append(missing, l)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	r.counts["linked_accounts"] = len(all)
	if len(missing) == 0 {
		return false, nil
	}
	pct := len(missing) * 100 / max(len(all), 1)
	exceeds := len(missing)*100 > cfg.DeletionThresholdPercent*len(all) || (cfg.DeletionThresholdCount > 0 && len(missing) > cfg.DeletionThresholdCount)
	if exceeds && !run.AllowMassDeprovision {
		for _, l := range missing {
			r.add(Finding{Kind: FindDeprovision, Reason: "deletion_threshold_exceeded", ExternalID: l.ExternalID, SourceDN: l.DN, LocalID: l.UserID})
		}
		r.counts["deprovision_refused"] = len(missing)
		r.add(Finding{Kind: FindError, Reason: "deletion_threshold_exceeded", Detail: map[string]any{"missing": len(missing), "linked": len(all),
			"percent": pct, "threshold_percent": cfg.DeletionThresholdPercent, "threshold_count": cfg.DeletionThresholdCount}})
		return true, nil
	}
	for _, l := range missing {
		err := s.runTx(ctx, r, func(tx pgx.Tx) error {
			if err := s.deprovisionOne(identity.WithExternalWriter(ctx), tx, c, r, l); err != nil {
				return err
			}
			if r.dry {
				return errDryRun
			}
			return nil
		})
		if err != nil && !errors.Is(err, errDryRun) {
			if errors.Is(err, jobs.ErrLeaseLost) {
				return false, err
			}
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			r.add(Finding{Kind: FindError, Reason: "deprovision_failed", ExternalID: l.ExternalID, LocalID: l.UserID})
		}
	}
	return false, nil
}

func (s *Service) deprovisionOne(ctx context.Context, tx pgx.Tx, c *Connector, r *runCtx, l *link) error {
	cfg := c.ldap
	f := Finding{Kind: FindDeprovision, ExternalID: l.ExternalID, SourceDN: l.DN, LocalID: l.UserID, Applied: !r.dry && cfg.DeprovisionAction != "report_only"}
	u, err := s.Users.LockUser(ctx, tx, c.RealmID, l.UserID)
	if err != nil {
		f.Reason, f.Applied = "linked_account_deleted", false
		r.add(f)
		return nil
	}
	if s.accountLocked(ctx, tx, c, u) {
		f.Reason, f.Applied = "protected_account", false
		r.add(f)
		return nil
	}
	switch cfg.DeprovisionAction {
	case "report_only":
		f.Reason = "report_only"
		r.add(f)
		return nil
	case "suspend_account":
		f.Reason = "account_suspended"
		if u.State == identity.StateActive || u.State == identity.StateRecoveryRestricted {
			if _, err := s.Users.SetStateTx(ctx, tx, c.RealmID, u.ID, identity.StateSuspended, c.Ref(), "DIRECTORY_DEPROVISIONED"); err != nil {
				return err
			}
		}
	case "remove_membership", "suspend_membership":
		var mid string
		if tx.QueryRow(ctx, `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
			c.OrganizationID, u.ID).Scan(&mid) == nil {
			var err error
			if cfg.DeprovisionAction == "remove_membership" {
				f.Reason = "membership_removed"
				err = s.Orgs.RemoveMemberTx(ctx, tx, c.RealmID, c.OrganizationID, mid, nil, c.Ref(), "directory_deprovisioned")
			} else {
				f.Reason = "membership_suspended"
				err = s.Orgs.SetMembershipStateTx(ctx, tx, c.RealmID, c.OrganizationID, mid, "suspended", nil, c.Ref())
			}
			if err != nil {
				return err
			}
		}
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE connector_external_ids SET source_state='missing', missing_since=$3, updated_at=$3
		WHERE connector_id=$1 AND resource_type='User' AND external_id=$2`, c.ID, l.ExternalID, now); err != nil {
		return err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.user.deprovisioned", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
		Subject: &audit.Ref{Type: "user", ID: u.ID}, Category: "account", ReasonCode: strings.ToUpper(f.Reason), Metadata: map[string]any{"run_id": r.id}}); err != nil {
		return err
	}
	r.add(f)
	return nil
}

// sortedKeys returns map keys in order (deterministic plans).
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
