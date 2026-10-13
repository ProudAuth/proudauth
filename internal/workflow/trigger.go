package workflow

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/storage"
)

// runStart describes a run to create.
type runStart struct {
	realmID, orgID, workflowID string
	revision                   int
	hash                       string
	schemaVersion              int
	triggerType, triggerKey    string
	eventType                  string
	subjectID                  string
	input                      map[string]any
	inputVersion               int
	accountable, startedBy     string
	depth                      int
}

// startRunTx inserts a run; a repeated trigger key starts nothing (the
// unique (workflow, trigger_key) makes triggers idempotent).
func (s *Service) startRunTx(ctx context.Context, tx pgx.Tx, r runStart) (string, bool, error) {
	in, _ := json.Marshal(r.input)
	id := newID(prefixRun)
	tag, err := tx.Exec(ctx, `INSERT INTO workflow_runs (id, realm_id, organization_id, workflow_id, revision_number, definition_hash, schema_version,
		trigger_type, trigger_key, trigger_event_type, subject_id, input, input_version, accountable_id, started_by_id, depth, state, next_run_at,
		created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'pending',$17,$17,$17)
		ON CONFLICT (workflow_id, trigger_key) DO NOTHING`, id, r.realmID, nilIfEmpty(r.orgID), r.workflowID, r.revision, r.hash, r.schemaVersion,
		r.triggerType, r.triggerKey, nilIfEmpty(r.eventType), r.subjectID, in, r.inputVersion, r.accountable, nilIfEmpty(r.startedBy), r.depth, s.d.Now())
	if err != nil {
		return "", false, err
	}
	if tag.RowsAffected() == 0 {
		var existing string
		err := tx.QueryRow(ctx, `SELECT id FROM workflow_runs WHERE workflow_id=$1 AND trigger_key=$2`, r.workflowID, r.triggerKey).Scan(&existing)
		return existing, false, err
	}
	actor := audit.Ref{Type: "user", ID: r.accountable}
	_, err = s.d.Audit.Record(withRun(ctx, id), tx, audit.Event{Type: "workflow.run.started", RealmID: r.realmID, OrgID: r.orgID, Actor: actor,
		Subject: &audit.Ref{Type: "user", ID: r.subjectID}, Target: &audit.Ref{Type: "workflow_run", ID: id}, Category: "configuration",
		Metadata: map[string]any{"workflow_id": r.workflowID, "revision": r.revision, "trigger": r.triggerType, "event_type": r.eventType,
			"started_by": r.startedBy, "depth": r.depth}})
	return id, true, err
}

// activeWorkflow is a published, enabled workflow with its definition.
type activeWorkflow struct {
	id, name, publisher string
	revision            int
	hash                string
	def                 *Definition
}

func (s *Service) activeWorkflows(ctx context.Context, q storage.Querier, sql string, args ...any) ([]activeWorkflow, error) {
	rows, err := q.Query(ctx, `SELECT w.id, w.name, w.published_by_id, r.number, r.definition_hash, r.definition FROM workflows w
		JOIN workflow_revisions r ON r.workflow_id=w.id AND r.number=w.active_revision WHERE w.state='active' AND `+sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []activeWorkflow
	for rows.Next() {
		var a activeWorkflow
		var raw []byte
		if err := rows.Scan(&a.id, &a.name, &a.publisher, &a.revision, &a.hash, &raw); err != nil {
			return nil, err
		}
		def, _, _, err := Parse(raw)
		if err != nil {
			// A stored revision that no longer parses (a schema version past
			// its sunset) never starts runs; publishing a current revision
			// repairs it.
			s.d.Log.Warn("workflow revision cannot be parsed", "workflow_id", a.id, "error", err)
			continue
		}
		a.def = def
		out = append(out, a)
	}
	return out, rows.Err()
}

// OnEvent starts runs for an outbox event inside the dispatcher's
// transaction (ARC-003): the event is marked dispatched exactly when its
// runs exist, and the unique trigger key keeps a redelivered event from
// starting a second run.
func (s *Service) OnEvent(ctx context.Context, tx pgx.Tx, realmID, orgID, eventID, eventType string, payload []byte) (int, error) {
	if realmID == "" || !slices.Contains(TriggerEvents, eventType) {
		return 0, nil
	}
	wfs, err := s.activeWorkflows(ctx, tx, `w.realm_id=$1 AND $2 = ANY(w.event_types)`, realmID, eventType)
	if err != nil || len(wfs) == 0 {
		return 0, err
	}
	var env struct {
		EventVersion  int            `json:"event_version"`
		OccurredAt    time.Time      `json:"occurred_at"`
		CorrelationID string         `json:"correlation_id"`
		Data          map[string]any `json:"data"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		return 0, nil
	}
	subject, _ := env.Data["user_id"].(string)
	if subject == "" {
		return 0, nil
	}
	// Events a run caused carry the run's ID as correlation ID: chains are
	// bounded and a workflow never re-triggers itself.
	depth, parentWorkflow := 0, ""
	if strings.HasPrefix(env.CorrelationID, prefixRun+"_") {
		if err := tx.QueryRow(ctx, `SELECT depth+1, workflow_id FROM workflow_runs WHERE id=$1 AND realm_id=$2`, env.CorrelationID, realmID).
			Scan(&depth, &parentWorkflow); err != nil && !storage.IsNoRows(err) {
			return 0, err
		}
	}
	n := 0
	for _, wf := range wfs {
		matched := false
		for _, t := range wf.def.Triggers {
			if t.Type == "event" && slices.Contains(t.EventTypes, eventType) && (t.OrganizationID == "" || t.OrganizationID == orgID) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if wf.id == parentWorkflow || depth > MaxDepth {
			if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.trigger.suppressed", RealmID: realmID, OrgID: orgID, Actor: audit.System,
				Target: &audit.Ref{Type: "workflow", ID: wf.id}, Category: "configuration", ReasonCode: "WORKFLOW_LOOP",
				Metadata: map[string]any{"event_id": eventID, "event_type": eventType, "depth": depth, "caused_by_run": env.CorrelationID}}); err != nil {
				return n, err
			}
			continue
		}
		input := map[string]any{"event_id": eventID, "event_type": eventType, "occurred_at": env.OccurredAt, "data": identifiersOnly(env.Data)}
		if orgID != "" {
			input["organization_id"] = orgID
		}
		version := env.EventVersion
		if version == 0 {
			version = 1
		}
		if _, created, err := s.startRunTx(ctx, tx, runStart{realmID: realmID, orgID: orgID, workflowID: wf.id, revision: wf.revision, hash: wf.hash,
			schemaVersion: wf.def.SchemaVersion, triggerType: "event", triggerKey: eventID, eventType: eventType, subjectID: subject, input: input,
			inputVersion: version, accountable: wf.publisher, depth: depth}); err != nil {
			return n, err
		} else if created {
			n++
		}
	}
	return n, nil
}

// identifiersOnly keeps the identifier and state members of event data: a
// run's input snapshot never holds personal data (EXT-008 minimal form).
func identifiersOnly(d map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range d {
		if strings.HasSuffix(k, "_id") || k == "state" || k == "reason" || k == "authorization_revision" {
			out[k] = v
		}
	}
	return out
}

// FireSchedules starts the runs of every due schedule trigger. Each workflow
// is claimed with a row lock and its next firing moves forward in the same
// transaction as the runs it starts, so a slot fires once across workers;
// slots missed while no worker ran are not replayed.
func (s *Service) FireSchedules(ctx context.Context) (int, error) {
	now := s.d.Now()
	total := 0
	for i := 0; i < 20; i++ {
		fired := false
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			var id, realmID string
			var slot time.Time
			var every int
			err := tx.QueryRow(ctx, `SELECT id, realm_id, next_fire_at, schedule_every_s FROM workflows WHERE state='active' AND next_fire_at <= $1
				AND schedule_every_s IS NOT NULL ORDER BY next_fire_at LIMIT 1 FOR UPDATE SKIP LOCKED`, now).Scan(&id, &realmID, &slot, &every)
			if storage.IsNoRows(err) {
				return nil
			}
			if err != nil {
				return err
			}
			fired = true
			interval := time.Duration(every) * time.Second
			next := slot.Add(interval)
			if !next.After(now) {
				next = now.Add(interval)
			}
			if _, err := tx.Exec(ctx, `UPDATE workflows SET next_fire_at=$2 WHERE id=$1`, id, next); err != nil {
				return err
			}
			wfs, err := s.activeWorkflows(ctx, tx, `w.id=$1`, id)
			if err != nil || len(wfs) == 0 {
				return err
			}
			wf := wfs[0]
			t, _ := wf.def.Schedule()
			if t == nil {
				return nil
			}
			subjects, truncated, err := s.selectSubjects(ctx, tx, realmID, t.Select, now)
			if err != nil {
				return err
			}
			key := "schedule:" + strconv.FormatInt(slot.Unix(), 10) + ":"
			started := 0
			for _, sub := range subjects {
				input := map[string]any{"schedule_slot": slot, "selector": t.Select.Type}
				if sub.org != "" {
					input["organization_id"] = sub.org
				}
				_, created, err := s.startRunTx(ctx, tx, runStart{realmID: realmID, orgID: sub.org, workflowID: wf.id, revision: wf.revision, hash: wf.hash,
					schemaVersion: wf.def.SchemaVersion, triggerType: "schedule", triggerKey: key + sub.user + ":" + sub.org, subjectID: sub.user,
					input: input, inputVersion: wf.def.SchemaVersion, accountable: wf.publisher})
				if err != nil {
					return err
				}
				if created {
					started++
				}
			}
			total += started
			_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.schedule.fired", RealmID: realmID, Actor: audit.System, Category: "configuration",
				Target: &audit.Ref{Type: "workflow", ID: id}, Metadata: map[string]any{"slot": slot, "runs_started": started, "truncated": truncated,
					"next_fire_at": next}})
			return err
		})
		if err != nil || !fired {
			return total, err
		}
	}
	return total, nil
}

type scheduledSubject struct{ user, org string }

// selectSubjects evaluates a fixed selector, bounded to MaxScheduleSubjects.
func (s *Service) selectSubjects(ctx context.Context, tx pgx.Tx, realmID string, sel *Selector, now time.Time) ([]scheduledSubject, bool, error) {
	var cutoff *time.Time
	if sel.GrantedBefore != "" {
		d, _ := time.ParseDuration(sel.GrantedBefore)
		c := now.Add(-d)
		cutoff = &c
	}
	var rows pgx.Rows
	var err error
	switch sel.Type {
	case "role_holders":
		rows, err = tx.Query(ctx, `SELECT DISTINCT ra.subject_id, CASE WHEN ra.scope_type='organization' THEN ra.scope_id ELSE '' END
			FROM role_assignments ra JOIN users u ON u.id=ra.subject_id
			WHERE ra.realm_id=$1 AND ra.role_id=$2 AND ra.subject_type='user' AND u.state='active'
			AND ($3='' OR (ra.scope_type='organization' AND ra.scope_id=$3)) AND ($4::timestamptz IS NULL OR ra.created_at <= $4)
			ORDER BY 1, 2 LIMIT $5`, realmID, sel.RoleID, sel.OrganizationID, cutoff, MaxScheduleSubjects+1)
	case "organization_members":
		rows, err = tx.Query(ctx, `SELECT m.user_id, m.organization_id FROM memberships m JOIN users u ON u.id=m.user_id
			WHERE m.realm_id=$1 AND m.organization_id=$2 AND m.state='active' AND u.state='active'
			AND ($3::timestamptz IS NULL OR m.created_at <= $3) ORDER BY m.user_id LIMIT $4`, realmID, sel.OrganizationID, cutoff, MaxScheduleSubjects+1)
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []scheduledSubject
	for rows.Next() {
		var x scheduledSubject
		if err := rows.Scan(&x.user, &x.org); err != nil {
			return nil, false, err
		}
		out = append(out, x)
	}
	truncated := len(out) > MaxScheduleSubjects
	if truncated {
		out = out[:MaxScheduleSubjects]
	}
	return out, truncated, rows.Err()
}

// StartInput starts a run by hand.
type StartInput struct {
	SubjectID      string `json:"subject_id"`
	OrganizationID string `json:"organization_id"`
}

// Start starts a run of a workflow with a manual trigger. The starter's own
// authority must cover every step too (a run never does more than the person
// who started it could), and nobody starts a run about themselves.
func (s *Service) Start(ctx context.Context, realmID, workflowID string, in StartInput, requestKey string, actor audit.Ref) (*Run, error) {
	if actor.Type != "user" {
		return nil, problem.ErrForbidden.WithDetail("runs are started by an administrator account")
	}
	if in.SubjectID == actor.ID {
		return nil, problem.ErrForbidden.WithDetail("a run cannot be started about yourself")
	}
	var runID string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		wfs, err := s.activeWorkflows(ctx, tx, `w.realm_id=$1 AND w.id=$2`, realmID, workflowID)
		if err != nil {
			return err
		}
		if len(wfs) == 0 {
			if _, err := s.get(ctx, tx, realmID, workflowID); err != nil {
				return err
			}
			return problem.ErrConflict.WithDetail("the workflow is not active")
		}
		wf := wfs[0]
		if !wf.def.Manual() {
			return problem.ErrConflict.WithDetail("the workflow has no manual trigger")
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 AND state NOT IN ('deleted','pending_deletion'))`,
			realmID, in.SubjectID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return problem.ErrValidation.WithField("subject_id", "unknown user")
		}
		if in.OrganizationID != "" {
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM organizations WHERE realm_id=$1 AND id=$2 AND state='active')`, realmID,
				in.OrganizationID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return problem.ErrValidation.WithField("organization_id", "unknown or inactive organization")
			}
		}
		starter := authorization.Subject{Type: authorization.SubjectUser, ID: actor.ID}
		for i, st := range wf.def.Steps {
			org := st.OrganizationID
			if org == "" {
				org = in.OrganizationID
			}
			if err := s.checkStepAuthority(ctx, tx, realmID, starter, st, org); err != nil {
				if pe, ok := problem.As(err); ok {
					return pe.WithField("steps["+strconv.Itoa(i)+"]", "exceeds your authority: "+pe.Detail)
				}
				return err
			}
		}
		if requestKey == "" {
			requestKey = newID("req")
		} else {
			// The caller's Idempotency-Key is only compared, never kept.
			requestKey = secret.Digest(requestKey)
		}
		input := map[string]any{"started_by": actor.ID}
		if in.OrganizationID != "" {
			input["organization_id"] = in.OrganizationID
		}
		runID, _, err = s.startRunTx(ctx, tx, runStart{realmID: realmID, orgID: in.OrganizationID, workflowID: wf.id, revision: wf.revision, hash: wf.hash,
			schemaVersion: wf.def.SchemaVersion, triggerType: "manual", triggerKey: "manual:" + actor.ID + ":" + requestKey, subjectID: in.SubjectID,
			input: input, inputVersion: wf.def.SchemaVersion, accountable: wf.publisher, startedBy: actor.ID})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetRun(ctx, realmID, runID)
}
