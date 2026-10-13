// Package workflow runs lifecycle workflows (EXT-015, EXT-016): versioned,
// realm-scoped definitions of onboarding, access-expiry, approval and
// offboarding steps, started by outbox events, by a schedule or by an
// administrator, and executed by the worker as durable runs.
//
// Safety contract:
//   - Steps come from a bounded vocabulary that calls existing services
//     (role assignment, group membership, membership removal, suspension,
//     notifications, signed calls to registered webhook endpoints). There is
//     no expression language and no embedded code (EXT-013).
//   - A run acts with the authority of the administrator who published its
//     revision (the accountable actor of every audit event it records), and
//     that authority is re-checked inside the transaction of every effect:
//     a workflow can never grant more than its publisher could, and stops
//     when the publisher loses the authority (AZ-006, TEN-008).
//   - Each run pins its revision; each step attempt records its input
//     version, result, retry policy, idempotency key and compensation
//     strategy. Internal effects commit atomically with their attempt record
//     under the run's lease, so a step re-run after a crash never repeats
//     them; endpoint calls carry a stable Idempotency-Key (EXT-016).
//   - A failed run compensates in reverse order what it can undo (role
//     assignments, group memberships it created) and records what it cannot
//     (sent notices, endpoint calls). Removals and suspensions are never
//     reversed automatically: re-granting access during a failure would be
//     unsafe.
package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/notification"
	"github.com/proudbase/proudauth/internal/organization"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/webhooks"
)

// Identifier prefixes.
const (
	prefixWorkflow = "wfl"
	prefixRevision = "wfr"
	prefixRun      = "wrn"
	prefixAttempt  = "wsa"
	prefixApproval = "wap"
)

// Service manages workflows and executes their runs.
type Service struct {
	d        *runtime.Deps
	Authz    *authorization.Service
	Users    *identity.Service
	Orgs     *organization.Service
	Notify   *notification.Service
	Webhooks *webhooks.Service
	Realms   *realm.Service
	// Observe, when set, sees each finished run's final state and each step
	// outcome (metrics).
	Observe func(kind, outcome string)
}

// New builds the service.
func New(d *runtime.Deps, authz *authorization.Service, users *identity.Service, orgs *organization.Service, notify *notification.Service,
	wh *webhooks.Service, realms *realm.Service) *Service {
	return &Service{d: d, Authz: authz, Users: users, Orgs: orgs, Notify: notify, Webhooks: wh, Realms: realms}
}

// ErrPluginManaged refuses ordinary API changes to a plugin's workflow.
var ErrPluginManaged = problem.ErrConflict.WithDetail("this workflow is managed by a plugin; change, disable or roll back the plugin instead")

// Workflow is a named, versioned definition.
type Workflow struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Description      string     `json:"description,omitempty"`
	State            string     `json:"state"`
	ActiveRevision   *int       `json:"active_revision,omitempty"`
	PublishedByID    string     `json:"published_by_id,omitempty"`
	RequiresApproval bool       `json:"requires_approval"`
	OwnerUserID      string     `json:"owner_user_id,omitempty"`
	PluginID         string     `json:"plugin_id,omitempty"`
	EventTypes       []string   `json:"event_types"`
	NextFireAt       *time.Time `json:"next_fire_at,omitempty"`
	Version          int64      `json:"version"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// Revision is an immutable definition revision.
type Revision struct {
	ID            string          `json:"id"`
	WorkflowID    string          `json:"workflow_id"`
	Number        int             `json:"number"`
	SchemaVersion int             `json:"schema_version"`
	Definition    json.RawMessage `json:"definition"`
	Hash          string          `json:"definition_hash"`
	Status        string          `json:"status"`
	AuthorID      string          `json:"author_id"`
	ApprovedByID  string          `json:"approved_by_id,omitempty"`
	ApprovedAt    *time.Time      `json:"approved_at,omitempty"`
	PublishedByID string          `json:"published_by_id,omitempty"`
	PublishedAt   *time.Time      `json:"published_at,omitempty"`
	Note          string          `json:"note,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

const workflowCols = `id, name, coalesce(description,''), state, active_revision, coalesce(published_by_id,''), requires_approval,
	coalesce(owner_user_id,''), coalesce(plugin_id,''), event_types, next_fire_at, version, created_at, updated_at`

func scanWorkflow(row pgx.Row) (*Workflow, error) {
	var w Workflow
	err := row.Scan(&w.ID, &w.Name, &w.Description, &w.State, &w.ActiveRevision, &w.PublishedByID, &w.RequiresApproval, &w.OwnerUserID,
		&w.PluginID, &w.EventTypes, &w.NextFireAt, &w.Version, &w.CreatedAt, &w.UpdatedAt)
	return &w, err
}

const revisionCols = `id, workflow_id, number, schema_version, definition, definition_hash, status, author_id, coalesce(approved_by_id,''),
	approved_at, coalesce(published_by_id,''), published_at, coalesce(note,''), created_at`

func scanRevision(row pgx.Row) (*Revision, error) {
	var r Revision
	var def []byte
	err := row.Scan(&r.ID, &r.WorkflowID, &r.Number, &r.SchemaVersion, &def, &r.Hash, &r.Status, &r.AuthorID, &r.ApprovedByID, &r.ApprovedAt,
		&r.PublishedByID, &r.PublishedAt, &r.Note, &r.CreatedAt)
	r.Definition = def
	return &r, err
}

// CreateInput creates a workflow with its first draft revision.
type CreateInput struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Definition  json.RawMessage `json:"definition"`
	Note        string          `json:"note"`
	// RequiresApproval asks for a second administrator's approval before
	// each publication; the realm policy extensions.workflow_publish_approval
	// makes it mandatory.
	RequiresApproval bool `json:"requires_approval"`
	// OwnerUserID is the accountable owner (DOM-009); it defaults to the
	// creating user.
	OwnerUserID string `json:"owner_user_id"`
}

func validName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 || strings.ContainsAny(name, "\r\n\t") {
		return "", problem.ErrValidation.WithField("name", "1..100 characters, no line breaks")
	}
	return name, nil
}

func (s *Service) policyFor(ctx context.Context, q storage.Querier, realmID string) realm.ExtensionsPolicy {
	if s.Realms == nil {
		return realm.ExtensionsPolicy{}
	}
	if r, err := s.Realms.ByID(ctx, q, realmID); err == nil {
		return r.Policy.Extensions
	}
	// Unknown policy: require approval (fail closed).
	return realm.ExtensionsPolicy{WorkflowPublishApproval: true}
}

// Create stores a new workflow in draft with revision 1.
func (s *Service) Create(ctx context.Context, realmID string, in CreateInput, actor audit.Ref) (*Workflow, *Revision, error) {
	name, err := validName(in.Name)
	if err != nil {
		return nil, nil, err
	}
	if len(in.Description) > 500 {
		return nil, nil, problem.ErrValidation.WithField("description", "at most 500 characters")
	}
	def, canon, hash, err := Parse(in.Definition)
	if err != nil {
		return nil, nil, err
	}
	var wf *Workflow
	var rev *Revision
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := s.checkReferences(ctx, tx, realmID, def); err != nil {
			return err
		}
		owner := in.OwnerUserID
		if owner == "" && actor.Type == "user" {
			owner = actor.ID
		}
		if owner != "" {
			var live bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 AND state='active')`, realmID, owner).Scan(&live); err != nil {
				return err
			}
			if !live {
				return problem.ErrValidation.WithField("owner_user_id", "an active account of this realm is required")
			}
		}
		requires := in.RequiresApproval || s.policyFor(ctx, tx, realmID).WorkflowPublishApproval
		id, now := newID(prefixWorkflow), s.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO workflows (id, realm_id, name, description, state, requires_approval, owner_user_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,'draft',$5,$6,$7,$7)`, id, realmID, name, nilIfEmpty(in.Description), requires, nilIfEmpty(owner), now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("name", "a workflow with this name exists")
			}
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.created", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "workflow", ID: id}, Metadata: map[string]any{"name": name, "requires_approval": requires}}); err != nil {
			return err
		}
		if rev, err = s.stageTx(ctx, tx, realmID, id, def, canon, hash, actor, in.Note, "draft", ""); err != nil {
			return err
		}
		wf, err = s.get(ctx, tx, realmID, id)
		return err
	})
	return wf, rev, err
}

func (s *Service) stageTx(ctx context.Context, tx pgx.Tx, realmID, workflowID string, def *Definition, canon []byte, hash string, actor audit.Ref,
	note, status, approvedBy string) (*Revision, error) {
	var next int
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(number),0)+1 FROM workflow_revisions WHERE workflow_id=$1`, workflowID).Scan(&next); err != nil {
		return nil, err
	}
	if len(note) > 500 {
		note = note[:500]
	}
	id := newID(prefixRevision)
	var approvedAt *time.Time
	if approvedBy != "" {
		t := s.d.Now()
		approvedAt = &t
	}
	if _, err := tx.Exec(ctx, `INSERT INTO workflow_revisions (id, realm_id, workflow_id, number, schema_version, definition, definition_hash, status,
		author_id, note, created_at, approved_by_id, approved_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, realmID, workflowID, next,
		def.SchemaVersion, canon, hash, status, actor.ID, nilIfEmpty(note), s.d.Now(), nilIfEmpty(approvedBy), approvedAt); err != nil {
		return nil, err
	}
	meta := map[string]any{"revision": next, "definition_hash": hash, "schema_version": def.SchemaVersion}
	var pluginID string
	if err := tx.QueryRow(ctx, `SELECT coalesce(plugin_id,'') FROM workflows WHERE id=$1`, workflowID).Scan(&pluginID); err != nil {
		return nil, err
	}
	if pluginID != "" {
		meta["plugin_id"] = pluginID
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.revision.staged", RealmID: realmID, Actor: actor, Category: "configuration",
		Target: &audit.Ref{Type: "workflow", ID: workflowID}, Metadata: meta}); err != nil {
		return nil, err
	}
	return scanRevision(tx.QueryRow(ctx, `SELECT `+revisionCols+` FROM workflow_revisions WHERE id=$1`, id))
}

func (s *Service) lock(ctx context.Context, tx pgx.Tx, realmID, id string) (*Workflow, error) {
	w, err := scanWorkflow(tx.QueryRow(ctx, `SELECT `+workflowCols+` FROM workflows WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return w, err
}

func (s *Service) get(ctx context.Context, q storage.Querier, realmID, id string) (*Workflow, error) {
	w, err := scanWorkflow(q.QueryRow(ctx, `SELECT `+workflowCols+` FROM workflows WHERE realm_id=$1 AND id=$2`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return w, err
}

// Get returns a workflow.
func (s *Service) Get(ctx context.Context, realmID, id string) (*Workflow, error) {
	return s.get(ctx, s.d.DB.Pool, realmID, id)
}

// List returns a realm's workflows.
func (s *Service) List(ctx context.Context, realmID string) ([]*Workflow, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+workflowCols+` FROM workflows WHERE realm_id=$1 ORDER BY name LIMIT 1000`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Workflow{}
	for rows.Next() {
		w, err := scanWorkflow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// Revisions lists a workflow's revisions, newest first.
func (s *Service) Revisions(ctx context.Context, realmID, id string) ([]*Revision, error) {
	if _, err := s.Get(ctx, realmID, id); err != nil {
		return nil, err
	}
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+revisionCols+` FROM workflow_revisions WHERE realm_id=$1 AND workflow_id=$2 ORDER BY number DESC LIMIT 200`, realmID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Revision{}
	for rows.Next() {
		r, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Revision returns one revision.
func (s *Service) Revision(ctx context.Context, realmID, id string, number int) (*Revision, error) {
	return s.revision(ctx, s.d.DB.Pool, realmID, id, number)
}

func (s *Service) revision(ctx context.Context, q storage.Querier, realmID, id string, number int) (*Revision, error) {
	r, err := scanRevision(q.QueryRow(ctx, `SELECT `+revisionCols+` FROM workflow_revisions WHERE realm_id=$1 AND workflow_id=$2 AND number=$3`,
		realmID, id, number))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return r, err
}

// StageRevision adds an immutable draft revision.
func (s *Service) StageRevision(ctx context.Context, realmID, id string, raw json.RawMessage, note string, actor audit.Ref) (*Revision, error) {
	def, canon, hash, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	var out *Revision
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		w, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if w.PluginID != "" {
			return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
		}
		if err := s.checkReferences(ctx, tx, realmID, def); err != nil {
			return err
		}
		out, err = s.stageTx(ctx, tx, realmID, id, def, canon, hash, actor, note, "draft", "")
		return err
	})
	return out, err
}

// DecideRevision approves or rejects a draft revision. The author never
// approves their own revision (AZ-018).
func (s *Service) DecideRevision(ctx context.Context, realmID, id string, number int, approve bool, note string, actor audit.Ref) (*Revision, error) {
	var out *Revision
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		w, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if w.PluginID != "" {
			return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
		}
		r, err := s.revision(ctx, tx, realmID, id, number)
		if err != nil {
			return err
		}
		if r.Status != "draft" {
			return problem.ErrConflict.WithDetail("only draft revisions can be approved or rejected")
		}
		if r.AuthorID == actor.ID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		status, event := "approved", "workflow.revision.approved"
		if !approve {
			status, event = "rejected", "workflow.revision.rejected"
		}
		if _, err := tx.Exec(ctx, `UPDATE workflow_revisions SET status=$2, approved_by_id=$3, approved_at=$4, note=coalesce(note,'')||$5 WHERE id=$1`,
			r.ID, status, actor.ID, s.d.Now(), trimNote(note)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "workflow", ID: id}, Metadata: map[string]any{"revision": number, "author_id": r.AuthorID, "definition_hash": r.Hash}}); err != nil {
			return err
		}
		out, err = s.revision(ctx, tx, realmID, id, number)
		return err
	})
	return out, err
}

func trimNote(n string) string {
	n = strings.TrimSpace(n)
	if n == "" {
		return ""
	}
	if len(n) > 200 {
		n = n[:200]
	}
	return " | " + n
}

// Publish makes a revision the active one. The publisher becomes the
// accountable actor of every run of the revision, so the publisher's
// authority must cover every step (delegation ceiling, AZ-006).
func (s *Service) Publish(ctx context.Context, realmID, id string, number int, actor audit.Ref) (*Workflow, error) {
	var out *Workflow
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		w, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if w.PluginID != "" {
			return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
		}
		r, err := s.revision(ctx, tx, realmID, id, number)
		if err != nil {
			return err
		}
		switch {
		case r.Status == "published":
			return problem.ErrConflict.WithDetail("this revision is already published")
		case r.Status == "rejected":
			return problem.ErrConflict.WithDetail("rejected revisions cannot be published")
		case r.Status == "superseded":
			return problem.ErrConflict.WithDetail("restore an earlier revision with rollback")
		case w.RequiresApproval && r.Status != "approved":
			return problem.ErrForbidden.WithDetail("this workflow requires an independent approval before publishing")
		}
		return s.publishTx(ctx, tx, realmID, w, r, actor, "workflow.published")
	})
	if err != nil {
		return nil, err
	}
	out, err = s.Get(ctx, realmID, id)
	return out, err
}

func (s *Service) publishTx(ctx context.Context, tx pgx.Tx, realmID string, w *Workflow, r *Revision, actor audit.Ref, event string) error {
	if actor.Type != "user" {
		// Runs need an accountable person whose authority can be re-checked.
		return problem.ErrForbidden.WithDetail("workflows are published by an administrator account")
	}
	def, _, _, err := Parse(r.Definition)
	if err != nil {
		return err
	}
	if err := s.checkReferences(ctx, tx, realmID, def); err != nil {
		return err
	}
	publisher := authorization.Subject{Type: authorization.SubjectUser, ID: actor.ID}
	if err := s.checkDefinitionAuthority(ctx, tx, realmID, publisher, def); err != nil {
		return err
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE workflow_revisions SET status='superseded' WHERE workflow_id=$1 AND status='published'`, w.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE workflow_revisions SET status='published', published_by_id=$2, published_at=$3 WHERE id=$1`, r.ID, actor.ID, now); err != nil {
		return err
	}
	var every *int
	var next *time.Time
	if _, d := def.Schedule(); d > 0 {
		sec := int(d / time.Second)
		every = &sec
		// Keep the slot of an unchanged schedule; a new schedule starts one
		// interval from now.
		t := now.Add(d)
		if w.NextFireAt != nil && w.NextFireAt.After(now) && w.NextFireAt.Before(t) {
			t = *w.NextFireAt
		}
		next = &t
	}
	state := w.State
	if state == "draft" {
		state = "active"
	}
	if _, err := tx.Exec(ctx, `UPDATE workflows SET active_revision=$2, published_by_id=$3, state=$4, event_types=$5, schedule_every_s=$6, next_fire_at=$7,
		version=version+1, updated_at=$8 WHERE id=$1`, w.ID, r.Number, actor.ID, state, def.EventTypes(), every, next, now); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, Actor: actor, Category: "configuration",
		Target: &audit.Ref{Type: "workflow", ID: w.ID}, Metadata: map[string]any{"name": w.Name, "revision": r.Number, "definition_hash": r.Hash,
			"previous_revision": w.ActiveRevision, "approved_by": r.ApprovedByID, "plugin_id": w.PluginID}})
	return err
}

// Rollback republishes an earlier published revision as a new revision with
// identical content, keeping history immutable. The administrator rolling
// back becomes the accountable publisher, so their authority is checked.
func (s *Service) Rollback(ctx context.Context, realmID, id string, toNumber int, actor audit.Ref) (*Workflow, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		w, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if w.PluginID != "" {
			return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
		}
		old, err := s.revision(ctx, tx, realmID, id, toNumber)
		if err != nil {
			return err
		}
		if old.PublishedAt == nil {
			return problem.ErrConflict.WithDetail("only previously published revisions can be restored")
		}
		if w.ActiveRevision != nil && *w.ActiveRevision == toNumber {
			return problem.ErrConflict.WithDetail("this revision is already active")
		}
		def, canon, hash, err := Parse(old.Definition)
		if err != nil {
			return err
		}
		// The restored content was approved before; the approval carries over.
		status := "draft"
		if old.ApprovedByID != "" {
			status = "approved"
		}
		r, err := s.stageTx(ctx, tx, realmID, id, def, canon, hash, actor, "rollback to revision "+itoa(toNumber), status, old.ApprovedByID)
		if err != nil {
			return err
		}
		if w.RequiresApproval && r.Status != "approved" {
			return problem.ErrForbidden.WithDetail("the restored revision was never approved")
		}
		return s.publishTx(ctx, tx, realmID, w, r, actor, "workflow.rolled_back")
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, realmID, id)
}

// SetState enables or disables a workflow. Disabling stops triggers and
// pauses every run in flight; compensation and cancellation still proceed
// (SEC-020).
func (s *Service) SetState(ctx context.Context, realmID, id, state string, actor audit.Ref, reason string) (*Workflow, error) {
	if state != "active" && state != "disabled" {
		return nil, problem.ErrValidation.WithField("state", "active or disabled")
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		w, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if w.PluginID != "" {
			return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
		}
		if state == "active" && w.ActiveRevision == nil {
			return problem.ErrConflict.WithDetail("publish a revision first")
		}
		if _, err := tx.Exec(ctx, `UPDATE workflows SET state=$2, version=version+1, updated_at=$3 WHERE id=$1`, id, state, s.d.Now()); err != nil {
			return err
		}
		// Disabling is an emergency control (SEC-020): it raises a security
		// alert like disabling a hook or a webhook subscription.
		category := "configuration"
		if state == "disabled" {
			category = "emergency"
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow." + map[string]string{"active": "enabled", "disabled": "disabled"}[state],
			RealmID: realmID, Actor: actor, Category: category, ReasonCode: reason, Target: &audit.Ref{Type: "workflow", ID: id}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.Get(ctx, realmID, id)
}

// Delete removes a workflow that never ran; a workflow with runs is kept as
// evidence and can only be disabled.
func (s *Service) Delete(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		w, err := s.lock(ctx, tx, realmID, id)
		if err != nil {
			return err
		}
		if w.PluginID != "" {
			return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
		}
		var runs bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workflow_runs WHERE workflow_id=$1)`, id).Scan(&runs); err != nil {
			return err
		}
		if runs {
			return problem.ErrConflict.WithDetail("a workflow with runs is kept as evidence; disable it instead")
		}
		if _, err := tx.Exec(ctx, `DELETE FROM workflows WHERE id=$1`, id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.deleted", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "workflow", ID: id}, Metadata: map[string]any{"name": w.Name}})
		return err
	})
}

// activeDefinition loads a workflow's active revision.
func (s *Service) definitionAt(ctx context.Context, q storage.Querier, realmID, workflowID string, number int) (*Definition, *Revision, error) {
	r, err := s.revision(ctx, q, realmID, workflowID, number)
	if err != nil {
		return nil, nil, err
	}
	def, _, _, err := Parse(r.Definition)
	if err != nil {
		return nil, nil, err
	}
	return def, r, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

var errLeaseLost = errors.New("workflow: run lease lost")
