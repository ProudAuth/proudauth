package workflow

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// ValidateDefinition checks a definition and its references as Create
// does; plugin packages validate their workflows with it before review.
func (s *Service) ValidateDefinition(ctx context.Context, realmID string, raw json.RawMessage) (*Definition, error) {
	def, _, _, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return def, s.checkReferences(ctx, s.d.DB.Pool, realmID, def)
}

// GuardManual refuses ordinary changes to a plugin's workflow.
func (s *Service) GuardManual(ctx context.Context, realmID, id string) error {
	w, err := s.Get(ctx, realmID, id)
	if err != nil {
		return err
	}
	if w.PluginID != "" {
		return ErrPluginManaged.WithExtension("plugin_id", w.PluginID)
	}
	return nil
}

// ApplyPluginTx creates or updates, by name, a workflow a plugin manages and
// publishes the plugin's definition with the installing administrator as the
// accountable publisher (their authority is checked like any publication).
// The plugin version's review stands in for the revision approval and is
// recorded as its approver. An unchanged definition keeps its revision.
func (s *Service) ApplyPluginTx(ctx context.Context, tx pgx.Tx, realmID, pluginID, name, description string, raw json.RawMessage, reviewerID string,
	enabled bool, actor audit.Ref) (string, error) {
	name, err := validName(name)
	if err != nil {
		return "", err
	}
	def, canon, hash, err := Parse(raw)
	if err != nil {
		return "", err
	}
	w, err := scanWorkflow(tx.QueryRow(ctx, `SELECT `+workflowCols+` FROM workflows WHERE realm_id=$1 AND name=$2 FOR UPDATE`, realmID, name))
	switch {
	case storage.IsNoRows(err):
		id := newID(prefixWorkflow)
		if _, err := tx.Exec(ctx, `INSERT INTO workflows (id, realm_id, name, description, state, requires_approval, owner_user_id, plugin_id, created_at, updated_at)
			VALUES ($1,$2,$3,$4,'draft',false,$5,$6,$7,$7)`, id, realmID, name, nilIfEmpty(description), nilIfEmpty(actor.ID), pluginID, s.d.Now()); err != nil {
			return "", err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "workflow.created", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "workflow", ID: id}, Metadata: map[string]any{"name": name, "plugin_id": pluginID}}); err != nil {
			return "", err
		}
		if w, err = s.lock(ctx, tx, realmID, id); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case w.PluginID != pluginID:
		return "", problem.ErrConflict.WithField("workflows", "a workflow named "+name+" exists and is not managed by this plugin")
	}
	// A version that names a retired workflow brings it back.
	if _, err := tx.Exec(ctx, `UPDATE workflows SET description=$2, plugin_retired=false WHERE id=$1`, w.ID, nilIfEmpty(description)); err != nil {
		return "", err
	}
	if w.ActiveRevision != nil {
		cur, err := s.revision(ctx, tx, realmID, w.ID, *w.ActiveRevision)
		if err != nil {
			return "", err
		}
		if cur.Hash == hash && cur.PublishedByID == actor.ID {
			return w.ID, s.setPluginWorkflowState(ctx, tx, w, enabled)
		}
	}
	if err := s.checkReferences(ctx, tx, realmID, def); err != nil {
		return "", err
	}
	r, err := s.stageTx(ctx, tx, realmID, w.ID, def, canon, hash, actor, "plugin "+pluginID, "approved", reviewerID)
	if err != nil {
		return "", err
	}
	if err := s.publishTx(ctx, tx, realmID, w, r, actor, "workflow.published"); err != nil {
		return "", err
	}
	if w, err = s.lock(ctx, tx, realmID, w.ID); err != nil {
		return "", err
	}
	return w.ID, s.setPluginWorkflowState(ctx, tx, w, enabled)
}

func (s *Service) setPluginWorkflowState(ctx context.Context, tx pgx.Tx, w *Workflow, enabled bool) error {
	state := "disabled"
	if enabled {
		state = "active"
	}
	if w.State == state {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE workflows SET state=$2, version=version+1, updated_at=$3 WHERE id=$1`, w.ID, state, s.d.Now())
	return err
}

// SetPluginStateTx enables or disables every published workflow of a plugin
// in the caller's transaction (EXT-014). Disabled workflows start nothing and
// their runs pause.
func (s *Service) SetPluginStateTx(ctx context.Context, tx pgx.Tx, realmID, pluginID, state string) (int, error) {
	if state != "active" && state != "disabled" {
		return 0, problem.ErrValidation.WithField("state", "active or disabled")
	}
	// Workflows a later version dropped stay as disabled evidence.
	tag, err := tx.Exec(ctx, `UPDATE workflows SET state=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND plugin_id=$2 AND active_revision IS NOT NULL
		AND state<>$3 AND NOT plugin_retired`, realmID, pluginID, state, s.d.Now())
	return int(tag.RowsAffected()), err
}

// RemovePluginPartsTx removes the plugin's workflows whose names are not in
// keep. A workflow that ran is kept, disabled, as evidence (and can return
// with a rollback); one that never ran is deleted.
func (s *Service) RemovePluginPartsTx(ctx context.Context, tx pgx.Tx, realmID, pluginID string, keep []string, actor audit.Ref) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id, name, EXISTS (SELECT 1 FROM workflow_runs r WHERE r.workflow_id=w.id) FROM workflows w
		WHERE realm_id=$1 AND plugin_id=$2 AND NOT plugin_retired FOR UPDATE`, realmID, pluginID)
	if err != nil {
		return nil, err
	}
	type item struct {
		id, name string
		ran      bool
	}
	var drop []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.name, &it.ran); err != nil {
			rows.Close()
			return nil, err
		}
		if !slices.Contains(keep, it.name) {
			drop = append(drop, it)
		}
	}
	rows.Close()
	var out []string
	for _, it := range drop {
		event := "workflow.deleted"
		if it.ran {
			event = "workflow.disabled"
			if _, err := tx.Exec(ctx, `UPDATE workflows SET state='disabled', plugin_retired=true, version=version+1, updated_at=$2 WHERE id=$1`, it.id, s.d.Now()); err != nil {
				return nil, err
			}
		} else if _, err := tx.Exec(ctx, `DELETE FROM workflows WHERE id=$1`, it.id); err != nil {
			return nil, err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "workflow", ID: it.id}, Metadata: map[string]any{"name": it.name, "plugin_id": pluginID}}); err != nil {
			return nil, err
		}
		out = append(out, it.id)
	}
	return out, nil
}
