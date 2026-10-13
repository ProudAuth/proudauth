package hooks

import (
	"context"
	"encoding/base64"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/keys"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/platform/secret"
	"github.com/proudbase/proudauth/internal/storage"
)

// Validate checks a hook exactly as the API does. Plugin packages validate
// every part they would configure before a review starts (EXT-014).
func (s *Service) Validate(in *Input) error { return s.validate(in) }

// ErrPluginManaged refuses ordinary API changes to a hook a plugin manages:
// the plugin is changed, disabled or rolled back instead, so its parts never
// drift from the reviewed package (EXT-014). Emergency controls still apply.
var ErrPluginManaged = problem.ErrConflict.WithDetail("this hook is managed by a plugin; change, disable or roll back the plugin instead")

// GuardManual returns ErrPluginManaged for a plugin-managed hook.
func (s *Service) GuardManual(ctx context.Context, realmID, id string) error {
	var p string
	err := s.d.DB.Pool.QueryRow(ctx, `SELECT coalesce(plugin_id,'') FROM hooks WHERE realm_id=$1 AND id=$2`, realmID, id).Scan(&p)
	if storage.IsNoRows(err) {
		return nil // the operation reports not found itself
	}
	if err != nil {
		return err
	}
	if p != "" {
		return ErrPluginManaged.WithExtension("plugin_id", p)
	}
	return nil
}

// ApplyPluginTx creates or updates, by name, a hook a plugin manages
// (EXT-014). An update keeps the signing secret, so the endpoint keeps
// verifying across plugin upgrades and rollbacks; the secret of a new hook is
// returned once. A hook of the same name that the plugin does not manage is
// never taken over.
func (s *Service) ApplyPluginTx(ctx context.Context, tx pgx.Tx, realmID, pluginID string, in Input, actor audit.Ref) (string, string, error) {
	if err := s.validate(&in); err != nil {
		return "", "", err
	}
	var id, owner string
	err := tx.QueryRow(ctx, `SELECT id, coalesce(plugin_id,'') FROM hooks WHERE realm_id=$1 AND name=$2 FOR UPDATE`, realmID, in.Name).Scan(&id, &owner)
	if err != nil && !storage.IsNoRows(err) {
		return "", "", err
	}
	if err == nil && owner != pluginID {
		return "", "", problem.ErrConflict.WithField("hooks", "a hook named "+in.Name+" exists and is not managed by this plugin")
	}
	if err == nil {
		if _, err := tx.Exec(ctx, `UPDATE hooks SET kind=$3, url=$4, timeout_ms=$5, failure_mode=$6, client_ids=$7, allow_private_network=$8,
			state=CASE WHEN emergency_disabled THEN 'disabled' ELSE $9 END, contract_version=$10, version=version+1, updated_at=$11 WHERE realm_id=$1 AND id=$2`, realmID, id, in.Kind, in.URL, in.TimeoutMS,
			in.FailureMode, in.ClientIDs, in.AllowPrivateNetwork, in.State, in.ContractVersion, s.d.Now()); err != nil {
			return "", "", err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.updated", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "hook", ID: id}, Metadata: map[string]any{"kind": in.Kind, "state": in.State, "failure_mode": in.FailureMode,
				"plugin_id": pluginID, "contract_version": in.ContractVersion}})
		return id, "", err
	}
	plain := "hksec_" + base64.StdEncoding.EncodeToString(secret.Random(32))
	id = ids.New("hok")
	ct, kv, err := s.d.Keys.Encrypt(keys.PurposeWebhook, []byte(plain), []byte("hook:"+id))
	if err != nil {
		return "", "", err
	}
	var ownerUser *string
	if actor.Type == "user" {
		ownerUser = &actor.ID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO hooks (id, realm_id, name, kind, url, secret_ciphertext, key_version, timeout_ms, failure_mode, client_ids,
		allow_private_network, state, created_at, updated_at, owner_user_id, contract_version, plugin_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16)`, id, realmID, in.Name, in.Kind, in.URL, ct, kv, in.TimeoutMS,
		in.FailureMode, in.ClientIDs, in.AllowPrivateNetwork, in.State, s.d.Now(), ownerUser, in.ContractVersion, pluginID); err != nil {
		return "", "", err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.created", RealmID: realmID, Actor: actor, Category: "configuration",
		Target: &audit.Ref{Type: "hook", ID: id}, Metadata: map[string]any{"kind": in.Kind, "url_host": hostOf(in.URL), "failure_mode": in.FailureMode,
			"plugin_id": pluginID, "contract_version": in.ContractVersion}})
	return id, plain, err
}

// RemovePluginPartsTx deletes the plugin's hooks whose names are not in keep
// (all of them for an empty keep) and returns their IDs.
func (s *Service) RemovePluginPartsTx(ctx context.Context, tx pgx.Tx, realmID, pluginID string, keep []string, actor audit.Ref) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT id, name FROM hooks WHERE realm_id=$1 AND plugin_id=$2 FOR UPDATE`, realmID, pluginID)
	if err != nil {
		return nil, err
	}
	var drop []string
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			rows.Close()
			return nil, err
		}
		if !slices.Contains(keep, name) {
			drop = append(drop, id)
		}
	}
	rows.Close()
	for _, id := range drop {
		if _, err := tx.Exec(ctx, `DELETE FROM hooks WHERE id=$1`, id); err != nil {
			return nil, err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "hook.deleted", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "hook", ID: id}, Metadata: map[string]any{"plugin_id": pluginID}}); err != nil {
			return nil, err
		}
	}
	return drop, nil
}

// SetPluginStateTx activates or disables every hook of a plugin in the
// caller's transaction (EXT-014: disabling a plugin stops all its parts at
// once). A disabled hook is simply not consulted.
func (s *Service) SetPluginStateTx(ctx context.Context, tx pgx.Tx, realmID, pluginID, state string) (int, error) {
	if state != "active" && state != "disabled" {
		return 0, problem.ErrValidation.WithField("state", "active or disabled")
	}
	// Parts an administrator switched off in an emergency stay off.
	tag, err := tx.Exec(ctx, `UPDATE hooks SET state=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND plugin_id=$2 AND state<>$3
		AND NOT (emergency_disabled AND $3='active')`, realmID, pluginID, state, s.d.Now())
	return int(tag.RowsAffected()), err
}
