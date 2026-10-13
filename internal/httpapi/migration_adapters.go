package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/migrate"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// migrationAdapterRoutes serve the first-party migration adapters (MIG-018):
// the adapters with their supported and tested source versions, and a
// read-only plan that converts an export and returns its capability report
// and what the conversion would meet in this realm. Nothing is written: the
// import itself goes through POST /organizations and POST /user-imports
// (identity-cli migrate-from --apply).
func (a *App) migrationAdapterRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/migration-adapters", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.import"); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": migrate.Adapters})
		return nil
	}))
	mux.HandleFunc("POST "+R+"/migration-plans", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.import"); err != nil {
			return err
		}
		// The exports carry password verifiers and seeds: they are
		// converted in memory and never stored, logged or returned.
		var b struct {
			Source         string            `json:"source"`
			SourceVersion  string            `json:"source_version"`
			SourceSystem   string            `json:"source_system"`
			Exports        []json.RawMessage `json:"exports"`
			Mapping        json.RawMessage   `json:"mapping"`
			KeepAttributes bool              `json:"keep_attributes"`
			ImportTOTP     bool              `json:"import_totp"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if _, ok := migrate.LookupAdapter(b.Source); !ok {
			return problem.ErrValidation.WithField("source", "keycloak, zitadel or supertokens (GET /migration-adapters)")
		}
		if len(b.Exports) == 0 || len(b.Exports) > 20 {
			return problem.ErrValidation.WithField("exports", "1 to 20 export documents")
		}
		if b.SourceSystem != "" && !identity.ValidSourceSystem(b.SourceSystem) {
			return problem.ErrValidation.WithField("source_system", "lowercase letters, digits, '.', '_' or '-', at most 63 characters")
		}
		var mapping *migrate.Mapping
		if len(b.Mapping) > 0 && string(b.Mapping) != "null" {
			m, err := migrate.ParseMapping(b.Mapping)
			if err != nil {
				return problem.ErrValidation.WithField("mapping", err.Error())
			}
			mapping = m
		}
		docs := make([][]byte, len(b.Exports))
		for i, e := range b.Exports {
			docs[i] = e
		}
		res, err := migrate.Convert(b.Source, docs, migrate.Options{SourceSystem: b.SourceSystem, SourceVersion: b.SourceVersion,
			Mapping: mapping, KeepAttributes: b.KeepAttributes, ImportTOTP: b.ImportTOTP, Now: a.D.Now})
		if err != nil {
			if errors.Is(err, migrate.ErrUnsupportedVersion) {
				return problem.ErrValidation.WithField("source_version", err.Error())
			}
			return problem.ErrValidation.WithField("exports", err.Error())
		}
		target, err := a.migrationTarget(r.Context(), p.Realm.ID, res)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"report": res.Report, "target": target, "mapping_template": migrate.Template(res, mapping)})
		return nil
	}))
}

// migrationTarget checks a conversion against the realm without writing:
// which target organizations exist (by the external ID an earlier run set,
// or by the slug a reviewed mapping names), which mapped roles exist, which
// records are already imported or were deleted (MIG-017), and which records
// meet an identifier that belongs to another account (imports never merge,
// MIG-004). Records are named by source ID only.
func (a *App) migrationTarget(ctx context.Context, realmID string, res *migrate.Result) (map[string]any, error) {
	pool := a.D.DB.Pool
	type orgPlan struct {
		migrate.TargetOrganization
		Status string `json:"status"`
		ID     string `json:"id,omitempty"`
	}
	orgs := []orgPlan{}
	for _, t := range res.Organizations {
		op := orgPlan{TargetOrganization: t, Status: "will_create"}
		var id string
		if t.ExternalID != "" && pool.QueryRow(ctx, `SELECT id FROM organizations WHERE realm_id=$1 AND external_id=$2 AND state<>'deleted'`,
			realmID, t.ExternalID).Scan(&id) == nil {
			op.Status, op.ID = "exists", id
		} else if o, err := a.Orgs.Resolve(ctx, realmID, t.Slug); err == nil {
			op.ID = o.ID
			op.Status = "exists"
			if !t.FromMapping {
				op.Status = "conflict"
			}
		} else if t.ExternalID == "" {
			op.Status = "conflict"
		}
		orgs = append(orgs, op)
	}
	wanted := map[string]bool{}
	for _, u := range res.Users {
		for _, m := range u.Memberships {
			for _, rn := range m.Roles {
				wanted[strings.ToLower(rn)] = true
			}
		}
	}
	roles := []map[string]any{}
	for _, rn := range slices.Sorted(maps.Keys(wanted)) {
		role, err := a.Authz.RoleByName(ctx, nil, realmID, "organization", rn)
		entry := map[string]any{"name": rn, "exists": err == nil}
		if err == nil {
			entry["privileged"] = a.Authz.IsPrivilegedRole(ctx, nil, realmID, role)
			entry["owner"] = role.IsOwnerRole
		}
		roles = append(roles, entry)
	}
	ids := make([]string, len(res.Users))
	for i, u := range res.Users {
		ids[i] = u.SourceID
	}
	already, deleted := []string{}, []string{}
	rows, err := pool.Query(ctx, `SELECT m.source_id, coalesce(u.state,'deleted') FROM import_mappings m LEFT JOIN users u ON u.id=m.local_id
		WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' AND m.source_id = ANY($3) ORDER BY m.source_id`, realmID, res.SourceSystem, ids)
	if err != nil {
		return nil, err
	}
	mapped := map[string]bool{}
	for rows.Next() {
		var sid, state string
		if err := rows.Scan(&sid, &state); err != nil {
			rows.Close()
			return nil, err
		}
		mapped[sid] = true
		if state == identity.StateDeleted {
			deleted = append(deleted, sid)
		} else {
			already = append(already, sid)
		}
	}
	rows.Close()
	// Identifiers owned by existing accounts, looked up in one query per
	// type; matching identifiers never merge accounts (MIG-004).
	keys := map[string][]string{}   // "type:canonical" -> source IDs
	values := map[string][]string{} // type -> canonical values
	for _, u := range res.Users {
		if mapped[u.SourceID] {
			continue
		}
		if c, _, err := canonical.Email(u.Email); u.Email != "" && err == nil {
			keys["email:"+c] = append(keys["email:"+c], u.SourceID)
			values["email"] = append(values["email"], c)
		}
		if c, err := canonical.Username(u.Username); u.Username != "" && err == nil {
			keys["username:"+c] = append(keys["username:"+c], u.SourceID)
			values["username"] = append(values["username"], c)
		}
	}
	conflicted := map[string]bool{}
	for typ, vs := range values {
		rows, err := pool.Query(ctx, `SELECT canonical_value FROM user_identifiers WHERE realm_id=$1 AND type=$2 AND canonical_value = ANY($3)`, realmID, typ, vs)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				rows.Close()
				return nil, err
			}
			for _, sid := range keys[typ+":"+c] {
				conflicted[sid] = true
			}
		}
		rows.Close()
	}
	conflicts := []string{}
	for _, u := range res.Users {
		if conflicted[u.SourceID] {
			conflicts = append(conflicts, u.SourceID)
		}
	}
	return map[string]any{"organizations": orgs, "roles": roles, "users": len(res.Users), "already_imported": already,
		"skipped_deleted": deleted, "identifier_conflicts": conflicts}, nil
}
