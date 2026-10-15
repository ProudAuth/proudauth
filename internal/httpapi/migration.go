package httpapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// migrationRoutes serve the import formats (MIG-002) and the reconciliation
// report an operator compares with the source before cutover (MIG-012).
func (a *App) migrationRoutes(mux *http.ServeMux) {
	a.migrationAdapterRoutes(mux) // first-party adapters (MIG-018)
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("GET "+R+"/user-import-formats", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.import"); err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": identity.ImportFormats})
		return nil
	}))
	mux.HandleFunc("GET "+R+"/user-imports/reconciliation", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.users.import"); err != nil {
			return err
		}
		q := r.URL.Query()
		source := q.Get("source_system")
		if !identity.ValidSourceSystem(source) {
			return problem.ErrValidation.WithField("source_system", "the source_system of the imports to reconcile")
		}
		rep, err := a.reconcileImport(r.Context(), p.Realm.ID, source)
		if err != nil {
			return err
		}
		// Expected counts from the source export are compared with what the
		// realm holds now; every difference is listed.
		mismatches := []map[string]any{}
		for _, m := range []struct{ param, measure string }{
			{"expected_users", "users"}, {"expected_memberships", "memberships"}, {"expected_privileged_assignments", "privileged_assignments"},
			{"expected_password_verifiers", "password_verifiers"}, {"expected_totp_factors", "totp_factors"},
		} {
			v := q.Get(m.param)
			if v == "" {
				continue
			}
			want, err := strconv.Atoi(v)
			if err != nil || want < 0 {
				return problem.ErrValidation.WithField(m.param, "a non-negative integer")
			}
			if got := rep.measures[m.measure]; got != want {
				mismatches = append(mismatches, map[string]any{"measure": m.measure, "expected": want, "actual": got})
			}
		}
		rep.body["mismatches"] = mismatches
		rep.body["reconciled"] = len(mismatches) == 0
		writeJSON(w, http.StatusOK, rep.body)
		return nil
	}))
}

type reconciliation struct {
	body     map[string]any
	measures map[string]int
}

// reconcileImport summarizes what the realm holds for the users imported from
// one source system: accounts by state, memberships, privileged assignments,
// credential usability and verified identifiers. It reports counts and, for
// privileged assignments, the accounts concerned; never credentials or
// contact data.
func (a *App) reconcileImport(ctx context.Context, realmID, source string) (*reconciliation, error) {
	pool := a.D.DB.Pool
	const mapped = `SELECT m.local_id AS user_id, m.source_id FROM import_mappings m JOIN users u ON u.id=m.local_id
		WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' AND u.state<>'deleted'`
	byState := map[string]int{}
	rows, err := pool.Query(ctx, `SELECT coalesce(u.state,'missing'), count(*) FROM import_mappings m LEFT JOIN users u ON u.id=m.local_id
		WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' GROUP BY 1`, realmID, source)
	if err != nil {
		return nil, err
	}
	mappings := 0
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			rows.Close()
			return nil, err
		}
		byState[st] = n
		mappings += n
	}
	rows.Close()
	if mappings == 0 {
		return nil, problem.ErrNotFound.WithDetail("no users were imported from this source_system")
	}
	var c struct {
		users, memberships, importedMemberships, orgs, passwords, unconverted, totp, passkeys, federated, noLogin, verified, signedIn int
	}
	err = pool.QueryRow(ctx, `WITH mu AS (`+mapped+`)
		SELECT (SELECT count(*) FROM mu),
		(SELECT count(*) FROM memberships ms JOIN mu ON mu.user_id=ms.user_id WHERE ms.state='active'),
		(SELECT count(*) FROM memberships ms JOIN mu ON mu.user_id=ms.user_id WHERE ms.state='active' AND ms.source='import' AND ms.source_reference=$2),
		(SELECT count(DISTINCT ms.organization_id) FROM memberships ms JOIN mu ON mu.user_id=ms.user_id WHERE ms.state='active'),
		(SELECT count(DISTINCT c.user_id) FROM credentials c JOIN mu ON mu.user_id=c.user_id WHERE c.type='password' AND c.state='active'),
		(SELECT count(DISTINCT c.user_id) FROM credentials c JOIN mu ON mu.user_id=c.user_id WHERE c.type='password' AND c.state='active' AND c.algorithm='imported'),
		(SELECT count(DISTINCT c.user_id) FROM credentials c JOIN mu ON mu.user_id=c.user_id WHERE c.type='totp' AND c.state='active'),
		(SELECT count(DISTINCT wc.user_id) FROM webauthn_credentials wc JOIN mu ON mu.user_id=wc.user_id),
		(SELECT count(DISTINCT ei.user_id) FROM external_identities ei JOIN mu ON mu.user_id=ei.user_id),
		(SELECT count(*) FROM mu WHERE NOT EXISTS (SELECT 1 FROM credentials c WHERE c.user_id=mu.user_id AND c.type='password' AND c.state='active')
			AND NOT EXISTS (SELECT 1 FROM webauthn_credentials wc WHERE wc.user_id=mu.user_id)
			AND NOT EXISTS (SELECT 1 FROM external_identities ei WHERE ei.user_id=mu.user_id)),
		(SELECT count(DISTINCT ui.user_id) FROM user_identifiers ui JOIN mu ON mu.user_id=ui.user_id WHERE ui.type='email' AND ui.verified_at IS NOT NULL),
		(SELECT count(*) FROM mu JOIN users u ON u.id=mu.user_id WHERE u.last_login_at IS NOT NULL)`, realmID, source).Scan(
		&c.users, &c.memberships, &c.importedMemberships, &c.orgs, &c.passwords, &c.unconverted, &c.totp, &c.passkeys, &c.federated,
		&c.noLogin, &c.verified, &c.signedIn)
	if err != nil {
		return nil, err
	}
	type privileged struct {
		UserID    string `json:"user_id"`
		SourceID  string `json:"source_id"`
		Role      string `json:"role"`
		ScopeType string `json:"scope_type"`
		ScopeID   string `json:"scope_id"`
		Source    string `json:"assignment_source"`
	}
	priv := []privileged{}
	var privTotal int
	if err := pool.QueryRow(ctx, `WITH mu AS (`+mapped+`) SELECT count(*) FROM role_assignments ra JOIN mu ON mu.user_id=ra.subject_id
		JOIN roles ro ON ro.realm_id=ra.realm_id AND ro.id=ra.role_id WHERE ra.subject_type='user' AND `+authorization.PrivilegedRoleSQL(3),
		realmID, source, authorization.PrivilegedPermissions()).Scan(&privTotal); err != nil {
		return nil, err
	}
	rows, err = pool.Query(ctx, `WITH mu AS (`+mapped+`) SELECT mu.user_id, mu.source_id, ro.name, ra.scope_type, ra.scope_id, ra.source
		FROM role_assignments ra JOIN mu ON mu.user_id=ra.subject_id JOIN roles ro ON ro.realm_id=ra.realm_id AND ro.id=ra.role_id
		WHERE ra.subject_type='user' AND `+authorization.PrivilegedRoleSQL(3)+` ORDER BY mu.source_id, ro.name LIMIT 200`,
		realmID, source, authorization.PrivilegedPermissions())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pa privileged
		if err := rows.Scan(&pa.UserID, &pa.SourceID, &pa.Role, &pa.ScopeType, &pa.ScopeID, &pa.Source); err != nil {
			rows.Close()
			return nil, err
		}
		priv = append(priv, pa)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	measures := map[string]int{"users": c.users, "memberships": c.memberships, "privileged_assignments": privTotal,
		"password_verifiers": c.passwords, "totp_factors": c.totp}
	body := map[string]any{
		"source_system": source,
		"generated_at":  a.D.Now().UTC(),
		"mappings":      map[string]any{"total": mappings, "by_state": byState},
		"users":         c.users,
		"memberships": map[string]any{"active": c.memberships, "from_import": c.importedMemberships,
			"organizations": c.orgs},
		"privileged_assignments": map[string]any{"total": privTotal, "items": priv, "truncated": privTotal > len(priv)},
		"credentials": map[string]any{"password": c.passwords, "password_not_yet_rehashed": c.unconverted, "totp": c.totp,
			"passkey": c.passkeys, "federated": c.federated, "without_sign_in_method": c.noLogin},
		"verified_emails":    c.verified,
		"signed_in_since":    c.signedIn,
		"subject_continuity": map[string]any{"resolvable_source_ids": c.users, "deleted_since_import": byState[identity.StateDeleted]},
	}
	return &reconciliation{body: body, measures: measures}, nil
}
