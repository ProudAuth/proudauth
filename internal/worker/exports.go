package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/credential"
	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/jobs"
	"github.com/proudbase/proudauth/internal/platform/canonical"
	"github.com/proudbase/proudauth/internal/platform/ids"
)

// exportUser produces the caller's permitted identity data without password
// verifiers, seeds, reusable tokens or other people's attributes (USR-013).
func (w *Worker) exportUser(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	userID, _ := j.Input["user_id"].(string)
	if userID == "" || userID != j.RequestedByID {
		return nil, nil, fmt.Errorf("%w: exports are limited to the requesting user", jobs.ErrPermanent)
	}
	q := w.App.D.DB.Pool
	u, err := w.App.Users.User(ctx, nil, j.RealmID, userID)
	if err != nil {
		return nil, nil, err
	}
	out := map[string]any{"format": "proudauth.user-export.v1", "generated_at": w.App.D.Now(),
		"profile": map[string]any{"id": u.ID, "display_name": u.DisplayName, "given_name": u.GivenName, "family_name": u.FamilyName,
			"locale": u.Locale, "zoneinfo": u.Zoneinfo, "profile": w.App.SchemaFor(j.RealmID).Visible(u.Profile, "self"), "created_at": u.CreatedAt}}
	idents := []map[string]any{}
	for _, i := range u.Identifiers {
		idents = append(idents, map[string]any{"type": i.Type, "value": i.Value, "verified": i.Verified(), "primary": i.IsPrimary})
	}
	out["identifiers"] = idents
	mems, _ := w.App.Orgs.UserMemberships(ctx, j.RealmID, userID)
	out["memberships"] = mems
	collect := func(sql string, args ...any) []map[string]any {
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return nil
		}
		defer rows.Close()
		var res []map[string]any
		fields := rows.FieldDescriptions()
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				return res
			}
			m := map[string]any{}
			for i, f := range fields {
				m[f.Name] = vals[i]
			}
			res = append(res, m)
		}
		return res
	}
	out["credentials"] = collect(`SELECT type, coalesce(name,'') AS name, state, created_at, last_used_at FROM credentials WHERE user_id=$1 AND state='active'`, userID)
	out["passkeys"] = collect(`SELECT coalesce(name,'') AS name, created_at, last_used_at FROM webauthn_credentials WHERE user_id=$1 AND state='active'`, userID)
	out["sessions"] = collect(`SELECT id, created_at, last_activity_at, amr, user_agent FROM sessions WHERE user_id=$1 AND state='active'`, userID)
	out["consents"] = collect(`SELECT c.client_id, cn.scopes, cn.granted_at FROM consents cn JOIN clients c ON c.id=cn.client_ref WHERE cn.user_id=$1 AND cn.revoked_at IS NULL`, userID)
	out["terms_acceptances"] = collect(`SELECT document, version, accepted_at FROM terms_acceptances WHERE user_id=$1`, userID)
	out["linked_identities"] = collect(`SELECT p.alias AS provider, e.created_at, e.last_used_at FROM external_identities e JOIN identity_providers p ON p.id=e.provider_id WHERE e.user_id=$1`, userID)
	out["security_events"] = collect(`SELECT type, occurred_at, outcome FROM audit_events WHERE realm_id=$1 AND subject_id=$2 ORDER BY seq DESC LIMIT 500`, j.RealmID, userID)
	// Historical records imported from earlier systems about the user (MIG-016).
	out["imported_history"] = collect(`SELECT source_system, event_type, occurred_at, outcome FROM imported_audit_events WHERE realm_id=$1 AND subject_id=$2
		ORDER BY occurred_at DESC LIMIT 500`, j.RealmID, userID)
	body := marshal(out)
	sum := sha256.Sum256(body)
	return map[string]any{"bytes": len(body), "sha256": hex.EncodeToString(sum[:])}, body, nil
}

// exportAudit exports a bounded audit range as JSON lines with a checksum (AUD-010).
func (w *Worker) exportAudit(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	if err := w.requesterStillAllowed(ctx, j); err != nil {
		return nil, nil, err
	}
	f := audit.Filter{RealmID: j.RealmID, OrgID: j.OrganizationID, Limit: 500}
	// Evidence for one support grant can be exported on its own (IMP-024).
	if v, ok := j.Input["impersonation_grant_id"].(string); ok {
		f.ImpersonationGrantID = v
	}
	if v, ok := j.Input["from"].(string); ok && v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid from", jobs.ErrPermanent)
		}
		f.From = &t
	}
	if v, ok := j.Input["to"].(string); ok && v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: invalid to", jobs.ErrPermanent)
		}
		f.To = &t
	}
	var sb strings.Builder
	h := sha256.New()
	count := 0
	for page := 0; page < 2000; page++ {
		events, next, err := audit.Query(ctx, w.App.D.DB.Pool, f)
		if err != nil {
			return nil, nil, err
		}
		for _, ev := range events {
			line, _ := json.Marshal(ev)
			sb.Write(line)
			sb.WriteByte('\n')
			h.Write(line)
			h.Write([]byte{'\n'})
			count++
		}
		if err := progress(map[string]any{"events": count}); err != nil {
			return nil, nil, err
		}
		if next == 0 {
			break
		}
		f.BeforeSeq = next
	}
	return map[string]any{"events": count, "sha256": hex.EncodeToString(h.Sum(nil)), "format": "application/x-ndjson"}, []byte(sb.String()), nil
}

// exportConfig exports realm configuration for configuration-as-code without
// secrets (APP-019, MIG-014): client secrets, keys and connector credentials are
// excluded and must be re-provisioned through secret references.
func (w *Worker) exportConfig(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	if err := w.requesterStillAllowed(ctx, j); err != nil {
		return nil, nil, err
	}
	doc, err := w.App.ExportConfig(ctx, j.RealmID)
	if err != nil {
		return nil, nil, err
	}
	body := marshal(doc)
	sum := sha256.Sum256(body)
	return map[string]any{"sha256": hex.EncodeToString(sum[:]), "format": doc.Format, "clients": len(doc.Clients), "resources": len(doc.Resources),
		"roles": len(doc.Roles), "permissions": len(doc.Permissions)}, body, nil
}

// ImportRecord and ImportMembership are defined in the identity package so the
// API validates import input strictly before a job is queued.
type (
	ImportRecord     = identity.ImportRecord
	ImportMembership = identity.ImportMembership
)

// importUsers imports a bounded batch with per-record validation, dry-run,
// source-qualified idempotency and checkpoints (USR-016, MIG-003/004/011). Password
// verifiers are imported only in supported formats (MIG-006); unknown roles are
// errors, never administrator access (MIG-005); deleted identifiers are not
// resurrected (MIG-017); verification flags are kept only when the import is
// explicitly trusted for them (MIG-009).
func (w *Worker) importUsers(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	source, _ := j.Input["source_system"].(string)
	trustVerified, _ := j.Input["trust_email_verification"].(bool)
	if f, _ := j.Input["format"].(string); f != "" {
		if _, ok := identity.LookupImportFormat(f); !ok {
			return nil, nil, fmt.Errorf("%w: unsupported import format %q", jobs.ErrPermanent, f)
		}
	}
	protected, err := w.Jobs.ProtectedInput(j)
	if err != nil {
		return nil, nil, err
	}
	raw, _ := json.Marshal(protected["users"])
	var records []ImportRecord
	if err := json.Unmarshal(raw, &records); err != nil || source == "" {
		return nil, nil, fmt.Errorf("%w: input requires source_system and users", jobs.ErrPermanent)
	}
	if len(records) > 1000 {
		return nil, nil, fmt.Errorf("%w: at most 1000 users per import job", jobs.ErrPermanent)
	}
	// The plan describes what a record would change (MIG-003): the identifier
	// mapping it creates, the protected fields it sets and the roles it grants.
	type planMembership struct {
		OrganizationID string   `json:"organization_id"`
		Roles          []string `json:"roles"`
		Privileged     bool     `json:"privileged,omitempty"`
	}
	type plan struct {
		Mapping          string           `json:"mapping"`
		EmailVerified    bool             `json:"email_verified"`
		PasswordVerifier bool             `json:"password_verifier"`
		TOTPFactor       bool             `json:"totp_factor"`
		Memberships      []planMembership `json:"memberships"`
		// State and RequiredActions are the protected account fields the
		// record sets (MIG-003); omitted for an active account without any.
		State           string   `json:"state,omitempty"`
		RequiredActions []string `json:"required_actions,omitempty"`
	}
	type result struct {
		Index    int    `json:"index"`
		SourceID string `json:"source_id"`
		Status   string `json:"status"`
		UserID   string `json:"user_id,omitempty"`
		Error    string `json:"error,omitempty"`
		Plan     *plan  `json:"plan,omitempty"`
	}
	results := []result{}
	counts := map[string]int{}
	totals := map[string]int{}
	start := 0
	// A resumed job continues after its last checkpoint and keeps the results
	// and counts recorded before it (MIG-011).
	if cp := j.Checkpoint(); cp != nil {
		if v, ok := cp["next_index"].(float64); ok {
			start = int(v)
		}
		raw, _ := json.Marshal(cp)
		var saved struct {
			Counts  map[string]int `json:"counts"`
			Totals  map[string]int `json:"totals"`
			Results []result       `json:"results"`
		}
		if json.Unmarshal(raw, &saved) == nil && len(saved.Results) == start {
			results = saved.Results
			for k, v := range saved.Counts {
				counts[k] = v
			}
			for k, v := range saved.Totals {
				totals[k] = v
			}
		} else {
			start = 0
		}
	}
	// Identifiers and source IDs repeated within the batch conflict with their
	// first occurrence, so a dry run reports what the real run would refuse.
	first := map[string]int{}
	batchKeys := func(rec ImportRecord) []string {
		keys := []string{"source:" + rec.SourceID}
		if c, _, err := canonical.Email(rec.Email); err == nil && rec.Email != "" {
			keys = append(keys, "email:"+c)
		}
		if c, err := canonical.Username(rec.Username); err == nil && rec.Username != "" {
			keys = append(keys, "username:"+c)
		}
		return keys
	}
	for i, rec := range records {
		for _, k := range batchKeys(rec) {
			if _, ok := first[k]; !ok {
				first[k] = i
			}
		}
	}
	actor := audit.Ref{Type: j.RequestedByType, ID: j.RequestedByID}
	// The job acts with its requester's authority, re-checked at execution time:
	// an import cannot grant more than the requester could grant directly
	// (MIG-005, INT-006), and trusting upstream verification is an explicit
	// verification override (USR-005).
	requester := authorization.Subject{Type: j.RequestedByType, ID: j.RequestedByID}
	realmScope := authorization.Scope{Type: authorization.ScopeRealm, ID: j.RealmID}
	if !w.App.Authz.Check(ctx, nil, j.RealmID, requester, "realm.users.import", realmScope) {
		return nil, nil, fmt.Errorf("%w: the requester no longer holds realm.users.import", jobs.ErrPermanent)
	}
	if trustVerified && !w.App.Authz.Check(ctx, nil, j.RealmID, requester, "realm.users.verification.override", realmScope) {
		return nil, nil, fmt.Errorf("%w: trust_email_verification requires realm.users.verification.override", jobs.ErrPermanent)
	}
	// Factor import (MIG-007) is a separate, explicit authorization.
	importTOTP, _ := j.Input["import_totp"].(bool)
	if importTOTP && !w.App.Authz.Check(ctx, nil, j.RealmID, requester, "realm.users.credentials.manage", realmScope) {
		return nil, nil, fmt.Errorf("%w: import_totp requires realm.users.credentials.manage", jobs.ErrPermanent)
	}
	// Required actions need the authority they need on existing accounts
	// (AUT-018), re-checked when the job runs.
	actionPerms := map[string]bool{}
	for _, perm := range identity.ImportPermissions(records) {
		actionPerms[perm] = w.App.Authz.Check(ctx, nil, j.RealmID, requester, perm, realmScope)
	}
	for i := start; i < len(records); i++ {
		rec := records[i]
		res := result{Index: i, SourceID: rec.SourceID}
		var recPlan *plan
		err := w.App.D.DB.Tx(ctx, func(tx pgx.Tx) error {
			res, recPlan = result{Index: i, SourceID: rec.SourceID}, nil
			if rec.SourceID == "" {
				return fmt.Errorf("source_id required")
			}
			for _, k := range batchKeys(rec) {
				if first[k] < i {
					res.Status = "conflict"
					res.Error = fmt.Sprintf("%s repeats record %d of this batch", strings.SplitN(k, ":", 2)[0], first[k])
					return nil
				}
			}
			var existing, existingState string
			if err := tx.QueryRow(ctx, `SELECT m.local_id, coalesce(u.state,'deleted') FROM import_mappings m LEFT JOIN users u ON u.id=m.local_id
				WHERE m.realm_id=$1 AND m.source_system=$2 AND m.source_type='user' AND m.source_id=$3`,
				j.RealmID, source, rec.SourceID).Scan(&existing, &existingState); err == nil {
				// Deletion continuity (MIG-017): a source record whose account was
				// deleted here is never recreated by a later import.
				if existingState == identity.StateDeleted {
					res.Status = "skipped_deleted"
					return nil
				}
				res.Status, res.UserID = "already_imported", existing
				return nil
			}
			if rec.Username != "" {
				if c, err := canonical.Username(rec.Username); err == nil {
					if tomb, _ := w.App.Users.IsTombstoned(ctx, tx, j.RealmID, "username", c); tomb {
						res.Status = "skipped_deleted"
						return nil
					}
				}
			}
			if rec.TOTPSecret != "" {
				if !importTOTP {
					return fmt.Errorf("totp_secret present but the import does not authorize factor import")
				}
				if _, err := credential.NormalizeImportedTOTPSeed(rec.TOTPSecret); err != nil {
					return err
				}
			}
			if rec.Email != "" {
				c, _, err := canonical.Email(rec.Email)
				if err != nil {
					return fmt.Errorf("invalid email")
				}
				if tomb, _ := w.App.Users.IsTombstoned(ctx, tx, j.RealmID, "email", c); tomb {
					res.Status = "skipped_deleted"
					return nil
				}
			}
			if err := validateImportProfile(rec, actionPerms, w.App.D.Cfg.Limits.MetadataBytes); err != nil {
				return err
			}
			if err := credential.ValidateImportedHash(rec.PasswordHash); err != nil {
				return err
			}
			// After the legacy migration window, legacy verifiers (salted
			// SHA-256, bcrypt, PBKDF2) are not brought in at all (CRED-004).
			if credential.IsLegacyVerifier(rec.PasswordHash) && !w.App.D.Cfg.Security.Password.LegacyHashDeadline().IsZero() &&
				!w.App.D.Now().Before(w.App.D.Cfg.Security.Password.LegacyHashDeadline()) {
				return fmt.Errorf("legacy password verifiers are no longer accepted (security.password.legacy_hashes_until)")
			}
			// Matching identifiers never merge accounts (MIG-004): an email or
			// username that belongs to an existing account is a conflict.
			for _, idf := range batchKeys(rec)[1:] {
				typ, canon, _ := strings.Cut(idf, ":")
				var owner string
				if tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type=$2 AND canonical_value=$3`,
					j.RealmID, typ, canon).Scan(&owner) == nil {
					res.Status = "conflict"
					res.Error = typ + " already belongs to another account; imports never merge accounts by matching identifiers"
					return nil
				}
			}
			pl := &plan{Mapping: source + "/" + rec.SourceID, EmailVerified: rec.Email != "" && rec.EmailVerified && trustVerified,
				PasswordVerifier: rec.PasswordHash != "", TOTPFactor: rec.TOTPSecret != "", Memberships: []planMembership{},
				RequiredActions: rec.RequiredActions}
			if rec.State == identity.StateSuspended {
				pl.State = rec.State
			}
			type mem struct {
				orgID string
				roles []string
			}
			var mems []mem
			for _, m := range rec.Memberships {
				org, err := w.App.Orgs.Resolve(ctx, j.RealmID, m.Organization)
				if err != nil {
					return fmt.Errorf("unknown organization %s", m.Organization)
				}
				pm := planMembership{OrganizationID: org.ID, Roles: []string{}}
				var roleIDs []string
				for _, rn := range m.Roles {
					role, err := w.App.Authz.RoleByName(ctx, tx, j.RealmID, "organization", rn)
					if err != nil {
						return fmt.Errorf("unmapped role %s", rn) // never becomes administrator access
					}
					if role.IsOwnerRole && j.Input["allow_owner_roles"] != true {
						return fmt.Errorf("owner role requires explicit approval")
					}
					if err := w.App.Authz.CheckAssignable(ctx, tx, j.RealmID, requester, role,
						authorization.Scope{Type: authorization.ScopeOrganization, ID: org.ID}); err != nil {
						return fmt.Errorf("role %s exceeds the requester's delegation ceiling", rn)
					}
					roleIDs = append(roleIDs, role.ID)
					pm.Roles = append(pm.Roles, role.Name)
					pm.Privileged = pm.Privileged || w.App.Authz.IsPrivilegedRole(ctx, tx, j.RealmID, role)
				}
				mems = append(mems, mem{org.ID, roleIDs})
				pl.Memberships = append(pl.Memberships, pm)
			}
			recPlan = pl
			if j.DryRun {
				res.Status, res.Plan = "valid", pl
				return nil
			}
			state := identity.StateActive
			if rec.State == identity.StateSuspended {
				state = identity.StateSuspended
			}
			u, err := w.App.Users.CreateTx(ctx, tx, j.RealmID, identity.CreateInput{Email: rec.Email, EmailVerified: rec.EmailVerified && trustVerified,
				VerificationSource: "import:" + source, Username: rec.Username, DisplayName: rec.DisplayName, GivenName: rec.GivenName,
				FamilyName: rec.FamilyName, Locale: rec.Locale, AdminMetadata: rec.AdminMetadata, RequiredActions: rec.RequiredActions,
				State: state, CreatedVia: "import:" + source})
			if err != nil {
				return err
			}
			if rec.PasswordHash != "" {
				if _, err := tx.Exec(ctx, `INSERT INTO credentials (id, realm_id, user_id, type, state, verifier, algorithm) VALUES ($1,$2,$3,'password','active',$4,'imported')`,
					ids.New(ids.Credential), j.RealmID, u.ID, rec.PasswordHash); err != nil {
					return err
				}
			}
			for _, m := range mems {
				if _, err := tx.Exec(ctx, `INSERT INTO memberships (id, realm_id, organization_id, user_id, state, source, source_reference, joined_at, created_at, updated_at)
					VALUES ($1,$2,$3,$4,'active','import',$5,$6,$6,$6)`, ids.New(ids.Membership), j.RealmID, m.orgID, u.ID, source, w.App.D.Now()); err != nil {
					return err
				}
				for _, rid := range m.roles {
					if _, err := w.App.Authz.AssignTx(ctx, tx, j.RealmID, nil, authorization.AssignInput{RoleID: rid,
						Subject: authorization.Subject{Type: authorization.SubjectUser, ID: u.ID}, Scope: authorization.Scope{Type: authorization.ScopeOrganization, ID: m.orgID},
						Source: "import", SkipCeiling: true}, actor); err != nil {
						return err
					}
				}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO import_mappings (realm_id, source_system, source_type, source_id, local_id, job_id) VALUES ($1,$2,'user',$3,$4,$5)`,
				j.RealmID, source, rec.SourceID, u.ID, j.ID); err != nil {
				return err
			}
			if rec.TOTPSecret != "" {
				if err := w.App.Auth.ImportTOTPTx(ctx, tx, j.RealmID, u.ID, rec.TOTPSecret, source, actor); err != nil {
					return err
				}
			}
			res.Status, res.UserID = "imported", u.ID
			_, err = w.App.D.Audit.Record(ctx, tx, audit.Event{Type: "user.imported", RealmID: j.RealmID, Actor: actor, Subject: &audit.Ref{Type: "user", ID: u.ID},
				Source: "import", Metadata: map[string]any{"source_system": source, "job_id": j.ID, "state": state, "required_actions": rec.RequiredActions}})
			return err
		})
		if err != nil {
			res = result{Index: i, SourceID: rec.SourceID, Status: "error", Error: err.Error()}
		} else if recPlan != nil && (res.Status == "valid" || res.Status == "imported") {
			totals["memberships"] += len(recPlan.Memberships)
			for _, pm := range recPlan.Memberships {
				totals["role_assignments"] += len(pm.Roles)
				if pm.Privileged {
					totals["privileged_memberships"]++
				}
			}
			for key, on := range map[string]bool{"trusted_verified_emails": recPlan.EmailVerified,
				"password_verifiers": recPlan.PasswordVerifier, "totp_factors": recPlan.TOTPFactor,
				"suspended_accounts":        recPlan.State == identity.StateSuspended,
				"password_updates_required": slices.Contains(recPlan.RequiredActions, identity.ActionUpdatePassword)} {
				if on {
					totals[key]++
				}
			}
		}
		counts[res.Status]++
		results = append(results, res)
		if (i+1)%50 == 0 {
			if err := progress(map[string]any{"next_index": i + 1, "counts": counts, "totals": totals, "results": results}); err != nil {
				return nil, nil, err
			}
		}
	}
	return map[string]any{"dry_run": j.DryRun, "counts": counts, "totals": totals, "results": results}, nil, nil
}

// requesterStillAllowed re-checks, when the job runs, the permission its
// requester needed to enqueue it (INT-006).
func (w *Worker) requesterStillAllowed(ctx context.Context, j *jobs.Job) error {
	perm := jobs.RequiredPermission(j.Type)
	if perm == "" {
		return nil
	}
	requester := authorization.Subject{Type: j.RequestedByType, ID: j.RequestedByID}
	if !w.App.Authz.Check(ctx, nil, j.RealmID, requester, perm, authorization.Scope{Type: authorization.ScopeRealm, ID: j.RealmID}) {
		return fmt.Errorf("%w: the requester no longer holds %s", jobs.ErrPermanent, perm)
	}
	return nil
}
