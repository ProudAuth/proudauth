package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/proudauth/proudauth/internal/jobs"
)

// RealmExportFormat names the portable realm export (OSS-008, MIG-014).
const RealmExportFormat = "proudauth.realm-export.v1"

// realmExportHeartbeat is how many records of one section are exported
// between lease renewals.
const realmExportHeartbeat = 1000

// realmExportExcluded lists what the export never carries, and why.
var realmExportExcluded = []string{
	"password verifiers and imported password hashes (credential secrets; migrate them through a dedicated, approved process)",
	"TOTP seeds and recovery codes (shared secrets)",
	"passkey credentials (bound to this relying party; users enroll again)",
	"client secrets, webhook and hook secrets, identity-provider client secrets (re-provision through secret references)",
	"signing and encryption keys",
	"active tokens, sessions, grants and consents (live bearer state)",
	"audit evidence (export it with POST /audit-exports)",
	"deleted accounts (tombstones only)",
}

// realmExportSections are dumped in order, each row as one NDJSON record
// {"kind": ..., "data": ...}. Columns are listed explicitly: secret columns
// can never leak into the export by being added to a table later.
var realmExportSections = []struct{ kind, sql string }{
	{"user", `SELECT row_to_json(x) FROM (SELECT u.id, u.state, u.display_name, u.given_name, u.family_name, u.locale, u.zoneinfo, u.profile,
		u.admin_metadata, u.protected, u.is_guest, u.required_actions, u.created_via, u.last_login_at, u.created_at, u.updated_at,
		(SELECT coalesce(json_agg(json_build_object('type', i.type, 'value', i.original_value, 'verified', i.verified_at IS NOT NULL,
			'verified_at', i.verified_at, 'primary', i.is_primary) ORDER BY i.type, i.original_value), '[]'::json) FROM user_identifiers i WHERE i.user_id=u.id) AS identifiers,
		(SELECT coalesce(json_agg(json_build_object('source_system', m.source_system, 'source_id', m.source_id) ORDER BY m.source_system), '[]'::json)
			FROM import_mappings m WHERE m.realm_id=u.realm_id AND m.source_type='user' AND m.local_id=u.id) AS external_ids,
		(SELECT coalesce(json_agg(json_build_object('provider_id', e.provider_id, 'upstream_issuer', e.upstream_issuer, 'upstream_subject', e.upstream_subject)
			ORDER BY e.provider_id), '[]'::json) FROM external_identities e WHERE e.user_id=u.id) AS federated_identities,
		json_build_object('password', EXISTS (SELECT 1 FROM credentials c WHERE c.user_id=u.id AND c.type='password' AND c.state='active'),
			'totp', EXISTS (SELECT 1 FROM credentials c WHERE c.user_id=u.id AND c.type='totp' AND c.state='active'),
			'hotp', EXISTS (SELECT 1 FROM credentials c WHERE c.user_id=u.id AND c.type='hotp' AND c.state='active'),
			'passkeys', (SELECT count(*) FROM webauthn_credentials w WHERE w.user_id=u.id AND w.state='active')) AS credentials
		FROM users u WHERE u.realm_id=$1 AND u.state <> 'deleted' ORDER BY u.id) x`},
	{"organization", `SELECT row_to_json(x) FROM (SELECT o.id, o.slug, o.display_name, o.state, o.locale, o.time_zone, o.metadata, o.contact, o.external_id,
		o.policy, o.template_name, o.template_version, o.created_at, o.updated_at,
		(SELECT coalesce(json_agg(json_build_object('domain', d.domain, 'state', d.state, 'include_subdomains', d.include_subdomains,
			'verified_at', d.verified_at) ORDER BY d.domain), '[]'::json) FROM organization_domains d WHERE d.organization_id=o.id AND d.state <> 'removed') AS domains
		FROM organizations o WHERE o.realm_id=$1 AND o.state <> 'deleted' ORDER BY o.id) x`},
	{"membership", `SELECT row_to_json(x) FROM (SELECT m.id, m.organization_id, m.user_id, m.state, m.source, m.external_id, m.metadata, m.joined_at,
		m.expires_at, m.created_at,
		(SELECT coalesce(json_agg(json_build_object('role_id', ra.role_id, 'role', r.name) ORDER BY r.name), '[]'::json)
			FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.membership_id=m.id) AS roles
		FROM memberships m WHERE m.realm_id=$1 AND m.state NOT IN ('removed','expired') ORDER BY m.id) x`},
	{"group", `SELECT row_to_json(x) FROM (SELECT g.id, g.organization_id, g.parent_id, g.name, g.description, g.metadata, g.external_id, g.source,
		g.dynamic_rule, g.created_at,
		(SELECT coalesce(json_agg(gm.membership_id ORDER BY gm.membership_id), '[]'::json) FROM group_memberships gm WHERE gm.group_id=g.id) AS members
		FROM groups g WHERE g.realm_id=$1 ORDER BY g.id) x`},
	{"role_assignment", `SELECT row_to_json(x) FROM (SELECT ra.id, ra.role_id, r.name AS role, ra.subject_type, ra.subject_id, ra.scope_type, ra.scope_id,
		ra.conditions, ra.valid_from, ra.expires_at, ra.source, ra.reason, ra.created_at
		FROM role_assignments ra JOIN roles r ON r.id=ra.role_id WHERE ra.realm_id=$1 AND ra.membership_id IS NULL ORDER BY ra.id) x`},
	{"authorization_policy", `SELECT row_to_json(x) FROM (SELECT p.id, p.name, p.description, p.scope_type, p.scope_id, p.state, p.requires_approval,
		p.owner_user_id, p.created_at,
		(SELECT v.definition FROM policy_versions v WHERE v.policy_id=p.id AND v.version_number=p.active_version) AS definition
		FROM policies p WHERE p.realm_id=$1 ORDER BY p.id) x`},
	{"project", `SELECT row_to_json(x) FROM (SELECT id, name, description, environment, state, owner_user_id, owner_organization_id, created_at
		FROM projects WHERE realm_id=$1 ORDER BY id) x`},
	{"service_principal", `SELECT row_to_json(x) FROM (SELECT id, name, description, owner_user_id, owner_organization_id, state, allowed_organization_ids,
		is_agent, created_at FROM service_principals WHERE realm_id=$1 AND state <> 'deleted' ORDER BY id) x`},
	{"identity_provider", `SELECT row_to_json(x) FROM (SELECT id, organization_id, alias, display_name, kind, adapter, state, issuer, config, linking_policy,
		jit_provisioning, jit_default_role_id, trust_upstream_mfa, claim_mapping, owner_user_id, created_at FROM identity_providers WHERE realm_id=$1 ORDER BY id) x`},
	{"webhook", `SELECT row_to_json(x) FROM (SELECT id, organization_id, name, destination_url, event_types, state, allow_private_network, payload_form,
		owner_user_id, created_at FROM webhook_subscriptions WHERE realm_id=$1 ORDER BY id) x`},
	{"hook", `SELECT row_to_json(x) FROM (SELECT id, name, kind, url, timeout_ms, failure_mode, client_ids, allow_private_network, state, owner_user_id,
		created_at FROM hooks WHERE realm_id=$1 ORDER BY id) x`},
}

// exportRealm writes the realm's identities, organizations, memberships,
// groups, assignments, policies, integrations and configuration as NDJSON
// with stable IDs (OSS-008, MIG-014). Credential secrets and live bearer
// state are excluded and listed in the header.
func (w *Worker) exportRealm(ctx context.Context, j *jobs.Job, progress func(map[string]any) error) (map[string]any, []byte, error) {
	if err := w.requesterStillAllowed(ctx, j); err != nil {
		return nil, nil, err
	}
	rlm, err := w.App.Realms.ByID(ctx, nil, j.RealmID)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	emit := func(kind string, data any) error { return enc.Encode(map[string]any{"kind": kind, "data": data}) }
	if err := emit("header", map[string]any{"format": RealmExportFormat, "generated_at": w.App.D.Now(),
		"realm":    map[string]any{"id": rlm.ID, "name": rlm.Name, "display_name": rlm.DisplayName, "issuer": rlm.Issuer},
		"excluded": realmExportExcluded}); err != nil {
		return nil, nil, err
	}
	cfg, err := w.App.ExportConfig(ctx, j.RealmID)
	if err != nil {
		return nil, nil, err
	}
	if err := emit("configuration", cfg); err != nil {
		return nil, nil, err
	}
	counts := map[string]any{}
	for _, sec := range realmExportSections {
		// progress renews the job's lease, as other long jobs renew it: before
		// every section and every realmExportHeartbeat records within one, so
		// a large realm never outlives the lease and gets claimed by a second
		// worker mid-export.
		if err := progress(map[string]any{"section": sec.kind, "records": 0}); err != nil {
			return nil, nil, err
		}
		rows, err := w.App.D.DB.Pool.Query(ctx, sec.sql, j.RealmID)
		if err != nil {
			return nil, nil, err
		}
		n := 0
		for rows.Next() {
			var raw json.RawMessage
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return nil, nil, err
			}
			if err := emit(sec.kind, raw); err != nil {
				rows.Close()
				return nil, nil, err
			}
			n++
			if n%realmExportHeartbeat == 0 {
				if err := progress(map[string]any{"section": sec.kind, "records": n}); err != nil {
					rows.Close()
					return nil, nil, err
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
		counts[sec.kind] = n
		if err := progress(map[string]any{"section": sec.kind, "records": n}); err != nil {
			return nil, nil, err
		}
	}
	body := buf.Bytes()
	sum := sha256.Sum256(body)
	return map[string]any{"format": RealmExportFormat, "content_type": "application/x-ndjson", "counts": counts, "sha256": hex.EncodeToString(sum[:])}, body, nil
}
