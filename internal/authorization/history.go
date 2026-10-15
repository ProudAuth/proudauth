package authorization

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// Historical entitlement evidence (ADV-011): what a subject was entitled to
// at a past instant, rebuilt from retained evidence — role-assignment,
// membership, group and role-definition audit events, OAuth grants, and the
// policy versions and realm policy revision in force. It is a
// reconstruction for investigations, not a replay of decisions: it says
// where evidence is missing and never claims application-owned facts.

// EntitlementHistory is the reconstruction.
type EntitlementHistory struct {
	Subject             Subject             `json:"subject"`
	At                  time.Time           `json:"at"`
	AccountState        string              `json:"account_state"`
	Memberships         []HistoryMembership `json:"memberships"`
	Groups              []HistoryGroup      `json:"groups"`
	Assignments         []HistoryAssignment `json:"assignments"`
	Permissions         []string            `json:"permissions"`
	Grants              []HistoryGrant      `json:"oauth_grants"`
	Policies            []HistoryPolicy     `json:"policies_in_force"`
	RealmPolicyRevision int64               `json:"realm_policy_revision"`
	Completeness        HistoryCompleteness `json:"completeness"`
}

// HistoryMembership is an organization membership held at the instant.
type HistoryMembership struct {
	OrganizationID string    `json:"organization_id"`
	MembershipID   string    `json:"membership_id"`
	Since          time.Time `json:"since"`
	Evidence       string    `json:"evidence"`
}

// HistoryGroup is a group the subject belonged to.
type HistoryGroup struct {
	GroupID        string    `json:"group_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	Since          time.Time `json:"since"`
	Evidence       string    `json:"evidence"`
}

// HistoryAssignment is a role held, directly or through a group.
type HistoryAssignment struct {
	AssignmentID        string     `json:"assignment_id"`
	RoleID              string     `json:"role_id"`
	RoleName            string     `json:"role_name"`
	ScopeType           string     `json:"scope_type"`
	ScopeID             string     `json:"scope_id"`
	Source              string     `json:"source,omitempty"`
	Via                 string     `json:"via"` // direct or group:<id>
	Since               time.Time  `json:"since"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
	Permissions         []string   `json:"permissions"`
	DeniedPermissions   []string   `json:"denied_permissions,omitempty"`
	PermissionsEvidence string     `json:"permissions_evidence"` // reconstructed, current_definition or unknown
	Evidence            []string   `json:"evidence"`
}

// HistoryGrant is an OAuth grant that was live at the instant.
type HistoryGrant struct {
	GrantID        string    `json:"grant_id"`
	ClientID       string    `json:"client_id"`
	OrganizationID string    `json:"organization_id,omitempty"`
	Scopes         []string  `json:"scopes"`
	Offline        bool      `json:"offline"`
	CreatedAt      time.Time `json:"created_at"`
}

// HistoryPolicy is the ABAC policy version that was published at the instant.
type HistoryPolicy struct {
	PolicyID       string    `json:"policy_id"`
	Name           string    `json:"name"`
	Version        int       `json:"version"`
	DefinitionHash string    `json:"definition_hash"`
	PublishedAt    time.Time `json:"published_at"`
}

// HistoryCompleteness says how far the evidence goes.
type HistoryCompleteness struct {
	EvidenceFrom *time.Time `json:"evidence_from,omitempty"`
	Complete     bool       `json:"complete"`
	Caveats      []string   `json:"caveats"`
}

type histEvent struct {
	id, typ, subjType, subjID, targetType, targetID, org string
	at                                                   time.Time
	meta                                                 map[string]any
}

func (s *Service) histEvents(ctx context.Context, realmID string, at time.Time, where string, args ...any) ([]histEvent, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, type, coalesce(subject_type,''), coalesce(subject_id,''), coalesce(target_type,''), coalesce(target_id,''),
		coalesce(organization_id,''), occurred_at, metadata FROM audit_events WHERE realm_id=$1 AND occurred_at <= $2 AND outcome='success' AND (`+where+`)
		ORDER BY occurred_at, seq LIMIT 20000`, append([]any{realmID, at}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []histEvent
	for rows.Next() {
		var e histEvent
		var meta []byte
		if err := rows.Scan(&e.id, &e.typ, &e.subjType, &e.subjID, &e.targetType, &e.targetID, &e.org, &e.at, &meta); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(meta, &e.meta)
		out = append(out, e)
	}
	return out, rows.Err()
}

func metaString(m map[string]any, k string) string { v, _ := m[k].(string); return v }

func metaStrings(m map[string]any, k string) []string {
	var out []string
	if list, ok := m[k].([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// ReconstructEntitlements rebuilds a user's or service principal's
// entitlements at an instant.
func (s *Service) ReconstructEntitlements(ctx context.Context, realmID string, subj Subject, at time.Time) (*EntitlementHistory, error) {
	if subj.Type != SubjectUser && subj.Type != SubjectService {
		return nil, problem.ErrValidation.WithField("subject_type", "user or service_principal")
	}
	if at.After(s.d.Now()) {
		return nil, problem.ErrValidation.WithField("at", "a past instant")
	}
	h := &EntitlementHistory{Subject: subj, At: at, AccountState: "unknown", Memberships: []HistoryMembership{}, Groups: []HistoryGroup{},
		Assignments: []HistoryAssignment{}, Permissions: []string{}, Grants: []HistoryGrant{}, Policies: []HistoryPolicy{}}
	caveats := []string{
		"Application-owned facts (application data, local authorization rules, third-party state) are not reconstructed.",
		"Decisions of hooks and external policy engines at that time are not reproduced; ABAC policy versions in force are listed.",
		"OAuth grants ended longer ago than privacy.session_retention are deleted and are not listed.",
	}
	var from *time.Time
	if err := s.d.DB.Pool.QueryRow(ctx, `SELECT min(occurred_at) FROM audit_events WHERE realm_id=$1 AND source='server'`, realmID).Scan(&from); err != nil {
		return nil, err
	}
	h.Completeness.EvidenceFrom = from
	complete := from != nil && !at.Before(*from)
	if !complete {
		caveats = append(caveats, "The instant precedes the oldest retained audit evidence; entitlements granted before it are missing.")
	}

	// Subject events: account state, memberships, direct assignments.
	events, err := s.histEvents(ctx, realmID, at, `subject_type=$3 AND subject_id=$4 AND type IN ('role.assigned','role.unassigned',
		'organization.membership.added','organization.membership.removed','organization.membership.expired','user.created','user.imported',
		'user.suspended','user.locked','user.reactivated','user.recovery_restricted','user.deleted')`, subj.Type, subj.ID)
	if err != nil {
		return nil, err
	}
	if len(events) >= 20000 {
		complete = false
		caveats = append(caveats, "More than 20000 events; the reconstruction is truncated.")
	}
	type assignment struct {
		HistoryAssignment
		ended bool
	}
	assignments := map[string]*assignment{}
	order := []string{}
	memberships := map[string]*HistoryMembership{} // by membership ID
	if subj.Type == SubjectService {
		h.AccountState = "active"
	}
	assign := func(e histEvent, via string) {
		a := &assignment{HistoryAssignment: HistoryAssignment{AssignmentID: e.targetID, RoleID: metaString(e.meta, "role_id"), RoleName: metaString(e.meta, "role_name"),
			ScopeType: metaString(e.meta, "scope_type"), ScopeID: metaString(e.meta, "scope_id"), Source: metaString(e.meta, "source"), Via: via, Since: e.at,
			Evidence: []string{e.id}}}
		if exp := metaString(e.meta, "expires_at"); exp != "" {
			if t, err := time.Parse(time.RFC3339Nano, exp); err == nil {
				a.ExpiresAt = &t
			}
		}
		if _, ok := assignments[e.targetID]; !ok {
			order = append(order, e.targetID)
		}
		assignments[e.targetID] = a
	}
	for _, e := range events {
		switch e.typ {
		case "user.created", "user.imported", "user.reactivated":
			h.AccountState = "active"
		case "user.suspended":
			h.AccountState = "suspended"
		case "user.locked":
			h.AccountState = "locked"
		case "user.recovery_restricted":
			h.AccountState = "recovery_restricted"
		case "user.deleted":
			h.AccountState = "deleted"
		case "role.assigned":
			assign(e, "direct")
		case "role.unassigned":
			if a := assignments[e.targetID]; a != nil {
				a.ended = true
			}
		case "organization.membership.added":
			memberships[e.targetID] = &HistoryMembership{OrganizationID: e.org, MembershipID: e.targetID, Since: e.at, Evidence: e.id}
		case "organization.membership.removed", "organization.membership.expired":
			delete(memberships, e.targetID)
			// Organization roles end with the membership.
			for _, a := range assignments {
				if a.ScopeType == ScopeOrganization && a.ScopeID == e.org && a.Since.Before(e.at.Add(time.Nanosecond)) {
					a.ended = true
				}
			}
		}
	}
	if subj.Type == SubjectUser && h.AccountState == "unknown" && complete {
		h.AccountState = "not_created"
	}

	// Groups of the memberships held, and the roles assigned to them.
	var membershipIDs []string
	for id := range memberships {
		membershipIDs = append(membershipIDs, id)
	}
	groups := map[string]*HistoryGroup{}
	if len(membershipIDs) > 0 {
		gev, err := s.histEvents(ctx, realmID, at, `type IN ('group.member.added','group.member.removed') AND metadata->>'membership_id' = ANY($3)`, membershipIDs)
		if err != nil {
			return nil, err
		}
		for _, e := range gev {
			if e.typ == "group.member.added" {
				groups[e.targetID] = &HistoryGroup{GroupID: e.targetID, OrganizationID: e.org, Since: e.at, Evidence: e.id}
			} else {
				delete(groups, e.targetID)
			}
		}
		var groupIDs []string
		for id := range groups {
			groupIDs = append(groupIDs, id)
		}
		if len(groupIDs) > 0 {
			rev, err := s.histEvents(ctx, realmID, at, `subject_type='group' AND subject_id = ANY($3) AND type IN ('role.assigned','role.unassigned','group.deleted')`, groupIDs)
			if err != nil {
				return nil, err
			}
			for _, e := range rev {
				switch e.typ {
				case "role.assigned":
					assign(e, "group:"+e.subjID)
				case "role.unassigned":
					if a := assignments[e.targetID]; a != nil {
						a.ended = true
					}
				}
			}
		}
		caveats = append(caveats, "Dynamic group membership is reconstructed from recorded membership changes only.")
	}
	// Grants revoked with a project grant end the assignments made through it.
	grantRevocations, err := s.histEvents(ctx, realmID, at, `type IN ('project.grant.revoked','project.grant.expired')`)
	if err != nil {
		return nil, err
	}
	for _, e := range grantRevocations {
		project := metaString(e.meta, "project_id")
		for _, a := range assignments {
			if a.ScopeType == ScopeProject && a.ScopeID == project && a.Source == "project_grant" && !a.Since.After(e.at) {
				a.ended = true
			}
		}
	}

	// Role definitions as they stood.
	roleIDs := []string{}
	for _, id := range order {
		a := assignments[id]
		if a.ended || (a.ExpiresAt != nil && !a.ExpiresAt.After(at)) {
			continue
		}
		if !slices.Contains(roleIDs, a.RoleID) {
			roleIDs = append(roleIDs, a.RoleID)
		}
	}
	defs := map[string]struct {
		allow, deny []string
		evidence    string
	}{}
	if len(roleIDs) > 0 {
		rev, err := s.histEvents(ctx, realmID, at, `target_type='role' AND target_id = ANY($3) AND type IN ('role.created','role.permissions.changed')`, roleIDs)
		if err != nil {
			return nil, err
		}
		created := map[string]bool{}
		for _, e := range rev {
			d := defs[e.targetID]
			switch e.typ {
			case "role.created":
				created[e.targetID] = true
				d.allow, d.deny, d.evidence = ExpandPatterns(metaStrings(e.meta, "permissions")), metaStrings(e.meta, "denied_permissions"), "reconstructed"
			case "role.permissions.changed":
				if !created[e.targetID] {
					continue
				}
				d.allow = slices.DeleteFunc(append(d.allow, metaStrings(e.meta, "added")...), func(p string) bool { return slices.Contains(metaStrings(e.meta, "removed"), p) })
			}
			defs[e.targetID] = d
		}
		for _, id := range roleIDs {
			if _, ok := defs[id]; ok {
				continue
			}
			// Built-in roles, and roles created before the retained evidence,
			// are shown with their current definition.
			r, err := s.Role(ctx, nil, realmID, id)
			if err != nil {
				defs[id] = struct {
					allow, deny []string
					evidence    string
				}{nil, nil, "unknown"}
				continue
			}
			defs[id] = struct {
				allow, deny []string
				evidence    string
			}{slices.Clone(r.Permissions), slices.Clone(r.DeniedPermissions), "current_definition"}
		}
	}
	allow, deny := map[string]bool{}, map[string]bool{}
	usedCurrent := false
	for _, id := range order {
		a := assignments[id]
		if a.ended || (a.ExpiresAt != nil && !a.ExpiresAt.After(at)) {
			continue
		}
		d := defs[a.RoleID]
		a.Permissions, a.DeniedPermissions, a.PermissionsEvidence = nonNilStrings(d.allow), d.deny, d.evidence
		if d.evidence != "reconstructed" {
			usedCurrent = true
		}
		for _, p := range d.allow {
			allow[p] = true
		}
		for _, p := range d.deny {
			deny[p] = true
		}
		h.Assignments = append(h.Assignments, a.HistoryAssignment)
	}
	if usedCurrent {
		caveats = append(caveats, "Some role definitions (built-in roles, or roles created before the retained evidence) are shown as they are now.")
	}
	for p := range allow {
		if !deny[p] {
			h.Permissions = append(h.Permissions, p)
		}
	}
	sort.Strings(h.Permissions)
	for _, m := range memberships {
		h.Memberships = append(h.Memberships, *m)
	}
	sort.Slice(h.Memberships, func(i, j int) bool { return h.Memberships[i].Since.Before(h.Memberships[j].Since) })
	for _, g := range groups {
		h.Groups = append(h.Groups, *g)
	}

	// OAuth grants live at the instant (rows are kept after revocation).
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT g.id, c.client_id, coalesce(g.organization_id,''), g.scopes, g.offline, g.created_at FROM authorization_grants g
		JOIN clients c ON c.id=g.client_ref WHERE g.realm_id=$1 AND g.subject_type=$2 AND g.subject_id=$3 AND g.created_at <= $4
		AND (g.revoked_at IS NULL OR g.revoked_at > $4) AND g.expires_at > $4 ORDER BY g.created_at LIMIT 500`, realmID, subj.Type, subj.ID, at)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var g HistoryGrant
		if err := rows.Scan(&g.GrantID, &g.ClientID, &g.OrganizationID, &g.Scopes, &g.Offline, &g.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		h.Grants = append(h.Grants, g)
	}
	rows.Close()

	// ABAC policy versions published at the instant (the latest published
	// version of each policy).
	prow, err := s.d.DB.Pool.Query(ctx, `SELECT DISTINCT ON (p.id) p.id, p.name, v.version_number, v.definition_hash, v.published_at
		FROM policies p JOIN policy_versions v ON v.policy_id=p.id WHERE p.realm_id=$1 AND v.published_at IS NOT NULL AND v.published_at <= $2
		ORDER BY p.id, v.published_at DESC`, realmID, at)
	if err != nil {
		return nil, err
	}
	for prow.Next() {
		var p HistoryPolicy
		if err := prow.Scan(&p.PolicyID, &p.Name, &p.Version, &p.DefinitionHash, &p.PublishedAt); err != nil {
			prow.Close()
			return nil, err
		}
		h.Policies = append(h.Policies, p)
	}
	prow.Close()
	_ = s.d.DB.Pool.QueryRow(ctx, `SELECT coalesce(max(revision),0) FROM configuration_revisions WHERE realm_id=$1 AND scope_type='realm_policy'
		AND created_at <= $2`, realmID, at).Scan(&h.RealmPolicyRevision)

	h.Completeness.Complete = complete
	h.Completeness.Caveats = caveats
	return h, nil
}

// RecordInvestigation audits a reconstruction with its reason.
func (s *Service) RecordInvestigation(ctx context.Context, realmID string, subj Subject, at time.Time, reason string, actor audit.Ref) error {
	_, err := s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "investigation.entitlements.reconstructed", RealmID: realmID, Actor: actor,
		Subject: &audit.Ref{Type: subj.Type, ID: subj.ID}, ReasonCode: reason, Category: "audit", Metadata: map[string]any{"at": at.UTC().Format(time.RFC3339Nano)}})
	return err
}
