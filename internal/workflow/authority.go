package workflow

import (
	"context"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/organization"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

func newID(prefix string) string { return ids.New(prefix) }

// checkReferences verifies that everything a definition names exists in the
// realm (tenant isolation: identifiers of another realm are refused as
// unknown) and fits the step that uses it.
func (s *Service) checkReferences(ctx context.Context, q storage.Querier, realmID string, d *Definition) error {
	exists := func(sql string, args ...any) (bool, error) {
		var ok bool
		err := q.QueryRow(ctx, `SELECT EXISTS (`+sql+`)`, args...).Scan(&ok)
		return ok, err
	}
	org := func(id, path string) error {
		if id == "" {
			return nil
		}
		ok, err := exists(`SELECT 1 FROM organizations WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, id)
		if err != nil {
			return err
		}
		if !ok {
			return field(path, "unknown or inactive organization")
		}
		return nil
	}
	role := func(id, scope, path string) error {
		r, err := s.Authz.Role(ctx, q, realmID, id)
		if err != nil {
			return field(path, "unknown role")
		}
		want := map[string]string{"realm": "realm", "organization": "organization"}[scope]
		if r.Boundary != want {
			return field(path, "the role's boundary is "+r.Boundary+", not "+scope)
		}
		return nil
	}
	for i, t := range d.Triggers {
		p := fmt.Sprintf("triggers[%d]", i)
		if err := org(t.OrganizationID, p+".organization_id"); err != nil {
			return err
		}
		if t.Select != nil {
			if err := org(t.Select.OrganizationID, p+".select.organization_id"); err != nil {
				return err
			}
			if t.Select.RoleID != "" {
				if _, err := s.Authz.Role(ctx, q, realmID, t.Select.RoleID); err != nil {
					return field(p+".select.role_id", "unknown role")
				}
			}
		}
	}
	for i, st := range d.Steps {
		p := fmt.Sprintf("steps[%d]", i)
		if err := org(st.OrganizationID, p+".organization_id"); err != nil {
			return err
		}
		switch st.Type {
		case StepAssignRole:
			if err := role(st.RoleID, st.Scope, p+".role_id"); err != nil {
				return err
			}
		case StepRemove:
			if st.Access == "role" {
				if err := role(st.RoleID, st.Scope, p+".role_id"); err != nil {
					return err
				}
			}
		}
		if st.GroupID != "" {
			gorg, err := s.groupOrg(ctx, q, realmID, st.GroupID)
			if err != nil {
				return field(p+".group_id", "unknown group")
			}
			if st.OrganizationID != "" && st.OrganizationID != gorg {
				return field(p+".organization_id", "the group belongs to another organization")
			}
		}
		if st.Type == StepApproval {
			for _, a := range st.Approvers {
				ok, err := exists(`SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 AND state='active' AND NOT is_guest`, realmID, a)
				if err != nil {
					return err
				}
				if !ok {
					return field(p+".approvers", "approvers must be active accounts of this realm")
				}
			}
		}
		if st.Type == StepCallWebhook {
			ok, err := exists(`SELECT 1 FROM webhook_subscriptions WHERE realm_id=$1 AND id=$2 AND organization_id IS NULL`, realmID, st.SubscriptionID)
			if err != nil {
				return err
			}
			if !ok {
				return field(p+".subscription_id", "a realm-wide webhook subscription of this realm")
			}
		}
	}
	return nil
}

func (s *Service) groupOrg(ctx context.Context, q storage.Querier, realmID, groupID string) (string, error) {
	var org string
	err := q.QueryRow(ctx, `SELECT g.organization_id FROM groups g JOIN organizations o ON o.id=g.organization_id
		WHERE o.realm_id=$1 AND g.id=$2`, realmID, groupID).Scan(&org)
	return org, err
}

// Permissions lists the permissions a definition needs from its publisher
// (plugin manifests declare them, EXT-014). Role and group grants also need
// the granted permissions themselves, which the ceiling check verifies.
func (d *Definition) Permissions() []string {
	out := []string{"realm.workflows.write", "realm.workflows.publish"}
	add := func(p string) {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	for _, st := range d.Steps {
		switch st.Type {
		case StepAssignRole:
			if st.Scope == "realm" {
				add("realm.roles.assign")
			} else {
				add("org.roles.assign")
			}
		case StepRemove:
			switch {
			case st.Access == "membership":
				add("org.members.write")
			case st.Access == "group":
				add("org.groups.write")
			case st.Scope == "realm":
				add("realm.roles.assign")
			default:
				add("org.roles.assign")
			}
		case StepAddToGroup:
			add("org.groups.write")
		case StepSuspend:
			add("realm.users.suspend")
		case StepCallWebhook:
			add("realm.webhooks.write")
		}
	}
	return out
}

// checkDefinitionAuthority runs every step's authority check for the
// publisher at publication time. Steps whose organization comes from the
// trigger are checked with the publisher's realm-wide authority over
// organizations; the exact organization is checked again when the step runs.
func (s *Service) checkDefinitionAuthority(ctx context.Context, tx pgx.Tx, realmID string, publisher authorization.Subject, d *Definition) error {
	if !s.Authz.Check(ctx, tx, realmID, publisher, "realm.workflows.publish", realmScope(realmID)) {
		return problem.ErrForbidden.WithDetail("publishing requires realm.workflows.publish")
	}
	for i, st := range d.Steps {
		org := st.OrganizationID
		if org == "" {
			org = pinnedTriggerOrg(d)
		}
		if err := s.checkStepAuthority(ctx, tx, realmID, publisher, st, org); err != nil {
			if pe, ok := problem.As(err); ok {
				return pe.WithField(fmt.Sprintf("definition.steps[%d]", i), "exceeds the publisher's authority: "+pe.Detail)
			}
			return err
		}
	}
	return nil
}

// pinnedTriggerOrg returns the organization every trigger pins, when they
// all pin the same one.
func pinnedTriggerOrg(d *Definition) string {
	org := ""
	for _, t := range d.Triggers {
		o := t.OrganizationID
		if t.Select != nil {
			o = t.Select.OrganizationID
		}
		if o == "" || (org != "" && o != org) {
			return ""
		}
		org = o
	}
	return org
}

func realmScope(realmID string) authorization.Scope {
	return authorization.Scope{Type: authorization.ScopeRealm, ID: realmID}
}

// orgScopeOrRealm is the organization scope, or the realm-wide view of
// organizations when the organization is not known yet (only realm-level
// grants count then).
func orgScope(orgID string) authorization.Scope {
	return authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
}

// checkStepAuthority verifies that the actor could perform the step directly
// through the API: the same permission and the same delegation ceiling
// (CheckAssignable). It is evaluated at publication, when an administrator
// starts a run by hand, and inside the transaction of every effect.
func (s *Service) checkStepAuthority(ctx context.Context, tx pgx.Tx, realmID string, actor authorization.Subject, st Step, orgID string) error {
	need := func(perm string, scope authorization.Scope) error {
		if !s.Authz.Check(ctx, tx, realmID, actor, perm, scope) {
			return problem.ErrForbidden.WithDetailf("requires %s", perm)
		}
		return nil
	}
	switch st.Type {
	case StepAssignRole, StepRemove:
		if st.Type == StepRemove && st.Access != "role" {
			if st.Access == "membership" {
				return need("org.members.write", orgScope(orgID))
			}
			return s.checkGroupAuthority(ctx, tx, realmID, actor, st.GroupID)
		}
		r, err := s.Authz.Role(ctx, tx, realmID, st.RoleID)
		if err != nil {
			return problem.ErrForbidden.WithDetail("the role no longer exists")
		}
		scope := realmScope(realmID)
		if st.Scope == "organization" {
			scope = orgScope(orgID)
		}
		return s.Authz.CheckAssignable(ctx, tx, realmID, actor, r, scope)
	case StepAddToGroup:
		return s.checkGroupAuthority(ctx, tx, realmID, actor, st.GroupID)
	case StepSuspend:
		return need("realm.users.suspend", realmScope(realmID))
	case StepCallWebhook:
		return need("realm.webhooks.write", realmScope(realmID))
	}
	return nil
}

// checkGroupAuthority mirrors the group membership API: the actor manages
// the group's organization's groups and could assign every role the group
// grants, including roles inherited from ancestor groups (TEN-008).
func (s *Service) checkGroupAuthority(ctx context.Context, tx pgx.Tx, realmID string, actor authorization.Subject, groupID string) error {
	org, err := s.groupOrg(ctx, tx, realmID, groupID)
	if err != nil {
		return problem.ErrForbidden.WithDetail("the group no longer exists")
	}
	scope := orgScope(org)
	if !s.Authz.Check(ctx, tx, realmID, actor, "org.groups.write", scope) {
		return problem.ErrForbidden.WithDetail("requires org.groups.write")
	}
	roles, err := organization.GroupRolesTx(ctx, tx, org, groupID)
	if err != nil {
		return err
	}
	for _, rid := range roles {
		r, err := s.Authz.Role(ctx, tx, realmID, rid)
		if err != nil {
			return err
		}
		if err := s.Authz.CheckAssignable(ctx, tx, realmID, actor, r, scope); err != nil {
			return err
		}
	}
	return nil
}
