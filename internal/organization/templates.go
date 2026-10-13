package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/storage"
)

// TemplateDocument is a repeatable organization setup (TEN-017): policy,
// custom roles, groups with their roles, and the organization's clients and
// integrations: service principals (organization-owned automation clients)
// with their roles, and webhook subscriptions. Templates are versioned and
// applied idempotently: existing items are left alone, missing ones created.
type TemplateDocument struct {
	Policy            *realm.OrgPolicy           `json:"policy,omitempty"`
	Roles             []TemplateRole             `json:"roles,omitempty"`
	Groups            []TemplateGroup            `json:"groups,omitempty"`
	ServicePrincipals []TemplateServicePrincipal `json:"service_principals,omitempty"`
	Webhooks          []TemplateWebhook          `json:"webhooks,omitempty"`
}

// TemplateServicePrincipal is an organization-owned service principal named
// "<organization slug>-<name>", with organization roles. Its credentials are
// issued separately, never by a template.
type TemplateServicePrincipal struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	RoleNames   []string `json:"role_names,omitempty"`
}

// TemplateWebhook is a webhook subscription scoped to the organization. Its
// signing secret is returned once by the application that creates it.
type TemplateWebhook struct {
	Name           string   `json:"name"`
	DestinationURL string   `json:"destination_url"`
	EventTypes     []string `json:"event_types"`
	PayloadForm    string   `json:"payload_form,omitempty"`
}

// TemplateIntegrations creates the clients and integrations a template names.
// The application wires it (the machine and webhooks packages depend on this
// one); every create runs in the template's transaction and is audited by
// its own service.
type TemplateIntegrations struct {
	CreateServicePrincipalTx func(ctx context.Context, tx pgx.Tx, realmID, orgID, name, description string, actor audit.Ref) (string, error)
	CreateWebhookTx          func(ctx context.Context, tx pgx.Tx, realmID, orgID string, w TemplateWebhook, actor audit.Ref) (id, secret string, err error)
}

// TemplateRole is an organization custom role.
type TemplateRole struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions"`
}

// TemplateGroup is a group and the organization roles granted to it.
type TemplateGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	RoleNames   []string `json:"role_names,omitempty"`
}

// Template is one stored version.
type Template struct {
	Name        string           `json:"name"`
	Version     int              `json:"version"`
	Description string           `json:"description,omitempty"`
	Document    TemplateDocument `json:"document"`
	CreatedByID string           `json:"created_by_id"`
	CreatedAt   time.Time        `json:"created_at"`
}

// TemplatePlan is the dry-run result of applying a template.
type TemplatePlan struct {
	Template  string   `json:"template"`
	Version   int      `json:"version"`
	Create    []string `json:"create"`
	Update    []string `json:"update"`
	Unchanged []string `json:"unchanged"`
	Conflicts []string `json:"conflicts"`
	Applied   bool     `json:"applied"`
	// WebhookSecrets maps each webhook created by this application to its
	// signing secret, shown once.
	WebhookSecrets map[string]string `json:"webhook_secrets,omitempty"`
}

var templateName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (d *TemplateDocument) validate() *problem.Error {
	if len(d.ServicePrincipals) > 20 || len(d.Webhooks) > 20 {
		return problem.ErrValidation.WithField("document", "at most 20 service principals and 20 webhooks")
	}
	sps := map[string]bool{}
	for _, sp := range d.ServicePrincipals {
		if !templateName.MatchString(sp.Name) || sps[sp.Name] || len(sp.RoleNames) > 20 || len(sp.Description) > 500 {
			return problem.ErrValidation.WithField("document.service_principals", "unique names of lowercase letters, digits and dashes, at most 20 roles each")
		}
		sps[sp.Name] = true
	}
	hooks := map[string]bool{}
	for _, w := range d.Webhooks {
		if w.Name == "" || len(w.Name) > 200 || hooks[strings.ToLower(w.Name)] || !strings.HasPrefix(w.DestinationURL, "https://") || len(w.EventTypes) == 0 {
			return problem.ErrValidation.WithField("document.webhooks", "unique names, an https destination_url and at least one event type")
		}
		hooks[strings.ToLower(w.Name)] = true
	}
	if len(d.Roles) > 50 || len(d.Groups) > 50 {
		return problem.ErrValidation.WithField("document", "at most 50 roles and 50 groups")
	}
	names := map[string]bool{}
	for _, r := range d.Roles {
		if r.Name == "" || len(r.Name) > 100 || names[strings.ToLower(r.Name)] {
			return problem.ErrValidation.WithField("document.roles", "role names must be present, unique and at most 100 characters")
		}
		names[strings.ToLower(r.Name)] = true
		if len(r.Permissions) == 0 || len(r.Permissions) > 100 {
			return problem.ErrValidation.WithField("document.roles", "every role needs 1 to 100 permissions")
		}
		for _, p := range r.Permissions {
			if strings.HasPrefix(p, "realm.") || strings.HasPrefix(p, "support.") {
				return problem.ErrValidation.WithField("document.roles", "organization roles cannot carry realm or support permissions")
			}
		}
	}
	groups := map[string]bool{}
	for _, g := range d.Groups {
		if g.Name == "" || len(g.Name) > 200 || groups[strings.ToLower(g.Name)] {
			return problem.ErrValidation.WithField("document.groups", "group names must be present and unique")
		}
		groups[strings.ToLower(g.Name)] = true
		if len(g.RoleNames) > 20 {
			return problem.ErrValidation.WithField("document.groups", "at most 20 roles per group")
		}
	}
	if d.Policy != nil {
		if perr := validateOrgPolicy(*d.Policy); perr != nil {
			return perr
		}
	}
	return nil
}

// SaveTemplate stores a new version of a template.
func (s *Service) SaveTemplate(ctx context.Context, realmID, name, description string, doc TemplateDocument, actor audit.Ref) (*Template, error) {
	if !templateName.MatchString(name) {
		return nil, problem.ErrValidation.WithField("name", "lowercase letters, digits and dashes")
	}
	if perr := doc.validate(); perr != nil {
		return nil, perr
	}
	raw, _ := json.Marshal(doc)
	t := &Template{Name: name, Description: description, Document: doc, CreatedByID: actor.ID, CreatedAt: s.d.Now()}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(version),0)+1 FROM organization_templates WHERE realm_id=$1 AND name=$2`, realmID, name).Scan(&t.Version); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO organization_templates (realm_id, name, version, description, document, created_by_id, created_at)
			VALUES ($1,$2,$3,nullif($4,''),$5,$6,$7)`, realmID, name, t.Version, description, raw, actor.ID, t.CreatedAt); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("a concurrent version was saved; retry")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.template.saved", RealmID: realmID, Actor: actor, Category: "configuration",
			Metadata: map[string]any{"template": name, "version": t.Version}})
		return err
	})
	return t, err
}

// Templates lists template versions, newest first; with name, only that
// template's versions.
func (s *Service) Templates(ctx context.Context, realmID, name string) ([]Template, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT name, version, coalesce(description,''), document, created_by_id, created_at FROM organization_templates
		WHERE realm_id=$1 AND ($2='' OR name=$2) ORDER BY name, version DESC LIMIT 500`, realmID, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Template{}
	for rows.Next() {
		var t Template
		var raw []byte
		if err := rows.Scan(&t.Name, &t.Version, &t.Description, &raw, &t.CreatedByID, &t.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &t.Document)
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) template(ctx context.Context, q storage.Querier, realmID, name string, version int) (*Template, error) {
	var t Template
	var raw []byte
	err := q.QueryRow(ctx, `SELECT name, version, coalesce(description,''), document, created_by_id, created_at FROM organization_templates
		WHERE realm_id=$1 AND name=$2 AND ($3=0 OR version=$3) ORDER BY version DESC LIMIT 1`, realmID, name, version).
		Scan(&t.Name, &t.Version, &t.Description, &raw, &t.CreatedByID, &t.CreatedAt)
	if err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(raw, &t.Document)
	return &t, nil
}

// ApplyTemplate plans, and unless dryRun applies, a template version to an
// organization in one transaction. Roles and grants are created with the
// actor's authority, so delegation ceilings apply as for direct changes.
func (s *Service) ApplyTemplate(ctx context.Context, realmID, orgID, name string, version int, dryRun bool, actor authorization.Subject,
	auditActor audit.Ref) (*TemplatePlan, error) {
	var plan *TemplatePlan
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		org, err := s.lockActiveTx(ctx, tx, realmID, orgID, !dryRun)
		if err != nil {
			return err
		}
		t, err := s.template(ctx, tx, realmID, name, version)
		if err != nil {
			return err
		}
		plan = &TemplatePlan{Template: t.Name, Version: t.Version, Create: []string{}, Update: []string{}, Unchanged: []string{}, Conflicts: []string{}}
		doc := t.Document
		// Policy.
		if doc.Policy != nil {
			cur, _ := json.Marshal(org.Policy)
			next, _ := json.Marshal(doc.Policy)
			if bytes.Equal(cur, next) {
				plan.Unchanged = append(plan.Unchanged, "policy")
			} else {
				plan.Update = append(plan.Update, "policy")
				if !dryRun {
					if _, err := tx.Exec(ctx, `UPDATE organizations SET policy=$3, version=version+1, updated_at=$4 WHERE realm_id=$1 AND id=$2`,
						realmID, orgID, next, s.d.Now()); err != nil {
						return err
					}
				}
			}
		}
		// Roles: organization custom roles by name.
		roleIDs := map[string]string{}
		for _, r := range doc.Roles {
			var id string
			var perms []string
			err := tx.QueryRow(ctx, `SELECT r.id, coalesce(array_agg(p.name ORDER BY p.name) FILTER (WHERE p.name IS NOT NULL), '{}') FROM roles r
				LEFT JOIN role_permissions rp ON rp.role_id=r.id AND rp.effect='allow' LEFT JOIN permissions p ON p.id=rp.permission_id
				WHERE r.realm_id=$1 AND r.organization_id=$2 AND lower(r.name)=lower($3) GROUP BY r.id`, realmID, orgID, r.Name).Scan(&id, &perms)
			switch {
			case err == nil:
				want := slices.Clone(r.Permissions)
				slices.Sort(want)
				if slices.Equal(perms, want) {
					plan.Unchanged = append(plan.Unchanged, "role "+r.Name)
				} else {
					// Existing roles are never rewritten by a template: their
					// holders' access would change silently.
					plan.Conflicts = append(plan.Conflicts, "role "+r.Name+" exists with different permissions")
				}
				roleIDs[strings.ToLower(r.Name)] = id
			case storage.IsNoRows(err):
				plan.Create = append(plan.Create, "role "+r.Name)
				if !dryRun {
					role, err := s.Authz.CreateRoleTx(ctx, tx, realmID, actor, authorization.RoleInput{Boundary: "organization", OrganizationID: orgID,
						Name: r.Name, Description: r.Description, Permissions: r.Permissions}, auditActor)
					if err != nil {
						return err
					}
					roleIDs[strings.ToLower(r.Name)] = role.ID
				}
			default:
				return err
			}
		}
		// Groups and their roles.
		for _, g := range doc.Groups {
			var groupID string
			err := tx.QueryRow(ctx, `SELECT id FROM groups WHERE organization_id=$1 AND lower(name)=lower($2) LIMIT 1`, orgID, g.Name).Scan(&groupID)
			switch {
			case err == nil:
			case storage.IsNoRows(err):
				plan.Create = append(plan.Create, "group "+g.Name)
				if !dryRun {
					grp, err := s.CreateGroupTx(ctx, tx, realmID, orgID, GroupInput{Name: g.Name, Description: g.Description, Source: "template"}, auditActor)
					if err != nil {
						return err
					}
					groupID = grp.ID
				}
			default:
				return err
			}
			for _, rn := range g.RoleNames {
				roleID := roleIDs[strings.ToLower(rn)]
				if roleID == "" {
					if role, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", rn); err == nil {
						roleID = role.ID
					}
				}
				if roleID == "" {
					if !dryRun || !slices.ContainsFunc(doc.Roles, func(r TemplateRole) bool { return strings.EqualFold(r.Name, rn) }) {
						plan.Conflicts = append(plan.Conflicts, "group "+g.Name+": unknown role "+rn)
					} else {
						plan.Create = append(plan.Create, "grant "+rn+" to group "+g.Name)
					}
					continue
				}
				var has bool
				if groupID != "" {
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_assignments WHERE realm_id=$1 AND role_id=$2 AND subject_type='group'
						AND subject_id=$3 AND scope_type='organization' AND scope_id=$4)`, realmID, roleID, groupID, orgID).Scan(&has); err != nil {
						return err
					}
				}
				if has {
					plan.Unchanged = append(plan.Unchanged, "grant "+rn+" to group "+g.Name)
					continue
				}
				if conflict, err := s.templateGrantNeedsApproval(ctx, tx, realmID, roleID, authorization.Subject{Type: authorization.SubjectGroup, ID: groupID},
					"grant "+rn+" to group "+g.Name); err != nil {
					return err
				} else if conflict != "" {
					plan.Conflicts = append(plan.Conflicts, conflict)
					continue
				}
				plan.Create = append(plan.Create, "grant "+rn+" to group "+g.Name)
				if !dryRun {
					if _, err := s.Authz.AssignTx(ctx, tx, realmID, &actor, authorization.AssignInput{RoleID: roleID,
						Subject: authorization.Subject{Type: authorization.SubjectGroup, ID: groupID},
						Scope:   authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}, Source: "template", Reason: t.Name}, auditActor); err != nil {
						return err
					}
				}
			}
		}
		// Clients and integrations need the same authority as creating them
		// directly in the organization.
		orgScope := authorization.Scope{Type: authorization.ScopeOrganization, ID: orgID}
		if len(doc.ServicePrincipals) > 0 && !s.Authz.Check(ctx, tx, realmID, actor, "org.service_principals.write", orgScope) {
			plan.Conflicts = append(plan.Conflicts, "service principals require org.service_principals.write")
		}
		if len(doc.Webhooks) > 0 && !s.Authz.Check(ctx, tx, realmID, actor, "org.integrations.write", orgScope) {
			plan.Conflicts = append(plan.Conflicts, "webhooks require org.integrations.write")
		}
		// The slugs the organization has had: a principal a template created
		// before a rename carries the former slug as its prefix.
		slugs := []string{org.Slug}
		if rows, err := tx.Query(ctx, `SELECT alias FROM organization_aliases WHERE realm_id=$1 AND organization_id=$2`, realmID, orgID); err == nil {
			for rows.Next() {
				var a string
				if rows.Scan(&a) == nil {
					slugs = append(slugs, a)
				}
			}
			rows.Close()
		}
		for _, sp := range doc.ServicePrincipals {
			full := org.Slug + "-" + sp.Name
			names := make([]string, len(slugs))
			for i, sl := range slugs {
				names[i] = strings.ToLower(sl + "-" + sp.Name)
			}
			var spID string
			// The organization's own principal for this template entry, named
			// after the organization's current or a former slug — never
			// another principal that merely ends with the entry's name;
			// otherwise any principal already holding the name.
			err := tx.QueryRow(ctx, `SELECT id FROM service_principals WHERE realm_id=$1 AND state <> 'deleted' AND (lower(name)=lower($2)
				OR (owner_organization_id=$3 AND lower(name) = ANY($4))) ORDER BY (owner_organization_id=$3) DESC, (lower(name)=lower($2)) DESC LIMIT 1`,
				realmID, full, orgID, names).Scan(&spID)
			var owner string
			switch {
			case err == nil:
				_ = tx.QueryRow(ctx, `SELECT coalesce(owner_organization_id,'') FROM service_principals WHERE id=$1`, spID).Scan(&owner)
				if owner != orgID {
					plan.Conflicts = append(plan.Conflicts, "service principal "+full+" exists outside this organization")
					continue
				}
				plan.Unchanged = append(plan.Unchanged, "service principal "+full)
			case storage.IsNoRows(err):
				plan.Create = append(plan.Create, "service principal "+full)
				if !dryRun && len(plan.Conflicts) == 0 {
					if s.Integrations.CreateServicePrincipalTx == nil {
						return problem.ErrInternal.WithDetail("template integrations are not configured")
					}
					if spID, err = s.Integrations.CreateServicePrincipalTx(ctx, tx, realmID, orgID, full, sp.Description, auditActor); err != nil {
						return err
					}
				}
			default:
				return err
			}
			for _, rn := range sp.RoleNames {
				roleID := roleIDs[strings.ToLower(rn)]
				if roleID == "" {
					if role, err := s.Authz.RoleByName(ctx, tx, realmID, "organization", rn); err == nil {
						roleID = role.ID
					}
				}
				if roleID == "" && (!dryRun || !slices.ContainsFunc(doc.Roles, func(r TemplateRole) bool { return strings.EqualFold(r.Name, rn) })) {
					plan.Conflicts = append(plan.Conflicts, "service principal "+full+": unknown role "+rn)
					continue
				}
				var has bool
				if spID != "" && roleID != "" {
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM role_assignments WHERE realm_id=$1 AND role_id=$2 AND subject_type='service_principal'
						AND subject_id=$3 AND scope_type='organization' AND scope_id=$4)`, realmID, roleID, spID, orgID).Scan(&has); err != nil {
						return err
					}
				}
				if has {
					plan.Unchanged = append(plan.Unchanged, "grant "+rn+" to service principal "+full)
					continue
				}
				if conflict, err := s.templateGrantNeedsApproval(ctx, tx, realmID, roleID, authorization.Subject{Type: authorization.SubjectService, ID: spID},
					"grant "+rn+" to service principal "+full); err != nil {
					return err
				} else if conflict != "" {
					plan.Conflicts = append(plan.Conflicts, conflict)
					continue
				}
				plan.Create = append(plan.Create, "grant "+rn+" to service principal "+full)
				if !dryRun && len(plan.Conflicts) == 0 {
					if _, err := s.Authz.AssignTx(ctx, tx, realmID, &actor, authorization.AssignInput{RoleID: roleID,
						Subject: authorization.Subject{Type: authorization.SubjectService, ID: spID},
						Scope:   orgScope, Source: "template", Reason: t.Name}, auditActor); err != nil {
						return err
					}
				}
			}
		}
		for _, wh := range doc.Webhooks {
			var dest string
			var types []string
			err := tx.QueryRow(ctx, `SELECT destination_url, event_types FROM webhook_subscriptions WHERE realm_id=$1 AND organization_id=$2 AND lower(name)=lower($3)`,
				realmID, orgID, wh.Name).Scan(&dest, &types)
			if err == nil {
				want, got := slices.Clone(wh.EventTypes), slices.Clone(types)
				slices.Sort(want)
				slices.Sort(got)
				if dest != wh.DestinationURL || !slices.Equal(want, got) {
					// Like roles, existing integrations are never rewritten.
					plan.Conflicts = append(plan.Conflicts, "webhook "+wh.Name+" exists with a different destination or event types")
				} else {
					plan.Unchanged = append(plan.Unchanged, "webhook "+wh.Name)
				}
				continue
			} else if !storage.IsNoRows(err) {
				return err
			}
			plan.Create = append(plan.Create, "webhook "+wh.Name)
			if !dryRun && len(plan.Conflicts) == 0 {
				if s.Integrations.CreateWebhookTx == nil {
					return problem.ErrInternal.WithDetail("template integrations are not configured")
				}
				_, secret, err := s.Integrations.CreateWebhookTx(ctx, tx, realmID, orgID, wh, auditActor)
				if err != nil {
					return err
				}
				if plan.WebhookSecrets == nil {
					plan.WebhookSecrets = map[string]string{}
				}
				plan.WebhookSecrets[wh.Name] = secret
			}
		}
		if dryRun {
			return nil
		}
		if len(plan.Conflicts) > 0 {
			return problem.ErrConflict.WithDetail("the template conflicts with the organization; review the dry run").WithExtension("conflicts", plan.Conflicts)
		}
		if _, err := tx.Exec(ctx, `UPDATE organizations SET template_name=$3, template_version=$4 WHERE realm_id=$1 AND id=$2`,
			realmID, orgID, t.Name, t.Version); err != nil {
			return err
		}
		plan.Applied = true
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.template.applied", RealmID: realmID, OrgID: orgID, Actor: auditActor,
			Category: "configuration", Target: &audit.Ref{Type: "organization", ID: orgID},
			Metadata: map[string]any{"template": t.Name, "version": t.Version, "created": len(plan.Create), "updated": len(plan.Update)}})
		return err
	})
	return plan, err
}

// templateGrantNeedsApproval applies the two-party rule of direct
// assignment (AZ-018, MCH-017; authorization.AssignmentNeedsApproval) to a
// grant a template would make: a role that requires approval, or a
// privileged role for an autonomous agent, is never granted on one
// administrator's say-so. Such a grant is a conflict naming the direct
// route (POST /role-assignments, which opens an approval request); once it
// is approved, the template sees the grant as unchanged. It returns "" when
// the template may make the grant. A role the template itself still has to
// create (dry run) cannot be evaluated and is left to the real application.
func (s *Service) templateGrantNeedsApproval(ctx context.Context, tx pgx.Tx, realmID, roleID string, subj authorization.Subject, what string) (string, error) {
	if roleID == "" {
		return "", nil
	}
	needs, err := s.Authz.AssignmentNeedsApprovalTx(ctx, tx, realmID, roleID, subj)
	if err != nil || !needs {
		return "", err
	}
	return what + " needs an independent approver: assign it through POST /role-assignments", nil
}
