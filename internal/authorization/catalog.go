// Package authorization implements scoped RBAC with delegation ceilings, explicit
// denies, bounded composite roles, group-derived roles, ABAC policies and the policy
// decision API (§15).
package authorization

import (
	"slices"
	"strconv"
	"strings"
)

// Built-in permissions. Namespaces are separated by trust class (DOM-005, AZ-005):
// "realm." for identity-domain administration, "org." for delegated organization
// administration, "support." for support operators. Application permissions are
// registered by projects and can never imply IdP administration.
type PermissionDef struct {
	Name        string
	Namespace   string
	Description string
	Sensitivity string
}

var BuiltInPermissions = []PermissionDef{
	// Realm administration.
	{"realm.settings.read", "realm", "Read realm security settings", "normal"},
	{"realm.settings.write", "realm", "Change realm security settings", "privileged"},
	{"realm.users.read", "realm", "Read realm-wide user records", "high"},
	{"realm.users.write", "realm", "Create users and edit administrator-controlled fields", "high"},
	{"realm.users.suspend", "realm", "Suspend or reactivate realm-wide accounts", "privileged"},
	{"realm.users.delete", "realm", "Delete realm-wide accounts", "privileged"},
	{"realm.users.credentials.manage", "realm", "Reset global credentials and factors of shared users", "privileged"},
	{"realm.users.verification.override", "realm", "Override identifier verification with a reason", "privileged"},
	{"realm.users.sessions.revoke", "realm", "Revoke sessions of realm users", "high"},
	{"realm.users.import", "realm", "Run bulk user imports", "privileged"},
	{"realm.registrations.review", "realm", "Approve or deny pending self-registrations", "high"},
	{"realm.users.sensitive.read", "realm", "Read unmasked sensitive identity data", "privileged"},
	{"realm.users.required_actions", "realm", "Set required actions on accounts", "high"},
	{"realm.organizations.read", "realm", "Read all organizations", "normal"},
	{"realm.organizations.create", "realm", "Create organizations", "high"},
	{"realm.organizations.write", "realm", "Edit any organization", "high"},
	{"realm.organizations.suspend", "realm", "Suspend or reactivate organizations", "privileged"},
	{"realm.organizations.delete", "realm", "Delete organizations", "privileged"},
	{"realm.projects.read", "realm", "Read projects", "normal"},
	{"realm.projects.write", "realm", "Manage projects and project grants", "high"},
	{"realm.clients.read", "realm", "Read client registrations", "normal"},
	{"realm.clients.write", "realm", "Manage client registrations", "high"},
	{"realm.clients.credentials", "realm", "Issue and revoke client credentials", "privileged"},
	{"realm.resources.read", "realm", "Read API resources and scopes", "normal"},
	{"realm.resources.write", "realm", "Manage API resources and scopes", "high"},
	{"realm.roles.read", "realm", "Read roles and permissions", "normal"},
	{"realm.roles.write", "realm", "Create and edit realm and project roles", "privileged"},
	{"realm.roles.assign", "realm", "Assign realm and project roles", "privileged"},
	{"realm.policies.read", "realm", "Read authorization policies", "normal"},
	{"realm.policies.write", "realm", "Edit authorization policies", "privileged"},
	{"realm.policies.publish", "realm", "Approve and publish policy revisions", "privileged"},
	{"realm.authorization.check", "realm", "Evaluate authorization decisions (resource servers)", "normal"},
	{"realm.session_events.read", "realm", "Read the session and access change stream (resource servers)", "normal"},
	{"realm.hooks.read", "realm", "Read pre-action hook configuration and health", "high"},
	{"realm.hooks.write", "realm", "Manage pre-action hooks", "privileged"},
	{"realm.authorization.simulate", "realm", "Simulate policy changes", "high"},
	{"realm.audit.read", "realm", "Query realm audit evidence", "high"},
	{"realm.audit.export", "realm", "Export realm audit evidence", "privileged"},
	{"realm.audit.legal_hold", "realm", "Place and release legal holds on audit evidence", "privileged"},
	{"realm.audit.import", "realm", "Import historical audit records from a source system", "privileged"},
	{"realm.audit.correct", "realm", "Record corrections to audit evidence as new linked events", "privileged"},
	{"realm.data.export", "realm", "Export the realm's identities, organizations, memberships, policies and configuration (credentials excluded)", "privileged"},
	{"realm.activity.report", "realm", "Report application activity into the audit log", "normal"},
	{"realm.keys.read", "realm", "Read signing-key lifecycle metadata", "normal"},
	{"realm.keys.rotate", "realm", "Rotate signing keys", "privileged"},
	{"realm.service_principals.read", "realm", "Read service principals", "normal"},
	{"realm.service_principals.write", "realm", "Manage service principals", "privileged"},
	{"realm.api_keys.manage", "realm", "Manage integration API keys", "privileged"},
	{"realm.identity_providers.read", "realm", "Read federation connections", "normal"},
	{"realm.identity_providers.write", "realm", "Manage federation connections", "privileged"},
	{"realm.provisioning.manage", "realm", "Manage provisioning connectors", "privileged"},
	{"realm.provisioning.read", "realm", "Read directory and outbound connector configuration, runs and health (never credentials)", "normal"},
	{"realm.webhooks.read", "realm", "Read webhook subscriptions and deliveries", "normal"},
	{"realm.webhooks.write", "realm", "Manage webhook subscriptions", "high"},
	{"realm.notifications.read", "realm", "Read notification settings and templates", "normal"},
	{"realm.notifications.write", "realm", "Manage notification settings and templates", "high"},
	{"realm.jobs.read", "realm", "Inspect jobs", "normal"},
	{"realm.jobs.cancel", "realm", "Cancel jobs", "high"},
	{"realm.configuration.export", "realm", "Export configuration", "high"},
	{"realm.configuration.import", "realm", "Reconcile configuration", "privileged"},
	{"realm.emergency", "realm", "Use emergency shutdown controls", "privileged"},
	{"realm.credentials.inventory", "realm", "Inspect automation credential inventory", "high"},
	{"realm.resource_types.read", "realm", "Read registered resource types and their relation schemas", "normal"},
	{"realm.resource_types.write", "realm", "Register resource types and their relation schemas (services)", "high"},
	{"realm.ssf_streams.manage", "realm", "Receive security events: create and manage the caller's own shared-signals streams", "high"},
	{"realm.ssf_streams.read", "realm", "Read every shared-signals stream and its delivery state", "normal"},
	{"realm.relationships.read", "realm", "Read resource relationships", "normal"},
	{"realm.relationships.write", "realm", "Write resource relationships (services)", "high"},
	{"realm.access_reviews.manage", "realm", "Run access review campaigns and apply their outcome", "privileged"},
	// Lifecycle workflows (EXT-015) and plugins (EXT-014). A published
	// workflow acts with its publisher's authority, never more.
	{"realm.workflows.read", "realm", "Read lifecycle workflows, their revisions and runs", "normal"},
	{"realm.workflows.write", "realm", "Draft lifecycle workflow revisions", "high"},
	{"realm.workflows.publish", "realm", "Approve, publish, roll back, enable and disable lifecycle workflows", "privileged"},
	{"realm.workflows.run", "realm", "Start and cancel lifecycle workflow runs", "high"},
	{"realm.plugins.read", "realm", "Read installed plugins and their versions", "normal"},
	{"realm.plugins.manage", "realm", "Upload, install, enable, disable, roll back and uninstall plugins", "privileged"},
	{"realm.plugins.approve", "realm", "Review and approve plugin versions uploaded by another administrator", "privileged"},
	// Organization administration (delegated).
	{"org.read", "organization", "Read organization profile", "low"},
	{"org.update", "organization", "Edit organization profile and policy", "high"},
	{"org.delete", "organization", "Delete the organization", "privileged"},
	{"org.members.read", "organization", "List organization members", "normal"},
	{"org.members.write", "organization", "Add, suspend and remove members", "high"},
	{"org.roles.read", "organization", "Read organization roles", "normal"},
	{"org.roles.write", "organization", "Create and edit organization roles", "high"},
	{"org.roles.assign", "organization", "Assign organization roles within ceiling", "high"},
	{"org.invites.read", "organization", "List invitations", "normal"},
	{"org.invites.create", "organization", "Create and resend invitations", "high"},
	{"org.invites.revoke", "organization", "Revoke invitations", "high"},
	{"org.groups.read", "organization", "Read groups", "normal"},
	{"org.groups.write", "organization", "Manage groups", "high"},
	{"org.domains.read", "organization", "Read domains", "normal"},
	{"org.domains.write", "organization", "Manage verified domains", "high"},
	{"org.ownership.transfer", "organization", "Transfer organization ownership", "privileged"},
	{"org.join_requests.review", "organization", "Review join requests", "high"},
	{"org.audit.read", "organization", "Read organization audit evidence", "high"},
	{"org.identity_providers.write", "organization", "Manage organization federation", "privileged"},
	{"org.support_access.approve", "organization", "Approve support access to members", "privileged"},
	{"org.service_principals.write", "organization", "Manage organization automation", "high"},
	{"org.integrations.write", "organization", "Manage the organization's own delivery and integration credentials", "privileged"},
	{"org.relationships.read", "organization", "Read the organization's parent, child and partner relationships", "normal"},
	{"org.relationships.write", "organization", "Propose, accept and end organization relationships", "high"},
	{"org.projects.share", "organization", "Grant selected roles of the organization's projects to related organizations", "privileged"},
	// Support.
	{"support.impersonation.start", "support", "Request customer support access", "privileged"},
	{"support.impersonation.approve", "support", "Approve another operator's support access", "privileged"},
	{"support.impersonation.revoke", "support", "Terminate any support grant", "privileged"},
	{"support.impersonation.read", "support", "List support grants", "high"},
	{"support.users.read", "support", "Read masked customer records", "high"},
	{"support.recovery.assist", "support", "Start assisted recovery workflows", "privileged"},
}

// RoleDef describes a built-in role.
type RoleDef struct {
	Name        string
	Boundary    string // realm | organization
	Description string
	Owner       bool
	Protected   bool
	Permissions []string // "*" suffix expands a namespace prefix
}

// Built-in role names.
const (
	RoleRealmAdmin      = "realm-admin"
	RoleUserAdmin       = "user-admin"
	RoleRealmAuditor    = "realm-auditor"
	RoleSupportOperator = "support-operator"
	RoleSupportApprover = "support-approver"
	RoleResourceServer  = "resource-server"
	RoleOrgOwner        = "owner"
	RoleOrgAdmin        = "admin"
	RoleOrgMember       = "member"
)

var BuiltInRoles = []RoleDef{
	{RoleRealmAdmin, "realm", "Full identity-domain administration", false, true, []string{"realm.*", "org.*", "support.*"}},
	{RoleUserAdmin, "realm", "Realm user administration", false, true, []string{"realm.users.read", "realm.users.write", "realm.users.suspend", "realm.users.sessions.revoke", "realm.users.required_actions", "realm.organizations.read"}},
	{RoleRealmAuditor, "realm", "Read-only audit and configuration access", false, true, []string{"realm.audit.read", "realm.settings.read", "realm.clients.read", "realm.resources.read", "realm.roles.read", "realm.organizations.read", "realm.keys.read", "realm.policies.read", "realm.webhooks.read", "realm.jobs.read", "support.impersonation.read", "realm.resource_types.read", "realm.relationships.read", "realm.provisioning.read",
		"realm.workflows.read", "realm.plugins.read", "realm.ssf_streams.read"}},
	{RoleSupportOperator, "realm", "Customer support with controlled impersonation", false, true, []string{"support.impersonation.start", "support.users.read", "support.impersonation.read"}},
	{RoleSupportApprover, "realm", "Approves support access requested by others", false, true, []string{"support.impersonation.approve", "support.impersonation.read", "support.impersonation.revoke"}},
	{RoleResourceServer, "realm", "Resource server: policy decisions, session change stream, resource types and relationships", false, true, []string{"realm.authorization.check",
		"realm.session_events.read", "realm.resource_types.read", "realm.resource_types.write", "realm.relationships.read", "realm.relationships.write"}},
	{RoleOrgOwner, "organization", "Organization owner", true, true, []string{"org.*"}},
	{RoleOrgAdmin, "organization", "Organization administrator", false, true, []string{"org.read", "org.update", "org.members.read", "org.members.write", "org.roles.read", "org.roles.write", "org.roles.assign", "org.invites.read", "org.invites.create", "org.invites.revoke", "org.groups.read", "org.groups.write", "org.domains.read", "org.join_requests.review", "org.audit.read", "org.service_principals.write", "org.relationships.read", "org.relationships.write"}},
	{RoleOrgMember, "organization", "Organization member", false, true, []string{"org.read"}},
}

// ExpandPatterns resolves "prefix.*" patterns against the catalog.
func ExpandPatterns(patterns []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range patterns {
		if len(p) > 1 && p[len(p)-1] == '*' {
			prefix := p[:len(p)-1]
			for _, d := range BuiltInPermissions {
				if len(d.Name) >= len(prefix) && d.Name[:len(prefix)] == prefix && !seen[d.Name] {
					seen[d.Name] = true
					out = append(out, d.Name)
				}
			}
			continue
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// Protected identity operations that impersonation tokens may never perform
// (IMP-012). The list and the matching rule are the SDK SupportGuard's
// (tests/fixtures/sdk-contracts/support-operations/cases.json is the shared test table).
var ImpersonationForbiddenActions = []string{
	"password.change", "password.reset", "mfa.change", "identifier.change", "account.link",
	"credential.export", "api_key.create", "personal_token.create", "consent.modify", "idp.admin",
	"payment", "refund", "ownership.transfer", "secret.read", "secret", "delete", "purge",
}

// WriteSegments are verbs that make an action a write wherever they appear
// as a segment of its name (the SDK list).
var WriteSegments = []string{"create", "add", "insert", "update", "edit", "modify", "change", "set", "put", "patch", "write",
	"upsert", "replace", "delete", "remove", "destroy", "erase", "purge", "archive", "unarchive", "restore", "reset", "rotate",
	"revoke", "grant", "assign", "unassign", "link", "unlink", "transfer", "issue", "approve", "reject", "cancel", "enable",
	"disable", "suspend", "reactivate", "activate", "deactivate", "lock", "unlock", "invite", "send", "submit", "publish",
	"unpublish", "import", "merge", "move", "rename", "refund", "pay", "execute"}

// actionSegments normalizes an action: trimmed, lowercased, '-' read as '_',
// split on '.', ':' and '/'.
func actionSegments(action string) []string {
	op := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(action)), "-", "_")
	return strings.FieldsFunc(op, func(r rune) bool { return r == '.' || r == ':' || r == '/' })
}

func segmentMatches(seg, entry string) bool {
	return seg == entry || seg == entry+"s" || seg+"s" == entry
}

func containsRun(segs, entry []string) bool {
	if len(entry) == 0 || len(entry) > len(segs) {
		return false
	}
	for start := 0; start+len(entry) <= len(segs); start++ {
		ok := true
		for k, e := range entry {
			if !segmentMatches(segs[start+k], e) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// IsSupportForbidden reports whether an action touches a protected identity,
// money or secret operation anywhere in its name: the segments of a
// forbidden entry occur as a contiguous run of the action's segments,
// case-insensitively and tolerating simple plurals ("refunds.issue",
// "payments.create", "secrets.read", "orders.purge"). Empty actions are
// forbidden (IMP-012, IMP-013).
func IsSupportForbidden(action string) bool {
	segs := actionSegments(action)
	if len(segs) == 0 {
		return true
	}
	for _, p := range ImpersonationForbiddenActions {
		if containsRun(segs, actionSegments(p)) {
			return true
		}
	}
	return false
}

// IsWriteAction reports whether any segment of the action is a write-like
// verb; such actions are writes whatever their suffix.
func IsWriteAction(action string) bool {
	for _, s := range actionSegments(action) {
		if slices.Contains(WriteSegments, s) {
			return true
		}
	}
	return false
}

// PermissionSensitivity returns the catalog sensitivity of a built-in
// permission ("low", "normal", "high" or "privileged"), or "" for
// application permissions.
func PermissionSensitivity(name string) string {
	for _, p := range BuiltInPermissions {
		if p.Name == name {
			return p.Sensitivity
		}
	}
	return ""
}

// PrivilegedPermissions lists the built-in permissions marked privileged.
func PrivilegedPermissions() []string {
	out := []string{}
	for _, p := range BuiltInPermissions {
		if p.Sensitivity == "privileged" {
			out = append(out, p.Name)
		}
	}
	return out
}

// MaxInspectedRoles bounds how many roles (the role and the roles it
// composes, at any depth) are inspected to decide whether a role is
// privileged; a larger composition counts as privileged (fails closed).
const MaxInspectedRoles = 64

// PrivilegedRoleSQL is a SQL condition on a roles row aliased ro that matches
// privileged roles exactly as IsPrivilegedRole decides: through composed
// roles at any depth; permissions registered as privileged (custom ones
// included) and wildcard grants count; and a composition of more than
// MaxInspectedRoles roles counts as privileged. $n must be bound to
// PrivilegedPermissions().
func PrivilegedRoleSQL(n int) string {
	arg := "$" + strconv.Itoa(n)
	// UNION (not UNION ALL) drops roles already reached, so cycles end; the
	// count reads at most one role past the cap.
	return `EXISTS (WITH RECURSIVE tree(id) AS (SELECT ro.id
			UNION SELECT c.id FROM tree t JOIN roles r ON r.realm_id=ro.realm_id AND r.id=t.id
				JOIN roles c ON c.realm_id=ro.realm_id AND c.id = ANY(r.composite_role_ids))
		SELECT 1 WHERE (SELECT count(*) FROM (SELECT 1 FROM tree LIMIT ` + strconv.Itoa(MaxInspectedRoles+1) + `) capped) > ` + strconv.Itoa(MaxInspectedRoles) + `
		OR EXISTS (SELECT 1 FROM tree t JOIN roles x ON x.realm_id=ro.realm_id AND x.id=t.id
		WHERE x.is_owner_role OR x.boundary_type='realm' OR EXISTS (SELECT 1 FROM role_permissions rp JOIN permissions p
			ON p.id=rp.permission_id WHERE rp.role_id=x.id AND rp.effect<>'deny' AND (p.sensitivity='privileged' OR p.name = ANY(` + arg + `)
			OR p.name='*' OR p.name LIKE '%.*'))))`
}
