package migrate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/canonical"
)

// sourceData is what an adapter extracts from an export: one shape for every
// source, so translation, mapping and reporting are shared.
type sourceData struct {
	version string
	scope   string // Keycloak realm, SuperTokens app; empty for ZITADEL
	orgs    []*srcOrg
	users   []*srcUser
	// roleNotes describes role keys for the mapping review and template.
	roleNotes map[string]string
	// other lists non-user entities (clients, identity providers, flows,
	// policies, projects, ...) with their outcome.
	other []otherEntity
	notes []string
}

type srcOrg struct {
	key       string // mapping key, e.g. "org:acme"
	id        string // immutable source ID, for the external ID
	name      string
	slug      string // proposed slug
	defaultOn bool   // an organization unless the mapping excludes it
	entity    string // report entity: organizations, groups or tenants
	lossNotes []string
	// notOrgReason, when set, is why the source organization is ignored
	// unless the mapping makes it an organization.
	notOrgReason string
}

type srcUser struct {
	id                     string
	username, email        string
	emailVerified          bool
	given, family, display string
	locale                 string
	disabled               bool
	stateNote              string // a loss in translating the source state
	machine                string // non-empty: not a human account (unsupported)
	unsupported            string // non-empty: the account cannot be imported
	password               *srcPassword
	totp                   []srcTOTP
	webauthn               []string
	recoveryCodes          int
	otherCreds             []string
	links                  []string
	phones                 []string
	attrs                  map[string]any
	actions                []string // ProudAuth required actions
	unsupportedActions     []string
	orgs                   []string // source organization keys the user belongs to
	grants                 []srcGrant
	losses                 []string
}

type srcPassword struct {
	algorithm string // what the source used, for the report
	hash      string // the verifier in a ProudAuth import format, if convertible
	problem   string // why it is not convertible
}

type srcTOTP struct {
	label   string
	seed    string // base32
	problem string // why it is not compatible
}

type srcGrant struct {
	key  string
	orgs []string // source organization keys that scope the grant
}

type otherEntity struct {
	entity, id, outcome string
	reasons             []string
}

var localeTag = regexp.MustCompile(`^[a-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$`)

// metadataLimit is the default limits.metadata_bytes: administrator metadata
// above it would be refused by the import.
const metadataLimit = 16 << 10

func translate(sd *sourceData, info SourceInfo, opts Options) *Result {
	rb := newReportBuilder(info, opts.SourceSystem, opts)
	res := &Result{Source: info, SourceSystem: opts.SourceSystem, Organizations: []TargetOrganization{}, Users: []identity.ImportRecord{}}
	m := opts.Mapping
	for _, n := range sd.notes {
		rb.note(n)
	}

	// Organizations: the source organizations the mapping (or the default)
	// turns into ProudAuth organizations.
	target := map[string]*TargetOrganization{} // source key -> target
	slugs := map[string]string{}               // slug -> source key
	known := map[string]bool{}
	srcMembers := map[string]int{}
	for _, u := range sd.users {
		for _, k := range u.orgs {
			srcMembers[k]++
		}
	}
	for _, o := range sd.orgs {
		known[o.key] = true
		t, listed := m.Organizations[o.key]
		review := OrgReview{Key: o.key, Name: o.name, Members: srcMembers[o.key]}
		switch {
		case listed && t == nil:
			review.Status = "excluded"
			rb.add(o.entity, o.key, Ignored, "excluded by the mapping")
		case listed:
			review.Status = "mapped"
			to := &TargetOrganization{SourceKey: o.key, Slug: t.Slug, DisplayName: firstNonEmpty(t.DisplayName, o.name, t.Slug),
				ExternalID: opts.SourceSystem + ":" + o.externalKey(), FromMapping: true}
			target[o.key] = to
		case o.defaultOn:
			review.Status = "auto"
			slug := o.slug
			if prev, dup := slugs[slug]; dup || slug == "" {
				base := firstNonEmpty(slug, "org")
				for i := 2; ; i++ {
					cand := fmt.Sprintf("%s-%d", strings.TrimRight(base[:min(len(base), 58)], "-"), i)
					if _, taken := slugs[cand]; !taken {
						slug = cand
						break
					}
				}
				if prev != "" {
					o.lossNotes = append(o.lossNotes, fmt.Sprintf("slug changed to %s (collides with %s)", slug, prev))
				} else {
					o.lossNotes = append(o.lossNotes, fmt.Sprintf("no slug can be derived from the name; using %s", slug))
				}
			}
			to := &TargetOrganization{SourceKey: o.key, Slug: slug, DisplayName: firstNonEmpty(o.name, slug),
				ExternalID: opts.SourceSystem + ":" + o.externalKey()}
			target[o.key] = to
		default:
			review.Status = "not_an_organization"
			rt, roleListed := m.Roles[o.key]
			switch {
			case o.notOrgReason != "":
				rb.add(o.entity, o.key, Ignored, o.notOrgReason)
			case roleListed && rt != nil && len(rt.Roles) > 0:
				rb.add(o.entity, o.key, Converted)
			case roleListed:
				rb.add(o.entity, o.key, Ignored, "mapped to no roles")
			case srcMembers[o.key] == 0:
				rb.add(o.entity, o.key, Ignored, "no members")
			default:
				rb.add(o.entity, o.key, Unsupported, "neither an organization nor a translated role: add it to the mapping")
			}
		}
		if to := target[o.key]; to != nil {
			review.Slug = to.Slug
			if prev, dup := slugs[to.Slug]; dup && prev != o.key {
				rb.note(fmt.Sprintf("source organizations %s and %s both map to %s: their members share one organization", prev, o.key, to.Slug))
			}
			slugs[to.Slug] = o.key
			if len(o.lossNotes) > 0 {
				rb.add(o.entity, o.key, ConvertedWithLoss, o.lossNotes...)
			} else {
				rb.add(o.entity, o.key, Converted)
			}
		}
		rb.r.Mapping.Organizations = append(rb.r.Mapping.Organizations, review)
	}
	for k := range m.Organizations {
		if !known[k] {
			rb.r.Mapping.UnknownKeys = append(rb.r.Mapping.UnknownKeys, k)
		}
	}

	// Role keys seen in the export, for the review.
	roleGrants := map[string]int{}
	for _, u := range sd.users {
		if u.machine != "" || u.unsupported != "" {
			continue
		}
		for _, g := range u.grants {
			roleGrants[g.key]++
		}
	}
	for k := range m.Roles {
		if _, ok := roleGrants[k]; !ok {
			if _, described := sd.roleNotes[k]; !described {
				rb.r.Mapping.UnknownKeys = append(rb.r.Mapping.UnknownKeys, k)
			}
		}
	}
	sort.Strings(rb.r.Mapping.UnknownKeys)

	s := &rb.r.Summary
	for _, u := range sd.users {
		if u.machine != "" {
			rb.add("service_accounts", u.id, Unsupported, u.machine)
			continue
		}
		s.Users++
		rec, ok := translateUser(u, rb, opts, target, m)
		if !ok {
			continue
		}
		s.UsersToImport++
		res.Users = append(res.Users, rec)
		if rec.PasswordHash != "" {
			s.PasswordsMigrated++
		}
		if slices.Contains(rec.RequiredActions, identity.ActionUpdatePassword) && rec.PasswordHash == "" && u.password != nil {
			s.PasswordResetsRequired++
		}
		if rec.TOTPSecret != "" {
			s.TOTPMigrated++
		}
		if slices.Contains(rec.RequiredActions, identity.ActionConfigureTOTP) && len(u.totp) > 0 {
			s.MFAReenrollmentsRequired++
		}
		if rec.State == identity.StateSuspended {
			s.SuspendedAccounts++
		}
		s.Memberships += len(rec.Memberships)
		for _, ms := range rec.Memberships {
			s.RoleAssignments += len(ms.Roles)
		}
	}

	// Members per organization, for the review and the plan.
	members := map[string]int{}
	for _, rec := range res.Users {
		for _, ms := range rec.Memberships {
			members[ms.Organization]++
		}
	}
	seen := map[string]bool{}
	for _, o := range sd.orgs {
		if t := target[o.key]; t != nil && !seen[t.Slug] {
			seen[t.Slug] = true
			t.Members = members[t.Slug]
			res.Organizations = append(res.Organizations, *t)
		}
	}
	// Organizations named only by role mappings must already exist.
	for _, rec := range res.Users {
		for _, ms := range rec.Memberships {
			if !seen[ms.Organization] {
				seen[ms.Organization] = true
				res.Organizations = append(res.Organizations, TargetOrganization{Slug: ms.Organization, DisplayName: ms.Organization,
					FromMapping: true, Members: members[ms.Organization]})
			}
		}
	}
	s.Organizations = len(res.Organizations)

	// Role review.
	keys := make([]string, 0, len(roleGrants))
	for k := range roleGrants {
		keys = append(keys, k)
	}
	for k := range sd.roleNotes {
		if _, ok := roleGrants[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		rr := RoleReview{Key: k, Note: sd.roleNotes[k], Grants: roleGrants[k]}
		t, listed := m.Roles[k]
		switch {
		case isDefaultRoleKey(k):
			rr.Status = "ignored"
		case !listed:
			rr.Status = "untranslated"
		case t == nil || len(t.Roles) == 0:
			rr.Status = "no_roles"
		default:
			rr.Status, rr.Organization, rr.Roles = "mapped", t.Organization, t.Roles
		}
		rb.r.Mapping.Roles = append(rb.r.Mapping.Roles, rr)
		if strings.HasPrefix(k, "group:") {
			continue // reported as groups
		}
		switch rr.Status {
		case "mapped":
			rb.add("role_definitions", k, Converted)
		case "no_roles":
			rb.add("role_definitions", k, Ignored, "mapped to no roles")
		case "ignored":
			rb.add("role_definitions", k, Ignored, "default role without access in ProudAuth")
		case "untranslated":
			if rr.Grants > 0 {
				rb.add("role_definitions", k, Unsupported, "no reviewed translation: add it to the mapping")
			} else {
				rb.add("role_definitions", k, Ignored, "not granted to any imported user")
			}
		}
	}

	for _, o := range sd.other {
		rb.add(o.entity, o.id, o.outcome, o.reasons...)
	}
	res.Report = rb.finish()
	return res
}

func (o *srcOrg) externalKey() string {
	kind, _, _ := strings.Cut(o.key, ":")
	return kind + ":" + firstNonEmpty(o.id, strings.TrimPrefix(o.key, kind+":"))
}

// translateUser converts one human account and reports every part of it.
func translateUser(u *srcUser, rb *reportBuilder, opts Options, target map[string]*TargetOrganization, m *Mapping) (identity.ImportRecord, bool) {
	var losses []string
	rec := identity.ImportRecord{SourceID: u.id, Memberships: []identity.ImportMembership{}}
	if u.id == "" || len(u.id) > 256 {
		rb.add("users", u.id, Unsupported, "source ID missing or longer than 256 characters")
		return rec, false
	}
	if u.unsupported != "" {
		rb.add("users", u.id, Unsupported, u.unsupported)
		reportCredentialsNotImported(u, rb, "account not imported")
		return rec, false
	}

	// Identifiers. Matching identifiers never merge accounts (MIG-004):
	// the import reports a conflict instead.
	if u.email != "" {
		if _, _, err := canonical.Email(u.email); err == nil {
			rec.Email, rec.EmailVerified = strings.TrimSpace(u.email), u.emailVerified
		} else {
			losses = append(losses, "email is not a valid address and was not imported")
		}
	}
	if u.username != "" && !strings.EqualFold(strings.TrimSpace(u.username), rec.Email) {
		if _, err := canonical.Username(u.username); err == nil {
			rec.Username = strings.TrimSpace(u.username)
		} else {
			losses = append(losses, fmt.Sprintf("username not imported (%v)", err))
		}
	}
	if rec.Email == "" && rec.Username == "" {
		rb.add("users", u.id, Unsupported, "no importable email or username (phone-only or invalid identifiers)")
		reportCredentialsNotImported(u, rb, "account not imported")
		return rec, false
	}

	// Profile.
	rec.GivenName, losses = clip(u.given, 100, "given name", losses)
	rec.FamilyName, losses = clip(u.family, 100, "family name", losses)
	display := u.display
	if display == "" {
		display = strings.TrimSpace(u.given + " " + u.family)
	}
	rec.DisplayName, losses = clip(display, 200, "display name", losses)
	if u.locale != "" && u.locale != "und" {
		if localeTag.MatchString(u.locale) {
			rec.Locale = u.locale
		} else {
			losses = append(losses, fmt.Sprintf("locale %q is not a BCP 47 tag and was not imported", u.locale))
		}
	}
	if u.disabled {
		rec.State = identity.StateSuspended
	}
	if u.stateNote != "" {
		losses = append(losses, u.stateNote)
	}
	losses = append(losses, u.losses...)

	actions := slices.Clone(u.actions)
	addAction := func(a string) {
		if !slices.Contains(actions, a) {
			actions = append(actions, a)
		}
	}

	// Password (MIG-006): imported only in an accepted format within the
	// bounds; otherwise the account must reset its password.
	if p := u.password; p != nil {
		problem := p.problem
		if problem == "" && p.hash != "" {
			if err := credential.ValidateImportedHash(p.hash); err != nil {
				problem = err.Error()
			}
		}
		if problem == "" && p.hash != "" {
			rec.PasswordHash = p.hash
			rb.add("password_credentials", u.id, Converted)
		} else {
			reason := fmt.Sprintf("%s: %s", p.algorithm, firstNonEmpty(problem, "not convertible"))
			rb.add("password_credentials", u.id, Unsupported, reason)
			losses = append(losses, "password not migrated ("+reason+"); password reset required")
			addAction(identity.ActionUpdatePassword)
		}
	}

	// TOTP (MIG-007): one compatible seed, only when authorized.
	imported := false
	for _, t := range u.totp {
		switch {
		case t.problem != "":
			rb.add("totp_factors", u.id, Unsupported, t.problem)
			losses = append(losses, "TOTP factor not migrated ("+t.problem+")")
		case !validSeed(t.seed):
			rb.add("totp_factors", u.id, Unsupported, "seed is not 80 to 512 bits of base32")
			losses = append(losses, "TOTP factor not migrated (invalid seed)")
		case !opts.ImportTOTP:
			rb.add("totp_factors", u.id, Ignored, "not requested (import TOTP seeds explicitly)")
			losses = append(losses, "TOTP factor not migrated (not requested)")
		case imported:
			rb.add("totp_factors", u.id, Ignored, "only one TOTP factor per account is imported")
			losses = append(losses, "additional TOTP factor not migrated")
		default:
			rec.TOTPSecret, imported = t.seed, true
			rb.add("totp_factors", u.id, Converted)
		}
	}
	if len(u.totp) > 0 && !imported {
		// The account had a second factor: it enrolls again rather than
		// silently losing it.
		addAction(identity.ActionConfigureTOTP)
	}
	for range u.webauthn {
		rb.add("webauthn_credentials", u.id, Unsupported, "passkeys are bound to the source's relying party and private keys never leave the authenticator; the user registers again (MIG-008)")
	}
	if len(u.webauthn) > 0 {
		losses = append(losses, fmt.Sprintf("%d WebAuthn credential(s) not migrated; re-registration required", len(u.webauthn)))
	}
	if u.recoveryCodes > 0 {
		rb.add("recovery_codes", u.id, Unsupported, "recovery codes are one-way hashed by the source and cannot be verified here; new codes are issued with the next factor enrollment")
		losses = append(losses, "recovery codes not migrated")
	}
	for _, c := range u.otherCreds {
		rb.add("other_credentials", u.id, Unsupported, c)
		losses = append(losses, "credential not migrated: "+c)
	}
	for range u.links {
		rb.add("federated_identities", u.id, Unsupported, "identity provider links are not imported; the user links again through the configured upstream connection (explicit linking policy)")
	}
	if len(u.links) > 0 {
		losses = append(losses, fmt.Sprintf("%d identity provider link(s) not migrated", len(u.links)))
	}
	for range u.phones {
		rb.add("phone_numbers", u.id, Unsupported, "phone identifiers are not imported")
	}
	if len(u.phones) > 0 {
		losses = append(losses, "phone number not migrated")
	}

	// Attributes and metadata: administrator-only, and only when kept.
	if len(u.attrs) > 0 {
		names := make([]string, 0, len(u.attrs))
		for k := range u.attrs {
			names = append(names, k)
		}
		sort.Strings(names)
		if opts.KeepAttributes {
			md := map[string]any{"migration": map[string]any{"source_system": opts.SourceSystem, "source_attributes": u.attrs}}
			if b, _ := json.Marshal(md); len(b) <= metadataLimit {
				rec.AdminMetadata = md
				rb.add("attributes", u.id, Converted)
			} else {
				rb.add("attributes", u.id, Unsupported, fmt.Sprintf("attributes exceed %d bytes of administrator metadata", metadataLimit))
				losses = append(losses, "attributes not kept (too large): "+strings.Join(names, ", "))
			}
		} else {
			rb.add("attributes", u.id, Ignored, "not requested (keep attributes explicitly)")
			losses = append(losses, "attributes not kept: "+strings.Join(names, ", "))
		}
	}

	// Required actions.
	for _, a := range u.unsupportedActions {
		rb.add("required_actions", u.id, Unsupported, "no equivalent required action: "+a)
		losses = append(losses, "required action not migrated: "+a)
	}
	// Actions added here (update_password, configure_totp) are counted in
	// the summary; this counts the source's own.
	rb.addN("required_actions", Converted, len(u.actions))
	if len(actions) > 0 {
		rec.RequiredActions = actions
	}

	// Memberships and role grants through the reviewed mapping (MIG-005).
	memberships := map[string][]string{}
	var order []string
	join := func(slug string, roles ...string) {
		if _, ok := memberships[slug]; !ok {
			order = append(order, slug)
			memberships[slug] = append([]string{}, m.MembershipRoles...)
		}
		for _, r := range roles {
			if !slices.ContainsFunc(memberships[slug], func(x string) bool { return strings.EqualFold(x, r) }) {
				memberships[slug] = append(memberships[slug], r)
			}
		}
	}
	userOrgs := []string{}
	for _, key := range u.orgs {
		if t := target[key]; t != nil {
			join(t.Slug)
			userOrgs = append(userOrgs, t.Slug)
		} else if mt, listed := m.Organizations[key]; listed && mt == nil {
			rb.add("memberships", u.id, Ignored, "organization "+key+" excluded by the mapping")
		}
	}
	for _, g := range u.grants {
		if isDefaultRoleKey(g.key) {
			rb.add("role_assignments", u.id, Ignored, "default role "+g.key+" carries no access in ProudAuth")
			continue
		}
		t, listed := m.Roles[g.key]
		switch {
		case !listed:
			rb.add("role_assignments", u.id, Unsupported, "no reviewed translation for "+g.key)
			losses = append(losses, "role grant "+g.key+" not translated")
			rb.r.Summary.UntranslatedRoleGrants++
			continue
		case t == nil || len(t.Roles) == 0:
			rb.add("role_assignments", u.id, Ignored, g.key+" is mapped to no roles")
			continue
		}
		var scope []string
		if t.Organization != "" {
			scope = []string{t.Organization}
		} else if len(g.orgs) > 0 {
			for _, k := range g.orgs {
				if to := target[k]; to != nil {
					scope = append(scope, to.Slug)
				}
			}
		} else {
			scope = userOrgs
		}
		scope = uniq(scope)
		if len(scope) == 0 {
			rb.add("role_assignments", u.id, Unsupported, g.key+": no organization to scope the roles in (set organization in the mapping)")
			losses = append(losses, "role grant "+g.key+" has no target organization")
			rb.r.Summary.UntranslatedRoleGrants++
			continue
		}
		for _, slug := range scope {
			join(slug, t.Roles...)
		}
		rb.add("role_assignments", u.id, Converted)
	}
	for _, slug := range order {
		rec.Memberships = append(rec.Memberships, identity.ImportMembership{Organization: slug, Roles: memberships[slug]})
		rb.add("memberships", u.id, Converted)
	}

	if len(losses) > 0 {
		rb.add("users", u.id, ConvertedWithLoss, losses...)
	} else {
		rb.add("users", u.id, Converted)
	}
	return rec, true
}

// reportCredentialsNotImported counts the credentials of an account that is
// not imported, so they are not dropped from the report.
func reportCredentialsNotImported(u *srcUser, rb *reportBuilder, why string) {
	if u.password != nil {
		rb.add("password_credentials", u.id, Unsupported, why)
	}
	for range u.totp {
		rb.add("totp_factors", u.id, Unsupported, why)
	}
	for range u.webauthn {
		rb.add("webauthn_credentials", u.id, Unsupported, why)
	}
	for range u.links {
		rb.add("federated_identities", u.id, Unsupported, why)
	}
	for range u.phones {
		rb.add("phone_numbers", u.id, Unsupported, why)
	}
	for _, g := range u.grants {
		rb.add("role_assignments", u.id, Unsupported, why+": "+g.key)
	}
}

func isDefaultRoleKey(k string) bool {
	if !strings.HasPrefix(k, "realm-role:") {
		return false
	}
	n := strings.TrimPrefix(k, "realm-role:")
	return n == "offline_access" || n == "uma_authorization" || strings.HasPrefix(n, "default-roles-")
}

func validSeed(seed string) bool {
	_, err := credential.NormalizeImportedTOTPSeed(seed)
	return err == nil
}

func clip(s string, max int, what string, losses []string) (string, []string) {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s, losses
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], append(losses, fmt.Sprintf("%s truncated to %d bytes", what, max))
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Template returns a mapping document listing every organization and role
// key of a conversion, for review: organizations with their proposed slugs,
// roles with no target roles yet (an empty list carries no roles).
func Template(res *Result, prev *Mapping) *Mapping {
	out := &Mapping{Format: MappingFormat, Organizations: map[string]*OrgTarget{}, Roles: map[string]*RoleTarget{}}
	if prev != nil {
		out.MembershipRoles = prev.MembershipRoles
	}
	for _, o := range res.Report.Mapping.Organizations {
		if prev != nil {
			if t, ok := prev.Organizations[o.Key]; ok {
				out.Organizations[o.Key] = t
				continue
			}
		}
		switch o.Status {
		case "auto", "mapped":
			out.Organizations[o.Key] = &OrgTarget{Slug: o.Slug, DisplayName: o.Name}
		case "not_an_organization":
			// Keycloak groups and the SuperTokens public tenant stay
			// out unless the reviewer adds them.
		case "excluded":
			out.Organizations[o.Key] = nil
		}
	}
	for _, r := range res.Report.Mapping.Roles {
		if r.Status == "ignored" {
			continue
		}
		if prev != nil {
			if t, ok := prev.Roles[r.Key]; ok {
				out.Roles[r.Key] = t
				continue
			}
		}
		out.Roles[r.Key] = &RoleTarget{Roles: []string{}, Note: strings.TrimSpace(fmt.Sprintf("%s (%d grants)", r.Note, r.Grants))}
	}
	return out
}
