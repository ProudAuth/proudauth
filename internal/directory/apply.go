package directory

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/events"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/jobs"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// entry is a directory user entry reduced to what the connector maps.
type entry struct {
	ext      string
	dn       string
	values   map[string]string // local attribute -> directory value
	disabled bool
	modified string // modifyTimestamp (generalized time)
	usn      int64
}

func readEntry(cfg *LDAPConfig, e *ldap.Entry) entry {
	ev := entry{ext: idValue(cfg, e), dn: e.DN, values: map[string]string{}, disabled: disabled(cfg, e),
		modified: e.GetEqualFoldAttributeValue("modifyTimestamp")}
	for local, remote := range cfg.AttributeMapping {
		if v := strings.TrimSpace(e.GetEqualFoldAttributeValue(remote)); v != "" {
			ev.values[local] = v
		}
	}
	if v := e.GetEqualFoldAttributeValue("uSNChanged"); v != "" {
		ev.usn, _ = strconv.ParseInt(v, 10, 64)
	}
	return ev
}

// Finding is one item of a run's plan or report.
type Finding struct {
	Seq        int            `json:"seq"`
	Kind       string         `json:"kind"`
	Reason     string         `json:"reason,omitempty"`
	ExternalID string         `json:"external_id,omitempty"`
	SourceDN   string         `json:"source_dn,omitempty"`
	LocalID    string         `json:"local_id,omitempty"`
	Attributes []string       `json:"attributes"`
	Applied    bool           `json:"applied"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// Finding kinds.
const (
	FindCreate      = "create"
	FindUpdate      = "update"
	FindLink        = "link"
	FindSuspend     = "suspend"
	FindReactivate  = "reactivate"
	FindDeprovision = "deprovision"
	FindConflict    = "conflict"
	FindDivergence  = "divergence"
	FindSkip        = "skip"
	FindError       = "error"
	FindGroup       = "group"
	FindDelivery    = "delivery"
)

// maxFindings bounds the stored findings of one run; counts stay complete.
const maxFindings = 5000

// runCtx accumulates one run's findings and counts.
type runCtx struct {
	id     string
	dry    bool
	full   bool
	jit    bool
	job    *jobs.Job
	mu     sync.Mutex
	items  []Finding
	stored int
	counts map[string]int
	seen   map[string]bool
}

func newRunCtx(id string, dry, full bool) *runCtx {
	return &runCtx{id: id, dry: dry, full: full, counts: map[string]int{}, seen: map[string]bool{}}
}

// runTx locks the job claim before domain rows, fencing every committed
// synchronization effect against a worker whose lease expired or was reclaimed.
// JIT authentication has no background job and keeps its existing transaction.
func (s *Service) runTx(ctx context.Context, r *runCtx, fn func(pgx.Tx) error) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if r.job != nil {
			if err := r.job.LockLease(ctx, tx); err != nil {
				return err
			}
		}
		return fn(tx)
	})
}

func (r *runCtx) add(f Finding) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[f.Kind]++
	if f.Attributes == nil {
		f.Attributes = []string{}
	}
	if r.stored >= maxFindings {
		r.counts["findings_truncated"]++
		return
	}
	r.stored++
	f.Seq = r.stored
	r.items = append(r.items, f)
}

// errDryRun rolls back a dry run's transaction after the plan was computed
// with exactly the logic a real run applies.
var errDryRun = errors.New("dry run")

// userView is the part of an account the directory compares.
type userView struct {
	id, state, createdVia, username, email string
	displayName, givenName, familyName     string
	locale, zoneinfo                       string
	profile                                map[string]any
	protected                              bool
}

func viewOf(u *identity.User) userView {
	v := userView{id: u.ID, state: u.State, createdVia: u.CreatedVia, displayName: u.DisplayName, givenName: u.GivenName, familyName: u.FamilyName,
		locale: u.Locale, zoneinfo: u.Zoneinfo, profile: u.Profile, protected: u.Protected, username: u.Username()}
	if e := u.PrimaryEmail(); e != nil {
		v.email = e.Value
	}
	return v
}

func (s *Service) source(c *Connector) string { return "directory:" + c.ID }

// accountLocked reports accounts a connector never changes (PROV-006):
// protected accounts and holders of privileged realm roles.
func (s *Service) accountLocked(ctx context.Context, q storage.Querier, c *Connector, u *identity.User) bool {
	if u.Protected {
		return true
	}
	priv, err := s.Authz.HoldsPrivilegedRealmRole(ctx, q, c.RealmID, u.ID)
	return err != nil || priv
}

// managesIdentity reports whether the connector owns the account's
// realm-wide attributes. A realm directory owns the accounts it links; an
// organization directory owns only accounts it created that belong to no
// other organization, mirroring inbound SCIM (PROV-005).
func (s *Service) managesIdentity(ctx context.Context, q storage.Querier, c *Connector, u userView) bool {
	if c.OrganizationID == "" {
		return true
	}
	if u.createdVia != s.source(c) {
		return false
	}
	var others int
	_ = q.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE user_id=$1 AND organization_id<>$2 AND state NOT IN ('removed','expired')`,
		u.id, c.OrganizationID).Scan(&others)
	return others == 0
}

func (s *Service) domainVerified(ctx context.Context, c *Connector, email string) bool {
	if c.OrganizationID == "" {
		return false
	}
	_, at, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok {
		return false
	}
	ok, err := s.Orgs.DomainCovered(ctx, c.RealmID, c.OrganizationID, at)
	return err == nil && ok
}

// applyEntry brings one directory entry into the identity domain inside tx
// and reports what it did (or, in a dry run, what it would do). It returns
// the linked account, if any.
func (s *Service) applyEntry(ctx context.Context, tx pgx.Tx, r *runCtx, c *Connector, ev entry) (string, error) {
	ctx = identity.WithExternalWriter(ctx)
	if ev.ext == "" {
		r.add(Finding{Kind: FindError, Reason: "missing_id_attribute", SourceDN: ev.dn})
		return "", nil
	}
	r.mu.Lock()
	r.seen[ev.ext] = true
	r.mu.Unlock()
	l, err := s.linkByExternal(ctx, tx, c.ID, ev.ext, true)
	if err != nil {
		return "", err
	}
	if l == nil {
		return s.newEntry(ctx, tx, r, c, ev)
	}
	return l.UserID, s.updateEntry(ctx, tx, r, c, ev, l)
}

// newEntry creates, adopts or reports a conflict for an entry the connector
// has not linked yet. Existing accounts are never merged silently: only an
// organization connector adopts one, through a verified domain, under the
// rules inbound SCIM uses (FED-004, PROV-004).
func (s *Service) newEntry(ctx context.Context, tx pgx.Tx, r *runCtx, c *Connector, ev entry) (string, error) {
	f := Finding{ExternalID: ev.ext, SourceDN: ev.dn}
	if ev.disabled {
		f.Kind, f.Reason = FindSkip, "disabled_in_directory"
		r.add(f)
		return "", nil
	}
	username, email := ev.values["username"], ev.values["email"]
	var userCanon, emailCanon string
	if username != "" {
		if cu, err := canonical.Username(username); err == nil {
			userCanon = cu
		}
	}
	if email != "" {
		if ce, _, err := canonical.Email(email); err == nil {
			emailCanon = ce
		} else {
			email = ""
		}
	}
	if userCanon == "" && emailCanon == "" {
		f.Kind, f.Reason = FindError, "no_usable_identifier"
		r.add(f)
		return "", nil
	}
	var byUser, byEmail string
	if userCanon != "" {
		_ = tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='username' AND canonical_value=$2`, c.RealmID, userCanon).Scan(&byUser)
	}
	if emailCanon != "" {
		_ = tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2 AND verified_at IS NOT NULL`,
			c.RealmID, emailCanon).Scan(&byEmail)
	}
	existing := byEmail
	if existing == "" {
		existing = byUser
	}
	if byUser != "" && byEmail != "" && byUser != byEmail {
		f.Kind, f.Reason = FindConflict, "identifiers_belong_to_different_accounts"
		r.add(f)
		return "", nil
	}
	if existing != "" {
		return s.adopt(ctx, tx, r, c, ev, existing, emailCanon)
	}
	verified := emailCanon != "" && s.domainVerified(ctx, c, emailCanon)
	in := identity.CreateInput{Email: email, EmailVerified: verified, VerificationSource: s.source(c), DisplayName: clip(ev.values["display_name"], 200),
		GivenName: clip(ev.values["given_name"], 100), FamilyName: clip(ev.values["family_name"], 100), Locale: clip(ev.values["locale"], 35),
		State: identity.StateActive, CreatedVia: s.source(c), Profile: map[string]any{}}
	if userCanon != "" {
		in.Username = username
	}
	if z := ev.values["zoneinfo"]; z != "" {
		if _, err := time.LoadLocation(z); err == nil {
			in.Zoneinfo = z
		}
	}
	for k, v := range ev.values {
		if pk, ok := strings.CutPrefix(k, "profile."); ok {
			in.Profile[pk] = clip(v, 1024)
		}
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return "", err
	}
	u, err := s.Users.CreateTx(ctx, sp, c.RealmID, in)
	if err != nil {
		_ = sp.Rollback(ctx)
		if pe, ok := problem.As(err); ok && pe.Status < 500 {
			f.Kind, f.Reason = FindConflict, "identifier_in_use"
			r.add(f)
			return "", nil
		}
		return "", err
	}
	if err := sp.Commit(ctx); err != nil {
		return "", err
	}
	if c.OrganizationID != "" {
		if err := s.ensureMembership(ctx, tx, c, u.ID, true); err != nil {
			return "", err
		}
	}
	l := &link{ExternalID: ev.ext, UserID: u.ID, DN: ev.dn, SourceState: "active", Snapshot: ev.values}
	if err := s.saveLink(ctx, tx, c, l, r.id); err != nil {
		return "", err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.user.provisioned", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
		Subject: &audit.Ref{Type: "user", ID: u.ID}, Category: "account", Metadata: map[string]any{"run_id": r.id, "jit": r.jit, "email_verified": verified}}); err != nil {
		return "", err
	}
	f.Kind, f.LocalID, f.Applied = FindCreate, u.ID, !r.dry
	for k := range ev.values {
		f.Attributes = append(f.Attributes, k)
	}
	sort.Strings(f.Attributes)
	r.add(f)
	return u.ID, nil
}

// adopt links an existing account only when an organization connector may
// claim it: its verified email is in a domain the organization verified, it
// is neither protected nor privileged, and no other connector manages it.
// Its local password is revoked, so sign-in never falls back to a stale
// local secret once the directory owns the password.
func (s *Service) adopt(ctx context.Context, tx pgx.Tx, r *runCtx, c *Connector, ev entry, userID, emailCanon string) (string, error) {
	f := Finding{ExternalID: ev.ext, SourceDN: ev.dn}
	u, err := s.Users.User(ctx, tx, c.RealmID, userID)
	if err != nil {
		return "", err
	}
	reason := ""
	verifiedMatch := false
	for _, i := range u.Identifiers {
		if i.Type == "email" && i.Verified() && i.Canonical == emailCanon {
			verifiedMatch = true
		}
	}
	var managed bool
	_ = tx.QueryRow(ctx, `SELECT true FROM connector_external_ids WHERE local_id=$1 AND resource_type='User' LIMIT 1`, userID).Scan(&managed)
	switch {
	case c.OrganizationID == "":
		reason = "identifier_in_use"
	case u.State == identity.StateDeleted || u.State == identity.StatePendingDeletion:
		reason = "identifier_in_use"
	case s.accountLocked(ctx, tx, c, u):
		reason = "protected_account"
	case managed || strings.HasPrefix(u.CreatedVia, "scim:") || (strings.HasPrefix(u.CreatedVia, "directory:") && u.CreatedVia != s.source(c)):
		reason = "managed_by_another_connector"
	case emailCanon == "" || !verifiedMatch || !s.domainVerified(ctx, c, emailCanon):
		reason = "domain_not_verified"
	}
	if userCanon, err := canonical.Username(ev.values["username"]); err == nil && reason == "" {
		var owner string
		_ = tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='username' AND canonical_value=$2`, c.RealmID, userCanon).Scan(&owner)
		if owner != "" && owner != userID {
			reason = "identifiers_belong_to_different_accounts"
		}
	}
	if reason != "" {
		f.Kind, f.Reason = FindConflict, reason
		r.add(f)
		return "", nil
	}
	if _, err := tx.Exec(ctx, `UPDATE credentials SET state='revoked', updated_at=$2 WHERE user_id=$1 AND type='password' AND state IN ('active','compromised')`,
		userID, s.d.Now()); err != nil {
		return "", err
	}
	if err := s.ensureMembership(ctx, tx, c, userID, true); err != nil {
		return "", err
	}
	l := &link{ExternalID: ev.ext, UserID: userID, DN: ev.dn, SourceState: "active", Snapshot: ev.values}
	if err := s.saveLink(ctx, tx, c, l, r.id); err != nil {
		if storage.IsUniqueViolation(err) {
			f.Kind, f.Reason = FindConflict, "managed_by_another_connector"
			r.add(f)
			return "", nil
		}
		return "", err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.user.linked", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
		Subject: &audit.Ref{Type: "user", ID: userID}, Category: "account", ReasonCode: "VERIFIED_DOMAIN",
		Metadata: map[string]any{"run_id": r.id, "local_password_revoked": true}}); err != nil {
		return "", err
	}
	f.Kind, f.Reason, f.LocalID, f.Applied = FindLink, "adopted_through_verified_domain", userID, !r.dry
	r.add(f)
	return userID, nil
}

// updateEntry applies a linked entry: attributes the directory owns, the
// account state, and the link's snapshot. Attributes with local authority
// are never overwritten; a difference is reported as divergence, so two
// authorities never overwrite each other in turn (PROV-017).
func (s *Service) updateEntry(ctx context.Context, tx pgx.Tx, r *runCtx, c *Connector, ev entry, l *link) error {
	cfg := c.ldap
	u, err := s.Users.LockUser(ctx, tx, c.RealmID, l.UserID)
	if err != nil && !problem.Is(err, problem.ErrNotFound) {
		return err
	}
	if err != nil || u.State == identity.StateDeleted {
		// The link stays (the entry is not imported again), but the
		// finding carries no DN: it would tie the erased account to a
		// name again (PRV-005).
		r.add(Finding{Kind: FindError, Reason: "linked_account_deleted", ExternalID: ev.ext, LocalID: l.UserID})
		return nil
	}
	if s.accountLocked(ctx, tx, c, u) {
		r.add(Finding{Kind: FindSkip, Reason: "protected_account", ExternalID: ev.ext, LocalID: u.ID})
		l.DN = ev.dn
		return s.saveLink(ctx, tx, c, l, r.id)
	}
	view := viewOf(u)
	manages := s.managesIdentity(ctx, tx, c, view)
	var changed, divergent []string
	set := map[string]string{}
	for attr, val := range ev.values {
		cur := localValue(view, attr)
		if sameValue(attr, cur, val) {
			continue
		}
		switch cfg.authority(attr) {
		case AuthorityDirectory, AuthorityWriteBack:
			if !manages {
				divergent = append(divergent, attr)
				continue
			}
			set[attr] = val
		case AuthorityLocal:
			if r.full {
				divergent = append(divergent, attr)
			}
		}
	}
	// A mapped attribute the directory cleared is cleared locally too when
	// the directory owns it (names, locale, profile values; never the
	// identifiers an account signs in with).
	for attr := range cfg.AttributeMapping {
		if _, present := ev.values[attr]; present || attr == "username" || attr == "email" {
			continue
		}
		if a := cfg.authority(attr); (a == AuthorityDirectory || a == AuthorityWriteBack) && manages && localValue(view, attr) != "" {
			set[attr] = ""
		}
	}
	if len(set) > 0 {
		applied, conflicts, err := s.setAttributes(ctx, tx, c, u, set)
		if err != nil {
			return err
		}
		changed = applied
		for _, a := range conflicts {
			r.add(Finding{Kind: FindConflict, Reason: "identifier_in_use", ExternalID: ev.ext, LocalID: u.ID, Attributes: []string{a}})
		}
	}
	sort.Strings(changed)
	sort.Strings(divergent)
	if len(changed) > 0 {
		r.add(Finding{Kind: FindUpdate, ExternalID: ev.ext, SourceDN: ev.dn, LocalID: u.ID, Attributes: changed, Applied: !r.dry})
	}
	if len(divergent) > 0 {
		reason := "local_authority"
		if !manages {
			reason = "shared_account"
		}
		r.add(Finding{Kind: FindDivergence, Reason: reason, ExternalID: ev.ext, LocalID: u.ID, Attributes: divergent})
	}
	newState := "active"
	if ev.disabled {
		newState = "disabled"
		if l.SourceState != "disabled" {
			if err := s.suspend(ctx, tx, r, c, u, "DIRECTORY_DISABLED"); err != nil {
				return err
			}
		}
	} else if l.SourceState == "disabled" || l.SourceState == "missing" {
		if err := s.reactivate(ctx, tx, r, c, u); err != nil {
			return err
		}
	}
	l.DN, l.SourceState = ev.dn, newState
	for attr, val := range ev.values {
		l.Snapshot[attr] = val
	}
	for attr := range l.Snapshot {
		if _, ok := ev.values[attr]; !ok {
			delete(l.Snapshot, attr)
		}
	}
	return s.saveLink(ctx, tx, c, l, r.id)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// setAttributes writes directory-owned values to an account. Identifier
// changes run in savepoints: a value another account holds is reported as a
// conflict and never taken from it.
func (s *Service) setAttributes(ctx context.Context, tx pgx.Tx, c *Connector, u *identity.User, set map[string]string) (applied, conflicts []string, err error) {
	view := viewOf(u)
	names := map[string]string{"display_name": view.displayName, "given_name": view.givenName, "family_name": view.familyName,
		"locale": view.locale, "zoneinfo": view.zoneinfo}
	profile := map[string]any{}
	for k, v := range view.profile {
		profile[k] = v
	}
	plain := false
	for attr, val := range set {
		switch attr {
		case "display_name", "given_name", "family_name", "locale", "zoneinfo":
			max := map[string]int{"display_name": 200, "given_name": 100, "family_name": 100, "locale": 35, "zoneinfo": 64}[attr]
			if attr == "zoneinfo" && val != "" {
				if _, err := time.LoadLocation(val); err != nil {
					conflicts = append(conflicts, attr)
					continue
				}
			}
			names[attr], plain = clip(val, max), true
			applied = append(applied, attr)
		case "username", "email":
			ok, err := s.setIdentifier(ctx, tx, c, u, attr, val)
			if err != nil {
				return nil, nil, err
			}
			if ok {
				applied = append(applied, attr)
			} else {
				conflicts = append(conflicts, attr)
			}
		default:
			if k, ok := strings.CutPrefix(attr, "profile."); ok {
				if val == "" {
					delete(profile, k)
				} else {
					profile[k] = clip(val, 1024)
				}
				plain = true
				applied = append(applied, attr)
			}
		}
	}
	if plain {
		prof, _ := json.Marshal(profile)
		if len(prof) > s.d.Cfg.Limits.MetadataBytes {
			return applied, append(conflicts, "profile"), nil
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET display_name=nullif($2,''), given_name=nullif($3,''), family_name=nullif($4,''), locale=nullif($5,''),
			zoneinfo=nullif($6,''), profile=$7, version=version+1, updated_at=$8 WHERE id=$1`, u.ID, names["display_name"], names["given_name"],
			names["family_name"], names["locale"], names["zoneinfo"], prof, s.d.Now()); err != nil {
			return nil, nil, err
		}
	}
	if len(applied) > 0 {
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "directory.user.updated", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Subject: &audit.Ref{Type: "user", ID: u.ID}, Category: "account", Metadata: map[string]any{"attributes": applied}}); err != nil {
			return nil, nil, err
		}
	}
	return applied, conflicts, nil
}

// setIdentifier replaces a username or email with the directory's value.
// The new email is verified only through a domain the connector's
// organization verified; a changed identifier is never marked verified
// otherwise (USR-004).
func (s *Service) setIdentifier(ctx context.Context, tx pgx.Tx, c *Connector, u *identity.User, typ, val string) (bool, error) {
	sp, err := tx.Begin(ctx)
	if err != nil {
		return false, err
	}
	fail := func(err error) (bool, error) {
		_ = sp.Rollback(ctx)
		if pe, ok := problem.As(err); ok && pe.Status < 500 {
			return false, nil
		}
		return false, err
	}
	var old *identity.Identifier
	for i := range u.Identifiers {
		id := u.Identifiers[i]
		if id.Type == typ && (typ == "username" || id.IsPrimary || old == nil) {
			old = &id
		}
	}
	switch typ {
	case "username":
		if _, err := s.Users.AddIdentifierTx(ctx, sp, c.RealmID, u.ID, "username", val, true); err != nil {
			return fail(err)
		}
	case "email":
		verified := s.domainVerified(ctx, c, val)
		if old != nil && !verified {
			if _, err := s.Users.RemoveIdentifierTx(ctx, sp, u.ID, old.ID); err != nil {
				return fail(err)
			}
		}
		ni, err := s.Users.AddIdentifierTx(ctx, sp, c.RealmID, u.ID, "email", val, false)
		if err != nil {
			return fail(err)
		}
		if verified {
			if err := s.Users.MarkIdentifierVerifiedTx(ctx, sp, c.RealmID, u.ID, "email", ni.Canonical, s.source(c)); err != nil {
				return fail(err)
			}
			if err := s.Users.PromoteIdentifierTx(ctx, sp, u.ID, ni.ID); err != nil {
				return fail(err)
			}
			if old != nil {
				if _, err := s.Users.RemoveIdentifierTx(ctx, sp, u.ID, old.ID); err != nil {
					return fail(err)
				}
			}
		}
	}
	if err := sp.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// ensureMembership gives an account without a live membership in the
// connector's organization one (with the connector's default role). An
// existing membership keeps its state.
func (s *Service) ensureMembership(ctx context.Context, tx pgx.Tx, c *Connector, userID string, active bool) error {
	if c.OrganizationID == "" {
		return nil
	}
	state := "active"
	if !active {
		state = "suspended"
	}
	var mid string
	err := tx.QueryRow(ctx, `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
		c.OrganizationID, userID).Scan(&mid)
	if storage.IsNoRows(err) {
		m, err := s.Orgs.CreateMembershipTx(ctx, tx, c.RealmID, c.OrganizationID, userID, "directory", c.ID, state)
		if err != nil {
			return err
		}
		if c.DefaultRoleID != "" {
			if _, err := s.Authz.AssignTx(ctx, tx, c.RealmID, nil, authorization.AssignInput{RoleID: c.DefaultRoleID,
				Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID},
				Scope:   authorization.Scope{Type: authorization.ScopeOrganization, ID: c.OrganizationID}, Source: "directory", SkipCeiling: true}, c.Ref()); err != nil {
				return err
			}
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.added", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "membership", ID: m.ID}, Metadata: map[string]any{"source": "directory"}}); err != nil {
			return err
		}
		_, err = s.d.Outbox.Publish(ctx, tx, events.Event{EventType: "organization.membership.added", RealmID: c.RealmID, OrgID: c.OrganizationID,
			AggregateType: "membership", AggregateID: m.ID, Data: map[string]any{"user_id": userID, "membership_id": m.ID, "source": "directory"}})
		return err
	}
	if err != nil {
		return err
	}
	// An existing membership keeps its state: adopting or linking an
	// account never lifts a suspension the directory did not make
	// (reactivate decides what the directory may undo).
	return nil
}

// suspend applies a directory disable: a realm directory suspends the
// account; an organization directory suspends only its organization's
// membership (PROV-005).
func (s *Service) suspend(ctx context.Context, tx pgx.Tx, r *runCtx, c *Connector, u *identity.User, reason string) error {
	f := Finding{Kind: FindSuspend, Reason: strings.ToLower(reason), LocalID: u.ID, Applied: !r.dry}
	if c.OrganizationID == "" {
		if u.State != identity.StateActive && u.State != identity.StateRecoveryRestricted {
			return nil
		}
		if _, err := s.Users.SetStateTx(ctx, tx, c.RealmID, u.ID, identity.StateSuspended, c.Ref(), reason); err != nil {
			return err
		}
		r.add(f)
		return nil
	}
	var mid string
	if tx.QueryRow(ctx, `SELECT id FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active'`, c.OrganizationID, u.ID).Scan(&mid) != nil {
		return nil
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if err := s.Orgs.SetMembershipStateTx(ctx, sp, c.RealmID, c.OrganizationID, mid, "suspended", nil, c.Ref()); err != nil {
		_ = sp.Rollback(ctx)
		if pe, ok := problem.As(err); ok && pe.Status < 500 {
			r.add(Finding{Kind: FindError, Reason: "membership_not_changed", LocalID: u.ID, Detail: map[string]any{"code": pe.Code}})
			return nil
		}
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return err
	}
	r.add(f)
	return nil
}

// reactivate undoes only what the directory did: an account (or
// membership) it suspended returns when the entry is enabled again. A
// suspension an administrator made for another reason stays.
func (s *Service) reactivate(ctx context.Context, tx pgx.Tx, r *runCtx, c *Connector, u *identity.User) error {
	f := Finding{Kind: FindReactivate, LocalID: u.ID, Applied: !r.dry}
	if c.OrganizationID == "" {
		if u.State != identity.StateSuspended {
			return nil
		}
		var reason string
		_ = tx.QueryRow(ctx, `SELECT coalesce(reason_code,'') FROM audit_events WHERE subject_id=$1 AND type='user.suspended' ORDER BY occurred_at DESC, seq DESC LIMIT 1`,
			u.ID).Scan(&reason)
		if reason != "DIRECTORY_DISABLED" && reason != "DIRECTORY_DEPROVISIONED" {
			r.add(Finding{Kind: FindDivergence, Reason: "suspended_locally", LocalID: u.ID, Attributes: []string{"state"}})
			return nil
		}
		if _, err := s.Users.SetStateTx(ctx, tx, c.RealmID, u.ID, identity.StateActive, c.Ref(), "DIRECTORY_ENABLED"); err != nil {
			return err
		}
		r.add(f)
		return nil
	}
	// An organization connector likewise undoes only its own suspension or
	// removal of the membership. The audit event written with every
	// membership state change names who made it; a membership an
	// administrator (or anyone else) suspended or removed last stays as it
	// is and is reported as divergence.
	var mid, mstate string
	err := tx.QueryRow(ctx, `SELECT id, state FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
		c.OrganizationID, u.ID).Scan(&mid, &mstate)
	switch {
	case storage.IsNoRows(err):
		found, ours, err := s.membershipChangedBy(ctx, tx, c, u.ID, "", "organization.membership.removed")
		if err != nil {
			return err
		}
		if found && !ours {
			r.add(Finding{Kind: FindDivergence, Reason: "removed_locally", LocalID: u.ID, Attributes: []string{"state"}})
			return nil
		}
	case err != nil:
		return err
	case mstate != "suspended":
		// Active, or invited / pending approval: nothing the directory did.
		return nil
	default:
		_, ours, err := s.membershipChangedBy(ctx, tx, c, u.ID, mid, "organization.membership.suspended")
		if err != nil {
			return err
		}
		if !ours {
			r.add(Finding{Kind: FindDivergence, Reason: "suspended_locally", LocalID: u.ID, Attributes: []string{"state"}})
			return nil
		}
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return err
	}
	if mid == "" {
		err = s.ensureMembership(ctx, sp, c, u.ID, true)
	} else {
		err = s.Orgs.SetMembershipStateTx(ctx, sp, c.RealmID, c.OrganizationID, mid, "active", nil, c.Ref())
	}
	if err != nil {
		_ = sp.Rollback(ctx)
		if pe, ok := problem.As(err); ok && pe.Status < 500 {
			r.add(Finding{Kind: FindError, Reason: "membership_not_changed", LocalID: u.ID})
			return nil
		}
		return err
	}
	if err := sp.Commit(ctx); err != nil {
		return err
	}
	r.add(f)
	return nil
}

// membershipChangedBy reads the newest audit event of type typ about the
// user's membership in the connector's organization (only membershipID's,
// when set): found reports one exists, ours that this connector made it.
// Membership state changes are audited in the transaction that makes them,
// so the newest such event names who made the current state.
func (s *Service) membershipChangedBy(ctx context.Context, q storage.Querier, c *Connector, userID, membershipID, typ string) (found, ours bool, err error) {
	var actorType, actorID string
	err = q.QueryRow(ctx, `SELECT actor_type, actor_id FROM audit_events WHERE subject_id=$1 AND organization_id=$2 AND type=$3
		AND ($4='' OR target_id=$4) ORDER BY seq DESC LIMIT 1`, userID, c.OrganizationID, typ, membershipID).Scan(&actorType, &actorID)
	if storage.IsNoRows(err) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	return true, actorType == "connector" && actorID == c.ID, nil
}
