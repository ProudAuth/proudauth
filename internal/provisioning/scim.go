package provisioning

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// SCIM schema URNs.
const (
	SchemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaList  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaError = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaPatch = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// Error is a SCIM error (RFC 7644 §3.12).
type Error struct {
	Status   int
	ScimType string
	Detail   string
}

func (e *Error) Error() string { return e.Detail }

// Body renders the error document.
func (e *Error) Body() map[string]any {
	b := map[string]any{"schemas": []string{SchemaError}, "status": strconv.Itoa(e.Status), "detail": e.Detail}
	if e.ScimType != "" {
		b["scimType"] = e.ScimType
	}
	return b
}

func scimErr(status int, typ, detail string) *Error {
	return &Error{Status: status, ScimType: typ, Detail: detail}
}

var (
	errNotFound     = scimErr(404, "", "resource not found")
	errPrecondition = scimErr(412, "", "the resource version does not match If-Match")
)

// userState is what a connector manages for one account.
type userState struct {
	ExternalID  string
	UserName    string
	GivenName   string
	FamilyName  string
	DisplayName string
	Email       string
	Active      bool
}

func str(m map[string]any, k string) string {
	for key, v := range m {
		if strings.EqualFold(key, k) {
			s, _ := v.(string)
			return s
		}
	}
	return ""
}

func get(m map[string]any, k string) (any, bool) {
	for key, v := range m {
		if strings.EqualFold(key, k) {
			return v, true
		}
	}
	return nil, false
}

// boolOf accepts SCIM booleans and the "True"/"False" strings some
// providers send.
func boolOf(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(strings.ToLower(x))
		return b, err == nil
	}
	return false, false
}

// stateFrom reads a User document into a state, starting from base.
func stateFrom(doc map[string]any, base userState) (userState, *Error) {
	st := base
	if v, ok := get(doc, "externalId"); ok {
		st.ExternalID, _ = v.(string)
	}
	if v, ok := get(doc, "userName"); ok {
		st.UserName, _ = v.(string)
	}
	if v, ok := get(doc, "displayName"); ok {
		st.DisplayName, _ = v.(string)
	}
	if v, ok := get(doc, "name"); ok {
		if n, ok := v.(map[string]any); ok {
			if _, ok := get(n, "givenName"); ok {
				st.GivenName = str(n, "givenName")
			}
			if _, ok := get(n, "familyName"); ok {
				st.FamilyName = str(n, "familyName")
			}
		}
	}
	if v, ok := get(doc, "emails"); ok {
		st.Email = primaryEmail(v)
	}
	if v, ok := get(doc, "active"); ok {
		b, ok := boolOf(v)
		if !ok {
			return st, scimErr(400, "invalidValue", "active must be a boolean")
		}
		st.Active = b
	}
	if len(st.UserName) > 256 || len(st.DisplayName) > 200 || len(st.GivenName) > 100 || len(st.FamilyName) > 100 || len(st.ExternalID) > 256 {
		return st, scimErr(400, "invalidValue", "an attribute is too long")
	}
	return st, nil
}

func primaryEmail(v any) string {
	first := ""
	for _, el := range asList(v) {
		m, ok := el.(map[string]any)
		if !ok {
			continue
		}
		val := str(m, "value")
		if first == "" {
			first = val
		}
		if p, _ := boolOf(m["primary"]); p {
			return val
		}
	}
	return first
}

// managedUser is a connector's view of one account.
type managedUser struct {
	user       *identity.User
	external   string
	version    int64
	membership string
	memberOn   bool
	created    time.Time
	updated    time.Time
}

const userMapping = `SELECT x.external_id, x.local_id, x.resource_version, x.created_at, x.updated_at FROM connector_external_ids x
	WHERE x.connector_id=$1 AND x.resource_type='User'`

func (s *Service) loadUser(ctx context.Context, q storage.Querier, c *Connector, id string) (*managedUser, error) {
	var mu managedUser
	var local string
	err := q.QueryRow(ctx, userMapping+` AND x.local_id=$2`, c.ID, id).Scan(&mu.external, &local, &mu.version, &mu.created, &mu.updated)
	if storage.IsNoRows(err) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	u, err := s.Users.User(ctx, q, c.RealmID, local)
	if err != nil {
		if errors.Is(err, problem.ErrNotFound) {
			return nil, errNotFound
		}
		return nil, err
	}
	if u.State == identity.StateDeleted {
		return nil, errNotFound
	}
	mu.user = u
	var state string
	if err := q.QueryRow(ctx, `SELECT id, state FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
		c.OrganizationID, local).Scan(&mu.membership, &state); err != nil && !storage.IsNoRows(err) {
		return nil, err
	}
	mu.memberOn = state == "active"
	// The entity tag reflects the resource itself, so changes made through
	// the administration API invalidate it too (PROV-008).
	mu.version = contentVersion(mu.version, s.userResource(&mu, ""))
	return &mu, nil
}

// contentVersion derives a resource version from its content (meta
// excluded) and the connector's own write counter.
func contentVersion(writes int64, resource map[string]any) int64 {
	body := make(map[string]any, len(resource))
	for k, v := range resource {
		if k != "meta" {
			body[k] = v
		}
	}
	b, _ := json.Marshal(body)
	sum := sha256.Sum256(append(b, []byte(strconv.FormatInt(writes, 10))...))
	return int64(binary.BigEndian.Uint64(sum[:8]) >> 1)
}

func (s *Service) userResource(mu *managedUser, base string) map[string]any {
	u := mu.user
	userName := ""
	email := ""
	for _, i := range u.Identifiers {
		switch {
		case i.Type == "username":
			userName = i.Value
		case i.Type == "email" && (i.IsPrimary || email == ""):
			email = i.Value
		}
	}
	if userName == "" {
		userName = email
	}
	r := map[string]any{
		"schemas":     []string{SchemaUser},
		"id":          u.ID,
		"userName":    userName,
		"displayName": u.DisplayName,
		"name":        map[string]any{"givenName": u.GivenName, "familyName": u.FamilyName},
		"active":      mu.memberOn,
		"meta": map[string]any{"resourceType": "User", "created": mu.created.UTC().Format(time.RFC3339), "lastModified": mu.updated.UTC().Format(time.RFC3339),
			"version": etag(mu.version), "location": base + "/Users/" + u.ID},
	}
	if !strings.HasPrefix(mu.external, "~") {
		r["externalId"] = mu.external
	}
	if email != "" {
		r["emails"] = []map[string]any{{"value": email, "primary": true, "type": "work"}}
	}
	return r
}

func etag(v int64) string { return `W/"` + strconv.FormatInt(v, 10) + `"` }

// matchVersion checks If-Match (PROV-008); "" and "*" match anything.
func matchVersion(ifMatch string, v int64) bool {
	if ifMatch == "" || ifMatch == "*" {
		return true
	}
	for _, t := range strings.Split(ifMatch, ",") {
		if strings.TrimSpace(t) == etag(v) || strings.Trim(strings.TrimPrefix(strings.TrimSpace(t), "W/"), `"`) == strconv.FormatInt(v, 10) {
			return true
		}
	}
	return false
}

// accountLocked reports accounts a connector may never change (PROV-006):
// protected accounts and holders of privileged realm roles.
func (s *Service) accountLocked(ctx context.Context, q storage.Querier, c *Connector, u *identity.User) bool {
	if u.Protected {
		return true
	}
	priv, err := s.Authz.HoldsPrivilegedRealmRole(ctx, q, c.RealmID, u.ID)
	return err != nil || priv
}

// ownsIdentity reports whether the connector may change the account's
// realm-wide identity attributes: it created the account and the account
// belongs to no other organization.
func (s *Service) ownsIdentity(ctx context.Context, q storage.Querier, c *Connector, u *identity.User) bool {
	if u.CreatedVia != "scim:"+c.ID {
		return false
	}
	var others int
	_ = q.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE user_id=$1 AND organization_id<>$2 AND state NOT IN ('removed','expired')`,
		u.ID, c.OrganizationID).Scan(&others)
	return others == 0
}

func (s *Service) domainVerified(ctx context.Context, c *Connector, email string) bool {
	_, at, ok := strings.Cut(strings.ToLower(email), "@")
	if !ok {
		return false
	}
	ok, err := s.Orgs.DomainCovered(ctx, c.RealmID, c.OrganizationID, at)
	return err == nil && ok
}

// CreateUser provisions an account in the connector's organization
// (PROV-001, PROV-004). A new account gets its email verified only when the
// domain is verified for the organization. An existing account is adopted
// only when its verified email belongs to such a domain, it is not protected
// and the connector does not manage it yet; otherwise the identifier is a
// uniqueness conflict, never a takeover.
func (s *Service) CreateUser(ctx context.Context, c *Connector, doc map[string]any, base string) (map[string]any, int64, error) {
	st, serr := stateFrom(doc, userState{Active: true})
	if serr != nil {
		return nil, 0, serr
	}
	if st.UserName == "" {
		return nil, 0, scimErr(400, "invalidValue", "userName is required")
	}
	email := st.Email
	if email == "" && strings.Contains(st.UserName, "@") {
		email = st.UserName
	}
	var id string
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if st.ExternalID != "" {
			var exists bool
			_ = tx.QueryRow(ctx, `SELECT true FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND external_id=$2`,
				c.ID, st.ExternalID).Scan(&exists)
			if exists {
				return scimErr(409, "uniqueness", "externalId already provisioned by this connector")
			}
		}
		var existing *identity.User
		if email != "" {
			canon, _, err := canonical.Email(email)
			if err != nil {
				return scimErr(400, "invalidValue", "invalid email")
			}
			var uid string
			if tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='email' AND canonical_value=$2`, c.RealmID, canon).Scan(&uid) == nil {
				existing, _ = s.Users.User(ctx, tx, c.RealmID, uid)
			}
		}
		if existing == nil && !strings.Contains(st.UserName, "@") {
			if canon, err := canonical.Username(st.UserName); err == nil {
				var uid string
				if tx.QueryRow(ctx, `SELECT user_id FROM user_identifiers WHERE realm_id=$1 AND type='username' AND canonical_value=$2`, c.RealmID, canon).Scan(&uid) == nil {
					return scimErr(409, "uniqueness", "userName is in use by an account this connector does not manage")
				}
			}
		}
		if existing != nil {
			var mapped bool
			_ = tx.QueryRow(ctx, `SELECT true FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=$2`, c.ID, existing.ID).Scan(&mapped)
			verified := false
			for _, i := range existing.Identifiers {
				if i.Type == "email" && strings.EqualFold(i.Value, email) && i.Verified() {
					verified = true
				}
			}
			if mapped || !verified || !s.domainVerified(ctx, c, email) || s.accountLocked(ctx, tx, c, existing) {
				return scimErr(409, "uniqueness", "an account with this email exists; it can be provisioned only through a domain the organization verified")
			}
			id = existing.ID
		} else {
			verifiedEmail := email != "" && s.domainVerified(ctx, c, email)
			in := identity.CreateInput{Email: email, EmailVerified: verifiedEmail, VerificationSource: "scim:" + c.ID, DisplayName: st.DisplayName,
				GivenName: st.GivenName, FamilyName: st.FamilyName, State: identity.StateActive, CreatedVia: "scim:" + c.ID}
			if !strings.Contains(st.UserName, "@") {
				if _, err := canonical.Username(st.UserName); err == nil {
					in.Username = st.UserName
				}
			}
			if email != "" && !verifiedEmail {
				in.RequiredActions = []string{identity.ActionVerifyEmail}
			}
			u, err := s.Users.CreateTx(ctx, tx, c.RealmID, in)
			if err != nil {
				return err
			}
			id = u.ID
		}
		if err := s.ensureMembership(ctx, tx, c, id, st.Active); err != nil {
			return err
		}
		ext := st.ExternalID
		if ext == "" {
			ext = "~" + id
		}
		if _, err := tx.Exec(ctx, `INSERT INTO connector_external_ids (connector_id, resource_type, external_id, local_id) VALUES ($1,'User',$2,$3)`,
			c.ID, ext, id); err != nil {
			if storage.IsUniqueViolation(err) {
				return scimErr(409, "uniqueness", "the account is already provisioned by this connector")
			}
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "scim.user.provisioned", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Subject: &audit.Ref{Type: "user", ID: id}, Category: "account", Metadata: map[string]any{"adopted": existing != nil, "active": st.Active}})
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	mu, err := s.loadUser(ctx, s.d.DB.Pool, c, id)
	if err != nil {
		return nil, 0, err
	}
	return s.userResource(mu, base), mu.version, nil
}

// ensureMembership gives the account a membership in the connector's
// organization (with the connector's default role) or sets its state.
func (s *Service) ensureMembership(ctx context.Context, tx pgx.Tx, c *Connector, userID string, active bool) error {
	state := "active"
	if !active {
		state = "suspended"
	}
	var mid, cur string
	err := tx.QueryRow(ctx, `SELECT id, state FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired')`,
		c.OrganizationID, userID).Scan(&mid, &cur)
	if storage.IsNoRows(err) {
		createState := state
		if !active && c.DefaultRoleID != "" {
			// AssignTx requires an active membership (AZ-003). Create, grant
			// and suspend inside this same transaction: no active membership
			// is visible outside it for an initially inactive SCIM account.
			createState = "active"
		}
		m, err := s.Orgs.CreateMembershipTx(ctx, tx, c.RealmID, c.OrganizationID, userID, "scim", c.ID, createState)
		if err != nil {
			return err
		}
		if c.DefaultRoleID != "" {
			if _, err := s.Authz.AssignTx(ctx, tx, c.RealmID, nil, authorization.AssignInput{RoleID: c.DefaultRoleID,
				Subject: authorization.Subject{Type: authorization.SubjectUser, ID: userID},
				Scope:   authorization.Scope{Type: authorization.ScopeOrganization, ID: c.OrganizationID}, Source: "scim", SkipCeiling: true}, c.Ref()); err != nil {
				return err
			}
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "organization.membership.added", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Subject: &audit.Ref{Type: "user", ID: userID}, Target: &audit.Ref{Type: "membership", ID: m.ID}, Metadata: map[string]any{"source": "scim"}})
		if err != nil {
			return err
		}
		if createState != state {
			return s.Orgs.SetMembershipStateTx(ctx, tx, c.RealmID, c.OrganizationID, m.ID, state, nil, c.Ref())
		}
		return nil
	}
	if err != nil {
		return err
	}
	if cur == state || (cur != "active" && cur != "suspended") {
		return nil
	}
	return s.Orgs.SetMembershipStateTx(ctx, tx, c.RealmID, c.OrganizationID, mid, state, nil, c.Ref())
}

// GetUser returns one account the connector manages.
func (s *Service) GetUser(ctx context.Context, c *Connector, id, base string) (map[string]any, int64, error) {
	mu, err := s.loadUser(ctx, s.d.DB.Pool, c, id)
	if err != nil {
		return nil, 0, err
	}
	return s.userResource(mu, base), mu.version, nil
}

// maxScan bounds how many managed resources one list request examines.
const maxScan = 20000

// candidates returns the local IDs a list request examines: an eq filter on
// id, externalId, userName or displayName is answered from indexes, any
// other filter scans at most maxScan managed resources (PROV-002).
func (s *Service) candidates(ctx context.Context, c *Connector, resourceType string, f Filter) ([]string, error) {
	query := `SELECT local_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type=$2 ORDER BY local_id LIMIT $3`
	args := []any{c.ID, resourceType, maxScan + 1}
	if cmp, ok := f.(compare); ok && cmp.op == "eq" {
		if v, isStr := cmp.value.(string); isStr {
			switch attr := strings.ToLower(unqualify(cmp.attr)); {
			case attr == "id":
				query, args = `SELECT local_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type=$2 AND local_id=$3`, []any{c.ID, resourceType, v}
			case attr == "externalid":
				query, args = `SELECT local_id FROM connector_external_ids WHERE connector_id=$1 AND resource_type=$2 AND external_id=$3`, []any{c.ID, resourceType, v}
			case attr == "username" && resourceType == "User":
				query, args = `SELECT DISTINCT x.local_id FROM connector_external_ids x JOIN user_identifiers ui ON ui.user_id=x.local_id
					WHERE x.connector_id=$1 AND x.resource_type=$2 AND ui.type IN ('username','email') AND (ui.canonical_value=lower($3) OR lower(ui.original_value)=lower($3))`, []any{c.ID, resourceType, v}
			case attr == "displayname" && resourceType == "Group":
				query, args = `SELECT x.local_id FROM connector_external_ids x JOIN groups g ON g.id=x.local_id
					WHERE x.connector_id=$1 AND x.resource_type=$2 AND lower(g.name)=lower($3)`, []any{c.ID, resourceType, v}
			}
		}
	}
	rows, err := s.d.DB.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if len(out) > maxScan {
		return nil, scimErr(400, "tooMany", "the connector manages more resources than one list request examines; filter with eq on id, externalId, userName or displayName")
	}
	return out, rows.Err()
}

// ListUsers filters and pages the accounts the connector manages (PROV-002).
func (s *Service) ListUsers(ctx context.Context, c *Connector, f Filter, startIndex, count int, base string) ([]map[string]any, int, error) {
	idsList, err := s.candidates(ctx, c, "User", f)
	if err != nil {
		return nil, 0, err
	}
	users, err := s.loadUsers(ctx, c, idsList)
	if err != nil {
		return nil, 0, err
	}
	if startIndex < 1 {
		startIndex = 1
	}
	if count < 0 {
		count = 0
	}
	matched := []map[string]any{}
	total := 0
	for _, id := range idsList {
		mu := users[id]
		if mu == nil {
			continue
		}
		r := s.userResource(mu, base)
		if f == nil || f.Match(r) {
			total++
			if total >= startIndex && len(matched) < count {
				matched = append(matched, r)
			}
		}
	}
	return matched, total, nil
}

// ReplaceUser applies a full User document (PUT).
func (s *Service) ReplaceUser(ctx context.Context, c *Connector, id string, doc map[string]any, ifMatch, base string) (map[string]any, int64, error) {
	return s.updateUser(ctx, c, id, ifMatch, base, func(cur userState) (userState, *Error) {
		st, err := stateFrom(doc, userState{Active: true})
		if err != nil {
			return st, err
		}
		if st.UserName == "" {
			return st, scimErr(400, "invalidValue", "userName is required")
		}
		if _, ok := get(doc, "externalId"); !ok {
			st.ExternalID = cur.ExternalID
		}
		return st, nil
	})
}

// PatchUser applies PatchOp operations (RFC 7644 §3.5.2).
func (s *Service) PatchUser(ctx context.Context, c *Connector, id string, ops []any, ifMatch, base string) (map[string]any, int64, error) {
	return s.updateUser(ctx, c, id, ifMatch, base, func(cur userState) (userState, *Error) {
		return applyUserPatch(cur, ops)
	})
}

func (s *Service) currentState(mu *managedUser) userState {
	st := userState{GivenName: mu.user.GivenName, FamilyName: mu.user.FamilyName, DisplayName: mu.user.DisplayName, Active: mu.memberOn}
	if !strings.HasPrefix(mu.external, "~") {
		st.ExternalID = mu.external
	}
	for _, i := range mu.user.Identifiers {
		switch {
		case i.Type == "username":
			st.UserName = i.Value
		case i.Type == "email" && i.IsPrimary:
			st.Email = i.Value
		}
	}
	if st.UserName == "" {
		st.UserName = st.Email
	}
	return st
}

func (s *Service) updateUser(ctx context.Context, c *Connector, id, ifMatch, base string, next func(userState) (userState, *Error)) (map[string]any, int64, error) {
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=$2 FOR UPDATE`, c.ID, id); err != nil {
			return err
		}
		if err := s.lockUserResource(ctx, tx, c, id); err != nil {
			return err
		}
		mu, err := s.loadUser(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if !matchVersion(ifMatch, mu.version) {
			return errPrecondition
		}
		if s.accountLocked(ctx, tx, c, mu.user) {
			return scimErr(403, "", "the account is protected; a connector cannot change it (PROV-006)")
		}
		cur := s.currentState(mu)
		st, serr := next(cur)
		if serr != nil {
			return serr
		}
		identityChanged := !strings.EqualFold(st.UserName, cur.UserName) || !strings.EqualFold(st.Email, cur.Email) || st.GivenName != cur.GivenName ||
			st.FamilyName != cur.FamilyName || st.DisplayName != cur.DisplayName
		if identityChanged && !s.ownsIdentity(ctx, tx, c, mu.user) {
			return scimErr(400, "mutability", "the account's identity attributes are managed outside this organization; only its membership state can change")
		}
		if identityChanged {
			if err := s.applyIdentity(ctx, tx, c, mu.user, cur, st); err != nil {
				return err
			}
		}
		if st.Active != cur.Active {
			if err := s.ensureMembership(ctx, tx, c, id, st.Active); err != nil {
				return err
			}
		}
		ext := st.ExternalID
		if ext == "" {
			ext = "~" + id
		}
		if _, err := tx.Exec(ctx, `UPDATE connector_external_ids SET external_id=$3, resource_version=resource_version+1, updated_at=$4
			WHERE connector_id=$1 AND resource_type='User' AND local_id=$2`, c.ID, id, ext, s.d.Now()); err != nil {
			if storage.IsUniqueViolation(err) {
				return scimErr(409, "uniqueness", "externalId already provisioned by this connector")
			}
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "scim.user.updated", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Subject: &audit.Ref{Type: "user", ID: id}, Category: "account", Metadata: map[string]any{"identity_changed": identityChanged, "active": st.Active}})
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return s.GetUser(ctx, c, id, base)
}

// lockUserResource locks the rows a User resource's entity tag is computed
// from, the account and its membership in the connector's organization,
// before the tag is compared (TEST-050, PROV-008). The administration API
// locks the same account row (identity.LockUser) and membership row, so a
// competing administrator change either commits first, and the If-Match
// comparison sees it (412), or waits until this write commits and is
// applied on top of it; at READ COMMITTED an unlocked read would let the
// write below overwrite it with the values read before it committed.
func (s *Service) lockUserResource(ctx context.Context, tx pgx.Tx, c *Connector, id string) error {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 FOR UPDATE`, c.RealmID, id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT 1 FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state NOT IN ('removed','expired') FOR UPDATE`,
		c.OrganizationID, id)
	return err
}

// applyIdentity changes the realm-wide attributes of an account the
// connector owns.
func (s *Service) applyIdentity(ctx context.Context, tx pgx.Tx, c *Connector, u *identity.User, cur, st userState) error {
	if _, err := tx.Exec(ctx, `UPDATE users SET given_name=nullif($2,''), family_name=nullif($3,''), display_name=nullif($4,''), version=version+1,
		updated_at=$5 WHERE id=$1`, u.ID, st.GivenName, st.FamilyName, st.DisplayName, s.d.Now()); err != nil {
		return err
	}
	if !strings.EqualFold(st.Email, cur.Email) && st.Email != "" {
		var oldID string
		for _, i := range u.Identifiers {
			if i.Type == "email" && strings.EqualFold(i.Value, cur.Email) {
				oldID = i.ID
			}
		}
		ni, err := s.Users.AddIdentifierTx(ctx, tx, c.RealmID, u.ID, "email", st.Email, false)
		if err != nil {
			return err
		}
		if s.domainVerified(ctx, c, st.Email) {
			if err := s.Users.MarkIdentifierVerifiedTx(ctx, tx, c.RealmID, u.ID, "email", ni.Canonical, "scim:"+c.ID); err != nil {
				return err
			}
		}
		if err := s.Users.PromoteIdentifierTx(ctx, tx, u.ID, ni.ID); err != nil {
			return err
		}
		if oldID != "" {
			if _, err := s.Users.RemoveIdentifierTx(ctx, tx, u.ID, oldID); err != nil {
				return err
			}
		}
	}
	if !strings.EqualFold(st.UserName, cur.UserName) && !strings.Contains(st.UserName, "@") {
		if _, err := canonical.Username(st.UserName); err == nil {
			if _, err := s.Users.AddIdentifierTx(ctx, tx, c.RealmID, u.ID, "username", st.UserName, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// DeleteUser deprovisions an account from the connector's organization
// (PROV-005): the membership is removed and the connector stops managing the
// account; the realm-wide account and its other memberships stay.
func (s *Service) DeleteUser(ctx context.Context, c *Connector, id, ifMatch string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		// The mapping row is locked like an update locks it, so the If-Match
		// check and the deletion see the same version (PROV-008).
		if _, err := tx.Exec(ctx, `SELECT 1 FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=$2 FOR UPDATE`, c.ID, id); err != nil {
			return err
		}
		if err := s.lockUserResource(ctx, tx, c, id); err != nil {
			return err
		}
		mu, err := s.loadUser(ctx, tx, c, id)
		if err != nil {
			return err
		}
		if !matchVersion(ifMatch, mu.version) {
			return errPrecondition
		}
		if s.accountLocked(ctx, tx, c, mu.user) {
			return scimErr(403, "", "the account is protected; a connector cannot change it (PROV-006)")
		}
		if mu.membership != "" {
			if err := s.Orgs.RemoveMemberTx(ctx, tx, c.RealmID, c.OrganizationID, mu.membership, nil, c.Ref(), "scim_deprovisioned"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM connector_external_ids WHERE connector_id=$1 AND resource_type='User' AND local_id=$2`, c.ID, id); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "scim.user.deprovisioned", RealmID: c.RealmID, OrgID: c.OrganizationID, Actor: c.Ref(),
			Subject: &audit.Ref{Type: "user", ID: id}, Category: "account"})
		return err
	})
}

// applyUserPatch applies add/replace/remove operations to a user state.
// Providers differ: Azure AD sends {"op":"Replace","path":"active","value":"False"},
// Okta sends {"op":"replace","value":{"active":false}}; both are accepted.
func applyUserPatch(cur userState, ops []any) (userState, *Error) {
	st := cur
	if len(ops) == 0 || len(ops) > 100 {
		return st, scimErr(400, "invalidValue", "1 to 100 operations")
	}
	for _, raw := range ops {
		op, ok := raw.(map[string]any)
		if !ok {
			return st, scimErr(400, "invalidSyntax", "operations must be objects")
		}
		kind := strings.ToLower(str(op, "op"))
		path := str(op, "path")
		value, _ := get(op, "value")
		switch kind {
		case "add", "replace":
			if path == "" {
				doc, ok := value.(map[string]any)
				if !ok {
					return st, scimErr(400, "invalidValue", "a patch without path needs an object value")
				}
				var err *Error
				if st, err = stateFrom(doc, st); err != nil {
					return st, err
				}
				continue
			}
			var err *Error
			if st, err = setPath(st, path, value); err != nil {
				return st, err
			}
		case "remove":
			if path == "" {
				return st, scimErr(400, "noTarget", "remove needs a path")
			}
			var err *Error
			if st, err = setPath(st, path, nil); err != nil {
				return st, err
			}
		default:
			return st, scimErr(400, "invalidSyntax", "op must be add, replace or remove")
		}
	}
	return st, nil
}

func setPath(st userState, path string, value any) (userState, *Error) {
	p := strings.ToLower(strings.TrimPrefix(path, SchemaUser+":"))
	s, _ := value.(string)
	switch {
	case p == "active":
		if value == nil {
			return st, scimErr(400, "mutability", "active cannot be removed")
		}
		b, ok := boolOf(value)
		if !ok {
			return st, scimErr(400, "invalidValue", "active must be a boolean")
		}
		st.Active = b
	case p == "username":
		st.UserName = s
	case p == "displayname":
		st.DisplayName = s
	case p == "externalid":
		st.ExternalID = s
	case p == "name.givenname":
		st.GivenName = s
	case p == "name.familyname":
		st.FamilyName = s
	case p == "name":
		if m, ok := value.(map[string]any); ok {
			st.GivenName, st.FamilyName = str(m, "givenName"), str(m, "familyName")
		} else if value == nil {
			st.GivenName, st.FamilyName = "", ""
		}
	case p == "emails" || strings.HasPrefix(p, "emails["):
		switch v := value.(type) {
		case nil:
			st.Email = ""
		case string:
			st.Email = v
		default:
			st.Email = primaryEmail(v)
		}
	default:
		// Attributes this server does not store (phoneNumbers, title, the
		// enterprise extension) are accepted and ignored, as advertised in
		// the schema.
	}
	return st, nil
}
