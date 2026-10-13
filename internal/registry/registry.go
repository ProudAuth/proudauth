// Package registry is the container-registry token bridge (ADV-010): it
// issues Distribution token-authentication tokens whose access list holds
// only the repository actions the authenticated principal's permissions
// allow. A registry service is tied to an API resource, so personal access
// tokens and API keys are minted for it like for any resource, and their
// scopes (pull, push, delete) cap the actions; tokens carry the registry's
// own service name as audience.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/application"
	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/runtime"
	"github.com/proudbase/proudauth/internal/storage"
	"github.com/proudbase/proudauth/internal/token"
)

// Actions a rule can map.
var Actions = []string{"pull", "push", "delete"}

// Rule maps repositories to the permission each action requires. Repository
// is a path.Match pattern ("acme/*" matches acme/app, not acme/team/app).
// OrganizationID, when set, evaluates the permissions in that organization
// and admits only credentials bound to it or to none. AnonymousPull lets
// anyone pull, signed in or not.
type Rule struct {
	Repository     string `json:"repository"`
	OrganizationID string `json:"organization_id,omitempty"`
	Pull           string `json:"pull,omitempty"`
	Push           string `json:"push,omitempty"`
	Delete         string `json:"delete,omitempty"`
	AnonymousPull  bool   `json:"anonymous_pull,omitempty"`
}

func (r Rule) permission(action string) string {
	switch action {
	case "pull":
		return r.Pull
	case "push":
		return r.Push
	case "delete":
		return r.Delete
	}
	return ""
}

// Service is a configured registry.
type Service struct {
	ID              string    `json:"id"`
	Service         string    `json:"service"`
	ResourceID      string    `json:"resource_id"`
	TokenTTLSeconds int       `json:"token_ttl_seconds"`
	Rules           []Rule    `json:"rules"`
	State           string    `json:"state"`
	Version         int64     `json:"version"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Input creates or replaces a registry service. Service is the
// registry's service name (the token audience); Audience names the API
// resource credentials are minted for.
type Input struct {
	Service         string `json:"service"`
	Audience        string `json:"audience"`
	TokenTTLSeconds int    `json:"token_ttl_seconds"`
	Rules           []Rule `json:"rules"`
	State           string `json:"state"`
}

// Bridge issues registry tokens.
type Bridge struct {
	d      *runtime.Deps
	Apps   *application.Service
	Authz  *authorization.Service
	Signer *token.Signer
}

// New returns the bridge.
func New(d *runtime.Deps) *Bridge { return &Bridge{d: d} }

const cols = `id, service, resource_id, token_ttl_seconds, rules, state, version, created_at, updated_at`

func scan(row pgx.Row) (*Service, error) {
	var s Service
	var rules []byte
	if err := row.Scan(&s.ID, &s.Service, &s.ResourceID, &s.TokenTTLSeconds, &rules, &s.State, &s.Version, &s.CreatedAt, &s.UpdatedAt); err != nil {
		if storage.IsNoRows(err) {
			return nil, problem.ErrNotFound
		}
		return nil, err
	}
	_ = json.Unmarshal(rules, &s.Rules)
	return &s, nil
}

func (b *Bridge) validate(ctx context.Context, q storage.Querier, realmID string, in *Input) (*application.Resource, error) {
	if in.Service == "" || len(in.Service) > 255 || strings.ContainsAny(in.Service, " /\t\r\n") {
		return nil, problem.ErrValidation.WithField("service", "the registry's service name, such as registry.example.com")
	}
	res, err := b.Apps.ResourceByAudience(ctx, q, realmID, in.Audience)
	if err != nil {
		return nil, problem.ErrValidation.WithField("audience", "the audience of an API resource of this realm")
	}
	if in.TokenTTLSeconds == 0 {
		in.TokenTTLSeconds = 300
	}
	if in.TokenTTLSeconds < 60 || in.TokenTTLSeconds > 3600 {
		return nil, problem.ErrValidation.WithField("token_ttl_seconds", "60 to 3600")
	}
	if in.State == "" {
		in.State = "active"
	}
	if in.State != "active" && in.State != "disabled" {
		return nil, problem.ErrValidation.WithField("state", "active or disabled")
	}
	if len(in.Rules) == 0 || len(in.Rules) > 200 {
		return nil, problem.ErrValidation.WithField("rules", "1 to 200 rules")
	}
	for i, r := range in.Rules {
		field := func(n string) string { return fmt.Sprintf("rules[%d].%s", i, n) }
		if r.Repository == "" || len(r.Repository) > 255 || strings.ContainsAny(r.Repository, " :") {
			return nil, problem.ErrValidation.WithField(field("repository"), "a repository name or path.Match pattern")
		}
		if _, err := path.Match(r.Repository, ""); err != nil {
			return nil, problem.ErrValidation.WithField(field("repository"), "a valid pattern")
		}
		if r.Pull == "" && r.Push == "" && r.Delete == "" && !r.AnonymousPull {
			return nil, problem.ErrValidation.WithField(field("pull"), "map at least one action to a permission")
		}
		for _, a := range Actions {
			if p := r.permission(a); p != "" {
				var n int
				if err := q.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE realm_id=$1 AND name=$2`, realmID, p).Scan(&n); err != nil {
					return nil, err
				}
				if n == 0 {
					return nil, problem.ErrValidation.WithField(field(a), "a permission registered in this realm")
				}
			}
		}
		if r.OrganizationID != "" {
			var n int
			if err := q.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, r.OrganizationID).Scan(&n); err != nil {
				return nil, err
			}
			if n == 0 {
				return nil, problem.ErrValidation.WithField(field("organization_id"), "an organization of this realm")
			}
		}
	}
	return res, nil
}

// Create configures a registry service.
func (b *Bridge) Create(ctx context.Context, realmID string, in Input, actor audit.Ref) (*Service, error) {
	id := ids.New("rgs")
	err := b.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		res, err := b.validate(ctx, tx, realmID, &in)
		if err != nil {
			return err
		}
		rules, _ := json.Marshal(in.Rules)
		now := b.d.Now()
		if _, err := tx.Exec(ctx, `INSERT INTO registry_services (id, realm_id, resource_id, service, token_ttl_seconds, rules, state, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8)`, id, realmID, res.ID, in.Service, in.TokenTTLSeconds, rules, in.State, now); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithDetail("this registry service is already configured")
			}
			return err
		}
		_, err = b.d.Audit.Record(ctx, tx, audit.Event{Type: "registry.service.created", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "registry_service", ID: id}, Category: "authorization", Metadata: map[string]any{"service": in.Service, "rules": len(in.Rules)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return b.Get(ctx, realmID, id)
}

// Update replaces a registry service's settings.
func (b *Bridge) Update(ctx context.Context, realmID, id string, expectedVersion int64, in Input, actor audit.Ref) (*Service, error) {
	err := b.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		cur, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM registry_services WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, id))
		if err != nil {
			return err
		}
		if expectedVersion != 0 && cur.Version != expectedVersion {
			return problem.ErrPrecondition
		}
		if in.Service == "" {
			in.Service = cur.Service
		}
		if in.Audience == "" {
			if err := tx.QueryRow(ctx, `SELECT audience FROM api_resources WHERE realm_id=$1 AND id=$2`, realmID, cur.ResourceID).Scan(&in.Audience); err != nil {
				return err
			}
		}
		if in.Service != cur.Service {
			return problem.ErrValidation.WithField("service", "cannot change; configure a new registry service")
		}
		res, err := b.validate(ctx, tx, realmID, &in)
		if err != nil {
			return err
		}
		rules, _ := json.Marshal(in.Rules)
		if _, err := tx.Exec(ctx, `UPDATE registry_services SET token_ttl_seconds=$2, rules=$3, state=$4, resource_id=$6, version=version+1, updated_at=$5 WHERE id=$1`,
			id, in.TokenTTLSeconds, rules, in.State, b.d.Now(), res.ID); err != nil {
			return err
		}
		_, err = b.d.Audit.Record(ctx, tx, audit.Event{Type: "registry.service.updated", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "registry_service", ID: id}, Category: "authorization", Metadata: map[string]any{"rules": len(in.Rules), "state": in.State}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return b.Get(ctx, realmID, id)
}

// Delete removes a registry service.
func (b *Bridge) Delete(ctx context.Context, realmID, id string, actor audit.Ref) error {
	return b.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM registry_services WHERE realm_id=$1 AND id=$2`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = b.d.Audit.Record(ctx, tx, audit.Event{Type: "registry.service.deleted", RealmID: realmID, Actor: actor,
			Target: &audit.Ref{Type: "registry_service", ID: id}, Category: "authorization"})
		return err
	})
}

// Get returns a registry service.
func (b *Bridge) Get(ctx context.Context, realmID, id string) (*Service, error) {
	return scan(b.d.DB.Pool.QueryRow(ctx, `SELECT `+cols+` FROM registry_services WHERE realm_id=$1 AND id=$2`, realmID, id))
}

// List returns the realm's registry services.
func (b *Bridge) List(ctx context.Context, realmID string) ([]*Service, error) {
	rows, err := b.d.DB.Pool.Query(ctx, `SELECT `+cols+` FROM registry_services WHERE realm_id=$1 ORDER BY service`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Service{}
	for rows.Next() {
		s, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ByService finds an active registry service by its service name.
func (b *Bridge) ByService(ctx context.Context, realmID, service string) (*Service, error) {
	return scan(b.d.DB.Pool.QueryRow(ctx, `SELECT `+cols+` FROM registry_services WHERE realm_id=$1 AND service=$2 AND state='active'`, realmID, service))
}

// Principal is who asks for a registry token. Scopes cap the actions (the
// credential's or the client grant's scopes); OrgID binds a credential to
// one organization.
type Principal struct {
	SubjectType string // user or service_principal; "" for anonymous
	SubjectID   string
	OrgID       string
	Scopes      []string
}

// Access is one granted access entry of a registry token.
type Access struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// ParseScope reads one Distribution scope "repository:<name>:<actions>";
// the name may itself contain colons (a registry host with a port).
func ParseScope(s string) (Access, bool) {
	first, last := strings.Index(s, ":"), strings.LastIndex(s, ":")
	if first <= 0 || last <= first {
		return Access{}, false
	}
	a := Access{Type: s[:first], Name: s[first+1 : last], Actions: strings.Split(s[last+1:], ",")}
	return a, a.Name != ""
}

// Grant decides each requested access: the first rule whose pattern matches
// the repository applies; an action is granted when the rule maps it to a
// permission the principal holds (in the rule's organization, or the realm)
// and the principal's scopes include the action, or for pull when the rule
// allows anonymous pulls. Anything else is left out of the token, which is
// how the protocol denies.
func (b *Bridge) Grant(ctx context.Context, realmID string, svc *Service, p Principal, requested []Access) []Access {
	out := []Access{}
	for _, req := range requested {
		if req.Type != "repository" {
			continue
		}
		var rule *Rule
		for i := range svc.Rules {
			if ok, _ := path.Match(svc.Rules[i].Repository, req.Name); ok {
				rule = &svc.Rules[i]
				break
			}
		}
		if rule == nil {
			continue
		}
		granted := []string{}
		for _, action := range req.Actions {
			if !slices.Contains(Actions, action) || slices.Contains(granted, action) {
				continue
			}
			if action == "pull" && rule.AnonymousPull {
				granted = append(granted, action)
				continue
			}
			perm := rule.permission(action)
			if perm == "" || p.SubjectID == "" || !slices.Contains(p.Scopes, action) {
				continue
			}
			if p.OrgID != "" && rule.OrganizationID != p.OrgID {
				continue
			}
			scope := authorization.Scope{Type: authorization.ScopeRealm, ID: realmID}
			if rule.OrganizationID != "" {
				scope = authorization.Scope{Type: authorization.ScopeOrganization, ID: rule.OrganizationID}
			}
			if b.Authz.Check(ctx, nil, realmID, authorization.Subject{Type: p.SubjectType, ID: p.SubjectID}, perm, scope) {
				granted = append(granted, action)
			}
		}
		if len(granted) > 0 {
			out = append(out, Access{Type: "repository", Name: req.Name, Actions: granted})
		}
	}
	return out
}

// Issue signs a registry token for the granted access.
func (b *Bridge) Issue(ctx context.Context, realmID, issuer string, svc *Service, p Principal, access []Access) (string, time.Time, error) {
	now := b.d.Now()
	exp := now.Add(time.Duration(svc.TokenTTLSeconds) * time.Second)
	sub := p.SubjectID
	claims := map[string]any{"iss": issuer, "sub": sub, "aud": svc.Service, "exp": exp.Unix(), "nbf": now.Add(-30 * time.Second).Unix(),
		"iat": now.Unix(), "jti": ids.New("rgt"), "access": access}
	tok, err := b.Signer.Sign(ctx, realmID, "JWT", claims)
	if err != nil {
		return "", time.Time{}, err
	}
	names := []string{}
	for _, a := range access {
		names = append(names, a.Name+":"+strings.Join(a.Actions, ","))
	}
	actor := audit.Ref{Type: "anonymous", ID: "anonymous"}
	if sub != "" {
		actor = audit.Ref{Type: p.SubjectType, ID: sub}
	}
	_, _ = b.d.Audit.Record(ctx, b.d.DB.Pool, audit.Event{Type: "registry.token.issued", RealmID: realmID, Actor: actor, OrgID: p.OrgID,
		Target: &audit.Ref{Type: "registry_service", ID: svc.ID}, Category: "token", Metadata: map[string]any{"service": svc.Service, "access": names}})
	return tok, exp, nil
}
