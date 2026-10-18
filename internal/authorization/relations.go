package authorization

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// Relationship-based authorization (AZ-021, AZ-022, AZ-023): a bounded
// model in which services register resource types (relations and the
// permissions each relation gives) and write relationship tuples linking
// subjects to their objects inside one organization. The identity provider
// keeps the relationships only, never the application's objects. Evaluation
// is bounded in depth and in the tuples it reads, and fails closed when a
// bound is reached.

// Subject kinds a relation can hold besides registered resource types.
const (
	RelSubjectUser         = "user"
	RelSubjectService      = "service_principal"
	RelSubjectGroup        = "group"
	RelSubjectOrganization = "organization"
)

const (
	maxRelationDepth  = 6
	maxRelationReads  = 64
	maxListCandidates = 5000
	maxListChecks     = 1000
)

// ErrRelationBound reports an evaluation that reached a bound; the decision
// is a denial.
var ErrRelationBound = errors.New("relationship evaluation bound reached")

// RelationDef is one relation of a resource type.
type RelationDef struct {
	Name string `json:"name"`
	// SubjectTypes may hold the relation directly: user, service_principal,
	// group (organization groups, through membership), organization (every
	// active member) or a registered resource type (links such as parent).
	SubjectTypes []string `json:"subject_types"`
	// ImpliedBy names relations of the same object that confer this one
	// (an editor is also a viewer).
	ImpliedBy []string `json:"implied_by,omitempty"`
}

// ResourceType is a service-registered object type (AZ-022).
type ResourceType struct {
	ID         string        `json:"id"`
	ResourceID string        `json:"resource_id"`
	Name       string        `json:"name"`
	Relations  []RelationDef `json:"relations"`
	// Permissions maps a registered permission to the relations that give
	// it: "viewer", or "parent.viewer" for the viewer relation of the object
	// linked through the parent relation.
	Permissions map[string][]string `json:"permissions"`
	// ShareableRelations may be offered by users to other members through
	// user-managed sharing (AZ-027); SharePermission is needed to share.
	ShareableRelations []string  `json:"shareable_relations"`
	SharePermission    string    `json:"share_permission,omitempty"`
	Version            int64     `json:"version"`
	CreatedByID        string    `json:"created_by_id"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

func (t *ResourceType) relation(name string) *RelationDef {
	for i := range t.Relations {
		if t.Relations[i].Name == name {
			return &t.Relations[i]
		}
	}
	return nil
}

// closure returns the relation and every relation that implies it.
func (t *ResourceType) closure(name string) []string {
	out := []string{name}
	for i := 0; i < len(out); i++ {
		if r := t.relation(out[i]); r != nil {
			for _, imp := range r.ImpliedBy {
				if !slices.Contains(out, imp) {
					out = append(out, imp)
				}
			}
		}
	}
	return out
}

var typeName = regexp.MustCompile(`^[a-z][a-z0-9_]{1,62}$`)

const rtCols = `id, resource_id, name, relations, permissions, shareable_relations, coalesce(share_permission,''), version, created_by_id, created_at, updated_at`

func scanType(row pgx.Row) (*ResourceType, error) {
	var t ResourceType
	var rel, perm []byte
	if err := row.Scan(&t.ID, &t.ResourceID, &t.Name, &rel, &perm, &t.ShareableRelations, &t.SharePermission, &t.Version, &t.CreatedByID,
		&t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(rel, &t.Relations)
	_ = json.Unmarshal(perm, &t.Permissions)
	return &t, nil
}

// ResourceTypeInput registers or replaces a resource type.
type ResourceTypeInput struct {
	ResourceID         string              `json:"resource_id"`
	Relations          []RelationDef       `json:"relations"`
	Permissions        map[string][]string `json:"permissions"`
	ShareableRelations []string            `json:"shareable_relations"`
	SharePermission    string              `json:"share_permission"`
}

// validate checks a schema against the realm: relations and their implied
// relations, subject types, permissions (registered, application namespace)
// and links through relations whose subjects are resource types.
func (s *Service) validateType(ctx context.Context, q storage.Querier, realmID, name string, in *ResourceTypeInput) *problem.Error {
	verr := problem.ErrValidation
	if !typeName.MatchString(name) {
		return verr.WithField("name", "lower-case letters, digits and underscores (2..63), starting with a letter")
	}
	var kind string
	if err := q.QueryRow(ctx, `SELECT kind FROM api_resources WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, in.ResourceID).Scan(&kind); err != nil || kind != "business" {
		return verr.WithField("resource_id", "an active business resource of this realm owns the type")
	}
	if len(in.Relations) == 0 || len(in.Relations) > 32 {
		return verr.WithField("relations", "1 to 32 relations")
	}
	t := &ResourceType{Name: name, Relations: in.Relations}
	names := map[string]bool{}
	for _, r := range in.Relations {
		if !typeName.MatchString(r.Name) || names[r.Name] {
			return verr.WithField("relations", "relation names are unique identifiers: "+r.Name)
		}
		names[r.Name] = true
	}
	for _, r := range in.Relations {
		if len(r.SubjectTypes) == 0 && len(r.ImpliedBy) == 0 {
			return verr.WithField("relations", r.Name+": give subject_types, implied_by or both")
		}
		for _, st := range r.SubjectTypes {
			switch st {
			case RelSubjectUser, RelSubjectService, RelSubjectGroup, RelSubjectOrganization:
			default:
				if st != name && !s.typeExists(ctx, q, realmID, st) {
					return verr.WithField("relations", r.Name+": unknown subject type "+st)
				}
			}
		}
		for _, imp := range r.ImpliedBy {
			if !names[imp] || imp == r.Name {
				return verr.WithField("relations", r.Name+": implied_by names another relation of this type")
			}
		}
	}
	// implied_by must not form a cycle: a cycle hides which grant is real.
	state := map[string]int{}
	var visit func(n string) bool
	visit = func(n string) bool {
		switch state[n] {
		case 1:
			return true
		case 2:
			return false
		}
		state[n] = 1
		for _, imp := range t.relation(n).ImpliedBy {
			if visit(imp) {
				return true
			}
		}
		state[n] = 2
		return false
	}
	for _, r := range in.Relations {
		if visit(r.Name) {
			return verr.WithField("relations", "implied_by relations form a cycle at "+r.Name)
		}
	}
	if len(in.Permissions) == 0 || len(in.Permissions) > 64 {
		return verr.WithField("permissions", "1 to 64 permissions")
	}
	for perm, via := range in.Permissions {
		var sens string
		if err := q.QueryRow(ctx, `SELECT sensitivity FROM permissions WHERE realm_id=$1 AND name=$2 AND NOT built_in`, realmID, perm).Scan(&sens); err != nil {
			return verr.WithField("permissions", "register the application permission first: "+perm)
		}
		if len(via) == 0 || len(via) > 16 {
			return verr.WithField("permissions", perm+": 1 to 16 relations")
		}
		for _, v := range via {
			link, target, linked := strings.Cut(v, ".")
			if !names[link] {
				return verr.WithField("permissions", perm+": unknown relation "+link)
			}
			if linked && (target == "" || strings.Contains(target, ".")) {
				return verr.WithField("permissions", perm+": use relation or link.relation")
			}
			if linked && !slices.ContainsFunc(t.relation(link).SubjectTypes, func(st string) bool {
				return st != RelSubjectUser && st != RelSubjectService && st != RelSubjectGroup && st != RelSubjectOrganization
			}) {
				return verr.WithField("permissions", perm+": "+link+" does not link to another resource type")
			}
		}
	}
	for _, r := range in.ShareableRelations {
		if !names[r] {
			return verr.WithField("shareable_relations", "unknown relation "+r)
		}
	}
	if len(in.ShareableRelations) > 0 {
		if _, ok := in.Permissions[in.SharePermission]; !ok {
			return verr.WithField("share_permission", "required with shareable_relations: one of the type's permissions")
		}
	}
	return nil
}

func (s *Service) typeExists(ctx context.Context, q storage.Querier, realmID, name string) bool {
	var ok bool
	_ = q.QueryRow(ctx, `SELECT true FROM resource_types WHERE realm_id=$1 AND name=$2`, realmID, name).Scan(&ok)
	return ok
}

// PutResourceType registers a resource type or replaces its schema
// (If-Match version when it exists).
func (s *Service) PutResourceType(ctx context.Context, realmID, name string, version int64, in ResourceTypeInput, actor audit.Ref) (*ResourceType, bool, error) {
	if in.ShareableRelations == nil {
		in.ShareableRelations = []string{}
	}
	var out *ResourceType
	created := false
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if perr := s.validateType(ctx, tx, realmID, name, &in); perr != nil {
			return perr
		}
		rel, _ := json.Marshal(in.Relations)
		perm, _ := json.Marshal(in.Permissions)
		cur, err := scanType(tx.QueryRow(ctx, `SELECT `+rtCols+` FROM resource_types WHERE realm_id=$1 AND name=$2 FOR UPDATE`, realmID, name))
		now := s.d.Now()
		switch {
		case storage.IsNoRows(err):
			created = true
			if _, err := tx.Exec(ctx, `INSERT INTO resource_types (id, realm_id, resource_id, name, relations, permissions, shareable_relations, share_permission,
				created_by_id, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`, ids.New("rty"), realmID, in.ResourceID, name, rel, perm,
				in.ShareableRelations, nilIfEmpty(in.SharePermission), actor.ID, now); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			if version == 0 {
				return problem.ErrPreconditionNeeded
			}
			if cur.Version != version {
				return problem.ErrPrecondition
			}
			if cur.ResourceID != in.ResourceID {
				return problem.ErrValidation.WithField("resource_id", "a type stays with the resource that registered it")
			}
			if _, err := tx.Exec(ctx, `UPDATE resource_types SET relations=$3, permissions=$4, shareable_relations=$5, share_permission=$6, version=version+1,
				updated_at=$7 WHERE realm_id=$1 AND name=$2`, realmID, name, rel, perm, in.ShareableRelations, nilIfEmpty(in.SharePermission), now); err != nil {
				return err
			}
		}
		typ := "authorization.resource_type.updated"
		if created {
			typ = "authorization.resource_type.registered"
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: typ, RealmID: realmID, Actor: actor, Category: "authorization",
			Target: &audit.Ref{Type: "resource_type", ID: name}, Metadata: map[string]any{"resource_id": in.ResourceID, "relations": len(in.Relations),
				"permissions": len(in.Permissions)}}); err != nil {
			return err
		}
		out, err = scanType(tx.QueryRow(ctx, `SELECT `+rtCols+` FROM resource_types WHERE realm_id=$1 AND name=$2`, realmID, name))
		return err
	})
	return out, created, err
}

// ResourceTypeByName returns a registered type.
func (s *Service) ResourceTypeByName(ctx context.Context, q storage.Querier, realmID, name string) (*ResourceType, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	t, err := scanType(q.QueryRow(ctx, `SELECT `+rtCols+` FROM resource_types WHERE realm_id=$1 AND name=$2`, realmID, name))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return t, err
}

// ListResourceTypes lists a realm's types.
func (s *Service) ListResourceTypes(ctx context.Context, realmID string) ([]*ResourceType, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+rtCols+` FROM resource_types WHERE realm_id=$1 ORDER BY name LIMIT 500`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ResourceType{}
	for rows.Next() {
		t, err := scanType(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteResourceType removes a type that no relationship uses any more.
func (s *Service) DeleteResourceType(ctx context.Context, realmID, name string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		var used bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM resource_relationships WHERE realm_id=$1 AND (object_type=$2 OR subject_type=$2))`,
			realmID, name).Scan(&used); err != nil {
			return err
		}
		if used {
			return problem.ErrConflict.WithDetail("relationships still use this type; remove them first")
		}
		tag, err := tx.Exec(ctx, `DELETE FROM resource_types WHERE realm_id=$1 AND name=$2`, realmID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.resource_type.deleted", RealmID: realmID, Actor: actor, Category: "authorization",
			Target: &audit.Ref{Type: "resource_type", ID: name}})
		return err
	})
}

// Relationship is one tuple.
type Relationship struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	ObjectType     string     `json:"object_type"`
	ObjectID       string     `json:"object_id"`
	Relation       string     `json:"relation"`
	SubjectType    string     `json:"subject_type"`
	SubjectID      string     `json:"subject_id"`
	Source         string     `json:"source"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedByID    string     `json:"created_by_id,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// RelationshipWrite adds or removes one tuple.
type RelationshipWrite struct {
	Op          string     `json:"op"`
	ObjectType  string     `json:"object_type"`
	ObjectID    string     `json:"object_id"`
	Relation    string     `json:"relation"`
	SubjectType string     `json:"subject_type"`
	SubjectID   string     `json:"subject_id"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	// exclusive makes an add create the tuple or fail with errTupleExists
	// instead of updating an equivalent tuple (shares, AZ-027). It cannot be
	// set through the relationships API.
	exclusive bool
}

// errTupleExists refuses an exclusive add: an equivalent tuple exists, and
// it is left as it is.
var errTupleExists = problem.ErrConflict.WithDetail("the subject already holds this relation on the object")

func validObjectID(id string) bool {
	return id != "" && len(id) <= 256 && !strings.ContainsFunc(id, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// checkSubjectTx confines a relationship subject to the organization: an
// active member, one of its groups, the organization itself, a service
// principal allowed in it, or an object of a registered type.
func (s *Service) checkSubjectTx(ctx context.Context, q storage.Querier, realmID, orgID, typ, id string) *problem.Error {
	verr := problem.ErrValidation
	var ok bool
	switch typ {
	case RelSubjectUser:
		_ = q.QueryRow(ctx, `SELECT true FROM memberships WHERE organization_id=$1 AND user_id=$2 AND state='active'`, orgID, id).Scan(&ok)
		if !ok {
			return verr.WithField("subject_id", "the user is not an active member of the organization")
		}
	case RelSubjectGroup:
		_ = q.QueryRow(ctx, `SELECT true FROM groups WHERE organization_id=$1 AND id=$2`, orgID, id).Scan(&ok)
		if !ok {
			return verr.WithField("subject_id", "unknown group in the organization")
		}
	case RelSubjectOrganization:
		if id != orgID {
			return verr.WithField("subject_id", "an organization subject is the organization itself")
		}
	case RelSubjectService:
		_ = q.QueryRow(ctx, `SELECT true FROM service_principals WHERE realm_id=$1 AND id=$2 AND state='active'
			AND ($3 = ANY(allowed_organization_ids) OR owner_organization_id=$3)`, realmID, id, orgID).Scan(&ok)
		if !ok {
			return verr.WithField("subject_id", "the service principal is not allowed in the organization")
		}
	default:
		if !validObjectID(id) {
			return verr.WithField("subject_id", "1 to 256 characters without control characters")
		}
	}
	return nil
}

// WriteRelationships applies a batch of adds and removes atomically within
// one organization (AZ-021).
func (s *Service) WriteRelationships(ctx context.Context, realmID, orgID string, writes []RelationshipWrite, source string, actor audit.Ref) error {
	if len(writes) == 0 || len(writes) > 100 {
		return problem.ErrValidation.WithField("writes", "1 to 100 writes")
	}
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		return s.writeRelationshipsTx(ctx, tx, realmID, orgID, writes, source, actor)
	})
}

func (s *Service) writeRelationshipsTx(ctx context.Context, tx pgx.Tx, realmID, orgID string, writes []RelationshipWrite, source string, actor audit.Ref) error {
	var orgOK bool
	if err := tx.QueryRow(ctx, `SELECT true FROM organizations WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, orgID).Scan(&orgOK); err != nil {
		return problem.ErrNotFound.WithDetail("unknown or inactive organization")
	}
	types := map[string]*ResourceType{}
	added, removed := 0, 0
	for _, w := range writes {
		t := types[w.ObjectType]
		if t == nil {
			var err error
			if t, err = s.ResourceTypeByName(ctx, tx, realmID, w.ObjectType); err != nil {
				return problem.ErrValidation.WithField("object_type", "unknown resource type "+w.ObjectType)
			}
			types[w.ObjectType] = t
		}
		rel := t.relation(w.Relation)
		if rel == nil {
			return problem.ErrValidation.WithField("relation", w.ObjectType+" has no relation "+w.Relation)
		}
		if !validObjectID(w.ObjectID) {
			return problem.ErrValidation.WithField("object_id", "1 to 256 characters without control characters")
		}
		switch w.Op {
		case "add":
			if !slices.Contains(rel.SubjectTypes, w.SubjectType) {
				return problem.ErrValidation.WithField("subject_type", w.Relation+" accepts "+strings.Join(rel.SubjectTypes, ", "))
			}
			if perr := s.checkSubjectTx(ctx, tx, realmID, orgID, w.SubjectType, w.SubjectID); perr != nil {
				return perr
			}
			if w.ExpiresAt != nil && !w.ExpiresAt.After(s.d.Now()) {
				return problem.ErrValidation.WithField("expires_at", "in the future")
			}
			onConflict := `DO UPDATE SET expires_at=EXCLUDED.expires_at, revision=resource_relationships.revision+1`
			if w.exclusive {
				// Atomic also against a concurrent write of the same tuple:
				// the insert waits for it and then does nothing.
				onConflict = `DO NOTHING`
			}
			tag, err := tx.Exec(ctx, `INSERT INTO resource_relationships (id, realm_id, organization_id, subject_type, subject_id, relation, object_type,
				object_id, source, expires_at, created_by_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
				ON CONFLICT (organization_id, subject_type, subject_id, relation, object_type, object_id) `+onConflict, ids.New("rel"), realmID, orgID,
				w.SubjectType, w.SubjectID, w.Relation, w.ObjectType, w.ObjectID, source, w.ExpiresAt, actor.ID)
			if err != nil {
				return err
			}
			if w.exclusive && tag.RowsAffected() == 0 {
				return errTupleExists
			}
			added++
		case "remove":
			tag, err := tx.Exec(ctx, `DELETE FROM resource_relationships WHERE organization_id=$1 AND subject_type=$2 AND subject_id=$3 AND relation=$4
				AND object_type=$5 AND object_id=$6`, orgID, w.SubjectType, w.SubjectID, w.Relation, w.ObjectType, w.ObjectID)
			if err != nil {
				return err
			}
			removed += int(tag.RowsAffected())
		default:
			return problem.ErrValidation.WithField("op", "add or remove")
		}
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.relationships.written", RealmID: realmID, OrgID: orgID, Actor: actor,
		Category: "authorization", Metadata: map[string]any{"added": added, "removed": removed, "source": source, "writes": writes}})
	return err
}

// ListRelationships lists tuples of an organization, filtered, by id.
func (s *Service) ListRelationships(ctx context.Context, realmID, orgID, objectType, objectID, subjectType, subjectID, after string, limit int) ([]*Relationship, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, organization_id, object_type, object_id, relation, subject_type, subject_id, source, expires_at,
		coalesce(created_by_id,''), created_at FROM resource_relationships WHERE realm_id=$1 AND organization_id=$2
		AND ($3='' OR object_type=$3) AND ($4='' OR object_id=$4) AND ($5='' OR subject_type=$5) AND ($6='' OR subject_id=$6) AND ($7='' OR id > $7)
		ORDER BY id LIMIT $8`, realmID, orgID, objectType, objectID, subjectType, subjectID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Relationship{}
	for rows.Next() {
		var r Relationship
		if err := rows.Scan(&r.ID, &r.OrganizationID, &r.ObjectType, &r.ObjectID, &r.Relation, &r.SubjectType, &r.SubjectID, &r.Source, &r.ExpiresAt,
			&r.CreatedByID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

// relEval evaluates relationships for one subject in one organization.
type relEval struct {
	s       *Service
	ctx     context.Context
	q       storage.Querier
	realmID string
	orgID   string
	subj    Subject
	now     time.Time
	// eligible: the organization is active and the subject may hold
	// relationships in it now; when false nothing matches.
	eligible bool
	member   bool
	groups   []string
	reads    int
	types    map[string]*ResourceType
	tuples   map[string][][3]string // object -> (relation, subject type, subject id)
}

// newRelEval prepares the evaluation with the same tenant eligibility as
// RBAC's effective (AZ-007, AZ-010, AZ-021): the organization must be active,
// the subject an active account or service principal; a user counts as a
// member only through an active, unexpired membership (also before the
// expiry sweep), and through the groups groupClosure yields (stale or broken
// dynamic groups excluded); a service principal only while it is allowed in
// the organization (owner organization or allowed_organization_ids).
func (s *Service) newRelEval(ctx context.Context, q storage.Querier, realmID, orgID string, subj Subject) (*relEval, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	e := &relEval{s: s, ctx: ctx, q: q, realmID: realmID, orgID: orgID, subj: subj, now: s.d.Now(), types: map[string]*ResourceType{},
		tuples: map[string][][3]string{}}
	if subj.Type != SubjectUser && subj.Type != SubjectService {
		return e, nil // only users and service principals hold relationships
	}
	var orgActive bool
	if err := q.QueryRow(ctx, `SELECT state='active' FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, orgID).Scan(&orgActive); err != nil {
		if storage.IsNoRows(err) {
			return e, nil
		}
		return nil, err
	}
	if !orgActive {
		return e, nil
	}
	if ok, err := s.subjectActive(ctx, q, realmID, subj); err != nil || !ok {
		return e, err
	}
	switch subj.Type {
	case SubjectUser:
		var membershipID string
		err := q.QueryRow(ctx, `SELECT m.id FROM memberships m JOIN organizations o ON o.id=m.organization_id
			WHERE m.realm_id=$1 AND m.organization_id=$2 AND m.user_id=$3 AND m.state='active' AND o.state='active'
			AND (m.expires_at IS NULL OR m.expires_at > $4)`, realmID, orgID, subj.ID, e.now).Scan(&membershipID)
		if storage.IsNoRows(err) {
			return e, nil
		}
		if err != nil {
			return nil, err
		}
		groups, err := s.groupClosure(ctx, q, orgID, membershipID, e.now)
		if err != nil {
			return nil, err
		}
		e.eligible, e.member, e.groups = true, true, groups
	case SubjectService:
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM service_principals WHERE realm_id=$1 AND id=$2 AND state='active'
			AND ($3 = ANY(allowed_organization_ids) OR owner_organization_id=$3))`, realmID, subj.ID, orgID).Scan(&e.eligible); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func (e *relEval) typ(name string) *ResourceType {
	if t, ok := e.types[name]; ok {
		return t
	}
	t, err := e.s.ResourceTypeByName(e.ctx, e.q, e.realmID, name)
	if err != nil {
		t = nil
	}
	e.types[name] = t
	return t
}

func (e *relEval) objectTuples(objType, objID string) ([][3]string, error) {
	key := objType + "\x00" + objID
	if t, ok := e.tuples[key]; ok {
		return t, nil
	}
	e.reads++
	if e.reads > maxRelationReads {
		return nil, ErrRelationBound
	}
	rows, err := e.q.Query(e.ctx, `SELECT relation, subject_type, subject_id FROM resource_relationships WHERE organization_id=$1 AND object_type=$2
		AND object_id=$3 AND (expires_at IS NULL OR expires_at > $4) LIMIT 1001`, e.orgID, objType, objID, e.now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var t [3]string
		if err := rows.Scan(&t[0], &t[1], &t[2]); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if len(out) > 1000 {
		return nil, ErrRelationBound
	}
	e.tuples[key] = out
	return out, rows.Err()
}

func (e *relEval) matches(subjType, subjID string) bool {
	switch subjType {
	case RelSubjectUser, RelSubjectService:
		return e.eligible && subjType == e.subj.Type && subjID == e.subj.ID
	case RelSubjectGroup:
		return e.member && slices.Contains(e.groups, subjID)
	case RelSubjectOrganization:
		return e.member && subjID == e.orgID
	}
	return false
}

// hasRelation reports whether the subject holds relation on the object,
// directly or through a relation that implies it.
func (e *relEval) hasRelation(objType, objID, relation string, depth int) (bool, error) {
	if depth > maxRelationDepth {
		return false, ErrRelationBound
	}
	t := e.typ(objType)
	if t == nil {
		return false, nil
	}
	rels := t.closure(relation)
	tuples, err := e.objectTuples(objType, objID)
	if err != nil {
		return false, err
	}
	for _, tu := range tuples {
		if slices.Contains(rels, tu[0]) && e.matches(tu[1], tu[2]) {
			return true, nil
		}
	}
	return false, nil
}

// permitted reports whether the subject has permission on the object.
func (e *relEval) permitted(objType, objID, permission string, depth int) (bool, error) {
	if depth > maxRelationDepth {
		return false, ErrRelationBound
	}
	t := e.typ(objType)
	if t == nil {
		return false, nil
	}
	for _, via := range t.Permissions[permission] {
		link, target, linked := strings.Cut(via, ".")
		if !linked {
			ok, err := e.hasRelation(objType, objID, link, depth)
			if err != nil || ok {
				return ok, err
			}
			continue
		}
		tuples, err := e.objectTuples(objType, objID)
		if err != nil {
			return false, err
		}
		for _, tu := range t.closure(link) {
			for _, x := range tuples {
				if x[0] != tu || e.typ(x[1]) == nil {
					continue
				}
				ok, err := e.hasRelation(x[1], x[2], target, depth+1)
				if err != nil || ok {
					return ok, err
				}
			}
		}
	}
	return false, nil
}

// CheckObject decides whether a subject may perform permission on one object
// through relationships (AZ-021). A bound reached is a denial, and so is an
// organization that is not active or a subject not eligible in it.
func (s *Service) CheckObject(ctx context.Context, q storage.Querier, realmID, orgID string, subj Subject, objType, objID, permission string) (bool, error) {
	if orgID == "" || objID == "" {
		return false, nil
	}
	e, err := s.newRelEval(ctx, q, realmID, orgID, subj)
	if err != nil || !e.eligible {
		return false, err
	}
	return e.permitted(objType, objID, permission, 0)
}

// ListObjects returns the objects of a type on which the subject has the
// permission through relationships (AZ-023), verified one by one, ordered by
// id after the cursor. Candidates come from the subject's own tuples and
// whatever links to them, within bounds; reaching a bound (also an object
// whose own evaluation reached one) returns what was verified with
// truncated=true, never an unverified object.
func (s *Service) ListObjects(ctx context.Context, realmID, orgID string, subj Subject, objType, permission, after string, limit int) ([]string, bool, error) {
	e, err := s.newRelEval(ctx, nil, realmID, orgID, subj)
	if err != nil {
		return nil, false, err
	}
	if e.typ(objType) == nil {
		return nil, false, problem.ErrValidation.WithField("resource.type", "unknown resource type")
	}
	if !e.eligible {
		// An organization that is not active, or a subject not eligible in
		// it, has no objects (as CheckObject denies).
		return []string{}, false, nil
	}
	type ref struct{ typ, id string }
	starts := [][2]string{{subj.Type, subj.ID}}
	if e.member {
		starts = append(starts, [2]string{RelSubjectOrganization, orgID})
		for _, g := range e.groups {
			starts = append(starts, [2]string{RelSubjectGroup, g})
		}
	}
	seen := map[ref]bool{}
	candidates := []string{}
	frontier := starts
	truncated := false
	for depth := 0; depth <= maxRelationDepth && len(frontier) > 0 && !truncated; depth++ {
		var next [][2]string
		for i := 0; i < len(frontier); i += 200 {
			chunk := frontier[i:min(i+200, len(frontier))]
			types := make([]string, len(chunk))
			idsList := make([]string, len(chunk))
			for j, c := range chunk {
				types[j], idsList[j] = c[0], c[1]
			}
			rows, err := s.d.DB.Pool.Query(ctx, `SELECT DISTINCT r.object_type, r.object_id FROM resource_relationships r
				JOIN unnest($2::text[], $3::text[]) AS f(t, i) ON r.subject_type=f.t AND r.subject_id=f.i
				WHERE r.organization_id=$1 AND (r.expires_at IS NULL OR r.expires_at > $4) LIMIT $5`, orgID, types, idsList, e.now, maxListCandidates+1)
			if err != nil {
				return nil, false, err
			}
			for rows.Next() {
				var r ref
				if err := rows.Scan(&r.typ, &r.id); err != nil {
					rows.Close()
					return nil, false, err
				}
				if seen[r] {
					continue
				}
				seen[r] = true
				if len(seen) > maxListCandidates {
					truncated = true
					break
				}
				if r.typ == objType {
					candidates = append(candidates, r.id)
				}
				next = append(next, [2]string{r.typ, r.id})
			}
			rows.Close()
		}
		frontier = next
	}
	sort.Strings(candidates)
	out := []string{}
	checks := 0
	for _, id := range candidates {
		if id <= after {
			continue
		}
		if len(out) >= limit {
			break
		}
		checks++
		if checks > maxListChecks {
			truncated = true
			break
		}
		ok, err := e.permitted(objType, id, permission, 0)
		if errors.Is(err, ErrRelationBound) {
			// The object could not be verified: it is left out, and the
			// answer says the list is incomplete.
			truncated = true
			e.reads = 0 // each object is verified with its own budget
			continue
		}
		if err != nil {
			return nil, false, err
		}
		e.reads = 0
		if ok {
			out = append(out, id)
		}
	}
	return out, truncated, nil
}
