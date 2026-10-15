package authorization

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// PolicyCacheTTL bounds how long a node may evaluate a superseded policy after
// another node publishes (AZ-019 freshness bound). Publishing on this node
// invalidates immediately.
const PolicyCacheTTL = 5 * time.Second

// Policy is a named, versioned policy.
type Policy struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description,omitempty"`
	ScopeType        string    `json:"scope_type"`
	ScopeID          string    `json:"scope_id,omitempty"`
	State            string    `json:"state"`
	ActiveVersion    *int      `json:"active_version,omitempty"`
	RequiresApproval bool      `json:"requires_approval"`
	Version          int64     `json:"version"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// PolicyVersion is an immutable revision.
type PolicyVersion struct {
	ID          string          `json:"id"`
	PolicyID    string          `json:"policy_id"`
	Number      int             `json:"version_number"`
	Definition  json.RawMessage `json:"definition"`
	Hash        string          `json:"definition_hash"`
	Status      string          `json:"status"`
	AuthorID    string          `json:"author_id"`
	ApprovedBy  string          `json:"approved_by_id,omitempty"`
	Note        string          `json:"note,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	ApprovedAt  *time.Time      `json:"approved_at,omitempty"`
	PublishedAt *time.Time      `json:"published_at,omitempty"`
}

// ActivePolicy is a published policy ready for evaluation.
type ActivePolicy struct {
	ID         string
	Name       string
	ScopeType  string
	ScopeID    string
	Version    int
	Definition *PolicyDefinition
}

// Label identifies the evaluated revision in decisions.
func (p *ActivePolicy) Label() string { return p.Name + "@" + itoa(p.Version) }

type policyCache struct {
	mu      sync.Mutex
	entries map[string]policyCacheEntry
}

type policyCacheEntry struct {
	at       time.Time
	policies []*ActivePolicy
}

var activeCache = &policyCache{entries: map[string]policyCacheEntry{}}

func (c *policyCache) invalidate(realmID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, realmID)
}

const policyCols = `id, name, coalesce(description,''), scope_type, coalesce(scope_id,''), state, active_version, requires_approval, version, created_at, updated_at`

func scanPolicy(row pgx.Row) (*Policy, error) {
	var p Policy
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.ScopeType, &p.ScopeID, &p.State, &p.ActiveVersion, &p.RequiresApproval, &p.Version,
		&p.CreatedAt, &p.UpdatedAt); err != nil {
		return nil, err
	}
	return &p, nil
}

const versionCols = `id, policy_id, version_number, definition, definition_hash, status, author_id, coalesce(approved_by_id,''), coalesce(note,''),
	created_at, approved_at, published_at`

func scanVersion(row pgx.Row) (*PolicyVersion, error) {
	var v PolicyVersion
	if err := row.Scan(&v.ID, &v.PolicyID, &v.Number, &v.Definition, &v.Hash, &v.Status, &v.AuthorID, &v.ApprovedBy, &v.Note, &v.CreatedAt,
		&v.ApprovedAt, &v.PublishedAt); err != nil {
		return nil, err
	}
	return &v, nil
}

// canonicalDefinition validates and canonicalizes a definition for hashing
// and diffs.
func canonicalDefinition(raw json.RawMessage) ([]byte, string, error) {
	def, err := ParsePolicy(raw)
	if err != nil {
		return nil, "", err
	}
	b, _ := json.MarshalIndent(def, "", "  ")
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// PolicyInput is a create request.
type PolicyCreate struct {
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	ScopeType        string          `json:"scope_type"`
	ScopeID          string          `json:"scope_id"`
	RequiresApproval bool            `json:"requires_approval"`
	Definition       json.RawMessage `json:"definition"`
	Note             string          `json:"note"`
	// OwnerUserID is the accountable owner (DOM-009); it defaults to the
	// creating user.
	OwnerUserID string `json:"owner_user_id"`
}

// CreatePolicy creates a draft policy with its first staged revision.
func (s *Service) CreatePolicy(ctx context.Context, realmID string, in PolicyCreate, actor audit.Ref) (*Policy, *PolicyVersion, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 || strings.ContainsAny(in.Name, "@\r\n") {
		return nil, nil, problem.ErrValidation.WithField("name", "1..100 characters, no @ or line breaks")
	}
	if in.ScopeType == "" {
		in.ScopeType = ScopeRealm
	}
	if in.ScopeType != ScopeRealm && in.ScopeType != ScopeOrganization {
		return nil, nil, problem.ErrValidation.WithField("scope_type", "realm or organization")
	}
	if (in.ScopeType == ScopeOrganization) != (in.ScopeID != "") {
		return nil, nil, problem.ErrValidation.WithField("scope_id", "required for organization scope only")
	}
	canon, hash, err := canonicalDefinition(in.Definition)
	if err != nil {
		return nil, nil, err
	}
	var pol *Policy
	var ver *PolicyVersion
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if in.ScopeType == ScopeOrganization {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM organizations WHERE realm_id=$1 AND id=$2`, realmID, in.ScopeID).Scan(&n); err != nil || n == 0 {
				return problem.ErrValidation.WithField("scope_id", "unknown organization")
			}
		}
		id, now := ids.New(ids.Policy), s.d.Now()
		owner := in.OwnerUserID
		if owner == "" && actor.Type == "user" {
			owner = actor.ID
		}
		if owner != "" {
			var live bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE realm_id=$1 AND id=$2 AND state='active')`, realmID, owner).Scan(&live); err != nil {
				return err
			}
			if !live {
				return problem.ErrValidation.WithField("owner_user_id", "an active account of this realm is required")
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO policies (id, realm_id, name, description, scope_type, scope_id, state, requires_approval, created_at, updated_at,
			owner_user_id) VALUES ($1,$2,$3,$4,$5,$6,'draft',$7,$8,$8,$9)`, id, realmID, in.Name, nilIfEmpty(in.Description), in.ScopeType, nilIfEmpty(in.ScopeID),
			in.RequiresApproval, now, nilIfEmpty(owner)); err != nil {
			if storage.IsUniqueViolation(err) {
				return problem.ErrConflict.WithField("name", "a policy with this name exists")
			}
			return err
		}
		v, err := s.stageTx(ctx, tx, realmID, id, canon, hash, actor, in.Note)
		if err != nil {
			return err
		}
		ver = v
		pol, err = scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE id=$1`, id))
		if err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.policy.created", RealmID: realmID, Actor: actor, Category: "authorization",
			Target: &audit.Ref{Type: "policy", ID: id}, Metadata: map[string]any{"name": in.Name, "scope_type": in.ScopeType, "requires_approval": in.RequiresApproval}})
		return err
	})
	return pol, ver, err
}

func (s *Service) stageTx(ctx context.Context, tx pgx.Tx, realmID, policyID string, canon []byte, hash string, actor audit.Ref, note string) (*PolicyVersion, error) {
	var next int
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(version_number),0)+1 FROM policy_versions WHERE policy_id=$1`, policyID).Scan(&next); err != nil {
		return nil, err
	}
	id := ids.New(ids.PolicyVersion)
	if len(note) > 500 {
		note = note[:500]
	}
	if _, err := tx.Exec(ctx, `INSERT INTO policy_versions (id, policy_id, version_number, definition, definition_hash, status, author_id, note, created_at)
		VALUES ($1,$2,$3,$4,$5,'staged',$6,$7,$8)`, id, policyID, next, canon, hash, actor.ID, nilIfEmpty(note), s.d.Now()); err != nil {
		return nil, err
	}
	if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.policy.version_staged", RealmID: realmID, Actor: actor, Category: "authorization",
		Target: &audit.Ref{Type: "policy", ID: policyID}, Metadata: map[string]any{"version": next, "definition_hash": hash}}); err != nil {
		return nil, err
	}
	return scanVersion(tx.QueryRow(ctx, `SELECT `+versionCols+` FROM policy_versions WHERE id=$1`, id))
}

func (s *Service) lockPolicy(ctx context.Context, tx pgx.Tx, realmID, policyID string) (*Policy, error) {
	p, err := scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE realm_id=$1 AND id=$2 FOR UPDATE`, realmID, policyID))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return p, err
}

// StageVersion adds an immutable staged revision.
func (s *Service) StageVersion(ctx context.Context, realmID, policyID string, def json.RawMessage, note string, actor audit.Ref) (*PolicyVersion, error) {
	canon, hash, err := canonicalDefinition(def)
	if err != nil {
		return nil, err
	}
	var out *PolicyVersion
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.lockPolicy(ctx, tx, realmID, policyID); err != nil {
			return err
		}
		out, err = s.stageTx(ctx, tx, realmID, policyID, canon, hash, actor, note)
		return err
	})
	return out, err
}

func (s *Service) version(ctx context.Context, q storage.Querier, policyID string, number int) (*PolicyVersion, error) {
	v, err := scanVersion(q.QueryRow(ctx, `SELECT `+versionCols+` FROM policy_versions WHERE policy_id=$1 AND version_number=$2`, policyID, number))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return v, err
}

// ApproveVersion approves a staged revision. The author cannot approve their
// own change (AZ-018).
func (s *Service) ApproveVersion(ctx context.Context, realmID, policyID string, number int, actor audit.Ref) (*PolicyVersion, error) {
	var out *PolicyVersion
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := s.lockPolicy(ctx, tx, realmID, policyID); err != nil {
			return err
		}
		v, err := s.version(ctx, tx, policyID, number)
		if err != nil {
			return err
		}
		if v.Status != "staged" {
			return problem.ErrConflict.WithDetail("only staged revisions can be approved")
		}
		if v.AuthorID == actor.ID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		if _, err := tx.Exec(ctx, `UPDATE policy_versions SET status='approved', approved_by_id=$2, approved_at=$3 WHERE id=$1`, v.ID, actor.ID, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.policy.version_approved", RealmID: realmID, Actor: actor, Category: "authorization",
			Target: &audit.Ref{Type: "policy", ID: policyID}, Metadata: map[string]any{"version": number, "author_id": v.AuthorID}}); err != nil {
			return err
		}
		out, err = s.version(ctx, tx, policyID, number)
		return err
	})
	return out, err
}

// PublishVersion makes a revision the active one. Policies that require
// approval publish only approved revisions.
func (s *Service) PublishVersion(ctx context.Context, realmID, policyID string, number int, actor audit.Ref) (*Policy, error) {
	var out *Policy
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lockPolicy(ctx, tx, realmID, policyID)
		if err != nil {
			return err
		}
		v, err := s.version(ctx, tx, policyID, number)
		if err != nil {
			return err
		}
		switch {
		case v.Status == "published":
			return problem.ErrConflict.WithDetail("this revision is already published")
		case v.Status == "rejected":
			return problem.ErrConflict.WithDetail("rejected revisions cannot be published")
		case p.RequiresApproval && v.Status != "approved" && v.Status != "superseded":
			return problem.ErrForbidden.WithDetail("this policy requires an independent approval before publishing")
		case p.RequiresApproval && v.Status == "superseded" && v.ApprovedBy == "":
			return problem.ErrForbidden.WithDetail("this revision was never approved")
		}
		if err := s.publishTx(ctx, tx, realmID, p, v, actor, "authorization.policy.published"); err != nil {
			return err
		}
		out, err = scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE id=$1`, policyID))
		return err
	})
	activeCache.invalidate(realmID)
	return out, err
}

func (s *Service) publishTx(ctx context.Context, tx pgx.Tx, realmID string, p *Policy, v *PolicyVersion, actor audit.Ref, event string) error {
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE policy_versions SET status='superseded' WHERE policy_id=$1 AND status='published'`, p.ID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE policy_versions SET status='published', published_at=$2 WHERE id=$1`, v.ID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE policies SET active_version=$2, state='active', version=version+1, updated_at=$3 WHERE id=$1`, p.ID, v.Number, now); err != nil {
		return err
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: event, RealmID: realmID, Actor: actor, Category: "authorization",
		Target: &audit.Ref{Type: "policy", ID: p.ID}, Metadata: map[string]any{"name": p.Name, "version": v.Number, "definition_hash": v.Hash,
			"previous_version": p.ActiveVersion}})
	return err
}

// Rollback republishes a previously published revision as a new revision with
// identical content, keeping history immutable (AZ-017).
func (s *Service) Rollback(ctx context.Context, realmID, policyID string, toNumber int, actor audit.Ref) (*Policy, error) {
	var out *Policy
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lockPolicy(ctx, tx, realmID, policyID)
		if err != nil {
			return err
		}
		old, err := s.version(ctx, tx, policyID, toNumber)
		if err != nil {
			return err
		}
		if old.PublishedAt == nil {
			return problem.ErrConflict.WithDetail("only previously published revisions can be restored")
		}
		v, err := s.stageTx(ctx, tx, realmID, policyID, old.Definition, old.Hash, actor, "rollback to version "+itoa(toNumber))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE policy_versions SET approved_by_id=$2, approved_at=$3 WHERE id=$1`, v.ID, nilIfEmpty(old.ApprovedBy), old.ApprovedAt); err != nil {
			return err
		}
		if err := s.publishTx(ctx, tx, realmID, p, v, actor, "authorization.policy.rolled_back"); err != nil {
			return err
		}
		out, err = scanPolicy(tx.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE id=$1`, policyID))
		return err
	})
	activeCache.invalidate(realmID)
	return out, err
}

// SetPolicyState disables or re-enables evaluation of a policy.
func (s *Service) SetPolicyState(ctx context.Context, realmID, policyID, state string, actor audit.Ref) error {
	if state != "active" && state != "disabled" {
		return problem.ErrValidation.WithField("state", "active or disabled")
	}
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		p, err := s.lockPolicy(ctx, tx, realmID, policyID)
		if err != nil {
			return err
		}
		if state == "active" && p.ActiveVersion == nil {
			return problem.ErrConflict.WithDetail("publish a revision first")
		}
		if _, err := tx.Exec(ctx, `UPDATE policies SET state=$2, version=version+1, updated_at=$3 WHERE id=$1`, policyID, state, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.policy." + map[string]string{"active": "enabled", "disabled": "disabled"}[state],
			RealmID: realmID, Actor: actor, Category: "authorization", Target: &audit.Ref{Type: "policy", ID: policyID}})
		return err
	})
	activeCache.invalidate(realmID)
	return err
}

// GetPolicy returns a policy.
func (s *Service) GetPolicy(ctx context.Context, realmID, id string) (*Policy, error) {
	p, err := scanPolicy(s.d.DB.Pool.QueryRow(ctx, `SELECT `+policyCols+` FROM policies WHERE realm_id=$1 AND (id=$2 OR name=$2)`, realmID, id))
	if storage.IsNoRows(err) {
		return nil, problem.ErrNotFound
	}
	return p, err
}

// ListPolicies lists a realm's policies.
func (s *Service) ListPolicies(ctx context.Context, realmID string) ([]*Policy, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+policyCols+` FROM policies WHERE realm_id=$1 ORDER BY name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Versions lists a policy's revisions.
func (s *Service) Versions(ctx context.Context, realmID, policyID string) ([]*PolicyVersion, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+versionCols+` FROM policy_versions v WHERE policy_id=$1
		AND EXISTS (SELECT 1 FROM policies p WHERE p.id=v.policy_id AND p.realm_id=$2) ORDER BY version_number`, policyID, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*PolicyVersion{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Version returns one revision of a realm's policy.
func (s *Service) Version(ctx context.Context, realmID, policyID string, number int) (*PolicyVersion, error) {
	if _, err := s.GetPolicy(ctx, realmID, policyID); err != nil {
		return nil, err
	}
	return s.version(ctx, s.d.DB.Pool, policyID, number)
}

// ActivePolicies returns published, enabled policies for a realm (cached for
// PolicyCacheTTL).
func (s *Service) ActivePolicies(ctx context.Context, realmID string) ([]*ActivePolicy, error) {
	now := time.Now()
	activeCache.mu.Lock()
	if e, ok := activeCache.entries[realmID]; ok && now.Sub(e.at) < PolicyCacheTTL {
		activeCache.mu.Unlock()
		return e.policies, nil
	}
	activeCache.mu.Unlock()
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT p.id, p.name, p.scope_type, coalesce(p.scope_id,''), v.version_number, v.definition
		FROM policies p JOIN policy_versions v ON v.policy_id=p.id AND v.version_number=p.active_version
		WHERE p.realm_id=$1 AND p.state='active' ORDER BY p.name`, realmID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ActivePolicy{}
	for rows.Next() {
		ap := &ActivePolicy{}
		var raw []byte
		if err := rows.Scan(&ap.ID, &ap.Name, &ap.ScopeType, &ap.ScopeID, &ap.Version, &raw); err != nil {
			return nil, err
		}
		def, err := ParsePolicy(raw)
		if err != nil {
			// A stored definition that no longer validates denies everything it
			// targets rather than silently dropping out (AZ-007).
			def = &PolicyDefinition{Target: PolicyTarget{Actions: []string{"*"}}, Rules: []PolicyRule{{ID: "invalid", Effect: "deny", ReasonCode: "POLICY_INVALID"}}}
		}
		ap.Definition = def
		out = append(out, ap)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	activeCache.mu.Lock()
	activeCache.entries[realmID] = policyCacheEntry{at: now, policies: out}
	activeCache.mu.Unlock()
	return out, nil
}

// Diff renders a line diff between two canonical definitions (AZ-017).
func Diff(a, b json.RawMessage) string {
	norm := func(r json.RawMessage) []string {
		var v any
		if json.Unmarshal(r, &v) != nil {
			return strings.Split(string(r), "\n")
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		return strings.Split(string(out), "\n")
	}
	x, y := norm(a), norm(b)
	// Longest common subsequence diff (bounded inputs: definitions ≤ 64 KiB).
	n, m := len(x), len(y)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var buf bytes.Buffer
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			buf.WriteString("  " + x[i] + "\n")
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			buf.WriteString("- " + x[i] + "\n")
			i++
		default:
			buf.WriteString("+ " + y[j] + "\n")
			j++
		}
	}
	for ; i < n; i++ {
		buf.WriteString("- " + x[i] + "\n")
	}
	for ; j < m; j++ {
		buf.WriteString("+ " + y[j] + "\n")
	}
	return buf.String()
}
