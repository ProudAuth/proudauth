package authorization

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// Access review campaigns (AZ-025): who holds which role in a scope is
// snapshotted when the campaign starts; named reviewers decide keep or
// revoke per item (never about their own access); closing applies the
// decisions (and the campaign's rule for undecided items) and keeps every
// decision and outcome as evidence. The evidence documents a review; it is
// not a regulatory certification.

const maxReviewItems = 10000

// AccessReview is a campaign.
type AccessReview struct {
	ID             string         `json:"id"`
	OrganizationID string         `json:"organization_id,omitempty"`
	Name           string         `json:"name"`
	Description    string         `json:"description,omitempty"`
	State          string         `json:"state"`
	ReviewerIDs    []string       `json:"reviewer_ids"`
	RoleIDs        []string       `json:"role_ids"`
	PrivilegedOnly bool           `json:"privileged_only"`
	OnNoDecision   string         `json:"on_no_decision"`
	DueAt          time.Time      `json:"due_at"`
	Overdue        bool           `json:"overdue"`
	ItemsTotal     int            `json:"items_total"`
	Decided        int            `json:"items_decided"`
	Summary        map[string]int `json:"summary,omitempty"`
	CreatedByID    string         `json:"created_by_id"`
	CreatedAt      time.Time      `json:"created_at"`
	ClosedByID     string         `json:"closed_by_id,omitempty"`
	ClosedAt       *time.Time     `json:"closed_at,omitempty"`
}

// ReviewItem is one assignment under review.
type ReviewItem struct {
	ID           string     `json:"id"`
	AssignmentID string     `json:"assignment_id"`
	RoleID       string     `json:"role_id"`
	RoleName     string     `json:"role_name"`
	Subject      Subject    `json:"subject"`
	Scope        Scope      `json:"scope"`
	Source       string     `json:"source,omitempty"`
	GrantedByID  string     `json:"granted_by_id,omitempty"`
	GrantedAt    *time.Time `json:"granted_at,omitempty"`
	Privileged   bool       `json:"privileged"`
	Decision     string     `json:"decision,omitempty"`
	DecidedByID  string     `json:"decided_by_id,omitempty"`
	DecidedAt    *time.Time `json:"decided_at,omitempty"`
	Comment      string     `json:"comment,omitempty"`
	Outcome      string     `json:"outcome,omitempty"`
	AppliedAt    *time.Time `json:"applied_at,omitempty"`
}

// ReviewInput starts a campaign.
type ReviewInput struct {
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	OrganizationID string    `json:"organization_id"`
	ReviewerIDs    []string  `json:"reviewer_ids"`
	RoleIDs        []string  `json:"role_ids"`
	PrivilegedOnly bool      `json:"privileged_only"`
	OnNoDecision   string    `json:"on_no_decision"`
	DueAt          time.Time `json:"due_at"`
}

const reviewCols = `r.id, coalesce(r.organization_id,''), r.name, coalesce(r.description,''), r.state, r.reviewer_ids, r.role_ids, r.privileged_only,
	r.on_no_decision, r.due_at, r.items_total, (SELECT count(*) FROM access_review_items i WHERE i.review_id=r.id AND i.decision IS NOT NULL), r.summary,
	r.created_by_id, r.created_at, coalesce(r.closed_by_id,''), r.closed_at`

func (s *Service) scanReview(row pgx.Row) (*AccessReview, error) {
	var r AccessReview
	var summary []byte
	if err := row.Scan(&r.ID, &r.OrganizationID, &r.Name, &r.Description, &r.State, &r.ReviewerIDs, &r.RoleIDs, &r.PrivilegedOnly, &r.OnNoDecision,
		&r.DueAt, &r.ItemsTotal, &r.Decided, &summary, &r.CreatedByID, &r.CreatedAt, &r.ClosedByID, &r.ClosedAt); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(summary, &r.Summary)
	r.Overdue = r.State == "open" && !r.DueAt.After(s.d.Now())
	return &r, nil
}

const itemCols = `id, assignment_id, role_id, role_name, subject_type, subject_id, scope_type, scope_id, coalesce(source,''), coalesce(granted_by_id,''),
	granted_at, privileged, coalesce(decision,''), coalesce(decided_by_id,''), decided_at, coalesce(comment,''), coalesce(outcome,''), applied_at`

func scanItem(row pgx.Row) (*ReviewItem, error) {
	var it ReviewItem
	err := row.Scan(&it.ID, &it.AssignmentID, &it.RoleID, &it.RoleName, &it.Subject.Type, &it.Subject.ID, &it.Scope.Type, &it.Scope.ID, &it.Source,
		&it.GrantedByID, &it.GrantedAt, &it.Privileged, &it.Decision, &it.DecidedByID, &it.DecidedAt, &it.Comment, &it.Outcome, &it.AppliedAt)
	return &it, err
}

// CreateReview starts a campaign and snapshots the assignments it covers.
func (s *Service) CreateReview(ctx context.Context, realmID string, in ReviewInput, auditActor audit.Ref) (*AccessReview, error) {
	verr := problem.ErrValidation
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 || len(in.Description) > 2000 {
		return nil, verr.WithField("name", "required, at most 200 characters (description at most 2000)")
	}
	if len(in.ReviewerIDs) == 0 || len(in.ReviewerIDs) > 20 {
		return nil, verr.WithField("reviewer_ids", "1 to 20 reviewers")
	}
	if in.OnNoDecision == "" {
		in.OnNoDecision = "keep"
	}
	if in.OnNoDecision != "keep" && in.OnNoDecision != "revoke" {
		return nil, verr.WithField("on_no_decision", "keep or revoke")
	}
	now := s.d.Now()
	if !in.DueAt.After(now) || in.DueAt.After(now.Add(366*24*time.Hour)) {
		return nil, verr.WithField("due_at", "in the future, within a year")
	}
	if in.RoleIDs == nil {
		in.RoleIDs = []string{}
	}
	var out *AccessReview
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		for _, u := range in.ReviewerIDs {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT true FROM users WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, u).Scan(&ok); err != nil {
				return verr.WithField("reviewer_ids", "unknown or inactive reviewer "+u)
			}
		}
		if in.OrganizationID != "" {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT true FROM organizations WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, in.OrganizationID).Scan(&ok); err != nil {
				return verr.WithField("organization_id", "unknown or inactive organization")
			}
		}
		id := ids.New("arv")
		if _, err := tx.Exec(ctx, `INSERT INTO access_reviews (id, realm_id, organization_id, name, description, state, reviewer_ids, role_ids, privileged_only,
			on_no_decision, due_at, created_by_id, created_at) VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8,$9,$10,$11,$12)`, id, realmID, nilIfEmpty(in.OrganizationID),
			in.Name, nilIfEmpty(in.Description), in.ReviewerIDs, in.RoleIDs, in.PrivilegedOnly, in.OnNoDecision, in.DueAt, auditActor.ID, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT ra.id, ra.role_id, ro.name, ra.subject_type, ra.subject_id, ra.scope_type, ra.scope_id, ra.source,
			coalesce(ra.granted_by_id,''), ra.created_at FROM role_assignments ra JOIN roles ro ON ro.realm_id=ra.realm_id AND ro.id=ra.role_id
			WHERE ra.realm_id=$1 AND ($2='' OR (ra.scope_type='organization' AND ra.scope_id=$2)) AND (cardinality($3::text[])=0 OR ra.role_id = ANY($3))
			ORDER BY ra.id LIMIT $4`, realmID, in.OrganizationID, in.RoleIDs, maxReviewItems+1)
		if err != nil {
			return err
		}
		type row struct {
			assignment, role, roleName, subjType, subjID, scopeType, scopeID, source, grantedBy string
			grantedAt                                                                           time.Time
		}
		var list []row
		for rows.Next() {
			var x row
			if err := rows.Scan(&x.assignment, &x.role, &x.roleName, &x.subjType, &x.subjID, &x.scopeType, &x.scopeID, &x.source, &x.grantedBy, &x.grantedAt); err != nil {
				rows.Close()
				return err
			}
			list = append(list, x)
		}
		rows.Close()
		if len(list) > maxReviewItems {
			return problem.ErrValidation.WithDetail("the campaign would cover more than 10000 assignments; narrow it by organization or roles")
		}
		privileged := map[string]bool{}
		n := 0
		for _, x := range list {
			p, ok := privileged[x.role]
			if !ok {
				if role, err := s.Role(ctx, tx, realmID, x.role); err == nil {
					p = s.IsPrivilegedRole(ctx, tx, realmID, role)
				}
				privileged[x.role] = p
			}
			if in.PrivilegedOnly && !p {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO access_review_items (id, review_id, assignment_id, role_id, role_name, subject_type, subject_id, scope_type,
				scope_id, source, granted_by_id, granted_at, privileged) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, ids.New("ari"), id, x.assignment,
				x.role, x.roleName, x.subjType, x.subjID, x.scopeType, x.scopeID, nilIfEmpty(x.source), nilIfEmpty(x.grantedBy), x.grantedAt, p); err != nil {
				return err
			}
			n++
		}
		if _, err := tx.Exec(ctx, `UPDATE access_reviews SET items_total=$2 WHERE id=$1`, id, n); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "access_review.started", RealmID: realmID, OrgID: in.OrganizationID, Actor: auditActor,
			Category: "authorization", Target: &audit.Ref{Type: "access_review", ID: id}, Metadata: map[string]any{"name": in.Name, "items": n,
				"reviewers": in.ReviewerIDs, "due_at": in.DueAt, "on_no_decision": in.OnNoDecision}}); err != nil {
			return err
		}
		out, err = s.scanReview(tx.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_reviews r WHERE r.id=$1`, id))
		return err
	})
	return out, err
}

// GetReview returns a campaign; reviewerID, when set, must be one of its
// reviewers.
func (s *Service) GetReview(ctx context.Context, q storage.Querier, realmID, id, reviewerID string) (*AccessReview, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	r, err := s.scanReview(q.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_reviews r WHERE r.realm_id=$1 AND r.id=$2`, realmID, id))
	if err != nil || (reviewerID != "" && !slices.Contains(r.ReviewerIDs, reviewerID)) {
		return nil, problem.ErrNotFound
	}
	return r, nil
}

// ListReviews lists campaigns, optionally by state or for one reviewer.
func (s *Service) ListReviews(ctx context.Context, realmID, state, reviewerID string) ([]*AccessReview, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+reviewCols+` FROM access_reviews r WHERE r.realm_id=$1 AND ($2='' OR r.state=$2)
		AND ($3='' OR $3 = ANY(r.reviewer_ids)) ORDER BY r.created_at DESC LIMIT 200`, realmID, state, reviewerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AccessReview{}
	for rows.Next() {
		r, err := s.scanReview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ReviewItems lists a campaign's items after a cursor, optionally by
// decision ("undecided", "keep", "revoke").
func (s *Service) ReviewItems(ctx context.Context, reviewID, decision, after string, limit int) ([]*ReviewItem, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+itemCols+` FROM access_review_items WHERE review_id=$1 AND ($2='' OR ($2='undecided' AND decision IS NULL)
		OR decision=$2) AND ($3='' OR id > $3) ORDER BY id LIMIT $4`, reviewID, decision, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*ReviewItem{}
	for rows.Next() {
		it, err := scanItem(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// DecideItem records a reviewer's decision; it can change until the
// campaign closes. Nobody certifies their own access.
func (s *Service) DecideItem(ctx context.Context, realmID, reviewerID, reviewID, itemID, decision, comment string) (*ReviewItem, error) {
	if decision != "keep" && decision != "revoke" {
		return nil, problem.ErrValidation.WithField("decision", "keep or revoke")
	}
	if len(comment) > 1000 {
		return nil, problem.ErrValidation.WithField("comment", "at most 1000 characters")
	}
	if decision == "revoke" && strings.TrimSpace(comment) == "" {
		return nil, problem.ErrValidation.WithField("comment", "required when revoking")
	}
	var out *ReviewItem
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		r, err := s.scanReview(tx.QueryRow(ctx, `SELECT `+reviewCols+` FROM access_reviews r WHERE r.realm_id=$1 AND r.id=$2 FOR UPDATE OF r`, realmID, reviewID))
		if err != nil || !slices.Contains(r.ReviewerIDs, reviewerID) {
			return problem.ErrNotFound
		}
		if r.State != "open" {
			return problem.ErrConflict.WithDetail("the campaign is " + r.State)
		}
		it, err := scanItem(tx.QueryRow(ctx, `SELECT `+itemCols+` FROM access_review_items WHERE review_id=$1 AND id=$2 FOR UPDATE`, reviewID, itemID))
		if err != nil {
			return problem.ErrNotFound
		}
		if it.Subject.Type == SubjectUser && it.Subject.ID == reviewerID {
			return problem.ErrForbidden.WithDetail("reviewers do not decide on their own access")
		}
		if _, err := tx.Exec(ctx, `UPDATE access_review_items SET decision=$2, decided_by_id=$3, decided_at=$4, comment=$5 WHERE id=$1`,
			itemID, decision, reviewerID, s.d.Now(), nilIfEmpty(comment)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "access_review.item_decided", RealmID: realmID, OrgID: r.OrganizationID,
			Actor: audit.Ref{Type: "user", ID: reviewerID}, Subject: &audit.Ref{Type: it.Subject.Type, ID: it.Subject.ID}, Category: "authorization",
			Target: &audit.Ref{Type: "access_review", ID: reviewID}, Metadata: map[string]any{"item_id": itemID, "assignment_id": it.AssignmentID,
				"role_id": it.RoleID, "decision": decision}}); err != nil {
			return err
		}
		out, err = scanItem(tx.QueryRow(ctx, `SELECT `+itemCols+` FROM access_review_items WHERE id=$1`, itemID))
		return err
	})
	return out, err
}

// CloseReview applies the campaign: revocations (decided, or undecided when
// on_no_decision is revoke) remove the assignment if it still exists; the
// rest are kept. Outcomes are recorded per item.
func (s *Service) CloseReview(ctx context.Context, realmID, id string, auditActor audit.Ref) (*AccessReview, error) {
	r, err := s.GetReview(ctx, nil, realmID, id, "")
	if err != nil {
		return nil, err
	}
	if r.State != "open" {
		return nil, problem.ErrConflict.WithDetail("the campaign is " + r.State)
	}
	summary := map[string]int{"kept": 0, "revoked": 0, "already_removed": 0, "revoke_failed": 0, "undecided": 0}
	after := ""
	for {
		items, err := s.ReviewItems(ctx, id, "", after, 500)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}
		for _, it := range items {
			after = it.ID
			if it.Outcome != "" {
				summary[it.Outcome]++
				continue
			}
			if it.Decision == "" {
				summary["undecided"]++
			}
			revoke := it.Decision == "revoke" || (it.Decision == "" && r.OnNoDecision == "revoke")
			outcome := "kept"
			if revoke {
				err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
					return s.UnassignTx(ctx, tx, realmID, it.AssignmentID, nil, auditActor, true)
				})
				switch {
				case err == nil:
					outcome = "revoked"
				case problem.Is(err, problem.ErrNotFound):
					outcome = "already_removed"
				default:
					// For example the last owner of an organization: kept,
					// and reported.
					outcome = "revoke_failed"
				}
			}
			summary[outcome]++
			if _, err := s.d.DB.Pool.Exec(ctx, `UPDATE access_review_items SET outcome=$2, applied_at=$3 WHERE id=$1`, it.ID, outcome, s.d.Now()); err != nil {
				return nil, err
			}
		}
	}
	err = s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		sum, _ := json.Marshal(summary)
		if _, err := tx.Exec(ctx, `UPDATE access_reviews SET state='closed', closed_by_id=$2, closed_at=$3, summary=$4 WHERE id=$1 AND state='open'`,
			id, auditActor.ID, s.d.Now(), sum); err != nil {
			return err
		}
		_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "access_review.closed", RealmID: realmID, OrgID: r.OrganizationID, Actor: auditActor,
			Category: "authorization", Target: &audit.Ref{Type: "access_review", ID: id}, Metadata: map[string]any{"summary": summary}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.GetReview(ctx, nil, realmID, id, "")
}

// CancelReview ends a campaign without applying anything.
func (s *Service) CancelReview(ctx context.Context, realmID, id string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE access_reviews SET state='cancelled', closed_by_id=$3, closed_at=$4 WHERE realm_id=$1 AND id=$2 AND state='open'`,
			realmID, id, auditActor.ID, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrConflict.WithDetail("only an open campaign can be cancelled")
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "access_review.cancelled", RealmID: realmID, Actor: auditActor, Category: "authorization",
			Target: &audit.Ref{Type: "access_review", ID: id}})
		return err
	})
}

// CloseDueReviews closes open campaigns past their due date (the sweep).
func (s *Service) CloseDueReviews(ctx context.Context) (int, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT realm_id, id FROM access_reviews WHERE state='open' AND due_at <= $1 LIMIT 20`, s.d.Now())
	if err != nil {
		return 0, err
	}
	var due [][2]string
	for rows.Next() {
		var x [2]string
		if err := rows.Scan(&x[0], &x[1]); err != nil {
			rows.Close()
			return 0, err
		}
		due = append(due, x)
	}
	rows.Close()
	n := 0
	for _, x := range due {
		if _, err := s.CloseReview(ctx, x[0], x[1], audit.System); err != nil && !problem.Is(err, problem.ErrConflict) {
			return n, err
		}
		n++
	}
	return n, nil
}

// ReviewEvidence is a campaign's complete record for export.
type ReviewEvidence struct {
	Review      *AccessReview `json:"review"`
	Items       []*ReviewItem `json:"items"`
	GeneratedAt time.Time     `json:"generated_at"`
	Statement   string        `json:"statement"`
}

// Evidence returns every item with its decision and outcome.
func (s *Service) Evidence(ctx context.Context, realmID, id string, auditActor audit.Ref) (*ReviewEvidence, error) {
	r, err := s.GetReview(ctx, nil, realmID, id, "")
	if err != nil {
		return nil, err
	}
	ev := &ReviewEvidence{Review: r, Items: []*ReviewItem{}, GeneratedAt: s.d.Now(),
		Statement: "Records the decisions of the named reviewers and their outcome. It documents an access review; it is not a regulatory certification."}
	after := ""
	for {
		items, err := s.ReviewItems(ctx, id, "", after, 1000)
		if err != nil {
			return nil, err
		}
		if len(items) == 0 {
			break
		}
		ev.Items = append(ev.Items, items...)
		after = items[len(items)-1].ID
	}
	_, _ = s.d.Audit.Record(ctx, s.d.DB.Pool, audit.Event{Type: "access_review.evidence_exported", RealmID: realmID, OrgID: r.OrganizationID, Actor: auditActor,
		Category: "authorization", Target: &audit.Ref{Type: "access_review", ID: id}, Metadata: map[string]any{"items": len(ev.Items)}})
	return ev, nil
}
