package authorization

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/storage"
)

// Just-in-time elevation (AZ-024): a role the person holds only for a
// bounded time, on request, with a reason, normally approved by someone
// else, ending on its own. It is an ordinary role assignment (source
// "elevation") while it lasts, so every decision and token sees it; it is
// not impersonation: the person acts as themselves.

// Elevation durations: at least five minutes, at most seven days.
const (
	minElevation = 5 * time.Minute
	maxElevation = 7 * 24 * time.Hour
)

// Eligibility lets a person ask for a role at a scope.
type Eligibility struct {
	ID                 string    `json:"id"`
	UserID             string    `json:"user_id"`
	RoleID             string    `json:"role_id"`
	RoleName           string    `json:"role_name"`
	Scope              Scope     `json:"scope"`
	MaxDurationSeconds int       `json:"max_duration_seconds"`
	RequiresApproval   bool      `json:"requires_approval"`
	State              string    `json:"state"`
	CreatedByID        string    `json:"created_by_id"`
	CreatedAt          time.Time `json:"created_at"`
}

// EligibilityInput creates an eligibility.
type EligibilityInput struct {
	UserID             string `json:"user_id"`
	RoleID             string `json:"role_id"`
	Scope              Scope  `json:"scope"`
	MaxDurationSeconds int    `json:"max_duration_seconds"`
	RequiresApproval   *bool  `json:"requires_approval"`
}

// Elevation is one request and, once granted, its time-bound assignment.
type Elevation struct {
	ID              string     `json:"id"`
	EligibilityID   string     `json:"eligibility_id"`
	UserID          string     `json:"user_id"`
	RoleID          string     `json:"role_id"`
	RoleName        string     `json:"role_name"`
	Scope           Scope      `json:"scope"`
	Reason          string     `json:"reason"`
	DurationSeconds int        `json:"duration_seconds"`
	State           string     `json:"state"`
	RequestedAt     time.Time  `json:"requested_at"`
	DecidedByID     string     `json:"decided_by_id,omitempty"`
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	StartsAt        *time.Time `json:"starts_at,omitempty"`
	EndsAt          *time.Time `json:"ends_at,omitempty"`
	AssignmentID    string     `json:"assignment_id,omitempty"`
}

const eligibilityCols = `e.id, e.user_id, e.role_id, r.name, e.scope_type, e.scope_id, e.max_duration_seconds, e.requires_approval, e.state, e.created_by_id, e.created_at`

func scanEligibility(row pgx.Row) (*Eligibility, error) {
	var e Eligibility
	err := row.Scan(&e.ID, &e.UserID, &e.RoleID, &e.RoleName, &e.Scope.Type, &e.Scope.ID, &e.MaxDurationSeconds, &e.RequiresApproval, &e.State,
		&e.CreatedByID, &e.CreatedAt)
	return &e, err
}

const elevationCols = `x.id, x.eligibility_id, x.user_id, e.role_id, r.name, e.scope_type, e.scope_id, x.reason, x.duration_seconds, x.state, x.requested_at,
	coalesce(x.decided_by_id,''), x.decided_at, x.starts_at, x.ends_at, coalesce(x.assignment_id,'')`

func (s *Service) scanElevation(row pgx.Row) (*Elevation, error) {
	var el Elevation
	if err := row.Scan(&el.ID, &el.EligibilityID, &el.UserID, &el.RoleID, &el.RoleName, &el.Scope.Type, &el.Scope.ID, &el.Reason, &el.DurationSeconds,
		&el.State, &el.RequestedAt, &el.DecidedByID, &el.DecidedAt, &el.StartsAt, &el.EndsAt, &el.AssignmentID); err != nil {
		return nil, err
	}
	// The sweep removes the assignment at the deadline; until it runs, the
	// view already says it is over.
	if el.State == "active" && el.EndsAt != nil && !el.EndsAt.After(s.d.Now()) {
		el.State = "expired"
	}
	return &el, nil
}

const elevationFrom = ` FROM elevations x JOIN elevation_eligibilities e ON e.id=x.eligibility_id JOIN roles r ON r.realm_id=e.realm_id AND r.id=e.role_id`

// CreateEligibility makes a person eligible for a role. Only someone who
// could assign the role at that scope may delegate the right to ask for it.
func (s *Service) CreateEligibility(ctx context.Context, realmID string, actor Subject, in EligibilityInput, auditActor audit.Ref) (*Eligibility, error) {
	if in.MaxDurationSeconds == 0 {
		in.MaxDurationSeconds = 3600
	}
	if d := time.Duration(in.MaxDurationSeconds) * time.Second; d < minElevation || d > maxElevation {
		return nil, problem.ErrValidation.WithField("max_duration_seconds", "300..604800 (five minutes to seven days)")
	}
	approval := true
	if in.RequiresApproval != nil {
		approval = *in.RequiresApproval
	}
	if in.Scope.Type == "" {
		in.Scope = Scope{Type: ScopeRealm, ID: realmID}
	}
	var out *Eligibility
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		role, err := s.Role(ctx, tx, realmID, in.RoleID)
		if err != nil {
			return problem.ErrValidation.WithField("role_id", "unknown role")
		}
		if !roleFitsScope(role, in.Scope) {
			return problem.ErrValidation.WithField("scope", "role boundary does not match the scope")
		}
		if err := s.CheckAssignable(ctx, tx, realmID, actor, role, in.Scope); err != nil {
			return err
		}
		// A privileged role reached without anyone else's approval is a
		// standing grant in disguise.
		if !approval && s.IsPrivilegedRole(ctx, tx, realmID, role) {
			return problem.ErrValidation.WithField("requires_approval", "privileged roles always need approval")
		}
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT true FROM users WHERE realm_id=$1 AND id=$2 AND state='active' AND NOT is_guest`, realmID, in.UserID).Scan(&ok); err != nil {
			return problem.ErrValidation.WithField("user_id", "an active, non-guest user")
		}
		if in.UserID == actor.ID {
			return problem.ErrValidation.WithField("user_id", "make someone else eligible")
		}
		id := ids.New("elg")
		if _, err := tx.Exec(ctx, `INSERT INTO elevation_eligibilities (id, realm_id, user_id, role_id, scope_type, scope_id, max_duration_seconds,
			requires_approval, created_by_id, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, realmID, in.UserID, role.ID, in.Scope.Type, in.Scope.ID,
			in.MaxDurationSeconds, approval, auditActor.ID, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.elevation.eligibility_created", RealmID: realmID, OrgID: orgOf(in.Scope),
			Actor: auditActor, Subject: &audit.Ref{Type: "user", ID: in.UserID}, Category: "authorization", Target: &audit.Ref{Type: "role", ID: role.ID},
			Metadata: map[string]any{"eligibility_id": id, "max_duration_seconds": in.MaxDurationSeconds, "requires_approval": approval}}); err != nil {
			return err
		}
		out, err = scanEligibility(tx.QueryRow(ctx, `SELECT `+eligibilityCols+` FROM elevation_eligibilities e JOIN roles r ON r.realm_id=e.realm_id
			AND r.id=e.role_id WHERE e.id=$1`, id))
		return err
	})
	return out, err
}

func orgOf(sc Scope) string {
	if sc.Type == ScopeOrganization {
		return sc.ID
	}
	return ""
}

// ListEligibilities lists active eligibilities, optionally for one person.
func (s *Service) ListEligibilities(ctx context.Context, realmID, userID string) ([]*Eligibility, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT `+eligibilityCols+` FROM elevation_eligibilities e JOIN roles r ON r.realm_id=e.realm_id AND r.id=e.role_id
		WHERE e.realm_id=$1 AND e.state='active' AND ($2='' OR e.user_id=$2) ORDER BY e.created_at DESC LIMIT 500`, realmID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Eligibility{}
	for rows.Next() {
		e, err := scanEligibility(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RevokeEligibility ends an eligibility; pending requests under it are
// cancelled and an elevation in progress ends now.
func (s *Service) RevokeEligibility(ctx context.Context, realmID, id string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE elevation_eligibilities SET state='revoked' WHERE realm_id=$1 AND id=$2 AND state='active'`, realmID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		now := s.d.Now()
		if _, err := tx.Exec(ctx, `UPDATE elevations SET state='cancelled', decided_at=$2 WHERE eligibility_id=$1 AND state='pending'`, id, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id, assignment_id FROM elevations WHERE eligibility_id=$1 AND state='active' AND assignment_id IS NOT NULL`, id)
		if err != nil {
			return err
		}
		var active [][2]string
		for rows.Next() {
			var x [2]string
			if err := rows.Scan(&x[0], &x[1]); err != nil {
				rows.Close()
				return err
			}
			active = append(active, x)
		}
		rows.Close()
		for _, x := range active {
			if err := s.endTx(ctx, tx, realmID, x[0], x[1], "ended", auditActor); err != nil {
				return err
			}
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.elevation.eligibility_revoked", RealmID: realmID, Actor: auditActor,
			Category: "authorization", Metadata: map[string]any{"eligibility_id": id, "ended": len(active)}})
		return err
	})
}

// ElevationRequest asks for an eligible role.
type ElevationRequest struct {
	EligibilityID   string `json:"eligibility_id"`
	DurationSeconds int    `json:"duration_seconds"`
	Reason          string `json:"reason"`
}

// RequestElevation records a request; without required approval the role is
// granted at once.
func (s *Service) RequestElevation(ctx context.Context, realmID, userID string, in ElevationRequest) (*Elevation, error) {
	in.Reason = strings.TrimSpace(in.Reason)
	if len(in.Reason) < 3 || len(in.Reason) > 500 {
		return nil, problem.ErrValidation.WithField("reason", "required: 3 to 500 characters")
	}
	var out *Elevation
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		el, err := scanEligibility(tx.QueryRow(ctx, `SELECT `+eligibilityCols+` FROM elevation_eligibilities e JOIN roles r ON r.realm_id=e.realm_id
			AND r.id=e.role_id WHERE e.realm_id=$1 AND e.id=$2 AND e.user_id=$3 AND e.state='active' FOR UPDATE OF e`, realmID, in.EligibilityID, userID))
		if err != nil {
			return problem.ErrNotFound.WithDetail("no such eligibility")
		}
		if in.DurationSeconds == 0 {
			in.DurationSeconds = el.MaxDurationSeconds
		}
		if d := time.Duration(in.DurationSeconds) * time.Second; d < minElevation || in.DurationSeconds > el.MaxDurationSeconds {
			return problem.ErrValidation.WithField("duration_seconds", "300 up to the eligibility's maximum")
		}
		var open bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM elevations WHERE eligibility_id=$1 AND (state='pending' OR (state='active' AND ends_at > $2)))`,
			el.ID, s.d.Now()).Scan(&open); err != nil {
			return err
		}
		if open {
			return problem.ErrConflict.WithDetail("a request under this eligibility is already pending or active")
		}
		id := ids.New("elv")
		if _, err := tx.Exec(ctx, `INSERT INTO elevations (id, realm_id, eligibility_id, user_id, reason, duration_seconds, state, requested_at)
			VALUES ($1,$2,$3,$4,$5,$6,'pending',$7)`, id, realmID, el.ID, userID, in.Reason, in.DurationSeconds, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.elevation.requested", RealmID: realmID, OrgID: orgOf(el.Scope),
			Actor: audit.Ref{Type: "user", ID: userID}, Category: "authorization", Target: &audit.Ref{Type: "role", ID: el.RoleID},
			ReasonCode: "ELEVATION", Metadata: map[string]any{"elevation_id": id, "reason": in.Reason, "duration_seconds": in.DurationSeconds}}); err != nil {
			return err
		}
		if !el.RequiresApproval {
			if err := s.activateTx(ctx, tx, realmID, id, ""); err != nil {
				return err
			}
		}
		out, err = s.scanElevation(tx.QueryRow(ctx, `SELECT `+elevationCols+elevationFrom+` WHERE x.id=$1`, id))
		return err
	})
	return out, err
}

// activateTx grants the role until the deadline. The eligibility was
// created by someone who could assign it, and an approver who could assign
// it agreed (when required), so the delegation ceiling is not re-applied to
// the requester; separation of duties still is.
func (s *Service) activateTx(ctx context.Context, tx pgx.Tx, realmID, id, approverID string) error {
	el, err := s.scanElevation(tx.QueryRow(ctx, `SELECT `+elevationCols+elevationFrom+` WHERE x.id=$1 FOR UPDATE OF x`, id))
	if err != nil {
		return err
	}
	now := s.d.Now()
	ends := now.Add(time.Duration(el.DurationSeconds) * time.Second)
	a, err := s.AssignTx(ctx, tx, realmID, nil, AssignInput{RoleID: el.RoleID, Subject: Subject{Type: SubjectUser, ID: el.UserID}, Scope: el.Scope,
		ExpiresAt: &ends, Reason: "elevation: " + el.Reason, ApproverID: approverID, Source: "elevation", SkipCeiling: true},
		audit.Ref{Type: "user", ID: el.UserID})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE elevations SET state='active', starts_at=$2, ends_at=$3, assignment_id=$4 WHERE id=$1`, id, now, ends, a.ID); err != nil {
		return err
	}
	_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.elevation.started", RealmID: realmID, OrgID: orgOf(el.Scope),
		Actor: audit.Ref{Type: "user", ID: el.UserID}, Subject: &audit.Ref{Type: "user", ID: el.UserID}, Category: "authorization",
		Target: &audit.Ref{Type: "role", ID: el.RoleID}, Metadata: map[string]any{"elevation_id": id, "assignment_id": a.ID, "ends_at": ends, "approved_by": approverID}})
	return err
}

// DecideElevation approves or rejects a pending request. The approver is
// someone else who could assign the role at that scope.
func (s *Service) DecideElevation(ctx context.Context, realmID string, approver Subject, id string, approve bool, auditActor audit.Ref) (*Elevation, error) {
	var out *Elevation
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		el, err := s.scanElevation(tx.QueryRow(ctx, `SELECT `+elevationCols+elevationFrom+` WHERE x.realm_id=$1 AND x.id=$2 FOR UPDATE OF x`, realmID, id))
		if err != nil {
			return problem.ErrNotFound
		}
		if el.State != "pending" {
			return problem.ErrConflict.WithDetail("the request is " + el.State)
		}
		if approver.ID == el.UserID {
			return problem.ErrForbidden.WithDetail("self-approval is not permitted")
		}
		role, err := s.Role(ctx, tx, realmID, el.RoleID)
		if err != nil {
			return err
		}
		if err := s.CheckAssignable(ctx, tx, realmID, approver, role, el.Scope); err != nil {
			return problem.ErrForbidden.WithDetail("the approver could not assign this role")
		}
		if _, err := tx.Exec(ctx, `UPDATE elevations SET decided_by_id=$2, decided_at=$3, state=CASE WHEN $4 THEN state ELSE 'rejected' END WHERE id=$1`,
			id, approver.ID, s.d.Now(), approve); err != nil {
			return err
		}
		typ := "authorization.elevation.rejected"
		if approve {
			typ = "authorization.elevation.approved"
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: typ, RealmID: realmID, OrgID: orgOf(el.Scope), Actor: auditActor,
			Subject: &audit.Ref{Type: "user", ID: el.UserID}, Category: "authorization", Target: &audit.Ref{Type: "role", ID: el.RoleID},
			Metadata: map[string]any{"elevation_id": id}}); err != nil {
			return err
		}
		if approve {
			if err := s.activateTx(ctx, tx, realmID, id, approver.ID); err != nil {
				return err
			}
		}
		out, err = s.scanElevation(tx.QueryRow(ctx, `SELECT `+elevationCols+elevationFrom+` WHERE x.id=$1`, id))
		return err
	})
	return out, err
}

// EndElevation ends an elevation early (the person, or an administrator) or
// cancels a pending request.
func (s *Service) EndElevation(ctx context.Context, realmID, id, userID string, auditActor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		el, err := s.scanElevation(tx.QueryRow(ctx, `SELECT `+elevationCols+elevationFrom+` WHERE x.realm_id=$1 AND x.id=$2 AND ($3='' OR x.user_id=$3)
			FOR UPDATE OF x`, realmID, id, userID))
		if err != nil {
			return problem.ErrNotFound
		}
		switch el.State {
		case "pending":
			_, err := tx.Exec(ctx, `UPDATE elevations SET state='cancelled', decided_at=$2 WHERE id=$1`, id, s.d.Now())
			return err
		case "active":
			return s.endTx(ctx, tx, realmID, id, el.AssignmentID, "ended", auditActor)
		default:
			return problem.ErrConflict.WithDetail("the elevation is " + el.State)
		}
	})
}

func (s *Service) endTx(ctx context.Context, tx pgx.Tx, realmID, id, assignmentID, state string, auditActor audit.Ref) error {
	if assignmentID != "" {
		if err := s.UnassignTx(ctx, tx, realmID, assignmentID, nil, auditActor, true); err != nil && !problem.Is(err, problem.ErrNotFound) {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE elevations SET state=$2, ends_at=LEAST(coalesce(ends_at, $3), $3) WHERE id=$1`, id, state, s.d.Now()); err != nil {
		return err
	}
	_, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.elevation." + state, RealmID: realmID, Actor: auditActor, Category: "authorization",
		Metadata: map[string]any{"elevation_id": id, "assignment_id": assignmentID}})
	return err
}

// MarkElevationExpiredTx records that the sweep removed an elevation's
// assignment at its deadline, with the audit event
// authorization.elevation.expired (actor system).
func (s *Service) MarkElevationExpiredTx(ctx context.Context, tx pgx.Tx, assignmentID string) error {
	rows, err := tx.Query(ctx, `UPDATE elevations x SET state='expired' FROM elevation_eligibilities e
		WHERE x.assignment_id=$1 AND x.state='active' AND e.id=x.eligibility_id
		RETURNING x.id, x.realm_id, x.user_id, e.role_id, e.scope_type, e.scope_id, x.ends_at`, assignmentID)
	if err != nil {
		return err
	}
	type ended struct {
		id, realm, user, role string
		scope                 Scope
		endsAt                *time.Time
	}
	var list []ended
	for rows.Next() {
		var x ended
		if err := rows.Scan(&x.id, &x.realm, &x.user, &x.role, &x.scope.Type, &x.scope.ID, &x.endsAt); err != nil {
			rows.Close()
			return err
		}
		list = append(list, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range list {
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.elevation.expired", RealmID: x.realm, OrgID: orgOf(x.scope),
			Actor: audit.System, Subject: &audit.Ref{Type: "user", ID: x.user}, Category: "authorization", Target: &audit.Ref{Type: "role", ID: x.role},
			Metadata: map[string]any{"elevation_id": x.id, "assignment_id": assignmentID, "ends_at": x.endsAt}}); err != nil {
			return err
		}
	}
	return nil
}

// ListElevations lists requests and elevations, optionally by person and
// state.
func (s *Service) ListElevations(ctx context.Context, q storage.Querier, realmID, userID, state string) ([]*Elevation, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	rows, err := q.Query(ctx, `SELECT `+elevationCols+elevationFrom+` WHERE x.realm_id=$1 AND ($2='' OR x.user_id=$2) AND ($3='' OR x.state=$3)
		ORDER BY x.requested_at DESC LIMIT 500`, realmID, userID, state)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Elevation{}
	for rows.Next() {
		el, err := s.scanElevation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, el)
	}
	return out, rows.Err()
}
