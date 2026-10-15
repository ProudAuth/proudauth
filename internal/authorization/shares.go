package authorization

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/storage"
)

// User-managed sharing (AZ-027): a profile on top of relationships in which
// the person who may share an object (the type's share_permission) offers
// one of its shareable relations to another member of the same
// organization, and the recipient consents by accepting. Acceptance writes
// the relationship tuple; revoking or declining removes it. Sharing never
// crosses organizations and never grants more than the offered relation.

// Share is one sharing offer.
type Share struct {
	ID              string     `json:"id"`
	OrganizationID  string     `json:"organization_id"`
	ObjectType      string     `json:"resource_type"`
	ObjectID        string     `json:"object_id"`
	Relation        string     `json:"relation"`
	OwnerUserID     string     `json:"owner_user_id"`
	RecipientUserID string     `json:"recipient_user_id"`
	State           string     `json:"state"`
	Message         string     `json:"message,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	DecidedAt       *time.Time `json:"decided_at,omitempty"`
	relationshipID  string
}

const shareCols = `id, organization_id, object_type, object_id, relation, owner_user_id, recipient_user_id, state, coalesce(message,''), expires_at,
	created_at, decided_at, coalesce(relationship_id,'')`

func scanShare(row pgx.Row) (*Share, error) {
	var sh Share
	err := row.Scan(&sh.ID, &sh.OrganizationID, &sh.ObjectType, &sh.ObjectID, &sh.Relation, &sh.OwnerUserID, &sh.RecipientUserID, &sh.State, &sh.Message,
		&sh.ExpiresAt, &sh.CreatedAt, &sh.DecidedAt, &sh.relationshipID)
	return &sh, err
}

// ShareInput is an offer.
type ShareInput struct {
	OrganizationID  string     `json:"organization_id"`
	ResourceType    string     `json:"resource_type"`
	ObjectID        string     `json:"object_id"`
	Relation        string     `json:"relation"`
	RecipientUserID string     `json:"recipient_user_id"`
	Message         string     `json:"message"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

// OfferShare records an offer from a member allowed to share the object.
func (s *Service) OfferShare(ctx context.Context, realmID, ownerID string, in ShareInput) (*Share, error) {
	verr := problem.ErrValidation
	if len(in.Message) > 500 {
		return nil, verr.WithField("message", "at most 500 characters")
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.d.Now()) {
		return nil, verr.WithField("expires_at", "in the future")
	}
	if in.RecipientUserID == ownerID {
		return nil, verr.WithField("recipient_user_id", "share with someone else")
	}
	var out *Share
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		t, err := s.ResourceTypeByName(ctx, tx, realmID, in.ResourceType)
		if err != nil {
			return verr.WithField("resource_type", "unknown resource type")
		}
		if !slices.Contains(t.ShareableRelations, in.Relation) {
			return verr.WithField("relation", "this relation cannot be shared; shareable: "+strings.Join(t.ShareableRelations, ", "))
		}
		if !validObjectID(in.ObjectID) {
			return verr.WithField("object_id", "1 to 256 characters without control characters")
		}
		ok, err := s.CheckObject(ctx, tx, realmID, in.OrganizationID, Subject{Type: SubjectUser, ID: ownerID}, t.Name, in.ObjectID, t.SharePermission)
		if err != nil {
			return err
		}
		if !ok {
			return problem.ErrForbidden.WithDetail("you may not share this object")
		}
		if perr := s.checkSubjectTx(ctx, tx, realmID, in.OrganizationID, RelSubjectUser, in.RecipientUserID); perr != nil {
			return problem.ErrValidation.WithField("recipient_user_id", "the recipient must be an active member of the organization")
		}
		var dup bool
		// A share past its expiry no longer counts, also before the sweep
		// recorded it as expired.
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM resource_shares WHERE organization_id=$1 AND object_type=$2 AND object_id=$3 AND relation=$4
			AND recipient_user_id=$5 AND state IN ('pending','accepted') AND (expires_at IS NULL OR expires_at > $6))`, in.OrganizationID, t.Name, in.ObjectID,
			in.Relation, in.RecipientUserID, s.d.Now()).Scan(&dup); err != nil {
			return err
		}
		if dup {
			return problem.ErrConflict.WithDetail("already offered or shared")
		}
		id := ids.New("shr")
		if _, err := tx.Exec(ctx, `INSERT INTO resource_shares (id, realm_id, organization_id, object_type, object_id, relation, owner_user_id, recipient_user_id,
			state, message, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11)`, id, realmID, in.OrganizationID, t.Name, in.ObjectID,
			in.Relation, ownerID, in.RecipientUserID, nilIfEmpty(in.Message), in.ExpiresAt, s.d.Now()); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.share.offered", RealmID: realmID, OrgID: in.OrganizationID,
			Actor: audit.Ref{Type: "user", ID: ownerID}, Subject: &audit.Ref{Type: "user", ID: in.RecipientUserID}, Category: "authorization",
			Target: &audit.Ref{Type: "share", ID: id}, Metadata: map[string]any{"resource_type": t.Name, "object_id": in.ObjectID, "relation": in.Relation}}); err != nil {
			return err
		}
		out, err = scanShare(tx.QueryRow(ctx, `SELECT `+shareCols+` FROM resource_shares WHERE id=$1`, id))
		return err
	})
	return out, err
}

// errShareExpired is returned inside RespondShare's transaction for an offer
// found past its expiry; the transaction rolls back and the state change is
// stored on its own afterwards.
var errShareExpired = problem.ErrConflict.WithDetail("the offer expired")

// RespondShare accepts or declines an offer made to the recipient.
func (s *Service) RespondShare(ctx context.Context, realmID, recipientID, id string, accept bool) (*Share, error) {
	var out *Share
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		sh, err := scanShare(tx.QueryRow(ctx, `SELECT `+shareCols+` FROM resource_shares WHERE realm_id=$1 AND id=$2 AND recipient_user_id=$3 FOR UPDATE`,
			realmID, id, recipientID))
		if err != nil {
			return problem.ErrNotFound
		}
		if sh.State != "pending" {
			return problem.ErrConflict.WithDetail("the offer is " + sh.State)
		}
		now := s.d.Now()
		if sh.ExpiresAt != nil && !sh.ExpiresAt.After(now) {
			// Refusing rolls this transaction back, so the expiry is
			// recorded after it, in a transaction of its own.
			return errShareExpired
		}
		state, relID := "declined", ""
		if accept {
			// The sharer must still be allowed to share, and the recipient
			// still a member, at the moment the relationship is created.
			t, err := s.ResourceTypeByName(ctx, tx, realmID, sh.ObjectType)
			if err != nil || !slices.Contains(t.ShareableRelations, sh.Relation) {
				return problem.ErrConflict.WithDetail("the relation is no longer shareable")
			}
			ok, err := s.CheckObject(ctx, tx, realmID, sh.OrganizationID, Subject{Type: SubjectUser, ID: sh.OwnerUserID}, t.Name, sh.ObjectID, t.SharePermission)
			if err != nil {
				return err
			}
			if !ok {
				return problem.ErrConflict.WithDetail("the person who shared it may no longer share it")
			}
			w := RelationshipWrite{Op: "add", ObjectType: sh.ObjectType, ObjectID: sh.ObjectID, Relation: sh.Relation, SubjectType: RelSubjectUser,
				SubjectID: recipientID, ExpiresAt: sh.ExpiresAt}
			if err := s.writeRelationshipsTx(ctx, tx, realmID, sh.OrganizationID, []RelationshipWrite{w}, "share:"+id, audit.Ref{Type: "user", ID: recipientID}); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT id FROM resource_relationships WHERE organization_id=$1 AND subject_type='user' AND subject_id=$2 AND relation=$3
				AND object_type=$4 AND object_id=$5`, sh.OrganizationID, recipientID, sh.Relation, sh.ObjectType, sh.ObjectID).Scan(&relID); err != nil {
				return err
			}
			state = "accepted"
		}
		if _, err := tx.Exec(ctx, `UPDATE resource_shares SET state=$2, decided_at=$3, relationship_id=$4 WHERE id=$1`, id, state, now, nilIfEmpty(relID)); err != nil {
			return err
		}
		if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.share." + state, RealmID: realmID, OrgID: sh.OrganizationID,
			Actor: audit.Ref{Type: "user", ID: recipientID}, Category: "authorization", Target: &audit.Ref{Type: "share", ID: id}}); err != nil {
			return err
		}
		out, err = scanShare(tx.QueryRow(ctx, `SELECT `+shareCols+` FROM resource_shares WHERE id=$1`, id))
		return err
	})
	if errors.Is(err, errShareExpired) {
		if _, xerr := s.ExpireShares(ctx, realmID, id); xerr != nil {
			return nil, xerr
		}
	}
	return out, err
}

// ExpireShares records shares past their expires_at as expired (AZ-027):
// pending offers that can no longer be accepted, and accepted shares whose
// relationship tuple has run out (the tuple the acceptance wrote is removed;
// it already granted nothing). With ids, only those shares of the realm;
// otherwise every due share (the expiry sweep), in batches. Each one is
// audited as authorization.share.expired. It returns how many expired.
func (s *Service) ExpireShares(ctx context.Context, realmID string, ids ...string) (int, error) {
	n := 0
	for {
		batch := 0
		err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
			now := s.d.Now()
			rows, err := tx.Query(ctx, `SELECT id, realm_id, organization_id, state, coalesce(relationship_id,'') FROM resource_shares
				WHERE state IN ('pending','accepted') AND expires_at IS NOT NULL AND expires_at <= $1 AND ($2='' OR realm_id=$2)
				AND (cardinality($3::text[])=0 OR id = ANY($3)) ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED`, now, realmID, nonNilStrings(ids))
			if err != nil {
				return err
			}
			type due struct{ id, realm, org, state, rel string }
			var list []due
			for rows.Next() {
				var d due
				if err := rows.Scan(&d.id, &d.realm, &d.org, &d.state, &d.rel); err != nil {
					rows.Close()
					return err
				}
				list = append(list, d)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, d := range list {
				if d.rel != "" {
					// Only the tuple this share wrote, and only while it is
					// still the expiring one (a later write may have extended it).
					if _, err := tx.Exec(ctx, `DELETE FROM resource_relationships WHERE id=$1 AND source=$2 AND expires_at IS NOT NULL AND expires_at <= $3`,
						d.rel, "share:"+d.id, now); err != nil {
						return err
					}
				}
				if _, err := tx.Exec(ctx, `UPDATE resource_shares SET state='expired', decided_at=coalesce(decided_at, $2) WHERE id=$1`, d.id, now); err != nil {
					return err
				}
				if _, err := s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.share.expired", RealmID: d.realm, OrgID: d.org, Actor: audit.System,
					Category: "authorization", Target: &audit.Ref{Type: "share", ID: d.id}, Metadata: map[string]any{"previous_state": d.state}}); err != nil {
					return err
				}
			}
			batch = len(list)
			return nil
		})
		if err != nil {
			return n, err
		}
		n += batch
		if batch < 200 || len(ids) > 0 {
			return n, nil
		}
	}
}

// RevokeShare ends a share: the sharer withdraws an offer or access, or the
// recipient gives access back.
func (s *Service) RevokeShare(ctx context.Context, realmID, userID, id string) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		sh, err := scanShare(tx.QueryRow(ctx, `SELECT `+shareCols+` FROM resource_shares WHERE realm_id=$1 AND id=$2 AND (owner_user_id=$3 OR recipient_user_id=$3)
			FOR UPDATE`, realmID, id, userID))
		if err != nil {
			return problem.ErrNotFound
		}
		if sh.State != "pending" && sh.State != "accepted" {
			return problem.ErrConflict.WithDetail("the share is " + sh.State)
		}
		if sh.relationshipID != "" {
			if _, err := tx.Exec(ctx, `DELETE FROM resource_relationships WHERE id=$1`, sh.relationshipID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE resource_shares SET state='revoked', decided_at=$2 WHERE id=$1`, id, s.d.Now()); err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "authorization.share.revoked", RealmID: realmID, OrgID: sh.OrganizationID,
			Actor: audit.Ref{Type: "user", ID: userID}, Category: "authorization", Target: &audit.Ref{Type: "share", ID: id},
			Metadata: map[string]any{"by": map[bool]string{true: "owner", false: "recipient"}[userID == sh.OwnerUserID]}})
		return err
	})
}

// ListShares lists a user's shares: sent or received.
func (s *Service) ListShares(ctx context.Context, q storage.Querier, realmID, userID, direction, state string) ([]*Share, error) {
	if q == nil {
		q = s.d.DB.Pool
	}
	col := "recipient_user_id"
	if direction == "sent" {
		col = "owner_user_id"
	}
	// A share past its expiry is listed (and filtered) as expired already
	// before the sweep stores that state.
	now := s.d.Now()
	rows, err := q.Query(ctx, `SELECT `+shareCols+` FROM resource_shares WHERE realm_id=$1 AND `+col+`=$2
		AND ($3='' OR (CASE WHEN state IN ('pending','accepted') AND expires_at <= $4 THEN 'expired' ELSE state END)=$3)
		ORDER BY created_at DESC LIMIT 500`, realmID, userID, state, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Share{}
	for rows.Next() {
		sh, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		if (sh.State == "pending" || sh.State == "accepted") && sh.ExpiresAt != nil && !sh.ExpiresAt.After(now) {
			sh.State = "expired"
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}
