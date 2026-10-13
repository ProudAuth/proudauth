package authentication

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// ConsentRecord is one consent of a user to a client (APP-013).
type ConsentRecord struct {
	ID                 string     `json:"id"`
	ClientRef          string     `json:"client"`
	ClientID           string     `json:"client_id"`
	ClientName         string     `json:"client_name"`
	Scopes             []string   `json:"scopes"`
	ResourceIDs        []string   `json:"resource_ids"`
	TermsVersion       string     `json:"terms_version,omitempty"`
	Mode               string     `json:"mode"`
	PreauthorizationID string     `json:"preauthorization_id,omitempty"`
	GrantedAt          time.Time  `json:"granted_at"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
}

// Consents lists a user's consents, newest first; revoked ones are included
// when history is true.
func (s *Service) Consents(ctx context.Context, realmID, userID string, history bool) ([]ConsentRecord, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT cn.id, cn.client_ref, c.client_id, c.name, cn.scopes, cn.resource_ids, coalesce(cn.terms_version,''), cn.mode,
		coalesce(cn.preauthorization_id,''), cn.granted_at, cn.revoked_at FROM consents cn JOIN clients c ON c.id=cn.client_ref
		WHERE cn.realm_id=$1 AND cn.user_id=$2 AND ($3 OR cn.revoked_at IS NULL) ORDER BY cn.granted_at DESC LIMIT 500`, realmID, userID, history)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConsentRecord{}
	for rows.Next() {
		var c ConsentRecord
		if err := rows.Scan(&c.ID, &c.ClientRef, &c.ClientID, &c.ClientName, &c.Scopes, &c.ResourceIDs, &c.TermsVersion, &c.Mode,
			&c.PreauthorizationID, &c.GrantedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// RevokeConsent ends a user's consent and the client's grants for the user.
func (s *Service) RevokeConsent(ctx context.Context, realmID, userID, consentID string, actor audit.Ref) error {
	return s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		clientRef, err := s.RevokeConsentTx(ctx, tx, realmID, userID, consentID)
		if err != nil {
			return err
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "consent.revoked", RealmID: realmID, Actor: actor,
			Subject: &audit.Ref{Type: "user", ID: userID}, Metadata: map[string]any{"client_ref": clientRef}})
		return err
	})
}

// ConsentPreauthorization lets an administrator consent for a third-party
// client on behalf of a realm or one organization (APP-013).
type ConsentPreauthorization struct {
	ID             string     `json:"id"`
	ClientRef      string     `json:"client"`
	OrganizationID string     `json:"organization_id,omitempty"`
	Scopes         []string   `json:"scopes"`
	TermsVersion   string     `json:"terms_version,omitempty"`
	Reason         string     `json:"reason"`
	GrantedByID    string     `json:"granted_by_id"`
	GrantedAt      time.Time  `json:"granted_at"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// Preauthorize records an administrative consent for the client's current
// terms version. Offline access always stays a user decision.
func (s *Service) Preauthorize(ctx context.Context, realmID, clientRef, orgID string, scopes []string, reason string, actor audit.Ref) (*ConsentPreauthorization, error) {
	if len(scopes) == 0 || len(scopes) > 50 {
		return nil, problem.ErrValidation.WithField("scopes", "1 to 50 scopes")
	}
	if slices.Contains(scopes, "offline_access") {
		return nil, problem.ErrValidation.WithField("scopes", "offline access always needs the user's own consent")
	}
	if len(strings.TrimSpace(reason)) < 5 {
		return nil, problem.ErrValidation.WithField("reason", "a reason is required")
	}
	var out *ConsentPreauthorization
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		client, err := s.Apps.ClientByRef(ctx, tx, realmID, clientRef)
		if err != nil {
			return problem.ErrNotFound
		}
		defs, err := s.Apps.ScopesByName(ctx, tx, realmID, scopes)
		if err != nil {
			return err
		}
		for _, sc := range scopes {
			if _, ok := defs[sc]; !ok {
				return problem.ErrValidation.WithField("scopes", "unknown scope "+sc)
			}
		}
		if orgID != "" && s.Orgs != nil {
			if _, err := s.Orgs.Get(ctx, tx, realmID, orgID); err != nil {
				return problem.ErrValidation.WithField("organization_id", "unknown organization")
			}
		}
		p := &ConsentPreauthorization{ID: ids.New(ids.Consent), ClientRef: clientRef, OrganizationID: orgID, Scopes: scopes,
			TermsVersion: client.ConsentTermsVersion, Reason: reason, GrantedByID: actor.ID, GrantedAt: s.d.Now()}
		if _, err := tx.Exec(ctx, `INSERT INTO consent_preauthorizations (id, realm_id, client_ref, organization_id, scopes, terms_version, reason,
			granted_by_id, granted_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, p.ID, realmID, clientRef, nilIfEmpty(orgID), scopes,
			nilIfEmpty(p.TermsVersion), reason, actor.ID, p.GrantedAt); err != nil {
			return err
		}
		out = p
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "consent.preauthorized", RealmID: realmID, OrgID: orgID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: clientRef}, ReasonCode: reason, Metadata: map[string]any{"scopes": scopes, "preauthorization_id": p.ID}})
		return err
	})
	return out, err
}

// Preauthorizations lists a client's pre-authorizations.
func (s *Service) Preauthorizations(ctx context.Context, realmID, clientRef string) ([]ConsentPreauthorization, error) {
	rows, err := s.d.DB.Pool.Query(ctx, `SELECT id, client_ref, coalesce(organization_id,''), scopes, coalesce(terms_version,''), reason, granted_by_id,
		granted_at, revoked_at FROM consent_preauthorizations WHERE realm_id=$1 AND client_ref=$2 ORDER BY granted_at DESC`, realmID, clientRef)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ConsentPreauthorization{}
	for rows.Next() {
		var p ConsentPreauthorization
		if err := rows.Scan(&p.ID, &p.ClientRef, &p.OrganizationID, &p.Scopes, &p.TermsVersion, &p.Reason, &p.GrantedByID, &p.GrantedAt, &p.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokePreauthorization withdraws a pre-authorization and every consent and
// grant that relied on it.
func (s *Service) RevokePreauthorization(ctx context.Context, realmID, clientRef, id string, actor audit.Ref) (int, error) {
	n := 0
	err := s.d.DB.Tx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE consent_preauthorizations SET revoked_at=$4 WHERE realm_id=$1 AND client_ref=$2 AND id=$3 AND revoked_at IS NULL`,
			realmID, clientRef, id, s.d.Now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return problem.ErrNotFound
		}
		rows, err := tx.Query(ctx, `SELECT id, user_id FROM consents WHERE preauthorization_id=$1 AND revoked_at IS NULL`, id)
		if err != nil {
			return err
		}
		type c struct{ id, user string }
		var list []c
		for rows.Next() {
			var x c
			if err := rows.Scan(&x.id, &x.user); err != nil {
				rows.Close()
				return err
			}
			list = append(list, x)
		}
		rows.Close()
		for _, x := range list {
			if _, err := s.RevokeConsentTx(ctx, tx, realmID, x.user, x.id); err != nil {
				if pe, ok := problem.As(err); ok && pe.Code == problem.ErrNotFound.Code {
					continue
				}
				return err
			}
			n++
		}
		_, err = s.d.Audit.Record(ctx, tx, audit.Event{Type: "consent.preauthorization_revoked", RealmID: realmID, Actor: actor, Category: "configuration",
			Target: &audit.Ref{Type: "client", ID: clientRef}, Metadata: map[string]any{"preauthorization_id": id, "consents_revoked": n}})
		return err
	})
	return n, err
}
