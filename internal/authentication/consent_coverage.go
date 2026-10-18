package authentication

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/platform/ids"
	"github.com/proudauth/proudauth/internal/storage"
)

// ConsentRequest is what a new grant would authorize: a user, a client, the
// organization it is issued for ("" for none) and its scopes.
type ConsentRequest struct {
	RealmID string
	UserID  string
	Client  *application.Client
	OrgID   string
	Scopes  []string
}

// ConsentCoverage is the basis on which a request is covered (APP-013,
// TOK-008).
type ConsentCoverage struct {
	// Required: the client is governed by consent for these scopes.
	Required bool
	// ConsentID is the user's own live consent covering the request.
	ConsentID string
	// PreauthorizationID is the live administrative pre-authorization
	// covering the request when the user's own consent does not.
	PreauthorizationID string
}

// Covered reports whether a grant for the request may be issued without
// asking the user.
func (c ConsentCoverage) Covered() bool {
	return !c.Required || c.ConsentID != "" || c.PreauthorizationID != ""
}

// offlineConsentRequired: offline access by a third-party client always needs
// the user's own consent, independent of remember-me and of any
// pre-authorization (OIDC-012, SES-021).
func offlineConsentRequired(c *application.Client, scopes []string) bool {
	return slices.Contains(scopes, "offline_access") && c.AllowOfflineAccess && !c.FirstParty
}

// CheckConsentCoverage decides whether the user's consent covers a request, the
// one check behind every issuance that rests on consent: the authentication
// transaction and the organization switch (POST /me/organization-grants).
//
// Consent is required for clients with consent_mode required and for
// offline_access requested by a third-party client allowed offline access.
// The user's own live consent (mode user) covers the request when it includes
// every requested scope and was given for the client's current terms version.
// Otherwise a live pre-authorization for the realm, or for the request's
// organization, covers it when it includes every scope at the same terms
// version; offline access never rests on one. A consent recorded for a
// pre-authorization (mode preauthorized) is not the user's decision and covers
// nothing by itself: it counts only while its pre-authorization covers the
// request, so an organization's pre-authorization never reaches another
// organization.
func (s *Service) CheckConsentCoverage(ctx context.Context, q storage.Querier, in ConsentRequest) (ConsentCoverage, error) {
	cov := ConsentCoverage{Required: in.Client.ConsentMode == "required" || offlineConsentRequired(in.Client, in.Scopes)}
	if !cov.Required {
		return cov, nil
	}
	var id, terms string
	var scopes []string
	err := q.QueryRow(ctx, `SELECT id, scopes, coalesce(terms_version,'') FROM consents
		WHERE realm_id=$1 AND user_id=$2 AND client_ref=$3 AND revoked_at IS NULL AND mode='user'`,
		in.RealmID, in.UserID, in.Client.Ref).Scan(&id, &scopes, &terms)
	switch {
	case err == nil:
		if terms == in.Client.ConsentTermsVersion && !slices.ContainsFunc(in.Scopes, func(sc string) bool { return !slices.Contains(scopes, sc) }) {
			cov.ConsentID = id
			return cov, nil
		}
	case !storage.IsNoRows(err):
		return cov, err
	}
	if offlineConsentRequired(in.Client, in.Scopes) {
		return cov, nil
	}
	pre, err := s.preauthorizationFor(ctx, q, in)
	cov.PreauthorizationID = pre
	return cov, err
}

// preauthorizationFor returns the live administrative pre-authorization
// covering the client, organization, scopes and terms, if any; one for the
// organization is preferred over a realm-wide one.
func (s *Service) preauthorizationFor(ctx context.Context, q storage.Querier, in ConsentRequest) (string, error) {
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM consent_preauthorizations WHERE realm_id=$1 AND client_ref=$2 AND revoked_at IS NULL
		AND (organization_id IS NULL OR organization_id=$3) AND scopes @> $4 AND coalesce(terms_version,'') = $5
		ORDER BY organization_id NULLS LAST, granted_at LIMIT 1`, in.RealmID, in.Client.Ref, in.OrgID, nonNil(in.Scopes), in.Client.ConsentTermsVersion).Scan(&id)
	if storage.IsNoRows(err) {
		return "", nil
	}
	return id, err
}

// ConsentBasisTx returns the consent a new grant for a covered request rests
// on, to be stored as the grant's ConsentID, so that revoking that consent, or
// the pre-authorization behind it, ends the grant (APP-013). A request covered
// by the user's own consent rests on it. One covered by a pre-authorization
// rests on a consent recorded for a pre-authorization (mode preauthorized):
// the live one when it includes the scopes and its pre-authorization still
// covers the request, otherwise a new one for cov.PreauthorizationID that
// replaces the user's live consent for the client. A request that needs no
// consent has no basis ("").
func (s *Service) ConsentBasisTx(ctx context.Context, tx pgx.Tx, in ConsentRequest, cov ConsentCoverage, resourceIDs []string) (string, error) {
	switch {
	case cov.ConsentID != "":
		return cov.ConsentID, nil
	case cov.PreauthorizationID == "":
		return "", nil
	}
	var id string
	err := tx.QueryRow(ctx, `SELECT cn.id FROM consents cn JOIN consent_preauthorizations p
		ON p.realm_id=cn.realm_id AND p.client_ref=cn.client_ref AND p.id=cn.preauthorization_id
		WHERE cn.realm_id=$1 AND cn.user_id=$2 AND cn.client_ref=$3 AND cn.revoked_at IS NULL AND cn.mode='preauthorized'
		AND cn.scopes @> $4 AND coalesce(cn.terms_version,'') = $5
		AND p.revoked_at IS NULL AND (p.organization_id IS NULL OR p.organization_id=$6) AND p.scopes @> $4 AND coalesce(p.terms_version,'') = $5`,
		in.RealmID, in.UserID, in.Client.Ref, nonNil(in.Scopes), in.Client.ConsentTermsVersion, in.OrgID).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !storage.IsNoRows(err) {
		return "", err
	}
	now := s.d.Now()
	if _, err := tx.Exec(ctx, `UPDATE consents SET revoked_at=$3 WHERE user_id=$1 AND client_ref=$2 AND revoked_at IS NULL`,
		in.UserID, in.Client.Ref, now); err != nil {
		return "", err
	}
	id = ids.New(ids.Consent)
	if _, err := tx.Exec(ctx, `INSERT INTO consents (id, realm_id, user_id, client_ref, scopes, resource_ids, granted_at, terms_version, mode,
		preauthorization_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'preauthorized',$9)`, id, in.RealmID, in.UserID, in.Client.Ref, nonNil(in.Scopes),
		nonNil(resourceIDs), now, nilIfEmpty(in.Client.ConsentTermsVersion), cov.PreauthorizationID); err != nil {
		return "", err
	}
	return id, nil
}
