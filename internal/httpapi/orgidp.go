package httpapi

import (
	"context"
	"net/http"
	"slices"

	"github.com/proudauth/proudauth/internal/federation"
	"github.com/proudauth/proudauth/internal/platform/canonical"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// orgIdentityProviderRoutes lets organization administrators manage their own
// organization's federation connections (TEN-007) within its boundary: the
// connection is always scoped to the organization, trusted-email linking and
// just-in-time provisioning are limited to the organization's verified
// domains, and trusting upstream MFA
// stays a realm-administrator decision because it affects the user's
// assurance everywhere in the realm.
func (a *App) orgIdentityProviderRoutes(mux *http.ServeMux) {
	base := "/api/v1/realms/{realm}/organizations/{org}/identity-providers"
	guard := func(p *Principal, r *http.Request) error {
		if a.Federation == nil {
			return problem.ErrFeatureDisabled
		}
		_, err := a.orgGuard(p, r, "org.identity_providers.write")
		return err
	}
	owned := func(ctx context.Context, p *Principal, orgID, id string) (*federation.Provider, error) {
		prov, err := a.Federation.Get(ctx, nil, p.Realm.ID, id)
		if err != nil || prov.OrganizationID != orgID {
			return nil, problem.ErrNotFound
		}
		return prov, nil
	}
	check := func(ctx context.Context, p *Principal, orgID string, in *federation.Input) error {
		in.OrganizationID = orgID
		if in.TrustUpstreamMFA && !a.can(ctx, p, "realm.identity_providers.write", a.realmScope(p)) {
			return problem.ErrForbidden.WithDetail("trusting upstream MFA requires a realm administrator")
		}
		// Just-in-time accounts are realm-wide, so an organization creates
		// them only for addresses in its own verified domains (TEN-007,
		// REG-009): an empty list would admit every domain, including other
		// tenants' and public ones.
		if in.JIT && len(in.Config.AllowedEmailDomains) == 0 {
			return problem.ErrValidation.WithField("config.allowed_email_domains", "just-in-time provisioning requires the organization's verified domains to be listed")
		}
		if in.LinkingPolicy != federation.LinkTrustedEmail && !in.JIT {
			return nil
		}
		verified, err := a.Orgs.VerifiedDomains(ctx, p.Realm.ID, orgID)
		if err != nil {
			return err
		}
		for _, d := range in.Config.AllowedEmailDomains {
			c, err := canonical.Domain(d)
			if err != nil {
				return problem.ErrValidation.WithField("config.allowed_email_domains", "invalid domain "+d)
			}
			if !slices.Contains(verified, c) {
				if in.JIT {
					return problem.ErrValidation.WithField("config.allowed_email_domains", "just-in-time provisioning is limited to the organization's verified domains")
				}
				return problem.ErrValidation.WithField("config.allowed_email_domains", "trusted email linking is limited to the organization's verified domains")
			}
		}
		return nil
	}
	mux.HandleFunc("GET "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := guard(p, r); err != nil {
			return err
		}
		all, err := a.Federation.List(r.Context(), nil, p.Realm.ID, false)
		if err != nil {
			return err
		}
		items := []*federation.Provider{}
		for _, prov := range all {
			if prov.OrganizationID == r.PathValue("org") {
				items = append(items, prov)
			}
		}
		return a.writeList(w, r, items)
	}))
	mux.HandleFunc("POST "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := guard(p, r); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var in federation.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := check(r.Context(), p, r.PathValue("org"), &in); err != nil {
			return err
		}
		out, err := a.Federation.Create(r.Context(), p.Realm.ID, in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusCreated, out)
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := guard(p, r); err != nil {
			return err
		}
		out, err := owned(r.Context(), p, r.PathValue("org"), r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("PUT "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := guard(p, r); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		if _, err := owned(r.Context(), p, r.PathValue("org"), r.PathValue("id")); err != nil {
			return err
		}
		ver, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in federation.Input
		if err := decode(r, &in); err != nil {
			return err
		}
		if err := check(r.Context(), p, r.PathValue("org"), &in); err != nil {
			return err
		}
		out, err := a.Federation.Update(r.Context(), p.Realm.ID, r.PathValue("id"), ver, in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, out.Version)
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("DELETE "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := guard(p, r); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		if _, err := owned(r.Context(), p, r.PathValue("org"), r.PathValue("id")); err != nil {
			return err
		}
		if err := a.Federation.Delete(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
}
