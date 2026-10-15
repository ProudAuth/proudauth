package httpapi

import (
	"net/http"
	"strconv"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// reviewRoutes serve access review campaigns (AZ-025): administrators run
// them, named reviewers decide through their own account.
func (a *App) reviewRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	mux.HandleFunc("POST "+R+"/access-reviews", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		var in authorization.ReviewInput
		if err := decode(r, &in); err != nil {
			return err
		}
		rv, err := a.Authz.CreateReview(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, rv)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/access-reviews", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		list, err := a.Authz.ListReviews(r.Context(), p.Realm.ID, r.URL.Query().Get("state"), "")
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+R+"/access-reviews/{id}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		rv, err := a.Authz.GetReview(r.Context(), nil, p.Realm.ID, r.PathValue("id"), "")
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, rv)
		return nil
	}))
	items := func(w http.ResponseWriter, r *http.Request, reviewID string) error {
		q := r.URL.Query()
		limit := 100
		if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 && n <= 500 {
			limit = n
		}
		d := q.Get("decision")
		if d != "" && d != "undecided" && d != "keep" && d != "revoke" {
			return problem.ErrValidation.WithField("decision", "undecided, keep or revoke")
		}
		list, err := a.Authz.ReviewItems(r.Context(), reviewID, d, q.Get("cursor"), limit+1)
		if err != nil {
			return err
		}
		out := map[string]any{"items": list}
		if len(list) > limit {
			out["items"], out["next_cursor"] = list[:limit], list[limit-1].ID
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}
	mux.HandleFunc("GET "+R+"/access-reviews/{id}/items", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		if _, err := a.Authz.GetReview(r.Context(), nil, p.Realm.ID, r.PathValue("id"), ""); err != nil {
			return err
		}
		return items(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("POST "+R+"/access-reviews/{id}/close", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		rv, err := a.Authz.CloseReview(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, rv)
		return nil
	}))
	mux.HandleFunc("POST "+R+"/access-reviews/{id}/cancel", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		if err := decode(r, &struct{}{}); err != nil {
			return err
		}
		if err := a.Authz.CancelReview(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+R+"/access-reviews/{id}/evidence", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.access_reviews.manage"); err != nil {
			return err
		}
		ev, err := a.Authz.Evidence(r.Context(), p.Realm.ID, r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, ev)
		return nil
	}))

	me := R + "/me/access-reviews"
	mux.HandleFunc("GET "+me, a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		state := r.URL.Query().Get("state")
		if state == "" {
			state = "open"
		}
		list, err := a.Authz.ListReviews(r.Context(), p.Realm.ID, state, p.SubjectID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("GET "+me+"/{id}/items", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.Authz.GetReview(r.Context(), nil, p.Realm.ID, r.PathValue("id"), p.SubjectID); err != nil {
			return err
		}
		return items(w, r, r.PathValue("id"))
	}))
	mux.HandleFunc("POST "+me+"/{id}/items/{item}/decision", a.self(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		var b struct {
			Decision string `json:"decision"`
			Comment  string `json:"comment"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		it, err := a.Authz.DecideItem(r.Context(), p.Realm.ID, p.SubjectID, r.PathValue("id"), r.PathValue("item"), b.Decision, b.Comment)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, it)
		return nil
	}))
}
