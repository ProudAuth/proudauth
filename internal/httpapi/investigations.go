package httpapi

import (
	"net/http"
	"time"

	"github.com/proudauth/proudauth/internal/authorization"
	"github.com/proudauth/proudauth/internal/platform/problem"
)

// investigationRoutes serve historical entitlement evidence (ADV-011) for
// authorized investigations.
func (a *App) investigationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/realms/{realm}/investigations/entitlements", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.audit.read"); err != nil {
			return err
		}
		var b struct {
			SubjectType string    `json:"subject_type"`
			SubjectID   string    `json:"subject_id"`
			At          time.Time `json:"at"`
			Reason      string    `json:"reason"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if b.Reason == "" || len(b.Reason) > 500 {
			return problem.ErrValidation.WithField("reason", "the investigation reference, 1 to 500 characters")
		}
		if b.At.IsZero() {
			return problem.ErrValidation.WithField("at", "an RFC 3339 instant")
		}
		subj := authorization.Subject{Type: b.SubjectType, ID: b.SubjectID}
		h, err := a.Authz.ReconstructEntitlements(r.Context(), p.Realm.ID, subj, b.At)
		if err != nil {
			return err
		}
		// The reconstruction is evidence access itself.
		if err := a.Authz.RecordInvestigation(r.Context(), p.Realm.ID, subj, b.At, b.Reason, p.AuditRef()); err != nil {
			return err
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, h)
		return nil
	}))
}
