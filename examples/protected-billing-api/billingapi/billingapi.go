// Package billingapi is an example offline-verifying resource server. It accepts
// short-lived JWTs verified locally and documents its revocation exposure: a revoked
// session remains usable until token expiry plus clock tolerance (SES-023, TEST-034).
package billingapi

import (
	"encoding/json"
	"net/http"

	"github.com/proudauth/proudauth-sdk-go/verifier"
)

// Invoice is an application record.
type Invoice struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
	Total int64  `json:"total_minor"`
}

// API is the billing service.
type API struct {
	V        *verifier.Verifier
	Invoices []Invoice
}

// Handler returns routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /invoices", verifier.Middleware(a.V, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := verifier.FromContext(r.Context())
		if c.RequireScope("billing:read") != nil || c.OrgID == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		out := []Invoice{}
		for _, inv := range a.Invoices {
			if inv.OrgID == c.OrgID {
				out = append(out, inv)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"items": out, "subject": c.Subject, "actor": c.Actor})
	})))
	return mux
}
