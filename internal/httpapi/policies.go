package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/proudbase/proudauth/internal/authorization"
	"github.com/proudbase/proudauth/internal/platform/problem"
)

// policyRoutes registers policy administration (AZ-013, AZ-015, AZ-017,
// AZ-018) and simulation.
func (a *App) policyRoutes(mux *http.ServeMux) {
	R := "/api/v1/realms/{realm}"
	P := R + "/policies"
	num := func(r *http.Request) (int, error) {
		n, err := strconv.Atoi(r.PathValue("version"))
		if err != nil || n < 1 {
			return 0, problem.ErrNotFound
		}
		return n, nil
	}
	mux.HandleFunc("GET "+P, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.read"); err != nil {
			return err
		}
		list, err := a.Authz.ListPolicies(r.Context(), p.Realm.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+P, a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.write"); err != nil {
			return err
		}
		var in authorization.PolicyCreate
		if err := decode(r, &in); err != nil {
			return err
		}
		pol, ver, err := a.Authz.CreatePolicy(r.Context(), p.Realm.ID, in, p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, pol.Version)
		writeJSON(w, http.StatusCreated, map[string]any{"policy": pol, "version": ver})
		return nil
	}))
	mux.HandleFunc("GET "+P+"/{policy}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.read"); err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		setETag(w, pol.Version)
		writeJSON(w, http.StatusOK, pol)
		return nil
	}))
	mux.HandleFunc("GET "+P+"/{policy}/versions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.read"); err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		list, err := a.Authz.Versions(r.Context(), p.Realm.ID, pol.ID)
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+P+"/{policy}/versions", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.write"); err != nil {
			return err
		}
		var b struct {
			Definition json.RawMessage `json:"definition"`
			Note       string          `json:"note"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		v, err := a.Authz.StageVersion(r.Context(), p.Realm.ID, pol.ID, b.Definition, b.Note, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusCreated, v)
		return nil
	}))
	mux.HandleFunc("GET "+P+"/{policy}/versions/{version}", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.read"); err != nil {
			return err
		}
		n, err := num(r)
		if err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		v, err := a.Authz.Version(r.Context(), p.Realm.ID, pol.ID, n)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, v)
		return nil
	}))
	transition := func(action string) http.HandlerFunc {
		return a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
			if err := a.requirePerm(r, p, "realm.policies.publish"); err != nil {
				return err
			}
			if err := a.requireRecentAuth(p, 0); err != nil && p.IsUser() {
				return err
			}
			if err := decode(r, &struct{}{}); err != nil {
				return err
			}
			n, err := num(r)
			if err != nil {
				return err
			}
			pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
			if err != nil {
				return err
			}
			if action == "approve" {
				v, err := a.Authz.ApproveVersion(r.Context(), p.Realm.ID, pol.ID, n, p.AuditRef())
				if err != nil {
					return err
				}
				writeJSON(w, http.StatusOK, v)
				return nil
			}
			out, err := a.Authz.PublishVersion(r.Context(), p.Realm.ID, pol.ID, n, p.AuditRef())
			if err != nil {
				return err
			}
			setETag(w, out.Version)
			writeJSON(w, http.StatusOK, out)
			return nil
		})
	}
	mux.HandleFunc("POST "+P+"/{policy}/versions/{version}/approve", transition("approve"))
	mux.HandleFunc("POST "+P+"/{policy}/versions/{version}/publish", transition("publish"))
	mux.HandleFunc("POST "+P+"/{policy}/rollback", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.publish"); err != nil {
			return err
		}
		var b struct {
			ToVersion int `json:"to_version"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		out, err := a.Authz.Rollback(r.Context(), p.Realm.ID, pol.ID, b.ToVersion, p.AuditRef())
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, out)
		return nil
	}))
	mux.HandleFunc("POST "+P+"/{policy}/state", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.publish"); err != nil {
			return err
		}
		var b struct {
			State string `json:"state"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		if err := a.Authz.SetPolicyState(r.Context(), p.Realm.ID, pol.ID, b.State, p.AuditRef()); err != nil {
			return err
		}
		w.WriteHeader(http.StatusNoContent)
		return nil
	}))
	mux.HandleFunc("GET "+P+"/{policy}/diff", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.policies.read"); err != nil {
			return err
		}
		pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, r.PathValue("policy"))
		if err != nil {
			return err
		}
		from, err1 := strconv.Atoi(r.URL.Query().Get("from"))
		to, err2 := strconv.Atoi(r.URL.Query().Get("to"))
		if err1 != nil || err2 != nil {
			return problem.ErrValidation.WithDetail("from and to version numbers are required")
		}
		va, err := a.Authz.Version(r.Context(), p.Realm.ID, pol.ID, from)
		if err != nil {
			return err
		}
		vb, err := a.Authz.Version(r.Context(), p.Realm.ID, pol.ID, to)
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "diff": authorization.Diff(va.Definition, vb.Definition)})
		return nil
	}))
	// Simulation evaluates checks against a candidate revision (or the active
	// set) without publishing or auditing them as real decisions. Subjects are
	// named explicitly, which requires realm.authorization.simulate.
	mux.HandleFunc("POST "+R+"/authorization/simulate", a.admin(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if err := a.requirePerm(r, p, "realm.authorization.simulate"); err != nil {
			return err
		}
		var b struct {
			Policy     string            `json:"policy"`
			Version    int               `json:"version"`
			Definition json.RawMessage   `json:"definition"`
			Checks     []DecisionRequest `json:"checks"`
		}
		if err := decode(r, &b); err != nil {
			return err
		}
		if len(b.Checks) == 0 || len(b.Checks) > a.D.Cfg.Limits.MaxBatchSize {
			return problem.ErrValidation.WithField("checks", "1..max_batch_size checks")
		}
		var ov *policyOverride
		if b.Policy != "" || len(b.Definition) > 0 {
			ov = &policyOverride{policyID: "candidate", label: "candidate", scope: authorization.ScopeRealm}
			raw := b.Definition
			if b.Policy != "" {
				pol, err := a.Authz.GetPolicy(r.Context(), p.Realm.ID, b.Policy)
				if err != nil {
					return err
				}
				ov.policyID, ov.scope, ov.scopeID = pol.ID, pol.ScopeType, pol.ScopeID
				if len(raw) == 0 {
					if b.Version == 0 {
						return problem.ErrValidation.WithField("version", "required when no definition is given")
					}
					v, err := a.Authz.Version(r.Context(), p.Realm.ID, pol.ID, b.Version)
					if err != nil {
						return err
					}
					raw = v.Definition
					ov.label = pol.Name + "@" + strconv.Itoa(v.Number) + "(candidate)"
				} else {
					ov.label = pol.Name + "@draft"
				}
			}
			def, err := authorization.ParsePolicy(raw)
			if err != nil {
				return err
			}
			ov.def = def
		}
		results := make([]map[string]any, 0, len(b.Checks))
		changed := 0
		for _, c := range b.Checks {
			cur := a.decideWith(r.Context(), p, c, nil, false)
			res := map[string]any{"current": cur}
			if ov != nil {
				cand := a.decideWith(r.Context(), p, c, ov, false)
				res["candidate"] = cand
				if cand.Allowed != cur.Allowed || cand.ReasonCode != cur.ReasonCode {
					res["changed"] = true
					changed++
				}
			}
			results = append(results, res)
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results, "changed": changed})
		return nil
	}))
}
