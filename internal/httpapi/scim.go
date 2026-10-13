package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/proudbase/proudauth/internal/platform/problem"
	"github.com/proudbase/proudauth/internal/provisioning"
	"github.com/proudbase/proudauth/internal/ratelimit"
	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/token"
)

// scimRoutes serve SCIM 2.0 to provisioning connectors (PROV-001..PROV-009)
// and let organization administrators manage connectors (PROV-003, PROV-018).
func (a *App) scimRoutes(mux *http.ServeMux) {
	S := "/api/v1/realms/{realm}/scim/v2"
	mux.HandleFunc("GET "+S+"/ServiceProviderConfig", a.scim("", func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
		writeSCIM(w, http.StatusOK, provisioning.ServiceProviderConfig(base+"/ServiceProviderConfig"))
		return nil
	}))
	mux.HandleFunc("GET "+S+"/ResourceTypes", a.scim("", func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
		types := provisioning.ResourceTypes(c, base)
		writeSCIM(w, http.StatusOK, listBody(toAny(types), len(types), 1))
		return nil
	}))
	mux.HandleFunc("GET "+S+"/Schemas", a.scim("", func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
		schemas := provisioning.Schemas()
		writeSCIM(w, http.StatusOK, listBody(toAny(schemas), len(schemas), 1))
		return nil
	}))
	for _, res := range []struct{ name, coll, item string }{
		{"User", "/api/v1/realms/{realm}/scim/v2/Users", "/api/v1/realms/{realm}/scim/v2/Users/{id}"},
		{"Group", "/api/v1/realms/{realm}/scim/v2/Groups", "/api/v1/realms/{realm}/scim/v2/Groups/{id}"},
	} {
		rt := res.name
		mux.HandleFunc("GET "+res.coll, a.scim(rt, func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
			q := r.URL.Query()
			var f provisioning.Filter
			if fs := q.Get("filter"); fs != "" {
				var err error
				if f, err = provisioning.ParseFilter(fs); err != nil {
					return &provisioning.Error{Status: 400, ScimType: "invalidFilter", Detail: err.Error()}
				}
			}
			start, _ := strconv.Atoi(q.Get("startIndex"))
			count := provisioning.MaxResults
			if v := q.Get("count"); v != "" {
				count, _ = strconv.Atoi(v)
				count = min(max(count, 0), provisioning.MaxResults)
			}
			if start < 1 {
				start = 1
			}
			var items []map[string]any
			var total int
			var err error
			if rt == "User" {
				items, total, err = a.Provisioning.ListUsers(r.Context(), c, f, start, count, base)
			} else {
				withMembers := !strings.Contains(strings.ToLower(q.Get("excludedAttributes")), "members")
				items, total, err = a.Provisioning.ListGroups(r.Context(), c, f, start, count, base, withMembers)
			}
			if err != nil {
				return err
			}
			for i := range items {
				items[i] = selectAttrs(items[i], q.Get("attributes"), q.Get("excludedAttributes"))
			}
			writeSCIM(w, http.StatusOK, listBody(toAny(items), total, start))
			return nil
		}))
		mux.HandleFunc("POST "+res.coll, a.scim(rt, func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
			doc, err := scimBody(r)
			if err != nil {
				return err
			}
			var res map[string]any
			var ver int64
			if rt == "User" {
				res, ver, err = a.Provisioning.CreateUser(r.Context(), c, doc, base)
			} else {
				res, ver, err = a.Provisioning.CreateGroup(r.Context(), c, doc, base)
			}
			if err != nil {
				return err
			}
			w.Header().Set("Location", res["meta"].(map[string]any)["location"].(string))
			w.Header().Set("ETag", `W/"`+strconv.FormatInt(ver, 10)+`"`)
			writeSCIM(w, http.StatusCreated, res)
			return nil
		}))
		mux.HandleFunc("GET "+res.item, a.scim(rt, func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
			var res map[string]any
			var ver int64
			var err error
			if rt == "User" {
				res, ver, err = a.Provisioning.GetUser(r.Context(), c, r.PathValue("id"), base)
			} else {
				res, ver, err = a.Provisioning.GetGroup(r.Context(), c, r.PathValue("id"), base)
			}
			if err != nil {
				return err
			}
			tag := `W/"` + strconv.FormatInt(ver, 10) + `"`
			if r.Header.Get("If-None-Match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return nil
			}
			w.Header().Set("ETag", tag)
			writeSCIM(w, http.StatusOK, selectAttrs(res, r.URL.Query().Get("attributes"), r.URL.Query().Get("excludedAttributes")))
			return nil
		}))
		update := func(method string) http.HandlerFunc {
			return a.scim(rt, func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
				doc, err := scimBody(r)
				if err != nil {
					return err
				}
				id, ifMatch := r.PathValue("id"), r.Header.Get("If-Match")
				var res map[string]any
				var ver int64
				switch {
				case method == "PUT" && rt == "User":
					res, ver, err = a.Provisioning.ReplaceUser(r.Context(), c, id, doc, ifMatch, base)
				case method == "PUT":
					res, ver, err = a.Provisioning.ReplaceGroup(r.Context(), c, id, doc, ifMatch, base)
				default:
					ops, _ := doc["Operations"].([]any)
					if ops == nil {
						ops, _ = doc["operations"].([]any)
					}
					if rt == "User" {
						res, ver, err = a.Provisioning.PatchUser(r.Context(), c, id, ops, ifMatch, base)
					} else {
						res, ver, err = a.Provisioning.PatchGroup(r.Context(), c, id, ops, ifMatch, base)
					}
				}
				if err != nil {
					return err
				}
				w.Header().Set("ETag", `W/"`+strconv.FormatInt(ver, 10)+`"`)
				writeSCIM(w, http.StatusOK, res)
				return nil
			})
		}
		mux.HandleFunc("PUT "+res.item, update("PUT"))
		mux.HandleFunc("PATCH "+res.item, update("PATCH"))
		mux.HandleFunc("DELETE "+res.item, a.scim(rt, func(w http.ResponseWriter, r *http.Request, c *provisioning.Connector, base string) error {
			var err error
			if rt == "User" {
				err = a.Provisioning.DeleteUser(r.Context(), c, r.PathValue("id"), r.Header.Get("If-Match"))
			} else {
				err = a.Provisioning.DeleteGroup(r.Context(), c, r.PathValue("id"), r.Header.Get("If-Match"))
			}
			if err != nil {
				return err
			}
			w.WriteHeader(http.StatusNoContent)
			return nil
		}))
	}

	// Connector management.
	base := "/api/v1/realms/{realm}/organizations/{org}/provisioning-connectors"
	mux.HandleFunc("GET "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		list, err := a.Provisioning.List(r.Context(), p.Realm.ID, r.PathValue("org"))
		if err != nil {
			return err
		}
		return a.writeList(w, r, list)
	}))
	mux.HandleFunc("POST "+base, a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		var in provisioning.ConnectorInput
		if err := decode(r, &in); err != nil {
			return err
		}
		c, tok, err := a.Provisioning.Create(r.Context(), p.Realm.ID, r.PathValue("org"), in, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusCreated, map[string]any{"connector": c, "token": tok,
			"scim_base_url": strings.TrimSuffix(a.D.Cfg.Server.PublicOrigin, "/") + "/api/v1/realms/" + p.Realm.Name + "/scim/v2"})
		return nil
	}))
	mux.HandleFunc("GET "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		c, err := a.Provisioning.Get(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"))
		if err != nil {
			return err
		}
		setETag(w, c.Version)
		writeJSON(w, http.StatusOK, c)
		return nil
	}))
	mux.HandleFunc("PUT "+base+"/{id}", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		version, err := ifMatch(r, true)
		if err != nil {
			return err
		}
		var in struct {
			provisioning.ConnectorInput
			State string `json:"state"`
		}
		if err := decode(r, &in); err != nil {
			return err
		}
		c, err := a.Provisioning.Update(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), version, in.ConnectorInput, in.State, p.Subject(), p.AuditRef())
		if err != nil {
			return err
		}
		setETag(w, c.Version)
		writeJSON(w, http.StatusOK, c)
		return nil
	}))
	mux.HandleFunc("POST "+base+"/{id}/token", a.tenant(func(w http.ResponseWriter, r *http.Request, p *Principal) error {
		if _, err := a.orgGuard(p, r, "org.integrations.write"); err != nil {
			return err
		}
		if err := a.requireMFASession(p); err != nil {
			return err
		}
		tok, err := a.Provisioning.RotateToken(r.Context(), p.Realm.ID, r.PathValue("org"), r.PathValue("id"), p.AuditRef())
		if err != nil {
			return err
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{"token": tok})
		return nil
	}))
}

// scim authenticates a connector and maps errors to SCIM error documents.
func (a *App) scim(resourceType string, h func(http.ResponseWriter, *http.Request, *provisioning.Connector, string) error) http.HandlerFunc {
	return a.public(func(w http.ResponseWriter, r *http.Request, rlm *realm.Realm) error {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || !strings.EqualFold(auth[:7], "bearer ") {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
			writeSCIM(w, http.StatusUnauthorized, (&provisioning.Error{Status: 401, Detail: "connector token required"}).Body())
			return nil
		}
		c, err := a.Provisioning.Authenticate(r.Context(), rlm.ID, strings.TrimSpace(auth[7:]))
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="scim", error="invalid_token"`)
			writeSCIM(w, http.StatusUnauthorized, (&provisioning.Error{Status: 401, Detail: "invalid connector token"}).Body())
			return nil
		}
		if resourceType != "" && !c.Allows(resourceType) {
			writeSCIM(w, http.StatusForbidden, (&provisioning.Error{Status: 403, Detail: "this connector may not manage " + resourceType + " resources"}).Body())
			return nil
		}
		// The budget fails closed: a limiter outage refuses rather than
		// letting a connector write without bounds.
		d, err := a.Limiter.Hit(r.Context(), ratelimit.Budget{Key: "scim:" + c.ID, Limit: 1200, Window: time.Minute})
		if err != nil {
			writeSCIM(w, http.StatusServiceUnavailable, (&provisioning.Error{Status: 503, Detail: "temporarily unavailable"}).Body())
			return nil
		}
		if !d.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(d.RetryAfter.Seconds())+1))
			writeSCIM(w, http.StatusTooManyRequests, (&provisioning.Error{Status: 429, Detail: "too many requests"}).Body())
			return nil
		}
		base := strings.TrimSuffix(a.D.Cfg.Server.PublicOrigin, "/") + "/api/v1/realms/" + rlm.Name + "/scim/v2"
		kind := resourceType
		if kind == "" {
			kind = "discovery"
		}
		op := strings.ToLower(r.Method) + "_" + strings.ToLower(kind)
		if err := h(w, r, c, base); err != nil {
			se := toSCIMError(err)
			if se.Status >= 500 {
				a.D.Log.Error("scim request failed", "connector", c.ID, "error", err)
			}
			a.Provisioning.RecordUse(r.Context(), c, op, se.Detail)
			writeSCIM(w, se.Status, se.Body())
			return nil
		}
		a.Provisioning.RecordUse(r.Context(), c, op, "")
		return nil
	})
}

func toSCIMError(err error) *provisioning.Error {
	var se *provisioning.Error
	if errors.As(err, &se) {
		return se
	}
	if pe, ok := problem.As(err); ok {
		switch pe.Status {
		case 404:
			return &provisioning.Error{Status: 404, Detail: "resource not found"}
		case 409:
			return &provisioning.Error{Status: 409, ScimType: "uniqueness", Detail: pe.Detail}
		case 412:
			return &provisioning.Error{Status: 412, Detail: "the resource version does not match If-Match"}
		case 400, 422:
			return &provisioning.Error{Status: 400, ScimType: "invalidValue", Detail: pe.Error()}
		case 403:
			return &provisioning.Error{Status: 403, Detail: pe.Detail}
		}
	}
	return &provisioning.Error{Status: 500, Detail: "internal error"}
}

// scimBody reads a SCIM JSON document (application/scim+json or
// application/json) and rejects duplicate members.
func scimBody(r *http.Request) (map[string]any, error) {
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if !strings.HasPrefix(ct, "application/scim+json") && !strings.HasPrefix(ct, "application/json") {
		return nil, &provisioning.Error{Status: 400, ScimType: "invalidSyntax", Detail: "Content-Type must be application/scim+json"}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, &provisioning.Error{Status: 400, ScimType: "invalidSyntax", Detail: "unreadable body"}
	}
	if err := token.RejectDuplicateKeys(raw); err != nil {
		return nil, &provisioning.Error{Status: 400, ScimType: "invalidSyntax", Detail: "invalid JSON or duplicate members"}
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, &provisioning.Error{Status: 400, ScimType: "invalidSyntax", Detail: "invalid JSON"}
	}
	return doc, nil
}

func writeSCIM(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func listBody(items []any, total, start int) map[string]any {
	return map[string]any{"schemas": []string{provisioning.SchemaList}, "totalResults": total, "startIndex": start, "itemsPerPage": len(items),
		"Resources": items}
}

func toAny(in []map[string]any) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// selectAttrs applies SCIM attribute selection to top-level attributes; id,
// schemas and meta are always returned.
func selectAttrs(r map[string]any, attributes, excluded string) map[string]any {
	split := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, a := range strings.Split(s, ",") {
			a = strings.ToLower(strings.TrimSpace(a))
			if i := strings.LastIndex(a, ":"); i >= 0 {
				a = a[i+1:]
			}
			if h, _, ok := strings.Cut(a, "."); ok {
				a = h
			}
			if a != "" {
				m[a] = true
			}
		}
		return m
	}
	keep := func(k string) bool { return k == "id" || k == "schemas" || k == "meta" }
	if attributes != "" {
		want := split(attributes)
		out := map[string]any{}
		for k, v := range r {
			if keep(k) || want[strings.ToLower(k)] {
				out[k] = v
			}
		}
		return out
	}
	if excluded != "" {
		drop := split(excluded)
		out := map[string]any{}
		for k, v := range r {
			if keep(k) || !drop[strings.ToLower(k)] {
				out[k] = v
			}
		}
		return out
	}
	return r
}
