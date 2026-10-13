// Package ordersapi is an example strict-online resource server (SDK-005). It
// demonstrates the §28.2 checklist: trusted issuer and audience, tenant derived from
// verified authority, object ownership checked against its own data, policy
// decisions with mandatory obligations for sensitive operations, and the support
// impersonation contract with actor-aware audit.
package ordersapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/proudbase/proudauth-sdk-go/verifier"
)

// Order is an application-owned record. Ownership is an application fact (§15.2).
type Order struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	OwnerUserID string `json:"owner_user_id"`
	AmountMinor int64  `json:"amount_minor"`
	Status      string `json:"status"`
}

// Config configures the API.
type Config struct {
	Issuer       string
	Audience     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
}

// API is the orders service.
type API struct {
	cfg      Config
	intro    *verifier.Introspector
	support  *verifier.SupportGuard
	mu       sync.Mutex
	orders   map[string]*Order
	Audit    []verifier.SupportEvent
	svcToken string
	svcExp   time.Time
}

// New builds the API and validates the support contract at startup.
func New(cfg Config) (*API, error) {
	a := &API{cfg: cfg, orders: map[string]*Order{}}
	a.intro = &verifier.Introspector{Endpoint: cfg.Issuer + "/oauth/introspect", ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		Issuer: cfg.Issuer, Audience: cfg.Audience, HTTPClient: cfg.HTTPClient}
	a.support = &verifier.SupportGuard{Introspector: a.intro, Auditor: a, WriteOperations: []string{"orders.annotate"}}
	if err := a.support.Validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// RecordSupportAccess persists actor-aware support evidence (IMP-006).
func (a *API) RecordSupportAccess(_ context.Context, ev verifier.SupportEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Audit = append(a.Audit, ev)
	return nil
}

// Put stores an order (test fixture helper).
func (a *API) Put(o Order) {
	a.mu.Lock()
	defer a.mu.Unlock()
	cp := o
	a.orders[o.ID] = &cp
}

// Handler returns the HTTP routes.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orders", a.list)
	mux.HandleFunc("GET /orders/{id}", a.get)
	mux.HandleFunc("POST /orders/{id}/refund", a.refund)
	mux.HandleFunc("POST /orders/{id}/annotate", a.annotate)
	return mux
}

type authn struct {
	claims  *verifier.Claims
	support bool
}

// authenticate verifies every request online. Support tokens go through the
// support guard; everything else through ordinary strict introspection.
func (a *API) authenticate(r *http.Request, operation string, read bool) (*authn, int) {
	raw, err := verifier.BearerToken(r)
	if err != nil {
		return nil, http.StatusUnauthorized
	}
	if strings.HasPrefix(raw, "pa_it_") {
		c, err := a.support.Authorize(r.Context(), raw, operation, read)
		if err != nil {
			if errors.Is(err, verifier.ErrSupportPolicy) {
				return nil, http.StatusForbidden
			}
			if errors.Is(err, verifier.ErrUnavailable) {
				return nil, http.StatusServiceUnavailable
			}
			return nil, http.StatusUnauthorized
		}
		return &authn{claims: c, support: true}, 0
	}
	c, err := a.intro.Authenticate(r.Context(), raw)
	if err != nil {
		if errors.Is(err, verifier.ErrUnavailable) {
			return nil, http.StatusServiceUnavailable // strict-online fails closed (TEST-035)
		}
		return nil, http.StatusUnauthorized
	}
	return &authn{claims: c}, 0
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	au, st := a.authenticate(r, "orders.list", true)
	if au == nil {
		w.WriteHeader(st)
		return
	}
	if au.claims.RequireScope("orders:read") != nil || au.claims.OrgID == "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	a.mu.Lock()
	out := []Order{}
	for _, o := range a.orders {
		if o.OrgID == au.claims.OrgID { // policy-aware filtering, never client-side hiding (AZ-023)
			out = append(out, *o)
		}
	}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "actor": actorOf(au.claims)})
}

func actorOf(c *verifier.Claims) string {
	if c.Actor != nil {
		return c.Actor.Subject
	}
	return ""
}

func (a *API) load(w http.ResponseWriter, r *http.Request, au *authn) *Order {
	a.mu.Lock()
	o, ok := a.orders[r.PathValue("id")]
	a.mu.Unlock()
	// Organization A tokens cannot see Organization B objects; existence is concealed (TEST-007).
	if !ok || au.claims.RequireOrganization(o.OrgID) != nil {
		w.WriteHeader(http.StatusNotFound)
		return nil
	}
	return o
}

func (a *API) get(w http.ResponseWriter, r *http.Request) {
	au, st := a.authenticate(r, "orders.read", true)
	if au == nil {
		w.WriteHeader(st)
		return
	}
	if au.claims.RequireScope("orders:read") != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if o := a.load(w, r, au); o != nil {
		writeJSON(w, http.StatusOK, o)
	}
}

func (a *API) annotate(w http.ResponseWriter, r *http.Request) {
	au, st := a.authenticate(r, "orders.annotate", false)
	if au == nil {
		w.WriteHeader(st)
		return
	}
	if au.claims.RequireScope("orders:write") != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if o := a.load(w, r, au); o != nil {
		writeJSON(w, http.StatusOK, map[string]any{"annotated": o.ID})
	}
}

// refund is a sensitive business operation: it needs the write scope, the
// orders.refund permission in the order's organization and any obligations the
// policy decision returns. Support tokens can never refund (IMP-013).
func (a *API) refund(w http.ResponseWriter, r *http.Request) {
	au, st := a.authenticate(r, "refund", false)
	if au == nil {
		w.WriteHeader(st)
		return
	}
	if au.claims.RequireScope("orders:write") != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	o := a.load(w, r, au)
	if o == nil {
		return
	}
	raw, _ := verifier.BearerToken(r)
	dec, err := a.decide(r.Context(), raw, "orders.refund", o)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable) // PDP unavailable: fail closed
		return
	}
	if allowed, _ := dec["allowed"].(bool); !allowed {
		writeJSON(w, http.StatusForbidden, dec)
		return
	}
	a.mu.Lock()
	o.Status = "refunded"
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, o)
}

func (a *API) serviceToken(ctx context.Context) (string, error) {
	a.mu.Lock()
	if a.svcToken != "" && time.Now().Before(a.svcExp) {
		t := a.svcToken
		a.mu.Unlock()
		return t, nil
	}
	a.mu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {a.cfg.Issuer + "/admin"}, "scope": {"proudauth:admin"}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Issuer+"/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(a.cfg.ClientID), url.QueryEscape(a.cfg.ClientSecret))
	res, err := a.client().Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if res.StatusCode != 200 || json.NewDecoder(res.Body).Decode(&tr) != nil {
		return "", errors.New("token request failed")
	}
	a.mu.Lock()
	a.svcToken, a.svcExp = tr.AccessToken, time.Now().Add(time.Duration(tr.ExpiresIn-10)*time.Second)
	a.mu.Unlock()
	return tr.AccessToken, nil
}

func (a *API) client() *http.Client {
	if a.cfg.HTTPClient != nil {
		return a.cfg.HTTPClient
	}
	return http.DefaultClient
}

// decide calls the policy decision API with trusted resource data from this
// service (amount and organization come from the order record, not the browser).
func (a *API) decide(ctx context.Context, subjectToken, action string, o *Order) (map[string]any, error) {
	tok, err := a.serviceToken(ctx)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]any{"subject_token": subjectToken, "action": action,
		"resource": map[string]any{"type": "order", "id": o.ID, "org_id": o.OrgID}, "context": map[string]any{"operation_amount_minor": o.AmountMinor}})
	realmBase := strings.Replace(a.cfg.Issuer, "/realms/", "/api/v1/realms/", 1)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, realmBase+"/authorization/check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := a.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 {
		return nil, errors.New("decision failed: " + string(b))
	}
	var d map[string]any
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	// Obligations are mandatory: this service cannot satisfy any, so a decision with
	// obligations is a denial (§15.3).
	if obs, ok := d["obligations"].([]any); ok && len(obs) > 0 {
		d["allowed"] = false
	}
	return d, nil
}
