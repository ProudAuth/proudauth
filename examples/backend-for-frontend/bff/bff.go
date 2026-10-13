// Package bff is an example backend-for-frontend (SDK-004, §28.4). Tokens never
// reach the browser: the BFF stores them server-side, keyed by an opaque HttpOnly
// session cookie, refreshes them with per-session serialization, and proxies API
// calls. State-changing BFF routes require a same-origin request.
package bff

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/proudbase/proudauth-sdk-go/oidcclient"
)

// BFF is the example server.
type BFF struct {
	Client             *oidcclient.Client
	OrdersAPI          string
	PostLogoutRedirect string
	Origin             string
	mu                 sync.Mutex
	pending            map[string]*oidcclient.AuthRequest // login state, server-side
	sessions           map[string]*sess
}

type sess struct {
	tokens  *oidcclient.Session
	idToken string
	subject string
}

// New builds a BFF.
func New(c *oidcclient.Client, ordersAPI, origin, postLogout string) *BFF {
	return &BFF{Client: c, OrdersAPI: ordersAPI, Origin: origin, PostLogoutRedirect: postLogout,
		pending: map[string]*oidcclient.AuthRequest{}, sessions: map[string]*sess{}}
}

func cookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}

// Handler returns routes.
func (b *BFF) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", b.login)
	mux.HandleFunc("GET /callback", b.callback)
	mux.HandleFunc("GET /api/orders", b.orders)
	mux.HandleFunc("GET /api/me", b.me)
	mux.HandleFunc("POST /logout", b.logout)
	return mux
}

func (b *BFF) login(w http.ResponseWriter, r *http.Request) {
	ar, err := b.Client.AuthCodeURL(r.Context(), url.Values{"organization": {r.URL.Query().Get("organization")}})
	if err != nil {
		http.Error(w, "provider unavailable", http.StatusServiceUnavailable)
		return
	}
	key := oidcclient.Random()
	b.mu.Lock()
	b.pending[key] = ar
	b.mu.Unlock()
	http.SetCookie(w, cookie("bff_login", key, 600))
	http.Redirect(w, r, ar.URL, http.StatusFound)
}

func (b *BFF) callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("bff_login")
	if err != nil {
		http.Error(w, "missing login state", http.StatusBadRequest)
		return
	}
	b.mu.Lock()
	ar := b.pending[c.Value]
	delete(b.pending, c.Value) // single use
	b.mu.Unlock()
	tokens, claims, err := b.Client.Exchange(r.Context(), ar, r.URL.Query())
	if err != nil {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	id := oidcclient.Random()
	b.mu.Lock()
	b.sessions[id] = &sess{tokens: b.Client.NewSession(tokens), idToken: tokens.IDToken, subject: claims.Subject}
	b.mu.Unlock()
	http.SetCookie(w, cookie("bff_login", "", -1))
	http.SetCookie(w, cookie("bff_session", id, 12*3600))
	http.Redirect(w, r, "/", http.StatusFound)
}

func (b *BFF) session(r *http.Request) (*sess, string) {
	c, err := r.Cookie("bff_session")
	if err != nil {
		return nil, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sessions[c.Value], c.Value
}

func (b *BFF) me(w http.ResponseWriter, r *http.Request) {
	s, _ := b.session(r)
	if s == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"subject": s.subject})
}

func (b *BFF) orders(w http.ResponseWriter, r *http.Request) {
	s, _ := b.session(r)
	if s == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	at, err := s.tokens.AccessToken(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized) // reauthenticate
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.OrdersAPI+"/orders", nil)
	req.Header.Set("Authorization", "Bearer "+at)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(res.StatusCode)
	_, _ = io.Copy(w, res.Body)
}

func (b *BFF) logout(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" && o != b.Origin {
		w.WriteHeader(http.StatusForbidden) // CSRF defense for cookie-authenticated POST
		return
	}
	s, id := b.session(r)
	if s == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if t := s.tokens.Tokens(); t != nil && t.RefreshToken != "" {
		_ = b.Client.Revoke(r.Context(), t.RefreshToken)
	}
	b.mu.Lock()
	delete(b.sessions, id)
	b.mu.Unlock()
	http.SetCookie(w, cookie("bff_session", "", -1))
	u, err := b.Client.LogoutURL(r.Context(), s.idToken, b.PostLogoutRedirect, "")
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"logout_url": u})
}
