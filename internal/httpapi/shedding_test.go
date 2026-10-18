package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/observability"
	"github.com/proudauth/proudauth/internal/platform/clock"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/storage"
	"github.com/proudauth/proudauth/internal/testutil"
	"github.com/proudauth/proudauth/internal/token"
)

// TestReservedPoolAdmission covers NFR-002: with every ordinary request slot
// taken, a request to an administrative path gets the reserved pool only
// when its bearer is a JWT whose header names, with its algorithm, a signing
// key of the path's realm that this process has cached. A junk, opaque,
// Basic or unknown-key credential, a key of another realm, an unloaded realm
// or no credential is shed with 503 and Retry-After without taking a
// reserve slot. Admission reads only caches, also past their TTL: the
// database is closed before the first request. /health/* keeps the
// reserve, a full reserve sheds credentialed administration too, and with
// ordinary capacity free a junk credential is served from the ordinary pool.
func TestReservedPoolAdmission(t *testing.T) {
	ctx := context.Background()
	admin := testutil.NewDB(t)
	// A pool of its own, closed once the caches are warm: any database query
	// during admission would fail and shed the request.
	db, err := storage.Open(ctx, admin.Pool.Config().ConnString(), storage.Options{MaxConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	cfg := configuration.Defaults()
	clk := clock.NewFake(time.Now())
	d := runtime.New(db, &cfg, clk, keys.NewRandom(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	a := &App{D: d, Metrics: observability.NewMetrics(), Realms: realm.NewService(d), KeyMgr: token.NewKeyManager(d)}
	signer := &token.Signer{Keys: a.KeyMgr}
	realmTokens := map[string]string{}
	for _, name := range []string{"main", "other"} {
		var rlm *realm.Realm
		if err := db.Tx(ctx, func(tx pgx.Tx) error {
			var err error
			rlm, err = a.Realms.CreateTx(ctx, tx, name, name, realm.Policy{})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := a.KeyMgr.CreateKey(ctx, db.Pool, rlm.ID, "ES256", token.StateActive, "token"); err != nil {
			t.Fatal(err)
		}
		// Request handling caches the realm by name; signing caches its keys.
		if _, err := a.Realms.ByName(ctx, name); err != nil {
			t.Fatal(err)
		}
		tok, err := signer.Sign(ctx, rlm.ID, token.TypeAccess, map[string]any{"sub": "usr_1", "jti": "jti_" + name})
		if err != nil {
			t.Fatal(err)
		}
		realmTokens[name] = tok
	}
	db.Close()
	// Past both cache TTLs: ByName or Lookup would now query the closed pool.
	clk.Advance(time.Minute)

	tok := realmTokens["main"]
	head, rest, _ := strings.Cut(tok, ".")
	hdr, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdr, &header); err != nil || header.Kid == "" {
		t.Fatalf("signed token header %s: %v", hdr, err)
	}
	kid := header.Kid
	forged := func(header string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + rest
	}

	a.inflight = make(chan struct{}, 1)
	a.adminSlots = make(chan struct{}, 1)
	var ran bool
	var heldReserve, heldOrdinary int
	h := a.middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran, heldReserve, heldOrdinary = true, len(a.adminSlots), len(a.inflight)
		w.WriteHeader(http.StatusNoContent)
	}))
	do := func(path, authorization string) *httptest.ResponseRecorder {
		t.Helper()
		ran, heldReserve, heldOrdinary = false, 0, 0
		reserve, ordinary := len(a.adminSlots), len(a.inflight)
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if len(a.adminSlots) != reserve || len(a.inflight) != ordinary {
			t.Fatalf("%s: pool slots not released after the request", path)
		}
		return w
	}

	a.inflight <- struct{}{} // every ordinary slot is busy
	for _, tc := range []struct{ name, path, authorization string }{
		{"junk bearer", "/api/v1/realms/main/users", "Bearer junk"},
		{"junk in three segments", "/api/v1/realms/main/users", "Bearer a.b.c"},
		{"opaque access token", "/api/v1/realms/main/users", "Bearer " + secret.Token(secret.PrefixOpaqueAccess)},
		{"Basic credentials", "/api/v1/realms/main/users", "Basic dXNlcjpwYXNz"},
		{"unknown key", "/api/v1/realms/main/users", "Bearer " + forged(`{"alg":"ES256","kid":"es256-20261018-0123456789abcdef","typ":"at+jwt"}`)},
		{"known key, other algorithm", "/api/v1/realms/main/users", "Bearer " + forged(`{"alg":"RS256","kid":"`+kid+`","typ":"at+jwt"}`)},
		{"no signature", "/api/v1/realms/main/users", "Bearer " + strings.TrimSuffix(tok, tok[strings.LastIndexByte(tok, '.')+1:])},
		{"another realm's key", "/api/v1/realms/main/settings", "Bearer " + realmTokens["other"]},
		{"realm not loaded", "/api/v1/realms/unloaded/users", "Bearer " + tok},
		{"no credential", "/api/v1/realms/main/users", ""},
	} {
		w := do(tc.path, tc.authorization)
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "2" || ran {
			t.Errorf("%s: %d (handler ran: %v), want 503 with Retry-After from the ordinary pool", tc.name, w.Code, ran)
		}
	}

	for _, tc := range []struct{ name, path, authorization string }{
		{"access token", "/api/v1/realms/main/users", "Bearer " + tok},
		{"DPoP scheme", "/api/v1/realms/main/emergency/controls", "DPoP " + tok},
		{"other realm's own token", "/api/v1/realms/other/sessions", "Bearer " + realmTokens["other"]},
		{"health probe", "/health/live", ""},
	} {
		w := do(tc.path, tc.authorization)
		if w.Code != http.StatusNoContent || !ran || heldReserve != 1 {
			t.Errorf("%s: %d (handler ran: %v, reserve slots held: %d), want it served from the reserve", tc.name, w.Code, ran, heldReserve)
		}
	}

	a.adminSlots <- struct{}{} // the reserve is full too
	if w := do("/api/v1/realms/main/users", "Bearer "+tok); w.Code != http.StatusServiceUnavailable || ran {
		t.Errorf("full reserve: %d (handler ran: %v), want 503", w.Code, ran)
	}
	<-a.adminSlots

	<-a.inflight // ordinary capacity is free again
	if w := do("/api/v1/realms/main/users", "Bearer junk"); w.Code != http.StatusNoContent || heldReserve != 0 || heldOrdinary != 1 {
		t.Errorf("junk bearer with ordinary capacity: %d (reserve %d, ordinary %d), want it served from the ordinary pool", w.Code, heldReserve, heldOrdinary)
	}
}
