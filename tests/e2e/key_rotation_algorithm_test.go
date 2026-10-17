package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/proudauth/proudauth/internal/audit"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/token"
	"github.com/proudauth/proudauth/internal/worker"
)

// repinResource pins a fixture resource to a signing algorithm (TOK-005).
func repinResource(f *Fixture, id, name, mode, alg string) {
	f.H.t.Helper()
	cur := f.must(f.AdminAPI("GET", "/resources/"+id, nil), 200, "resource")
	f.must(f.H.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/resources/" + id, Token: f.AdminToken,
		JSON:    map[string]any{"name": name, "verification_mode": mode, "signing_algorithm": alg},
		Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}}), 200, "re-pin "+name+" to "+alg)
}

// keyIn returns the realm's token signing key in a state.
func keyIn(t *testing.T, h *Harness, state string) (token.KeyMetadata, bool) {
	t.Helper()
	list, err := h.App.KeyMgr.List(context.Background(), h.Realm.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range list {
		if k.State == state {
			return k, true
		}
	}
	return token.KeyMetadata{}, false
}

func algOf(tok string) string {
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(tok, ".")[0])
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	s, _ := m["alg"].(string)
	return s
}

// TestScheduledRotationKeepsRealmAlgorithm covers TOK-012 with TOK-005: the
// worker's scheduled rotation keeps a realm's algorithm, that of its active
// key, instead of reverting it to keys.signing_algorithm, so resources pinned
// to that algorithm keep receiving tokens. A rotation through the admin API
// without an algorithm keeps it too, and new resources pin it.
func TestScheduledRotationKeepsRealmAlgorithm(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	w := worker.New(h.App, "test")
	lifecycle := func() {
		t.Helper()
		if _, err := w.KeyLifecycle(ctx); err != nil {
			t.Fatalf("keys.lifecycle: %v", err)
		}
		h.App.KeyMgr.Invalidate(h.Realm.ID)
	}
	issue := func(what string) string {
		t.Helper()
		lr := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read")
		mustStatus(t, lr.Tokens, 200, what)
		return lr.Tokens.Str("access_token")
	}
	if h.Cfg.Keys.SigningAlgorithm != "RS256" {
		t.Fatalf("deployment default must differ from the realm's algorithm: %s", h.Cfg.Keys.SigningAlgorithm)
	}

	// Move the realm to ES256: re-pin its resources, then rotate.
	repinResource(f, f.Orders, "Orders API", "strict_online", "ES256")
	repinResource(f, f.Billing, "Billing API", "offline", "ES256")
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"algorithm": "ES256", "reason": "algorithm migration"}), 201, "rotate to ES256")
	h.Clock.Advance(h.Cfg.Keys.PrepublishPeriod + time.Minute)
	lifecycle()
	first, ok := keyIn(t, h, "active")
	if !ok || first.Algorithm != "ES256" {
		t.Fatalf("migration key not active: %+v", first)
	}
	if alg := algOf(issue("issuance after the migration")); alg != "ES256" {
		t.Fatalf("access token alg %s", alg)
	}

	// The scheduled rotation keeps ES256 through prepublication and activation.
	h.Clock.Advance(h.Cfg.Keys.RotationInterval + time.Minute)
	lifecycle()
	pending, ok := keyIn(t, h, "pending")
	if !ok {
		t.Fatal("no scheduled rotation after keys.rotation_interval")
	}
	if pending.Algorithm != "ES256" {
		t.Fatalf("scheduled rotation reverted the realm to %s", pending.Algorithm)
	}
	h.Clock.Advance(h.Cfg.Keys.PrepublishPeriod + time.Minute)
	lifecycle()
	active, _ := keyIn(t, h, "active")
	if active.KID == first.KID || active.Algorithm != "ES256" {
		t.Fatalf("scheduled key not activated with the realm's algorithm: %+v (was %+v)", active, first)
	}
	tok := issue("issuance for the pinned resource after the scheduled rotation")
	if kidOf(tok) != active.KID || algOf(tok) != "ES256" {
		t.Fatalf("token signed with %s/%s, want %s/ES256", kidOf(tok), algOf(tok), active.KID)
	}

	// Without an algorithm, the admin API keeps the realm's as well, and a
	// new resource pins it.
	f.ReloginAdmin()
	f.must(f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"mode": "planned", "reason": "CHG-1"}), 201, "planned rotation without algorithm")
	if k, _ := keyIn(t, h, "pending"); k.Algorithm != "ES256" {
		t.Fatalf("admin rotation without algorithm used %s", k.Algorithm)
	}
	res := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Ledger API", "audience": "https://ledger.test", "verification_mode": "offline"}),
		201, "resource without algorithm")
	if alg := res.Str("signing_algorithm"); alg != "ES256" {
		t.Fatalf("new resource pinned %q, want the realm's ES256", alg)
	}
}

// TestKeyRotationGuardsAllCallers covers TOK-005 and TOK-012: KeyManager.Rotate
// itself refuses a key algorithm that pinned resources reject, so the
// scheduled rotation cannot bypass the guard; the worker counts the refusal
// and finishes the lifecycle batch instead of failing it.
func TestKeyRotationGuardsAllCallers(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	_, err := h.App.KeyMgr.Rotate(ctx, h.Realm.ID, "ES256", token.RotationPlanned, audit.System, "direct caller")
	pe, ok := problem.As(err)
	if !ok || pe.Status != 409 || !errors.Is(err, token.ErrRotationPinnedResources) {
		t.Fatalf("Rotate to an algorithm pinned resources reject: %v", err)
	}
	if res, _ := pe.Extensions["resources"].([]string); !slices.Contains(res, f.OrdersAud) || !slices.Contains(res, f.BillingAud) {
		t.Fatalf("refusal names %v", pe.Extensions["resources"])
	}
	if k, ok := keyIn(t, h, "pending"); ok {
		t.Fatalf("refused rotation left a pending key: %+v", k)
	}

	// A realm whose resources pin another algorithm than its active key: the
	// scheduled rotation is refused, counted and does not fail the batch.
	repinResource(f, f.Orders, "Orders API", "strict_online", "ES256")
	h.Clock.Advance(h.Cfg.Keys.RotationInterval + time.Minute)
	if _, err := worker.New(h.App, "test").KeyLifecycle(ctx); err != nil {
		t.Fatalf("a refused rotation failed the lifecycle batch: %v", err)
	}
	if k, ok := keyIn(t, h, "pending"); ok {
		t.Fatalf("scheduled rotation ignored the pinned resource: %+v", k)
	}
	var buf strings.Builder
	h.App.Metrics.Registry.WriteText(&buf)
	if !strings.Contains(buf.String(), `proudauth_key_rotations_refused_total{reason="pinned_resources"} 1`) {
		t.Fatalf("refusal not counted:\n%s", buf.String())
	}
}

// TestKeyRotationKeepsFAPI2Algorithm covers ADV-001 with TOK-012: while fapi2
// clients exist, a rotation to an algorithm FAPI 2.0 does not allow is
// refused by KeyManager.Rotate and by the admin API.
func TestKeyRotationKeepsFAPI2Algorithm(t *testing.T) {
	h := NewHarness(t, func(c *configuration.Config) { c.Keys.SigningAlgorithm = "PS256" })
	f := fixtureOn(t, h)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwks, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "c1", Use: "sig"}}})
	f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "bank-app", "name": "Bank app", "client_type": "confidential",
		"security_profile": "fapi2", "token_endpoint_auth_method": "private_key_jwt", "jwks": json.RawMessage(jwks),
		"redirect_uris": []string{"https://bank.test/cb"}, "grant_types": []string{"authorization_code", "refresh_token"},
		"token_policy": map[string]any{"require_dpop": true}}), 201, "fapi2 client")
	// Resources already pin RS256, so only the fapi2 guard can refuse.
	repinResource(f, f.Orders, "Orders API", "strict_online", "RS256")
	repinResource(f, f.Billing, "Billing API", "offline", "RS256")
	ctx := context.Background()
	_, err := h.App.KeyMgr.Rotate(ctx, h.Realm.ID, "RS256", token.RotationPlanned, audit.System, "downgrade")
	pe, ok := problem.As(err)
	if !ok || pe.Status != 409 || !errors.Is(err, token.ErrRotationFAPI2Clients) {
		t.Fatalf("Rotate to RS256 with fapi2 clients: %v", err)
	}
	if c, _ := pe.Extensions["clients"].([]string); !slices.Contains(c, "bank-app") {
		t.Fatalf("refusal names %v", pe.Extensions["clients"])
	}
	f.ReloginAdmin()
	r := f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"algorithm": "RS256", "reason": "downgrade"})
	if r.Status != 409 || !strings.Contains(string(r.Raw), "bank-app") {
		t.Fatalf("admin rotation to RS256 with fapi2 clients: %d %s", r.Status, r.Raw)
	}
	if k, ok := keyIn(t, h, "pending"); ok {
		t.Fatalf("refused rotation left a pending key: %+v", k)
	}
	f.must(f.AdminAPI("POST", "/signing-key-rotations", map[string]any{"algorithm": "ES256", "reason": "FAPI algorithm change"}), 409, "pinned resources still refuse ES256")
}
