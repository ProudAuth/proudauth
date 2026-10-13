package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/proudbase/proudauth/internal/platform/ids"
	"github.com/proudbase/proudauth/internal/ssf"
)

// TestSharedSignalsReceiver covers ADV-007: security events pushed by a
// registered transmitter are authenticated (push secret and signature),
// checked for issuer, audience, age and replay, mapped to local accounts
// through an explicit subject mapping, and applied only as the explicit
// action policy says.
func TestSharedSignalsReceiver(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := jose.JSONWebKey{Key: &key.PublicKey, KeyID: "sig-1", Algorithm: "ES256", Use: "sig"}
	pub, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	priv, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key, KeyID: "sig-1", Algorithm: "ES256"}}})

	provider := f.must(f.AdminAPI("POST", "/identity-providers", map[string]any{"alias": "partner", "display_name": "Partner", "issuer": "https://partner.test",
		"client_secret": "s", "config": map[string]any{"client_id": "c"}}), 201, "provider").Str("id")
	if _, err := h.App.D.DB.Pool.Exec(ctx, `INSERT INTO external_identities (id, realm_id, user_id, provider_id, upstream_issuer, upstream_subject,
		linking_provenance) VALUES ($1,$2,$3,$4,'https://partner.test','p-alice','test')`, ids.New(ids.ExternalIdent), h.Realm.ID, f.Users["alice"], provider); err != nil {
		t.Fatal(err)
	}
	base := map[string]any{"name": "partner-signals", "issuer": "https://signals.partner.test", "jwks": json.RawMessage(pub), "provider_id": provider,
		"allow_email_subjects": true}
	bad := func(mut func(m map[string]any)) {
		t.Helper()
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		mustStatus(t, f.AdminAPI("POST", "/ssf-transmitters", m), 422, "invalid transmitter")
	}
	bad(func(m map[string]any) { m["actions"] = map[string]string{ssf.EventAccountEnabled: "suspend_user"} })
	bad(func(m map[string]any) { m["actions"] = map[string]string{"https://example.test/event": "record_only"} })
	bad(func(m map[string]any) { m["jwks"] = json.RawMessage(priv) })
	base["actions"] = map[string]string{ssf.EventSessionRevoked: "revoke_sessions", ssf.EventAccountDisabled: "suspend_user"}
	reg := f.must(f.AdminAPI("POST", "/ssf-transmitters", base), 201, "register")
	id, secret, aud := reg.Str("transmitter.id"), reg.Str("push_secret"), reg.Str("transmitter.push_endpoint")
	if secret == "" || aud != h.Realm.Issuer+"/ssf/receivers/"+id+"/events" {
		t.Fatalf("registration: %s", reg.Raw)
	}
	if strings.Contains(string(f.must(f.AdminAPI("GET", "/ssf-transmitters/"+id, nil), 200, "get").Raw), secret) {
		t.Fatal("push secret shown again")
	}

	signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: "sig-1"}},
		(&jose.SignerOptions{}).WithType("secevent+jwt"))
	set := func(mut func(c map[string]any), signWith jose.Signer) string {
		c := map[string]any{"iss": "https://signals.partner.test", "aud": aud, "iat": h.Clock.Now().Unix(), "jti": ids.New("jti"),
			"sub_id": map[string]any{"format": "iss_sub", "iss": "https://partner.test", "sub": "p-alice"},
			"events": map[string]any{ssf.EventSessionRevoked: map[string]any{"event_timestamp": h.Clock.Now().Unix()}}}
		if mut != nil {
			mut(c)
		}
		b, _ := json.Marshal(c)
		if signWith == nil {
			signWith = signer
		}
		obj, _ := signWith.Sign(b)
		s, _ := obj.CompactSerialize()
		return s
	}
	push := func(tok, bearer string) *Resp {
		hdr := map[string]string{"Content-Type": "application/secevent+jwt"}
		if bearer != "" {
			hdr["Authorization"] = "Bearer " + bearer
		}
		return h.Do(Req{Method: "POST", Path: "/realms/main/ssf/receivers/" + id + "/events", RawBody: []byte(tok), Headers: hdr})
	}
	sessions := func(user string) int {
		var n int
		_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id=$1 AND state='active'`, f.Users[user]).Scan(&n)
		return n
	}
	f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read")
	if sessions("alice") == 0 {
		t.Fatal("no session to revoke")
	}

	// Authentication, issuer, audience, signature and age.
	tok := set(nil, nil)
	if r := push(tok, ""); r.Status != 401 || r.Str("err") != "authentication_failed" {
		t.Fatalf("no bearer: %d %s", r.Status, r.Raw)
	}
	if r := push(set(func(c map[string]any) { c["aud"] = "https://elsewhere.test" }, nil), secret); r.Str("err") != "invalid_audience" {
		t.Fatalf("audience: %s", r.Raw)
	}
	if r := push(set(func(c map[string]any) { c["iss"] = "https://evil.test" }, nil), secret); r.Str("err") != "invalid_issuer" {
		t.Fatalf("issuer: %s", r.Raw)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	forger, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: other, KeyID: "sig-1"}}, (&jose.SignerOptions{}).WithType("secevent+jwt"))
	if r := push(set(nil, forger), secret); r.Str("err") != "invalid_key" {
		t.Fatalf("forged signature: %s", r.Raw)
	}
	if r := push(set(func(c map[string]any) { c["iat"] = h.Clock.Now().Add(-48 * time.Hour).Unix() }, nil), secret); r.Str("err") != "invalid_request" {
		t.Fatalf("stale event: %s", r.Raw)
	}
	if sessions("alice") == 0 {
		t.Fatal("a rejected event had an effect")
	}

	// A valid event applies its action once.
	mustStatus(t, push(tok, secret), 202, "session revoked")
	if sessions("alice") != 0 {
		t.Fatal("sessions not revoked")
	}
	f.LoginWeb("alice", f.Acme, f.OrdersAud, "orders:read")
	mustStatus(t, push(tok, secret), 202, "replay accepted without effect")
	if sessions("alice") == 0 {
		t.Fatal("a replayed event acted again")
	}
	// Unmapped event types are recorded only; unknown subjects get the same
	// answer and no action.
	mustStatus(t, push(set(func(c map[string]any) {
		c["events"] = map[string]any{ssf.EventCredentialChange: map[string]any{"credential_type": "password", "change_type": "update"}}
	}, nil), secret), 202, "unmapped event")
	mustStatus(t, push(set(func(c map[string]any) {
		c["sub_id"] = map[string]any{"format": "iss_sub", "iss": "https://partner.test", "sub": "nobody"}
	}, nil), secret), 202, "unknown subject")
	if sessions("alice") == 0 {
		t.Fatal("record-only event acted")
	}
	// Email subjects (allowed for this transmitter) map to verified addresses;
	// account-disabled suspends, except protected accounts.
	mustStatus(t, push(set(func(c map[string]any) {
		c["sub_id"] = map[string]any{"format": "email", "email": "bob@example.test"}
		c["events"] = map[string]any{ssf.EventAccountDisabled: map[string]any{}}
	}, nil), secret), 202, "account disabled")
	var state string
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["bob"]).Scan(&state)
	if state != "suspended" {
		t.Fatalf("bob not suspended: %s", state)
	}
	if _, err := h.App.D.DB.Pool.Exec(ctx, `UPDATE users SET protected=true WHERE id=$1`, f.Users["alice"]); err != nil {
		t.Fatal(err)
	}
	mustStatus(t, push(set(func(c map[string]any) { c["events"] = map[string]any{ssf.EventAccountDisabled: map[string]any{}} }, nil), secret), 202, "protected")
	_ = h.App.D.DB.Pool.QueryRow(ctx, `SELECT state FROM users WHERE id=$1`, f.Users["alice"]).Scan(&state)
	if state != "active" || sessions("alice") != 0 {
		t.Fatalf("protected account handling: state %s sessions %d", state, sessions("alice"))
	}

	ev := f.must(f.AdminAPI("GET", "/ssf-transmitters/"+id+"/events", nil), 200, "received")
	outcomes := jsonString(ev.Get("items"))
	for _, want := range []string{`"applied"`, `"subject_unknown"`, `"protected_account_sessions_revoked"`, `"recorded"`} {
		if !strings.Contains(outcomes, want) {
			t.Fatalf("received events lack %s: %s", want, outcomes)
		}
	}
	if strings.Contains(string(ev.Raw), "p-alice") || strings.Contains(string(ev.Raw), "bob@example.test") {
		t.Fatal("received-event records keep subject identifiers")
	}
	// Rotating the secret retires the old one.
	rot := f.must(f.AdminAPI("POST", "/ssf-transmitters/"+id+"/rotate-secret", nil), 200, "rotate")
	if r := push(set(nil, nil), secret); r.Status != 401 {
		t.Fatalf("old secret accepted: %d", r.Status)
	}
	mustStatus(t, push(set(func(c map[string]any) { c["sub_id"] = map[string]any{"format": "opaque", "id": "x"} }, nil), rot.Str("push_secret")), 202, "new secret")
}
