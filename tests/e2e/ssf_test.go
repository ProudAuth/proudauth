package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/ssf"
)

// TestSharedSignalsTransmitter covers AUD-016: a declared Shared Signals
// Framework transmitter profile. A receiver (a client holding
// realm.ssf_streams.manage) creates streams; CAEP and RISC events about its
// own users are queued with their audit evidence and delivered as signed
// Security Event Tokens by poll (RFC 8936) and push (RFC 8935).
func TestSharedSignalsTransmitter(t *testing.T) {
	var mu sync.Mutex
	var pushed, pushAuth, pushType []string
	pushStatus, pushBody := http.StatusAccepted, ""
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		pushed, pushAuth, pushType = append(pushed, string(b)), append(pushAuth, r.Header.Get("Authorization")), append(pushType, r.Header.Get("Content-Type"))
		w.WriteHeader(pushStatus)
		_, _ = w.Write([]byte(pushBody))
	}))
	defer recv.Close()
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	ctx := context.Background()
	iss := h.Realm.Issuer

	mustStatus(t, h.Do(Req{Method: "GET", Path: "/realms/main/.well-known/ssf-configuration"}), 404, "transmitter off")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.SharedSignals.Enabled = true }), 200, "enable transmitter")
	for _, path := range []string{"/realms/main/.well-known/ssf-configuration", "/.well-known/ssf-configuration/realms/main"} {
		md := h.Do(Req{Method: "GET", Path: path})
		mustStatus(t, md, 200, "metadata")
		if md.Str("issuer") != iss || md.Str("configuration_endpoint") != iss+"/ssf/streams" || md.Str("jwks_uri") != iss+"/jwks" {
			t.Fatalf("metadata: %s", md.Raw)
		}
	}

	// A receiver: a confidential client users sign in to, with a service
	// principal holding only the stream permission.
	sp := f.must(f.AdminAPI("POST", "/service-principals", map[string]any{"name": "risk-engine"}), 201, "sp").Str("id")
	role := f.must(f.AdminAPI("POST", "/roles", map[string]any{"boundary_type": "realm", "name": "ssf-receiver",
		"permissions": []string{"realm.ssf_streams.manage"}}), 201, "role").Str("id")
	f.must(f.AdminAPI("POST", "/role-assignments", map[string]any{"role_id": role, "subject": map[string]any{"type": "service_principal", "id": sp}}), 201, "assign")
	cr := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "risk-rp", "name": "Risk-aware app", "client_type": "confidential",
		"service_principal_id": sp, "grant_types": []string{"authorization_code", "client_credentials"}, "redirect_uris": []string{"https://rp.test/cb"}}), 201, "client")
	rp := Client{Ref: cr.Str("client.id"), ID: cr.Str("client.client_id"), Secret: cr.Str("client_secret")}
	resources := f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources")
	var userinfoID, adminID string
	for _, it := range resources.Get("items").([]any) {
		switch m := it.(map[string]any); m["kind"] {
		case "userinfo":
			userinfoID = m["id"].(string)
		case "admin":
			adminID = m["id"].(string)
		}
	}
	f.must(f.AdminAPI("PUT", "/clients/"+rp.Ref+"/resource-grants/"+userinfoID, map[string]any{"allowed_scopes": []string{"openid", "profile", "email"},
		"subject_types": []string{"user"}}), 204, "userinfo grant")
	f.must(f.AdminAPI("PUT", "/clients/"+rp.Ref+"/resource-grants/"+adminID, map[string]any{"allowed_scopes": []string{"proudauth:admin"},
		"subject_types": []string{"service_principal"}}), 204, "admin grant")
	tok := f.MachineToken(rp, iss+"/admin", "proudauth:admin", "").Str("access_token")
	if tok == "" {
		t.Fatal("receiver token")
	}
	call := func(method, path, token string, body any) *Resp {
		return h.Do(Req{Method: method, Path: "/realms/main/ssf/streams" + path, Token: token, JSON: body})
	}
	// Only a permitted machine client manages streams.
	mustStatus(t, call("GET", "", f.AdminToken, nil), 403, "human administrator")
	other := f.MachineToken(f.Clients["orders-rs"], iss+"/admin", "proudauth:admin", "").Str("access_token")
	mustStatus(t, call("GET", "", other, nil), 403, "client without permission")

	poll := call("POST", "", tok, map[string]any{"delivery": map[string]any{"method": ssf.MethodPoll},
		"events_requested": []string{ssf.EventSessionRevoked, ssf.EventAccountDisabled, "https://example.test/unknown"}, "description": "risk"})
	mustStatus(t, poll, 201, "create poll stream")
	pollID := poll.Str("stream_id")
	if poll.Str("delivery.endpoint_url") != iss+"/ssf/streams/"+pollID+"/poll" || poll.Str("aud") != "risk-rp" ||
		len(poll.Get("events_delivered").([]any)) != 2 || len(poll.Get("events_requested").([]any)) != 3 {
		t.Fatalf("stream: %s", poll.Raw)
	}
	mustStatus(t, call("POST", "", tok, map[string]any{"delivery": map[string]any{"method": ssf.MethodPoll}, "subject_scope": "all"}), 403, "scope all")
	mustStatus(t, call("POST", "", tok, map[string]any{"delivery": map[string]any{"method": "urn:example:carrier-pigeon"}}), 422, "bad method")
	if call("GET", "?stream_id="+pollID, tok, nil).Str("stream_id") != pollID {
		t.Fatal("get stream")
	}
	mustStatus(t, call("GET", "?stream_id="+pollID, other, nil), 403, "other receiver")

	// alice authorized the receiver; bob did not.
	h.Login(LoginOpts{ClientID: "risk-rp", ClientSecret: rp.Secret, RedirectURI: "https://rp.test/cb", Scope: "openid", Identifier: "alice@example.test"})
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend alice")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["bob"]+"/suspend", map[string]any{"reason": "investigation"}), 200, "suspend bob")

	keys := h.Do(Req{Method: "GET", Path: "/realms/main/jwks"})
	var jwks jose.JSONWebKeySet
	_ = json.Unmarshal(keys.Raw, &jwks)
	verify := func(raw string) map[string]any {
		t.Helper()
		sig, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256, jose.EdDSA})
		if err != nil {
			t.Fatalf("parse SET: %v", err)
		}
		if typ, _ := sig.Signatures[0].Header.ExtraHeaders["typ"].(string); typ != "secevent+jwt" {
			t.Fatalf("typ = %q", typ)
		}
		k := jwks.Key(sig.Signatures[0].Header.KeyID)
		if len(k) == 0 {
			t.Fatal("unknown signing key")
		}
		payload, err := sig.Verify(k[0])
		if err != nil {
			t.Fatalf("SET signature: %v", err)
		}
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		return claims
	}
	pollNow := func(body map[string]any) (map[string]string, bool) {
		t.Helper()
		r := call("POST", "/"+pollID+"/poll", tok, body)
		mustStatus(t, r, 200, "poll")
		out := map[string]string{}
		for k, v := range r.Get("sets").(map[string]any) {
			out[k] = v.(string)
		}
		return out, r.Get("moreAvailable") == true
	}
	sets, _ := pollNow(map[string]any{"returnImmediately": true})
	types := map[string]int{}
	for jti, raw := range sets {
		c := verify(raw)
		if c["jti"] != jti || c["iss"] != iss || c["aud"] != "risk-rp" {
			t.Fatalf("SET claims: %v", c)
		}
		sub, _ := c["sub_id"].(map[string]any)
		user := sub
		if sub["format"] == "complex" {
			user, _ = sub["user"].(map[string]any)
			if s, _ := sub["session"].(map[string]any); s["format"] != "opaque" || s["id"] == "" {
				t.Fatalf("session subject: %v", sub)
			}
		}
		if user["format"] != "iss_sub" || user["sub"] != f.Users["alice"] || user["iss"] != iss {
			t.Fatalf("subject: %v", c["sub_id"])
		}
		for typ, body := range c["events"].(map[string]any) {
			types[typ]++
			if b := body.(map[string]any); b["event_timestamp"] == nil {
				t.Fatalf("event without timestamp: %v", body)
			}
		}
	}
	if types[ssf.EventAccountDisabled] != 1 || types[ssf.EventSessionRevoked] < 1 || len(types) != 2 {
		t.Fatalf("delivered event types: %v", types)
	}
	// Unacknowledged events come back unchanged; acknowledged ones do not.
	again, _ := pollNow(map[string]any{})
	for jti, raw := range sets {
		if again[jti] != raw {
			t.Fatal("a re-polled event changed")
		}
	}
	jtis := []string{}
	for jti := range sets {
		jtis = append(jtis, jti)
	}
	if rest, _ := pollNow(map[string]any{"ack": jtis}); len(rest) != 0 {
		t.Fatalf("acknowledged events returned: %v", rest)
	}

	// Verification.
	mustStatus(t, call("POST", "/verify", tok, map[string]any{"stream_id": pollID, "state": "s-123"}), 204, "verify")
	mustStatus(t, call("POST", "/verify", tok, map[string]any{"stream_id": pollID}), 429, "verify too soon")
	vs, _ := pollNow(map[string]any{})
	if len(vs) != 1 {
		t.Fatalf("verification events: %v", vs)
	}
	for jti, raw := range vs {
		c := verify(raw)
		ev, _ := c["events"].(map[string]any)[ssf.EventVerification].(map[string]any)
		if ev["state"] != "s-123" || c["sub_id"].(map[string]any)["format"] != "opaque" {
			t.Fatalf("verification SET: %v", c)
		}
		pollNow(map[string]any{"ack": []string{jti}})
	}

	// Listed scope narrows events to added subjects; unknown subjects are
	// accepted without effect.
	mustStatus(t, call("PATCH", "", tok, map[string]any{"stream_id": pollID, "subject_scope": "listed"}), 200, "listed")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/suspend", map[string]any{"reason": "again"}), 200, "suspend again")
	if s, _ := pollNow(map[string]any{}); len(s) != 0 {
		t.Fatalf("listed scope leaked events: %d", len(s))
	}
	mustStatus(t, call("POST", "/subjects/add", tok, map[string]any{"stream_id": pollID, "subject": map[string]any{"format": "email", "email": "nobody@example.test"}}), 200, "unknown subject")
	mustStatus(t, call("POST", "/subjects/add", tok, map[string]any{"stream_id": pollID, "subject": map[string]any{"format": "iss_sub", "iss": iss, "sub": f.Users["alice"]}}), 200, "add alice")
	mustStatus(t, call("POST", "/subjects/add", tok, map[string]any{"stream_id": pollID, "subject": map[string]any{"format": "phone_number"}}), 422, "bad format")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate")
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/suspend", map[string]any{"reason": "third"}), 200, "suspend third")
	if s, _ := pollNow(map[string]any{}); len(s) == 0 {
		t.Fatal("added subject received nothing")
	}
	mustStatus(t, call("POST", "/subjects/remove", tok, map[string]any{"stream_id": pollID, "subject": map[string]any{"format": "iss_sub", "iss": iss, "sub": f.Users["alice"]}}), 204, "remove")

	// Push delivery with the receiver's Authorization header.
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/reactivate", map[string]any{"reason": "cleared"}), 200, "reactivate")
	push := call("POST", "", tok, map[string]any{"delivery": map[string]any{"method": ssf.MethodPush, "endpoint_url": recv.URL + "/events",
		"authorization_header": "Bearer receiver-secret"}, "events_requested": []string{ssf.EventAccountDisabled, ssf.EventAccountEnabled}})
	mustStatus(t, push, 201, "push stream")
	pushID := push.Str("stream_id")
	if strings.Contains(string(push.Raw), "receiver-secret") {
		t.Fatal("authorization header echoed")
	}
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/suspend", map[string]any{"reason": "push"}), 200, "suspend for push")
	deliver := func() {
		t.Helper()
		if _, err := h.App.SSF.Deliver(ctx, func(ctx context.Context, id string) (*realm.Realm, error) { return h.App.Realms.ByID(ctx, nil, id) }); err != nil {
			t.Fatal(err)
		}
	}
	deliver()
	mu.Lock()
	if len(pushed) != 1 || pushAuth[0] != "Bearer receiver-secret" || pushType[0] != "application/secevent+jwt" {
		t.Fatalf("push: %v %v %v", pushed, pushAuth, pushType)
	}
	c := verify(pushed[0])
	mu.Unlock()
	if _, ok := c["events"].(map[string]any)[ssf.EventAccountDisabled]; !ok {
		t.Fatalf("pushed SET: %v", c)
	}
	// A 400 rejection fails the event without retries.
	mu.Lock()
	pushStatus, pushBody = http.StatusBadRequest, `{"err":"invalid_audience","description":"wrong aud"}`
	mu.Unlock()
	mustStatus(t, f.AdminAPI("POST", "/users/"+f.Users["alice"]+"/reactivate", map[string]any{"reason": "push"}), 200, "reactivate for push")
	deliver()
	h.Clock.Advance(2 * time.Minute)
	deliver()
	f.ReloginAdmin()
	mu.Lock()
	n := len(pushed)
	mu.Unlock()
	if n != 2 {
		t.Fatalf("rejected event was retried: %d pushes", n)
	}
	evs := f.must(f.AdminAPI("GET", "/ssf-streams/"+pushID+"/events", nil), 200, "admin events")
	states := map[string]bool{}
	for _, it := range evs.Get("items").([]any) {
		states[it.(map[string]any)["state"].(string)] = true
	}
	if !states["delivered"] || !states["failed"] {
		t.Fatalf("event states: %s", evs.Raw)
	}

	// Administrators see every stream and can pause one; the receiver is told.
	list := f.must(f.AdminAPI("GET", "/ssf-streams", nil), 200, "admin list")
	if len(list.Get("items").([]any)) != 2 {
		t.Fatalf("admin list: %s", list.Raw)
	}
	f.must(f.AdminAPI("POST", "/ssf-streams/"+pollID+"/status", map[string]any{"status": "paused", "reason": "maintenance"}), 200, "pause")
	if st := call("GET", "/status?stream_id="+pollID, tok, nil); st.Str("status") != "paused" || st.Str("reason") != "maintenance" {
		t.Fatalf("status: %s", st.Raw)
	}
	if s, _ := pollNow(map[string]any{}); len(s) != 0 {
		t.Fatal("a paused stream delivered")
	}
	mustStatus(t, call("POST", "/status", tok, map[string]any{"stream_id": pollID, "status": "enabled"}), 200, "receiver enables")
	s, _ := pollNow(map[string]any{})
	updated := 0
	for _, raw := range s {
		if _, ok := verify(raw)["events"].(map[string]any)[ssf.EventStreamUpdated]; ok {
			updated++
		}
	}
	if updated != 1 {
		t.Fatalf("stream-updated events: %d", updated)
	}
	f.must(f.AdminAPI("PATCH", "/ssf-streams/"+pollID, map[string]any{"subject_scope": "all"}), 200, "admin sets all")
	mustStatus(t, call("PATCH", "", tok, map[string]any{"stream_id": pollID, "subject_scope": "client_users"}), 403, "receiver cannot undo admin scope")
	// Echoing the configuration it read is not a change.
	mustStatus(t, call("PATCH", "", tok, map[string]any{"stream_id": pollID, "subject_scope": "all"}), 200, "receiver echoes admin scope")

	// Retention: a delivered push stays delivered; it is never relabelled
	// expired.
	h.Clock.Advance(8 * 24 * time.Hour)
	if _, err := h.App.SSF.Prune(ctx); err != nil {
		t.Fatal(err)
	}
	f.ReloginAdmin()
	tok = f.MachineToken(rp, iss+"/admin", "proudauth:admin", "").Str("access_token")
	kept := f.must(f.AdminAPI("GET", "/ssf-streams/"+pushID+"/events", nil), 200, "events after retention")
	if s := jsonString(kept.Get("items")); !strings.Contains(s, `"delivered"`) || strings.Contains(s, `"expired"`) {
		t.Fatalf("delivered pushes after retention: %s", s)
	}

	mustStatus(t, call("DELETE", "?stream_id="+pushID, tok, nil), 204, "delete")
	mustStatus(t, call("GET", "?stream_id="+pushID, tok, nil), 404, "deleted")
	mustStatus(t, f.SetPolicy(func(p *realm.Policy) { p.SharedSignals.Enabled = false }), 200, "disable transmitter")
	mustStatus(t, call("GET", "", tok, nil), 404, "transmitter off")
}
