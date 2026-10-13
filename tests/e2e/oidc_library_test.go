package e2e

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/proudbase/proudauth/internal/audit"
	"github.com/proudbase/proudauth/internal/token"
)

// TestOIDCRelyingPartyLibrary runs an independent, third-party OpenID Connect
// relying-party stack against the server: github.com/coreos/go-oidc/v3
// (v3.18.0) and golang.org/x/oauth2 (v0.37.0), at the versions pinned in
// go.mod, with none of this repository's client code in the token path.
// QA-004 (a named external client at an exact version, recorded in
// docs/integrations/interoperability.md), OIDC-001 (the library's
// authorization request, built from discovery, with S256 PKCE, state and
// nonce, is accepted; the code is bound to the library's verifier),
// OIDC-003 (the ID token passes the library's issuer, audience, expiry and
// signature checks, its nonce and at_hash match; an ID token for another
// client or a tampered one is refused) and TOK-011 (the library's remote key
// set verifies through the published JWKS and, after a planned rotation,
// fetches the new key by its kid).
//
// The login itself goes through the headless interaction API with the
// harness's credentials (Harness.AuthorizeHeadless), because the library has
// no login UI; the authorization request, token exchange, ID-token
// verification, UserInfo call and refresh are the library's own.
func TestOIDCRelyingPartyLibrary(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	// A plain HTTP client for the library: no redirect handling is needed and
	// the harness's client must keep its own settings.
	ctx := oidc.ClientContext(context.Background(), &http.Client{Timeout: 30 * time.Second})

	userinfoID := ""
	for _, it := range f.must(f.AdminAPI("GET", "/resources", nil), 200, "resources").Get("items").([]any) {
		if m := it.(map[string]any); m["kind"] == "userinfo" {
			userinfoID = m["id"].(string)
		}
	}
	register := func(clientID, redirect string) Client {
		r := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": clientID, "name": clientID, "client_type": "confidential",
			"first_party": true, "grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{redirect}}), 201, "client "+clientID)
		c := Client{Ref: r.Str("client.id"), ID: clientID, Secret: r.Str("client_secret")}
		f.must(f.AdminAPI("PUT", "/clients/"+c.Ref+"/resource-grants/"+userinfoID, map[string]any{"allowed_scopes": []string{"openid", "profile", "email"},
			"subject_types": []string{"user"}}), 204, "userinfo grant "+clientID)
		return c
	}
	rp := register("go-oidc-rp", "https://rp.test/callback")
	other := register("go-oidc-other", "https://other.test/callback")

	// Discovery (OIDC-001 inputs): the provider document must name this issuer.
	provider, err := oidc.NewProvider(ctx, h.Realm.Issuer)
	if err != nil {
		t.Fatalf("go-oidc discovery: %v", err)
	}
	var meta struct {
		UserInfo string   `json:"userinfo_endpoint"`
		JWKS     string   `json:"jwks_uri"`
		Methods  []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&meta); err != nil || meta.JWKS == "" || meta.UserInfo == "" || !slices.Contains(meta.Methods, "S256") {
		t.Fatalf("discovery document: %+v %v", meta, err)
	}
	config := func(c Client, redirect string) *oauth2.Config {
		return &oauth2.Config{ClientID: c.ID, ClientSecret: c.Secret, Endpoint: provider.Endpoint(), RedirectURL: redirect,
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"}}
	}
	// The harness's fake clock issues the tokens; the library checks expiry
	// against it rather than the wall clock, which TOTP steps move ahead.
	verifier := provider.Verifier(&oidc.Config{ClientID: rp.ID, Now: h.Clock.Now})

	// signIn runs the library's authorization-code flow with PKCE, state and
	// nonce for a user and returns the library's token and verified ID token.
	signIn := func(c Client, redirect, user string, v *oidc.IDTokenVerifier) (*oauth2.Token, string, *oidc.IDToken) {
		t.Helper()
		cfg := config(c, redirect)
		pkce := oauth2.GenerateVerifier()
		state, nonce := oauth2.GenerateVerifier()[:22], oauth2.GenerateVerifier()[:22]
		authURL := cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce))
		back := h.AuthorizeHeadless(authURL, LoginOpts{Identifier: user + "@example.test"})
		if back.Get("state") != state || back.Get("iss") != h.Realm.Issuer || back.Get("code") == "" {
			t.Fatalf("authorization response: %v", back)
		}
		// The code is bound to the library's PKCE verifier: another verifier fails.
		if _, err := cfg.Exchange(ctx, back.Get("code"), oauth2.VerifierOption(oauth2.GenerateVerifier())); err == nil {
			t.Fatal("code redeemed with a different PKCE verifier")
		}
		back = h.AuthorizeHeadless(cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)), LoginOpts{Identifier: user + "@example.test"})
		tok, err := cfg.Exchange(ctx, back.Get("code"), oauth2.VerifierOption(pkce))
		if err != nil {
			t.Fatalf("go-oidc/oauth2 code exchange: %v", err)
		}
		raw, _ := tok.Extra("id_token").(string)
		if raw == "" {
			t.Fatal("no id_token in the token response")
		}
		if v == nil {
			return tok, raw, nil
		}
		idt, err := v.Verify(ctx, raw)
		if err != nil {
			t.Fatalf("go-oidc ID-token verification: %v", err)
		}
		if idt.Nonce != nonce {
			t.Fatalf("nonce %q, want %q", idt.Nonce, nonce)
		}
		if err := idt.VerifyAccessToken(tok.AccessToken); err != nil {
			t.Fatalf("at_hash: %v", err)
		}
		return tok, raw, idt
	}

	tok, raw, idt := signIn(rp, "https://rp.test/callback", "alice", verifier)
	if idt.Issuer != h.Realm.Issuer || idt.Subject != f.Users["alice"] || !slices.Contains(idt.Audience, rp.ID) || idt.Expiry.Before(h.Clock.Now()) {
		t.Fatalf("ID token: iss=%s sub=%s aud=%v exp=%s", idt.Issuer, idt.Subject, idt.Audience, idt.Expiry)
	}
	var claims struct {
		AZP string `json:"azp"`
	}
	if err := idt.Claims(&claims); err != nil || claims.AZP != rp.ID {
		t.Fatalf("azp %q: %v", claims.AZP, err)
	}

	// UserInfo through the library, with the access token it obtained.
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		t.Fatalf("go-oidc UserInfo: %v", err)
	}
	if info.Subject != idt.Subject || !strings.EqualFold(info.Email, "alice@example.test") {
		t.Fatalf("UserInfo: sub=%s email=%s", info.Subject, info.Email)
	}

	// Refresh through the library's TokenSource once the token is expired
	// from the library's point of view; the rotated refresh token is used.
	stale := *tok
	stale.Expiry = time.Now().Add(-time.Minute)
	fresh, err := config(rp, "https://rp.test/callback").TokenSource(ctx, &stale).Token()
	if err != nil {
		t.Fatalf("oauth2 refresh: %v", err)
	}
	if fresh.AccessToken == tok.AccessToken || fresh.RefreshToken == "" || fresh.RefreshToken == tok.RefreshToken {
		t.Fatal("refresh did not issue a new access token and a rotated refresh token")
	}
	if rawFresh, _ := fresh.Extra("id_token").(string); rawFresh != "" {
		if again, err := verifier.Verify(ctx, rawFresh); err != nil || again.Subject != idt.Subject {
			t.Fatalf("refreshed ID token: %v", err)
		}
	}
	if info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(fresh)); err != nil || info.Subject != idt.Subject {
		t.Fatalf("UserInfo with the refreshed token: %v", err)
	}

	// Negatives: an ID token issued to another client, and a tampered one.
	_, otherRaw, _ := signIn(other, "https://other.test/callback", "bob", nil)
	if _, err := verifier.Verify(ctx, otherRaw); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("ID token for %s accepted by %s's verifier: %v", other.ID, rp.ID, err)
	}
	if _, err := provider.Verifier(&oidc.Config{ClientID: other.ID, Now: h.Clock.Now}).Verify(ctx, otherRaw); err != nil {
		t.Fatalf("ID token for %s refused by its own verifier: %v", other.ID, err)
	}
	parts := strings.Split(raw, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var body map[string]any
	_ = json.Unmarshal(payload, &body)
	body["sub"] = f.Users["bob"]
	forged, _ := json.Marshal(body)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(forged) + "." + parts[2]
	if _, err := verifier.Verify(ctx, tampered); err == nil {
		t.Fatal("tampered ID token accepted")
	}
	if _, err := verifier.Verify(ctx, parts[0]+"."+parts[1]+"."); err == nil {
		t.Fatal("ID token without a signature accepted")
	}

	// TOK-011 with the library's key cache: a planned rotation switches
	// issuance to a new kid, which the remote key set fetches on first use;
	// the earlier token keeps verifying while its key is still published.
	before := kidOf(raw)
	if _, err := h.App.KeyMgr.Rotate(ctx, h.Realm.ID, "RS256", token.RotationPlanned, audit.System, "go-oidc interop"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.App.KeyMgr.ActivateDue(ctx, 0, time.Hour); err != nil {
		t.Fatal(err)
	}
	h.App.KeyMgr.Invalidate(h.Realm.ID)
	_, rotated, _ := signIn(rp, "https://rp.test/callback", "alice", verifier)
	if kidOf(rotated) == before {
		t.Fatalf("ID token still signed with %s after the rotation", before)
	}
	if _, err := verifier.Verify(ctx, raw); err != nil {
		t.Fatalf("pre-rotation ID token refused while its key is published: %v", err)
	}
	// An emergency rotation withdraws the key: a relying party whose cache
	// starts after it (a fresh provider) refuses tokens signed with it.
	if _, err := h.App.KeyMgr.Rotate(ctx, h.Realm.ID, "RS256", token.RotationEmergency, audit.System, "go-oidc interop"); err != nil {
		t.Fatal(err)
	}
	h.App.KeyMgr.Invalidate(h.Realm.ID)
	later, err := oidc.NewProvider(ctx, h.Realm.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := later.Verifier(&oidc.Config{ClientID: rp.ID, Now: h.Clock.Now}).Verify(ctx, rotated); err == nil {
		t.Fatal("ID token signed with a withdrawn key accepted by a fresh key set")
	}
}
