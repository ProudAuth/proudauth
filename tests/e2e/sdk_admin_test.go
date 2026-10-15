package e2e

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/proudauth/proudauth-sdk-go/admin"
)

// TestAdminSDKInterop covers SDK-007 and SDK-010 against a running server:
// pagination, structured problems, idempotency, preconditions and one-time
// secrets behave as the SDK documents.
func TestAdminSDKInterop(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	ctx := context.Background()
	c := &admin.Client{BaseURL: h.Srv.URL, Realm: "main", Token: admin.StaticToken(f.AdminToken), HTTPClient: h.Srv.Client()}

	users := 0
	if err := admin.List(ctx, c, "/users?limit=2", func(admin.User) error { users++; return nil }); err != nil || users < 3 {
		t.Fatalf("paginated users: %d %v", users, err)
	}
	_, err := c.CreateOrganization(ctx, f.must(f.AdminAPI("GET", "/organizations/"+f.Acme, nil), 200, "org").Str("slug"), "Duplicate")
	var p *admin.Problem
	if !errors.As(err, &p) || p.Status != http.StatusConflict || p.Code == "" || p.RequestID == "" {
		t.Fatalf("structured problem: %v", err)
	}
	key := admin.NewIdempotencyKey()
	first, err := c.CreateOrganization(ctx, "sdk-made", "SDK Made", admin.WithIdempotencyKey(key))
	if err != nil {
		t.Fatal(err)
	}
	again, err := c.CreateOrganization(ctx, "sdk-made", "SDK Made", admin.WithIdempotencyKey(key))
	if err != nil || again.ID != first.ID {
		t.Fatalf("idempotent retry: %v %v", again, err)
	}
	created, err := c.CreateClient(ctx, map[string]any{"client_id": "sdk-svc", "name": "SDK", "client_type": "confidential",
		"grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://sdk.test/cb"}})
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := created["client_secret"].(admin.Secret)
	if !ok || !strings.HasPrefix(secret.Reveal(), "pa_cs_") || strings.Contains(secret.String(), "pa_cs_") {
		t.Fatalf("client secret: %#v", created["client_secret"])
	}
	var org map[string]any
	res, err := c.Do(ctx, http.MethodGet, "/organizations/"+first.ID, nil, &org)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(ctx, http.MethodPatch, "/organizations/"+first.ID, map[string]any{"policy": map[string]any{"mfa_required": true}}, nil,
		admin.WithIfMatch(`W/"v0"`)); !errors.As(err, &p) || p.Status != http.StatusPreconditionFailed {
		t.Fatalf("v0 precondition: %v", err)
	}
	if _, err := c.Do(ctx, http.MethodPatch, "/organizations/"+first.ID, map[string]any{"policy": map[string]any{"mfa_required": true}}, nil,
		admin.WithIfMatch(res.Header.Get("ETag"))); err != nil {
		t.Fatalf("precondition with the current ETag: %v", err)
	}
}
