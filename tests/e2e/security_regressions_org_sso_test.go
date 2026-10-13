package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestOrganizationCreationRefusesForeignConnection covers QA-008, TEN-007 and
// FED-006 ("Another organization's SSO connection" in CHANGELOG.md): a new
// organization cannot require another organization's connection as its
// sso_provider_id at creation (422), the way PATCH already refused it
// (TestFederation); a realm-wide connection is accepted.
func TestOrganizationCreationRefusesForeignConnection(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	idp := newFakeIdP(t, h.Clock.Now)
	h.App.Federation.Egress.AllowPrivate = true
	h.App.Federation.Egress.RootCAs = idp.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	conn := func(alias, org string) string {
		body := map[string]any{"alias": alias, "display_name": alias, "issuer": idp.srv.URL, "client_secret": "upstream-secret",
			"config": map[string]any{"client_id": "proudauth-main"}}
		if org != "" {
			body["organization_id"] = org
		}
		return f.must(f.AdminAPI("POST", "/identity-providers", body), 201, "connection "+alias).Str("id")
	}
	acmeConn, shared := conn("acme-sso", f.Acme), conn("shared-sso", "")
	create := func(slug, provider string) *Resp {
		return f.AdminAPI("POST", "/organizations", map[string]any{"slug": slug, "display_name": slug,
			"policy": map[string]any{"sso_required": true, "sso_provider_id": provider}})
	}
	if r := create("initech", acmeConn); r.Status != 422 || !strings.Contains(string(r.Raw), "sso_provider_id") {
		t.Fatalf("organization created requiring another organization's connection: %d %s", r.Status, r.Raw)
	}
	if r := create("initech", "idp_unknown"); r.Status != 422 {
		t.Fatalf("organization created requiring an unknown connection: %d %s", r.Status, r.Raw)
	}
	mustStatus(t, create("initech", shared), 201, "realm-wide connection")
}
