package e2e

import (
	"context"
	"net/url"
	"testing"

	"github.com/proudbase/proudauth/internal/token"
)

// TestGrantRevocationStopsJWTAuthority covers SES-008, SES-021, SES-023,
// TOK-010 and TOK-017: revoking one grant stops its session/offline JWTs,
// UserInfo and exchanged descendants, without ending another grant or SSO
// session. Account APIs apply the same rule and unlinked/foreign-client grant
// claims cannot replace it. All three independent replicas read live state.
func TestGrantRevocationStopsJWTAuthority(t *testing.T) {
	for _, profile := range []string{"session", "offline"} {
		t.Run(profile, func(t *testing.T) {
			f, nodes := replicaStressFixture(t)
			h := f.H
			scope := "openid orders:read"
			if profile == "offline" {
				scope += " offline_access"
			}
			g := replicaGrantOf(t, h, loginWebOn(nodes[1], f, "alice", f.Acme, f.OrdersAud, scope), f.Clients["web"])
			if jwtPayload(g.access)["grant_id"] != g.grant {
				t.Fatal("access token does not name its own durable grant")
			}
			control := loginWebOn(nodes[2], f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
			account := replicaGrantOf(t, h, f.AccountToken("alice").Tokens, Client{ID: "proudauth-cli"})
			accountControl := accountTokenOn(nodes[2], "alice")
			exchange := func(n *Harness) *Resp {
				return n.TokenRequest(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
					"subject_token": {g.access}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
					"resource": {f.BillingAud}, "scope": {"billing:read"}}, f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret)
			}
			exchanged := exchange(nodes[2])
			mustStatus(t, exchanged, 200, "exchange before revocation")
			if jwtPayload(exchanged.Str("access_token"))["grant_id"] != g.grant {
				t.Fatal("exchange lost the originating grant")
			}
			ui := nodes[1].TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {g.refresh},
				"resource": {h.Realm.Issuer + "/userinfo"}}, g.client.ID, g.client.Secret)
			mustStatus(t, ui, 200, "UserInfo access token")
			for _, n := range nodes {
				replicaIntrospection(t, n, f.Clients["orders-rs"], g.access, true)
				replicaIntrospection(t, n, f.Clients["billing-rs"], exchanged.Str("access_token"), true)
				mustStatus(t, n.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: ui.Str("access_token")}), 200, "UserInfo before revocation")
				mustStatus(t, n.API("GET", "/me", account.access, nil), 200, "account before revocation")
			}
			// Even a correctly signed access-token shape cannot use another
			// client's grant or omit the grant link; mappings/hooks reserve it.
			for name, grantID := range map[string]string{"missing": "", "wrong-client": account.grant, "unknown": "agr_unknown"} {
				claims := jwtPayload(g.access)
				if grantID == "" {
					delete(claims, "grant_id")
				} else {
					claims["grant_id"] = grantID
				}
				forged, err := h.App.OAuth.Signer.Sign(context.Background(), h.Realm.ID, token.TypeAccess, claims)
				if err != nil {
					t.Fatal(err)
				}
				for _, n := range nodes {
					replicaIntrospection(t, n, f.Clients["orders-rs"], forged, false)
				}
				t.Logf("%s grant link refused", name)
			}
			mustStatus(t, nodes[0].Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {ui.Str("refresh_token")}},
				Basic: [2]string{g.client.ID, g.client.Secret}}), 200, "revoke the originating grant")
			mustStatus(t, nodes[0].Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {account.refresh}, "client_id": {"proudauth-cli"}}}), 200, "revoke one account grant")
			for i, n := range nodes {
				replicaIntrospection(t, n, f.Clients["orders-rs"], g.access, false)
				replicaIntrospection(t, n, f.Clients["billing-rs"], exchanged.Str("access_token"), false)
				replicaIntrospection(t, n, f.Clients["orders-rs"], control, true)
				mustStatus(t, n.Do(Req{Method: "GET", Path: "/realms/main/oidc/userinfo", Token: ui.Str("access_token")}), 401, "UserInfo after grant revocation")
				mustStatus(t, n.API("GET", "/me", account.access, nil), 401, "account after grant revocation")
				mustStatus(t, n.API("GET", "/me", accountControl, nil), 200, "other account grant")
				if r := exchange(n); r.Status != 400 || r.Str("error") != "invalid_grant" {
					t.Fatalf("node %d exchanged a revoked grant: %d/%s", i, r.Status, r.Str("error"))
				}
				if r := replicaRefreshOn(n, g, ui.Str("refresh_token")); r.Status != 400 || r.Str("error") != "invalid_grant" {
					t.Fatalf("node %d refreshed a revoked grant: %d/%s", i, r.Status, r.Str("error"))
				}
				var state string
				if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT state FROM sessions WHERE realm_id=$1 AND id=$2`, h.Realm.ID, g.session).Scan(&state); err != nil {
					t.Fatal(err)
				}
				if state != "active" {
					t.Fatal("client-local grant revocation ended the SSO session")
				}
			}
		})
	}
}
