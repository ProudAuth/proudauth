package e2e

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestReplicaSharedSSORevocationStress covers ARC-005, ARC-006, SES-005,
// SES-007, SES-008, SES-014, SES-015, SES-021, SES-023 and NFR-007. Three
// independently created grants really share one browser SSO session. Concurrent
// client-local revocation, offline/bound reuse, session revocation and account
// revocation must preserve their distinct scopes on all three independent pools.
func TestReplicaSharedSSORevocationStress(t *testing.T) {
	for _, profile := range []string{"client-grant", "offline-reuse", "bound-reuse", "session-revoke", "account-wide"} {
		t.Run(profile, func(t *testing.T) {
			f, nodes := replicaStressFixture(t, func(p *realm.Policy) { p.Interaction.LoginUIURL = "https://login.test/ui" })
			h := f.H
			const notesCB = "https://replica-notes.test/cb"
			r := f.must(f.AdminAPI("POST", "/clients", map[string]any{"client_id": "replica-notes", "name": "Replica Notes",
				"client_type": "confidential", "first_party": true, "allow_offline_access": true,
				"grant_types": []string{"authorization_code", "refresh_token"}, "redirect_uris": []string{notesCB}}), 201, "notes client")
			notes := Client{Ref: r.Str("client.id"), ID: r.Str("client.client_id"), Secret: r.Str("client_secret")}
			f.must(f.AdminAPI("PUT", "/clients/"+notes.Ref+"/resource-grants/"+f.Orders,
				map[string]any{"allowed_scopes": []string{"orders:read"}, "subject_types": []string{"user"}}), 204, "notes grant")
			otherUser := loginWebOn(nodes[2], f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
			const rounds, concurrency = 3, 32
			for round := range rounds {
				// Account-wide revocation has a same-second cutoff. Advance
				// deterministically between fixtures; never reset a rate counter.
				h.Clock.Advance(2 * time.Second)
				otherSession := loginWebOn(nodes[2], f, "bob", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
				b := newBrowser(h)
				path, verifier := sesAuthorizeQuery("web-bff", webRedirect, "orders:read", f.OrdersAud, f.Acme, nil)
				done := sesBrowserSignIn(t, b, b.do("GET", path, nil, nil), "bob")
				cookie := respCookie(done, "pa_sid")
				if cookie == nil || cookie.Value == "" {
					t.Fatal("shared SSO fixture has no browser session cookie")
				}
				g0 := replicaGrantOf(t, h, sesRedeem(t, nodes[1], done.Str("redirect_to"), verifier, webRedirect,
					f.Clients["web"].ID, f.Clients["web"].Secret), f.Clients["web"])
				grants := []replicaRefreshGrant{g0}
				for i, scope := range []string{"orders:read", "orders:read offline_access"} {
					path, verifier := sesAuthorizeQuery(notes.ID, notesCB, scope, f.OrdersAud, f.Acme, url.Values{"prompt": {"none"}})
					n := nodes[(round+i+1)%len(nodes)]
					authz := n.Do(Req{Method: "GET", Path: path, Headers: map[string]string{"Cookie": "pa_sid=" + cookie.Value}})
					mustStatus(t, authz, 302, "SSO authorization on another node")
					grants = append(grants, replicaGrantOf(t, h,
						sesRedeem(t, n, authz.Header.Get("Location"), verifier, notesCB, notes.ID, notes.Secret), notes))
				}
				for i, g := range grants {
					if g.session != g0.session || g.offline != (i == 2) || g.grant == "" || g.family == "" {
						t.Fatal("grants do not share the intended SSO session and profiles")
					}
					for _, other := range grants[:i] {
						if g.grant == other.grant || g.family == other.family {
							t.Fatal("SSO clients must have independent grants/families")
						}
					}
					for _, n := range nodes {
						replicaIntrospection(t, n, f.Clients["orders-rs"], g.access, true)
					}
				}
				live := []bool{false, true, true}
				if profile == "offline-reuse" {
					live = []bool{true, true, false}
				} else if profile == "bound-reuse" || profile == "session-revoke" {
					live = []bool{false, false, true}
				} else if profile == "account-wide" {
					live = []bool{false, false, false}
				}
				sessionLive := profile == "client-grant" || profile == "offline-reuse"
				reuseTarget := -1
				if profile == "offline-reuse" {
					reuseTarget = 2
				} else if profile == "bound-reuse" {
					reuseTarget = 0
				}
				winners := make([]*Resp, len(grants))
				refreshIndex := func(i int) int {
					if reuseTarget >= 0 {
						if i < 30 {
							return reuseTarget
						}
						if reuseTarget == 2 {
							return i - 30
						}
						return i - 29
					}
					return i - 16
				}
				results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
					if reuseTarget >= 0 || (i >= 16 && i < 19) {
						g := grants[refreshIndex(i)]
						return replicaRefreshOn(n, g, g.refresh)
					}
					if i >= 19 {
						return n.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, grants[2].access)
					}
					switch profile {
					case "client-grant":
						return n.Do(Req{Method: "POST", Path: "/realms/main/oauth/revoke", Form: url.Values{"token": {g0.refresh}},
							Basic: [2]string{g0.client.ID, g0.client.Secret}})
					case "session-revoke":
						return n.API("DELETE", "/users/"+f.Users["bob"]+"/sessions/"+g0.session, f.AdminToken, nil)
					default:
						return n.API("POST", "/users/"+f.Users["bob"]+"/revoke-sessions", f.AdminToken, map[string]any{})
					}
				})
				for i, r := range results {
					if reuseTarget < 0 && i < 16 {
						want := 200
						if profile == "session-revoke" {
							want = 204
						}
						mustStatus(t, r, want, "concurrent revocation receipt")
						continue
					}
					if reuseTarget < 0 && i >= 19 {
						if r.Status != 200 || (r.Get("active") != true && r.Get("active") != false) ||
							(profile != "account-wide" && r.Get("active") != (profile != "offline-reuse")) {
							t.Fatalf("concurrent offline introspection: %d, active %v", r.Status, r.Get("active"))
						}
						continue
					}
					index := refreshIndex(i)
					if r.Status == 200 && r.Str("access_token") != "" && r.Str("refresh_token") != "" {
						if winners[index] != nil {
							t.Fatal("same shared-session family produced two successors")
						}
						winners[index] = r
					} else if r.Status != 400 || r.Str("error") != "invalid_grant" || (index != reuseTarget && live[index]) {
						t.Fatalf("shared SSO refresh %d: %d/%s", index, r.Status, r.Str("error"))
					}
				}
				if reuseTarget >= 0 && winners[reuseTarget] == nil {
					t.Fatal("reuse burst must first produce exactly one successor")
				}
				// After every receipt has returned, rotate each surviving family
				// once and reject every ended family. The other 29 requests check
				// online authority; no legitimate token is presented twice here.
				post := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
					index := i % len(grants)
					g := grants[index]
					if i < len(grants) {
						plain := g.refresh
						if winner := winners[index]; winner != nil {
							plain = winner.Str("refresh_token")
						}
						return replicaRefreshOn(n, g, plain)
					}
					return n.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, g.access)
				})
				for i, r := range post {
					index := i % len(grants)
					if i < len(grants) {
						if live[index] {
							mustStatus(t, r, 200, "unaffected family remains refreshable")
							if r.Str("access_token") == "" || r.Str("refresh_token") == "" {
								t.Fatal("surviving grant returned empty authority")
							}
						} else if r.Status != 400 || r.Str("error") != "invalid_grant" {
							t.Fatalf("ended shared SSO family refreshed: %d/%s", r.Status, r.Str("error"))
						}
					} else if r.Status != 200 || r.Get("active") != live[index] {
						t.Fatalf("post-commit authority: %d active %v, want %v", r.Status, r.Get("active"), live[index])
					}
				}
				for node, n := range nodes {
					replicaIntrospection(t, n, f.Clients["orders-rs"], otherUser, true)
					replicaIntrospection(t, n, f.Clients["orders-rs"], otherSession, profile != "account-wide")
					for i, g := range grants {
						if winner := winners[i]; winner != nil {
							replicaIntrospection(t, n, f.Clients["orders-rs"], winner.Str("access_token"), live[i])
						}
						if live[i] {
							replicaIntrospection(t, n, f.Clients["orders-rs"], post[i].Str("access_token"), true)
						}
						wantGeneration := 1
						if winners[i] != nil {
							wantGeneration++
						}
						if live[i] {
							wantGeneration++
						}
						wantFamily, wantGrant := "revoked", "revoked"
						if live[i] {
							wantFamily, wantGrant = "active", "active"
						} else if i == reuseTarget {
							wantFamily = "compromised"
						}
						var familyState, grantState string
						var generation, tokens, roots, consumed, badLineage, audits, events int
						if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT f.state,g.state,f.current_generation,
							(SELECT count(*) FROM refresh_tokens WHERE family_id=f.id),
							(SELECT count(*) FROM refresh_tokens WHERE family_id=f.id AND generation=1 AND parent_id IS NULL AND token_digest=$3),
							(SELECT count(*) FROM refresh_tokens WHERE family_id=f.id AND consumed_at IS NOT NULL),
							(SELECT count(*) FROM refresh_tokens child LEFT JOIN refresh_tokens parent ON parent.id=child.parent_id
							 WHERE child.family_id=f.id AND child.generation>1 AND
							 (parent.id IS NULL OR parent.family_id<>f.id OR parent.generation<>child.generation-1)),
							(SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='token.refresh.reuse_detected' AND grant_id=g.id),
							(SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='security.refresh_reuse_detected' AND aggregate_id=g.id)
							FROM refresh_families f JOIN authorization_grants g ON g.id=f.grant_id WHERE f.realm_id=$1 AND f.id=$2`,
							h.Realm.ID, g.family, secret.Digest(g.refresh)).Scan(&familyState, &grantState, &generation, &tokens, &roots, &consumed, &badLineage, &audits, &events); err != nil {
							t.Fatal(err)
						}
						wantReuse := 0
						if i == reuseTarget {
							wantReuse = 1
						}
						if familyState != wantFamily || grantState != wantGrant || generation != wantGeneration || tokens != generation ||
							roots != 1 || consumed != generation-1 || badLineage != 0 || audits != wantReuse || events != wantReuse {
							t.Fatalf("round %d node %d grant %d: family/grant %s/%s, gen/tokens/root/consumed/bad/audit/event %d/%d/%d/%d/%d/%d/%d",
								round, node, i, familyState, grantState, generation, tokens, roots, consumed, badLineage, audits, events)
						}
					}
					var state string
					var clients, activeClients, audits, events, revocations int
					if err := n.App.D.DB.Pool.QueryRow(context.Background(), `SELECT s.state,
						(SELECT count(*) FROM client_sessions WHERE session_id=s.id),
						(SELECT count(*) FROM client_sessions WHERE session_id=s.id AND state='active'),
						(SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='session.revoked' AND session_id=s.id),
						(SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='session.revoked' AND payload->'data'->>'session_id'=s.id),
						(SELECT count(*) FROM token_revocations WHERE realm_id=$1 AND reference_type='session' AND reference_id=s.id)
						FROM sessions s WHERE s.realm_id=$1 AND s.id=$2`, h.Realm.ID, g0.session).
						Scan(&state, &clients, &activeClients, &audits, &events, &revocations); err != nil {
						t.Fatal(err)
					}
					wantState, wantActive, wantEvents := "revoked", 0, 1
					if sessionLive {
						wantState, wantActive, wantEvents = "active", 2, 0
					}
					if state != wantState || clients != 2 || activeClients != wantActive || audits != wantEvents || events != wantEvents || revocations != wantEvents {
						t.Fatalf("round %d node %d: SSO %s clients/active/audit/event/revocation %d/%d/%d/%d/%d", round, node, state, clients, activeClients, audits, events, revocations)
					}
					path, _ := sesAuthorizeQuery("web-bff", webRedirect, "orders:read", f.OrdersAud, f.Acme, url.Values{"prompt": {"none"}})
					authz := n.Do(Req{Method: "GET", Path: path, Headers: map[string]string{"Cookie": "pa_sid=" + cookie.Value}})
					loc, err := url.Parse(authz.Header.Get("Location"))
					if err != nil || authz.Status != 302 || loc == nil ||
						(sessionLive && loc.Query().Get("code") == "") || (!sessionLive && loc.Query().Get("error") != "login_required") {
						t.Fatal("silent SSO disagrees with the committed logout scope")
					}
				}
				t.Logf("round %d: all 32 race and 32 post-commit observations accounted for; three shared-SSO families preserve %s scope on every pool", round+1, profile)
			}
		})
	}
}
