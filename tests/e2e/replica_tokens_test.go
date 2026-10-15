package e2e

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/platform/secret"
)

type replicaRefreshGrant struct {
	access, refresh, family, grant, session string
	client                                  Client
	offline                                 bool
}

func replicaGrantOf(t *testing.T, h *Harness, tokens *Resp, client Client) replicaRefreshGrant {
	t.Helper()
	g := replicaRefreshGrant{access: tokens.Str("access_token"), refresh: tokens.Str("refresh_token"), client: client}
	if g.access == "" || g.refresh == "" {
		t.Fatal("replica fixture lacks access or refresh authority")
	}
	if err := h.App.D.DB.Pool.QueryRow(context.Background(), `SELECT f.id, g.id, g.session_id, g.offline
		FROM refresh_tokens t JOIN refresh_families f ON f.id=t.family_id
		JOIN authorization_grants g ON g.id=f.grant_id WHERE t.realm_id=$1 AND t.token_digest=$2`,
		h.Realm.ID, secret.Digest(g.refresh)).Scan(&g.family, &g.grant, &g.session, &g.offline); err != nil {
		t.Fatal(err)
	}
	return g
}

func replicaRefreshOn(n *Harness, g replicaRefreshGrant, token string) *Resp {
	return n.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}, g.client.ID, g.client.Secret)
}

func replicaIntrospection(t *testing.T, n *Harness, client Client, token string, want bool) {
	t.Helper()
	r := n.Introspect(client.ID, client.Secret, token)
	if r.Status != 200 || r.Get("active") != want {
		t.Fatalf("replica introspection: status %d, active %v, want %v", r.Status, r.Get("active"), want)
	}
}

// TestReplicaRefreshRotationStress covers SES-006, SES-007, SES-008, DB-006,
// TEST-030, TEST-031 and NFR-007. Every family first withstands 32 foreign-client
// attempts without changing, then 32 owning-client redemptions produce exactly
// one successor and one committed reuse event across three independent pools.
// Session-bound JWT/opaque and offline JWT grants retain their distinct effects.
func TestReplicaRefreshRotationStress(t *testing.T) {
	for _, profile := range []string{"session-jwt", "session-opaque", "offline-jwt"} {
		t.Run(profile, func(t *testing.T) {
			f, nodes := replicaStressFixture(t)
			h := f.H
			ctx := context.Background()
			resource, scope := f.OrdersAud, "orders:read"
			if profile == "session-opaque" {
				resource = "https://replica-ledger.test"
				ledger := f.must(f.AdminAPI("POST", "/resources", map[string]any{"name": "Replica ledger", "audience": resource,
					"token_format": "opaque", "verification_mode": "strict_online", "scopes": []map[string]any{{"name": "ledger:read"}}}), 201, "ledger").Str("id")
				f.must(f.AdminAPI("PUT", "/clients/"+f.Clients["web"].Ref+"/resource-grants/"+ledger,
					map[string]any{"allowed_scopes": []string{"ledger:read"}, "subject_types": []string{"user"}}), 204, "ledger grant")
				f.must(f.AdminAPI("POST", "/resources/"+ledger+"/introspectors", map[string]any{"client": f.Clients["orders-rs"].Ref}), 204, "ledger introspector")
				scope = "ledger:read"
			} else if profile == "offline-jwt" {
				scope += " offline_access"
			}
			control := loginWebOn(nodes[1], f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
			const rounds, concurrency = 4, 32
			for round := range rounds {
				g := replicaGrantOf(t, h, loginWebOn(nodes[round%len(nodes)], f, "bob", f.Acme, resource, scope), f.Clients["web"])
				if g.offline != (profile == "offline-jwt") {
					t.Fatal("incorrect refresh profile fixture")
				}
				for _, n := range nodes {
					replicaIntrospection(t, n, f.Clients["orders-rs"], g.access, true)
				}
				foreign := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
					return n.TokenRequest(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {g.refresh}}, "proudauth-cli", "")
				})
				for _, r := range foreign {
					if r.Status != 400 || r.Str("error") != "invalid_grant" {
						t.Fatalf("foreign-client refresh outcome %d/%s", r.Status, r.Str("error"))
					}
				}
				for i, n := range nodes {
					var state string
					var generation, tokens, events int
					if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT state, current_generation,
						(SELECT count(*) FROM refresh_tokens WHERE family_id=$1),
						(SELECT count(*) FROM outbox_events WHERE realm_id=$2 AND event_type='security.refresh_reuse_detected' AND aggregate_id=$3)
						FROM refresh_families WHERE id=$1`, g.family, h.Realm.ID, g.grant).Scan(&state, &generation, &tokens, &events); err != nil {
						t.Fatal(err)
					}
					if state != "active" || generation != 1 || tokens != 1 || events != 0 {
						t.Fatalf("round %d node %d: foreign attempts changed family: %s, generation %d, tokens %d, events %d", round, i, state, generation, tokens, events)
					}
				}
				results := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
					return replicaRefreshOn(n, g, g.refresh)
				})
				accepted, refused := 0, 0
				var winner *Resp
				for _, r := range results {
					switch {
					case r.Status == 200 && r.Str("refresh_token") != "" && r.Str("access_token") != "":
						accepted++
						winner = r
					case r.Status == 400 && r.Str("error") == "invalid_grant":
						refused++
					default:
						t.Fatalf("round %d: refresh outcome %d/%s", round, r.Status, r.Str("error"))
					}
				}
				if accepted != 1 || refused != concurrency-1 {
					t.Fatalf("round %d: %d successors, %d refusals", round, accepted, refused)
				}
				if winner.Str("refresh_token") == g.refresh {
					t.Fatal("refresh did not rotate")
				}
				for i, n := range nodes {
					r := replicaRefreshOn(n, g, winner.Str("refresh_token"))
					if r.Status != 400 || r.Str("error") != "invalid_grant" {
						t.Fatalf("node %d accepted a compromised successor: %d/%s", i, r.Status, r.Str("error"))
					}
					replicaIntrospection(t, n, f.Clients["orders-rs"], g.access, false)
					replicaIntrospection(t, n, f.Clients["orders-rs"], winner.Str("access_token"), false)
					replicaIntrospection(t, n, f.Clients["orders-rs"], control, true)
					var familyState, familyReason, grantState, sessionState string
					var generation, tokens, consumed, revoked, roots, children, audits, events int
					q := n.App.D.DB.Pool
					if err := q.QueryRow(ctx, `SELECT f.state, f.revoke_reason, f.current_generation, g.state, s.state
						FROM refresh_families f JOIN authorization_grants g ON g.id=f.grant_id JOIN sessions s ON s.id=g.session_id
						WHERE f.realm_id=$1 AND f.id=$2`, h.Realm.ID, g.family).Scan(&familyState, &familyReason, &generation, &grantState, &sessionState); err != nil {
						t.Fatal(err)
					}
					if err := q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE consumed_at IS NOT NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL),
						count(*) FILTER (WHERE generation=1 AND parent_id IS NULL AND token_digest=$2),
						count(*) FILTER (WHERE generation=2 AND token_digest=$3 AND parent_id=(SELECT id FROM refresh_tokens WHERE token_digest=$2))
						FROM refresh_tokens WHERE realm_id=$4 AND family_id=$1`, g.family, secret.Digest(g.refresh), secret.Digest(winner.Str("refresh_token")), h.Realm.ID).
						Scan(&tokens, &consumed, &revoked, &roots, &children); err != nil {
						t.Fatal(err)
					}
					if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='token.refresh.reuse_detected' AND grant_id=$2`, h.Realm.ID, g.grant).Scan(&audits); err != nil {
						t.Fatal(err)
					}
					if err := q.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='security.refresh_reuse_detected' AND aggregate_id=$2`, h.Realm.ID, g.grant).Scan(&events); err != nil {
						t.Fatal(err)
					}
					wantSession := "revoked"
					if g.offline {
						wantSession = "active"
					}
					if familyState != "compromised" || familyReason != "reuse_detected" || generation != 2 || grantState != "revoked" || sessionState != wantSession || tokens != 2 || consumed != 1 || revoked != 2 || roots != 1 || children != 1 || audits != 1 || events != 1 {
						t.Fatalf("round %d node %d: family %s/%s gen %d grant %s session %s; tokens/consumed/revoked/root/child/audit/event %d/%d/%d/%d/%d/%d/%d", round, i,
							familyState, familyReason, generation, grantState, sessionState, tokens, consumed, revoked, roots, children, audits, events)
					}
					if profile == "session-opaque" {
						var minted, live int
						if err := q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE revoked_at IS NULL) FROM opaque_access_tokens WHERE realm_id=$1 AND grant_id=$2`, h.Realm.ID, g.grant).Scan(&minted, &live); err != nil {
							t.Fatal(err)
						}
						if minted != 2 || live != 0 {
							t.Fatalf("round %d node %d: minted %d opaque tokens, %d still live", round, i, minted, live)
						}
					}
				}
				t.Logf("round %d: 32 foreign refusals, one successor, 31 invalid grants, one reuse audit/outbox event on every pool", round+1)
			}
		})
	}
}

// TestReplicaRevocationStress covers ARC-005, SES-003, SES-005, SES-023 and
// NFR-007. Refresh and administrator revocation race at concurrency 32, then
// another barrier burst must reject all affected refresh/access/account tokens
// after the revocation responses. Unrelated users remain active on every node.
func TestReplicaRevocationStress(t *testing.T) {
	for _, profile := range []string{"one-session", "account-wide"} {
		t.Run(profile, func(t *testing.T) {
			f, nodes := replicaStressFixture(t)
			h := f.H
			ctx := context.Background()
			control := loginWebOn(nodes[1], f, "alice", f.Acme, f.OrdersAud, "orders:read").Str("access_token")
			const rounds, concurrency = 3, 32
			for round := range rounds {
				// Account revocation covers tokens issued in its same second.
				// Start the next fixture after that boundary, without resetting state.
				h.Clock.Advance(2 * time.Second)
				bound := replicaGrantOf(t, h, loginWebOn(nodes[round%len(nodes)], f, "bob", f.Acme, f.OrdersAud, "orders:read"), f.Clients["web"])
				grants := []replicaRefreshGrant{bound}
				account := accountTokenOn(nodes[(round+1)%len(nodes)], "bob")
				if profile == "account-wide" {
					grants = append(grants, replicaGrantOf(t, h, loginWebOn(nodes[(round+2)%len(nodes)], f, "bob", f.Acme, f.OrdersAud, "orders:read offline_access"), f.Clients["web"]))
				}
				for _, n := range nodes {
					for _, g := range grants {
						replicaIntrospection(t, n, f.Clients["orders-rs"], g.access, true)
					}
					mustStatus(t, n.API("GET", "/me", account, nil), 200, "account before revocation")
				}
				results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
					if i%2 == 0 {
						if profile == "account-wide" {
							return n.API("POST", "/users/"+f.Users["bob"]+"/revoke-sessions", f.AdminToken, map[string]any{})
						}
						return n.API("DELETE", "/users/"+f.Users["bob"]+"/sessions/"+bound.session, f.AdminToken, nil)
					}
					g := grants[(i/2)%len(grants)]
					return replicaRefreshOn(n, g, g.refresh)
				})
				winners := make([]*Resp, len(grants))
				for i, r := range results {
					if i%2 == 0 {
						want := 204
						if profile == "account-wide" {
							want = 200
						}
						mustStatus(t, r, want, "concurrent administrator revocation")
						continue
					}
					index := (i / 2) % len(grants)
					if r.Status == 200 && r.Str("access_token") != "" && r.Str("refresh_token") != "" {
						if winners[index] != nil {
							t.Fatal("revocation race issued two successors for one generation")
						}
						winners[index] = r
					} else if r.Status != 400 || r.Str("error") != "invalid_grant" {
						t.Fatalf("revocation race refresh outcome %d/%s", r.Status, r.Str("error"))
					}
				}
				// These requests begin only after every revocation response, not
				// merely after its request was queued. Pre-commit winners are allowed.
				post := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
					g := grants[(i/2)%len(grants)]
					if i%2 == 0 {
						token := g.refresh
						if winner := winners[(i/2)%len(grants)]; winner != nil {
							token = winner.Str("refresh_token")
						}
						return replicaRefreshOn(n, g, token)
					}
					return n.Introspect(f.Clients["orders-rs"].ID, f.Clients["orders-rs"].Secret, g.access)
				})
				for i, r := range post {
					if i%2 == 0 {
						if r.Status != 400 || r.Str("error") != "invalid_grant" {
							t.Fatalf("post-commit refresh outcome %d/%s", r.Status, r.Str("error"))
						}
					} else if r.Status != 200 || r.Get("active") != false {
						t.Fatalf("post-commit introspection outcome %d, active %v", r.Status, r.Get("active"))
					}
				}
				for i, n := range nodes {
					replicaIntrospection(t, n, f.Clients["orders-rs"], control, true)
					wantAccount := 200
					if profile == "account-wide" {
						wantAccount = 401
					}
					mustStatus(t, n.API("GET", "/me", account, nil), wantAccount, "account after revocation")
					for index, g := range grants {
						var familyState, grantState string
						var generation, tokens, activeGrants, children int
						if err := n.App.D.DB.Pool.QueryRow(ctx, `SELECT f.state, f.current_generation, g.state,
							(SELECT count(*) FROM refresh_tokens WHERE family_id=f.id),
							(SELECT count(*) FROM refresh_tokens WHERE family_id=f.id AND parent_id IS NOT NULL),
							(SELECT count(*) FROM authorization_grants WHERE id=g.id AND state='active')
							FROM refresh_families f JOIN authorization_grants g ON g.id=f.grant_id WHERE f.realm_id=$1 AND f.id=$2`,
							h.Realm.ID, g.family).Scan(&familyState, &generation, &grantState, &tokens, &children, &activeGrants); err != nil {
							t.Fatal(err)
						}
						wantGeneration := 1
						if winner := winners[index]; winner != nil {
							wantGeneration++
							replicaIntrospection(t, n, f.Clients["orders-rs"], winner.Str("access_token"), false)
						}
						if (familyState != "revoked" && familyState != "compromised") || generation != wantGeneration || tokens != wantGeneration || children != wantGeneration-1 || grantState != "revoked" || activeGrants != 0 {
							t.Fatalf("round %d node %d: family %s gen/tokens/children %d/%d/%d, grant %s, active %d", round, i, familyState, generation, tokens, children, grantState, activeGrants)
						}
					}
					var state string
					var transitions, events, revocations int
					q := n.App.D.DB.Pool
					if err := q.QueryRow(ctx, `SELECT state,
						(SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='session.revoked' AND session_id=$2),
						(SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='session.revoked' AND payload->'data'->>'session_id'=$2),
						(SELECT count(*) FROM token_revocations WHERE realm_id=$1 AND reference_type='session' AND reference_id=$2)
						FROM sessions WHERE realm_id=$1 AND id=$2`, h.Realm.ID, bound.session).Scan(&state, &transitions, &events, &revocations); err != nil {
						t.Fatal(err)
					}
					if state != "revoked" || transitions != 1 || events != 1 || revocations != 1 {
						t.Fatalf("round %d node %d: session %s, transitions/events/revocations %d/%d/%d", round, i, state, transitions, events, revocations)
					}
					if profile == "account-wide" {
						var liveSessions, liveGrants, liveFamilies, userRevocations int
						if err := q.QueryRow(ctx, `SELECT
							(SELECT count(*) FROM sessions WHERE realm_id=$1 AND user_id=$2 AND state='active'),
							(SELECT count(*) FROM authorization_grants WHERE realm_id=$1 AND subject_type='user' AND subject_id=$2 AND state='active'),
							(SELECT count(*) FROM refresh_families f JOIN authorization_grants g ON g.id=f.grant_id WHERE g.realm_id=$1 AND g.subject_id=$2 AND f.state='active'),
							(SELECT count(*) FROM token_revocations WHERE realm_id=$1 AND reference_type='user' AND reference_id=$2)`,
							h.Realm.ID, f.Users["bob"]).Scan(&liveSessions, &liveGrants, &liveFamilies, &userRevocations); err != nil {
							t.Fatal(err)
						}
						if liveSessions != 0 || liveGrants != 0 || liveFamilies != 0 || userRevocations != (round+1)*16 {
							t.Fatalf("round %d node %d: live sessions/grants/families %d/%d/%d, account revocations %d", round, i, liveSessions, liveGrants, liveFamilies, userRevocations)
						}
					}
				}
				t.Logf("round %d: 16 revocation receipts, at most one successor per family, all 32 post-commit requests refuse affected authority", round+1)
			}
		})
	}
}
