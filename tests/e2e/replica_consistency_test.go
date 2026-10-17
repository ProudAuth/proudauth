package e2e

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/platform/secret"
	"github.com/proudauth/proudauth/internal/realm"
)

// replicaStressFixture uses three in-process HTTP servers, each with its own
// runtime, database pool, transaction semaphore, keyring and signing-key cache.
// They share only the database, equivalent root-key material, immutable test
// configuration and a deterministic clock. This is consistency evidence, not
// a multi-machine capacity or process/network-failure measurement.
func replicaStressFixture(t *testing.T, mutate ...func(*realm.Policy)) (*Fixture, []*Harness) {
	t.Helper()
	return replicaStressFixtureWithOptions(t, nil, mutate...)
}

func replicaStressFixtureWithOptions(t *testing.T, opts []Option, mutate ...func(*realm.Policy)) (*Fixture, []*Harness) {
	t.Helper()
	return replicaStressFixtureWithRoot(t, secret.Random(32), opts, mutate...)
}

func replicaStressFixtureWithRoot(t *testing.T, root []byte, opts []Option, mutate ...func(*realm.Policy)) (*Fixture, []*Harness) {
	t.Helper()
	keyring := func() *keys.Keyring {
		t.Helper()
		k, err := keys.New(map[uint32][]byte{1: append([]byte(nil), root...)}, 1)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	f := fixtureOn(t, newHarnessWithKeyring(t, keyring(), opts...), mutate...)
	nodes := []*Harness{f.H}
	for range 2 {
		nodes = append(nodes, startNode(t, f.H, keyring(), nil))
	}
	for i, n := range nodes {
		for _, other := range nodes[:i] {
			if n.App == other.App || n.App.D.DB == other.App.D.DB || n.App.D.DB.Pool == other.App.D.DB.Pool || n.App.D.Keys == other.App.D.Keys {
				t.Fatal("stress replicas must have independent runtimes, pools and keyrings")
			}
		}
	}
	return f, nodes
}

// replicaBurst releases every request from one barrier. Results stay indexed
// by request, so a failed goroutine cannot disappear from the observations.
func replicaBurst(t *testing.T, nodes []*Harness, count int, call func(int, *Harness) *Resp) []*Resp {
	t.Helper()
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(count)
	done.Add(count)
	out := make([]*Resp, count)
	for i := range out {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			out[i] = call(i, nodes[i%len(nodes)])
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()
	for i, r := range out {
		if r == nil {
			t.Fatalf("replica request %d returned no observation", i)
		}
	}
	return out
}

// TestReplicaRecoveryConsumptionStress covers MFA-004, DB-005, TEST-023 and
// NFR-007: independent transactions submit one recovery code across three
// replicas at concurrency 32 on eight transactions. Exactly one succeeds,
// the other three uses of its closed transaction fail, the unchanged account
// budget permits only ten evaluations, and each replica sees one consumed
// verifier, one completed transaction and one success audit per round.
func TestReplicaRecoveryConsumptionStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	f.EnrollTOTP("carol")
	token := f.AccountToken("carol").Tokens.Str("access_token")
	r := f.must(h.API("POST", "/me/recovery-codes/regenerate", token, nil), 200, "fresh recovery batch")
	codes, ok := r.Get("recovery_codes").([]any)
	const rounds, concurrency, transactions = 6, 32, 8
	if !ok || len(codes) != h.Cfg.Security.RecoveryCodeCount || len(codes) < rounds {
		t.Fatal("missing full recovery-code batch")
	}
	if h.Cfg.Security.RateLimits.OTPVerifyPerAccount != 10 {
		t.Fatal("the stress profile requires the unchanged ten-proof account budget")
	}
	type pendingRecovery struct{ id, continuation string }
	for round := range rounds {
		// Advance the deterministic clock to the next policy window;
		// never reset a counter or raise a budget.
		h.Clock.Advance(h.Cfg.Security.RateLimits.OTPVerifyWindow + time.Minute)
		pending := make([]pendingRecovery, transactions)
		ids := make([]string, transactions)
		for i := range pending {
			n := nodes[i%len(nodes)]
			id, cont, state := afterPassword(n, "carol@example.test")
			if state.Status != 200 || !hasAction(state, "recovery_code") {
				t.Fatalf("round %d request %d did not reach the recovery step", round, i)
			}
			pending[i] = pendingRecovery{id, cont}
			ids[i] = id
		}
		code := codes[round].(string)
		results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
			p := pending[i%transactions]
			return n.Step(p.id, p.continuation, "recovery-code", map[string]any{"code": code})
		})
		accepted, invalid, limited, closed := 0, 0, 0, 0
		winner := ""
		var closedIDs []string
		for i, result := range results {
			switch {
			case result.Status == 200 && result.Str("redirect_to") != "":
				accepted++
				winner = pending[i%transactions].id
			case result.Status == 400 && result.Str("code") == "invalid_proof":
				invalid++
			case result.Status == 400 && result.Str("code") == "transaction_invalid":
				closed++
				closedIDs = append(closedIDs, pending[i%transactions].id)
			case result.Status == 429 && result.Str("code") == "rate_limited":
				seconds, err := strconv.Atoi(result.Header.Get("Retry-After"))
				if err != nil || seconds <= 0 {
					t.Fatal("shared proof-budget refusal lacks positive Retry-After")
				}
				limited++
			default:
				t.Fatalf("round %d: unexpected recovery outcome %d/%s", round, result.Status, result.Str("code"))
			}
		}
		if accepted != 1 || invalid != 9 || closed != 3 || limited != concurrency-13 {
			t.Fatalf("round %d: %d accepted, %d invalid, %d closed, %d limited", round, accepted, invalid, closed, limited)
		}
		for _, id := range closedIDs {
			if id != winner {
				t.Fatal("a non-winning transaction closed before its four-request burst completed")
			}
		}
		for i, node := range nodes {
			var active, consumed, complete, used, failed, transactionFailures, maxFailures int
			q := node.App.D.DB.Pool
			if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state='active'), count(*) FILTER (WHERE state='consumed')
				FROM recovery_codes WHERE realm_id=$1 AND user_id=$2`, h.Realm.ID, f.Users["carol"]).Scan(&active, &consumed); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FROM auth_transactions WHERE realm_id=$1 AND id=ANY($2) AND status='completed'`, h.Realm.ID, ids).Scan(&complete); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT coalesce(sum(failure_count),0), coalesce(max(failure_count),0) FROM auth_transactions WHERE realm_id=$1 AND id=ANY($2)`, h.Realm.ID, ids).Scan(&transactionFailures, &maxFailures); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE type='mfa.recovery_code.used'), count(*) FILTER (WHERE type='mfa.recovery_code.failed')
				FROM audit_events WHERE realm_id=$1 AND subject_id=$2`, h.Realm.ID, f.Users["carol"]).Scan(&used, &failed); err != nil {
				t.Fatal(err)
			}
			if active != len(codes)-round-1 || consumed != round+1 || complete != 1 || used != round+1 || failed != (round+1)*9 || transactionFailures != 9 || maxFailures > 4 {
				t.Fatalf("round %d node %d: active %d consumed %d complete %d used %d failed %d", round, i, active, consumed, complete, used, failed)
			}
		}
		t.Logf("round %d across three independent pools: one use, nine invalid proofs, three closed-transaction refusals, 19 budget refusals", round+1)
	}
}

// TestReplicaInvitationAcceptanceStress covers INV-004, DB-004, DB-005,
// TEST-016 and NFR-007: eight invitations each receive 32 simultaneous
// authenticated accepts across three replicas. Require exact response
// classes, one membership, exactly the invited role, one use, and one
// acceptance audit/outbox event visible from every independent pool.
func TestReplicaInvitationAcceptanceStress(t *testing.T) {
	f, nodes := replicaStressFixture(t)
	h := f.H
	ctx := context.Background()
	// Granting roles by invitation needs an MFA session (TestOrgAuthorityGrantsNeedMFA).
	f.EnrollTOTP("alice")
	alice := f.AccountToken("alice").Tokens.Str("access_token")
	const rounds, concurrency = 8, 32
	for round := range rounds {
		name := fmt.Sprintf("replica-invite-%d", round)
		userID := f.CreateUser(name)
		inv := f.must(h.API("POST", "/organizations/"+f.Acme+"/invitations", alice, map[string]any{"email": name + "@example.test", "role_ids": []string{f.Roles["orders-viewer"]}}), 201, "invitation")
		secret := invitationFromMail(h.Mail(name+"@example.test", "invitation"))
		if secret == "" {
			t.Fatal("invitation fixture was not delivered")
		}
		account := f.AccountToken(name).Tokens.Str("access_token")
		results := replicaBurst(t, nodes, concurrency, func(_ int, n *Harness) *Resp {
			return n.API("POST", "/invitations/accept", account, map[string]any{"invitation": secret})
		})
		accepted, refused := 0, 0
		var membership string
		for _, result := range results {
			switch {
			case result.Status == 200 && result.Str("membership_id") != "":
				accepted++
				membership = result.Str("membership_id")
			case result.Status == 400 && result.Str("code") == "invitation_invalid":
				refused++
			default:
				t.Fatalf("round %d: unexpected invitation outcome %d/%s", round, result.Status, result.Str("code"))
			}
		}
		if accepted != 1 || refused != concurrency-1 {
			t.Fatalf("round %d: %d accepted, %d refused", round, accepted, refused)
		}
		for i, node := range nodes {
			q := node.App.D.DB.Pool
			var members, uses, audits, events int
			var roleIDs []string
			var state, acceptor, storedMembership string
			if err := q.QueryRow(ctx, `SELECT count(*) FROM memberships WHERE realm_id=$1 AND organization_id=$2 AND user_id=$3`, h.Realm.ID, f.Acme, userID).Scan(&members); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT coalesce(array_agg(role_id ORDER BY role_id), '{}') FROM role_assignments WHERE realm_id=$1 AND membership_id=$2`, h.Realm.ID, membership).Scan(&roleIDs); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT state, use_count, accepted_by_user_id, membership_id FROM invitations WHERE realm_id=$1 AND id=$2`, h.Realm.ID, inv.Str("invitation.id")).Scan(&state, &uses, &acceptor, &storedMembership); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND type='invitation.accepted' AND target_id=$2`, h.Realm.ID, inv.Str("invitation.id")).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if err := q.QueryRow(ctx, `SELECT count(*) FROM outbox_events WHERE realm_id=$1 AND event_type='organization.membership.added' AND aggregate_id=$2`, h.Realm.ID, membership).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if members != 1 || uses != 1 || audits != 1 || events != 1 || state != "accepted" || acceptor != userID || storedMembership != membership || len(roleIDs) != 1 || roleIDs[0] != f.Roles["orders-viewer"] {
				t.Fatalf("round %d node %d: members %d uses %d audits %d events %d state %s roles %v", round, i, members, uses, audits, events, state, roleIDs)
			}
		}
		t.Logf("round %d across three independent pools: one membership, role, acceptance audit and outbox event", round+1)
	}
}
