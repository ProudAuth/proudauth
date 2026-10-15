package e2e

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/credential"
	"github.com/proudauth/proudauth/internal/keys"
	"github.com/proudauth/proudauth/internal/realm"
)

// TestReplicaOTPGuessBudgets covers TEST-021, NFR-006, NFR-007 and MFA-013:
// email, SMS and HOTP guesses across independent transactions, source networks
// and three pools must share the unchanged account budget, including mixed
// methods. Phantom accounts retain a bounded identifier budget without gaining
// authority. Stored failures/audits agree; new windows permit real proofs.
func TestReplicaOTPGuessBudgets(t *testing.T) {
	for _, profile := range []string{"email", "sms", "hotp", "mixed", "unknown"} {
		t.Run(profile, func(t *testing.T) {
			f, nodes := replicaStressFixtureWithOptions(t, []Option{func(c *configuration.Config) {
				c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
				c.Delivery.SMS.Adapter = "dev_sink"
				c.Delivery.SMS.AllowedCountries = []string{"+1"}
			}}, func(p *realm.Policy) {
				p.Login.SMSOTP, p.Login.SMSRiskAccepted = true, true
				p.Login.Identifiers = append(p.Login.Identifiers, "phone")
				p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, "hotp")
			})
			h, ctx := f.H, context.Background()
			if h.Cfg.Security.RateLimits.OTPVerifyPerAccount != 10 || h.Cfg.Security.RateLimits.OTPVerifyWindow != 15*time.Minute || h.Cfg.Security.OTPMaxAttempts != 5 {
				t.Fatal("profile must preserve default account and challenge budgets")
			}
			const phone = "+15550100002"
			account := f.AccountToken("bob").Tokens.Str("access_token")
			if profile == "sms" || profile == "mixed" {
				id := f.must(h.API("POST", "/me/identifiers", account, map[string]any{"type": "phone", "value": phone}), 201, "add phone").Str("id")
				ch := f.must(h.API("POST", "/verification-challenges", account, map[string]any{"identifier_id": id}), 201, "prove phone").Str("challenge_id")
				code := CodeFrom(h.Mail(phone, "email_verification"))
				if code == "" {
					t.Fatal("phone proof not delivered")
				}
				mustStatus(t, h.API("POST", "/verification-challenges/"+ch+"/consume", account, map[string]any{"code": code}), 200, "verify phone")
			}
			seed, hotpCode, wrongHOTP := "", "", ""
			if profile == "hotp" || profile == "mixed" {
				seed = f.must(h.API("POST", "/me/hotp/enroll", account, nil), 201, "enroll HOTP").Str("secret")
				activation, err := credential.HOTPCode(seed, 0)
				if err != nil {
					t.Fatal(err)
				}
				mustStatus(t, h.API("POST", "/me/hotp/activate", account, map[string]any{"code": activation}), 200, "activate HOTP")
				hotpCode, err = credential.HOTPCode(seed, 1)
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; ; i++ {
					wrongHOTP = fmt.Sprintf("%06d", i)
					if _, ok := credential.MatchHOTP(seed, wrongHOTP, 1, h.Realm.Policy.MFA.HOTPLookAhead()); !ok {
						break
					}
				}
			}
			// Start well inside the next fixed window. Send cooldown advances are
			// setup only; no rate counter is reset and no proof limit is raised.
			window := h.Cfg.Security.RateLimits.OTPVerifyWindow
			h.Clock.Set(h.Clock.Now().Truncate(window).Add(window + time.Minute))
			type pendingProof struct{ id, continuation, kind, right, wrong, ip string }
			prepare := func(i int, kind string) pendingProof {
				t.Helper()
				n := nodes[i%len(nodes)]
				ip := fmt.Sprintf("203.0.113.%d", i+1)
				_, challenge := PKCE()
				start := n.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions", Headers: map[string]string{"X-Forwarded-For": ip},
					JSON: map[string]any{"client_id": "proudauth-cli", "redirect_uri": "http://127.0.0.1/callback", "scope": "proudauth:account",
						"resource": []string{h.Realm.Issuer + "/account"}, "code_challenge": challenge, "code_challenge_method": "S256"}})
				p := pendingProof{id: start.Str("transaction_id"), continuation: start.Str("continuation_token"), kind: kind, ip: ip}
				if p.id == "" || p.continuation == "" {
					t.Fatalf("transaction start: %d/%s", start.Status, start.Str("code"))
				}
				identifier := "bob@example.test"
				if kind == "sms" {
					identifier = phone
				}
				if profile == "unknown" {
					identifier = "no-account@example.test"
				}
				mustStatus(t, n.Step(p.id, p.continuation, "identify", map[string]any{"identifier": identifier}), 200, "identify proof owner")
				if kind == "hotp" {
					st := n.Step(p.id, p.continuation, "password", map[string]any{"password": h.passwords[identifier]})
					if st.Status != 200 || !hasAction(st, "hotp") {
						t.Fatal("password did not reach HOTP")
					}
					p.right, p.wrong = hotpCode, wrongHOTP
				} else {
					h.Clock.Advance(2 * time.Second)
					mustStatus(t, n.Step(p.id, p.continuation, "otp/send", map[string]any{"purpose": "login"}), 200, "send login code")
					p.right = CodeFrom(h.Mail(identifier, "login_code"))
					if profile == "unknown" {
						if p.right != "" {
							t.Fatal("phantom account received a message")
						}
						// Exclude an accidental correct phantom code without
						// recovering its secret or sending a notification.
						var challengeID, verifier string
						var version int
						if err := h.App.D.DB.Pool.QueryRow(ctx, `SELECT id, verifier, key_version FROM challenges
							WHERE transaction_id=$1 AND purpose='login_otp'`, p.id).Scan(&challengeID, &verifier, &version); err != nil {
							t.Fatal(err)
						}
						for guess := 0; ; guess++ {
							p.right = fmt.Sprintf("%06d", guess)
							if !h.App.D.Keys.VerifyMAC(keys.PurposeOTP, version, verifier, "challenge", challengeID, "login_otp", p.right) {
								break
							}
						}
					}
					if len(p.right) != 6 {
						t.Fatal("login code not delivered")
					}
					p.wrong = fmt.Sprintf("%d%s", (p.right[0]-'0'+1)%10, p.right[1:])
					if profile == "unknown" {
						p.wrong = p.right
					}
				}
				return p
			}
			step := func(n *Harness, p pendingProof, code string) *Resp {
				path := "otp/verify"
				if p.kind == "hotp" {
					path = "hotp"
				}
				return n.Do(Req{Method: "POST", Path: "/api/v1/realms/main/auth/transactions/" + p.id + "/" + path,
					Headers: map[string]string{"X-Transaction-Token": p.continuation, "X-Forwarded-For": p.ip}, JSON: map[string]any{"code": code}})
			}
			const transactions, concurrency = 8, 32
			pending, txIDs := make([]pendingProof, transactions), make([]string, transactions)
			for i := range pending {
				kind := profile
				if kind == "unknown" {
					kind = "email"
				}
				if kind == "mixed" {
					kind = []string{"email", "sms", "hotp"}[i%3]
				}
				pending[i] = prepare(i, kind)
				txIDs[i] = pending[i].id
			}
			results := replicaBurst(t, nodes, concurrency, func(i int, n *Harness) *Resp {
				p := pending[i%transactions]
				return step(n, p, p.wrong)
			})
			invalid, limited, invalidHOTP := 0, 0, 0
			for i, r := range results {
				switch {
				case r.Status == 400 && r.Str("code") == "invalid_proof":
					invalid++
					if pending[i%transactions].kind == "hotp" {
						invalidHOTP++
					}
				case r.Status == 429 && r.Str("code") == "rate_limited":
					seconds, err := strconv.Atoi(r.Header.Get("Retry-After"))
					if err != nil || seconds <= 0 {
						t.Fatal("budget refusal lacks retry guidance")
					}
					limited++
				default:
					t.Fatalf("unexpected guess result %d/%s", r.Status, r.Str("code"))
				}
			}
			if invalid != 10 || limited != 22 {
				t.Fatalf("shared account budget: %d evaluated, %d limited; want 10/22", invalid, limited)
			}
			for i, n := range nodes {
				var failures, maxFailures, done, networks, challengeAttempts, auditedOTP, auditedHOTP int
				q := n.App.D.DB.Pool
				if err := q.QueryRow(ctx, `SELECT sum(failure_count), max(failure_count), count(*) FILTER (WHERE status<>'pending'), count(DISTINCT client_ip)
					FROM auth_transactions WHERE id=ANY($1)`, txIDs).Scan(&failures, &maxFailures, &done, &networks); err != nil {
					t.Fatal(err)
				}
				if err := q.QueryRow(ctx, `SELECT coalesce(sum(attempts),0) FROM challenges WHERE transaction_id=ANY($1) AND purpose='login_otp'`, txIDs).Scan(&challengeAttempts); err != nil {
					t.Fatal(err)
				}
				// Passwordless transactions have no authenticated actor yet.
				if err := q.QueryRow(ctx, `SELECT count(*) FILTER (WHERE type='authentication.otp.failed'), count(*) FILTER (WHERE type='mfa.hotp.failed')
					FROM audit_events WHERE realm_id=$1`, h.Realm.ID).Scan(&auditedOTP, &auditedHOTP); err != nil {
					t.Fatal(err)
				}
				if failures != 10 || maxFailures > 4 || done != 0 || networks != 8 || auditedOTP != 10-invalidHOTP || auditedHOTP != invalidHOTP || challengeAttempts != 10-invalidHOTP {
					t.Fatalf("pool %d: failures=%d max=%d done=%d networks=%d challenge attempts=%d OTP/HOTP audits=%d/%d", i, failures, maxFailures, done, networks, challengeAttempts, auditedOTP, auditedHOTP)
				}
				if seed != "" {
					var counter int
					if err := q.QueryRow(ctx, `SELECT counter FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active'`, f.Users["bob"]).Scan(&counter); err != nil || counter != 1 {
						t.Fatalf("guess changed HOTP counter: %d, %v", counter, err)
					}
				}
			}
			// A known valid code is also refused while the budget is exhausted.
			mustStatus(t, step(nodes[2], pending[0], pending[0].right), 429, "valid proof respects exhausted budget")
			h.Clock.Set(h.Clock.Now().Truncate(window).Add(window + time.Minute))
			kind := profile
			if kind == "mixed" {
				kind = "hotp"
			}
			if kind == "unknown" {
				kind = "email"
			}
			fresh := prepare(8, kind)
			r := step(nodes[1], fresh, fresh.right)
			if profile == "unknown" {
				if r.Status != 400 || r.Str("code") != "invalid_proof" || r.Str("redirect_to") != "" {
					t.Fatal("phantom proof gained authority after rollover")
				}
			} else if r.Status != 200 || r.Str("redirect_to") == "" {
				t.Fatalf("new-window correct proof cannot complete: %d/%s", r.Status, r.Str("code"))
			}
			for i, n := range nodes {
				var user, status string
				var failures int
				q := n.App.D.DB.Pool
				if err := q.QueryRow(ctx, `SELECT coalesce(user_id,''), status, failure_count FROM auth_transactions WHERE id=$1`, fresh.id).Scan(&user, &status, &failures); err != nil {
					t.Fatal(err)
				}
				if profile == "unknown" {
					if user != "" || status != "pending" || failures != 1 {
						t.Fatalf("pool %d: phantom transaction acquired authority", i)
					}
				} else if user != f.Users["bob"] || status != "completed" || failures != 0 {
					t.Fatalf("pool %d: real proof failed to restore access", i)
				}
				if kind == "hotp" {
					var counter, used int
					if err := q.QueryRow(ctx, `SELECT counter FROM credentials WHERE user_id=$1 AND type='hotp' AND state='active'`, f.Users["bob"]).Scan(&counter); err != nil {
						t.Fatal(err)
					}
					if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE realm_id=$1 AND subject_id=$2 AND type='mfa.hotp.used'`, h.Realm.ID, f.Users["bob"]).Scan(&used); err != nil {
						t.Fatal(err)
					}
					if counter != 2 || used != 1 {
						t.Fatal("real HOTP proof did not advance the counter once")
					}
				} else if profile != "unknown" {
					var attempts, consumed int
					if err := q.QueryRow(ctx, `SELECT attempts, CASE WHEN consumed_at IS NOT NULL THEN 1 ELSE 0 END
						FROM challenges WHERE transaction_id=$1 AND purpose='login_otp'`, fresh.id).Scan(&attempts, &consumed); err != nil {
						t.Fatal(err)
					}
					if attempts != 1 || consumed != 1 {
						t.Fatal("real channel proof did not consume its challenge once")
					}
				}
			}
			t.Log("32 guesses: 10 invalid proofs, 22 budget refusals; eight source IPs, three independent pools; exhausted-budget refusal and next-window authority checked")
		})
	}
}
