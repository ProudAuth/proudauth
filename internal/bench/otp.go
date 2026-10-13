package bench

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// otpGuess attacks only its own new account's TOTP factor (NFR-006). Its
// eight prepared transactions share the account budget without altering it.
type otpGuess struct {
	key          []byte
	transactions []*otpTransaction
}
type otpTransaction struct {
	id, continuation string
	closed           atomic.Bool
}

func (*otpGuess) Name() string      { return "otp-guess" }
func (*otpGuess) Adversarial() bool { return true }
func (s *otpGuess) Notes() []string {
	return []string{fmt.Sprintf("one additional isolated account with a self-enrolled SHA1/6-digit/30s TOTP factor; %d prepared MFA transactions share its unchanged proof budget; setup is unmeasured", len(s.transactions)),
		"each operation submits a well-formed wrong TOTP; codes accepted in the five neighboring steps on each side of the load host's clock are excluded (server clock within 60s, request deadline 30s, supported skew <=2 steps)",
		"failed transactions are retired only after their authenticated state proves too_many_failures; no new password sign-in is performed while measuring; run before the prepared transactions' expiry",
		"warm-up uses benign discovery only; secret and continuation authority stay in memory and are cleared at close; covers TOTP guessing, not email/SMS challenge codes or HOTP"}
}

func (s *otpGuess) Prepare(ctx context.Context, e *Env) error {
	if e.Client == nil || e.Concurrency < 1 || e.Admin == nil || e.Seed == nil || e.Seed.AccountAudience == "" {
		return fmt.Errorf("otp-guess requires an MFA admin token and a fresh seed with account access")
	}
	prefix, err := runPrefix(e.Seed, "otp-guess")
	if err != nil {
		return err
	}
	email, password := prefix+"@bench.test", e.Seed.UserPassword(0)
	job, err := e.Client.API(ctx, "POST", "/user-imports", e.adminToken(ctx), map[string]any{"source_system": prefix, "users": []any{map[string]any{"source_id": "otp", "email": email, "email_verified": true, "password_hash": legacyHash(password, 0)}}, "trust_email_verification": true, "verification_reason": "synthetic OTP benchmark account"})
	if out := expectedOutcome(job, err, 202); out != "ok" {
		return fmt.Errorf("OTP account import: %s", out)
	}
	if err := waitJob(ctx, e.Client, e.Admin, job.Str("job_id")); err != nil {
		return err
	}
	token, out := e.loginPassword(ctx, email, password, e.Seed.AccountAudience, "proudauth:account")
	if out != "ok" {
		return fmt.Errorf("OTP enrollment sign-in: %s", out)
	}
	access := token.Str("access_token")
	en, err := e.Client.API(ctx, "POST", "/me/totp/enroll", access, nil)
	if out := expectedOutcome(en, err, 201); out != "ok" {
		return fmt.Errorf("OTP enrollment: %s", out)
	}
	// Enrollment and activation return secrets once. Never use raw response
	// bodies in setup errors, result notes or observations.
	secret := en.Str("secret")
	u, err := url.Parse(en.Str("otpauth_uri"))
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("algorithm") != "SHA1" || u.Query().Get("digits") != "6" || u.Query().Get("period") != "30" || u.Query().Get("secret") != secret {
		return fmt.Errorf("OTP enrollment did not provide the supported TOTP profile")
	}
	s.key, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil || len(s.key) != 20 {
		return fmt.Errorf("OTP enrollment lacks a 160-bit base32 seed")
	}
	activated, err := e.Client.API(ctx, "POST", "/me/totp/activate", access, map[string]any{"code": benchTOTP(s.key, benchNow(e).Unix()/30)})
	if out := expectedOutcome(activated, err, 200); out != "ok" {
		return fmt.Errorf("OTP activation: %s", out)
	}
	if activated.Str("status") != "totp_enrolled" {
		return fmt.Errorf("OTP activation did not confirm enrollment")
	}
	s.transactions = nil
	// One enrollment sign-in plus eight MFA sign-ins stay under the unchanged
	// ten-password-attempt identifier budget. This also leaves live transactions
	// when one reaches its five-failure limit before the account budget does.
	for i := 0; i < 8; i++ {
		_, challenge := PKCE()
		start, err := e.Client.API(ctx, "POST", "/auth/transactions", "", map[string]any{"client_id": e.Seed.Web.ClientID, "redirect_uri": e.Seed.RedirectURI, "scope": "bench:read", "resource": []string{e.Seed.Audience}, "code_challenge": challenge, "code_challenge_method": "S256"})
		if out := expectedOutcome(start, err, 201); out != "ok" {
			return fmt.Errorf("OTP transaction start: %s", out)
		}
		tx := &otpTransaction{id: start.Str("transaction_id"), continuation: start.Str("continuation_token")}
		if tx.id == "" || tx.continuation == "" {
			return fmt.Errorf("OTP transaction lacks continuation authority")
		}
		s.transactions = append(s.transactions, tx)
		identified, err := s.step(ctx, e, tx, "identify", map[string]any{"identifier": email})
		if out := expectedOutcome(identified, err, 200); out != "ok" {
			return fmt.Errorf("OTP transaction identify: %s", out)
		}
		state, err := s.step(ctx, e, tx, "password", map[string]any{"password": password})
		if out := expectedOutcome(state, err, 200); out != "ok" {
			return fmt.Errorf("OTP transaction password: %s", out)
		}
		if state.Str("status") != "pending" || state.Str("redirect_to") != "" || !otpAction(state, "totp") {
			return fmt.Errorf("OTP transaction is not awaiting its enrolled TOTP factor")
		}
	}
	return nil
}

func otpAction(r *Response, want string) bool {
	actions, _ := r.Body["next_actions"].([]any)
	for _, a := range actions {
		if stringValue(object(a), "type") == want {
			return true
		}
	}
	return false
}
func (s *otpGuess) step(ctx context.Context, e *Env, tx *otpTransaction, action string, body any) (*Response, error) {
	return e.Client.Do(ctx, Request{Method: "POST", Path: "/api/v1/realms/" + e.Client.Realm + "/auth/transactions/" + tx.id + "/" + action, Headers: map[string]string{"X-Transaction-Token": tx.continuation}, JSON: body})
}

func (s *otpGuess) Op(ctx context.Context, e *Env, worker int, rnd *mrand.Rand) string {
	if len(s.key) != 20 || len(s.transactions) == 0 {
		return "setup_missing_otp_factor"
	}
	var tx *otpTransaction
	for i := 0; i < len(s.transactions); i++ {
		candidate := s.transactions[(worker+i)%len(s.transactions)]
		if !candidate.closed.Load() {
			tx = candidate
			break
		}
	}
	if tx == nil {
		return "invariant_no_live_transaction_for_account_budget"
	}
	code := wrongBenchTOTP(s.key, benchNow(e), rnd.IntN(1000000))
	r, err := s.step(ctx, e, tx, "totp", map[string]any{"code": code})
	if err != nil || r == nil {
		return "transport_error"
	}
	if r.Status < 400 {
		return "invariant_wrong_otp_accepted"
	}
	if r.Status == 400 && r.Str("code") == "invalid_proof" {
		return "invalid_proof"
	}
	if r.Status == 429 && r.Str("code") == "rate_limited" {
		retry, err := strconv.ParseInt(r.Header.Get("Retry-After"), 10, 64)
		if err != nil || retry <= 0 {
			return "invariant_missing_retry_guidance"
		}
		return "rate_limited"
	}
	if r.Status == 400 && r.Str("code") == "transaction_invalid" {
		state, err := e.Client.Do(ctx, Request{Method: "GET", Path: "/api/v1/realms/" + e.Client.Realm + "/auth/transactions/" + tx.id, Headers: map[string]string{"X-Transaction-Token": tx.continuation}})
		if expectedOutcome(state, err, 200) != "ok" || state.Str("status") != "failed" || state.Str("error") != "too_many_failures" {
			return "invariant_unproven_transaction_limit"
		}
		tx.closed.Store(true)
		return "transaction_limit"
	}
	return r.Outcome()
}

func (s *otpGuess) Observations() map[string]any {
	retired := 0
	for _, tx := range s.transactions {
		if tx.closed.Load() {
			retired++
		}
	}
	return map[string]any{"subject_accounts": 1, "prepared_transactions": len(s.transactions), "retired_transactions": retired, "excluded_steps_each_side": 5, "scope": "TOTP SHA1/6 digits/30 seconds; subject and transaction budgets unchanged; no secrets or guesses retained"}
}
func (s *otpGuess) Close(context.Context, *Env) error {
	clear(s.key)
	s.key = nil
	for _, tx := range s.transactions {
		tx.id = ""
		tx.continuation = ""
	}
	s.transactions = nil
	return nil
}
func benchNow(e *Env) time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// RFC 4226 dynamic truncation, using standard HMAC rather than ProudAuth's
// verifier. The receiver's owned seed lets guesses exclude legitimate codes.
func benchTOTP(key []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	o := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
func wrongBenchTOTP(key []byte, now time.Time, start int) string {
	valid := map[string]bool{}
	step := now.Unix() / 30
	for d := int64(-5); d <= 5; d++ {
		if step+d >= 0 {
			valid[benchTOTP(key, step+d)] = true
		}
	}
	for n := start; ; n = (n + 1) % 1000000 {
		code := fmt.Sprintf("%06d", n)
		if !valid[code] {
			return code
		}
	}
}
