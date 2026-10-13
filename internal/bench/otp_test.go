package bench

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBenchTOTPExcludesValidGuesses(t *testing.T) {
	key := []byte("12345678901234567890")
	// Published RFC 4226 vectors independently check dynamic truncation;
	// the benchmark does not call the server's factor verifier.
	for step, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := benchTOTP(key, int64(step)); got != want {
			t.Fatalf("counter %d: %s, want %s", step, got, want)
		}
	}
	for _, step := range []int64{0, 5, 56789012} {
		for offset := int64(-5); offset <= 5; offset++ {
			if step+offset < 0 {
				continue
			}
			start, _ := strconv.Atoi(benchTOTP(key, step+offset))
			for _, candidate := range []int{start, 999999} {
				got := wrongBenchTOTP(key, time.Unix(step*30+29, 0), candidate)
				if n, err := strconv.Atoi(got); err != nil || len(got) != 6 || n < 0 || n > 999999 {
					t.Fatalf("malformed guess %q", got)
				}
				for d := int64(-5); d <= 5; d++ {
					if step+d >= 0 && got == benchTOTP(key, step+d) {
						t.Fatalf("guess matches valid step %d", step+d)
					}
				}
			}
		}
	}
}

// NFR-006, NFR-008: a successful guess, an unproven closed transaction or
// missing retry guidance cannot masquerade as budget enforcement. Results
// expose counts only; factor and transaction authority are cleared at close.
func TestBenchOTPGuessesProveDenialAndKeepAuthorityPrivate(t *testing.T) {
	for _, tc := range []struct {
		name, code, retry, state, stateError, want string
		status                                     int
	}{
		{name: "evaluated wrong proof", status: 400, code: "invalid_proof", want: "invalid_proof"},
		{name: "subject budget", status: 429, code: "rate_limited", retry: "900", want: "rate_limited"},
		{name: "no retry", status: 429, code: "rate_limited", want: "invariant_missing_retry_guidance"},
		{name: "invalid retry", status: 429, code: "rate_limited", retry: "-1", want: "invariant_missing_retry_guidance"},
		{name: "accepted guess", status: 200, want: "invariant_wrong_otp_accepted"},
		{name: "unexpected failure", status: 500, want: "http_500"},
		{name: "transaction budget", status: 400, code: "transaction_invalid", state: "failed", stateError: "too_many_failures", want: "transaction_limit"},
		{name: "still pending", status: 400, code: "transaction_invalid", state: "pending", want: "invariant_unproven_transaction_limit"},
		{name: "other failure", status: 400, code: "transaction_invalid", state: "failed", stateError: "cancelled", want: "invariant_unproven_transaction_limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := []byte("12345678901234567890")
			now := time.Unix(1700000000, 0)
			gets := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Transaction-Token") != "private-continuation" {
					t.Error("transaction authority missing")
				}
				if r.Method == "GET" {
					gets++
					_ = json.NewEncoder(w).Encode(map[string]string{"status": tc.state, "error": tc.stateError})
					return
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				for d := int64(-5); d <= 5; d++ {
					if body["code"] == benchTOTP(key, now.Unix()/30+d) {
						t.Error("submitted a legitimate TOTP")
					}
				}
				w.Header().Set("Retry-After", tc.retry)
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]string{"code": tc.code})
			}))
			defer srv.Close()
			tx := &otpTransaction{id: "private-transaction", continuation: "private-continuation"}
			s := &otpGuess{key: key, transactions: []*otpTransaction{tx}}
			e := &Env{Client: NewClient(srv.URL, "bench", 1), Now: func() time.Time { return now }}
			if got := s.Op(context.Background(), e, 0, rand.New(rand.NewPCG(1, 2))); got != tc.want {
				t.Fatalf("outcome %s, want %s", got, tc.want)
			}
			if tx.closed.Load() != (tc.want == "transaction_limit") || gets != boolInt(tc.code == "transaction_invalid") {
				t.Fatalf("retired %v after %d state reads", tx.closed.Load(), gets)
			}
			published, err := json.Marshal(map[string]any{"notes": s.Notes(), "observations": s.Observations()})
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{string(key), base32.StdEncoding.EncodeToString(key), tx.id, tx.continuation} {
				if strings.Contains(string(published), secret) {
					t.Fatal("published private authority")
				}
			}
			_ = s.Close(context.Background(), e)
			for _, b := range key {
				if b != 0 {
					t.Fatal("factor key not cleared")
				}
			}
			if tx.id != "" || tx.continuation != "" || s.key != nil || s.transactions != nil {
				t.Fatal("authority retained after close")
			}
		})
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestBenchOTPPreparationRedactsUnexpectedEnrollment(t *testing.T) {
	const secret = "private-enrollment-secret"
	enrolled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/user-imports"):
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"job_id":"import"}`))
		case strings.HasSuffix(r.URL.Path, "/jobs/import"):
			_, _ = w.Write([]byte(`{"state":"succeeded"}`))
		case strings.HasSuffix(r.URL.Path, "/auth/transactions"):
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"transaction_id":"signin","continuation_token":"continuation"}`))
		case strings.HasSuffix(r.URL.Path, "/identify"):
			_, _ = w.Write([]byte(`{}`))
		case strings.HasSuffix(r.URL.Path, "/password"):
			_, _ = w.Write([]byte(`{"redirect_to":"https://app.bench.test/callback?code=code"}`))
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			_, _ = w.Write([]byte(`{"access_token":"enrollment-access"}`))
		case strings.HasSuffix(r.URL.Path, "/me/totp/enroll"):
			// Unexpected success status on a secret-bearing response must
			// fail setup without echoing its body.
			enrolled = true
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"secret":%q,"recovery_codes":[%q]}`, secret, secret)
		default:
			t.Errorf("unexpected setup request %s", r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	s := &otpGuess{}
	e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("admin"), Concurrency: 1, Seed: &SeedData{AccountAudience: "account"}}
	err := s.Prepare(context.Background(), e)
	if !enrolled || err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "OTP enrollment:") {
		t.Fatalf("setup error %v, reached enrollment %v", err, enrolled)
	}
}
