package e2e

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/testutil"
)

// TestTimeAndUnicodeInvariants covers NFR-010: lifetimes are computed in
// absolute time, independent of the host's zone and its daylight-saving
// changes, and identifiers compare by canonical form, never by locale.
func TestTimeAndUnicodeInvariants(t *testing.T) {
	_ = testutil.DatabaseURL(t)
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skip("no tz database:", err)
	}
	// time.Local is read by HTTP/database goroutines. Start an isolated test
	// process with TZ set before Go initializes it instead of replacing that
	// global pointer while requests and cleanup are still running.
	if os.Getenv("PROUDAUTH_TIME_TEST_CHILD") != "1" {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTimeAndUnicodeInvariants$", "-test.timeout=2m", "-test.v")
		cmd.Env = append(os.Environ(), "TZ=America/New_York", "PROUDAUTH_TIME_TEST_CHILD=1")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("timezone subprocess: %v\n%s", err, output)
		}
		return
	}
	if time.Local.String() != ny.String() {
		t.Fatalf("subprocess timezone %s, want %s", time.Local, ny)
	}
	f := NewFixture(t)
	h := f.H
	// Ten minutes before the next daylight-saving change in New York.
	now := h.Clock.Now()
	_, off := now.In(ny).Zone()
	next := now
	for i := 0; i < 24*400; i++ {
		next = next.Add(time.Hour)
		if _, o := next.In(ny).Zone(); o != off {
			break
		}
	}
	h.Clock.Set(next.Truncate(time.Hour).Add(-10 * time.Minute))
	f.ReloginAdmin()
	tok := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens
	mustStatus(t, tok, 200, "login across the DST change")
	claims := jwtPayload(tok.Str("access_token"))
	iat, exp := int64(claims["iat"].(float64)), int64(claims["exp"].(float64))
	if got, want := time.Duration(exp-iat)*time.Second, time.Duration(tok.Get("expires_in").(float64))*time.Second; got != want {
		t.Fatalf("lifetime %v differs from expires_in %v", got, want)
	}
	if time.Unix(iat, 0).UTC() != h.Clock.Now().UTC().Truncate(time.Second) {
		t.Fatalf("iat %v is not the absolute issue time %v", time.Unix(iat, 0).UTC(), h.Clock.Now().UTC())
	}
	// Identifiers: full-width and case variants canonicalize to one account,
	// by Unicode normalization and case mapping that never depend on a locale.
	for _, id := range []string{"BOB@EXAMPLE.TEST", "bob@Example.Test"} {
		start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
			Organization: f.Acme})
		h.Step(start.Str("transaction_id"), cont, "identify", map[string]any{"identifier": id})
		st := h.Step(start.Str("transaction_id"), cont, "password", map[string]any{"password": h.passwords["bob@example.test"]})
		if st.Str("redirect_to") == "" {
			t.Fatalf("%s did not resolve to bob: %s", id, st.Raw)
		}
	}
	start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "orders:read", Resources: []string{f.OrdersAud},
		Organization: f.Acme})
	h.Step(start.Str("transaction_id"), cont, "identify", map[string]any{"identifier": "BOB@EXAMPLE.TEST"})
	if r := h.Step(start.Str("transaction_id"), cont, "password", map[string]any{"password": h.passwords["bob@example.test"] + "İ"}); r.Status == 200 &&
		r.Str("redirect_to") != "" {
		t.Fatal("a different password was accepted")
	}
	mustStatus(t, f.AdminAPI("POST", "/users", map[string]any{"username": "boB"}), 409, "case variant of an existing username")
	mustStatus(t, f.AdminAPI("POST", "/users", map[string]any{"username": "ｂｏｂ"}), 409, "full-width variant of an existing username")
	// U+0130 lower-cases to "i" by Unicode's locale-independent mapping, so
	// "kadİr" and "kadir" are one canonical username.
	f.must(f.AdminAPI("POST", "/users", map[string]any{"username": "kadİr"}), 201, "dotted capital I")
	mustStatus(t, f.AdminAPI("POST", "/users", map[string]any{"username": "kadir"}), 409, "canonical collision")
	mustStatus(t, f.AdminAPI("POST", "/users", map[string]any{"username": "kadır"}), 422, "dotless i is outside the username alphabet")
}
