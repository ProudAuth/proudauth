package hooks

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/egress"
	"github.com/proudauth/proudauth/internal/token"
)

// TestClaimsAnswerBounds covers TEST-053 and EXT-011 at the unit level: a
// token.claims answer that sets any reserved claim, roles or permissions, a
// claim name over 64 characters, more than 20 claims or more than 4 KiB of
// claims is malformed (so the diagnostics say malformed_response), and the
// limits are exact.
func TestClaimsAnswerBounds(t *testing.T) {
	protected := []string{"roles", "permissions", strings.Repeat("x", 65)}
	for k := range token.ReservedClaims {
		protected = append(protected, k)
	}
	for _, k := range protected {
		err := checkClaims(map[string]any{"tenant_tier": "gold", k: "hook-injected"})
		if err == nil {
			t.Fatalf("claim %q accepted", k)
		}
		if cat, _ := errorCategory(err); cat != "malformed_response" {
			t.Fatalf("claim %q: category %q", k, cat)
		}
	}
	many := map[string]any{}
	for i := range MaxClaims {
		many[fmt.Sprintf("c%02d", i)] = i
	}
	if err := checkClaims(many); err != nil {
		t.Fatalf("%d claims refused: %v", MaxClaims, err)
	}
	many["one_more"] = true
	if err := checkClaims(many); err == nil {
		t.Fatalf("%d claims accepted", MaxClaims+1)
	}
	// {"big":"…"} is 10 bytes plus the value.
	if err := checkClaims(map[string]any{"big": strings.Repeat("a", MaxClaimsBytes-10)}); err != nil {
		t.Fatalf("exactly 4 KiB of claims refused: %v", err)
	}
	if err := checkClaims(map[string]any{"big": strings.Repeat("a", MaxClaimsBytes-9)}); err == nil {
		t.Fatal("more than 4 KiB of claims accepted")
	}
	if err := checkClaims(nil); err != nil {
		t.Fatalf("no claims: %v", err)
	}
}

// timeoutErr is a network timeout that is not a context deadline (such as
// the transport's response-header timeout).
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "net/http: timeout awaiting response headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// TestErrorCategories covers EXT-017: hook failures reduce to the coarse
// categories the diagnostics publish, and every kind of timeout is a
// timeout.
func TestErrorCategories(t *testing.T) {
	code := 502
	for _, c := range []struct {
		err  error
		want string
	}{
		{statusError{code: code}, "status"},
		{fmt.Errorf("hook unreachable: %w", &url.Error{Op: "Post", URL: "https://hook.test", Err: context.DeadlineExceeded}), "timeout"},
		{fmt.Errorf("hook unreachable: %w", &url.Error{Op: "Post", URL: "https://hook.test", Err: timeoutErr{}}), "timeout"},
		{fmt.Errorf("hook unreachable: %w", egress.ErrForbiddenDestination), "egress_denied"},
		{errors.New("hook returned a malformed response"), "malformed_response"},
		{errTooManyObligations, "malformed_response"},
		{fmt.Errorf("hook unreachable: %w", errors.New("EOF")), "unreachable"},
		{errors.New("something else"), "error"},
	} {
		if got, _ := errorCategory(c.err); got != c.want {
			t.Errorf("%v: category %q, want %q", c.err, got, c.want)
		}
	}
}
