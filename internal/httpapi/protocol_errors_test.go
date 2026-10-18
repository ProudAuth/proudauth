package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/oauth"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/platform/reqctx"
)

// TestProtocolRouteErrorFormat covers API-001, API-007 and API-009 at the
// rendering layer: on /realms/{realm}/oauth/* and /realms/{realm}/oidc/*
// every error, including the ones the middleware, the host policy and
// public() decide before a handler runs, is an OAuth error (RFC 6749 §5.2:
// error and error_description only, never problem details), keeps its HTTP
// status, and carries Retry-After on 429 and 503; every other path keeps
// problem details. Internal causes never reach either format.
func TestProtocolRouteErrorFormat(t *testing.T) {
	for path, want := range map[string]bool{
		"/realms/main/oauth/token":                            true,
		"/realms/main/oauth/register/cl_123":                  true,
		"/realms/main/oidc/userinfo":                          true,
		"/realms/main/oidc/check-session/origin":              true,
		"/realms/main/oauth":                                  true,
		"/realms/main/.well-known/openid-configuration":       false,
		"/realms/main/jwks":                                   false,
		"/realms/main/registry/token":                         false,
		"/realms/main/ssf/receivers/x/events":                 false,
		"/realms/main/oauthx/token":                           false,
		"/realms/oauth":                                       false,
		"/realms/":                                            false,
		"/api/v1/realms/main/oauth/token":                     false,
		"/api/v1/realms/main/users":                           false,
		"/.well-known/oauth-authorization-server/realms/main": false,
		"/health/ready":                                       false,
	} {
		if got := protocolRoute(path); got != want {
			t.Errorf("protocolRoute(%q) = %v, want %v", path, got, want)
		}
	}

	a := &App{}
	render := func(path string, err error) (*httptest.ResponseRecorder, map[string]any) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r = r.WithContext(reqctx.With(r.Context(), reqctx.Info{RequestID: "req-1"}))
		w := httptest.NewRecorder()
		a.writeError(w, r, err)
		var body map[string]any
		if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
			t.Fatalf("%s: body is not JSON: %v: %s", path, e, w.Body)
		}
		return w, body
	}
	leak := errors.New("dial tcp 10.0.0.5:5432: password=hunter2")
	for _, tc := range []struct {
		name   string
		err    error
		status int
		code   string
		desc   string
		retry  string
	}{
		{"load shedding", problem.ErrUnavailable.WithDetail("server is shedding load").WithRetryAfter(2 * time.Second), 503,
			"temporarily_unavailable", "server is shedding load", "2"},
		{"maintenance without a delay", problem.ErrMaintenance.WithDetail("Upgrading"), 503, "temporarily_unavailable", "Upgrading", "2"},
		{"maintenance with a delay", problem.ErrMaintenance.WithRetryAfter(2 * time.Minute), 503, "temporarily_unavailable",
			problem.ErrMaintenance.Title, "120"},
		{"body over the limit", problem.ErrTooLarge, 413, "invalid_request", problem.ErrTooLarge.Title, ""},
		{"unknown realm", problem.ErrNotFound, 404, "invalid_request", problem.ErrNotFound.Title, ""},
		{"host policy", problem.ErrMisdirected, 421, "invalid_request", problem.ErrMisdirected.Title, ""},
		{"wrong media type", problem.ErrUnsupportedMedia, 415, "invalid_request", problem.ErrUnsupportedMedia.Title, ""},
		{"throttled without a delay", problem.ErrRateLimited, 429, "slow_down", problem.ErrRateLimited.Title, "2"},
		{"throttled with a delay", problem.ErrRateLimited.WithRetryAfter(7500 * time.Millisecond), 429, "slow_down", problem.ErrRateLimited.Title, "8"},
		{"forbidden", problem.ErrForbidden, 403, "access_denied", problem.ErrForbidden.Title, ""},
		{"unauthenticated", problem.ErrUnauthenticated, 401, "invalid_token", problem.ErrUnauthenticated.Title, ""},
		{"internal problem", problem.ErrInternal.With(leak), 500, "server_error", "", ""},
		{"unknown error", leak, 500, "server_error", "", ""},
		{"OAuth error passes through", oauth.ErrTemporarilyUnavailable, 503, "temporarily_unavailable", "", "2"},
		{"OAuth invalid_client", oauth.ErrInvalidClient, 401, "invalid_client", "client authentication failed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, body := render("/realms/main/oauth/token", tc.err)
			if w.Code != tc.status || w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("status %d Content-Type %q, want %d application/json", w.Code, w.Header().Get("Content-Type"), tc.status)
			}
			if body["error"] != tc.code {
				t.Fatalf("error %v, want %s: %s", body["error"], tc.code, w.Body)
			}
			if desc, _ := body["error_description"].(string); desc != tc.desc {
				t.Fatalf("error_description %q, want %q", desc, tc.desc)
			}
			for k := range body {
				if k != "error" && k != "error_description" {
					t.Fatalf("member %q outside the OAuth error format: %s", k, w.Body)
				}
			}
			if got := w.Header().Get("Retry-After"); got != tc.retry {
				t.Fatalf("Retry-After %q, want %q", got, tc.retry)
			}
			switch tc.code {
			case "invalid_client":
				if w.Header().Get("WWW-Authenticate") != `Basic realm="token", error="invalid_client"` {
					t.Fatalf("invalid_client challenge %q", w.Header().Get("WWW-Authenticate"))
				}
			case "invalid_token":
				if w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
					t.Fatalf("invalid_token challenge %q", w.Header().Get("WWW-Authenticate"))
				}
			}
			if strings.Contains(w.Body.String(), "hunter2") || strings.Contains(w.Body.String(), "10.0.0.5") {
				t.Fatalf("internals in the response: %s", w.Body)
			}

			// Outside the protocol endpoints the same error stays a problem.
			if _, isOAuth := tc.err.(*oauth.Error); isOAuth {
				return
			}
			pw, pbody := render("/api/v1/realms/main/users", tc.err)
			if pw.Code != tc.status || pw.Header().Get("Content-Type") != "application/problem+json" || pbody["code"] == nil || pbody["request_id"] != "req-1" {
				t.Fatalf("custom API: %d %q %s", pw.Code, pw.Header().Get("Content-Type"), pw.Body)
			}
			if got := pw.Header().Get("Retry-After"); got != tc.retry {
				t.Fatalf("custom API Retry-After %q, want %q", got, tc.retry)
			}
		})
	}
}

// TestSenderConstraintChallenges covers TOK-019 with RFC 9449 §7.1: UserInfo
// answers a refused DPoP binding with a DPoP challenge naming the accepted
// proof algorithms (invalid_token for a DPoP-bound token without the DPoP
// scheme or with another key's proof, invalid_dpop_proof for a missing or
// invalid proof), and keeps the Bearer challenge for every other refusal.
func TestSenderConstraintChallenges(t *testing.T) {
	algs := `algs="RS256 PS256 ES256 EdDSA"`
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errDPoPScheme, `DPoP error="invalid_token", error_description="` + errDPoPScheme.Detail + `", ` + algs},
		{errDPoPKey, `DPoP error="invalid_token", error_description="` + errDPoPKey.Detail + `", ` + algs},
		{errDPoPProof, `DPoP error="invalid_dpop_proof", error_description="` + errDPoPProof.Detail + `", ` + algs},
		{errCertificateBinding, `Bearer error="invalid_token"`},
		{errNotSenderBound, `Bearer error="invalid_token"`},
		{problem.ErrUnauthenticated, `Bearer error="invalid_token"`},
	} {
		if got := senderChallenge(tc.err); got != tc.want {
			t.Errorf("%v: challenge %q, want %q", tc.err, got, tc.want)
		}
	}
	if got := dpopChallenge("", ""); got != "DPoP "+algs {
		t.Errorf("challenge without credentials %q", got)
	}
}
