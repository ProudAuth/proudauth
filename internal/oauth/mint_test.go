package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/configuration"
	"github.com/proudauth/proudauth/internal/identity"
	"github.com/proudauth/proudauth/internal/realm"
	"github.com/proudauth/proudauth/internal/runtime"
	"github.com/proudauth/proudauth/internal/token"
)

// checkError fails unless got is the OAuth error with exactly this status,
// code and description. Most protocol errors are built per call (for example
// ErrInvalidRequest(...)), so their identity is the triple, not a pointer.
func checkError(t *testing.T, got *Error, status int, code, desc string) {
	t.Helper()
	if got == nil {
		t.Fatalf("got no error, want %d %s %q", status, code, desc)
	}
	if got.Status != status || got.Code != code || got.Description != desc {
		t.Fatalf("got error %d %s %q, want %d %s %q", got.Status, got.Code, got.Description, status, code, desc)
	}
}

// TestErrorFormat pins the protocol error rendering (RFC 6749 §5.2,
// API-007): the JSON body carries only error and error_description (omitted
// when empty); the HTTP status and Retry-After stay out of the body.
func TestErrorFormat(t *testing.T) {
	retry := oerr(429, "slow_down", "token request budget exhausted")
	retry.RetryAfter = 5 * time.Second
	cases := []struct {
		name    string
		err     *Error
		status  int
		code    string
		desc    string
		json    string
		message string
	}{
		{"invalid_request", ErrInvalidRequest("parameter state must not repeat"), 400, "invalid_request", "parameter state must not repeat",
			`{"error":"invalid_request","error_description":"parameter state must not repeat"}`, "invalid_request: parameter state must not repeat"},
		{"invalid_client", ErrInvalidClient, 401, "invalid_client", "client authentication failed",
			`{"error":"invalid_client","error_description":"client authentication failed"}`, "invalid_client: client authentication failed"},
		{"invalid_client_metadata", ErrInvalidClientMetadata("no key"), 400, "invalid_client_metadata", "no key",
			`{"error":"invalid_client_metadata","error_description":"no key"}`, "invalid_client_metadata: no key"},
		{"invalid_grant", ErrInvalidGrant("invalid authorization code"), 400, "invalid_grant", "invalid authorization code",
			`{"error":"invalid_grant","error_description":"invalid authorization code"}`, "invalid_grant: invalid authorization code"},
		{"unauthorized_client", ErrUnauthorizedClient("device flow not allowed"), 400, "unauthorized_client", "device flow not allowed",
			`{"error":"unauthorized_client","error_description":"device flow not allowed"}`, "unauthorized_client: device flow not allowed"},
		{"unsupported_grant_type", ErrUnsupportedGrantType, 400, "unsupported_grant_type", "grant type not supported",
			`{"error":"unsupported_grant_type","error_description":"grant type not supported"}`, "unsupported_grant_type: grant type not supported"},
		{"invalid_scope", ErrInvalidScope("unknown scope x"), 400, "invalid_scope", "unknown scope x",
			`{"error":"invalid_scope","error_description":"unknown scope x"}`, "invalid_scope: unknown scope x"},
		{"invalid_target", ErrInvalidTarget("no resource requested"), 400, "invalid_target", "no resource requested",
			`{"error":"invalid_target","error_description":"no resource requested"}`, "invalid_target: no resource requested"},
		{"server_error has no description", ErrServerError, 500, "server_error", "", `{"error":"server_error"}`, "server_error: "},
		{"temporarily_unavailable", ErrTemporarilyUnavailable, 503, "temporarily_unavailable", "", `{"error":"temporarily_unavailable"}`, "temporarily_unavailable: "},
		{"slow_down", ErrSlowDown, 400, "slow_down", "", `{"error":"slow_down"}`, "slow_down: "},
		{"authorization_pending", ErrAuthorizationPending, 400, "authorization_pending", "", `{"error":"authorization_pending"}`, "authorization_pending: "},
		{"expired_token", ErrExpiredToken, 400, "expired_token", "", `{"error":"expired_token"}`, "expired_token: "},
		{"access_denied", ErrAccessDenied, 400, "access_denied", "", `{"error":"access_denied"}`, "access_denied: "},
		{"retry-after stays out of the body", retry, 429, "slow_down", "token request budget exhausted",
			`{"error":"slow_down","error_description":"token request budget exhausted"}`, "slow_down: token request budget exhausted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkError(t, tc.err, tc.status, tc.code, tc.desc)
			b, err := json.Marshal(tc.err)
			if err != nil {
				t.Fatal(err)
			}
			if string(b) != tc.json {
				t.Fatalf("JSON %s, want %s", b, tc.json)
			}
			if got := tc.err.Error(); got != tc.message {
				t.Fatalf("Error() %q, want %q", got, tc.message)
			}
		})
	}
}

// TestServerError checks that a protocol error raised inside a transaction
// keeps its identity while any other failure becomes the bare server_error.
func TestServerError(t *testing.T) {
	s := &Service{d: &runtime.Deps{Log: slog.New(slog.DiscardHandler)}}
	budget := oerr(429, "slow_down", "organization token budget exhausted")
	cases := []struct {
		name string
		in   error
		want *Error
	}{
		{"protocol error", budget, budget},
		{"wrapped protocol error", fmt.Errorf("issue: %w", budget), budget},
		{"doubly wrapped protocol error", fmt.Errorf("tx: %w", fmt.Errorf("issue: %w", ErrTemporarilyUnavailable)), ErrTemporarilyUnavailable},
		{"internal failure", errors.New("connection reset"), ErrServerError},
		{"internal failure wrapping a sentinel", fmt.Errorf("mint: %w", token.ErrNoActiveKey), ErrServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverError(s, tc.in); !errors.Is(got, tc.want) {
				t.Fatalf("serverError(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestAccessTTL pins the access-token lifetime rules (TOK-018, ADV-001):
// the resource sets the base lifetime, every other limit only shortens it,
// and the configured maximum always applies.
func TestAccessTTL(t *testing.T) {
	s := &Service{d: &runtime.Deps{Cfg: &configuration.Config{Tokens: configuration.TokensConfig{
		AccessTokenTTL: 15 * time.Minute, MaxAccessTokenTTL: time.Hour}}}}
	pol := func(p realm.TokenLifetimePolicy) *realm.Realm { return &realm.Realm{Policy: realm.Policy{Tokens: p}} }
	client := func(seconds int, profile string) *application.Client {
		return &application.Client{SecurityProfile: profile, TokenPolicy: application.TokenPolicy{AccessTokenTTLSeconds: seconds}}
	}
	const mfa, single = "urn:proudauth:acr:mfa", "urn:proudauth:acr:single_factor"
	cases := []struct {
		name string
		sp   AccessSpec
		want time.Duration
	}{
		{"configured default", AccessSpec{}, 15 * time.Minute},
		{"resource lifetime above the default", AccessSpec{Resource: &application.Resource{AccessTokenTTL: 1800}}, 30 * time.Minute},
		{"resource lifetime capped by the configured maximum", AccessSpec{Resource: &application.Resource{AccessTokenTTL: 7200}}, time.Hour},
		{"resource lifetime below the default", AccessSpec{Resource: &application.Resource{AccessTokenTTL: 60}}, time.Minute},
		{"client policy shortens", AccessSpec{Client: client(300, "")}, 5 * time.Minute},
		{"client policy never lengthens", AccessSpec{Client: client(3600, "")}, 15 * time.Minute},
		{"realm limit shortens", AccessSpec{Realm: pol(realm.TokenLifetimePolicy{AccessTokenTTLSeconds: 600})}, 10 * time.Minute},
		{"realm limit never lengthens", AccessSpec{Realm: pol(realm.TokenLifetimePolicy{AccessTokenTTLSeconds: 3600})}, 15 * time.Minute},
		{"service limit for a service principal", AccessSpec{SubjectType: "service_principal",
			Realm: pol(realm.TokenLifetimePolicy{ServiceAccessTokenTTLSeconds: 120})}, 2 * time.Minute},
		{"service limit not for a user", AccessSpec{SubjectType: "user", ACR: mfa,
			Realm: pol(realm.TokenLifetimePolicy{ServiceAccessTokenTTLSeconds: 120})}, 15 * time.Minute},
		{"single-factor limit for a single-factor user", AccessSpec{SubjectType: "user", ACR: single,
			Realm: pol(realm.TokenLifetimePolicy{SingleFactorAccessTokenTTLSeconds: 300})}, 5 * time.Minute},
		{"single-factor limit for a user without acr", AccessSpec{SubjectType: "user",
			Realm: pol(realm.TokenLifetimePolicy{SingleFactorAccessTokenTTLSeconds: 300})}, 5 * time.Minute},
		{"single-factor limit for a recovery session", AccessSpec{SubjectType: "user", ACR: "urn:proudauth:acr:recovery",
			Realm: pol(realm.TokenLifetimePolicy{SingleFactorAccessTokenTTLSeconds: 300})}, 5 * time.Minute},
		{"single-factor limit not for an MFA user", AccessSpec{SubjectType: "user", ACR: mfa,
			Realm: pol(realm.TokenLifetimePolicy{SingleFactorAccessTokenTTLSeconds: 300})}, 15 * time.Minute},
		{"single-factor limit not for a phishing-resistant user", AccessSpec{SubjectType: "user", ACR: "urn:proudauth:acr:phishing_resistant",
			Realm: pol(realm.TokenLifetimePolicy{SingleFactorAccessTokenTTLSeconds: 300})}, 15 * time.Minute},
		{"single-factor limit not for a service principal", AccessSpec{SubjectType: "service_principal",
			Realm: pol(realm.TokenLifetimePolicy{SingleFactorAccessTokenTTLSeconds: 300})}, 15 * time.Minute},
		{"impersonation limit for support tokens", AccessSpec{Kind: token.KindImpersonationAccess,
			Realm: pol(realm.TokenLifetimePolicy{ImpersonationAccessTokenTTLSeconds: 60})}, time.Minute},
		{"impersonation limit not for other tokens", AccessSpec{Kind: token.KindUserAccess,
			Realm: pol(realm.TokenLifetimePolicy{ImpersonationAccessTokenTTLSeconds: 60})}, 15 * time.Minute},
		{"FAPI 2.0 client capped at ten minutes", AccessSpec{Client: client(0, application.ProfileFAPI2),
			Resource: &application.Resource{AccessTokenTTL: 1800}}, 10 * time.Minute},
		{"TTL cap shortens", AccessSpec{TTLCap: 90 * time.Second}, 90 * time.Second},
		{"TTL cap never lengthens", AccessSpec{TTLCap: 2 * time.Hour}, 15 * time.Minute},
		{"smallest limit wins", AccessSpec{SubjectType: "user", Client: client(600, ""), TTLCap: 400 * time.Second,
			Realm: pol(realm.TokenLifetimePolicy{AccessTokenTTLSeconds: 500, SingleFactorAccessTokenTTLSeconds: 300})}, 5 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.accessTTL(tc.sp); got != tc.want {
				t.Fatalf("accessTTL = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestUserClaims pins minimal disclosure by scope (OIDC-007): each standard
// scope releases its own claims and nothing else.
func TestUserClaims(t *testing.T) {
	verified := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	updated := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	address := map[string]any{"country": "JO", "locality": "Amman"}
	full := &identity.User{DisplayName: "Jo Doe", GivenName: "Jo", FamilyName: "Doe", Locale: "ar-JO", Zoneinfo: "Asia/Amman", UpdatedAt: updated,
		Profile: map[string]any{"address": address, "department": "R&D"},
		Identifiers: []identity.Identifier{
			{Type: "email", Value: "old@example.com"},
			{Type: "email", Value: "jo@example.com", IsPrimary: true, VerifiedAt: &verified},
			{Type: "username", Value: "jdoe"},
			{Type: "phone", Value: "+962700000001"},
			{Type: "phone", Value: "+962700000002", IsPrimary: true},
		}}
	profile := map[string]any{"name": "Jo Doe", "given_name": "Jo", "family_name": "Doe", "locale": "ar-JO", "zoneinfo": "Asia/Amman",
		"preferred_username": "jdoe", "updated_at": updated.Unix()}
	merge := func(ms ...map[string]any) map[string]any {
		out := map[string]any{}
		for _, m := range ms {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}
	email := map[string]any{"email": "jo@example.com", "email_verified": true}
	phone := map[string]any{"phone_number": "+962700000002", "phone_number_verified": false}
	addr := map[string]any{"address": address}
	cases := []struct {
		name   string
		user   *identity.User
		scopes []string
		want   map[string]any
	}{
		{"no scope", full, nil, map[string]any{}},
		{"openid alone releases no user claim", full, []string{"openid"}, map[string]any{}},
		{"profile", full, []string{"openid", "profile"}, profile},
		{"email uses the primary address", full, []string{"email"}, email},
		{"phone uses the primary number", full, []string{"phone"}, phone},
		{"address", full, []string{"address"}, addr},
		{"every scope", full, []string{"openid", "profile", "email", "phone", "address", "offline_access"}, merge(profile, email, phone, addr)},
		{"unknown scope releases nothing", full, []string{"department"}, map[string]any{}},
		{"empty profile still carries updated_at", &identity.User{UpdatedAt: updated}, []string{"profile"}, map[string]any{"updated_at": updated.Unix()}},
		{"first email when none is primary", &identity.User{Identifiers: []identity.Identifier{{Type: "email", Value: "a@example.com"},
			{Type: "email", Value: "b@example.com"}}}, []string{"email"}, map[string]any{"email": "a@example.com", "email_verified": false}},
		{"no email identifier", &identity.User{}, []string{"email"}, map[string]any{}},
		{"non-primary phone is not released", &identity.User{Identifiers: []identity.Identifier{{Type: "phone", Value: "+1"}}}, []string{"phone"}, map[string]any{}},
		{"address that is not an object is not released", &identity.User{Profile: map[string]any{"address": "Main St"}}, []string{"address"}, map[string]any{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UserClaims(tc.user, tc.scopes); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("UserClaims = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestClaimSource checks that only attributes the realm marks claimable and
// not user-editable are exposed to claim mappings (APP-011).
func TestClaimSource(t *testing.T) {
	rlm := &realm.Realm{Policy: realm.Policy{Profile: realm.ProfilePolicy{Attributes: []identity.AttributeDef{
		{Name: "employee_id", Claimable: true},
		{Name: "nickname", Claimable: true, UserEditable: true},
		{Name: "cost_center"},
	}}}}
	u := &identity.User{GivenName: "Jo", FamilyName: "Doe", DisplayName: "Jo Doe", Locale: "ar-JO", Zoneinfo: "Asia/Amman",
		Profile: map[string]any{"employee_id": "E-1", "nickname": "jojo", "cost_center": "42"}}
	got := claimSource(rlm, u)
	want := application.ClaimSource{
		User:      map[string]string{"given_name": "Jo", "family_name": "Doe", "display_name": "Jo Doe", "locale": "ar-JO", "zoneinfo": "Asia/Amman"},
		Profile:   u.Profile,
		Claimable: map[string]bool{"employee_id": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("claimSource = %#v, want %#v", got, want)
	}
}
