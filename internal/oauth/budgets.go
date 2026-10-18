package oauth

import (
	"context"
	"net/http"
	"net/url"

	"github.com/proudauth/proudauth/internal/application"
	"github.com/proudauth/proudauth/internal/platform/problem"
	"github.com/proudauth/proudauth/internal/ratelimit"
	"github.com/proudauth/proudauth/internal/realm"
)

// Budgets of the protocol endpoints (owner decision 9 of 0.2.0-alpha.6, the
// finding core-oauth-oidc/token-endpoint-rate-limit; SEC-006, ABU-001,
// REG-012, TEN-018).
//
// The token endpoint and PAR keep a failure budget per requesting network
// (IPv4 /32, IPv6 /64, with the wider /24 or /48 at network_coarse_factor
// times the limit): before the client is authenticated and before anything
// is audited, one read-only statement checks it (NetworkBudget), and a
// network that has spent it is refused; a request that then fails (client
// authentication, or an invalid grant or pushed request, failedRequest)
// counts against it, in one statement after the answer is known. A
// confidential client's backend or a NAT whose requests succeed never uses
// it, however many it sends, while a flood of junk client IDs, wrong secrets,
// bad codes or stolen tokens from one network is cut off before client
// authentication. Device authorization stores a row for every request, so
// its network budget counts every request instead. The browser authorization
// endpoint and the headless start write a row only by starting a
// transaction, which the transaction-start budget (start_per_network)
// already counts.
//
// After authentication, the token budget of a client (token_per_client)
// counts every request of a confidential client, as before. A public client
// authenticates with its client_id alone, so anyone can spend its budget:
// for a public client the budget counts only failed grants
// (publicFailureBudgets), and every network's share of those failures is
// bounded by token_per_network_client, so one network cannot use the
// client's budget up for everyone. Once either is spent the client's token
// requests from that network, or from everywhere, are refused until the
// window ends: aggregate caps fail closed.

// Endpoint names a protocol endpoint with a per-network budget checked before
// client authentication. Its value is the budget's key family.
type Endpoint string

// Endpoints with a pre-authentication network budget.
const (
	// EndpointToken is the token endpoint: failed requests per network,
	// token_failures_per_network per token_window.
	EndpointToken Endpoint = "token-ip"
	// EndpointPAR is the pushed authorization request endpoint: failed
	// requests per network, par_failures_per_network per token_window.
	EndpointPAR Endpoint = "par-ip"
	// EndpointDevice is the device authorization endpoint: every request
	// per network, device_per_network per login_window.
	EndpointDevice Endpoint = "device-ip"
)

// networkBudgets are the budgets of the network ip at the endpoint, with the
// wider network.
func (s *Service) networkBudgets(rlm *realm.Realm, ep Endpoint, ip string) []ratelimit.Budget {
	rl := s.d.Cfg.Security.RateLimits
	limit, window := rl.TokenFailuresPerNetwork, rl.TokenWindow
	switch ep {
	case EndpointPAR:
		limit = rl.PARFailuresPerNetwork
	case EndpointDevice:
		limit, window = rl.DevicePerNetwork, rl.LoginWindow
	}
	return ratelimit.PerNetwork(string(ep)+":"+rlm.ID+":", ip, limit, window, rl.NetworkCoarseFactor)
}

// NetworkBudget runs the budget of the network a request comes from at the
// endpoint, before the client is authenticated and before anything is
// audited. At the token endpoint and PAR it checks the network's failure
// budget without counting the request (failed requests are counted once they
// have failed, chargeNetworkFailure); at device authorization it counts the
// request. A spent budget answers 429 slow_down with Retry-After (the OAuth
// form of the protocol routes); an unavailable limiter answers 503
// temporarily_unavailable, failing closed. A limit of 0 disables the budget.
func (s *Service) NetworkBudget(ctx context.Context, rlm *realm.Realm, ep Endpoint, ip string) *Error {
	budgets := s.networkBudgets(rlm, ep, ip)
	if ep == EndpointDevice {
		d, err := s.Limiter.Hit(ctx, budgets...)
		return budgetRefusal(d, err, "request budget of this network exhausted")
	}
	d, err := s.Limiter.Check(ctx, budgets...)
	return budgetRefusal(d, err, "failed request budget of this network exhausted")
}

// budgetRefusal turns a budget decision into the OAuth error of a protocol
// endpoint: 503 temporarily_unavailable when the limiter failed (budgets fail
// closed), 429 slow_down with Retry-After when a budget is spent, nil
// otherwise.
func budgetRefusal(d ratelimit.Decision, err error, desc string) *Error {
	if err != nil {
		return oerr(http.StatusServiceUnavailable, "temporarily_unavailable", "request budget unavailable")
	}
	if !d.Allowed {
		e := oerr(http.StatusTooManyRequests, "slow_down", desc)
		e.RetryAfter = d.RetryAfter
		return e
	}
	return nil
}

// tokenClientBudget runs the token budgets of an authenticated client before
// its grant: a confidential client's request counts against token-client; a
// public client's request only checks that its failure budgets
// (publicFailureBudgets) have a unit left, and chargeFailures counts it once
// the grant fails.
func (s *Service) tokenClientBudget(ctx context.Context, rlm *realm.Realm, c *application.Client, ip string) *Error {
	if c.Public() {
		d, err := s.Limiter.Check(ctx, s.publicFailureBudgets(rlm, c, ip)...)
		return budgetRefusal(d, err, "token request budget exhausted")
	}
	rl := s.d.Cfg.Security.RateLimits
	d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "token-client:" + c.Ref, Limit: rl.TokenPerClient, Window: rl.TokenWindow})
	return budgetRefusal(d, err, "token request budget exhausted")
}

// publicFailureBudgets are the budgets a public client's failed grant counts
// against besides its network's: the network's share for the client
// (token_per_network_client, with the wider network) and the client's own
// token budget (token_per_client).
func (s *Service) publicFailureBudgets(rlm *realm.Realm, c *application.Client, ip string) []ratelimit.Budget {
	rl := s.d.Cfg.Security.RateLimits
	return append(ratelimit.PerNetwork("token-ip-client:"+rlm.ID+":"+c.Ref+":", ip, rl.TokenPerNetworkClient, rl.TokenWindow, rl.NetworkCoarseFactor),
		ratelimit.Budget{Key: "token-client:" + c.Ref, Limit: rl.TokenPerClient, Window: rl.TokenWindow})
}

// failedRequest reports whether a token or PAR error is a failed request that
// counts against the failure budgets: the client's authentication, or the
// request, grant, client binding, scope, resource or proof it presents, is
// not valid (invalid_client, invalid_request, invalid_grant, invalid_scope,
// invalid_target, unauthorized_client, unsupported_grant_type,
// invalid_dpop_proof, and at PAR unsupported_response_type and
// request_not_supported). The answers of device-flow polling
// (authorization_pending, slow_down, expired_token, access_denied), budget
// refusals and server errors are not failures of the request.
func failedRequest(e *Error) bool {
	if e == nil || e.Status >= http.StatusInternalServerError || e.Status == http.StatusTooManyRequests {
		return false
	}
	switch e.Code {
	case "invalid_client", "invalid_request", "invalid_grant", "invalid_scope", "invalid_target", "unauthorized_client",
		"unsupported_grant_type", "invalid_dpop_proof", "unsupported_response_type", "request_not_supported":
		return true
	}
	return false
}

// chargeFailures counts a failed request against the failure budgets in one
// statement: its network's at the endpoint and, for a public client's failed
// grant at the token endpoint, the client's (publicFailureBudgets). c is the
// authenticated client, nil when authentication failed. The answer is
// already the failure; a limiter that fails here leaves it uncounted, and
// the next request's check fails closed.
func (s *Service) chargeFailures(ctx context.Context, rlm *realm.Realm, ep Endpoint, c *application.Client, ip string) {
	budgets := s.networkBudgets(rlm, ep, ip)
	if ep == EndpointToken && c != nil && c.Public() {
		budgets = append(budgets, s.publicFailureBudgets(rlm, c, ip)...)
	}
	if _, err := s.Limiter.Hit(ctx, budgets...); err != nil && s.d.Log != nil {
		s.d.Log.Warn("failed request not counted", "component", "oauth", "event_code", "oauth.failure_budget_unavailable",
			"realm_id", rlm.ID, "endpoint", string(ep), "error", err)
	}
}

// PAR authenticates the client of a pushed authorization request and stores
// the request (PushAuthorizationRequest). The caller has checked the
// network's failure budget (NetworkBudget with EndpointPAR) before reading
// client credentials; a request that fails client authentication or
// validation counts against it.
func (s *Service) PAR(ctx context.Context, rlm *realm.Realm, auth application.ClientAuthInput, endpoint string, v url.Values, dpopProof, ip string) (*PARResponse, *Error) {
	c, err := s.Apps.Authenticate(ctx, rlm.ID, rlm.Issuer, endpoint, auth)
	if err != nil {
		s.chargeFailures(ctx, rlm, EndpointPAR, nil, ip)
		return nil, ErrInvalidClient
	}
	res, oe := s.PushAuthorizationRequest(ctx, rlm, c, v, dpopProof, endpoint)
	if failedRequest(oe) {
		s.chargeFailures(ctx, rlm, EndpointPAR, c, ip)
	}
	return res, oe
}

// parClientBudget counts a public client's pushed authorization request
// against par-client (par_per_client per token_window), which bounds the
// requests anyone can push in the client's name from every network. A
// confidential client's requests are bounded by its credentials.
func (s *Service) parClientBudget(ctx context.Context, rlm *realm.Realm, c *application.Client) *Error {
	if !c.Public() {
		return nil
	}
	rl := s.d.Cfg.Security.RateLimits
	d, err := s.Limiter.Hit(ctx, ratelimit.Budget{Key: "par-client:" + rlm.ID + ":" + c.Ref, Limit: rl.PARPerClient, Window: rl.TokenWindow})
	return budgetRefusal(d, err, "pushed request budget of this client exhausted")
}

// userCodeBudgets are the failure budget of device-approval user-code
// lookups from a network (user_code_failures_per_network per login_window,
// with the wider network): only lookups that find no pending code count.
func (s *Service) userCodeBudgets(rlm *realm.Realm, ip string) []ratelimit.Budget {
	rl := s.d.Cfg.Security.RateLimits
	return ratelimit.PerNetwork("device-code-ip:"+rlm.ID+":", ip, rl.UserCodeFailuresPerNetwork, rl.LoginWindow, rl.NetworkCoarseFactor)
}

// checkUserCodeBudget refuses a user-code lookup from a network whose failure
// budget is spent: 429 rate_limited with Retry-After, or 503 when the limiter
// is unavailable (failing closed).
func (s *Service) checkUserCodeBudget(ctx context.Context, rlm *realm.Realm, ip string) error {
	d, err := s.Limiter.Check(ctx, s.userCodeBudgets(rlm, ip)...)
	if err != nil {
		return problem.ErrUnavailable
	}
	if !d.Allowed {
		return problem.ErrRateLimited.WithRetryAfter(d.RetryAfter)
	}
	return nil
}

// chargeUserCodeFailure counts a user-code lookup that found no pending
// code. A limiter that fails here leaves it uncounted; the next lookup's
// check fails closed.
func (s *Service) chargeUserCodeFailure(ctx context.Context, rlm *realm.Realm, ip string) {
	if _, err := s.Limiter.Hit(ctx, s.userCodeBudgets(rlm, ip)...); err != nil && s.d.Log != nil {
		s.d.Log.Warn("user-code failure not counted", "component", "oauth", "event_code", "oauth.device.failure_budget_unavailable",
			"realm_id", rlm.ID, "error", err)
	}
}
