package e2e

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/proudauth/proudauth/internal/configuration"
)

// TestJoinRequestBudgets covers REG-012, TEN-018 and INV-013
// (authz-org-realm/join-request-no-budget): a requester's request-withdraw
// loop meets the per-user budget, many requesters meet the per-organization
// budget without touching another organization's, and requests the per-user
// budget refuses do not spend the organization's. A refusal is 429
// rate_limited with Retry-After and writes no audit event; withdrawing never
// refunds a budget; 0 disables a budget.
func TestJoinRequestBudgets(t *testing.T) {
	const window = time.Hour
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.RateLimits.JoinRequestsPerUser = 3
		c.Security.RateLimits.JoinRequestsPerOrganization = 5
		c.Security.RateLimits.JoinRequestWindow = window
	})
	// Budgets use fixed windows: start a minute into one so none rolls over
	// while the test runs.
	h.Clock.Set(h.Clock.Now().Truncate(window).Add(window + time.Minute))
	f := fixtureOn(t, h)
	j := newJoinRequests(t, f)
	for _, u := range []string{"dave", "erin", "gus", "finn", "ivy", "jack", "kim"} {
		f.CreateUser(u)
	}
	dave := f.AccountToken("dave").Tokens.Str("access_token")

	t.Run("REG-012 a request-withdraw loop meets the per-user budget", func(t *testing.T) {
		for i := range 3 {
			r := j.request(f.Acme, dave)
			mustStatus(t, r, 201, "request "+strconv.Itoa(i+1))
			mustStatus(t, j.withdraw(f.Acme, r.Str("id"), dave), 204, "withdraw")
		}
		audits := j.count(`SELECT count(*) FROM audit_events`)
		j.refused(t, j.request(f.Acme, dave), "fourth request after withdrawing three")
		if n := j.count(`SELECT count(*) FROM audit_events`); n != audits {
			t.Fatalf("a refused join request wrote %d audit events", n-audits)
		}
		if n := j.count(`SELECT count(*) FROM join_requests WHERE organization_id=$1 AND user_id=$2`, f.Acme, f.Users["dave"]); n != 3 {
			t.Fatalf("join requests recorded: %d, want 3", n)
		}
		if n := j.created(f.Acme); n != 3 {
			t.Fatalf("organization.join_request.created events: %d, want 3", n)
		}
	})

	t.Run("TEN-018 many requesters meet the per-organization budget", func(t *testing.T) {
		// Requests the requester's own budget refuses do not spend the
		// organization's, so one account cannot shut others out.
		for range 3 {
			j.refused(t, j.request(f.Globex, dave), "requester over budget")
		}
		for _, u := range []string{"erin", "gus", "finn", "ivy", "jack"} {
			mustStatus(t, j.request(f.Globex, f.AccountToken(u).Tokens.Str("access_token")), 201, u+" requests")
		}
		kim := f.AccountToken("kim").Tokens.Str("access_token")
		j.refused(t, j.request(f.Globex, kim), "sixth requester")
		if n := j.notices(f.Globex, "carol"); n != 5 {
			t.Fatalf("Globex reviewer notices: %d, want one per requester (5)", n)
		}
		mustStatus(t, j.request(f.Acme, kim), 201, "another organization's budget is separate")
	})

	t.Run("0 disables a budget", func(t *testing.T) {
		rl := &h.App.D.Cfg.Security.RateLimits
		rl.JoinRequestsPerUser, rl.JoinRequestsPerOrganization = 0, 0
		defer func() { rl.JoinRequestsPerUser, rl.JoinRequestsPerOrganization = 3, 5 }()
		for i := range 6 {
			r := j.request(f.Acme, dave)
			mustStatus(t, r, 201, "unbudgeted request "+strconv.Itoa(i+1))
			mustStatus(t, j.withdraw(f.Acme, r.Str("id"), dave), 204, "withdraw")
		}
		mustStatus(t, j.request(f.Globex, f.AccountToken("kim").Tokens.Str("access_token")), 201, "organization budget disabled")
	})
}

// TestJoinRequestReviewerNotices covers INV-013 with REG-012
// (authz-org-realm/join-request-no-budget): the reviewers get one notice for
// a requester's first request and none for the same requester's repeat
// requests to that organization within security.rate_limits.join_request_window,
// which are still recorded and audited; another requester, or a request after
// the window, notifies them again, and a zero window turns the
// de-duplication off.
func TestJoinRequestReviewerNotices(t *testing.T) {
	const window = time.Hour
	h := NewHarness(t, func(c *configuration.Config) {
		c.Security.RateLimits.JoinRequestsPerUser = 0
		c.Security.RateLimits.JoinRequestsPerOrganization = 0
		c.Security.RateLimits.JoinRequestWindow = window
	})
	f := fixtureOn(t, h)
	j := newJoinRequests(t, f)
	f.CreateUser("dave")
	f.CreateUser("erin")
	dave := f.AccountToken("dave").Tokens.Str("access_token")
	loop := func(n int, what string) {
		t.Helper()
		for i := range n {
			r := j.request(f.Acme, dave)
			mustStatus(t, r, 201, what+" "+strconv.Itoa(i+1))
			mustStatus(t, j.withdraw(f.Acme, r.Str("id"), dave), 204, "withdraw")
		}
	}
	suppressed := func() int {
		return j.count(`SELECT count(*) FROM audit_events WHERE type='organization.join_request.created' AND organization_id=$1
			AND metadata->>'reviewer_notice'='suppressed_repeat'`, f.Acme)
	}

	loop(4, "request")
	if n := j.notices(f.Acme, "alice"); n != 1 {
		t.Fatalf("reviewer notices after four requests within the window: %d, want 1", n)
	}
	if n, s := j.created(f.Acme), suppressed(); n != 4 || s != 3 {
		t.Fatalf("created events %d (want 4), marked as repeats %d (want 3)", n, s)
	}
	mustStatus(t, j.request(f.Acme, f.AccountToken("erin").Tokens.Str("access_token")), 201, "another requester")
	if n := j.notices(f.Acme, "alice"); n != 2 {
		t.Fatalf("reviewer notices after another requester: %d, want 2", n)
	}

	h.Clock.Advance(window + time.Minute)
	dave = f.AccountToken("dave").Tokens.Str("access_token")
	loop(2, "request after the window")
	if n := j.notices(f.Acme, "alice"); n != 3 {
		t.Fatalf("reviewer notices after the window: %d, want 3", n)
	}

	h.App.D.Cfg.Security.RateLimits.JoinRequestWindow = 0
	defer func() { h.App.D.Cfg.Security.RateLimits.JoinRequestWindow = window }()
	loop(1, "request with a zero window")
	if n := j.notices(f.Acme, "alice"); n != 4 {
		t.Fatalf("reviewer notices with a zero window: %d, want 4", n)
	}
}

// joinRequests drives join requests against a fixture whose organizations
// accept them.
type joinRequests struct {
	t testing.TB
	f *Fixture
}

func newJoinRequests(t testing.TB, f *Fixture) *joinRequests {
	t.Helper()
	for _, org := range []string{f.Acme, f.Globex} {
		o := f.must(f.AdminAPI("GET", "/organizations/"+org, nil), 200, "org")
		mustStatus(t, f.H.Do(Req{Method: "PATCH", Path: "/api/v1/realms/main/organizations/" + org, Token: f.AdminToken,
			Headers: map[string]string{"If-Match": o.Header.Get("ETag")}, JSON: map[string]any{"policy": map[string]any{"join_requests_enabled": true}}}), 200, "enable joins")
	}
	return &joinRequests{t: t, f: f}
}

func (j *joinRequests) request(org, token string) *Resp {
	j.t.Helper()
	return j.f.H.API("POST", "/organizations/"+org+"/join-requests", token, map[string]any{})
}

func (j *joinRequests) withdraw(org, id, token string) *Resp {
	j.t.Helper()
	return j.f.H.API("POST", "/organizations/"+org+"/join-requests/"+id+"/withdraw", token, nil)
}

// refused checks a budget refusal: 429 rate_limited with a Retry-After within
// the window.
func (j *joinRequests) refused(t testing.TB, r *Resp, what string) {
	t.Helper()
	window := j.f.H.App.D.Cfg.Security.RateLimits.JoinRequestWindow
	secs, err := strconv.Atoi(r.Header.Get("Retry-After"))
	if r.Status != 429 || r.Str("code") != "rate_limited" || err != nil || secs < 1 || time.Duration(secs)*time.Second > window {
		t.Fatalf("%s: want 429 rate_limited with Retry-After within %s, got %d Retry-After %q %s", what, window, r.Status, r.Header.Get("Retry-After"), r.Raw)
	}
}

func (j *joinRequests) count(query string, args ...any) int {
	j.t.Helper()
	var n int
	if err := j.f.H.App.D.DB.Pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		j.t.Fatal(err)
	}
	return n
}

// notices counts the join-request notices queued for a reviewer in an
// organization.
func (j *joinRequests) notices(org, reviewer string) int {
	return j.count(`SELECT count(*) FROM notification_jobs WHERE organization_id=$1 AND template='join_request' AND user_id=$2`, org, j.f.Users[reviewer])
}

// created counts the organization.join_request.created audit events of an
// organization.
func (j *joinRequests) created(org string) int {
	return j.count(`SELECT count(*) FROM audit_events WHERE type='organization.join_request.created' AND organization_id=$1`, org)
}
