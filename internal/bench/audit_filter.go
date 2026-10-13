package bench

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// complexAuditFilter measures AUD-006/AUD-011 conjunctions and bounded
// cursor pages under NFR-004/NFR-006. It owns public application reports;
// these never pretend to be server-observed security events.
type complexAuditFilter struct {
	owned           map[string]auditFilterEvent
	matches         []string // newest first, established by serial public writes
	query           url.Values
	cursor          string
	network         string
	realmID         string
	sourceContext   string
	next            atomic.Uint64
	preparedSeconds float64
}

type auditFilterEvent struct {
	typ, org, outcome, client, actor, subject, request string
	at                                                 time.Time
	ordinal                                            int
}

func (*complexAuditFilter) Name() string      { return "complex-audit-filter" }
func (*complexAuditFilter) Adversarial() bool { return true }
func (s *complexAuditFilter) Notes() []string {
	return []string{fmt.Sprintf("%d additional public application reports, matching seed.spec.users; serial fixture setup took %.3fs and is unmeasured", len(s.owned), s.preparedSeconds),
		"eleven simultaneous type-prefix, organization, actor, subject, client, request, category, outcome, network and from/to predicates; exact owned sequence pages capped at 200 despite limit=1000",
		"seven alternating profiles cover nonempty/empty conjunctions, a literal percent prefix, invalid network/time, a changed-filter cursor refusal and a resumed page; each operation is one GET",
		"fixture writes are application-reported evidence from one isolated service principal; credentials and event identifiers remain private; no counters are reset and no audit retention/partition or multi-host capacity is claimed"}
}
func (s *complexAuditFilter) Observations() map[string]any {
	return map[string]any{"fixture_events": len(s.owned), "compound_matches": len(s.matches), "requested_page_size": 1000,
		"required_max_page_size": 200, "profiles": 7, "prepared_seconds": s.preparedSeconds, "fixture_source": "public application reports",
		"scope": "one realm, two seeded organizations, one isolated reporting service; identifiers and authority omitted"}
}

func (s *complexAuditFilter) Prepare(ctx context.Context, e *Env) error {
	if e.Client == nil || e.Admin == nil || e.Seed == nil || e.Seed.Spec.Users < 16 || e.Seed.Spec.Users > 20000 || e.Seed.AdminAudience == "" {
		return fmt.Errorf("complex-audit-filter requires an MFA admin token and a fresh seed with 16..20000 users, two organizations and its admin audience")
	}
	other := ""
	for _, id := range e.Seed.OrgIDs {
		if id != e.Seed.LargeOrgID {
			other = id
			break
		}
	}
	if other == "" {
		return fmt.Errorf("complex-audit-filter requires two seeded organizations")
	}
	started := time.Now()
	prefix, err := runPrefix(e.Seed, "audit")
	if err != nil {
		return err
	}
	api := func(method, path string, doc any, want int) (*Response, error) {
		r, err := e.Client.API(ctx, method, path, e.adminToken(ctx), doc)
		if out := expectedOutcome(r, err, want); out != "ok" {
			return nil, fmt.Errorf("audit fixture %s %s: %s", method, path, out)
		}
		return r, nil
	}
	resources, err := api("GET", "/resources?limit=200", nil, 200)
	if err != nil {
		return err
	}
	resourceID := ""
	items, _ := resources.Body["items"].([]any)
	for _, item := range items {
		m := object(item)
		if stringValue(m, "audience") == e.Seed.AdminAudience {
			resourceID = stringValue(m, "id")
		}
	}
	if resourceID == "" {
		return fmt.Errorf("audit fixture admin resource absent")
	}
	sp, err := api("POST", "/service-principals", map[string]any{"name": prefix}, 201)
	if err != nil {
		return err
	}
	actor := sp.Str("id")
	decoy, err := api("POST", "/service-principals", map[string]any{"name": prefix + "-subject"}, 201)
	if err != nil {
		return err
	}
	role, err := api("POST", "/roles", map[string]any{"boundary_type": "realm", "name": prefix, "permissions": []string{"realm.activity.report"}}, 201)
	if err != nil {
		return err
	}
	if _, err := api("POST", "/role-assignments", map[string]any{"role_id": role.Str("id"), "subject": map[string]any{"type": "service_principal", "id": actor}}, 201); err != nil {
		return err
	}
	cl, err := api("POST", "/clients", map[string]any{"client_id": prefix, "name": prefix, "client_type": "machine", "service_principal_id": actor,
		"grant_types": []string{"client_credentials"}}, 201)
	if err != nil {
		return err
	}
	ref, err := clientRef(cl)
	if err != nil {
		return err
	}
	if _, err := api("PUT", "/clients/"+ref+"/resource-grants/"+resourceID, map[string]any{"allowed_scopes": []string{"proudauth:admin"}, "subject_types": []string{"service_principal"}}, 204); err != nil {
		return err
	}
	credential := SeedClient{ClientID: prefix, Secret: cl.Str("client_secret")}
	// Renew synchronously during unmeasured writes; no background fixture
	// token renewal should spill into the measured read-only operations.
	token, renewAt := "", time.Time{}
	reporter := tokenFetch("audit reporter token", func(ctx context.Context) (*Response, error) {
		return e.machineToken(ctx, credential, e.Seed.AdminAudience, "proudauth:admin")
	})
	s.owned = make(map[string]auditFilterEvent, e.Seed.Spec.Users)
	s.matches, s.cursor, s.network = nil, "", ""
	s.next.Store(0)
	at := time.Now().UTC().Truncate(time.Second)
	if e.Now != nil {
		at = e.Now().UTC().Truncate(time.Second)
	}
	typeBase := "app." + strings.ReplaceAll(prefix, "-", "_") + "."
	request := prefix + "-reports"
	for i := range e.Seed.Spec.Users {
		profile := i % 8
		ev := auditFilterEvent{typ: typeBase + "hit_kind", org: e.Seed.LargeOrgID, outcome: "success", actor: actor, subject: actor, client: prefix, request: request, at: at, ordinal: i}
		switch profile {
		case 1:
			ev.typ = typeBase + "hitxkind" // An underscore must not match this.
		case 2:
			ev.org = other
		case 3:
			ev.outcome = "denied"
		case 4:
			ev.subject = decoy.Str("id")
		case 5:
			ev.request = prefix + "-other-request"
		case 6:
			ev.at = at.Add(-time.Hour)
		case 7:
			ev.typ = typeBase + "miss_kind"
		}
		if time.Now().After(renewAt) {
			var ttl time.Duration
			token, ttl, err = reporter(ctx)
			if err != nil {
				return err
			}
			renewAt = time.Now().Add(ttl - min(ttl/5, time.Minute))
		}
		r, err := e.Client.Do(ctx, Request{Method: "POST", Path: "/api/v1/realms/" + e.Client.Realm + "/activity-events", Token: token,
			Headers: map[string]string{"X-Request-Id": ev.request}, JSON: map[string]any{"type": ev.typ, "organization_id": ev.org, "outcome": ev.outcome,
				"subject": map[string]any{"type": "service_principal", "id": ev.subject}, "occurred_at": ev.at,
				"metadata": map[string]any{"benchmark_ordinal": i}}})
		if out := expectedOutcome(r, err, 202); out != "ok" {
			return fmt.Errorf("audit public report %d: %s", i, out)
		}
		id := r.Str("id")
		if id == "" || r.Str("source") != "application" || r.Str("reporting_service") != prefix {
			return fmt.Errorf("audit report lacks owned identity/provenance")
		}
		if _, duplicate := s.owned[id]; duplicate {
			return fmt.Errorf("audit report reused identity")
		}
		s.owned[id] = ev
		if profile == 0 {
			s.matches = append(s.matches, id)
		}
	}
	for i, j := 0, len(s.matches)-1; i < j; i, j = i+1, j-1 {
		s.matches[i], s.matches[j] = s.matches[j], s.matches[i]
	}
	// Discover the deployment's stored, already truncated source network.
	r, err := api("GET", "/audit-events?id="+url.QueryEscape(s.matches[0]), nil, 200)
	if err != nil {
		return err
	}
	items, _ = r.Body["items"].([]any)
	if len(items) != 1 || stringValue(object(items[0]), "id") != s.matches[0] {
		return fmt.Errorf("audit owned source event absent")
	}
	s.realmID = stringValue(object(items[0]), "realm_id")
	s.sourceContext = stringValue(object(items[0]), "ip_context")
	s.network = s.sourceContext
	if _, err := netip.ParsePrefix(s.network); err != nil {
		if addr, aerr := netip.ParseAddr(s.network); aerr == nil {
			s.network = netip.PrefixFrom(addr, addr.BitLen()).String()
		} else {
			return fmt.Errorf("audit source context is not an address or network")
		}
	}
	s.query = url.Values{"limit": {"1000"}, "type_prefix": {typeBase + "hit_"}, "organization_id": {e.Seed.LargeOrgID}, "actor_id": {actor},
		"subject_id": {actor}, "client_id": {prefix}, "request_id": {request}, "category": {"application"}, "outcome": {"success"},
		"network": {s.network}, "from": {at.Format(time.RFC3339)}, "to": {at.Add(time.Second).Format(time.RFC3339)}}
	q := cloneAuditQuery(s.query)
	q.Set("limit", "1")
	r, err = api("GET", "/audit-events?"+q.Encode(), nil, 200)
	if err != nil {
		return err
	}
	if !s.checkPage(r, s.matches[:1], true) {
		return fmt.Errorf("audit first sequence page mismatches owned report")
	}
	s.cursor = r.Str("next_cursor")
	if s.cursor == "" {
		return fmt.Errorf("audit sequence fixture lacks cursor")
	}
	s.preparedSeconds = time.Since(started).Seconds()
	return nil
}

func cloneAuditQuery(q url.Values) url.Values {
	out := url.Values{}
	for k, vs := range q {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func (s *complexAuditFilter) Op(ctx context.Context, e *Env, _ int, _ *mrand.Rand) string {
	profile := int(s.next.Add(1)-1) % 7
	q := cloneAuditQuery(s.query)
	want, next := s.matches[:min(200, len(s.matches))], len(s.matches) >= 200
	label, status := "compound_match", 200
	switch profile {
	case 1:
		q.Set("type_prefix", q.Get("type_prefix")+"absent")
		want, next, label = nil, false, "compound_empty"
	case 2:
		q.Set("type_prefix", strings.TrimSuffix(q.Get("type_prefix"), "_")+"%")
		want, next, label = nil, false, "literal_prefix_empty"
	case 3:
		q.Set("network", "not-an-address-or-prefix")
		label, status = "invalid_network", 422
	case 4:
		q.Set("from", "not-a-timestamp")
		label, status = "invalid_time", 422
	case 5:
		q.Set("cursor", s.cursor)
		q.Set("category", "configuration")
		label, status = "cursor_scope_rejected", 400
	case 6:
		q.Set("cursor", s.cursor)
		want, next, label = s.matches[1:min(201, len(s.matches))], len(s.matches)-1 >= 200, "cursor_page"
	}
	r, err := e.Client.API(ctx, "GET", "/audit-events?"+q.Encode(), e.adminToken(ctx), nil)
	if err != nil {
		return "transport_error"
	}
	if r.Status != status {
		return "invariant_audit_filter_status"
	}
	if status != 200 {
		code, field := "invalid_request", ""
		if status == 422 {
			code = "validation_failed"
			field = "network"
			if profile == 4 {
				field = "from"
			}
		}
		if _, exposed := r.Body["items"]; exposed || r.Str("next_cursor") != "" || r.Str("code") != code ||
			r.Body["status"] != float64(status) || (field != "" && stringValue(object(r.Body["errors"]), field) == "") {
			return "invariant_audit_error_contains_results"
		}
		return label
	}
	if !s.checkPage(r, want, next) {
		return "invariant_audit_filter_page"
	}
	return label
}

func (s *complexAuditFilter) checkPage(r *Response, want []string, next bool) bool {
	items, ok := r.Body["items"].([]any)
	if !ok || len(items) != len(want) || (r.Str("next_cursor") != "") != next {
		return false
	}
	for i, item := range items {
		m := object(item)
		ev, exists := s.owned[want[i]]
		at, err := time.Parse(time.RFC3339Nano, stringValue(m, "occurred_at"))
		if !exists || stringValue(m, "id") != want[i] || stringValue(m, "type") != ev.typ || stringValue(m, "org_id") != ev.org ||
			stringValue(m, "realm_id") != s.realmID || stringValue(m, "ip_context") != s.sourceContext ||
			stringValue(m, "outcome") != ev.outcome || stringValue(m, "source") != "application" || stringValue(m, "reporting_service") != ev.client ||
			stringValue(m, "client_id") != ev.client || stringValue(m, "request_id") != ev.request || stringValue(m, "category") != "application" ||
			stringValue(object(m["actor"]), "id") != ev.actor || stringValue(object(m["subject"]), "id") != ev.subject ||
			stringValue(object(m["actor"]), "type") != "service_principal" || stringValue(object(m["subject"]), "type") != "service_principal" ||
			m["schema_version"] != float64(1) || object(m["metadata"])["benchmark_ordinal"] != float64(ev.ordinal) || err != nil || !at.Equal(ev.at) {
			return false
		}
	}
	return true
}

func (s *complexAuditFilter) Close(context.Context, *Env) error {
	s.owned, s.matches, s.query = nil, nil, nil
	s.cursor, s.network, s.realmID, s.sourceContext = "", "", "", ""
	return nil
}
