package bench

import (
	"context"
	"fmt"
	mrand "math/rand/v2"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const scimErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"

// complexFilter measures SCIM's scan, expression and connector bounds
// (NFR-006). Fixtures use only public APIs and one unchanged-budget connector.
type complexFilter struct {
	groups          bool
	token           string
	owned           map[string]filterSubject
	memberNames     map[string]string
	memberIDs       []string
	count           int
	next            atomic.Uint64
	preparedSeconds float64
}
type filterSubject struct {
	username string
	active   bool
	version  string
	location string
	members  []string
}

func (s *complexFilter) Name() string {
	if s.groups {
		return "complex-group-filter"
	}
	return "complex-filter"
}
func (*complexFilter) Adversarial() bool { return true }
func (s *complexFilter) Notes() []string {
	if s.groups {
		return []string{fmt.Sprintf("one additional isolated connector with %d owned Groups, matching seed.spec.organizations, and %d owned Users matching seed.spec.large_group_members; one Group has every owned member and each other Group has one; public-API setup took %.3fs and is unmeasured", s.count, len(s.memberIDs), s.preparedSeconds),
			"fixture writes start at least 65ms apart under the unchanged 1200/minute connector budget; preparation consumes that budget without a reset or raised limit",
			"64-node filters require member presence and the exact hit/miss display-name prefix; alternate 65-node and 1025-byte refusals; pages must retain exact totals, owned data, ETags and members, including when members are excluded",
			"unpaced cohosted measurement includes budget refusals and is not successful-query capacity; connector and fixture authority stay private and are cleared on close"}
	}
	return []string{fmt.Sprintf("one additional isolated connector with %d additional managed users, matching seed.spec.users; public-API setup took %.3fs and is unmeasured", s.count, s.preparedSeconds),
		"fixture writes start at least 65ms apart under the unchanged 1200/minute connector budget; preparation consumes that budget, and no counter is reset or raised before measurement",
		"operations alternate 64-node full-scan true/false filters, a 65-node filter and a 1025-byte filter; valid results must prove exact counts, bounded pages and owned IDs; refusals must be SCIM errors with retry guidance",
		"measurement is unpaced at the requested concurrency on one connector; aggregate latency includes budget refusals and is not successful query capacity; connector authority remains in memory and is cleared at close"}
}

func (s *complexFilter) Prepare(ctx context.Context, e *Env) error {
	if e.Client == nil || e.Admin == nil || e.Seed == nil || e.Seed.RoleID == "" {
		return fmt.Errorf("%s requires an MFA admin token, a fresh seed and an organization role", s.Name())
	}
	s.count = e.Seed.Spec.Users
	if s.groups {
		s.count = e.Seed.Spec.Organizations
		if s.count < 2 || s.count > 20000 || e.Seed.Spec.GroupMembers < 1 || e.Seed.Spec.GroupMembers > 20000 {
			return fmt.Errorf("complex-group-filter requires 2..20000 organizations and 1..20000 large-group members in the seed")
		}
	} else if s.count < 2 || s.count > 20000 {
		return fmt.Errorf("complex-filter requires an MFA admin token and a fresh seed with 2..20000 users and an organization role")
	}
	started := time.Now()
	prefix, err := runPrefix(e.Seed, s.Name())
	if err != nil {
		return err
	}
	r, err := e.Client.API(ctx, "POST", "/organizations/"+e.Seed.LargeOrgID+"/provisioning-connectors", e.adminToken(ctx), map[string]any{"name": prefix, "role_ceiling_ids": []string{e.Seed.RoleID}, "default_role_id": e.Seed.RoleID})
	if out := expectedOutcome(r, err, 201); out != "ok" {
		return fmt.Errorf("filter connector: %s", out)
	}
	s.token = r.Str("token")
	if s.token == "" {
		return fmt.Errorf("filter connector lacks authority")
	}
	s.owned = make(map[string]filterSubject, s.count)
	s.next.Store(0)
	next := time.Now()
	write := func(path string, doc map[string]any) (*Response, error) {
		if wait := time.Until(next); wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		next = time.Now().Add(65 * time.Millisecond)
		return e.Client.Do(ctx, Request{Method: "POST", Path: path, Token: s.token, JSON: doc})
	}
	if s.groups {
		s.memberNames = make(map[string]string, e.Seed.Spec.GroupMembers)
		s.memberIDs = nil
		for i := range e.Seed.Spec.GroupMembers {
			name, display := fmt.Sprintf("%s-member-%d", prefix, i), fmt.Sprintf("Group filter member %d", i)
			r, err := write("/api/v1/realms/"+e.Client.Realm+"/scim/v2/Users", map[string]any{
				"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": name, "externalId": name, "displayName": display, "active": true})
			if out := expectedOutcome(r, err, 201); out != "ok" {
				return fmt.Errorf("group filter member %d: %s", i, out)
			}
			id := r.Str("id")
			if id == "" || r.Str("userName") != name || r.Str("displayName") != display || r.Body["active"] != true {
				return fmt.Errorf("group filter member does not match its owned identity")
			}
			if _, exists := s.memberNames[id]; exists {
				return fmt.Errorf("group filter reused a member identity")
			}
			s.memberNames[id] = display
			s.memberIDs = append(s.memberIDs, id)
		}
	}
	for i := 0; i < s.count; i++ {
		name := fmt.Sprintf("%s-u%d", prefix, i)
		active := i%2 == 0
		doc := map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": name, "externalId": name, "active": active}
		var members []string
		if s.groups {
			tag := "miss."
			if active {
				tag = "hit."
			}
			name = tag + name
			members = []string{s.memberIDs[i%len(s.memberIDs)]}
			if i == 0 {
				members = append([]string(nil), s.memberIDs...)
			}
			values := make([]map[string]any, len(members))
			for j, id := range members {
				values[j] = map[string]any{"value": id}
			}
			doc = map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"}, "displayName": name, "externalId": name, "members": values}
		}
		r, err := write(s.path(e), doc)
		if out := expectedOutcome(r, err, 201); out != "ok" {
			return fmt.Errorf("filter user %d: %s", i, out)
		}
		id := r.Str("id")
		meta := object(r.Body["meta"])
		version, location := stringValue(meta, "version"), stringValue(meta, "location")
		if id == "" || r.Str("externalId") != name || (!s.groups && (r.Str("userName") != name || r.Body["active"] != active)) ||
			(s.groups && (r.Str("displayName") != name || version == "" || location == "")) {
			return fmt.Errorf("%s fixture %d mismatches owned identity (id_present=%t external_matches=%t username_matches=%t display_matches=%t version_present=%t)",
				s.Name(), i, id != "", r.Str("externalId") == name, r.Str("userName") == name, r.Str("displayName") == name, version != "")
		}
		if _, exists := s.owned[id]; exists {
			return fmt.Errorf("filter fixture reused an identity")
		}
		s.owned[id] = filterSubject{username: name, active: active, members: members, version: version, location: location}
	}
	s.preparedSeconds = time.Since(started).Seconds()
	return nil
}
func (s *complexFilter) path(e *Env) string {
	resource := "Users"
	if s.groups {
		resource = "Groups"
	}
	return "/api/v1/realms/" + e.Client.Realm + "/scim/v2/" + resource
}

func filterExpression(profile int) string {
	if profile == 3 {
		return strings.Repeat(" ", 1025-len("active pr")) + "active pr"
	}
	value := "true"
	if profile == 1 {
		value = "false"
	}
	n := 32
	if profile == 2 {
		n = 33
	}
	clauses := make([]string, n)
	for i := range clauses {
		clauses[i] = "active eq " + value
	}
	expr := strings.Join(clauses, " or ")
	if profile != 2 {
		expr = "(" + expr + ")"
	} // 32 comparisons + 31 ORs + one group = 64 nodes.
	return expr
}

func groupFilterExpression(profile int) string {
	if profile == 3 {
		return strings.Repeat(" ", 1025-len("members pr")) + "members pr"
	}
	n, prefix := 32, "hit."
	if profile == 1 {
		prefix = "miss."
	}
	if profile == 2 {
		n = 33
	}
	clauses := make([]string, n)
	for i := range clauses {
		clauses[i] = "members pr"
	}
	clauses[n-1] = "displayName sw \"" + prefix + "\""
	expr := strings.Join(clauses, " and ")
	if profile != 2 {
		expr = "(" + expr + ")"
	}
	return expr
}

func (s *complexFilter) Op(ctx context.Context, e *Env, _ int, rnd *mrand.Rand) string {
	if s.token == "" || len(s.owned) != s.count || s.count < 2 {
		return "setup_missing_filter_fixture"
	}
	profile := int((s.next.Add(1) - 1) % 4)
	start := 1
	if rnd.IntN(2) == 1 {
		start = 201
	}
	q := url.Values{"filter": {filterExpression(profile)}, "count": {"1000"}, "startIndex": {strconv.Itoa(start)}}
	excludeMembers := false
	if s.groups {
		q.Set("filter", groupFilterExpression(profile))
		excludeMembers = rnd.IntN(2) == 0
		if excludeMembers {
			q.Set("excludedAttributes", "members")
		}
	}
	r, err := e.Client.Do(ctx, Request{Method: "GET", Path: s.path(e) + "?" + q.Encode(), Token: s.token})
	if err != nil || r == nil {
		return "transport_error"
	}
	if r.Status == 429 {
		retry, err := strconv.Atoi(r.Header.Get("Retry-After"))
		if !filterError(r, "429", "") || err != nil || retry <= 0 {
			return "invariant_invalid_budget_refusal"
		}
		return "rate_limited"
	}
	if profile >= 2 {
		if r.Status != 400 || !filterError(r, "400", "invalidFilter") {
			return "invariant_filter_bound_not_enforced"
		}
		if profile == 2 {
			return "invalid_filter_nodes"
		}
		return "invalid_filter_bytes"
	}
	if r.Status != 200 {
		return r.Outcome()
	}
	active := profile == 0
	total := s.count / 2
	if active {
		total = (s.count + 1) / 2
	}
	items, ok := r.Body["Resources"].([]any)
	schemas, schemaOK := r.Body["schemas"].([]any)
	expected := min(max(total-start+1, 0), 200)
	if !ok || !schemaOK || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" || r.Body["totalResults"] != float64(total) || r.Body["startIndex"] != float64(start) || r.Body["itemsPerPage"] != float64(expected) || len(items) != expected {
		return "invariant_incomplete_filter_result"
	}
	seen := map[string]bool{}
	for _, item := range items {
		m := object(item)
		id := stringValue(m, "id")
		known, exists := s.owned[id]
		if !exists || seen[id] || known.active != active || m["externalId"] != known.username ||
			(!s.groups && (m["active"] != active || m["userName"] != known.username)) ||
			(s.groups && (m["displayName"] != known.username || stringValue(object(m["meta"]), "version") != known.version || !s.checkGroupMembers(m, known, excludeMembers))) {
			return "invariant_foreign_or_wrong_filter_result"
		}
		seen[id] = true
	}
	if active {
		return "bounded_true"
	}
	return "bounded_false"
}
func filterError(r *Response, status, typ string) bool {
	schemas, ok := r.Body["schemas"].([]any)
	return ok && len(schemas) == 1 && schemas[0] == scimErrorSchema && r.Str("status") == status && r.Str("scimType") == typ
}
func (s *complexFilter) Observations() map[string]any {
	if s.groups {
		return map[string]any{"subject_connectors": 1, "managed_groups": s.count, "fixture_groups_confirmed": len(s.owned), "managed_member_users": len(s.memberIDs),
			"large_group_members": len(s.memberIDs), "total_group_member_links": len(s.memberIDs) + s.count - 1, "prepared_seconds": s.preparedSeconds,
			"connector_budget_per_minute": 1200, "valid_filter_nodes": 64, "overflow_filter_nodes": 65, "overflow_filter_bytes": 1025,
			"requested_page_size": 1000, "required_max_page_size": 200, "scope": "one connector; additional owned Groups and Users; no connector authority or fixture IDs published"}
	}
	return map[string]any{"subject_connectors": 1, "managed_users": s.count, "fixture_users_confirmed": len(s.owned), "prepared_seconds": s.preparedSeconds, "connector_budget_per_minute": 1200, "valid_filter_nodes": 64, "overflow_filter_nodes": 65, "overflow_filter_bytes": 1025, "requested_page_size": 1000, "required_max_page_size": 200, "scope": "one connector; additional owned Users; no connector tokens or fixture IDs published"}
}
func (s *complexFilter) Close(context.Context, *Env) error {
	s.token = ""
	clear(s.owned)
	s.owned = nil
	clear(s.memberNames)
	s.memberNames = nil
	clear(s.memberIDs)
	s.memberIDs = nil
	return nil
}

func (s *complexFilter) checkGroupMembers(resource map[string]any, known filterSubject, excluded bool) bool {
	schemas, ok := resource["schemas"].([]any)
	meta := object(resource["meta"])
	id := stringValue(resource, "id")
	if !ok || len(schemas) != 1 || schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:Group" ||
		stringValue(meta, "resourceType") != "Group" || stringValue(meta, "location") != known.location ||
		!strings.HasSuffix(known.location, "/Groups/"+id) {
		return false
	}
	raw, present := resource["members"]
	if excluded {
		return !present
	}
	values, ok := raw.([]any)
	if !ok || len(values) != len(known.members) {
		return false
	}
	expected := make(map[string]bool, len(known.members))
	for _, id := range known.members {
		expected[id] = true
	}
	for _, v := range values {
		m := object(v)
		id := stringValue(m, "value")
		display, owned := s.memberNames[id]
		base := strings.TrimSuffix(known.location, "/Groups/"+stringValue(resource, "id"))
		if !owned || !expected[id] || stringValue(m, "display") != display || stringValue(m, "$ref") != base+"/Users/"+id {
			return false
		}
		delete(expected, id)
	}
	return len(expected) == 0
}
