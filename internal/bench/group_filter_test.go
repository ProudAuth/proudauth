package bench

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/proudbase/proudauth/internal/provisioning"
)

func TestBenchGroupFilterExpressionsReachDeclaredBounds(t *testing.T) {
	for profile := range 4 {
		expr := groupFilterExpression(profile)
		f, err := provisioning.ParseFilter(expr)
		if profile >= 2 {
			if err == nil {
				t.Fatal("group filter overflow accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{"hit.", "miss."} {
			for _, members := range []any{[]any{}, []any{map[string]any{"value": "owned"}}} {
				want := prefix == []string{"hit.", "miss."}[profile] && len(members.([]any)) > 0
				if f.Match(map[string]any{"displayName": prefix + "group", "members": members}) != want {
					t.Fatal("group filter lost its member/name predicate")
				}
			}
		}
		if _, err := provisioning.ParseFilter("(" + expr + ")"); err == nil {
			t.Fatal("group filter is not at the 64-node boundary")
		}
	}
	if len(groupFilterExpression(3)) != 1025 {
		t.Fatal("wrong group-filter byte boundary")
	}
}

func TestBenchGroupFilterPreparationReadsNestedMetadata(t *testing.T) {
	var base string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		if strings.HasSuffix(r.URL.Path, "/provisioning-connectors") {
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "private-group-connector"})
			return
		}
		var doc map[string]any
		if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
			t.Error(err)
		}
		if strings.HasSuffix(r.URL.Path, "/Users") {
			doc["id"] = "private-member"
		} else {
			name := stringValue(doc, "displayName")
			doc["id"] = name
			doc["meta"] = map[string]any{"version": "owned-version", "resourceType": "Group", "location": base + "/Groups/" + name}
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer srv.Close()
	base = srv.URL
	s := &complexFilter{groups: true}
	e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("private-admin"),
		Seed: &SeedData{Prefix: "b25-", RoleID: "role", LargeOrgID: "org", Spec: SeedSpec{Organizations: 2, GroupMembers: 1}}}
	if err := s.Prepare(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if len(s.owned) != 2 || len(s.memberIDs) != 1 {
		t.Fatal("Group preparation incomplete")
	}
	for _, group := range s.owned {
		if group.version != "owned-version" || group.location == "" {
			t.Fatal("nested Group metadata was not retained")
		}
	}
	_ = s.Close(context.Background(), e)
}

// NFR-006, NFR-008: Group fixtures must verify complete pages, member values,
// projection, schemas, references and ETags instead of accepting any 200/429.
func TestBenchComplexGroupFilterChecksOwnedResultsAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		profile    int
	}{
		{"valid true", "bounded_true", 0}, {"valid false", "bounded_false", 1},
		{"excluded", "bounded_true", 0}, {"empty page", "bounded_true", 0},
		{"partial total", "invariant_incomplete_filter_result", 0}, {"foreign group", "invariant_foreign_or_wrong_filter_result", 0},
		{"wrong schema", "invariant_foreign_or_wrong_filter_result", 0}, {"wrong version", "invariant_foreign_or_wrong_filter_result", 0},
		{"foreign member", "invariant_foreign_or_wrong_filter_result", 0}, {"duplicate member", "invariant_foreign_or_wrong_filter_result", 0},
		{"wrong reference", "invariant_foreign_or_wrong_filter_result", 0}, {"wrong display", "invariant_foreign_or_wrong_filter_result", 0},
		{"member omitted", "invariant_foreign_or_wrong_filter_result", 0}, {"projection leaked", "invariant_foreign_or_wrong_filter_result", 0},
		{"nodes rejected", "invalid_filter_nodes", 2}, {"bytes rejected", "invalid_filter_bytes", 3},
		{"overflow accepted", "invariant_filter_bound_not_enforced", 2}, {"wrong refusal", "invariant_filter_bound_not_enforced", 2},
		{"budget", "rate_limited", 0}, {"no retry", "invariant_invalid_budget_refusal", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const base = "http://owned.test/scim/v2"
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				q := r.URL.Query()
				if r.URL.Path != "/api/v1/realms/bench/scim/v2/Groups" || r.Header.Get("Authorization") != "Bearer private-group-connector" || q.Get("filter") != groupFilterExpression(tc.profile) {
					t.Error("wrong measured Group request")
				}
				excluded := q.Get("excludedAttributes") == "members"
				id, name := "hit-id", "hit.private-group"
				if tc.profile == 1 {
					id, name = "miss-id", "miss.private-group"
				}
				members := []any{map[string]any{"value": "private-user-1", "display": "One", "$ref": base + "/Users/private-user-1"}}
				if tc.profile == 0 {
					members = append(members, map[string]any{"value": "private-user-2", "display": "Two", "$ref": base + "/Users/private-user-2"})
				}
				meta := map[string]any{"resourceType": "Group", "version": "owned-version", "location": base + "/Groups/" + id}
				item := map[string]any{"schemas": []string{provisioning.SchemaGroup}, "id": id, "displayName": name, "externalId": name, "meta": meta}
				if !excluded {
					item["members"] = members
				}
				page, start := []any{item}, 1
				if q.Get("startIndex") == "201" {
					page, start = []any{}, 201
				}
				body := map[string]any{"schemas": []string{provisioning.SchemaList}, "Resources": page, "totalResults": 1, "startIndex": start, "itemsPerPage": len(page)}
				status := 200
				switch tc.name {
				case "partial total":
					body["totalResults"] = 0
				case "foreign group":
					item["id"] = "foreign-group"
				case "wrong schema":
					item["schemas"] = []string{provisioning.SchemaUser}
				case "wrong version":
					meta["version"] = "changed-version"
				case "foreign member":
					members[0].(map[string]any)["value"] = "foreign-user"
				case "duplicate member":
					members[1] = members[0]
				case "wrong reference":
					members[0].(map[string]any)["$ref"] = "http://foreign.test/Users/private-user-1"
				case "wrong display":
					members[0].(map[string]any)["display"] = "Changed"
				case "member omitted":
					delete(item, "members")
				case "projection leaked":
					item["members"] = members
				case "nodes rejected", "bytes rejected", "wrong refusal":
					status = 400
					body = map[string]any{"schemas": []string{provisioning.SchemaError}, "status": "400", "scimType": "invalidFilter"}
					if tc.name == "wrong refusal" {
						body["scimType"] = "tooMany"
					}
				case "budget", "no retry":
					status = 429
					body = map[string]any{"schemas": []string{provisioning.SchemaError}, "status": "429"}
					if tc.name == "budget" {
						w.Header().Set("Retry-After", "60")
					}
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			s := &complexFilter{groups: true, token: "private-group-connector", count: 2,
				memberNames: map[string]string{"private-user-1": "One", "private-user-2": "Two"}, memberIDs: []string{"private-user-1", "private-user-2"},
				owned: map[string]filterSubject{
					"hit-id":  {username: "hit.private-group", active: true, version: "owned-version", location: base + "/Groups/hit-id", members: []string{"private-user-1", "private-user-2"}},
					"miss-id": {username: "miss.private-group", active: false, version: "owned-version", location: base + "/Groups/miss-id", members: []string{"private-user-1"}},
				}}
			s.next.Store(uint64(tc.profile))
			second, excluded := 0, 1
			if tc.name == "empty page" {
				second = 1
			}
			if tc.name == "excluded" || tc.name == "projection leaked" {
				excluded = 0
			}
			seed := uint64(1)
			for {
				rnd := rand.New(rand.NewPCG(seed, 2))
				if rnd.IntN(2) == second && rnd.IntN(2) == excluded {
					break
				}
				seed++
			}
			e := &Env{Client: NewClient(srv.URL, "bench", 1)}
			if got := s.Op(context.Background(), e, 0, rand.New(rand.NewPCG(seed, 2))); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			published, _ := json.Marshal(map[string]any{"notes": s.Notes(), "observations": s.Observations()})
			if strings.Contains(string(published), s.token) || strings.Contains(string(published), "private-user-1") || strings.Contains(string(published), "hit-id") {
				t.Fatal("Group fixture authority published")
			}
			_ = s.Close(context.Background(), e)
			if s.token != "" || len(s.owned) != 0 || len(s.memberIDs) != 0 || len(s.memberNames) != 0 {
				t.Fatal("Group fixture authority retained")
			}
		})
	}
}
