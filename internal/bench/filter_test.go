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

func TestBenchFilterExpressionsReachDeclaredBounds(t *testing.T) {
	for i := 0; i < 4; i++ {
		expr := filterExpression(i)
		f, err := provisioning.ParseFilter(expr)
		if i >= 2 {
			if err == nil {
				t.Fatalf("overflow %d accepted", i)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, active := range []bool{true, false} {
			if f.Match(map[string]any{"active": active}) != (active == (i == 0)) {
				t.Fatal("wrong boundary-filter predicate")
			}
		}
		// Removing only the outer group goes from 64 to 63 nodes; adding
		// one group to the accepted expression crosses the 64-node bound.
		if _, err := provisioning.ParseFilter("(" + expr + ")"); err == nil {
			t.Fatal("boundary expression is not 64 nodes")
		}
	}
	if len(filterExpression(3)) != 1025 {
		t.Fatal("wrong byte boundary")
	}
}

// NFR-006, NFR-008: errors, partial pages and connector budget refusals
// cannot masquerade as completed bounded searches or rejected overflows.
func TestBenchComplexFilterChecksExactResultsAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		profile    int
	}{
		{"valid true", "bounded_true", 0}, {"valid false", "bounded_false", 1}, {"empty second page", "bounded_true", 0},
		{"partial total", "invariant_incomplete_filter_result", 0}, {"wrong page", "invariant_incomplete_filter_result", 0},
		{"foreign ID", "invariant_foreign_or_wrong_filter_result", 0},
		{"nodes rejected", "invalid_filter_nodes", 2}, {"bytes rejected", "invalid_filter_bytes", 3},
		{"overflow accepted", "invariant_filter_bound_not_enforced", 2},
		{"wrong error type", "invariant_filter_bound_not_enforced", 2},
		{"budget", "rate_limited", 0}, {"no retry", "invariant_invalid_budget_refusal", 0},
		{"database error", "http_500", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer private-connector" {
					t.Error("missing connector authority")
				}
				q := r.URL.Query()
				if q.Get("filter") != filterExpression(tc.profile) || q.Get("count") != "1000" {
					t.Error("wrong measured filter")
				}
				status := 200
				body := map[string]any{"schemas": []string{provisioning.SchemaList}, "Resources": []any{}, "totalResults": 1, "startIndex": 201, "itemsPerPage": 0}
				if q.Get("startIndex") == "1" {
					body["startIndex"] = 1
					body["itemsPerPage"] = 1
					id, name, active := "true-id", "true-name", true
					if tc.profile == 1 {
						id, name, active = "false-id", "false-name", false
					}
					body["Resources"] = []any{map[string]any{"id": id, "userName": name, "externalId": name, "active": active}}
				}
				switch tc.name {
				case "partial total":
					body["totalResults"] = 0
				case "wrong page":
					body["itemsPerPage"] = 200
				case "foreign ID":
					body["Resources"] = []any{map[string]any{"id": "foreign"}}
					body["startIndex"] = 1
					body["itemsPerPage"] = 1
				case "nodes rejected", "bytes rejected", "wrong error type":
					status = 400
					body = map[string]any{"schemas": []string{provisioning.SchemaError}, "status": "400", "scimType": "invalidFilter"}
					if tc.name == "wrong error type" {
						body["scimType"] = "invalidSyntax"
					}
				case "budget", "no retry":
					status = 429
					body = map[string]any{"schemas": []string{provisioning.SchemaError}, "status": "429"}
					if tc.name == "budget" {
						w.Header().Set("Retry-After", "59")
					}
				case "database error":
					status = 500
					body = map[string]any{"schemas": []string{provisioning.SchemaError}, "status": "500"}
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			s := &complexFilter{token: "private-connector", count: 2, owned: map[string]filterSubject{"true-id": {username: "true-name", active: true}, "false-id": {username: "false-name", active: false}}}
			s.next.Store(uint64(tc.profile))
			e := &Env{Client: NewClient(srv.URL, "bench", 1)}
			pageDraw := 0
			if tc.name == "empty second page" {
				pageDraw = 1
			}
			seed := uint64(1)
			for rand.New(rand.NewPCG(seed, 2)).IntN(2) != pageDraw {
				seed++
			}
			if got := s.Op(context.Background(), e, 0, rand.New(rand.NewPCG(seed, 2))); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			published, _ := json.Marshal(map[string]any{"notes": s.Notes(), "observations": s.Observations()})
			if strings.Contains(string(published), s.token) || strings.Contains(string(published), "true-id") {
				t.Fatal("private fixture authority published")
			}
			_ = s.Close(context.Background(), e)
			if s.token != "" || len(s.owned) != 0 {
				t.Fatal("private state retained")
			}
		})
	}
}
