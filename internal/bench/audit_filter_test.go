package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func auditScenarioFixture() *complexAuditFilter {
	s := &complexAuditFilter{owned: map[string]auditFilterEvent{}, query: url.Values{"limit": {"1000"}, "type_prefix": {"app.owned.hit_"}, "category": {"application"}},
		cursor: "private-position", realmID: "owned-realm", sourceContext: "127.0.0.0/24"}
	for i := range 251 {
		id := fmt.Sprintf("owned-%03d", i)
		s.matches = append(s.matches, id)
		s.owned[id] = auditFilterEvent{typ: "app.owned.hit_kind", org: "owned-org", outcome: "success", client: "owned-reporter", actor: "owned-service", subject: "owned-subject", request: "owned-request",
			at: time.Unix(1700000000, 0).UTC(), ordinal: i}
	}
	return s
}

func auditScenarioPage(s *complexAuditFilter, ids []string, next bool) map[string]any {
	items := []any{}
	for _, id := range ids {
		ev := s.owned[id]
		items = append(items, map[string]any{"id": id, "schema_version": 1, "realm_id": s.realmID, "org_id": ev.org, "type": ev.typ, "outcome": ev.outcome,
			"source": "application", "category": "application", "reporting_service": ev.client, "client_id": ev.client, "request_id": ev.request,
			"ip_context": s.sourceContext, "occurred_at": ev.at, "actor": map[string]any{"type": "service_principal", "id": ev.actor},
			"subject": map[string]any{"type": "service_principal", "id": ev.subject}, "metadata": map[string]any{"benchmark_ordinal": ev.ordinal}})
	}
	cursor := ""
	if next {
		cursor = "private-next-position"
	}
	return map[string]any{"items": items, "next_cursor": cursor}
}

// NFR-008: a successful HTTP status cannot hide partial/foreign/wrongly
// ordered evidence or a falsely classified input/cursor refusal.
func TestBenchAuditFilterValidatesPagesAndRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		profile    int
	}{
		{"match", "compound_match", 0}, {"empty", "compound_empty", 1}, {"literal", "literal_prefix_empty", 2},
		{"network", "invalid_network", 3}, {"time", "invalid_time", 4}, {"scope", "cursor_scope_rejected", 5}, {"resumed", "cursor_page", 6},
		{"partial", "invariant_audit_filter_page", 0}, {"duplicate", "invariant_audit_filter_page", 0}, {"wrong realm", "invariant_audit_filter_page", 0},
		{"wrong org", "invariant_audit_filter_page", 0}, {"wrong source", "invariant_audit_filter_page", 0}, {"wrong ordinal", "invariant_audit_filter_page", 0},
		{"missing cursor", "invariant_audit_filter_page", 0}, {"extra empty cursor", "invariant_audit_filter_page", 1},
		{"wrong code", "invariant_audit_error_contains_results", 3}, {"missing field", "invariant_audit_error_contains_results", 4},
		{"error results", "invariant_audit_error_contains_results", 5}, {"accepted cursor", "invariant_audit_filter_status", 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := auditScenarioFixture()
			s.next.Store(uint64(tc.profile))
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("limit") != "1000" || r.Header.Get("Authorization") != "Bearer private-admin" {
					t.Error("request lost page/authority contract")
				}
				status := 200
				body := auditScenarioPage(s, s.matches[:200], true)
				switch tc.profile {
				case 1, 2:
					body = auditScenarioPage(s, nil, false)
				case 3, 4:
					status = 422
					field := "network"
					if tc.profile == 4 {
						field = "from"
					}
					body = map[string]any{"code": "validation_failed", "status": status, "errors": map[string]any{field: "invalid input"}}
				case 5:
					status = 400
					body = map[string]any{"code": "invalid_request", "status": status, "detail": "invalid cursor"}
				case 6:
					if r.URL.Query().Get("cursor") != s.cursor {
						t.Error("resumed request lost cursor")
					}
					body = auditScenarioPage(s, s.matches[1:201], true)
				}
				switch tc.name {
				case "partial":
					body["items"] = body["items"].([]any)[:199]
				case "duplicate":
					body["items"].([]any)[1] = body["items"].([]any)[0]
				case "wrong realm", "wrong org", "wrong source", "wrong ordinal":
					first := object(body["items"].([]any)[0])
					switch tc.name {
					case "wrong realm":
						first["realm_id"] = "foreign"
					case "wrong org":
						first["org_id"] = "foreign"
					case "wrong source":
						first["source"] = "server"
					case "wrong ordinal":
						object(first["metadata"])["benchmark_ordinal"] = 9999
					}
				case "missing cursor":
					body["next_cursor"] = ""
				case "extra empty cursor":
					body["next_cursor"] = "unexpected-position"
				case "wrong code":
					body["code"] = "forbidden"
				case "missing field":
					delete(body, "errors")
				case "error results":
					body["items"] = []any{}
				case "accepted cursor":
					status = 200
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(body)
			}))
			defer srv.Close()
			e := &Env{Client: NewClient(srv.URL, "bench", 1), Admin: StaticToken("private-admin")}
			if got := s.Op(context.Background(), e, 0, rand.New(rand.NewPCG(1, 1))); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
			if err := s.Close(context.Background(), e); err != nil || s.owned != nil || s.matches != nil || s.cursor != "" || s.realmID != "" {
				t.Fatal("private audit fixture data retained after close")
			}
		})
	}
}
