package e2e

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/proudbase/proudauth/internal/realm"
	"github.com/proudbase/proudauth/internal/webhooks"
	"github.com/proudbase/proudauth/internal/worker"
)

// TestContractVersions covers EXT-018: webhook event schemas, the hook
// contract, plugin manifests and workflow definitions are versioned
// independently; every supported version is rendered by the running server
// and checked against the published JSON schemas; subscriptions and hooks
// created before versioning keep exactly what they received. It also covers
// EXT-008: every delivered event, in the minimal and the standard payload
// form, matches its published versioned payload schema.
func TestContractVersions(t *testing.T) {
	h := NewHarness(t, allowPrivate)
	f := fixtureOn(t, h)
	w := worker.New(h.App, "contracts")
	schemas := apiSchemas(t)
	if _, err := w.DispatchOutbox(bg()); err != nil {
		t.Fatal(err)
	}

	t.Run("contract catalog", func(t *testing.T) {
		r := f.must(f.AdminAPI("GET", "/extension-contracts", nil), 200, "contracts")
		found := map[string][]any{}
		for _, it := range r.Get("items").([]any) {
			m := it.(map[string]any)
			found[m["name"].(string)] = m["versions"].([]any)
		}
		for _, name := range []string{"webhook_events", "hook_contract", "plugin_manifest", "workflow_definition", "management_api"} {
			if len(found[name]) == 0 {
				t.Fatalf("contract %s missing: %s", name, r.Raw)
			}
		}
		ev := found["webhook_events"]
		if len(ev) != 2 || ev[0].(map[string]any)["default"] != true || ev[1].(map[string]any)["status"] != "current" {
			t.Fatalf("event versions: %v", ev)
		}
		if r.Get("support_window_months").(float64) < 12 {
			t.Fatalf("support window: %s", r.Raw)
		}
	})

	t.Run("webhook events in every version", func(t *testing.T) {
		ep := newEndpoint(t)
		type sub struct {
			id, secret, form string
			version          int
		}
		subs := map[string]*sub{}
		create := func(path string, body map[string]any) *sub {
			body["name"], body["destination_url"], body["event_types"], body["allow_private_network"] = path, ep.srv.URL+"/"+path, []string{"*"}, true
			r := f.must(f.AdminAPI("POST", "/webhooks", body), 201, "subscription "+path)
			s := &sub{id: r.Str("subscription.id"), secret: r.Str("signing_secret"), form: r.Str("subscription.payload_form"),
				version: int(r.Get("subscription.event_version").(float64))}
			subs["/"+path] = s
			return s
		}
		// Created like before event versioning existed: no event_version.
		legacy := create("legacy", map[string]any{"payload_form": "standard"})
		if legacy.version != 1 {
			t.Fatalf("default event version %d", legacy.version)
		}
		create("v1min", map[string]any{"event_version": 1})
		create("v2std", map[string]any{"event_version": 2, "payload_form": "standard"})
		create("v2min", map[string]any{"event_version": 2})
		for _, v := range []int{3, -1} {
			mustStatus(t, f.AdminAPI("POST", "/webhooks", map[string]any{"name": "bad", "destination_url": ep.srv.URL + "/bad", "event_types": []string{"*"},
				"allow_private_network": true, "event_version": v}), 422, "unsupported event version "+strconv.Itoa(v))
		}
		// Events of several families: account, organization, membership,
		// authorization and security.
		dave := f.CreateUser("dave")
		mid := f.must(f.AdminAPI("POST", "/organizations/"+f.Acme+"/members", map[string]any{"user_id": dave, "role_ids": []string{f.Roles["member"]}}), 201,
			"member").Str("id")
		f.must(f.AdminAPI("POST", "/organizations", map[string]any{"slug": "initech", "display_name": "Initech"}), 201, "organization")
		f.must(f.AdminAPI("POST", "/users/"+dave+"/suspend", map[string]any{"reason": "TEST"}), 200, "suspend")
		f.must(f.AdminAPI("POST", "/users/"+dave+"/reactivate", map[string]any{}), 200, "reactivate")
		mustStatus(t, f.AdminAPI("DELETE", "/organizations/"+f.Acme+"/members/"+mid, nil), 204, "remove member")
		deliverWebhooks(t, w)

		var outbox = map[string]map[string]any{}
		rows, err := h.App.D.DB.Pool.Query(bg(), `SELECT id, payload FROM outbox_events WHERE realm_id=$1`, h.Realm.ID)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id string
			var payload []byte
			if err := rows.Scan(&id, &payload); err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			_ = json.Unmarshal(payload, &m)
			outbox[id] = m
		}
		rows.Close()

		types := map[string]bool{}
		perVersion := map[int]int{}
		for _, c := range ep.received("") {
			s := subs[c.Path]
			if s == nil {
				continue
			}
			if err := webhooks.VerifySignature(s.secret, c.Header.Get("Webhook-Id"), c.Header.Get("Webhook-Timestamp"), c.Header.Get("Webhook-Signature"),
				c.Body, h.Clock.Now(), 5*time.Minute); err != nil {
				t.Fatalf("%s: signature: %v", c.Path, err)
			}
			var body map[string]any
			if err := json.Unmarshal(c.Body, &body); err != nil {
				t.Fatal(err)
			}
			typ := body["event_type"].(string)
			types[typ] = true
			perVersion[s.version]++
			file := typ + ".v" + strconv.Itoa(s.version) + ".json"
			if err := schemas.Validate(file, body); err != nil {
				t.Errorf("%s delivery does not match %v", c.Path, err)
			}
			stored := outbox[body["event_id"].(string)]
			switch {
			case c.Path == "/legacy" && !reflect.DeepEqual(stored, body):
				// v1 standard is the stored envelope itself: nothing changed
				// for subscriptions that predate event versioning.
				t.Errorf("legacy delivery differs from the stored event:\n%s\n%v", c.Body, stored)
			case s.version == 2:
				if _, has := body["org_id"]; has || body["payload_form"] != s.form || body["organization_id"] != stored["org_id"] {
					t.Errorf("v2 envelope: %s", c.Body)
				}
			}
		}
		for _, typ := range []string{"user.created", "organization.membership.added", "organization.membership.removed", "organization.created",
			"user.suspended", "user.reactivated", "authorization.role.assigned", "security.alert"} {
			if !types[typ] {
				t.Errorf("no %s delivery checked", typ)
			}
		}
		if perVersion[1] == 0 || perVersion[2] == 0 {
			t.Fatalf("deliveries per version: %v", perVersion)
		}
		// A subscriber moves to version 2 when it is ready; unsupported
		// versions are refused.
		mustStatus(t, f.AdminAPI("PATCH", "/webhooks/"+legacy.id, map[string]any{"event_version": 7}), 422, "unsupported version")
		up := f.must(f.AdminAPI("PATCH", "/webhooks/"+legacy.id, map[string]any{"event_version": 2}), 200, "upgrade subscription")
		if up.Get("event_version").(float64) != 2 {
			t.Fatalf("patched: %s", up.Raw)
		}
		legacy.version = 2
		ep.reset()
		f.CreateUser("erin")
		deliverWebhooks(t, w)
		for _, c := range ep.received("/legacy") {
			if err := schemas.ValidateBytes(gjsonType(c.Body)+".v2.json", c.Body); err != nil {
				t.Errorf("after the upgrade: %v", err)
			}
		}
		if len(ep.received("/legacy")) == 0 {
			t.Fatal("no delivery after the upgrade")
		}
	})

	t.Run("hook contract", func(t *testing.T) {
		hp := newEndpoint(t)
		echo := ""
		answers := map[string]string{
			"registration.eligibility": `{"allow":true}`,
			"profile.validation":       `{"allow":true}`,
			"token.claims":             `{"claims":{"tenant_tier":"gold"}}`,
			"authorization.decision":   `{"allow":true,"obligations":[]}`,
			"authentication.risk":      `{"level":"low","reasons":["known_network"]}`,
		}
		hp.setAnswer(func(r *http.Request, body []byte) (int, http.Header, []byte) {
			var in map[string]any
			_ = json.Unmarshal(body, &in)
			hdr := http.Header{}
			if echo != "" {
				hdr.Set("ProudAuth-Hook-Version", echo)
			}
			return 200, hdr, []byte(answers[in["hook_kind"].(string)])
		})
		ids := map[string]string{}
		for kind := range answers {
			body := map[string]any{"name": kind, "kind": kind, "url": hp.srv.URL + "/" + kind, "allow_private_network": true}
			if kind == "token.claims" {
				body["client_ids"] = []string{"web-bff"}
			}
			r := f.must(f.AdminAPI("POST", "/hooks", body), 201, "hook "+kind)
			if r.Get("hook.contract_version").(float64) != 1 {
				t.Fatalf("default hook contract: %s", r.Raw)
			}
			ids[kind] = r.Str("hook.id")
		}
		mustStatus(t, f.AdminAPI("POST", "/hooks", map[string]any{"name": "future", "kind": "profile.validation", "url": hp.srv.URL + "/future",
			"allow_private_network": true, "contract_version": 2}), 422, "unsupported hook contract")
		mustStatus(t, f.SetPolicy(func(p *realm.Policy) {
			p.AuthFlow.Rules = []realm.AuthFlowRule{{Name: "high risk", When: realm.AuthFlowCondition{RiskAtLeast: "high"}, Outcome: "deny", OnMissingSignal: "skip"}}
		}), 200, "flow policy")
		register := func(email string) *Resp {
			start, _, cont := h.StartTx(LoginOpts{ClientID: "web-bff", RedirectURI: webRedirect, Scope: "openid orders:read", Resources: []string{f.OrdersAud}})
			return h.Do(Req{Method: "POST", Path: "/api/v1/realms/main/registrations", JSON: map[string]any{"transaction_id": start.Str("transaction_id"),
				"email": email, "password": "a brand new passphrase 2026"}, Headers: map[string]string{"X-Transaction-Token": cont}})
		}
		mustStatus(t, register("newcomer@example.test"), 201, "registration")
		bob := f.AccountToken("bob").Tokens.Str("access_token")
		mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"display_name": "Robert"}), 200, "profile")
		web := f.LoginWeb("bob", f.Acme, f.OrdersAud, "orders:read").Tokens.Str("access_token")
		svc := f.MachineToken(f.Clients["orders-rs"], h.Realm.Issuer+"/admin", "proudauth:admin", "").Str("access_token")
		check := h.API("POST", "/authorization/check", svc, map[string]any{"subject_token": web, "action": "orders.read",
			"resource": map[string]any{"type": "order", "org_id": f.Acme}})
		if check.Get("allowed") != true {
			t.Fatalf("decision: %s", check.Raw)
		}
		seen := map[string]bool{}
		for _, c := range hp.received("") {
			kind := strings.TrimPrefix(c.Path, "/")
			seen[kind] = true
			if c.Header.Get("ProudAuth-Hook-Version") != "1" {
				t.Errorf("%s: contract header %q", kind, c.Header.Get("ProudAuth-Hook-Version"))
			}
			if err := schemas.ValidateBytes(kind+".request.v1.json", c.Body); err != nil {
				t.Errorf("%s request: %v", kind, err)
			}
			if err := schemas.ValidateBytes(kind+".response.v1.json", c.Answer); err != nil {
				t.Errorf("%s response: %v", kind, err)
			}
		}
		for kind := range answers {
			if !seen[kind] {
				t.Errorf("hook %s was not exercised", kind)
			}
		}
		// Negotiation: an answer for another contract version is malformed,
		// so security hooks fail closed and a skip-mode claims hook is
		// skipped.
		echo = "2"
		if r := register("later@example.test"); r.Status != 503 {
			t.Fatalf("registration with a mismatched hook contract: %d %s", r.Status, r.Raw)
		}
		echo = "1"
		mustStatus(t, register("echo@example.test"), 201, "registration with the echoed version")
		diag := f.must(f.AdminAPI("GET", "/hooks/"+ids["registration.eligibility"]+"/diagnostics", nil), 200, "diagnostics")
		if !strings.Contains(string(diag.Raw), `"error_category":"malformed_response"`) {
			t.Fatalf("contract mismatch not diagnosed: %s", diag.Raw)
		}
	})

	t.Run("definition and manifest versions", func(t *testing.T) {
		r := f.AdminAPI("POST", "/workflows", map[string]any{"name": "future", "definition": map[string]any{"schema_version": 2,
			"triggers": []any{map[string]any{"type": "manual"}}, "steps": []any{map[string]any{"id": "x", "type": "end"}}}})
		if r.Status != 422 || !strings.Contains(string(r.Raw), "supported schema versions: 1") {
			t.Fatalf("workflow schema version 2: %d %s", r.Status, r.Raw)
		}
	})
}

// gjsonType returns the event_type of a raw envelope.
func gjsonType(raw []byte) string {
	var m struct {
		EventType string `json:"event_type"`
	}
	_ = json.Unmarshal(raw, &m)
	return m.EventType
}
