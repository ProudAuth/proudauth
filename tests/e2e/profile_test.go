package e2e

import (
	"encoding/json"
	"testing"

	"github.com/proudbase/proudauth/internal/identity"
	"github.com/proudbase/proudauth/internal/realm"
)

// TestProfileSchemaAndCompletion covers USR-007 (typed attribute schema with
// editability), REG-007/AUT-018 (progressive profiling as a required action)
// and TEST-013 (self-service cannot introduce undefined attributes).
func TestProfileSchemaAndCompletion(t *testing.T) {
	f := NewFixture(t)
	h := f.H
	setPolicy := func(mut func(*realm.Policy)) *Resp {
		cur := f.must(f.AdminAPI("GET", "/settings", nil), 200, "settings")
		var pol realm.Policy
		_ = json.Unmarshal([]byte(jsonString(cur.Get("policy"))), &pol)
		mut(&pol)
		return h.Do(Req{Method: "PUT", Path: "/api/v1/realms/main/settings", Token: f.AdminToken, JSON: map[string]any{"policy": pol, "reason": "USR-007"},
			Headers: map[string]string{"If-Match": cur.Header.Get("ETag")}})
	}
	// Schema definitions are validated.
	mustStatus(t, setPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{{Name: "Bad Name", Type: "string"}}
	}), 422, "invalid attribute name")
	mustStatus(t, setPolicy(func(p *realm.Policy) { p.Registration.RequiredProfileFields = []string{"undefined"} }), 422, "unknown required field")
	mustStatus(t, setPolicy(func(p *realm.Policy) {
		p.Profile.Attributes = []identity.AttributeDef{
			{Name: "department", Type: "enum", Enum: []string{"sales", "support"}, UserEditable: true},
			{Name: "employee_id", Type: "string", Visibility: "admin"},
			{Name: "risk_score", Type: "number", Visibility: "internal"},
		}
		p.Registration.RequiredProfileFields = []string{"department"}
	}), 200, "schema")
	start, _, cont := h.StartTx(LoginOpts{ClientID: "proudauth-cli", Scope: "proudauth:account", Resources: []string{h.Realm.Issuer + "/account"}})
	tx := start.Str("transaction_id")
	st := h.Drive(tx, cont, &Resp{Status: 200, Body: start.Get("state").(map[string]any)}, LoginOpts{Identifier: "bob@example.test"})
	if !hasAction(st, "complete_profile") {
		t.Fatalf("missing required attribute did not produce complete_profile: %s", st.Raw)
	}
	mustStatus(t, h.Step(tx, cont, "profile", map[string]any{"fields": map[string]any{"department": "legal"}}), 422, "enum enforced")
	mustStatus(t, h.Step(tx, cont, "profile", map[string]any{"fields": map[string]any{"employee_id": "E1"}}), 403, "admin attribute")
	done := h.Step(tx, cont, "profile", map[string]any{"fields": map[string]any{"department": "sales"}})
	mustStatus(t, done, 200, "complete profile")
	if hasAction(done, "complete_profile") {
		t.Fatalf("profile completion did not clear the action: %s", done.Raw)
	}
	bob := f.AccountToken("bob").Tokens.Str("access_token")
	mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"profile": map[string]any{"is_admin": true}}), 422, "undefined attribute")
	mustStatus(t, h.API("PATCH", "/me", bob, map[string]any{"profile": map[string]any{"department": "support"}}), 200, "editable attribute")
	// Visibility on read (USR-002, USR-007): administrators see admin
	// attributes, the user does not; internal ones stay internal. Admin edits
	// are type-checked.
	mustStatus(t, f.AdminAPI("PATCH", "/users/"+f.Users["bob"], map[string]any{"profile": map[string]any{"employee_id": 42}}), 422, "admin edit type-checked")
	mustStatus(t, f.AdminAPI("PATCH", "/users/"+f.Users["bob"], map[string]any{"profile": map[string]any{"undefined_attr": "x"}}), 422, "admin edit of an undefined attribute")
	f.must(f.AdminAPI("PATCH", "/users/"+f.Users["bob"], map[string]any{"profile": map[string]any{"employee_id": "E-7", "risk_score": 0.4}}), 200, "admin edit")
	me := f.must(h.API("GET", "/me", bob, nil), 200, "me")
	if prof := me.Get("profile").(map[string]any); prof["employee_id"] != nil || prof["risk_score"] != nil || prof["department"] != "support" {
		t.Fatalf("self view exposes non-self attributes: %v", prof)
	}
	adm := f.must(f.AdminAPI("GET", "/users/"+f.Users["bob"], nil), 200, "admin view")
	if prof := adm.Get("profile").(map[string]any); prof["employee_id"] != "E-7" || prof["risk_score"] != nil {
		t.Fatalf("admin view: %v", prof)
	}
	ev := f.must(f.AdminAPI("GET", "/audit-events?type=user.profile.completed", nil), 200, "audit")
	if len(ev.Get("items").([]any)) == 0 {
		t.Fatal("profile completion not audited")
	}
}

func hasAction(r *Resp, typ string) bool {
	acts, _ := r.Get("next_actions").([]any)
	for _, a := range acts {
		if m, ok := a.(map[string]any); ok && m["type"] == typ {
			return true
		}
	}
	return false
}
