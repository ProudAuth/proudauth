package authorization

import (
	"encoding/json"
	"testing"
	"time"
)

// FuzzPolicyDefinition (QA-003): arbitrary policy documents are either
// rejected by validation or evaluate without panicking, within bounds, for
// arbitrary request attributes.
func FuzzPolicyDefinition(f *testing.F) {
	f.Add([]byte(`{"target":{"actions":["orders.*"]},"rules":[{"effect":"deny","when":{"attr":"context.amount","op":"gt","value":100},"reason_code":"LIMIT"}]}`),
		[]byte(`{"amount":250,"region":"eu"}`))
	f.Add([]byte(`{"target":{"actions":["a.b"]},"rules":[{"effect":"deny","when":{"all":[{"attr":"subject.assurance","op":"eq","value":"mfa"}]}}]}`), []byte(`{}`))
	f.Add([]byte(`{}`), []byte(`null`))
	f.Fuzz(func(t *testing.T, def, ctx []byte) {
		if len(def) > 64<<10 || len(ctx) > 4<<10 {
			return
		}
		var d PolicyDefinition
		if json.Unmarshal(def, &d) != nil || d.Validate() != nil {
			return
		}
		var c map[string]any
		_ = json.Unmarshal(ctx, &c)
		in := &PolicyInput{Action: "orders.refund", Subject: map[string]any{"id": "usr_1", "assurance": "mfa"}, Resource: map[string]any{"type": "order"},
			Context: c, Environment: map[string]any{"now_unix": float64(time.Now().Unix())}, Now: time.Now()}
		res := d.Evaluate(in)
		if res.Denied && !res.Applicable {
			t.Fatalf("a policy denied a request it does not apply to: %+v", res)
		}
	})
}
