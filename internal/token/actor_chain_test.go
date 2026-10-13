package token

import (
	"encoding/json"
	"testing"
)

// TestActorAuditChain covers AUD-005: the audit record of a delegated token
// keeps every actor of its act chain, outermost first, with agents marked,
// bounded by MaxAuditChain; the act claim reads the same whether
// introspection returned it as an *Actor (JWT) or a JSON object (opaque
// token).
func TestActorAuditChain(t *testing.T) {
	a := &Actor{Issuer: "https://idp.test", Subject: "web-bff", Act: &Actor{Subject: "sp_agent", Agent: true, Act: &Actor{Subject: "sp_orders"}}}
	chain, truncated := a.AuditChain()
	if truncated || len(chain) != 3 || chain[0]["sub"] != "web-bff" || chain[0]["iss"] != "https://idp.test" ||
		chain[1]["sub"] != "sp_agent" || chain[1]["agent"] != true || chain[2]["sub"] != "sp_orders" || chain[2]["agent"] != nil {
		t.Fatalf("chain: %v (truncated %v)", chain, truncated)
	}
	var nilActor *Actor
	if c, tr := nilActor.AuditChain(); c != nil || tr {
		t.Fatalf("nil actor: %v %v", c, tr)
	}
	long := &Actor{Subject: "a0"}
	for i := 1; i <= MaxAuditChain+3; i++ {
		long = &Actor{Subject: "a", Act: long}
	}
	if c, tr := long.AuditChain(); len(c) != MaxAuditChain || !tr {
		t.Fatalf("unbounded chain: %d entries, truncated %v", len(c), tr)
	}

	var decoded map[string]any
	b, _ := json.Marshal(a)
	_ = json.Unmarshal(b, &decoded)
	for name, v := range map[string]any{"pointer": a, "value": *a, "object": decoded} {
		got := ActorFrom(v)
		if got == nil || got.Subject != "web-bff" || got.Act == nil || got.Act.Subject != "sp_agent" || !got.Act.Agent || got.Act.Act == nil {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	for _, v := range []any{nil, "web-bff", map[string]any{"iss": "x"}, 42} {
		if got := ActorFrom(v); got != nil {
			t.Fatalf("%v read as an actor: %+v", v, got)
		}
	}
}
