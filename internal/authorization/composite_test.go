package authorization

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/proudbase/proudauth/internal/platform/problem"
)

// TestCompositeRoleGraphChecks covers AZ-011 and TEST-014 for composite
// roles: checkCompositeGraph (behind assertAcyclic, run when a composite
// role is created) refuses cycles, wherever they are in the reachable
// graph, with a 422, refuses a graph larger than limits.max_role_expansion
// (counted like evaluation: the role and every role it reaches), and visits
// each role once, so a wide diamond-shaped composition stays cheap. Cycles
// cannot be created through the API (composites are immutable after
// creation), so they are planted here directly.
func TestCompositeRoleGraphChecks(t *testing.T) {
	type graph map[string][]string
	run := func(g graph, start string, max int) (int, error) {
		calls := 0
		err := checkCompositeGraph(start, max, func(id string) ([]string, error) {
			calls++
			return g[id], nil
		})
		return calls, err
	}
	isCycle := func(err error) bool {
		pe, ok := problem.As(err)
		return ok && errors.Is(err, errRoleCycle) && pe.Status == http.StatusUnprocessableEntity
	}

	chain := graph{"a": {"b"}, "b": {"c"}}
	if _, err := run(chain, "a", 3); err != nil {
		t.Fatalf("chain at the bound refused: %v", err)
	}
	if _, err := run(chain, "a", 2); !errors.Is(err, ErrGraphTooLarge) {
		t.Fatalf("chain past the bound: %v, want ErrGraphTooLarge", err)
	}
	wide := graph{"a": {"b", "c", "d"}}
	if _, err := run(wide, "a", 3); !errors.Is(err, ErrGraphTooLarge) {
		t.Fatalf("wide composition past the bound: %v, want ErrGraphTooLarge", err)
	}

	for name, g := range map[string]graph{
		"self loop":             {"a": {"a"}},
		"two-role cycle":        {"a": {"b"}, "b": {"a"}},
		"cycle below the start": {"a": {"b"}, "b": {"c"}, "c": {"b"}},
		"cycle behind a shared role": {
			"a": {"b", "c"}, "b": {"d"}, "c": {"d"}, "d": {"e"}, "e": {"c"},
		},
	} {
		if _, err := run(g, "a", 64); !isCycle(err) {
			t.Errorf("%s: %v, want a 422 cycle refusal", name, err)
		}
	}

	// A shared role reached twice is not a cycle.
	if _, err := run(graph{"a": {"b", "c"}, "b": {"d"}, "c": {"d"}}, "a", 64); err != nil {
		t.Fatalf("diamond refused: %v", err)
	}
	// 30 layers of two roles, each composing both roles of the next layer:
	// 2^30 paths, 61 roles; each role is looked up once.
	layered := graph{"top": {"l0a", "l0b"}}
	for i := 0; i < 29; i++ {
		next := []string{fmt.Sprintf("l%da", i+1), fmt.Sprintf("l%db", i+1)}
		layered[fmt.Sprintf("l%da", i)] = next
		layered[fmt.Sprintf("l%db", i)] = next
	}
	calls, err := run(layered, "top", 64)
	if err != nil {
		t.Fatalf("layered composition refused: %v", err)
	}
	if calls != 61 {
		t.Fatalf("layered composition looked up %d roles, want 61 (each once)", calls)
	}

	boom := errors.New("lookup failed")
	if err := checkCompositeGraph("a", 64, func(string) ([]string, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("lookup error not returned: %v", err)
	}
}
