package realm

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/proudauth/proudauth/internal/platform/problem"
)

// TestNoSecurityQuestions covers MFA-011: knowledge-based personal questions
// are not an accepted factor. A realm policy that names one as an MFA factor
// or as a sign-in method of an authentication flow rule is refused, and the
// policy has no member that could configure one.
func TestNoSecurityQuestions(t *testing.T) {
	field := func(err error) string {
		var pe *problem.Error
		if !errors.As(err, &pe) {
			return ""
		}
		for k := range pe.Fields {
			return k
		}
		return ""
	}
	if err := ValidatePolicy(DefaultPolicy(), false); err != nil {
		t.Fatalf("default policy: %v", err)
	}
	for _, f := range []string{"security_question", "security_questions", "knowledge_based", "kba", "personal_question", "secret_question"} {
		p := DefaultPolicy()
		p.MFA.AllowedFactors = append(p.MFA.AllowedFactors, f)
		if err := ValidatePolicy(p, false); field(err) != "mfa.allowed_factors" {
			t.Errorf("factor %q accepted: %v", f, err)
		} else if pe, _ := problem.As(err); pe.Status != 422 {
			t.Errorf("factor %q: status %d, want 422", f, pe.Status)
		}
		p = DefaultPolicy()
		p.AuthFlow.Rules = []AuthFlowRule{{Name: "questions", When: AuthFlowCondition{Methods: []string{f}}, Outcome: FlowRequireMFA}}
		if err := ValidatePolicy(p, false); field(err) != "authentication_flow.rules[0].when.methods" {
			t.Errorf("flow method %q accepted: %v", f, err)
		}
	}
	// No policy member configures knowledge-based questions.
	var walk func(reflect.Type, string)
	seen := map[reflect.Type]bool{}
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			sf := rt.Field(i)
			name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
			for _, w := range []string{"question", "knowledge", "kba"} {
				if strings.Contains(strings.ToLower(name), w) {
					t.Errorf("policy member %s%s configures knowledge-based questions", path, name)
				}
			}
			walk(sf.Type, path+name+".")
		}
	}
	walk(reflect.TypeOf(Policy{}), "")
}
