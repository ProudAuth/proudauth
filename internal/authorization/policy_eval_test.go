package authorization

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestPolicyInContainsUnknownOnMistypedAttributes covers AZ-007 and AZ-015
// for the in and contains operators: a comparison over a missing or mistyped
// attribute is unknown, as it is for eq, ne and the numeric operators, so a
// rule over it applies (deny or require) instead of being skipped. in is
// false only when the attribute could be compared with at least one list
// element; contains is false only when the attribute is a list with at least
// one element comparable with the value (an empty list contains nothing).
// not, any and all keep three-valued logic over the result.
func TestPolicyInContainsUnknownOnMistypedAttributes(t *testing.T) {
	cond := func(t *testing.T, raw string) *Condition {
		t.Helper()
		dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
		dec.UseNumber()
		var c Condition
		if err := dec.Decode(&c); err != nil {
			t.Fatal(err)
		}
		nodes := 0
		if err := c.validate(1, &nodes); err != nil {
			t.Fatalf("condition %s: %v", raw, err)
		}
		return &c
	}
	const (
		in       = `{"op":"in","attr":"resource.classification","value":["secret","top_secret"]}`
		inMixed  = `{"op":"in","attr":"resource.classification","value":["secret",3]}`
		inNum    = `{"op":"in","attr":"resource.level","value":[1,2]}`
		contains = `{"op":"contains","attr":"resource.tags","value":"secret"}`
		byAttr   = `{"op":"contains","attr":"resource.tags","value_attr":"context.tag"}`
	)
	not := func(c string) string { return `{"not":` + c + `}` }
	anyOf := func(cs ...string) string { return `{"any":[` + strings.Join(cs, ",") + `]}` }
	allOf := func(cs ...string) string { return `{"all":[` + strings.Join(cs, ",") + `]}` }
	const (
		alwaysTrue  = `{"op":"exists","attr":"resource.type"}`
		alwaysFalse = `{"op":"exists","attr":"resource.absent"}`
	)
	res := func(attrs map[string]any) *PolicyInput {
		r := map[string]any{"type": "document"}
		for k, v := range attrs {
			r[k] = v
		}
		return &PolicyInput{Action: "documents.read", Resource: r, Context: map[string]any{"tag": "secret"}}
	}
	cases := []struct {
		name string
		cond string
		in   *PolicyInput
		want tri
	}{
		// in: match, non-match, missing, mistyped.
		{"in match", in, res(map[string]any{"classification": "secret"}), triTrue},
		{"in non-match", in, res(map[string]any{"classification": "public"}), triFalse},
		{"in missing", in, res(nil), triUnknown},
		{"in null", in, res(map[string]any{"classification": nil}), triUnknown},
		{"in number against strings", in, res(map[string]any{"classification": 7}), triUnknown},
		{"in json number against strings", in, res(map[string]any{"classification": json.Number("7")}), triUnknown},
		{"in bool against strings", in, res(map[string]any{"classification": true}), triUnknown},
		{"in list against strings", in, res(map[string]any{"classification": []any{"secret"}}), triUnknown},
		{"in object against strings", in, res(map[string]any{"classification": map[string]any{"level": "secret"}}), triUnknown},
		{"in mixed list, comparable non-match", inMixed, res(map[string]any{"classification": 7}), triFalse},
		{"in mixed list, number match", inMixed, res(map[string]any{"classification": 3.0}), triTrue},
		{"in numbers match", inNum, res(map[string]any{"level": json.Number("2")}), triTrue},
		{"in numbers non-match", inNum, res(map[string]any{"level": 5}), triFalse},
		{"in string against numbers", inNum, res(map[string]any{"level": "2"}), triUnknown},
		// contains: match, non-match, missing, mistyped.
		{"contains match", contains, res(map[string]any{"tags": []any{"public", "secret"}}), triTrue},
		{"contains match []string", contains, res(map[string]any{"tags": []string{"secret"}}), triTrue},
		{"contains non-match", contains, res(map[string]any{"tags": []any{"public"}}), triFalse},
		{"contains non-match []string", contains, res(map[string]any{"tags": []string{"public"}}), triFalse},
		{"contains empty list", contains, res(map[string]any{"tags": []any{}}), triFalse},
		{"contains missing", contains, res(nil), triUnknown},
		{"contains on a string", contains, res(map[string]any{"tags": "secret"}), triUnknown},
		{"contains numbers against a string", contains, res(map[string]any{"tags": []any{1, 2}}), triUnknown},
		{"contains objects against a string", contains, res(map[string]any{"tags": []any{map[string]any{"name": "secret"}}}), triUnknown},
		{"contains nested lists against a string", contains, res(map[string]any{"tags": []any{[]any{"secret"}}}), triUnknown},
		{"contains mixed list, comparable non-match", contains, res(map[string]any{"tags": []any{1, "public"}}), triFalse},
		{"contains mixed list, match", contains, res(map[string]any{"tags": []any{1, "secret"}}), triTrue},
		{"contains value_attr match", byAttr, res(map[string]any{"tags": []any{"secret"}}), triTrue},
		{"contains value_attr object", byAttr, &PolicyInput{Resource: map[string]any{"tags": []any{"secret"}},
			Context: map[string]any{"tag": map[string]any{"x": 1}}}, triUnknown},
		{"contains value_attr object, empty list", byAttr, &PolicyInput{Resource: map[string]any{"tags": []any{}},
			Context: map[string]any{"tag": []any{"secret"}}}, triUnknown},
		// not keeps unknown unknown, and still negates known results.
		{"not in match", not(in), res(map[string]any{"classification": "secret"}), triFalse},
		{"not in non-match", not(in), res(map[string]any{"classification": "public"}), triTrue},
		{"not in missing", not(in), res(nil), triUnknown},
		{"not in mistyped", not(in), res(map[string]any{"classification": 7}), triUnknown},
		{"not contains match", not(contains), res(map[string]any{"tags": []any{"secret"}}), triFalse},
		{"not contains non-match", not(contains), res(map[string]any{"tags": []any{"public"}}), triTrue},
		{"not contains mistyped", not(contains), res(map[string]any{"tags": []any{7}}), triUnknown},
		// any: true wins, otherwise unknown beats false.
		{"any in match", anyOf(alwaysFalse, in), res(map[string]any{"classification": "secret"}), triTrue},
		{"any in non-match", anyOf(alwaysFalse, in), res(map[string]any{"classification": "public"}), triFalse},
		{"any in missing", anyOf(alwaysFalse, in), res(nil), triUnknown},
		{"any in mistyped", anyOf(alwaysFalse, in), res(map[string]any{"classification": []any{"secret"}}), triUnknown},
		{"any contains mistyped", anyOf(alwaysFalse, contains), res(map[string]any{"tags": []any{7}}), triUnknown},
		{"any contains mistyped or true", anyOf(contains, alwaysTrue), res(map[string]any{"tags": []any{7}}), triTrue},
		// all: false wins, otherwise unknown beats true.
		{"all in match", allOf(alwaysTrue, in), res(map[string]any{"classification": "secret"}), triTrue},
		{"all in non-match", allOf(alwaysTrue, in), res(map[string]any{"classification": "public"}), triFalse},
		{"all in missing", allOf(alwaysTrue, in), res(nil), triUnknown},
		{"all in mistyped", allOf(alwaysTrue, in), res(map[string]any{"classification": 7}), triUnknown},
		{"all contains mistyped", allOf(alwaysTrue, contains), res(map[string]any{"tags": []any{7}}), triUnknown},
		{"all contains mistyped and false", allOf(contains, alwaysFalse), res(map[string]any{"tags": []any{7}}), triFalse},
	}
	names := map[tri]string{triFalse: "false", triTrue: "true", triUnknown: "unknown"}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := cond(t, c.cond).eval(c.in); got != c.want {
				t.Fatalf("%s over %v: %s, want %s", c.cond, c.in.Resource, names[got], names[c.want])
			}
		})
	}

	// A positive deny rule fails closed on a mistyped attribute, like eq:
	// the rule applies and the reason says an attribute was unusable.
	def, err := ParsePolicy([]byte(`{"target":{"actions":["documents.*"]},"rules":[
		{"id":"secret-in","effect":"deny","reason_code":"CLASSIFIED","when":` + in + `},
		{"id":"secret-tag","effect":"deny","reason_code":"CLASSIFIED","when":` + contains + `}]}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		attrs      map[string]any
		denied     bool
		reason     string
		unknownIDs []string
	}{
		{"neither matches", map[string]any{"classification": "public", "tags": []any{"public"}}, false, "", nil},
		{"in matches", map[string]any{"classification": "secret", "tags": []any{}}, true, "CLASSIFIED", nil},
		{"contains matches", map[string]any{"classification": "public", "tags": []any{"secret"}}, true, "CLASSIFIED", nil},
		{"in mistyped", map[string]any{"classification": 7, "tags": []any{"public"}}, true, "POLICY_ATTRIBUTE_MISSING", []string{"secret-in"}},
		{"contains mistyped", map[string]any{"classification": "public", "tags": []any{7}}, true, "POLICY_ATTRIBUTE_MISSING", []string{"secret-tag"}},
		{"both missing", nil, true, "POLICY_ATTRIBUTE_MISSING", []string{"secret-in"}},
	} {
		t.Run("deny rule "+c.name, func(t *testing.T) {
			r := def.Evaluate(res(c.attrs))
			if r.Denied != c.denied || r.ReasonCode != c.reason || !slices.Equal(r.Unknown, c.unknownIDs) {
				t.Fatalf("got denied=%v reason=%q unknown=%v, want denied=%v reason=%q unknown=%v", r.Denied, r.ReasonCode, r.Unknown,
					c.denied, c.reason, c.unknownIDs)
			}
		})
	}
}
