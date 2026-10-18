package authorization

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/proudauth/proudauth/internal/platform/problem"
)

// Policies are typed, bounded, side-effect-free restrictions evaluated after
// RBAC (AZ-013, AZ-015). They can only deny or add obligations; they never grant
// a permission that roles do not already confer, so a policy cannot become an
// escalation path. Evaluation is three-valued: a comparison over a missing or
// mistyped attribute is "unknown", and an unknown rule condition applies the
// rule (deny or require). Missing attributes and evaluation errors therefore
// never become authorization success (AZ-007).

// Limits bound policy size and evaluation cost.
const (
	MaxPolicyRules     = 50
	MaxConditionDepth  = 8
	MaxConditionNodes  = 64
	MaxListValues      = 100
	MaxPolicyBytes     = 64 << 10
	DefaultDenyReason  = "POLICY_DENIED"
	StepUpReason       = "STEP_UP_REQUIRED"
	ObligationReauth   = "reauthenticate"
	ObligationApproval = "approval"
	ObligationJustify  = "justification"
)

// PolicyDefinition is one immutable policy revision.
type PolicyDefinition struct {
	Description string       `json:"description,omitempty"`
	Target      PolicyTarget `json:"target"`
	Rules       []PolicyRule `json:"rules"`
}

// PolicyTarget selects the requests a policy applies to. Action patterns are
// exact names or a namespace prefix ending in ".*".
type PolicyTarget struct {
	Actions       []string `json:"actions"`
	ResourceTypes []string `json:"resource_types,omitempty"`
}

// PolicyRule is a deny or require rule.
type PolicyRule struct {
	ID          string       `json:"id"`
	Description string       `json:"description,omitempty"`
	Effect      string       `json:"effect"` // deny | require
	Actions     []string     `json:"actions,omitempty"`
	When        *Condition   `json:"when,omitempty"`
	ReasonCode  string       `json:"reason_code,omitempty"`
	Obligations []Obligation `json:"obligations,omitempty"`
}

// Obligation is a mandatory condition returned to the caller (§15.3). The IdP
// itself evaluates reauthenticate obligations against the subject's session;
// others (approval, justification) must be enforced by the caller, which must
// deny when it cannot.
type Obligation struct {
	Type            string `json:"type"`
	RequiredProfile string `json:"required_profile,omitempty"`
	MaxAgeSeconds   int    `json:"max_age_seconds,omitempty"`
	Approvals       int    `json:"approvals,omitempty"`
}

// Condition is a node of the condition language. Exactly one of All, Any, Not
// or Op is set.
type Condition struct {
	All []Condition `json:"all,omitempty"`
	Any []Condition `json:"any,omitempty"`
	Not *Condition  `json:"not,omitempty"`
	// Op compares Attr with Value (or ValueAttr): eq, ne, lt, le, gt, ge, in,
	// contains, starts_with, exists.
	Op        string `json:"op,omitempty"`
	Attr      string `json:"attr,omitempty"`
	Value     any    `json:"value,omitempty"`
	ValueAttr string `json:"value_attr,omitempty"`
}

var attrRoots = []string{"subject.", "resource.", "context.", "environment."}

func validAttr(a string) bool {
	if a == "action" {
		return true
	}
	if len(a) > 128 || strings.ContainsAny(a, " \t\r\n") {
		return false
	}
	for _, r := range attrRoots {
		if strings.HasPrefix(a, r) && len(a) > len(r) {
			return true
		}
	}
	return false
}

// ParsePolicy decodes and validates a definition strictly.
func ParsePolicy(raw []byte) (*PolicyDefinition, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes {
		return nil, problem.ErrValidation.WithField("definition", "required, at most 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var d PolicyDefinition
	if err := dec.Decode(&d); err != nil {
		return nil, problem.ErrValidation.WithField("definition", "invalid policy document: "+sanitize(err.Error()))
	}
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return &d, nil
}

func sanitize(s string) string {
	if len(s) > 160 {
		s = s[:160]
	}
	return strings.ReplaceAll(s, "\"", "'")
}

func validPattern(p string) bool {
	if p == "" || len(p) > 128 || strings.ContainsAny(p, " \t\r\n") {
		return false
	}
	if strings.Contains(p, "*") {
		return strings.HasSuffix(p, ".*") && strings.Count(p, "*") == 1 && len(p) > 2
	}
	return strings.Contains(p, ".")
}

func matchPattern(p, action string) bool {
	if p == "*" {
		return true // internal fail-closed placeholder only; not accepted in definitions
	}
	if strings.HasSuffix(p, ".*") {
		return strings.HasPrefix(action, strings.TrimSuffix(p, "*"))
	}
	return p == action
}

// Validate checks structure, bounds and types.
func (d *PolicyDefinition) Validate() error {
	verr := func(field, msg string) error { return problem.ErrValidation.WithField(field, msg) }
	if len(d.Target.Actions) == 0 || len(d.Target.Actions) > 50 {
		return verr("target.actions", "1..50 action patterns")
	}
	for _, a := range d.Target.Actions {
		if !validPattern(a) {
			return verr("target.actions", "invalid pattern "+a+" (use exact names or a namespace.* prefix)")
		}
	}
	if len(d.Rules) == 0 || len(d.Rules) > MaxPolicyRules {
		return verr("rules", fmt.Sprintf("1..%d rules", MaxPolicyRules))
	}
	seen := map[string]bool{}
	for i, r := range d.Rules {
		f := fmt.Sprintf("rules[%d]", i)
		if r.ID == "" || len(r.ID) > 64 || seen[r.ID] {
			return verr(f+".id", "required, unique, at most 64 characters")
		}
		seen[r.ID] = true
		for _, a := range r.Actions {
			if !validPattern(a) {
				return verr(f+".actions", "invalid pattern "+a)
			}
		}
		switch r.Effect {
		case "deny":
			if len(r.Obligations) > 0 {
				return verr(f+".obligations", "deny rules carry no obligations")
			}
			if r.ReasonCode != "" && (len(r.ReasonCode) > 64 || strings.Trim(r.ReasonCode, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789") != "") {
				return verr(f+".reason_code", "UPPER_SNAKE_CASE, at most 64 characters")
			}
		case "require":
			if len(r.Obligations) == 0 || len(r.Obligations) > 5 {
				return verr(f+".obligations", "1..5 obligations")
			}
			for _, o := range r.Obligations {
				switch o.Type {
				case ObligationReauth:
					if o.RequiredProfile != "" && o.RequiredProfile != "mfa" && o.RequiredProfile != "phishing_resistant" {
						return verr(f+".obligations", "required_profile must be mfa or phishing_resistant")
					}
					if o.MaxAgeSeconds < 0 || o.MaxAgeSeconds > 86400 || (o.MaxAgeSeconds == 0 && o.RequiredProfile == "") {
						return verr(f+".obligations", "reauthenticate needs required_profile and/or max_age_seconds (0..86400)")
					}
				case ObligationApproval:
					if o.Approvals < 1 || o.Approvals > 5 {
						return verr(f+".obligations", "approval needs approvals 1..5")
					}
				case ObligationJustify:
				default:
					return verr(f+".obligations", "type must be reauthenticate, approval or justification")
				}
			}
		default:
			return verr(f+".effect", "deny or require (policies never grant permissions)")
		}
		if r.When != nil {
			nodes := 0
			if err := r.When.validate(1, &nodes); err != nil {
				return verr(f+".when", err.Error())
			}
		}
	}
	return nil
}

func (c *Condition) validate(depth int, nodes *int) error {
	*nodes++
	if depth > MaxConditionDepth {
		return fmt.Errorf("conditions nest at most %d levels", MaxConditionDepth)
	}
	if *nodes > MaxConditionNodes {
		return fmt.Errorf("at most %d condition nodes", MaxConditionNodes)
	}
	set := 0
	if len(c.All) > 0 {
		set++
	}
	if len(c.Any) > 0 {
		set++
	}
	if c.Not != nil {
		set++
	}
	if c.Op != "" {
		set++
	}
	if set != 1 {
		return fmt.Errorf("each node needs exactly one of all, any, not or op")
	}
	for _, ch := range append(append([]Condition{}, c.All...), c.Any...) {
		if err := ch.validate(depth+1, nodes); err != nil {
			return err
		}
	}
	if c.Not != nil {
		return c.Not.validate(depth+1, nodes)
	}
	if c.Op == "" {
		if c.Attr != "" || c.Value != nil || c.ValueAttr != "" {
			return fmt.Errorf("attr/value are only valid with op")
		}
		return nil
	}
	if !validAttr(c.Attr) {
		return fmt.Errorf("attr must be action or start with a supported prefix (subject., resource., context. or environment.)")
	}
	if c.ValueAttr != "" && (!validAttr(c.ValueAttr) || c.Value != nil) {
		return fmt.Errorf("value_attr must be a valid attribute and excludes value")
	}
	switch c.Op {
	case "exists":
		if c.Value != nil || c.ValueAttr != "" {
			return fmt.Errorf("exists takes no value")
		}
	case "eq", "ne":
		if c.ValueAttr == "" && !scalar(c.Value) {
			return fmt.Errorf("%s needs a string, number or boolean value", c.Op)
		}
	case "lt", "le", "gt", "ge":
		if c.ValueAttr == "" {
			if _, ok := number(c.Value); !ok {
				return fmt.Errorf("%s needs a numeric value", c.Op)
			}
		}
	case "in":
		l, ok := c.Value.([]any)
		if !ok || len(l) == 0 || len(l) > MaxListValues {
			return fmt.Errorf("in needs a list of 1..%d scalars", MaxListValues)
		}
		for _, v := range l {
			if !scalar(v) {
				return fmt.Errorf("in lists contain scalars only")
			}
		}
	case "contains":
		if c.ValueAttr == "" && !scalar(c.Value) {
			return fmt.Errorf("contains needs a scalar value")
		}
	case "starts_with":
		if _, ok := c.Value.(string); !ok {
			return fmt.Errorf("starts_with needs a string value")
		}
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	return nil
}

func scalar(v any) bool {
	switch v.(type) {
	case string, bool, json.Number, float64, int, int64:
		return true
	}
	return false
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil && !math.IsInf(f, 0) && !math.IsNaN(f)
	case float64:
		return n, !math.IsInf(n, 0) && !math.IsNaN(n)
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// tri is a three-valued truth value.
type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

// PolicyInput is the trusted evaluation input. Subject attributes come from
// validated tokens and the IdP's own records; resource and context attributes
// are asserted by the authenticated calling service for its own resources
// (AZ-016); environment attributes come from the IdP clock.
type PolicyInput struct {
	Action      string
	Subject     map[string]any
	Resource    map[string]any
	Context     map[string]any
	Environment map[string]any
	// Satisfied reports whether a reauthenticate obligation is already met.
	ACR      string
	AuthTime time.Time
	Now      time.Time
}

func (in *PolicyInput) lookup(path string) (any, bool) {
	if path == "action" {
		return in.Action, in.Action != ""
	}
	var root map[string]any
	var rest string
	switch {
	case strings.HasPrefix(path, "subject."):
		root, rest = in.Subject, path[len("subject."):]
	case strings.HasPrefix(path, "resource."):
		root, rest = in.Resource, path[len("resource."):]
	case strings.HasPrefix(path, "context."):
		root, rest = in.Context, path[len("context."):]
	case strings.HasPrefix(path, "environment."):
		root, rest = in.Environment, path[len("environment."):]
	default:
		return nil, false
	}
	var cur any = root
	for _, part := range strings.Split(rest, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[part]; !ok || cur == nil {
			return nil, false
		}
	}
	return cur, true
}

func (c *Condition) eval(in *PolicyInput) tri {
	switch {
	case len(c.All) > 0:
		out := triTrue
		for i := range c.All {
			switch c.All[i].eval(in) {
			case triFalse:
				return triFalse
			case triUnknown:
				out = triUnknown
			}
		}
		return out
	case len(c.Any) > 0:
		out := triFalse
		for i := range c.Any {
			switch c.Any[i].eval(in) {
			case triTrue:
				return triTrue
			case triUnknown:
				out = triUnknown
			}
		}
		return out
	case c.Not != nil:
		switch c.Not.eval(in) {
		case triTrue:
			return triFalse
		case triFalse:
			return triTrue
		}
		return triUnknown
	}
	left, ok := in.lookup(c.Attr)
	if c.Op == "exists" {
		if ok {
			return triTrue
		}
		return triFalse
	}
	if !ok {
		return triUnknown
	}
	right := c.Value
	if c.ValueAttr != "" {
		if right, ok = in.lookup(c.ValueAttr); !ok {
			return triUnknown
		}
	}
	b := func(v bool) tri {
		if v {
			return triTrue
		}
		return triFalse
	}
	switch c.Op {
	case "eq", "ne":
		eq, comparable := equalValues(left, right)
		if !comparable {
			return triUnknown
		}
		return b(eq == (c.Op == "eq"))
	case "lt", "le", "gt", "ge":
		l, ok1 := number(left)
		r, ok2 := number(right)
		if !ok1 || !ok2 {
			return triUnknown
		}
		switch c.Op {
		case "lt":
			return b(l < r)
		case "le":
			return b(l <= r)
		case "gt":
			return b(l > r)
		default:
			return b(l >= r)
		}
	case "in":
		// False only when the attribute could be compared with the list:
		// a number, list or object checked against a list of strings is
		// unknown, as eq would be, not a non-match.
		list, _ := right.([]any)
		return memberOf(list, func(v any) (bool, bool) { return equalValues(left, v) })
	case "contains":
		list, ok := left.([]any)
		if !ok {
			if ls, ok2 := left.([]string); ok2 {
				for _, s := range ls {
					list = append(list, s)
				}
			} else {
				return triUnknown
			}
		}
		if len(list) == 0 && scalar(right) {
			return triFalse // an empty list contains nothing
		}
		return memberOf(list, func(v any) (bool, bool) { return equalValues(v, right) })
	case "starts_with":
		ls, ok1 := left.(string)
		rs, ok2 := right.(string)
		if !ok1 || !ok2 {
			return triUnknown
		}
		return b(strings.HasPrefix(ls, rs))
	}
	return triUnknown
}

// memberOf is true when cmp matches an element, false when at least one
// element was comparable and none matched, and unknown when no element was
// comparable (a mistyped attribute, AZ-007).
func memberOf(list []any, cmp func(any) (eq, comparable bool)) tri {
	compared := false
	for _, v := range list {
		eq, ok := cmp(v)
		if ok && eq {
			return triTrue
		}
		compared = compared || ok
	}
	if compared {
		return triFalse
	}
	return triUnknown
}

func equalValues(a, b any) (eq bool, comparable bool) {
	if an, ok := number(a); ok {
		if bn, ok := number(b); ok {
			return an == bn, true
		}
		return false, false
	}
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv, ok
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv, ok
	}
	return false, false
}

// PolicyResult is the outcome of evaluating one policy.
type PolicyResult struct {
	Applicable  bool         `json:"applicable"`
	Denied      bool         `json:"denied"`
	ReasonCode  string       `json:"reason_code,omitempty"`
	RuleID      string       `json:"rule_id,omitempty"`
	Obligations []Obligation `json:"obligations,omitempty"`
	// Unknown lists rules applied because an attribute was missing.
	Unknown []string `json:"unknown_rules,omitempty"`
}

func assuranceOK(profile, acr string) bool {
	switch profile {
	case "phishing_resistant":
		return assuranceRank(acr) >= 3
	case "mfa":
		return assuranceRank(acr) >= 2
	}
	return true
}

// Evaluate applies the policy. Deny overrides require.
func (d *PolicyDefinition) Evaluate(in *PolicyInput) PolicyResult {
	res := PolicyResult{}
	if !slices.ContainsFunc(d.Target.Actions, func(p string) bool { return matchPattern(p, in.Action) }) {
		return res
	}
	if len(d.Target.ResourceTypes) > 0 {
		rt, _ := in.Resource["type"].(string)
		if !slices.Contains(d.Target.ResourceTypes, rt) {
			return res
		}
	}
	res.Applicable = true
	for i := range d.Rules {
		r := &d.Rules[i]
		if len(r.Actions) > 0 && !slices.ContainsFunc(r.Actions, func(p string) bool { return matchPattern(p, in.Action) }) {
			continue
		}
		t := triTrue
		if r.When != nil {
			t = r.When.eval(in)
		}
		if t == triFalse {
			continue
		}
		if t == triUnknown {
			res.Unknown = append(res.Unknown, r.ID)
		}
		switch r.Effect {
		case "deny":
			res.Denied = true
			res.RuleID = r.ID
			res.ReasonCode = r.ReasonCode
			if res.ReasonCode == "" {
				res.ReasonCode = DefaultDenyReason
			}
			if t == triUnknown {
				res.ReasonCode = "POLICY_ATTRIBUTE_MISSING"
			}
			res.Obligations = nil
			return res
		case "require":
			for _, o := range r.Obligations {
				if o.Type == ObligationReauth {
					fresh := o.MaxAgeSeconds == 0 || (!in.AuthTime.IsZero() && in.Now.Sub(in.AuthTime) <= time.Duration(o.MaxAgeSeconds)*time.Second)
					if fresh && assuranceOK(o.RequiredProfile, in.ACR) {
						continue // already satisfied by the subject's session
					}
					res.Denied = true
					res.ReasonCode = StepUpReason
					res.RuleID = r.ID
				}
				res.Obligations = append(res.Obligations, o)
			}
		}
	}
	return res
}

// ObligationMaps renders obligations for the decision response.
func ObligationMaps(obs []Obligation) []map[string]any {
	out := make([]map[string]any, 0, len(obs))
	for _, o := range obs {
		m := map[string]any{"type": o.Type}
		if o.RequiredProfile != "" {
			m["required_profile"] = o.RequiredProfile
		}
		if o.MaxAgeSeconds > 0 {
			m["max_age_seconds"] = o.MaxAgeSeconds
		}
		if o.Approvals > 0 {
			m["approvals"] = o.Approvals
		}
		out = append(out, m)
	}
	return out
}
