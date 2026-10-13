package provisioning

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Filter is a parsed SCIM filter (RFC 7644 §3.4.2.2): comparisons eq, ne,
// co, sw, ew, gt, ge, lt, le and pr; and, or, not and parentheses; and value
// paths such as emails[type eq "work"].value. Attribute names compare
// without case; string values compare without case unless the attribute is
// case-exact (id, externalId).
type Filter interface {
	Match(resource map[string]any) bool
}

// ErrInvalidFilter reports a filter outside the supported grammar.
var ErrInvalidFilter = errors.New("invalid filter")

// ParseFilter parses a filter expression; at most 64 nodes.
func ParseFilter(s string) (Filter, error) {
	if len(s) > 1024 {
		return nil, ErrInvalidFilter
	}
	p := &parser{toks: tokenize(s)}
	f, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) || p.nodes > 64 {
		return nil, ErrInvalidFilter
	}
	return f, nil
}

type token struct {
	kind string // word, str, lpar, rpar, lbr, rbr
	val  string
}

func tokenize(s string) []token {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			out = append(out, token{"lpar", "("})
			i++
		case c == ')':
			out = append(out, token{"rpar", ")"})
			i++
		case c == '[':
			out = append(out, token{"lbr", "["})
			i++
		case c == ']':
			out = append(out, token{"rbr", "]"})
			i++
		case c == '"':
			var b strings.Builder
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					j++
				}
				b.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				return append(out, token{"bad", ""})
			}
			out = append(out, token{"str", b.String()})
			i = j + 1
		default:
			j := i
			for j < len(s) && !strings.ContainsRune(" \t()[]\"", rune(s[j])) {
				j++
			}
			out = append(out, token{"word", s[i:j]})
			i = j
		}
	}
	return out
}

type parser struct {
	toks  []token
	pos   int
	nodes int
}

func (p *parser) peekWord(w string) bool {
	return p.pos < len(p.toks) && p.toks[p.pos].kind == "word" && strings.EqualFold(p.toks[p.pos].val, w)
}

func (p *parser) or() (Filter, error) {
	left, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peekWord("or") {
		p.pos++
		right, err := p.and()
		if err != nil {
			return nil, err
		}
		p.nodes++
		left = orF{left, right}
	}
	return left, nil
}

func (p *parser) and() (Filter, error) {
	left, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.peekWord("and") {
		p.pos++
		right, err := p.unary()
		if err != nil {
			return nil, err
		}
		p.nodes++
		left = andF{left, right}
	}
	return left, nil
}

func (p *parser) unary() (Filter, error) {
	p.nodes++
	if p.peekWord("not") {
		p.pos++
		if p.pos >= len(p.toks) || p.toks[p.pos].kind != "lpar" {
			return nil, ErrInvalidFilter
		}
		f, err := p.unary()
		if err != nil {
			return nil, err
		}
		return notF{f}, nil
	}
	if p.pos < len(p.toks) && p.toks[p.pos].kind == "lpar" {
		p.pos++
		f, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.toks) || p.toks[p.pos].kind != "rpar" {
			return nil, ErrInvalidFilter
		}
		p.pos++
		return f, nil
	}
	return p.comparison()
}

func (p *parser) comparison() (Filter, error) {
	if p.pos >= len(p.toks) || p.toks[p.pos].kind != "word" {
		return nil, ErrInvalidFilter
	}
	attr := p.toks[p.pos].val
	if !attrName.MatchString(attr) || p.peekWord("and") || p.peekWord("or") || p.peekWord("not") {
		return nil, ErrInvalidFilter
	}
	p.pos++
	// Value path: attr[filter].sub
	if p.pos < len(p.toks) && p.toks[p.pos].kind == "lbr" {
		p.pos++
		inner, err := p.or()
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.toks) || p.toks[p.pos].kind != "rbr" {
			return nil, ErrInvalidFilter
		}
		p.pos++
		sub := ""
		if p.pos < len(p.toks) && p.toks[p.pos].kind == "word" && strings.HasPrefix(p.toks[p.pos].val, ".") {
			sub = strings.TrimPrefix(p.toks[p.pos].val, ".")
			p.pos++
		}
		vp := valuePath{attr: attr, inner: inner}
		if sub == "" {
			return vp, nil
		}
		cmp, err := p.operator(sub)
		if err != nil {
			return nil, err
		}
		vp.sub = &cmp
		return vp, nil
	}
	cmp, err := p.operator(attr)
	if err != nil {
		return nil, err
	}
	return cmp, nil
}

func (p *parser) operator(attr string) (compare, error) {
	if p.pos >= len(p.toks) || p.toks[p.pos].kind != "word" {
		return compare{}, ErrInvalidFilter
	}
	op := strings.ToLower(p.toks[p.pos].val)
	p.pos++
	switch op {
	case "pr":
		return compare{attr: attr, op: op}, nil
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
	default:
		return compare{}, fmt.Errorf("%w: operator %s", ErrInvalidFilter, op)
	}
	if p.pos >= len(p.toks) {
		return compare{}, ErrInvalidFilter
	}
	t := p.toks[p.pos]
	p.pos++
	c := compare{attr: attr, op: op}
	switch {
	case t.kind == "str":
		c.value = t.val
	case t.kind == "word" && (t.val == "true" || t.val == "false"):
		c.value = t.val == "true"
	case t.kind == "word" && t.val == "null":
		c.value = nil
	case t.kind == "word":
		f, err := strconv.ParseFloat(t.val, 64)
		if err != nil {
			return compare{}, ErrInvalidFilter
		}
		c.value = f
	default:
		return compare{}, ErrInvalidFilter
	}
	// Ordering and substring operators need a value they can order or search.
	if _, isStr := c.value.(string); op != "eq" && op != "ne" && !isStr {
		if _, isNum := c.value.(float64); !isNum || op == "co" || op == "sw" || op == "ew" {
			return compare{}, ErrInvalidFilter
		}
	}
	return c, nil
}

// attrName is an attribute path, optionally schema-qualified; the logical
// keywords are never attribute names.
var attrName = regexp.MustCompile(`^(?i:(?:urn:[A-Za-z0-9:._-]+:)?[A-Za-z][A-Za-z0-9_$-]*(?:\.[A-Za-z][A-Za-z0-9_$-]*)?)$`)

type andF struct{ a, b Filter }
type orF struct{ a, b Filter }
type notF struct{ f Filter }

func (f andF) Match(r map[string]any) bool { return f.a.Match(r) && f.b.Match(r) }
func (f orF) Match(r map[string]any) bool  { return f.a.Match(r) || f.b.Match(r) }
func (f notF) Match(r map[string]any) bool { return !f.f.Match(r) }

type compare struct {
	attr  string
	op    string
	value any
}

type valuePath struct {
	attr  string
	inner Filter
	sub   *compare
}

func (v valuePath) Match(r map[string]any) bool {
	for _, el := range asList(lookup(r, v.attr)) {
		m, ok := el.(map[string]any)
		if !ok || !v.inner.Match(m) {
			continue
		}
		if v.sub == nil || v.sub.Match(m) {
			return true
		}
	}
	return false
}

// unqualify strips a core schema URN (User or Group) from an attribute path:
// a schema-qualified path names the same attribute as the bare one (RFC 7644
// §3.10), and URNs, like attribute names, compare without case.
func unqualify(path string) string {
	for _, urn := range []string{SchemaUser + ":", SchemaGroup + ":"} {
		if len(path) > len(urn) && strings.EqualFold(path[:len(urn)], urn) {
			return path[len(urn):]
		}
	}
	return path
}

// lookup resolves a (case-insensitive, possibly dotted, possibly
// schema-qualified) attribute path; for multi-valued attributes it returns
// every value.
func lookup(r map[string]any, path string) any {
	path = unqualify(path)
	head, rest, _ := strings.Cut(path, ".")
	var v any
	for k, val := range r {
		if strings.EqualFold(k, head) {
			v = val
		}
	}
	if rest == "" || v == nil {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		return lookup(x, rest)
	case []any:
		var out []any
		for _, el := range x {
			if m, ok := el.(map[string]any); ok {
				if sub := lookup(m, rest); sub != nil {
					out = append(out, sub)
				}
			}
		}
		return out
	case []map[string]any:
		var out []any
		for _, m := range x {
			if sub := lookup(m, rest); sub != nil {
				out = append(out, sub)
			}
		}
		return out
	}
	return nil
}

func asList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	case []map[string]any:
		out := make([]any, len(x))
		for i := range x {
			out[i] = x[i]
		}
		return out
	}
	return []any{v}
}

var caseExact = map[string]bool{"id": true, "externalid": true}

func (c compare) Match(r map[string]any) bool {
	values := asList(lookup(r, c.attr))
	if c.op == "pr" {
		for _, v := range values {
			if v != nil && v != "" {
				return true
			}
		}
		return false
	}
	exact := caseExact[strings.ToLower(c.attr)]
	for _, v := range values {
		if c.one(v, exact) {
			return true
		}
	}
	return c.op == "ne" && len(values) == 0 && c.value != nil
}

func (c compare) one(v any, exact bool) bool {
	switch want := c.value.(type) {
	case nil:
		return (c.op == "eq") == (v == nil)
	case bool:
		got, ok := v.(bool)
		if !ok {
			return c.op == "ne"
		}
		return (c.op == "eq") == (got == want)
	case float64:
		var got float64
		switch x := v.(type) {
		case float64:
			got = x
		case int:
			got = float64(x)
		case int64:
			got = float64(x)
		default:
			return false
		}
		switch c.op {
		case "eq":
			return got == want
		case "ne":
			return got != want
		case "gt":
			return got > want
		case "ge":
			return got >= want
		case "lt":
			return got < want
		case "le":
			return got <= want
		}
		return false
	case string:
		got, ok := v.(string)
		if !ok {
			return c.op == "ne"
		}
		if !exact {
			got, want = strings.ToLower(got), strings.ToLower(want)
		}
		switch c.op {
		case "eq":
			return got == want
		case "ne":
			return got != want
		case "co":
			return strings.Contains(got, want)
		case "sw":
			return strings.HasPrefix(got, want)
		case "ew":
			return strings.HasSuffix(got, want)
		case "gt":
			return got > want
		case "ge":
			return got >= want
		case "lt":
			return got < want
		case "le":
			return got <= want
		}
	}
	return false
}
