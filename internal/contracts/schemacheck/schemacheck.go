// Package schemacheck validates JSON documents against the published JSON
// Schema (draft 2020-12) files under api/ for the compatibility tests
// (EXT-018). It implements the keyword subset the published schemas use
// ($ref across files and JSON pointers, allOf/anyOf/oneOf/not,
// if/then/else, type, const, enum, properties, required,
// additionalProperties, items, length, pattern, numeric bounds,
// dependentRequired); annotation keywords (description, examples, format,
// x-*) are ignored, as standard validators do by default. An unknown
// assertion keyword is an error, so a schema can never silently validate
// less than it claims.
package schemacheck

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Set is a directory tree of schema files, addressed by file name relative to
// the root (for example "envelope.v1.json" or "hooks/registration.request.v1.json").
type Set struct {
	docs map[string]any
}

// Load reads every *.json file under the given directories. Files are keyed by
// base name, so relative $refs between files of one directory resolve.
func Load(dirs ...string) (*Set, error) {
	s := &Set{docs: map[string]any{}}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".json") {
				return err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			name := filepath.Base(path)
			if _, dup := s.docs[name]; dup {
				return fmt.Errorf("duplicate schema file name %s", name)
			}
			s.docs[name] = doc
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Has reports whether a schema file is loaded.
func (s *Set) Has(file string) bool { _, ok := s.docs[file]; return ok }

// Files lists the loaded schema file names, sorted.
func (s *Set) Files() []string {
	out := make([]string, 0, len(s.docs))
	for k := range s.docs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Doc returns a loaded schema document.
func (s *Set) Doc(file string) any { return s.docs[file] }

// Validate checks instance (decoded JSON: map[string]any, []any, float64,
// string, bool or nil) against a schema file and returns every violation.
func (s *Set) Validate(file string, instance any) error {
	doc, ok := s.docs[file]
	if !ok {
		return fmt.Errorf("schema %s not loaded", file)
	}
	v := &validator{set: s}
	v.check(file, doc, normalize(instance), "")
	if len(v.errs) > 0 {
		return fmt.Errorf("%s: %s", file, strings.Join(v.errs, "; "))
	}
	return nil
}

// ValidateBytes decodes raw JSON and validates it.
func (s *Set) ValidateBytes(file string, raw []byte) error {
	var inst any
	if err := json.Unmarshal(raw, &inst); err != nil {
		return fmt.Errorf("%s: instance is not JSON: %w", file, err)
	}
	return s.Validate(file, inst)
}

// normalize round-trips Go values through JSON so typed structs and ints
// compare like decoded documents.
func normalize(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

type validator struct {
	set  *Set
	errs []string
}

func (v *validator) fail(at, format string, args ...any) {
	if at == "" {
		at = "/"
	}
	v.errs = append(v.errs, at+": "+fmt.Sprintf(format, args...))
}

// annotations are keywords without assertion semantics.
var annotations = map[string]bool{"$schema": true, "$id": true, "$defs": true, "title": true, "description": true, "examples": true,
	"format": true, "default": true, "deprecated": true, "readOnly": true, "writeOnly": true, "$comment": true,
	"contentEncoding": true, "contentMediaType": true, "contentSchema": true}

// sub validates against a subschema and reports whether it held, without
// recording its errors (for anyOf, oneOf, not and if).
func (v *validator) sub(file string, schema, inst any, at string) bool {
	probe := &validator{set: v.set}
	probe.check(file, schema, inst, at)
	return len(probe.errs) == 0
}

func (v *validator) check(file string, schema, inst any, at string) {
	switch sc := schema.(type) {
	case bool:
		if !sc {
			v.fail(at, "false schema")
		}
		return
	case map[string]any:
		v.checkObject(file, sc, inst, at)
	default:
		v.fail(at, "invalid schema node %T", schema)
	}
}

func (v *validator) resolve(file, ref string) (string, any, error) {
	target, frag, _ := strings.Cut(ref, "#")
	if target != "" {
		file = filepath.Base(target)
	}
	doc, ok := v.set.docs[file]
	if !ok {
		return "", nil, fmt.Errorf("unresolvable $ref %q (schema %s not loaded)", ref, file)
	}
	node := doc
	if frag != "" {
		for _, part := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			m, ok := node.(map[string]any)
			if !ok {
				return "", nil, fmt.Errorf("unresolvable $ref %q", ref)
			}
			if node, ok = m[part]; !ok {
				return "", nil, fmt.Errorf("unresolvable $ref %q", ref)
			}
		}
	}
	return file, node, nil
}

func (v *validator) checkObject(file string, sc map[string]any, inst any, at string) {
	for k := range sc {
		if annotations[k] || strings.HasPrefix(k, "x-") {
			continue
		}
		switch k {
		case "$ref", "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "type", "const", "enum", "properties", "required",
			"additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "minLength", "maxLength", "pattern", "minimum", "maximum",
			"exclusiveMinimum", "exclusiveMaximum", "dependentRequired", "minProperties", "maxProperties", "propertyNames", "patternProperties":
		default:
			v.fail(at, "schema uses unsupported keyword %q", k)
		}
	}
	if ref, ok := sc["$ref"].(string); ok {
		f, node, err := v.resolve(file, ref)
		if err != nil {
			v.fail(at, "%v", err)
		} else {
			v.check(f, node, inst, at)
		}
	}
	for _, kw := range []string{"allOf"} {
		if list, ok := sc[kw].([]any); ok {
			for _, s := range list {
				v.check(file, s, inst, at)
			}
		}
	}
	if list, ok := sc["anyOf"].([]any); ok {
		held := false
		for _, s := range list {
			if v.sub(file, s, inst, at) {
				held = true
				break
			}
		}
		if !held {
			v.fail(at, "matches none of anyOf")
		}
	}
	if list, ok := sc["oneOf"].([]any); ok {
		n := 0
		for _, s := range list {
			if v.sub(file, s, inst, at) {
				n++
			}
		}
		if n != 1 {
			v.fail(at, "matches %d of oneOf (want exactly 1)", n)
		}
	}
	if s, ok := sc["not"]; ok && v.sub(file, s, inst, at) {
		v.fail(at, "matches a not schema")
	}
	if cond, ok := sc["if"]; ok {
		if v.sub(file, cond, inst, at) {
			if then, ok := sc["then"]; ok {
				v.check(file, then, inst, at)
			}
		} else if els, ok := sc["else"]; ok {
			v.check(file, els, inst, at)
		}
	}
	if t, ok := sc["type"]; ok && !typeMatches(t, inst) {
		v.fail(at, "type %s, want %v", jsonType(inst), t)
	}
	if c, ok := sc["const"]; ok && !reflect.DeepEqual(c, inst) {
		v.fail(at, "value %v is not the constant %v", inst, c)
	}
	if list, ok := sc["enum"].([]any); ok {
		found := false
		for _, e := range list {
			if reflect.DeepEqual(e, inst) {
				found = true
				break
			}
		}
		if !found {
			v.fail(at, "value %v is not one of %v", inst, list)
		}
	}
	switch x := inst.(type) {
	case map[string]any:
		v.checkProperties(file, sc, x, at)
	case []any:
		if items, ok := sc["items"]; ok {
			for i, el := range x {
				v.check(file, items, el, at+"/"+strconv.Itoa(i))
			}
		}
		if n, ok := num(sc["minItems"]); ok && float64(len(x)) < n {
			v.fail(at, "fewer than %v items", n)
		}
		if n, ok := num(sc["maxItems"]); ok && float64(len(x)) > n {
			v.fail(at, "more than %v items", n)
		}
		if u, _ := sc["uniqueItems"].(bool); u {
			for i := range x {
				for j := i + 1; j < len(x); j++ {
					if reflect.DeepEqual(x[i], x[j]) {
						v.fail(at, "items %d and %d are equal", i, j)
					}
				}
			}
		}
	case string:
		n := float64(utf8.RuneCountInString(x))
		if m, ok := num(sc["minLength"]); ok && n < m {
			v.fail(at, "shorter than %v", m)
		}
		if m, ok := num(sc["maxLength"]); ok && n > m {
			v.fail(at, "longer than %v", m)
		}
		if p, ok := sc["pattern"].(string); ok {
			re, err := regexp.Compile(p)
			if err != nil {
				v.fail(at, "invalid pattern %q: %v", p, err)
			} else if !re.MatchString(x) {
				v.fail(at, "%q does not match %s", x, p)
			}
		}
	case float64:
		if m, ok := num(sc["minimum"]); ok && x < m {
			v.fail(at, "%v is below the minimum %v", x, m)
		}
		if m, ok := num(sc["maximum"]); ok && x > m {
			v.fail(at, "%v is above the maximum %v", x, m)
		}
		if m, ok := num(sc["exclusiveMinimum"]); ok && x <= m {
			v.fail(at, "%v is not above %v", x, m)
		}
		if m, ok := num(sc["exclusiveMaximum"]); ok && x >= m {
			v.fail(at, "%v is not below %v", x, m)
		}
	}
}

func (v *validator) checkProperties(file string, sc map[string]any, obj map[string]any, at string) {
	props, _ := sc["properties"].(map[string]any)
	for name, s := range props {
		if val, ok := obj[name]; ok {
			v.check(file, s, val, at+"/"+name)
		}
	}
	patterns, _ := sc["patternProperties"].(map[string]any)
	matchedPattern := func(name string) bool {
		hit := false
		for p, s := range patterns {
			if re, err := regexp.Compile(p); err == nil && re.MatchString(name) {
				v.check(file, s, obj[name], at+"/"+name)
				hit = true
			}
		}
		return hit
	}
	if req, ok := sc["required"].([]any); ok {
		for _, r := range req {
			if name, _ := r.(string); name != "" {
				if _, ok := obj[name]; !ok {
					v.fail(at, "missing required member %q", name)
				}
			}
		}
	}
	if dep, ok := sc["dependentRequired"].(map[string]any); ok {
		for name, list := range dep {
			if _, ok := obj[name]; !ok {
				continue
			}
			for _, r := range list.([]any) {
				if _, ok := obj[r.(string)]; !ok {
					v.fail(at, "member %q requires %q", name, r)
				}
			}
		}
	}
	if pn, ok := sc["propertyNames"]; ok {
		for name := range obj {
			v.check(file, pn, name, at+"/"+name)
		}
	}
	if n, ok := num(sc["minProperties"]); ok && float64(len(obj)) < n {
		v.fail(at, "fewer than %v members", n)
	}
	if n, ok := num(sc["maxProperties"]); ok && float64(len(obj)) > n {
		v.fail(at, "more than %v members", n)
	}
	if ap, ok := sc["additionalProperties"]; ok {
		for name, val := range obj {
			if _, declared := props[name]; declared {
				continue
			}
			if matchedPattern(name) {
				continue
			}
			if b, isBool := ap.(bool); isBool {
				if !b {
					v.fail(at, "unexpected member %q", name)
				}
				continue
			}
			v.check(file, ap, val, at+"/"+name)
		}
	} else {
		for name := range obj {
			if _, declared := props[name]; !declared {
				matchedPattern(name)
			}
		}
	}
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func jsonType(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case float64:
		if x == math.Trunc(x) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

func typeMatches(t, inst any) bool {
	got := jsonType(inst)
	one := func(name string) bool {
		return name == got || name == "number" && got == "integer"
	}
	switch tt := t.(type) {
	case string:
		return one(tt)
	case []any:
		for _, x := range tt {
			if s, _ := x.(string); one(s) {
				return true
			}
		}
	}
	return false
}
