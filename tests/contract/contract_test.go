// Package contract keeps the published machine-readable contracts (API-002) in sync
// with the server: the OpenAPI document must list exactly the routes the HTTP layer
// registers, and the event and configuration schemas must be well-formed JSON Schema.
// The checks are static (source and document parsing) and need no database.
package contract

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/proudauth/proudauth/internal/webhooks"
)

const (
	repoRoot    = "../.."
	openAPIPath = "api/openapi/proudauth.yaml"
	httpAPIDir  = "internal/httpapi"
)

var httpMethods = []string{"get", "put", "post", "patch", "delete", "options", "head", "trace"}

// route is one method + path pair, normalized to OpenAPI path templating.
type route struct {
	Method string // lower case
	Path   string
}

func (r route) String() string { return strings.ToUpper(r.Method) + " " + r.Path }

// ---------- OpenAPI document ----------

func loadOpenAPI(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, openAPIPath))
	if err != nil {
		t.Fatalf("read OpenAPI document: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", openAPIPath, err)
	}
	if v, _ := doc["openapi"].(string); !strings.HasPrefix(v, "3.1.") {
		t.Fatalf("%s: openapi version %q, want 3.1.x", openAPIPath, v)
	}
	return doc
}

func documentedRoutes(t *testing.T, doc map[string]any) map[route]map[string]any {
	t.Helper()
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		t.Fatalf("%s: no paths", openAPIPath)
	}
	out := map[route]map[string]any{}
	for p, item := range paths {
		ops, ok := item.(map[string]any)
		if !ok {
			t.Errorf("path %s: not an object", p)
			continue
		}
		for m, op := range ops {
			if !slices.Contains(httpMethods, m) {
				continue // parameters, summary, servers, ...
			}
			opm, ok := op.(map[string]any)
			if !ok {
				t.Errorf("%s %s: operation is not an object", m, p)
				continue
			}
			out[route{Method: m, Path: p}] = opm
		}
	}
	return out
}

// ---------- registered routes (static analysis of the router) ----------

// registeredRoutes collects every pattern passed to mux.HandleFunc / mux.Handle in
// internal/httpapi, plus routes that optional modules register through App.Extend
// anywhere under internal/. Route patterns are built from string literals, local
// string variables (base, R) and range loops over struct literals (suspend/
// reactivate families), which the evaluator below resolves. Any pattern it cannot
// resolve fails the test, so new registration styles cannot silently escape the
// contract.
func registeredRoutes(t *testing.T) map[route]string {
	t.Helper()
	routes := map[route]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(filepath.Join(repoRoot, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		inHTTPAPI := filepath.Dir(path) == filepath.Join(repoRoot, httpAPIDir)
		consts := packageStrings(f)
		ev := &evaluator{t: t, fset: fset, consts: consts, routes: routes}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if inHTTPAPI {
				ev.block(fd.Body.List, scope{})
				continue
			}
			// Outside the HTTP package only module registrations through App.Extend count.
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || calleeName(call) != "Extend" {
					return true
				}
				for _, arg := range call.Args {
					if lit, ok := arg.(*ast.FuncLit); ok {
						ev.block(lit.Body.List, scope{})
					}
				}
				return false
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan router source: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("no routes found in internal/httpapi; the route extractor is broken")
	}
	return routes
}

// packageStrings returns package-level string constants and variables of one file.
func packageStrings(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || (gd.Tok != token.CONST && gd.Tok != token.VAR) {
			continue
		}
		for _, spec := range gd.Specs {
			vs := spec.(*ast.ValueSpec)
			for i, name := range vs.Names {
				if i < len(vs.Values) {
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if s, err := strconv.Unquote(lit.Value); err == nil {
							out[name.Name] = s
						}
					}
				}
			}
		}
	}
	return out
}

func calleeName(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		return sel.Sel.Name
	}
	return ""
}

// scope maps local identifiers to known string values and range variables over
// struct literals to their current element's field values.
type scope struct {
	strs    map[string]string
	structs map[string]map[string]string
}

func (s scope) clone() scope {
	c := scope{strs: map[string]string{}, structs: map[string]map[string]string{}}
	for k, v := range s.strs {
		c.strs[k] = v
	}
	for k, v := range s.structs {
		c.structs[k] = v
	}
	return c
}

type evaluator struct {
	t      *testing.T
	fset   *token.FileSet
	consts map[string]string
	routes map[route]string
}

func (e *evaluator) eval(x ast.Expr, sc scope) (string, bool) {
	switch v := x.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, ok1 := e.eval(v.X, sc)
		r, ok2 := e.eval(v.Y, sc)
		return l + r, ok1 && ok2
	case *ast.ParenExpr:
		return e.eval(v.X, sc)
	case *ast.Ident:
		if s, ok := sc.strs[v.Name]; ok {
			return s, true
		}
		s, ok := e.consts[v.Name]
		return s, ok
	case *ast.SelectorExpr:
		if id, ok := v.X.(*ast.Ident); ok {
			if fields, ok := sc.structs[id.Name]; ok {
				s, ok := fields[v.Sel.Name]
				return s, ok
			}
		}
	}
	return "", false
}

func (e *evaluator) block(stmts []ast.Stmt, sc scope) {
	sc = sc.clone()
	for _, st := range stmts {
		e.stmt(st, sc)
	}
}

func (e *evaluator) stmt(st ast.Stmt, sc scope) {
	switch v := st.(type) {
	case *ast.AssignStmt:
		for i, lhs := range v.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(v.Rhs) || len(v.Lhs) != len(v.Rhs) {
				continue
			}
			if s, ok := e.eval(v.Rhs[i], sc); ok {
				sc.strs[id.Name] = s
			} else {
				delete(sc.strs, id.Name)
			}
		}
		e.exprs(v.Rhs, sc)
	case *ast.ExprStmt:
		e.expr(v.X, sc)
	case *ast.BlockStmt:
		e.block(v.List, sc)
	case *ast.IfStmt:
		if v.Init != nil {
			e.stmt(v.Init, sc)
		}
		e.block(v.Body.List, sc)
		if v.Else != nil {
			e.stmt(v.Else, sc)
		}
	case *ast.ForStmt:
		e.block(v.Body.List, sc)
	case *ast.SwitchStmt:
		for _, c := range v.Body.List {
			e.block(c.(*ast.CaseClause).Body, sc)
		}
	case *ast.TypeSwitchStmt:
		for _, c := range v.Body.List {
			e.block(c.(*ast.CaseClause).Body, sc)
		}
	case *ast.RangeStmt:
		elems, ok := structLiteralElems(v.X)
		val, isIdent := v.Value.(*ast.Ident)
		if !ok || !isIdent {
			e.block(v.Body.List, sc)
			return
		}
		for _, fields := range elems {
			inner := sc.clone()
			inner.structs[val.Name] = fields
			e.block(v.Body.List, inner)
		}
	case *ast.ReturnStmt:
		e.exprs(v.Results, sc)
	case *ast.DeclStmt, *ast.IncDecStmt, *ast.BranchStmt, *ast.DeferStmt, *ast.GoStmt, *ast.LabeledStmt, *ast.SendStmt, *ast.EmptyStmt, *ast.SelectStmt:
		// No route registrations expected here; function literals inside are still
		// inspected so registrations cannot hide in them.
		ast.Inspect(v, func(n ast.Node) bool {
			if lit, ok := n.(*ast.FuncLit); ok {
				e.block(lit.Body.List, sc)
				return false
			}
			return true
		})
	}
}

func (e *evaluator) exprs(xs []ast.Expr, sc scope) {
	for _, x := range xs {
		e.expr(x, sc)
	}
}

// expr records route registrations and descends into function literals.
func (e *evaluator) expr(x ast.Expr, sc scope) {
	ast.Inspect(x, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncLit:
			e.block(v.Body.List, sc)
			return false
		case *ast.CallExpr:
			name := calleeName(v)
			if (name == "HandleFunc" || name == "Handle") && len(v.Args) == 2 {
				e.register(v, sc)
			}
		}
		return true
	})
}

var wildcard = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)(\.\.\.)?\}`)

func (e *evaluator) register(call *ast.CallExpr, sc scope) {
	pos := e.fset.Position(call.Pos())
	pattern, ok := e.eval(call.Args[0], sc)
	if !ok {
		e.t.Errorf("%s: cannot statically resolve route pattern; build it from literals, local string variables or range-over-struct-literal fields", pos)
		return
	}
	method, path, found := strings.Cut(pattern, " ")
	if !found || method == "" || !strings.HasPrefix(path, "/") {
		e.t.Errorf("%s: route %q must be registered with an explicit method (\"METHOD /path\")", pos, pattern)
		return
	}
	path = strings.TrimSuffix(path, "{$}")
	path = wildcard.ReplaceAllString(path, "{$1}")
	r := route{Method: strings.ToLower(method), Path: path}
	if prev, dup := e.routes[r]; dup {
		e.t.Errorf("%s: route %s already registered at %s", pos, r, prev)
		return
	}
	e.routes[r] = pos.String()
}

// structLiteralElems returns the field values of each element of a
// []struct{...}{{...}, ...} literal (string fields only).
func structLiteralElems(x ast.Expr) ([]map[string]string, bool) {
	lit, ok := x.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	at, ok := lit.Type.(*ast.ArrayType)
	if !ok {
		return nil, false
	}
	st, ok := at.Elt.(*ast.StructType)
	if !ok {
		return nil, false
	}
	var names []string
	for _, f := range st.Fields.List {
		for _, n := range f.Names {
			names = append(names, n.Name)
		}
	}
	var out []map[string]string
	for _, el := range lit.Elts {
		cl, ok := el.(*ast.CompositeLit)
		if !ok {
			return nil, false
		}
		fields := map[string]string{}
		for i, v := range cl.Elts {
			key := ""
			if kv, ok := v.(*ast.KeyValueExpr); ok {
				id, _ := kv.Key.(*ast.Ident)
				if id == nil {
					return nil, false
				}
				key, v = id.Name, kv.Value
			} else if i < len(names) {
				key = names[i]
			}
			if bl, ok := v.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, err := strconv.Unquote(bl.Value); err == nil {
					fields[key] = s
				}
			}
		}
		out = append(out, fields)
	}
	return out, true
}

// ---------- tests ----------

// TestOpenAPIMatchesRouter fails when a registered route is undocumented or the
// document lists a route the server does not register.
func TestOpenAPIMatchesRouter(t *testing.T) {
	doc := loadOpenAPI(t)
	documented := documentedRoutes(t, doc)
	registered := registeredRoutes(t)

	var missing, extra []string
	for r, where := range registered {
		if _, ok := documented[r]; !ok {
			missing = append(missing, fmt.Sprintf("%s (registered at %s)", r, where))
		}
	}
	for r := range documented {
		if _, ok := registered[r]; !ok {
			extra = append(extra, r.String())
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, m := range missing {
		t.Errorf("route missing from %s: %s", openAPIPath, m)
	}
	for _, x := range extra {
		t.Errorf("%s documents a route the server does not register: %s", openAPIPath, x)
	}
	t.Logf("%d registered routes, %d documented operations", len(registered), len(documented))
}

// TestOpenAPIOperationsWellFormed checks the per-operation conventions the contract
// promises: unique operationIds, tags, an explicit security requirement, responses,
// declared path parameters, and resolvable local $refs.
func TestOpenAPIOperationsWellFormed(t *testing.T) {
	doc := loadOpenAPI(t)
	ids := map[string]string{}
	for r, op := range documentedRoutes(t, doc) {
		id, _ := op["operationId"].(string)
		if id == "" {
			t.Errorf("%s: missing operationId", r)
		} else if prev, dup := ids[id]; dup {
			t.Errorf("%s: operationId %q already used by %s", r, id, prev)
		} else {
			ids[id] = r.String()
		}
		if tags, _ := op["tags"].([]any); len(tags) == 0 {
			t.Errorf("%s: missing tags", r)
		}
		if _, ok := op["security"]; !ok {
			t.Errorf("%s: missing explicit security requirement", r)
		}
		if resp, _ := op["responses"].(map[string]any); len(resp) == 0 {
			t.Errorf("%s: missing responses", r)
		}
		want := map[string]bool{}
		for _, m := range wildcard.FindAllStringSubmatch(r.Path, -1) {
			want[m[1]] = true
		}
		got := map[string]bool{}
		params, _ := op["parameters"].([]any)
		for _, p := range params {
			pm, _ := resolve(doc, p).(map[string]any)
			if pm["in"] == "path" {
				name, _ := pm["name"].(string)
				got[name] = true
				if pm["required"] != true {
					t.Errorf("%s: path parameter %q must be required", r, name)
				}
			}
		}
		for name := range want {
			if !got[name] {
				t.Errorf("%s: path parameter %q is not declared", r, name)
			}
		}
		for name := range got {
			if !want[name] {
				t.Errorf("%s: declared path parameter %q is not in the path", r, name)
			}
		}
	}
	checkRefs(t, doc, doc, "#")
	checkRequired(t, doc, "#")
}

func resolve(doc map[string]any, node any) any {
	m, ok := node.(map[string]any)
	if !ok {
		return node
	}
	ref, ok := m["$ref"].(string)
	if !ok || !strings.HasPrefix(ref, "#/") {
		return node
	}
	var cur any = doc
	for _, part := range strings.Split(ref[2:], "/") {
		cm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = cm[strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")]
	}
	return cur
}

func checkRefs(t *testing.T, doc map[string]any, node any, at string) {
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := v["$ref"].(string); ok && strings.HasPrefix(ref, "#/") && resolve(doc, v) == nil {
			t.Errorf("%s: unresolvable $ref %q", at, ref)
		}
		for k, c := range v {
			checkRefs(t, doc, c, at+"/"+k)
		}
	case []any:
		for i, c := range v {
			checkRefs(t, doc, c, at+"/"+strconv.Itoa(i))
		}
	}
}

// checkRequired verifies that closed object schemas only require declared members.
func checkRequired(t *testing.T, node any, at string) {
	switch v := node.(type) {
	case map[string]any:
		if req, ok := v["required"].([]any); ok && v["additionalProperties"] == false {
			props, _ := v["properties"].(map[string]any)
			for _, r := range req {
				if name, _ := r.(string); props[name] == nil {
					t.Errorf("%s: required member %q is not a declared property", at, name)
				}
			}
		}
		for k, c := range v {
			checkRequired(t, c, at+"/"+k)
		}
	case []any:
		for i, c := range v {
			checkRequired(t, c, at+"/"+strconv.Itoa(i))
		}
	}
}

// TestJSONSchemasWellFormed parses every JSON document under api/events and
// api/schemas and requires a "$schema" declaration.
func TestJSONSchemasWellFormed(t *testing.T) {
	for _, dir := range []string{"api/events", "api/schemas"} {
		n := 0
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".json") {
				return nil
			}
			n++
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Errorf("%s: invalid JSON: %v", path, err)
				return nil
			}
			if s, _ := doc["$schema"].(string); s == "" {
				t.Errorf("%s: missing \"$schema\"", path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
		if n == 0 {
			t.Errorf("%s: no JSON schema files found", dir)
		}
	}
}

// TestEventCatalogHasSchemas requires a versioned schema for every subscribable
// webhook event type and the delivery envelope.
func TestEventCatalogHasSchemas(t *testing.T) {
	want := append([]string{"envelope"}, webhooks.EventTypes...)
	for _, typ := range want {
		p := filepath.Join(repoRoot, "api/events", typ+".v1.json")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("event type %q has no schema: %v", typ, err)
		}
	}
}
