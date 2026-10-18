package contract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestHeadlessErrorCodesDocumented covers NFR-009 (clear, stable error codes
// for consuming interfaces): the problem-code table in the Errors section of
// docs/protocols/headless-authentication.md must match the codes the
// transaction API is built from. Every documented code must exist in
// internal/platform/problem with the documented HTTP status, and every
// problem the transaction step implementation can return must be documented
// there, so a login UI can map each one to its own accessible message.
func TestHeadlessErrorCodesDocumented(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join(repoRoot, "docs/protocols/headless-authentication.md"))
	if err != nil {
		t.Fatal(err)
	}
	documented := headlessErrorTable(t, string(doc))
	byVar, byCode := problemCatalog(t)

	for code, status := range documented {
		got, ok := byCode[code]
		if !ok {
			t.Errorf("documented code %q is not a problem code in internal/platform/problem", code)
			continue
		}
		if got != status {
			t.Errorf("documented code %q has status %d, the server answers %d", code, status, got)
		}
	}

	// The transaction API: its HTTP layer and the step implementation.
	files := []string{"internal/httpapi/interaction.go", "internal/authentication/steps.go",
		"internal/authentication/transaction.go", "internal/authentication/flow.go", "internal/authentication/secondfactor.go"}
	for _, f := range files {
		for _, v := range returnedProblems(t, filepath.Join(repoRoot, f)) {
			code, ok := byVar[v]
			if !ok {
				t.Errorf("%s: problem.%s is not declared in internal/platform/problem", f, v)
				continue
			}
			if code == "internal_error" {
				continue // generic, never a stable condition
			}
			if _, ok := documented[code]; !ok {
				t.Errorf("%s can return problem code %q (problem.%s), which the Errors table of headless-authentication.md does not list", f, code, v)
			}
		}
	}
}

// headlessErrorTable parses the "| Status | `code` | When |" table of the
// Errors section into code -> status.
func headlessErrorTable(t *testing.T, doc string) map[string]int {
	t.Helper()
	_, rest, ok := strings.Cut(doc, "\n## Errors\n")
	if !ok {
		t.Fatal("headless-authentication.md has no Errors section")
	}
	if i := strings.Index(rest, "\n#"); i >= 0 {
		rest = rest[:i]
	}
	row := regexp.MustCompile("(?m)^\\| (\\d{3}) \\| `([a-z_]+)` \\|")
	out := map[string]int{}
	for _, m := range row.FindAllStringSubmatch(rest, -1) {
		status, _ := strconv.Atoi(m[1])
		if prev, dup := out[m[2]]; dup && prev != status {
			t.Errorf("code %q documented with statuses %d and %d", m[2], prev, status)
		}
		out[m[2]] = status
	}
	if len(out) < 8 {
		t.Fatalf("parsed only %d codes from the Errors table; the table format changed", len(out))
	}
	return out
}

// problemCatalog reads the stable errors declared with newErr in
// internal/platform/problem/problem.go: variable name -> code and
// code -> HTTP status.
func problemCatalog(t *testing.T) (map[string]string, map[string]int) {
	t.Helper()
	statuses := map[string]int{
		"StatusBadRequest": http.StatusBadRequest, "StatusUnauthorized": http.StatusUnauthorized, "StatusForbidden": http.StatusForbidden,
		"StatusNotFound": http.StatusNotFound, "StatusConflict": http.StatusConflict, "StatusGone": http.StatusGone,
		"StatusPreconditionFailed": http.StatusPreconditionFailed, "StatusPreconditionRequired": http.StatusPreconditionRequired,
		"StatusTooManyRequests": http.StatusTooManyRequests, "StatusServiceUnavailable": http.StatusServiceUnavailable,
		"StatusMisdirectedRequest": http.StatusMisdirectedRequest, "StatusInternalServerError": http.StatusInternalServerError,
		"StatusRequestEntityTooLarge": http.StatusRequestEntityTooLarge, "StatusUnsupportedMediaType": http.StatusUnsupportedMediaType,
		"StatusUnprocessableEntity": http.StatusUnprocessableEntity, "StatusMethodNotAllowed": http.StatusMethodNotAllowed,
		"StatusBadGateway": http.StatusBadGateway, "StatusGatewayTimeout": http.StatusGatewayTimeout, "StatusNotImplemented": http.StatusNotImplemented,
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(repoRoot, "internal/platform/problem/problem.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	byVar, byCode := map[string]string{}, map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != len(vs.Values) {
			return true
		}
		for i, v := range vs.Values {
			call, ok := v.(*ast.CallExpr)
			if !ok || len(call.Args) < 2 {
				continue
			}
			if fn, ok := call.Fun.(*ast.Ident); !ok || fn.Name != "newErr" {
				continue
			}
			sel, ok1 := call.Args[0].(*ast.SelectorExpr)
			lit, ok2 := call.Args[1].(*ast.BasicLit)
			if !ok1 || !ok2 {
				t.Fatalf("%s: newErr arguments are not http.Status* and a string literal", vs.Names[i].Name)
			}
			status, known := statuses[sel.Sel.Name]
			if !known {
				t.Fatalf("%s uses http.%s; add it to the status table of this test", vs.Names[i].Name, sel.Sel.Name)
			}
			code, _ := strconv.Unquote(lit.Value)
			byVar[vs.Names[i].Name] = code
			byCode[code] = status
		}
		return true
	})
	if len(byVar) < 20 {
		t.Fatalf("found only %d problem errors; problem.go changed shape", len(byVar))
	}
	return byVar, byCode
}

// returnedProblems lists the problem.Err* variables a file uses, except
// those it only compares an error against (the second argument of
// problem.Is), sorted and de-duplicated.
func returnedProblems(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	isProblem := func(e ast.Expr) (string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", false
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "problem" || !strings.HasPrefix(sel.Sel.Name, "Err") || sel.Sel.Name == "Error" {
			return "", false
		}
		return sel.Sel.Name, true
	}
	compared := map[ast.Expr]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && len(call.Args) == 2 {
			if fn, ok := call.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "Is" {
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "problem" {
					compared[call.Args[1]] = true
				}
			}
		}
		return true
	})
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		e, ok := n.(ast.Expr)
		if !ok || compared[e] {
			return true
		}
		if name, ok := isProblem(e); ok {
			seen[name] = true
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
