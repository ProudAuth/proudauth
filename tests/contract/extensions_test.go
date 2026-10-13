package contract

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoEmbeddedCodeExecution covers EXT-013 as ADR 0021 decides it:
// ProudAuth offers no embedded logic, so there is nothing that would need a
// sandbox. No server or tool package imports an interpreter, expression
// language, WASM runtime or Go's plugin loader, go.mod requires none, and the
// only process execution is the operator-configured KMS command. Custom logic
// runs out of process (hooks, webhooks, workflow call_webhook steps).
// Requirements: ARC-007 (no extension code runs inside the server that holds
// the database connection and signing keys).
func TestNoEmbeddedCodeExecution(t *testing.T) {
	// Module path prefixes of embeddable interpreters and runtimes.
	forbidden := []string{
		"github.com/dop251/goja", "github.com/robertkrimen/otto", "github.com/traefik/yaegi", "github.com/yuin/gopher-lua",
		"github.com/Shopify/go-lua", "go.starlark.net", "github.com/google/cel-go", "github.com/expr-lang/expr", "github.com/antonmedv/expr",
		"github.com/Knetic/govaluate", "github.com/tetratelabs/wazero", "github.com/bytecodealliance/wasmtime-go",
		"github.com/wasmerio/wasmer-go", "github.com/open-policy-agent/opa", "rogchap.com/v8go", "github.com/d5/tengo",
	}
	// Process execution is limited to operator configuration, never tenant
	// or request data.
	execAllowed := map[string]bool{"internal/configuration/kms.go": true}

	mod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range forbidden {
		if strings.Contains(string(mod), p) {
			t.Errorf("go.mod requires %s, an embedded code runtime (EXT-013, ADR 0021)", p)
		}
	}
	files := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			files++
			rel, _ := filepath.Rel(repoRoot, path)
			rel = filepath.ToSlash(rel)
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				switch {
				case p == "plugin":
					t.Errorf("%s imports Go's plugin loader (EXT-013, ADR 0021)", rel)
				case p == "os/exec" && !execAllowed[rel]:
					t.Errorf("%s imports os/exec; only the operator-configured KMS command may start processes (EXT-013)", rel)
				}
				for _, bad := range forbidden {
					if p == bad || strings.HasPrefix(p, bad+"/") {
						t.Errorf("%s imports %s, an embedded code runtime (EXT-013, ADR 0021)", rel, p)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if files < 100 {
		t.Fatalf("only %d Go files checked; the layout changed", files)
	}
}
