package contract

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// goImports returns the import paths of every non-test Go file in dir.
func goImports(t *testing.T, dir string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(repoRoot, path)
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			out[filepath.ToSlash(rel)] = append(out[filepath.ToSlash(rel)], p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCustomAPIsVersioned covers API-001 (with API-007 for the documented
// error format): every product-specific route is served under /api/v1, the
// only unversioned routes are standard protocol endpoints (OAuth, OIDC,
// SAML, shared signals, discovery, JWKS, registry tokens), health probes and
// the CORS preflight, and every documented error of a custom API is an RFC
// 9457 problem, while SCIM and the OAuth protocol errors keep their own
// formats.
func TestCustomAPIsVersioned(t *testing.T) {
	protocol := regexp.MustCompile(`^(/realms/\{realm\}/(oauth|oidc|saml|ssf)/|/realms/\{realm\}/\.well-known/|/\.well-known/|/realms/\{realm\}/jwks$|` +
		`/realms/\{realm\}/registry/token$|/health/(live|ready)$)`)
	for r, where := range registeredRoutes(t) {
		switch {
		case strings.HasPrefix(r.Path, "/api/v1/realms/{realm}/") || strings.HasPrefix(r.Path, "/api/v1/"):
		case r.Method == "options" && r.Path == "/realms/{realm}/":
		case protocol.MatchString(r.Path):
		default:
			t.Errorf("%s (%s) is neither versioned under /api/v1 nor a standard protocol endpoint", r, where)
		}
	}
	doc := loadOpenAPI(t)
	for r, op := range documentedRoutes(t, doc) {
		resps, _ := op["responses"].(map[string]any)
		for code, resp := range resps {
			if code < "400" && code != "default" {
				continue
			}
			rm, _ := resolve(doc, resp).(map[string]any)
			content, _ := rm["content"].(map[string]any)
			_, problem := content["application/problem+json"]
			switch {
			case strings.Contains(r.Path, "/scim/v2/"):
				if _, ok := content["application/scim+json"]; !ok || problem {
					t.Errorf("%s %s: SCIM errors must use application/scim+json", r, code)
				}
			case strings.HasPrefix(r.Path, "/api/v1/"):
				if !problem {
					t.Errorf("%s %s: custom API error is not application/problem+json", r, code)
				}
			case strings.HasPrefix(r.Path, "/realms/{realm}/oauth/") && (code == "400" || code == "401"):
				// The errors OAuth defines keep its format; infrastructure
				// failures (unknown realm, throttling, outages) are problems.
				if problem {
					t.Errorf("%s %s: OAuth protocol errors keep their standard format", r, code)
				}
			}
		}
	}
}

// TestBootstrapOnlyThroughOperator covers SEC-011: the first administrator
// is created only by the local operator command; no HTTP route bootstraps a
// realm, and nothing outside cmd/ calls the bootstrap.
func TestBootstrapOnlyThroughOperator(t *testing.T) {
	for r, where := range registeredRoutes(t) {
		if strings.Contains(strings.ToLower(r.Path), "bootstrap") {
			t.Errorf("HTTP route %s (%s) offers bootstrap", r, where)
		}
	}
	callers := 0
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "node_modules" || n == ".git" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !strings.Contains(string(src), ".BootstrapAdmin(") {
			return nil
		}
		rel, _ := filepath.Rel(repoRoot, path)
		rel = filepath.ToSlash(rel)
		if !strings.HasPrefix(rel, "cmd/") {
			t.Errorf("%s calls BootstrapAdmin; only the operator CLI may", rel)
		}
		callers++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers == 0 {
		t.Fatal("no operator bootstrap command found; the check is broken")
	}
}

// TestVettedCryptography covers ARC-009: JOSE, WebAuthn, XML signatures and
// password hashing come from maintained libraries pinned in go.mod and are
// used by the packages that handle them, and no package implements its own
// block cipher or hash.
func TestVettedCryptography(t *testing.T) {
	gomod := readRepoFile(t, "go.mod")
	for _, mod := range []string{"github.com/go-jose/go-jose/v4", "github.com/go-webauthn/webauthn", "github.com/russellhaering/goxmldsig",
		"golang.org/x/crypto", "github.com/pquerna/otp"} {
		if !regexp.MustCompile(`(?m)^\s*(require\s+)?` + regexp.QuoteMeta(mod) + ` v\d+\.\d+\.\d+`).MatchString(gomod) {
			t.Errorf("go.mod does not pin %s", mod)
		}
	}
	uses := func(dir, lib string) {
		t.Helper()
		for _, imports := range goImports(t, dir) {
			for _, p := range imports {
				if p == lib || strings.HasPrefix(p, lib+"/") {
					return
				}
			}
		}
		t.Errorf("%s does not use %s", dir, lib)
	}
	uses("internal/token", "github.com/go-jose/go-jose/v4")
	uses("internal/passkey", "github.com/go-webauthn/webauthn")
	uses("internal/saml", "github.com/russellhaering/goxmldsig")
	uses("internal/credential", "golang.org/x/crypto/argon2")
	uses("internal/credential", "github.com/pquerna/otp")

	primitive := regexp.MustCompile(`(?m)^func \([^)]*\) (BlockSize\(\) int|Sum\(b \[\]byte\) \[\]byte)`)
	for _, dir := range []string{"internal", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(repoRoot, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if primitive.Match(src) {
				t.Errorf("%s implements a hash or block cipher", path)
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, src, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if ts, ok := n.(*ast.TypeSpec); ok && regexp.MustCompile(`(?i)^(aes|sha\d*|hmac|gcm|rsa|ecdsa|ed25519)$`).MatchString(ts.Name.Name) {
					t.Errorf("%s defines a type named like a primitive: %s", path, ts.Name.Name)
				}
				return true
			})
			return nil
		})
	}
}

// TestReleaseSupplyChain covers SEC-016: dependencies are pinned (go.sum,
// pinned tool versions) and updated through reviewed pull requests; release
// artifacts are vulnerability-scanned, described by SBOMs, checksummed,
// signed and attested with build provenance; and the reproducibility limits
// are documented.
func TestReleaseSupplyChain(t *testing.T) {
	release := readRepoFile(t, ".github/workflows/release.yml")
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	for what, re := range map[string]string{
		"full CI before publishing":      `(?m)^\s*needs: \[(?:ci-status, )?ci\]`,
		"vulnerability scan of binaries": `govulncheck@v\d+\.\d+\.\d+ -mode=binary`,
		"source SBOM":                    `syft@v\d+\.\d+\.\d+ dir:\. -o spdx-json=`,
		"image SBOM":                     `syft@v\d+\.\d+\.\d+ \$\{IMAGE\}@\$\{DIGEST\}(?: --platform linux/(?:amd64|arm64))? -o spdx-json=`,
		"checksums":                      `sha256sum > SHA256SUMS`,
		"build provenance":               `uses: actions/attest-build-provenance@[a-f0-9]{40}\b`,
		"SBOM attestation":               `uses: actions/attest-sbom@[a-f0-9]{40}\b`,
		"image signature":                `cosign sign --yes`,
	} {
		if !regexp.MustCompile(re).MatchString(release) {
			t.Errorf("release.yml lacks %s (%s)", what, re)
		}
	}
	if !regexp.MustCompile(`govulncheck@v\d+\.\d+\.\d+`).MatchString(ci) {
		t.Error("ci.yml does not scan for vulnerabilities")
	}
	for _, tool := range regexp.MustCompile(`go run ([^\s@]+)@(\S+)`).FindAllStringSubmatch(release+ci, -1) {
		if !regexp.MustCompile(`^v?\d+\.\d+\.\d+$`).MatchString(tool[2]) {
			t.Errorf("tool %s is not pinned to a release: @%s", tool[1], tool[2])
		}
	}
	if _, err := os.Stat(filepath.Join(repoRoot, "go.sum")); err != nil {
		t.Error("go.sum missing: module versions are not locked")
	}
	dependabot := readRepoFile(t, ".github/dependabot.yml")
	for _, eco := range []string{"gomod", "github-actions", "docker"} {
		if !strings.Contains(dependabot, "package-ecosystem: "+eco) {
			t.Errorf("dependabot does not update %s pins", eco)
		}
	}
	if tm := readRepoFile(t, "docs/threat-models/system.md"); !strings.Contains(tm, "not reproducibly verified") {
		t.Error("the threat model no longer states the reproducibility limit")
	}
}

// TestDeprecationsDocumented covers API-013: the compatibility page states
// the supported API version, what changes without client work, the
// deprecation process and the security exceptions, and an operation can only
// be marked deprecated in the OpenAPI document with a named replacement and
// a CHANGELOG "Deprecated" entry.
func TestDeprecationsDocumented(t *testing.T) {
	page := readRepoFile(t, "docs/protocols/compatibility.md")
	for _, want := range []string{"## Versioned surfaces", "/api/v1/", "## Changes that do not need client work", "## Changes that need client work",
		"### Deprecation process", "### Security exceptions", "**Deprecated**", "**Removed**"} {
		if !strings.Contains(page, want) {
			t.Errorf("docs/protocols/compatibility.md lacks %q", want)
		}
	}
	changelog := readRepoFile(t, "CHANGELOG.md")
	deprecated := ""
	if i := strings.Index(changelog, "### Deprecated"); i >= 0 {
		deprecated = changelog[i:]
	}
	doc := loadOpenAPI(t)
	for r, op := range documentedRoutes(t, doc) {
		if op["deprecated"] != true {
			continue
		}
		if desc, _ := op["description"].(string); !strings.Contains(strings.ToLower(desc), "use ") && !strings.Contains(strings.ToLower(desc), "replace") {
			t.Errorf("%s is deprecated without naming its replacement", r)
		}
		if !strings.Contains(deprecated, r.Path) {
			t.Errorf("%s is deprecated without a CHANGELOG Deprecated entry", r)
		}
	}
}
