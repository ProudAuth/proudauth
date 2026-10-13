package contract

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/proudbase/proudauth/internal/configuration"
)

// Static checks of the repository's quality and governance controls: what CI
// runs, who must review what, how a release is published and what the
// project promises not to contain. They read files only and need no
// database.

type govWorkflow struct {
	On   map[string]any    `yaml:"on"`
	Jobs map[string]govJob `yaml:"jobs"`
}

type govJob struct {
	Needs    any               `yaml:"needs"`
	Uses     string            `yaml:"uses"`
	Services map[string]any    `yaml:"services"`
	Env      map[string]string `yaml:"env"`
	Steps    []govStep         `yaml:"steps"`
}

type govStep struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
}

// runs joins the job's shell steps.
func (j govJob) runs() string {
	var b strings.Builder
	for _, s := range j.Steps {
		b.WriteString(s.Run)
		b.WriteString("\n")
	}
	return b.String()
}

// uses lists the actions the job's steps use.
func (j govJob) uses() []string {
	var out []string
	for _, s := range j.Steps {
		if s.Uses != "" {
			out = append(out, s.Uses)
		}
	}
	return out
}

func (j govJob) needs(job string) bool {
	switch n := j.Needs.(type) {
	case string:
		return n == job
	case []any:
		return slices.Contains(n, any(job))
	}
	return false
}

func govRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func govLoadWorkflow(t *testing.T, rel string) govWorkflow {
	t.Helper()
	var w govWorkflow
	if err := yaml.Unmarshal([]byte(govRead(t, rel)), &w); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	if len(w.Jobs) == 0 {
		t.Fatalf("%s defines no jobs", rel)
	}
	return w
}

// TestCIRunsSecurityTests covers QA-001: the critical-invariant tests are
// what gates a change, not a coverage percentage. CI runs every Go test with
// the race detector against PostgreSQL (without a database the end-to-end
// security tests skip and still pass), every fuzz target CI and `make fuzz`
// name exists (go test -fuzz with a pattern that matches nothing passes
// without fuzzing), and the release publishes only after the whole CI
// workflow has passed.
func TestCIRunsSecurityTests(t *testing.T) {
	ci := govLoadWorkflow(t, ".github/workflows/ci.yml")
	if _, ok := ci.On["pull_request"]; !ok {
		t.Error("ci.yml does not run on pull requests")
	}
	test, ok := ci.Jobs["test"]
	if !ok {
		t.Fatal("ci.yml has no test job")
	}
	if test.Env["PROUDAUTH_TEST_DATABASE_URL"] == "" || test.Services["postgres"] == nil {
		t.Error("the test job must provide a PostgreSQL service and PROUDAUTH_TEST_DATABASE_URL; without them the end-to-end tests skip and pass")
	}
	runs := test.runs()
	if !regexp.MustCompile(`(?m)^go test \./\.\.\. .*-race`).MatchString(runs) {
		t.Error("the test job must run go test ./... with -race")
	}
	if regexp.MustCompile(`-coverprofile|-cover\b`).MatchString(runs) {
		t.Error("the test job gates on coverage; QA-001 requires direct tests of invariants, not a coverage number")
	}

	fuzz := regexp.MustCompile(`go test (\./\S+) -run '\^\$\$?' -fuzz '\^(Fuzz\w+)\$\$?'`)
	targets := fuzz.FindAllStringSubmatch(runs, -1)
	if len(targets) < 8 {
		t.Fatalf("the fuzz smoke runs %d targets; the parsers of untrusted input need theirs", len(targets))
	}
	targets = append(targets, fuzz.FindAllStringSubmatch(govRead(t, "Makefile"), -1)...)
	for _, m := range targets {
		dir, name := filepath.Join(repoRoot, m[1]), m[2]
		files, _ := filepath.Glob(filepath.Join(dir, "*_test.go"))
		found := false
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err == nil && strings.Contains(string(b), "func "+name+"(f *testing.F)") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("fuzz target %s is not defined in %s: go test -fuzz would pass without fuzzing", name, m[1])
		}
	}

	rel := govLoadWorkflow(t, ".github/workflows/release.yml")
	if rel.Jobs["ci"].Uses != "./.github/workflows/ci.yml" || !rel.Jobs["release"].needs("ci") {
		t.Error("the release job must need a ci job that calls .github/workflows/ci.yml")
	}
}

// TestCIStaticAndDependencyChecks covers QA-002: CI runs linting, type
// checks, dependency vulnerability review, secret scanning and the license
// policy, with pinned tools, and every path the secret scan skips is a
// triaged exception listed with its reason in
// docs/operations/security-checks.md.
func TestCIStaticAndDependencyChecks(t *testing.T) {
	ci := govLoadWorkflow(t, ".github/workflows/ci.yml")
	var all strings.Builder
	for _, j := range ci.Jobs {
		all.WriteString(j.runs())
	}
	for _, c := range []struct{ what, re string }{
		{"type checks (go build)", `go build \./\.\.\.`},
		{"go vet", `go vet \./\.\.\.`},
		{"the gofmt check", `gofmt -l`},
		{"staticcheck at a pinned version", `staticcheck@\d+\.\d+\.\d+ \./\.\.\.`},
		{"govulncheck at a pinned version", `govulncheck@v\d+\.\d+\.\d+ \./\.\.\.`},
		{"the secret scan", `\./scripts/check-secrets\.sh`},
		{"the license policy", `\./scripts/check-licenses\.sh`},
	} {
		if !regexp.MustCompile(c.re).MatchString(all.String()) {
			t.Errorf("ci.yml does not run %s", c.what)
		}
	}
	for _, s := range []string{"scripts/check-secrets.sh", "scripts/check-licenses.sh"} {
		st, err := os.Stat(filepath.Join(repoRoot, s))
		if err != nil || st.Mode()&0o111 == 0 {
			t.Errorf("%s is missing or not executable: %v", s, err)
		}
	}

	scan := govRead(t, "scripts/check-secrets.sh")
	m := regexp.MustCompile(`grep -v -E '\^\(\\\./\)\?\(([^']*)\)'`).FindStringSubmatch(scan)
	if m == nil {
		t.Fatal("cannot find the secret scan's path exclusions in scripts/check-secrets.sh")
	}
	register := govRead(t, "docs/operations/security-checks.md")
	if !strings.Contains(register, "## Exceptions") {
		t.Fatal("docs/operations/security-checks.md has no Exceptions section")
	}
	clean := strings.NewReplacer(`\.`, ".", "$", "", ".*", "*")
	for _, alt := range strings.Split(m[1], "|") {
		p := clean.Replace(alt)
		if p == "scripts/check-secrets.sh" {
			continue // the scanner holds the patterns it looks for
		}
		if !strings.Contains(register, "`"+p+"`") {
			t.Errorf("the secret scan skips %s, which docs/operations/security-checks.md does not list as a triaged exception", p)
		}
	}
}

// codeOwnerRule is one CODEOWNERS line.
type codeOwnerRule struct {
	pattern string
	owners  []string
}

// owner returns the owners of a repository path: the last matching rule
// wins. Only the pattern forms this repository uses are supported: "*",
// "/dir/" and "/file".
func codeOwnersOf(rules []codeOwnerRule, path string) []string {
	var out []string
	for _, r := range rules {
		p := strings.TrimPrefix(r.pattern, "/")
		switch {
		case r.pattern == "*":
			out = r.owners
		case strings.HasSuffix(p, "/") && strings.HasPrefix(path, p):
			out = r.owners
		case path == p:
			out = r.owners
		}
	}
	return out
}

// TestCodeOwnersReviewBoundaries covers GOV-004: authentication,
// authorization, cryptography, migrations, impersonation and release
// infrastructure are owned by the security reviewers alone, so a code-owner
// approval for them always comes from a security reviewer; every rule names
// a path that exists; and the contribution rules say passing tests are not
// enough to merge a security-sensitive change.
func TestCodeOwnersReviewBoundaries(t *testing.T) {
	var rules []codeOwnerRule
	for i, line := range strings.Split(govRead(t, ".github/CODEOWNERS"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			t.Fatalf("CODEOWNERS line %d has no owner: %q", i+1, line)
		}
		if f[0] != "*" {
			if _, err := os.Stat(filepath.Join(repoRoot, strings.TrimPrefix(f[0], "/"))); err != nil {
				t.Errorf("CODEOWNERS rule %s names a path that does not exist", f[0])
			}
		}
		rules = append(rules, codeOwnerRule{pattern: f[0], owners: f[1:]})
	}
	if len(rules) == 0 || rules[0].pattern != "*" {
		t.Fatal("CODEOWNERS must start with a default rule so no path is unowned")
	}
	security := []string{"@proudbase/security-reviewers"}
	for area, paths := range map[string][]string{
		"authentication": {"internal/authentication/", "internal/session/", "internal/credential/", "internal/passkey/", "internal/federation/",
			"internal/oauth/", "internal/token/", "internal/saml/", "internal/certauth/", "internal/application/", "internal/httpapi/auth.go",
			"internal/httpapi/clientcert.go"},
		"authorization":  {"internal/authorization/"},
		"cryptography":   {"internal/keys/", "internal/platform/secret/"},
		"migrations":     {"migrations/", "internal/migrate/"},
		"impersonation":  {"internal/impersonation/"},
		"release":        {".github/workflows/release.yml", ".github/workflows/ci.yml", ".github/CODEOWNERS", "Dockerfile", ".dockerignore", "Makefile", "scripts/offline-bundle.sh", "go.mod", "go.sum"},
		"review process": {"scripts/check-secrets.sh", "scripts/check-licenses.sh"},
	} {
		for _, p := range paths {
			if _, err := os.Stat(filepath.Join(repoRoot, p)); err != nil {
				t.Errorf("%s path %s does not exist; update this test", area, p)
				continue
			}
			probe := p
			if strings.HasSuffix(p, "/") {
				probe = p + "probe.go"
			}
			if got := codeOwnersOf(rules, probe); !slices.Equal(got, security) {
				t.Errorf("%s path %s is owned by %v, want only %v", area, p, got, security)
			}
		}
	}
	// A path outside the sensitive areas keeps the default owners, so the
	// matcher above is not trivially satisfied.
	if got := codeOwnersOf(rules, "internal/httpapi/routes.go"); slices.Equal(got, security) {
		t.Errorf("the CODEOWNERS matcher assigns security reviewers everywhere: %v", got)
	}
	if !strings.Contains(govRead(t, "CONTRIBUTING.md"), "Passing tests are not sufficient") {
		t.Error("CONTRIBUTING.md must state that passing tests are not sufficient for security-sensitive changes")
	}
}

// TestReleaseTransparency covers GOV-005: releases are cut only from version
// tags through the release workflow, which publishes the tag's own
// CHANGELOG section as release notes, the binaries with checksums, SBOMs,
// build provenance attestations and a signed image; the CHANGELOG keeps
// breaking changes, security fixes (with advisories) and known limitations
// in their own sections.
func TestReleaseTransparency(t *testing.T) {
	raw := govRead(t, ".github/workflows/release.yml")
	rel := govLoadWorkflow(t, ".github/workflows/release.yml")
	if !regexp.MustCompile(`(?m)^\s+tags: \["v\*"\]`).MatchString(raw) || rel.On["push"] == nil || len(rel.On) != 1 {
		t.Errorf("the release workflow must run only for pushed v* tags: %v", rel.On)
	}
	job, ok := rel.Jobs["release"]
	if !ok {
		t.Fatal("release.yml has no release job")
	}
	runs, uses := job.runs(), strings.Join(job.uses(), "\n")
	for _, c := range []struct{ what, re, in string }{
		{"binaries for every platform", `for os in linux darwin; do for arch in amd64 arm64`, runs},
		{"checksums of every release file", `sha256sum > SHA256SUMS`, runs},
		{"a source SBOM", `syft@v[\d.]+ dir:\. -o spdx-json=dist/sbom\.spdx\.json`, runs},
		{"an image SBOM", `-o spdx-json=dist/image-sbom\.spdx\.json`, runs},
		{"an image signature", `cosign sign --yes`, runs},
		{"release notes from the CHANGELOG", `--notes-file dist/RELEASE_NOTES\.md`, runs},
		{"a release bound to the existing tag", `(?s)gh release create "\$\{GITHUB_REF_NAME\}" .*?--verify-tag`, runs},
		{"build provenance attestations", `actions/attest-build-provenance@`, uses},
		{"an SBOM attestation", `actions/attest-sbom@`, uses},
	} {
		if !regexp.MustCompile(c.re).MatchString(c.in) {
			t.Errorf("the release job does not publish %s", c.what)
		}
	}

	// The release notes are exactly the tag's CHANGELOG section.
	m := regexp.MustCompile(`awk -v v="\$\{GITHUB_REF_NAME#v\}" '([^']+)' CHANGELOG\.md > dist/RELEASE_NOTES\.md`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("cannot find the release-notes step in release.yml")
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk is not installed")
	}
	changelog := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(changelog, []byte(`# Changelog

## [Unreleased]

### Added

- unreleased item

## [1.2.0] - 2026-10-01

### Changed

- breaking change A

### Security fixes

- fix B (GHSA-0000-0000-0000)

### Known limitations

- limitation C

## [1.1.0] - 2026-09-01

### Added

- old item
`), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := func(version string) string {
		out, err := exec.Command("awk", "-v", "v="+version, m[1], changelog).Output()
		if err != nil {
			t.Fatalf("release-notes awk program: %v", err)
		}
		return string(out)
	}
	got := notes("1.2.0")
	for _, want := range []string{"## [1.2.0] - 2026-10-01", "breaking change A", "fix B (GHSA-0000-0000-0000)", "limitation C"} {
		if !strings.Contains(got, want) {
			t.Errorf("release notes for 1.2.0 lack %q:\n%s", want, got)
		}
	}
	for _, other := range []string{"unreleased item", "old item", "[1.1.0]"} {
		if strings.Contains(got, other) {
			t.Errorf("release notes for 1.2.0 include %q from another section:\n%s", other, got)
		}
	}
	if got := notes("1.3.0"); strings.TrimSpace(got) != "" {
		t.Errorf("a tag without a CHANGELOG section must produce empty notes (the step then fails), got:\n%s", got)
	}

	// The CHANGELOG has the sections the notes are made of.
	cl := govRead(t, "CHANGELOG.md")
	for _, h := range []string{"## [Unreleased]", "### Changed", "### Security fixes", "### Known limitations"} {
		if !strings.Contains(cl, "\n"+h+"\n") {
			t.Errorf("CHANGELOG.md has no %q section", h)
		}
	}
	if !strings.Contains(cl, "breaking changes") || !strings.Contains(strings.ToLower(govRead(t, "SECURITY.md")), "advisor") {
		t.Error("CHANGELOG.md must say where breaking changes are listed and SECURITY.md how advisories are published")
	}
}

// TestNoEditionGating covers GOV-007: there is no privileged paid branch.
// No code or published contract has an edition, licence-key or paid-tier
// gate; the default configuration names no outbound endpoint, so nothing
// depends on a project-operated control plane; and the dependency licence
// policy CI enforces admits only open-source licences.
func TestNoEditionGating(t *testing.T) {
	gate := regexp.MustCompile(`(?i)(enterprise[_-]?(only|edition|feature|tier|plan|license)|is_?enterprise|\beditions?\b|licen[cs]e[_-]?(key|server|check|token|tier|file)|premium|paid[_-]?(tier|plan|feature|only)|subscription[_-]?(tier|plan|level)|activation[_-]?(key|code)|x-(enterprise|edition|paid|premium))`)
	scanned := 0
	for _, root := range []string{"internal", "cmd", "api"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			ext := filepath.Ext(path)
			if strings.HasSuffix(path, "_test.go") || strings.Contains(path, string(filepath.Separator)+"testdata"+string(filepath.Separator)) ||
				(ext != ".go" && ext != ".json" && ext != ".yaml" && ext != ".yml") {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			scanned++
			if loc := gate.FindIndex(b); loc != nil {
				rel, _ := filepath.Rel(repoRoot, path)
				t.Errorf("%s contains %q: editions, licence keys and paid tiers are not part of this project", rel, b[loc[0]:loc[1]])
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files", scanned)
	}

	// No default outbound endpoint: every connector is configured by the
	// operator, so a deployment needs no service the project operates.
	var walk func(v reflect.Value, at string)
	walk = func(v reflect.Value, at string) {
		switch v.Kind() {
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem(), at)
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i), at+"."+v.Type().Field(i).Name)
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i), at)
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				walk(v.MapIndex(k), at)
			}
		case reflect.String:
			if strings.Contains(v.String(), "://") {
				t.Errorf("default configuration %s points at %q", at, v.String())
			}
		}
	}
	walk(reflect.ValueOf(configuration.Defaults()), "Config")

	// The licence policy admits open-source licences only.
	m := regexp.MustCompile(`(?m)^allowed='([^']+)'`).FindStringSubmatch(govRead(t, "scripts/check-licenses.sh"))
	if m == nil {
		t.Fatal("cannot find the allowed licences in scripts/check-licenses.sh")
	}
	open := []string{"Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MPL-2.0", "0BSD", "Unlicense", "CC0-1.0"}
	for _, l := range strings.Split(m[1], "|") {
		if !slices.Contains(open, l) {
			t.Errorf("the licence policy admits %s, which is not an open-source licence this project accepts", l)
		}
	}
}

// TestNotificationsCarryNoAttachments covers MIG-015 for delivery: messages
// are built as plain text or text and HTML alternatives only, so no export or
// migration archive can leave as an email attachment; archives are fetched
// through the authenticated, single-use download API instead.
func TestNotificationsCarryNoAttachments(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot, "internal/notification/*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no notification sources: %v", err)
	}
	built := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		built = built || strings.Contains(s, "multipart/alternative")
		for _, bad := range []string{"multipart/mixed", "Content-Disposition", "attachment"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s builds mail with %q", filepath.Base(f), bad)
			}
		}
	}
	if !built {
		t.Fatal("the mail builder was not found (multipart/alternative); update this test")
	}
}
