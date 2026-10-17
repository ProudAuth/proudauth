package contract

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/proudauth/proudauth/internal/configuration"
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
	Strategy struct {
		Matrix map[string][]any `yaml:"matrix"`
	} `yaml:"strategy"`
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
// the race detector against PostgreSQL: the test job runs every package but
// tests/e2e, and the e2e job runs tests/e2e in parallel shards
// (scripts/e2e-shard.sh). Both pipe `go test -json` through
// internal/tools/testreport with tests/skip-allowlist.txt, so a test that
// skips outside the allowlist, a package that fails to build or a -run
// pattern that matches nothing fails the job instead of passing silently.
// Every fuzz target CI and `make fuzz` name exists (go test -fuzz with a
// pattern that matches nothing passes without fuzzing), and the release
// publishes only after the whole CI workflow has passed.
func TestCIRunsSecurityTests(t *testing.T) {
	ci := govLoadWorkflow(t, ".github/workflows/ci.yml")
	if _, ok := ci.On["pull_request"]; !ok {
		t.Error("ci.yml does not run on pull requests")
	}
	test, ok := ci.Jobs["test"]
	if !ok {
		t.Fatal("ci.yml has no test job")
	}
	e2e, ok := ci.Jobs["e2e"]
	if !ok {
		t.Fatal("ci.yml has no e2e job")
	}
	for name, job := range map[string]govJob{"test": test, "e2e": e2e} {
		if job.Env["PROUDAUTH_TEST_DATABASE_URL"] == "" || job.Services["postgres"] == nil {
			t.Errorf("the %s job must provide a PostgreSQL service and PROUDAUTH_TEST_DATABASE_URL; without them the database tests skip", name)
		}
		runs := job.runs()
		if !strings.Contains(runs, "go run ./internal/tools/testreport") || !strings.Contains(runs, "-allowlist tests/skip-allowlist.txt") || !strings.Contains(runs, "-require-tests") {
			t.Errorf("the %s job must pipe go test -json through internal/tools/testreport with tests/skip-allowlist.txt and -require-tests, so a skipped test or an empty -run pattern fails the job", name)
		}
		if !strings.Contains(runs, "set -o pipefail") {
			t.Errorf("the %s job pipes go test into testreport without pipefail, so a go test failure could be lost", name)
		}
		if regexp.MustCompile(`-coverprofile|-cover\b`).MatchString(runs) {
			t.Errorf("the %s job gates on coverage; QA-001 requires direct tests of invariants, not a coverage number", name)
		}
	}
	runs := test.runs()
	if !regexp.MustCompile(`(?m)^go test \$\(go list \./\.\.\. \| grep -v '/tests/e2e\$'\) .*-race .*-json`).MatchString(runs) {
		t.Error("the test job must run go test with -race and -json over every package except tests/e2e")
	}
	shards := e2e.Strategy.Matrix["shard"]
	if len(shards) < 2 {
		t.Errorf("the e2e job runs %d shard(s); the suite is sharded so a pull request gets its result in parallel", len(shards))
	}
	shardRun := regexp.MustCompile(`\./scripts/e2e-shard\.sh \$\{\{ matrix\.shard \}\} (\d+) .*-race .*-json`).FindStringSubmatch(e2e.runs())
	if shardRun == nil {
		t.Error("the e2e job must run ./scripts/e2e-shard.sh ${{ matrix.shard }} <total> with -race and -json")
	} else if shardRun[1] != strconv.Itoa(len(shards)) {
		t.Errorf("e2e-shard.sh runs %s shards but the matrix has %d; a test would never run", shardRun[1], len(shards))
	}
	if st, err := os.Stat(filepath.Join(repoRoot, "scripts/e2e-shard.sh")); err != nil || st.Mode()&0o111 == 0 {
		t.Errorf("scripts/e2e-shard.sh must exist and be executable: %v", err)
	}
	if !ci.Jobs["image"].needs("e2e") || !ci.Jobs["image"].needs("test") {
		t.Error("the image job must need the test and e2e jobs: image is a required check, so a failing shard must block it")
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

// TestSkipAllowlistNamesRealTests keeps tests/skip-allowlist.txt honest: every
// entry has a reason and names a test that exists in the package it points
// to, so an allowed skip cannot outlive the test or hide a typo.
func TestSkipAllowlistNamesRealTests(t *testing.T) {
	const module = "github.com/proudauth/proudauth"
	text := govRead(t, "tests/skip-allowlist.txt")
	for i, line := range strings.Split(text, "\n") {
		reason := ""
		if j := strings.Index(line, "#"); j >= 0 {
			reason = strings.TrimSpace(line[j+1:])
			line = line[:j]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 || reason == "" {
			t.Errorf("tests/skip-allowlist.txt:%d: want \"<package> <Test> # reason\"", i+1)
			continue
		}
		dir := strings.TrimPrefix(f[0], module+"/")
		top, _, _ := strings.Cut(f[1], "/")
		files, _ := filepath.Glob(filepath.Join(repoRoot, dir, "*_test.go"))
		found := false
		for _, file := range files {
			b, err := os.ReadFile(file)
			if err == nil && strings.Contains(string(b), "func "+top+"(") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("tests/skip-allowlist.txt:%d: no test %s in %s", i+1, top, dir)
		}
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
	security := []string{"@ProudAuth/security-reviewers"}
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
// CHANGELOG section as release notes (refused without a Known limitations
// heading), the binaries with checksums, SBOMs, build provenance attestations
// and a signed image; the CHANGELOG keeps breaking changes, security fixes
// (with advisories) and known limitations in their own sections, links every
// version, and points to the history before the first tag in docs/history/.
// The only other trigger is the manual dry run, which publishes nothing.
func TestReleaseTransparency(t *testing.T) {
	raw := govRead(t, ".github/workflows/release.yml")
	rel := govLoadWorkflow(t, ".github/workflows/release.yml")
	if _, dispatch := rel.On["workflow_dispatch"]; !regexp.MustCompile(`(?m)^\s+tags: \["v\*"\]`).MatchString(raw) || rel.On["push"] == nil || !dispatch || len(rel.On) != 2 {
		t.Errorf("the release workflow must run for pushed v* tags and the manual dry run only: %v", rel.On)
	}
	job, ok := rel.Jobs["release"]
	if !ok {
		t.Fatal("release.yml has no release job")
	}
	if job.Env["DRY_RUN"] != "${{ github.event_name == 'workflow_dispatch' }}" {
		t.Errorf("the release job must derive DRY_RUN from the manual trigger, got %q", job.Env["DRY_RUN"])
	}
	for _, step := range job.Steps {
		if strings.Contains(step.Run, "gh release create") || strings.Contains(step.Run, "/dispatches") {
			if !regexp.MustCompile(`(?s)\[ "\$DRY_RUN" = true \].*?exit 0.*?(gh release create|gh api)`).MatchString(step.Run) {
				t.Errorf("step %q must stop before publishing when DRY_RUN is true", step.Name)
			}
		}
	}
	runs, uses := job.runs(), strings.Join(job.uses(), "\n")
	if !strings.Contains(runs, `grep -q '^### Known limitations' dist/RELEASE_NOTES.md`) {
		t.Error("the release job must refuse a CHANGELOG section without a '### Known limitations' heading")
	}
	for _, c := range []struct{ what, re, in string }{
		{"binaries for every platform", `for os in linux darwin; do for arch in amd64 arm64`, runs},
		{"checksums of every release file", `sha256sum > SHA256SUMS`, runs},
		{"a source SBOM", `syft@v[\d.]+ dir:\. -o spdx-json=dist/sbom\.spdx\.json`, runs},
		{"an image SBOM", `-o spdx-json=dist/image-sbom\.spdx\.json`, runs},
		{"an image signature", `cosign sign --yes`, runs},
		{"release notes from the CHANGELOG", `--notes-file dist/RELEASE_NOTES\.md`, runs},
		{"a release bound to the existing tag", `(?s)gh release create "\$\{RELEASE_TAG\}" .*?--verify-tag`, runs},
		{"build provenance attestations", `actions/attest-build-provenance@`, uses},
		{"an SBOM attestation", `actions/attest-sbom@`, uses},
	} {
		if !regexp.MustCompile(c.re).MatchString(c.in) {
			t.Errorf("the release job does not publish %s", c.what)
		}
	}

	// The release notes are exactly the tag's CHANGELOG section (the
	// Unreleased section on a dry run).
	if !strings.Contains(raw, "section=${RELEASE_TAG#v}") || !strings.Contains(raw, `[ "$DRY_RUN" = true ] && section=Unreleased`) {
		t.Error("the release-notes step must select the tag's section, or Unreleased on a dry run")
	}
	m := regexp.MustCompile(`awk -v v="\$section" '([^']+)' CHANGELOG\.md > dist/RELEASE_NOTES\.md`).FindStringSubmatch(raw)
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
	notesFrom := func(file, version string) string {
		out, err := exec.Command("awk", "-v", "v="+version, m[1], file).Output()
		if err != nil {
			t.Fatalf("release-notes awk program: %v", err)
		}
		return string(out)
	}
	notes := func(version string) string { return notesFrom(changelog, version) }
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

	// The CHANGELOG has the sections the notes are made of. Keep a Changelog
	// names the security section "Security"; SECURITY.md and the development
	// history call it "Security fixes".
	cl := govRead(t, "CHANGELOG.md")
	for _, h := range [][]string{{"## [Unreleased]"}, {"### Changed"}, {"### Security", "### Security fixes"}, {"### Known limitations"}} {
		if !slices.ContainsFunc(h, func(s string) bool { return strings.Contains(cl, "\n"+s+"\n") }) {
			t.Errorf("CHANGELOG.md has no %q section", strings.Join(h, `" or "`))
		}
	}

	// Each version heading has its Keep a Changelog link: Unreleased compares
	// the latest tag with main, a version compares with the one before it,
	// and the oldest links its tag. The development history before the first
	// tag lives in docs/history/, linked under a heading of its own, so the
	// link block never ends up in a version's release notes.
	const repo = "https://github.com/proudauth/proudauth/"
	versions := regexp.MustCompile(`(?m)^## \[([^\]]+)\]`).FindAllStringSubmatch(cl, -1)
	linkDef := regexp.MustCompile(`(?m)^\[[^\]]+\]: https://`)
	if len(versions) < 2 || versions[0][1] != "Unreleased" {
		t.Fatalf("CHANGELOG.md must start with [Unreleased] followed by the released versions, got %q", versions)
	}
	for i, v := range versions {
		want := repo + "releases/tag/v" + v[1]
		if i == 0 {
			want = repo + "compare/v" + versions[1][1] + "...main"
		} else if i < len(versions)-1 {
			want = repo + "compare/v" + versions[i+1][1] + "...v" + v[1]
		}
		if !strings.Contains(cl, "\n["+v[1]+"]: "+want+"\n") {
			t.Errorf("CHANGELOG.md lacks the link [%s]: %s", v[1], want)
		}
		if i > 0 {
			if got := notesFrom(filepath.Join(repoRoot, "CHANGELOG.md"), v[1]); linkDef.MatchString(got) {
				t.Errorf("release notes for %s include the link block:\n%s", v[1], got)
			}
		}
	}
	if !strings.Contains(cl, "](docs/history/CHANGELOG-pre-0.2.0.md)") ||
		!strings.Contains(govRead(t, "docs/history/CHANGELOG-pre-0.2.0.md"), "\n## Historical development before 0.2.0-alpha.1\n") {
		t.Error("CHANGELOG.md must link the development history before the first tag, docs/history/CHANGELOG-pre-0.2.0.md")
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
