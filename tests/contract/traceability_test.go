package contract

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestRequirementsTraceability keeps docs/requirements-traceability.md in
// step with docs/plan.md and the repository: every requirement and TEST case
// of the plan is listed with the tests, code and documents that cite its ID.
// It fails when a P0–P2 requirement has no evidence at all, when a TEST case
// is cited by no test, when a partial entry is cited by no test, or when the
// committed matrix is stale. This file itself is not evidence (see
// generatorFile). Regenerate the matrix with
// PROUDAUTH_REGENERATE_TRACEABILITY=1 go test ./tests/contract -run TestRequirementsTraceability.
func TestRequirementsTraceability(t *testing.T) {
	const root = "../.."
	plan, err := os.ReadFile(filepath.Join(root, "docs/plan.md"))
	if err != nil {
		t.Fatal(err)
	}
	reqs, cases := parsePlan(string(plan))
	if len(reqs) < 500 || len(cases) < 70 {
		t.Fatalf("parsed %d requirements and %d TEST cases from docs/plan.md; the plan format changed", len(reqs), len(cases))
	}
	known := map[string]bool{}
	for _, r := range reqs {
		known[r.id] = true
	}
	for _, c := range cases {
		known[c.id] = true
	}
	ev, err := collectEvidence(root, known)
	if err != nil {
		t.Fatal(err)
	}
	for id := range notOffered {
		if !known[id] {
			t.Errorf("notOffered names %s, which is not in docs/plan.md", id)
		}
	}
	for id := range byDocument {
		if !known[id] {
			t.Errorf("byDocument names %s, which is not in docs/plan.md", id)
		}
	}
	for id := range openExternal {
		if !known[id] {
			t.Errorf("openExternal names %s, which is not in docs/plan.md", id)
		}
	}
	for id := range partial {
		if !known[id] {
			t.Errorf("partial names %s, which is not in docs/plan.md", id)
		} else if len(ev[id].tests) == 0 {
			t.Errorf("partial names %s, which no test cites; Partial needs test evidence", id)
		}
	}
	for _, r := range reqs {
		st := status(r, ev[r.id])
		if st == "Missing" && r.priority != "P3" {
			t.Errorf("%s [%s] %s: no test, code or document cites it", r.id, r.priority, r.title)
		}
		if r.priority == "P3" && st != "Tested" && notOffered[r.id] == "" {
			t.Errorf("%s [P3] is neither tested nor listed as not offered", r.id)
		}
	}
	for _, c := range cases {
		if len(ev[c.id].tests) == 0 {
			t.Errorf("%s (%s): no test cites it", c.id, c.title)
		}
	}
	doc := renderMatrix(reqs, cases, ev)
	path := filepath.Join(root, "docs/requirements-traceability.md")
	if os.Getenv("PROUDAUTH_REGENERATE_TRACEABILITY") == "1" {
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	current, err := os.ReadFile(path)
	if err != nil || string(current) != doc {
		t.Errorf("docs/requirements-traceability.md is stale; regenerate it with PROUDAUTH_REGENERATE_TRACEABILITY=1")
	}
}

// notOffered lists the P3 requirements this release deliberately does not
// implement (docs/plan.md section 35.1: M5 is a selection of P3 capabilities,
// and the release states its subset). Each is documented as not offered in
// docs/protocols/compatibility.md and nothing advertises it.
var notOffered = map[string]string{
	"MFA-014":  "no push or out-of-band approval channel ([compatibility.md](protocols/compatibility.md))",
	"ADV-005":  "no CIBA endpoint, and discovery advertises none ([compatibility.md](protocols/compatibility.md))",
	"ADV-006":  "no UMA profile ([compatibility.md](protocols/compatibility.md))",
	"ADV-008":  "no verifiable-credential issuer ([compatibility.md](protocols/compatibility.md))",
	"ADV-009":  "no credential presentation or wallet federation ([compatibility.md](protocols/compatibility.md))",
	"PROV-015": "no Kerberos/SPNEGO module; keytab custody, cross-realm trust, a shared replay cache and a KDC test harness are not designed yet ([directory.md](integrations/directory.md#kerberos-and-spnego-are-not-offered), [ADR 0018](architecture-decisions/0018-enterprise-protocols-deferred.md))",
	"API-014":  "no gRPC management interface, so no alternate administrative path exists ([compatibility.md](protocols/compatibility.md))",
}

// byDocument lists requirements whose evidence is a document or a repository
// policy rather than code: licensing, governance, process and deployment
// decisions. Every other P0–P2 requirement must be cited by code or a test.
var byDocument = map[string]string{
	"OSS-001": "one source tree and one build, no edition split ([README](../README.md), [ADR 0003](architecture-decisions/0003-apache-2-license.md))",
	"OSS-002": "no license server, activation key or usage counter in the code ([README](../README.md))",
	"OSS-004": "service source, migrations, deployments and tests live here; SDKs have independently buildable public repositories and a pinned Go dependency ([repository-migration.md](repository-migration.md), [sdk-compatibility.md](integrations/sdk-compatibility.md))",
	"OSS-009": "cost statement in the [README](../README.md)",
	"ARC-010": "[ADR 0001](architecture-decisions/0001-modular-monolith.md): one deployable until measurements justify a split",
	"SEC-019": "[SECURITY.md](../SECURITY.md): contact, private route, triage, supported versions, advisories",
	"GOV-001": "[architecture decision records](architecture-decisions/README.md) and [compatibility.md](protocols/compatibility.md)",
	"GOV-002": "DCO sign-off, checked by the CI job `dco` ([CONTRIBUTING.md](../CONTRIBUTING.md))",
	"GOV-003": "[SECURITY.md](../SECURITY.md); issue templates route vulnerabilities to private advisories",
	"GOV-008": "documentation changes ship with code changes ([CONTRIBUTING.md](../CONTRIBUTING.md), pull-request template)",
	"QA-006":  "[ADR 0020](architecture-decisions/0020-compliance-posture.md) states that nothing is certified and no conformance suite was run",
	"PRV-009": "[ADR 0020](architecture-decisions/0020-compliance-posture.md): no compliance claim",
	"DB-012":  "nothing is partitioned; the policy for doing it is in [capacity.md](operations/capacity.md)",
	"DB-013":  "row-level security is deliberately not used ([ADR 0004](architecture-decisions/0004-persistence.md))",
	"DEP-018": "one authoritative write region ([ADR 0019](architecture-decisions/0019-single-write-region.md))",
	"TEN-019": "realm-per-customer and deployment-per-customer patterns ([isolation-tiers.md](operations/isolation-tiers.md))",
	"MIG-013": "cutover and rollback runbook ([migration.md](operations/migration.md))",
	"QA-004":  "tested profiles with exact versions, including the third-party products used ([interoperability.md](integrations/interoperability.md))",
	"SDK-006": "language policy ([sdk-compatibility.md](integrations/sdk-compatibility.md#language-policy-sdk-006))",
	"GOV-006": "maturity and maintenance of every integration ([integrations/README.md](integrations/README.md#maturity-and-maintenance-gov-006))",
	"OPS-016": "incident runbooks with their tests ([incidents.md](operations/incidents.md))",
	"OPS-007": "PostgreSQL point-in-time recovery, prerequisites, protection and data-loss window ([backup-restore.md](operations/backup-restore.md))",
	"DEP-019": "warm-standby profile and promotion runbook; neither active-active writes nor global immediate revocation is offered ([backup-restore.md](operations/backup-restore.md#disaster-region-recovery-dep-019))",
	"INT-001": "HTTP pattern ([patterns.md](integrations/patterns.md)); the SDK adapters implement it",
	"INT-002": "GraphQL pattern ([patterns.md](integrations/patterns.md))",
	"INT-007": "message-consumer pattern ([patterns.md](integrations/patterns.md))",
	"INT-008": "download-grant pattern ([patterns.md](integrations/patterns.md))",
}

// openExternal lists requirements that need action outside the repository;
// the documents say plainly that it has not happened.
var openExternal = map[string]string{
	"SEC-018": "no external security review has been performed; the [README](../README.md) and [threat models](threat-models/README.md) say so",
	"QA-005":  "no qualified external review yet; the [README](../README.md) says the software is not independently reviewed",
}

// partial lists requirements and TEST cases whose citing tests cover only part
// of what the plan asks, or rest on synthetic evidence. The reason names the
// gap and the release planned to close it. An entry is rated Partial instead
// of Tested, and it must still be cited by at least one test.
var partial = map[string]string{
	"TEST-061": "the mixed-version evidence is synthetic: `TestMixedVersionWindow` inserts fake `schema_migrations` rows instead of running an older release; a real N-1 upgrade CI job is planned for 0.2.0-alpha.7",
	"DEP-012":  "the mixed-version evidence is synthetic: `TestMixedVersionWindow` inserts fake `schema_migrations` rows instead of running an older release; a real N-1 upgrade CI job is planned for 0.2.0-alpha.7",
	"QA-003":   "no fuzz target covers SAML XML and bindings, SCIM filters, authorization-request parsing or client-certificate parsing; those targets are planned for 0.2.0-beta.2",
	"SDK-010":  "only the Go SDK is tested against a running server; a live-server smoke test for the Node.js, Dart, PHP and .NET SDKs is planned for SDK 0.3.0",
	"SAML-010": "one independent SAML counterpart, Keycloak 26.8.0 ([interoperability.md](integrations/interoperability.md#third-party-products)); SimpleSAMLphp is planned for 0.2.0-beta.2",
}

// generatorFile is this file. Its maps and parser examples name plan IDs, but
// naming an ID here tests nothing, so collectEvidence does not read it.
const generatorFile = "tests/contract/traceability_test.go"

type planReq struct{ id, priority, title string }

type planCase struct{ id, title string }

var (
	reqRe   = regexp.MustCompile(`\*\*([A-Z]+-\d{3}) \[(P[0-3])\] — (.+?)\.\*\*`)
	caseRe  = regexp.MustCompile(`(?m)^\| (TEST-\d{3}) \| ([^|]+?)\s*\|`)
	idRe    = regexp.MustCompile(`\b([A-Z]{2,9})-(\d{3})\b`)
	rangeRe = regexp.MustCompile(`\b([A-Z]{2,9})-(\d{3}) ?(?:\.\.|–) ?(?:([A-Z]{2,9})-)?(\d{3})\b`)
	testFn  = regexp.MustCompile(`^func (Test\w+|Fuzz\w+)\(`)
)

func parsePlan(plan string) ([]planReq, []planCase) {
	var reqs []planReq
	seen := map[string]bool{}
	for _, m := range reqRe.FindAllStringSubmatch(plan, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			reqs = append(reqs, planReq{m[1], m[2], m[3]})
		}
	}
	var cases []planCase
	for _, m := range caseRe.FindAllStringSubmatch(plan, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			cases = append(cases, planCase{m[1], m[2]})
		}
	}
	return reqs, cases
}

type evidence struct {
	tests, code, docs map[string]bool
}

func (e *evidence) add(kind, ref string) {
	m := map[string]*map[string]bool{"test": &e.tests, "code": &e.code, "doc": &e.docs}[kind]
	if *m == nil {
		*m = map[string]bool{}
	}
	(*m)[ref] = true
}

// collectEvidence finds every citation of a plan ID. Go tests are credited by
// function (the test whose doc comment or body names the ID); other tests,
// code and documents by file (code by directory). The plan, the matrix and
// this generator are not evidence and are skipped.
func collectEvidence(root string, known map[string]bool) (map[string]*evidence, error) {
	ev := map[string]*evidence{}
	for id := range known {
		ev[id] = &evidence{}
	}
	skipDir := map[string]bool{"node_modules": true, ".dart_tool": true, ".git": true, "vectors": true, "bin": true, "obj": true}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDir[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if rel == "docs/plan.md" || rel == "docs/requirements-traceability.md" || rel == generatorFile {
			return nil
		}
		kind := classify(rel)
		if kind == "" {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		goTest := strings.HasSuffix(rel, "_test.go")
		var fns []string // test function for each line, for Go tests
		if goTest {
			fns = testFunctions(src)
		}
		line := 0
		sc := bufio.NewScanner(bytes.NewReader(src))
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			text := sc.Text()
			ref := rel
			switch {
			case goTest && fns[line] != "":
				ref = fns[line] + " (" + rel + ")"
			case kind == "code":
				ref = filepath.ToSlash(filepath.Dir(rel)) + "/"
			}
			for _, id := range idsIn(text) {
				if known[id] {
					ev[id].add(kind, ref)
				}
			}
			line++
		}
		return sc.Err()
	})
	return ev, err
}

// classify sorts a repository file into test, code or doc evidence.
func classify(rel string) string {
	ext := filepath.Ext(rel)
	switch {
	case rel == "scripts/dr-drill.sh", rel == "scripts/smoke-test.sh":
		// Executable checks run by CI against real processes.
		return "test"
	case strings.HasSuffix(rel, "_test.go"), strings.HasPrefix(rel, "tests/"):
		if slices.Contains([]string{".go", ".ts", ".dart", ".php", ".cs"}, ext) {
			return "test"
		}
		return ""
	case ext == ".md":
		return "doc"
	case slices.Contains([]string{".go", ".ts", ".dart", ".php", ".cs", ".sql"}, ext),
		strings.HasPrefix(rel, "api/") && slices.Contains([]string{".yaml", ".json"}, ext),
		strings.HasPrefix(rel, ".github/") && slices.Contains([]string{".yml", ".yaml"}, ext),
		strings.HasPrefix(rel, "deploy/") && slices.Contains([]string{".yaml", ".yml"}, ext),
		rel == "Dockerfile", rel == "Makefile", rel == ".github/CODEOWNERS", strings.HasPrefix(rel, "scripts/"):
		return "code"
	}
	return ""
}

// testFunctions maps each line of a Go test file to the test it documents or
// belongs to: a comment block directly above a test belongs to that test.
func testFunctions(src []byte) []string {
	lines := strings.Split(string(src), "\n")
	out := make([]string, len(lines)+1)
	current := ""
	for i, l := range lines {
		if m := testFn.FindStringSubmatch(l); m != nil {
			current = m[1]
			for j := i - 1; j >= 0 && strings.HasPrefix(lines[j], "//"); j-- {
				out[j] = current
			}
		} else if strings.HasPrefix(l, "func ") || strings.HasPrefix(l, "var ") || strings.HasPrefix(l, "type ") {
			current = ""
		}
		if out[i] == "" {
			out[i] = current
		}
	}
	return out
}

// idsIn returns the plan IDs a line names, expanding ranges such as
// SDK-010..SDK-012 and PWDLESS-001..005.
func idsIn(text string) []string {
	var ids []string
	for _, m := range idRe.FindAllStringSubmatch(text, -1) {
		ids = append(ids, m[1]+"-"+m[2])
	}
	for _, m := range rangeRe.FindAllStringSubmatch(text, -1) {
		if m[3] != "" && m[3] != m[1] {
			continue
		}
		from, _ := strconv.Atoi(m[2])
		to, _ := strconv.Atoi(m[4])
		// Both ends of PREFIX-NNN..PREFIX-MMM are full IDs already; in the
		// short form PREFIX-NNN..MMM the upper end is not.
		last := to - 1
		if m[3] == "" {
			last = to
		}
		for n := from + 1; n <= last && to-from <= 80; n++ {
			ids = append(ids, fmt.Sprintf("%s-%03d", m[1], n))
		}
	}
	return ids
}

func status(r planReq, e *evidence) string {
	switch {
	case notOffered[r.id] != "":
		return "Not offered"
	case openExternal[r.id] != "":
		return "Open (external)"
	case len(e.tests) > 0 && partial[r.id] != "":
		return "Partial"
	case len(e.tests) > 0:
		return "Tested"
	case len(e.code) > 0:
		return "Implemented"
	case byDocument[r.id] != "":
		return "Documented"
	case len(e.docs) > 0:
		return "Documented"
	}
	return "Missing"
}

// note is the reason printed after a status that needs one.
func note(id, st string) string {
	switch st {
	case "Not offered":
		return notOffered[id]
	case "Open (external)":
		return openExternal[id]
	case "Partial":
		return partial[id]
	case "Documented":
		return byDocument[id]
	}
	return ""
}

// caseStatus rates a TEST case: Tested when a test cites it, Partial when
// partial says those tests fall short.
func caseStatus(id string, e *evidence) string {
	switch {
	case len(e.tests) == 0:
		return "Missing"
	case partial[id] != "":
		return "Partial"
	}
	return "Tested"
}

func renderMatrix(reqs []planReq, cases []planCase, ev map[string]*evidence) string {
	var b strings.Builder
	counts := map[string]map[string]int{}
	for _, r := range reqs {
		st := status(r, ev[r.id])
		if counts[r.priority] == nil {
			counts[r.priority] = map[string]int{}
		}
		counts[r.priority][st]++
	}
	b.WriteString(`# Requirements traceability

Generated from [plan.md](plan.md) by ` + "`TestRequirementsTraceability`" + ` (` + "`tests/contract/traceability_test.go`" + `);
do not edit by hand. Regenerate with:

` + "```sh\nPROUDAUTH_REGENERATE_TRACEABILITY=1 go test ./tests/contract -run TestRequirementsTraceability\n```" + `

Each requirement and TEST case of the plan is listed with the tests, code and
documents that cite its ID. **Status:**

- **Tested**: at least one test names the requirement (in its doc comment or
  body) and runs in CI.
- **Partial**: tests name the requirement, but they cover only part of it or
  rest on synthetic evidence; the gap and the release planned to close it are
  given.
- **Implemented**: code, an API contract, a CI job or deployment file names
  it, but no test does.
- **Documented**: the evidence is a document or repository policy
  (licensing, governance, process, deployment decisions); the reason is
  given.
- **Not offered**: a P3 capability outside this release's selection
  (plan section 35.1, milestone M5), stated as not offered and not advertised.
- **Open (external)**: needs action outside the repository (an independent
  security review); the documents state that it has not happened.

The contract test fails when a P0–P2 requirement has no evidence, when a TEST
case is cited by no test, when a Partial entry is cited by no test, or when
this file is stale. The generator's own file is not counted as a test. A
citation shows where a requirement is handled; whether the behaviour is right
is what the cited tests check.

## Summary

| Priority | Requirements | Tested | Partial | Implemented | Documented | Not offered | Open (external) |
| --- | --- | --- | --- | --- | --- | --- | --- |
`)
	total := map[string]int{}
	for _, p := range []string{"P0", "P1", "P2", "P3"} {
		c := counts[p]
		n := 0
		for _, v := range c {
			n += v
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %d | %d |\n", p, n, c["Tested"], c["Partial"], c["Implemented"], c["Documented"], c["Not offered"], c["Open (external)"])
		total["n"] += n
		for _, s := range []string{"Tested", "Partial", "Implemented", "Documented", "Not offered", "Open (external)"} {
			total[s] += c[s]
		}
	}
	fmt.Fprintf(&b, "| All | %d | %d | %d | %d | %d | %d | %d |\n", total["n"], total["Tested"], total["Partial"], total["Implemented"], total["Documented"], total["Not offered"], total["Open (external)"])
	caseCounts := map[string]int{}
	for _, c := range cases {
		caseCounts[caseStatus(c.id, ev[c.id])]++
	}
	fmt.Fprintf(&b, "\nTEST cases (plan section 34): %d of %d are cited by at least one test (%d Tested, %d Partial).\n",
		caseCounts["Tested"]+caseCounts["Partial"], len(cases), caseCounts["Tested"], caseCounts["Partial"])

	group := ""
	for _, r := range reqs {
		prefix := r.id[:strings.LastIndex(r.id, "-")]
		if prefix != group {
			group = prefix
			fmt.Fprintf(&b, "\n## %s\n\n| ID | P | Requirement | Status | Tests | Code | Documents |\n| --- | --- | --- | --- | --- | --- | --- |\n", prefix)
		}
		e := ev[r.id]
		st := status(r, e)
		if n := note(r.id, st); n != "" {
			st += ": " + n
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n", r.id, r.priority, cell(r.title), st,
			refs(e.tests, 4), refs(e.code, 3), docRefs(e.docs, 3))
	}
	b.WriteString("\n## TEST cases\n\n| ID | Scenario | Status | Tests |\n| --- | --- | --- | --- |\n")
	for _, c := range cases {
		st := caseStatus(c.id, ev[c.id])
		if n := note(c.id, st); n != "" {
			st += ": " + n
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.id, cell(c.title), st, refs(ev[c.id].tests, 6))
	}
	return b.String()
}

func cell(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "|", "\\|") }

// refs prints up to n sorted references and how many more there are.
func refs(m map[string]bool, n int) string {
	if len(m) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, n+1)
	for i, k := range keys {
		if i == n {
			out = append(out, fmt.Sprintf("+%d more", len(keys)-n))
			break
		}
		out = append(out, "`"+k+"`")
	}
	return strings.Join(out, ", ")
}

// docRefs links documents relative to docs/.
func docRefs(m map[string]bool, n int) string {
	if len(m) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		// Documents under docs/ first, then the rest, each alphabetically.
		di, dj := strings.HasPrefix(keys[i], "docs/"), strings.HasPrefix(keys[j], "docs/")
		if di != dj {
			return di
		}
		return keys[i] < keys[j]
	})
	out := make([]string, 0, n+1)
	for i, k := range keys {
		if i == n {
			out = append(out, fmt.Sprintf("+%d more", len(keys)-n))
			break
		}
		target := "../" + k
		if strings.HasPrefix(k, "docs/") {
			target = strings.TrimPrefix(k, "docs/")
		}
		out = append(out, "["+filepath.Base(k)+"]("+target+")")
	}
	return strings.Join(out, ", ")
}

// TestTraceabilityRanges pins the citation parser: both range forms credit
// every ID from the first to the last.
func TestTraceabilityRanges(t *testing.T) {
	for in, want := range map[string]string{
		"covers FED-001..003 and X":     "FED-001 FED-002 FED-003",
		"covers SDK-010..SDK-012":       "SDK-010 SDK-012 SDK-011",
		"PWDLESS-001–002, TOK-007":      "PWDLESS-001 TOK-007 PWDLESS-002",
		"nothing here, not a range 1..": "",
	} {
		if got := strings.Join(idsIn(in), " "); got != want {
			t.Errorf("idsIn(%q) = %q, want %q", in, got, want)
		}
	}
}
