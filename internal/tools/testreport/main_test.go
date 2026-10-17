package main

import (
	"strings"
	"testing"
)

const stream = `{"Action":"start","Package":"github.com/proudauth/proudauth/internal/x"}
{"Action":"run","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestPasses"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestPasses","Output":"=== RUN   TestPasses\n"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestPasses","Output":"--- PASS: TestPasses (0.00s)\n"}
{"Action":"pass","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestPasses","Elapsed":0.01}
{"Action":"run","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestSkips"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestSkips","Output":"=== RUN   TestSkips\n"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestSkips","Output":"    x_test.go:12: PROUDAUTH_TEST_DATABASE_URL not set; skipping database integration test\n"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestSkips","Output":"--- SKIP: TestSkips (0.00s)\n"}
{"Action":"skip","Package":"github.com/proudauth/proudauth/internal/x","Test":"TestSkips","Elapsed":0}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Output":"ok  \tgithub.com/proudauth/proudauth/internal/x\t0.1s\n"}
{"Action":"pass","Package":"github.com/proudauth/proudauth/internal/x","Elapsed":0.1}
`

const failing = `{"Action":"run","Package":"github.com/proudauth/proudauth/internal/y","Test":"TestFails"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/y","Test":"TestFails","Output":"    y_test.go:9: expected 1, got 2\n"}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/y","Test":"TestFails","Output":"--- FAIL: TestFails (0.00s)\n"}
{"Action":"fail","Package":"github.com/proudauth/proudauth/internal/y","Test":"TestFails","Elapsed":0}
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/y","Output":"FAIL\tgithub.com/proudauth/proudauth/internal/y\t0.1s\n"}
{"Action":"fail","Package":"github.com/proudauth/proudauth/internal/y","Elapsed":0.1}
`

const buildFailed = `# github.com/proudauth/proudauth/internal/z
internal/z/z.go:3:1: syntax error
{"Action":"output","Package":"github.com/proudauth/proudauth/internal/z","Output":"FAIL\tgithub.com/proudauth/proudauth/internal/z [build failed]\n"}
{"Action":"fail","Package":"github.com/proudauth/proudauth/internal/z","Elapsed":0}
`

func exec(t *testing.T, in string, opt options) (int, string) {
	t.Helper()
	if opt.module == "" {
		opt.module = "github.com/proudauth/proudauth"
	}
	if opt.allowlist == nil {
		opt.allowlist = map[string]string{}
	}
	var out strings.Builder
	code := run(strings.NewReader(in), &out, opt)
	return code, out.String()
}

func TestSkipOutsideAllowlistFails(t *testing.T) {
	code, out := exec(t, stream, options{})
	if code != 1 {
		t.Fatalf("exit %d, want 1:\n%s", code, out)
	}
	for _, want := range []string{"PASS  internal/x TestPasses", "SKIP  internal/x TestSkips: PROUDAUTH_TEST_DATABASE_URL not set", "1 passed, 0 failed, 1 skipped", "skipped outside the allowlist"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestAllowlistedSkipPasses(t *testing.T) {
	for _, entry := range []string{"internal/x TestSkips", "github.com/proudauth/proudauth/internal/x TestSkips"} {
		code, out := exec(t, stream, options{allowlist: map[string]string{entry: "needs a database"}})
		if code != 0 {
			t.Fatalf("entry %q: exit %d, want 0:\n%s", entry, code, out)
		}
	}
	// A subtest skip is covered by its top-level test's entry.
	sub := strings.ReplaceAll(stream, `"Test":"TestSkips"`, `"Test":"TestSkips/db"`)
	if code, out := exec(t, sub, options{allowlist: map[string]string{"internal/x TestSkips": "needs a database"}}); code != 0 {
		t.Fatalf("subtest: exit %d, want 0:\n%s", code, out)
	}
}

func TestFailuresShowOutputAndFail(t *testing.T) {
	code, out := exec(t, failing, options{})
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for _, want := range []string{"FAIL  internal/y TestFails", "expected 1, got 2", "failed packages: internal/y"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestBuildFailureFails(t *testing.T) {
	code, out := exec(t, buildFailed, options{})
	if code != 1 || !strings.Contains(out, "syntax error") || !strings.Contains(out, "[build failed]") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestRequireTests(t *testing.T) {
	empty := `{"Action":"output","Package":"github.com/proudauth/proudauth/internal/x","Output":"ok  \tgithub.com/proudauth/proudauth/internal/x\t0.1s\n"}
{"Action":"pass","Package":"github.com/proudauth/proudauth/internal/x","Elapsed":0.1}
`
	if code, _ := exec(t, empty, options{}); code != 0 {
		t.Fatalf("without -require-tests: exit %d, want 0", code)
	}
	if code, out := exec(t, empty, options{requireTests: true}); code != 1 || !strings.Contains(out, "no test ran") {
		t.Fatalf("with -require-tests: exit %d:\n%s", code, out)
	}
}

func TestQuietHidesPasses(t *testing.T) {
	_, out := exec(t, stream, options{quiet: true, allowlist: map[string]string{"internal/x TestSkips": "needs a database"}})
	if strings.Contains(out, "PASS  internal/x TestPasses") || !strings.Contains(out, "SKIP  internal/x TestSkips") {
		t.Fatalf("quiet output:\n%s", out)
	}
}

func TestParseAllowlist(t *testing.T) {
	al, err := parseAllowlist("f", "# header\n\ninternal/x TestA # reason one\ngithub.com/proudauth/proudauth/tests/e2e TestB/sub   # reason two\n")
	if err != nil || len(al) != 2 || al["internal/x TestA"] != "reason one" || al["github.com/proudauth/proudauth/tests/e2e TestB/sub"] != "reason two" {
		t.Fatalf("%v %v", al, err)
	}
	for _, bad := range []string{"internal/x TestA\n", "internal/x # no test\n", "a b c # three fields\n"} {
		if _, err := parseAllowlist("f", bad); err == nil {
			t.Errorf("%q parsed without error", bad)
		}
	}
}
