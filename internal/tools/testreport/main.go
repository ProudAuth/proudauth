// Command testreport reads the JSON stream of `go test -json` and prints a
// compact log: one line per finished test, the captured output of every failed
// or skipped test, and a summary. It exits non-zero when a test or package
// failed, when a test skipped outside the allowlist, or (with -require-tests)
// when no test ran, so a run cannot pass by matching nothing or by skipping its
// database tests (QA-001).
//
//	go test ./... -json | go run ./internal/tools/testreport -allowlist tests/skip-allowlist.txt -require-tests
//
// Allowlist lines are "<package> <TestName> # reason", where <package> is the
// import path or its path relative to the module root and <TestName> is a
// top-level test or a Test/subtest path. Blank lines and lines starting with #
// are ignored; every entry needs a reason.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type event struct {
	Action  string  `json:"Action"`
	Package string  `json:"Package"`
	Test    string  `json:"Test"`
	Output  string  `json:"Output"`
	Elapsed float64 `json:"Elapsed"`
}

type options struct {
	module       string
	allowlist    map[string]string // "<relative package> <Test>" -> reason
	requireTests bool
	quiet        bool
}

type skip struct{ pkg, full, test, reason string }

func main() {
	allow := flag.String("allowlist", "", "file of tests allowed to skip (\"<package> <Test> # reason\" per line)")
	require := flag.Bool("require-tests", false, "fail when no test ran")
	quiet := flag.Bool("quiet", false, "print only failures, skips and package results")
	module := flag.String("module", "github.com/proudauth/proudauth", "module path that allowlist package paths are relative to")
	flag.Parse()
	opt := options{module: *module, requireTests: *require, quiet: *quiet, allowlist: map[string]string{}}
	if *allow != "" {
		al, err := readAllowlist(*allow)
		if err != nil {
			fmt.Fprintln(os.Stderr, "testreport:", err)
			os.Exit(2)
		}
		opt.allowlist = al
	}
	os.Exit(run(os.Stdin, os.Stdout, opt))
}

func readAllowlist(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseAllowlist(path, string(b))
}

func parseAllowlist(path, text string) (map[string]string, error) {
	out := map[string]string{}
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
		if len(f) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"<package> <Test> # reason\"", path, i+1)
		}
		if reason == "" {
			return nil, fmt.Errorf("%s:%d: every allowed skip needs a reason after #", path, i+1)
		}
		out[f[0]+" "+f[1]] = reason
	}
	return out, nil
}

// run reads events from r, writes the log to w and returns the exit code.
func run(r io.Reader, w io.Writer, opt options) int {
	var passed, failed, skipped int
	var pkgFailed []string
	var skips []skip
	buildFailed := false
	outputs := map[string][]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		var ev event
		if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &ev) != nil {
			// Not an event (go tool messages before a build failure): pass through.
			fmt.Fprintln(w, string(line))
			continue
		}
		key := ev.Package + "\x00" + ev.Test
		rel := relPkg(ev.Package, opt.module)
		switch ev.Action {
		case "output":
			outputs[key] = append(outputs[key], ev.Output)
			if ev.Test == "" && (strings.Contains(ev.Output, "[build failed]") || strings.Contains(ev.Output, "[setup failed]")) {
				buildFailed = true
			}
		case "pass", "fail", "skip":
			out := outputs[key]
			delete(outputs, key)
			if ev.Test == "" {
				switch ev.Action {
				case "pass":
					fmt.Fprintf(w, "ok    %s (%.1fs)\n", rel, ev.Elapsed)
				case "skip":
					fmt.Fprintf(w, "---   %s [no test files]\n", rel)
				case "fail":
					pkgFailed = append(pkgFailed, rel)
					fmt.Fprintf(w, "FAIL  %s (%.1fs)\n", rel, ev.Elapsed)
					writeOutput(w, out)
				}
				continue
			}
			switch ev.Action {
			case "pass":
				passed++
				if !opt.quiet {
					fmt.Fprintf(w, "PASS  %s %s (%.2fs)\n", rel, ev.Test, ev.Elapsed)
				}
			case "fail":
				failed++
				fmt.Fprintf(w, "FAIL  %s %s (%.2fs)\n", rel, ev.Test, ev.Elapsed)
				writeOutput(w, out)
			case "skip":
				skipped++
				reason := skipReason(out)
				skips = append(skips, skip{rel, ev.Package, ev.Test, reason})
				fmt.Fprintf(w, "SKIP  %s %s: %s\n", rel, ev.Test, reason)
			}
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(w, "testreport: read:", err)
		return 2
	}
	// Output that never got a result: the binary died (panic, timeout, kill).
	for key, out := range outputs {
		pkg, test, _ := strings.Cut(key, "\x00")
		if test == "" || len(out) == 0 {
			continue
		}
		fmt.Fprintf(w, "LOST  %s %s (no result; the test binary ended first)\n", relPkg(pkg, opt.module), test)
		writeOutput(w, out)
	}

	fmt.Fprintf(w, "\n%d passed, %d failed, %d skipped\n", passed, failed, skipped)
	code := 0
	if failed > 0 || len(pkgFailed) > 0 || buildFailed {
		code = 1
		if len(pkgFailed) > 0 {
			fmt.Fprintf(w, "failed packages: %s\n", strings.Join(pkgFailed, ", "))
		}
	}
	var violations []skip
	for _, s := range skips {
		if allowed(opt.allowlist, s) {
			continue
		}
		violations = append(violations, s)
	}
	if len(violations) > 0 {
		code = 1
		fmt.Fprintf(w, "%d test(s) skipped outside the allowlist; a skipped test proves nothing (QA-001):\n", len(violations))
		for _, s := range violations {
			fmt.Fprintf(w, "  %s %s: %s\n", s.pkg, s.test, s.reason)
		}
	}
	if opt.requireTests && passed+failed == 0 {
		code = 1
		fmt.Fprintln(w, "no test ran: the -run pattern matched nothing, or every test skipped")
	}
	return code
}

// allowed reports whether the allowlist names the skipped test, by relative or
// full package path and by its own name or its top-level test's name.
func allowed(allowlist map[string]string, s skip) bool {
	top, _, _ := strings.Cut(s.test, "/")
	for _, pkg := range []string{s.pkg, s.full} {
		for _, test := range []string{s.test, top} {
			if _, ok := allowlist[pkg+" "+test]; ok {
				return true
			}
		}
	}
	return false
}

func relPkg(pkg, module string) string {
	if pkg == module {
		return "."
	}
	return strings.TrimPrefix(pkg, module+"/")
}

func writeOutput(w io.Writer, lines []string) {
	for _, l := range lines {
		fmt.Fprint(w, "      ", l)
		if !strings.HasSuffix(l, "\n") {
			fmt.Fprintln(w)
		}
	}
}

var position = regexp.MustCompile(`^\S+\.go:\d+: `)

// skipReason is the message the test gave t.Skip: the last output line that is
// neither a test-runner marker nor empty, without its file position.
func skipReason(lines []string) string {
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if l == "" || strings.HasPrefix(l, "=== ") || strings.HasPrefix(l, "--- ") {
			continue
		}
		return position.ReplaceAllString(l, "")
	}
	return "(no reason given)"
}
