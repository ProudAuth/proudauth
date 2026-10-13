package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestAttackSuitesExist keeps the provisioning and federation attack suites
// (M4 exit gate, docs/threat-models/attack-suites.md) runnable: every test a
// suite names exists, and `make attack-provisioning` / `make
// attack-federation` run exactly the tests the document lists.
func TestAttackSuitesExist(t *testing.T) {
	doc, err := os.ReadFile("../../docs/threat-models/attack-suites.md")
	if err != nil {
		t.Fatal(err)
	}
	makefile, err := os.ReadFile("../../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(doc)
	prov := text[strings.Index(text, "## Provisioning suite"):strings.Index(text, "## Federation suite")]
	fed := text[strings.Index(text, "## Federation suite"):]
	defined := map[string]bool{}
	fn := regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	for _, dir := range []string{"../../tests", "../../internal", "../../cmd"} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return err
			}
			src, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range fn.FindAllStringSubmatch(string(src), -1) {
				defined[m[1]] = true
			}
			return nil
		})
	}
	for suite, section := range map[string]string{"ATTACK_PROVISIONING": prov, "ATTACK_FEDERATION": fed} {
		line := regexp.MustCompile(`(?m)^` + suite + ` = (.*)$`).FindStringSubmatch(string(makefile))
		if line == nil {
			t.Fatalf("Makefile has no %s", suite)
		}
		inMake := map[string]bool{}
		for _, n := range strings.Split(strings.TrimSpace(line[1]), "|") {
			inMake[n] = true
		}
		listed := map[string]bool{}
		for _, m := range regexp.MustCompile("`(Test\\w+)`").FindAllStringSubmatch(section, -1) {
			listed[m[1]] = true
			if !defined[m[1]] {
				t.Errorf("%s names %s, which does not exist", suite, m[1])
			}
			if !inMake[m[1]] {
				t.Errorf("%s in the Makefile does not run %s", suite, m[1])
			}
		}
		for n := range inMake {
			if !listed[n] {
				t.Errorf("%s in the Makefile runs %s, which the document does not list", suite, n)
			}
		}
		if len(listed) < 10 {
			t.Errorf("%s lists only %d tests", suite, len(listed))
		}
	}
}
