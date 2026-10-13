package contract

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestBenchRunnerSQLKeepsCallerInput covers NFR-008: command-form SQL cannot
// consume a streaming caller's later validation/cleanup commands. Explicit
// heredoc SQL must still reach psql. The stub exercises stdin without Docker.
func TestBenchRunnerSQLKeepsCallerInput(t *testing.T) {
	source, err := os.ReadFile("../../scripts/bench-local.sh")
	if err != nil {
		t.Fatal(err)
	}
	helper := regexp.MustCompile(`(?ms)^psql_pg\(\) \{.*?^\}`).Find(source)
	if len(helper) == 0 {
		t.Fatal("runner PostgreSQL helper not found")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nif [ \"$2\" = -i ]; then cat >/dev/null; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "set -eu\nPG=owned\n" + string(helper) + "\npsql_pg postgres -c 'SELECT 1'\nprintf 'after-command\\n'\npsql_pg postgres <<SQL\nSELECT 2;\nSQL\nprintf 'after-heredoc\\n'\n"
	cmd := exec.Command("sh", "-s")
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("runner helper: %v: %s", err, out)
	}
	if string(out) != "after-command\nafter-heredoc\n" {
		t.Fatalf("SQL consumed caller validation commands: %q", out)
	}
}
