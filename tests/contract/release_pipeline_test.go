package contract

// DEP-003, DEP-006, DEP-017 and SEC-016: publication reuses CI only for the
// immutable release commit, and archive assembly rejects generated private state.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseCIReuseExactLatestCommit(t *testing.T) {
	workflow := deployRead(t, ".github/workflows/release.yml")
	match := regexp.MustCompile(`'([[]\.workflow_runs\[\][^']+)' ci-runs\.json`).FindStringSubmatch(workflow)
	if len(match) != 2 {
		t.Fatal("release CI reuse must expose its actual exact-commit status selector")
	}
	filter := match[1]
	for _, tc := range []struct{ name, runs, want string }{
		{"green-exact", `[{"head_sha":"release","event":"push","head_branch":"main","status":"completed","conclusion":"success"}]`, "true"},
		{"wrong-commit", `[{"head_sha":"older","event":"push","head_branch":"main","status":"completed","conclusion":"success"}]`, "false"},
		{"pull-request-only", `[{"head_sha":"release","event":"pull_request","head_branch":"main","status":"completed","conclusion":"success"}]`, "false"},
		{"wrong-branch", `[{"head_sha":"release","event":"push","head_branch":"feature","status":"completed","conclusion":"success"}]`, "false"},
		{"in-progress", `[{"head_sha":"release","event":"push","head_branch":"main","status":"in_progress","conclusion":null}]`, "false"},
		{"failure", `[{"head_sha":"release","event":"push","head_branch":"main","status":"completed","conclusion":"failure"}]`, "false"},
		{"latest-rerun-failed", `[{"head_sha":"release","event":"push","head_branch":"main","status":"completed","conclusion":"failure"},{"head_sha":"release","event":"push","head_branch":"main","status":"completed","conclusion":"success"}]`, "false"},
		{"no-runs", `[]`, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("jq", "-r", "--arg", "sha", "release", filter)
			cmd.Stdin = strings.NewReader(`{"workflow_runs":` + tc.runs + `}`)
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("actual CI status selector: got %s, error %v, want %s", out, err, tc.want)
			}
		})
	}
	rel := deployDocs(t, ".github/workflows/release.yml")[0]
	if deployDig(rel, "jobs", "ci", "uses") != "./.github/workflows/ci.yml" {
		t.Error("non-reusable CI status must fall back to the complete reusable CI workflow")
	}
	condition, _ := deployDig(rel, "jobs", "release", "if").(string)
	for _, required := range []string{"needs.ci-status.result == 'success'", "needs.ci.result == 'success'", "needs.ci-status.outputs.verified == 'true'"} {
		if !strings.Contains(condition, required) {
			t.Errorf("release condition must fail closed around %s", required)
		}
	}
}

func TestOfflineBundleExcludesInstalledReleaseState(t *testing.T) {
	f := newBundleFixture(t)
	private := "fixture-private-release-state-must-never-be-published"
	// A production .env filled in the packaging checkout.
	filled := "PROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:0.2.0-alpha.2\nPROUDAUTH_ROOT_KEY=" + private +
		"\nPROUDAUTH_DATABASE_URL=postgres://proudauth:" + private + "@db.example.test/proudauth\nPROUDAUTH_SMTP_PASSWORD=" + private + "\n"
	path := filepath.Join(f.root, "deploy/prod/.env")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(filled), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := f.command(context.Background(), "dev-test").CombinedOutput(); err != nil {
		t.Fatalf("actual offline bundle assembly: %v\n%s", err, out)
	}
	archive, err := os.ReadFile(filepath.Join(f.root, "dist/proudauth-dev-test-offline.tar.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(body, []byte(private)) {
			t.Errorf("private installed state leaked through %s", header.Name)
		}
	}
}
