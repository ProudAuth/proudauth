package contract

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPrepareReleaseMovesEveryVersionReference (GOV-005, DEP-003): one command
// moves the pinned image, the install commands and the guides the websites
// publish to the new version, and turns the Unreleased notes into its section.
// The release workflow refuses a tag those files do not match, and asks both
// websites to redeploy.
func TestPrepareReleaseMovesEveryVersionReference(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Fatal("python3 is required to verify the release preparation script")
	}
	dir := t.TempDir()
	files := []string{"scripts/prepare-release.sh", "deploy/prod/.env", "deploy/dev/.env", "README.md", "deploy/README.md",
		"docs/operations/docker-compose.md", "docs/operations/environment.md", "docs/operations/installation.md",
		"scripts/package-deployment.sh"}
	for _, rel := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(deployRead(t, rel)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	current := strings.TrimPrefix(deployEnvFile(t, "deploy/prod/.env")["PROUDAUTH_IMAGE"], "ghcr.io/proudbase/proudauth:")
	changelog := "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- A fix worth releasing.\n\n## [" + current + "] - 2026-01-01\n\n- Earlier.\n"
	write := func(body string) {
		if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run := func(version string) ([]byte, error) {
		cmd := exec.Command("sh", filepath.Join(dir, "scripts/prepare-release.sh"), version)
		cmd.Env = append(os.Environ(), "RELEASE_DATE=2030-01-02")
		return cmd.CombinedOutput()
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	write("# Changelog\n\n## [Unreleased]\n\nNo changes recorded after " + current + ".\n\n## [" + current + "] - 2026-01-01\n\n- Earlier.\n")
	if out, err := run("v9.8.7"); err == nil || !strings.Contains(string(out), "release notes") {
		t.Fatalf("a release without notes must be refused: %v %s", err, out)
	}
	if !strings.Contains(read("deploy/prod/.env"), current) {
		t.Fatal("a refused preparation must not change any file")
	}
	write(changelog)
	if out, err := run("v9.8.7"); err != nil {
		t.Fatalf("prepare-release: %v\n%s", err, out)
	}
	for rel, want := range map[string]string{
		"deploy/prod/.env":                  "\nPROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:9.8.7\n",
		"docs/operations/docker-compose.md": "\nPROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:9.8.7\n",
		"README.md":                         "raw.githubusercontent.com/proudbase/proudauth/v9.8.7/deploy/prod/.env",
		"deploy/README.md":                  "raw.githubusercontent.com/proudbase/proudauth/v9.8.7/deploy/prod/docker-compose.yaml",
		"scripts/package-deployment.sh":     "${1:-v9.8.7}",
		"CHANGELOG.md":                      "## [Unreleased]\n\nNo changes recorded after 9.8.7.\n\n## [9.8.7] - 2030-01-02\n\n### Fixed\n\n- A fix worth releasing.\n\n## [" + current + "]",
	} {
		if !strings.Contains(read(rel), want) {
			t.Errorf("%s does not contain %q after preparing v9.8.7", rel, want)
		}
	}
	for _, rel := range files[1:] {
		if strings.Contains(read(rel), current) {
			t.Errorf("%s still mentions %s", rel, current)
		}
	}
	if out, err := run("v9.8.7"); err == nil {
		t.Fatalf("preparing the current version again must be refused:\n%s", out)
	}
	if out, err := run("9.8.8"); err == nil {
		t.Fatalf("a version without the v prefix must be refused:\n%s", out)
	}

	workflow := deployRead(t, ".github/workflows/release.yml")
	for _, want := range []string{
		`grep -qx "PROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:${GITHUB_REF_NAME#v}" deploy/prod/.env`,
		`grep -qx "PROUDAUTH_IMAGE=ghcr.io/proudbase/proudauth:${GITHUB_REF_NAME#v}" docs/operations/docker-compose.md`,
		`--annotation "index:org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}"`, "## Docker image",
		"secrets.WEBSITES_DISPATCH_TOKEN", "repos/proudbase/${site}/dispatches", "event_type=proudauth-release",
	} {
		if !strings.Contains(workflow, want) {
			t.Errorf("release.yml lacks %q", want)
		}
	}
}
