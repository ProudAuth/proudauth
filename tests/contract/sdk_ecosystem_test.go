package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type sdkRepositorySnapshot struct {
	Language       string            `json:"language"`
	Repository     string            `json:"repository"`
	Revision       string            `json:"revision"`
	WorkflowPath   string            `json:"workflow_path"`
	WorkflowSHA256 string            `json:"workflow_sha256"`
	Workflow       string            `json:"workflow"`
	CIRun          string            `json:"ci_run"`
	CIConclusion   string            `json:"ci_conclusion"`
	Fixtures       map[string]string `json:"fixtures"`
}

// TestSDKRepositoryBoundaries covers OSS-004, SDK-009, SDK-010 and QA-002:
// the service consumes a pinned public Go module; independently owned SDK CI
// retains its language checks and the same synthetic security contracts.
// This validates a recorded, source-pinned CI snapshot. It does not execute
// foreign SDK tests or credit them as local requirement-test evidence.
func TestSDKRepositoryBoundaries(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRoot, "sdk")); !os.IsNotExist(err) {
		t.Fatal("SDK implementations must be owned by their standalone repositories")
	}
	gomod := readRepoFile(t, "go.mod")
	if !strings.HasPrefix(gomod, "module github.com/proudauth/proudauth\n") {
		t.Error("service module must use its independently cloneable public path")
	}
	if strings.Contains(gomod, "replace ") || strings.Contains(gomod, "replace (") {
		t.Error("published service must consume normal pinned modules without local replacements")
	}
	const sdkVersion = "v0.2.0" // tag on proudauth-sdk-go commit 1be1ba20
	if !strings.Contains(gomod, "github.com/proudauth/proudauth-sdk-go "+sdkVersion) {
		t.Error("service Go SDK dependency must identify the verified public source")
	}
	if !strings.Contains(readRepoFile(t, "go.sum"), "github.com/proudauth/proudauth-sdk-go "+sdkVersion+" h1:") {
		t.Error("service Go SDK dependency needs a verified module checksum")
	}
	var snapshot struct {
		SchemaVersion int                     `json:"schema_version"`
		Repositories  []sdkRepositorySnapshot `json:"repositories"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "docs/integrations/sdk-repositories.json")), &snapshot); err != nil {
		t.Fatal(err)
	}
	checks := map[string][]string{
		"go":     {"go test -race", "FuzzVerify", "FuzzSenderURLNormalization"},
		"node":   {"npm ci", "npm audit --audit-level=high", "npm test"},
		"dart":   {"dart pub get --enforce-lockfile", "dart analyze", "dart format", "dart test"},
		"php":    {"composer validate", "php -l", "tests/run.php", "dev-main#", "composer install --working-dir="},
		"dotnet": {"dotnet restore", "--locked-mode", "dotnet build", "dotnet run", "dotnet format", "dotnet pack"},
	}
	if snapshot.SchemaVersion != 1 || len(snapshot.Repositories) != len(checks) {
		t.Fatalf("expected one source-pinned snapshot for each maintained SDK, got %d", len(snapshot.Repositories))
	}
	seen := map[string]bool{}
	for _, sdk := range snapshot.Repositories {
		if seen[sdk.Language] || checks[sdk.Language] == nil {
			t.Errorf("unexpected or duplicate SDK %q", sdk.Language)
			continue
		}
		seen[sdk.Language] = true
		if sdk.Repository != "proudauth/proudauth-sdk-"+sdk.Language || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(sdk.Revision) {
			t.Errorf("%s must name the public owner and immutable source revision", sdk.Language)
		}
		if sdk.Language == "go" && !strings.HasPrefix(sdk.Revision, "1be1ba206169") {
			t.Error("Go SDK snapshot revision differs from the service dependency")
		}
		if sdk.WorkflowPath != ".github/workflows/ci.yml" || sdk.CIConclusion != "success" ||
			!regexp.MustCompile(`^https://github\.com/`+regexp.QuoteMeta(sdk.Repository)+`/actions/runs/[0-9]+$`).MatchString(sdk.CIRun) {
			t.Errorf("%s must record the independently verified successful workflow run", sdk.Language)
		}
		hash := sha256.Sum256([]byte(sdk.Workflow))
		if hex.EncodeToString(hash[:]) != sdk.WorkflowSHA256 {
			t.Errorf("%s workflow bytes differ from their snapshot checksum", sdk.Language)
		}
		for _, command := range checks[sdk.Language] {
			if !strings.Contains(sdk.Workflow, command) {
				t.Errorf("%s independent CI lacks %s", sdk.Language, command)
			}
		}
		if len(sdk.Fixtures) != 2 {
			t.Errorf("%s must pin both shared contract fixtures", sdk.Language)
		}
		for _, fixture := range []string{"access-tokens/cases.json", "support-operations/cases.json"} {
			data, err := os.ReadFile(filepath.Join(repoRoot, "tests/fixtures/sdk-contracts", fixture))
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(data)
			if sdk.Fixtures[fixture] != hex.EncodeToString(hash[:]) {
				t.Errorf("%s fixture %s differs from the source-pinned SDK contract; update and verify every SDK together", sdk.Language, fixture)
			}
		}
	}
}
