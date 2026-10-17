package contract

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// releaseStateExcluded are the documents TestDocsDoNotDenyPublishedReleases
// does not read: the specification, whose dated checkpoints describe the
// checkout they were written for; the generated traceability matrix; and the
// directories of recorded benchmark, consistency and release evidence, which
// keep the wording of the snapshot they record. A directory ends in "/" and
// excludes everything below it; anything else names exactly one file.
var releaseStateExcluded = []string{
	"docs/plan.md",
	"docs/requirements-traceability.md",
	"docs/operations/bench-results/",
	"docs/operations/consistency-results/",
	"docs/operations/release-results/",
}

// releaseStateStale are statements that were true before the first
// prerelease, the SDK repository split or the first npm publication, and are
// false now. They are matched case-insensitively on text whose runs of white
// space are folded into one space, so a line break cannot hide them.
var releaseStateStale = []string{
	// v0.2.0-alpha.1 was published on 2026-10-13.
	"no version has been tagged",
	"has not published a release",
	"no release has been tagged",
	"no release has been published",
	"nothing is released yet",
	"with nothing tagged",
	"this local snapshot has not been published",
	// SECURITY.md: the latest prerelease receives fixes, not main.
	"only the `main` branch receives fixes",
	// The SDKs moved to their own repositories (proudauth-sdk-*).
	"sdk/node/",
	"sdk/dart/",
	"sdk/php/",
	"sdk/dotnet/",
	"sdk/go/",
	// @proudauth/sdk 0.2.0 has been on npm since 2026-10-16.
	"unpublished 0.2.0): verifier",
	"npm, pub.dev, packagist and nuget packages have not been published",
	// PostgreSQL 18.x is the only supported version; CI runs 18.6.
	"postgres:17",
	"ci runs against postgresql 17",
	"postgresql 17 (ci)",
}

// TestDocsDoNotDenyPublishedReleases covers GOV-005, GOV-008 and SEC-019:
// the README, SECURITY.md, CONTRIBUTING.md and every document under docs/
// (except the historical records in releaseStateExcluded) describe the
// published state. None says that nothing has been tagged or published, that
// only main receives security fixes, or that the SDKs live under sdk/; the
// README's current release, any "today `vX`" claim and the documented Go SDK
// pin match what deploy/prod/.env and go.mod actually pin.
func TestDocsDoNotDenyPublishedReleases(t *testing.T) {
	docs := releaseStateDocs(t)

	t.Run("matcher", func(t *testing.T) {
		// Passages as they stood before the 2026-10-17 consistency pass.
		old := "The source API version is **0.2.0**. npm, pub.dev, Packagist and NuGet packages\n" +
			"have not been published; public source availability does not establish registry\n\n" +
			"No release has been tagged yet, so today only the `main` branch receives fixes.\n" +
			"- the component (for example `internal/oauth`, `sdk/go/verifier`, a migration);\n"
		got := releaseStateFind(old)
		want := []string{
			`1: "npm, pub.dev, packagist and nuget packages have not been published"`,
			`4: "no release has been tagged"`,
			"4: \"only the `main` branch receives fixes\"",
			`5: "sdk/go/"`,
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("stale passages found as\n%q\nwant\n%q", got, want)
		}
	})

	t.Run("no stale statements", func(t *testing.T) {
		for _, rel := range docs {
			for _, f := range releaseStateFind(govRead(t, rel)) {
				t.Errorf("%s:%s, which is no longer true; describe the published state (docs/releases/)", rel, f)
			}
		}
	})

	image := deployEnvFile(t, "deploy/prod/.env")["PROUDAUTH_IMAGE"]
	pinned, ok := strings.CutPrefix(image, "ghcr.io/proudauth/proudauth:")
	if !ok || pinned == "" {
		t.Fatalf("deploy/prod/.env pins %q, not a ghcr.io/proudauth/proudauth version", image)
	}

	t.Run("current release", func(t *testing.T) {
		var current []string
		for _, line := range strings.Split(govRead(t, "README.md"), "\n") {
			if strings.HasPrefix(line, "**Current release:") {
				current = append(current, line)
			}
		}
		if len(current) != 1 {
			t.Fatalf("README.md has %d \"**Current release:\" lines, want 1", len(current))
		}
		if !strings.Contains(current[0], "`v"+pinned+"`") {
			t.Errorf("README.md says %q, but deploy/prod/.env pins %s", current[0], pinned)
		}
		today := regexp.MustCompile("(?i)\\btoday `(v[^`]+)`")
		for _, rel := range docs {
			for _, m := range today.FindAllStringSubmatch(govRead(t, rel), -1) {
				if m[1] != "v"+pinned {
					t.Errorf("%s says %q, but deploy/prod/.env pins %s; name the current release", rel, m[0], pinned)
				}
			}
		}
	})

	t.Run("go sdk pin", func(t *testing.T) {
		pin := regexp.MustCompile(`(?m)^\s*github\.com/proudauth/proudauth-sdk-go (v\S+)$`).FindStringSubmatch(govRead(t, "go.mod"))
		if pin == nil {
			t.Fatal("go.mod does not require github.com/proudauth/proudauth-sdk-go")
		}
		if doc := govRead(t, "docs/repository-migration.md"); !strings.Contains(doc, "`"+pin[1]+"`") {
			t.Errorf("docs/repository-migration.md does not name the Go SDK version go.mod pins (%s)", pin[1])
		}
	})
}

// releaseStateDocs lists README.md, SECURITY.md, CONTRIBUTING.md and the
// Markdown files under docs/ that are not excluded. Every exclusion must
// still exclude something, so the list cannot outgrow the repository.
func releaseStateDocs(t *testing.T) []string {
	t.Helper()
	docs := []string{"README.md", "SECURITY.md", "CONTRIBUTING.md"}
	used := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(repoRoot, "docs"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if slices.Contains(releaseStateExcluded, rel+"/") {
				used[rel+"/"] = true
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".md") {
			return nil
		}
		if slices.Contains(releaseStateExcluded, rel) {
			used[rel] = true
			return nil
		}
		docs = append(docs, rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ex := range releaseStateExcluded {
		if !used[ex] {
			t.Errorf("releaseStateExcluded names %s, which does not exist; remove it", ex)
		}
	}
	return docs
}

// releaseStateFind returns `<line>: "<phrase>"` for every occurrence of a
// releaseStateStale phrase in text. The text is lower-cased and its runs of
// white space are folded into one space; the line is where the phrase starts.
func releaseStateFind(text string) []string {
	var words []string
	var lines []int
	for n, line := range strings.Split(text, "\n") {
		for _, w := range strings.Fields(line) {
			words = append(words, strings.ToLower(w))
			lines = append(lines, n+1)
		}
	}
	folded := strings.Join(words, " ")
	var found []string
	for _, phrase := range releaseStateStale {
		for off := 0; ; {
			i := strings.Index(folded[off:], phrase)
			if i < 0 {
				break
			}
			at := off + i
			found = append(found, fmt.Sprintf("%d: %q", lines[strings.Count(folded[:at], " ")], phrase))
			off = at + len(phrase)
		}
	}
	return found
}
