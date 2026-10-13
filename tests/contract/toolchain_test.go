package contract

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestReleaseToolchainPinned keeps release binaries and the container image on
// one exact Go toolchain (DEP-003, SEC-016): the release workflow's
// go-version must equal the Dockerfile's build-stage golang tag, and neither
// may float.
func TestReleaseToolchainPinned(t *testing.T) {
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	release, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	image := regexp.MustCompile(`(?m)^FROM (?:--platform=\S+\s+)?golang:(\d+\.\d+\.\d+)[-\s]`).FindSubmatch(dockerfile)
	if image == nil {
		t.Fatal("Dockerfile build stage must use an exact golang:<major>.<minor>.<patch> tag")
	}
	setup := regexp.MustCompile(`go-version: "([^"]+)"`).FindAllSubmatch(release, -1)
	if len(setup) == 0 {
		t.Fatal("release.yml sets no go-version")
	}
	for _, m := range setup {
		if string(m[1]) != string(image[1]) {
			t.Errorf("release.yml go-version %q differs from the Dockerfile's golang:%s", m[1], image[1])
		}
	}
	if regexp.MustCompile(`check-latest:\s*true`).Match(release) {
		t.Error("release.yml must not use check-latest: the release toolchain is pinned")
	}
	for _, from := range regexp.MustCompile(`(?m)^FROM (?:--platform=\S+\s+)?(\S+)`).FindAllSubmatch(dockerfile, -1) {
		if !regexp.MustCompile(`@sha256:[a-f0-9]{64}$`).Match(from[1]) {
			t.Errorf("external build/runtime image %q must carry an immutable digest", from[1])
		}
	}
	if !regexp.MustCompile(`(?m)^# syntax=docker/dockerfile:[A-Za-z0-9_.-]+@sha256:[a-f0-9]{64}$`).Match(dockerfile) {
		t.Error("Dockerfile frontend must carry an immutable digest")
	}
	if !regexp.MustCompile(`-buildid=`).Match(release) {
		t.Error("release binaries must be built with -buildid= like the image")
	}
}

// TestWorkflowActionsPinned covers SEC-016 and DEP-003: external action
// references must resolve to full immutable commits, while local workflows
// remain tied to the checked-out source. Mutable tags and shortened hashes
// cannot silently replace reviewed references.
func TestWorkflowActionsPinned(t *testing.T) {
	commit := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[a-f0-9]{40}$`)
	pinned := func(ref string) bool {
		return strings.HasPrefix(ref, "./") || commit.MatchString(ref)
	}
	for _, tc := range []struct {
		name, ref string
		want      bool
	}{
		{"local", "./.github/workflows/ci.yml", true},
		{"commit", "actions/checkout@" + strings.Repeat("a", 40), true},
		{"subdirectory", "owner/repo/action@" + strings.Repeat("b", 40), true},
		{"major-tag", "actions/checkout@v4", false},
		{"release-tag", "actions/checkout@v4.2.2", false},
		{"branch", "actions/checkout@main", false},
		{"short-hash", "actions/checkout@11d5960", false},
		{"missing-ref", "actions/checkout", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pinned(tc.ref); got != tc.want {
				t.Fatalf("immutable reference %q: got %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
	paths, err := filepath.Glob("../../.github/workflows/*.y*ml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("workflow inventory: %v", err)
	}
	uses := regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*(\S+)`)
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range uses.FindAllSubmatch(data, -1) {
			ref := strings.Trim(string(match[1]), "\"'")
			if !pinned(ref) {
				t.Errorf("%s has a mutable external action reference: %q", path, ref)
			}
		}
	}
}
