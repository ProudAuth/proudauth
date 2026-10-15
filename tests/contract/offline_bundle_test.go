package contract

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

type bundleFixture struct{ root, bin, hashTool, hashFlag string }

func newBundleFixture(t *testing.T) bundleFixture {
	t.Helper()
	f := bundleFixture{root: t.TempDir()}
	f.bin = filepath.Join(f.root, "test-bin")
	f.hashTool, _ = exec.LookPath("sha256sum")
	if f.hashTool == "" {
		var err error
		f.hashTool, err = exec.LookPath("shasum")
		if err != nil {
			t.Fatal(err)
		}
		f.hashFlag = "shasum"
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		path = filepath.Join(f.root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	script, err := os.ReadFile(filepath.Join(repoRoot, "scripts/offline-bundle.sh"))
	if err != nil {
		t.Fatal(err)
	}
	write("scripts/offline-bundle.sh", string(script), 0o700)
	for _, path := range []string{"migrations/0001.sql", "migrations/embed.go", "api/openapi/identity.yaml", "deploy/compose/compose.yaml", "docs/operations/installation.md", "docs/operations/space name.md", "LICENSE", "NOTICE", "README.md", "SECURITY.md", "CHANGELOG.md"} {
		write(path, "public fixture: "+path+"\n", 0o600)
	}
	write("deploy/compose/secrets/private-fixture", "must-not-enter-the-bundle", 0o600)
	write("deploy/prod/.env", "# template\nPROUDAUTH_ROOT_KEY=must-not-enter-the-bundle\nPROUDAUTH_DATABASE_URL=postgres://u:must-not-enter-the-bundle@db/pa\nPROUDAUTH_LOG_LEVEL=info\n", 0o600)
	write("go.mod", "module github.com/proudbase/proudauth\n\ngo 1.27.1\n", 0o600)
	write("test-bin/go", `#!/bin/sh
set -eu
case "$1" in
 build)
  echo build >>"$TEST_BUNDLE_ROOT/go-calls"
  [ "${TEST_FAIL_BUILD:-0}" != 1 ] || exit 41
  if [ "${TEST_HOLD_BUILD:-0}" = 1 ]; then
   : >"$TEST_BUNDLE_ROOT/build-held"
   while [ ! -f "$TEST_BUNDLE_ROOT/release-build" ]; do sleep 0.02; done
  fi
  while [ "$1" != -o ]; do shift; done
  mkdir -p "$(dirname "$2")"
  printf 'test-only %s binary\n' "$GOARCH" >"$2"
  ;;
 list) printf 'github.com/proudbase/proudauth\n' ;;
 version) printf 'go version test-only linux/arm64\n' ;;
 *) exit 42 ;;
esac
`, 0o700)
	write("test-bin/docker", `#!/bin/sh
set -eu
case "$1" in
 image) [ "${TEST_FAIL_INSPECT:-0}" != 1 ] || exit 43 ;;
 save)
  [ "$2" = -o ] || exit 44
  printf 'partial image export' >"$3"
  [ "${TEST_FAIL_EXPORT:-0}" != 1 ] || exit 45
  ;;
 *) exit 46 ;;
esac
`, 0o700)
	write("test-bin/mv", `#!/bin/sh
set -eu
case "$1" in
 *.tar.gz.sha256)
  if [ "${TEST_FAIL_PUBLISH:-0}" = 1 ] && [ "$2" = dist/proudauth-dev-test-offline.tar.gz.sha256 ] && [ ! -f "$TEST_BUNDLE_ROOT/publish-failed" ]; then
   : >"$TEST_BUNDLE_ROOT/publish-failed"
   exit 47
  fi ;;
esac
exec /bin/mv "$@"
`, 0o700)
	write("test-bin/sha256sum", `#!/bin/sh
set -eu
[ "${TEST_FAIL_HASH:-0}" != 1 ] || { echo 'partial manifest'; exit 48; }
if [ "$TEST_HASH_FLAG" = shasum ]; then exec "$TEST_HASH_TOOL" -a 256 "$@"; fi
exec "$TEST_HASH_TOOL" "$@"
`, 0o700)
	write("dist/proudauth-dev-test-offline.tar.gz", "previous verified archive", 0o600)
	write("dist/proudauth-dev-test-offline.tar.gz.sha256", "previous verified checksum", 0o600)
	return f
}
func (f bundleFixture) command(ctx context.Context, version string, env ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "/bin/sh", filepath.Join(f.root, "scripts/offline-bundle.sh"), version)
	c.Dir = f.root
	c.Env = append(os.Environ(), "PATH="+f.bin+":/usr/bin:/bin", "TEST_BUNDLE_ROOT="+f.root, "BUNDLE_OUT=dist", "IMAGE=")
	c.Env = append(c.Env, "TEST_HASH_TOOL="+f.hashTool, "TEST_HASH_FLAG="+f.hashFlag)
	c.Env = append(c.Env, env...)
	return c
}
func (f bundleFixture) preserved(t *testing.T) {
	t.Helper()
	for name, want := range map[string]string{"proudauth-dev-test-offline.tar.gz": "previous verified archive", "proudauth-dev-test-offline.tar.gz.sha256": "previous verified checksum"} {
		got, err := os.ReadFile(filepath.Join(f.root, "dist", name))
		if err != nil || string(got) != want {
			t.Fatalf("prior artifact %s changed: %v", name, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(f.root, "dist"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("private staging/lock leaked: %v %v", entries, err)
	}
}

// TestOfflineBundleRejectsUnsafeVersion covers DEP-017: untrusted version
// labels cannot select filesystem paths or linker flags, and fail before a
// build or deletion. Prior release artifacts remain unchanged.
func TestOfflineBundleRejectsUnsafeVersion(t *testing.T) {
	for i, version := range []string{"", "../escape", "dev/../../outside", "dev bad", "dev;touch", "-dev", "dev\nmore"} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newBundleFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if out, err := f.command(ctx, version).CombinedOutput(); err == nil {
				t.Fatalf("unsafe version accepted: %s", out)
			}
			if _, err := os.Stat(filepath.Join(f.root, "go-calls")); !os.IsNotExist(err) {
				t.Fatal("unsafe version reached the builder")
			}
			f.preserved(t)
		})
	}
}

// TestOfflineBundleFailurePreservesArtifacts covers DEP-017 and QA-008:
// actual subprocess build/export/publication failures preserve the previous
// archive/checksum pair and remove only this invocation's staging files.
func TestOfflineBundleFailurePreservesArtifacts(t *testing.T) {
	for name, env := range map[string][]string{
		"build":                {"TEST_FAIL_BUILD=1"},
		"missing-image":        {"IMAGE=pa-bench-fixture:dev", "TEST_FAIL_INSPECT=1"},
		"partial-image-export": {"IMAGE=pa-bench-fixture:dev", "TEST_FAIL_EXPORT=1"},
		"checksum-publication": {"TEST_FAIL_PUBLISH=1"},
		"partial-checksum":     {"TEST_FAIL_HASH=1"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBundleFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if out, err := f.command(ctx, "dev-test", env...).CombinedOutput(); err == nil {
				t.Fatalf("failed operation reported success: %s", out)
			}
			f.preserved(t)
		})
	}
}

// TestOfflineBundleContentsAndChecksums covers DEP-017: the real packaging
// script's archive has both architecture command sets, reviewed inputs,
// internal/external integrity checks and no development secret or Go embed
// file. The controlled builder is not proof of native binary correctness.
func TestOfflineBundleContentsAndChecksums(t *testing.T) {
	f := newBundleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := f.command(ctx, "dev-test", "IMAGE=pa-bench-fixture:dev").CombinedOutput(); err != nil {
		t.Fatalf("bundle: %v: %s", err, out)
	}
	archive := filepath.Join(f.root, "dist/proudauth-dev-test-offline.tar.gz")
	data, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := os.ReadFile(archive + ".sha256")
	if err != nil || !strings.HasPrefix(string(sum), fmt.Sprintf("%x", sha256.Sum256(data))) {
		t.Fatal("external checksum mismatch", err)
	}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	tr := tar.NewReader(z)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := strings.TrimPrefix(h.Name, "proudauth-dev-test-offline/")
		if name == h.Name || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			t.Fatal("unsafe member", h.Name)
		}
		body, err := io.ReadAll(io.LimitReader(tr, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = body
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, cmd := range []string{"identity-server", "identity-worker", "identity-cli"} {
			if len(files["bin/linux-"+arch+"/"+cmd]) == 0 {
				t.Fatal("binary missing", arch, cmd)
			}
		}
	}
	for _, name := range []string{"LICENSE", "NOTICE", "VERIFY.md", "source-notes/modules.txt", "source-notes/toolchain.txt", "source-notes/commit.txt", "image-dev-test.tar.gz", "api/openapi/identity.yaml", "docs/operations/installation.md", "migrations/0001.sql"} {
		if len(files[name]) == 0 {
			t.Fatal("required file missing", name)
		}
	}
	for name, body := range files {
		if strings.Contains(name, "compose/secrets") || name == "migrations/embed.go" || bytes.Contains(body, []byte("must-not-enter-the-bundle")) {
			t.Fatal("private/development file shipped", name)
		}
	}
	if prod := string(files["deploy/prod/.env"]); !strings.Contains(prod, "PROUDAUTH_ROOT_KEY=\n") || !strings.Contains(prod, "PROUDAUTH_LOG_LEVEL=info\n") {
		t.Fatalf("the bundle must keep deploy/prod/.env as an emptied template, got %q", prod)
	}
	manifest := strings.TrimSpace(string(files["SHA256SUMS"]))
	seen := map[string]bool{}
	for _, line := range strings.Split(manifest, "\n") {
		digest, path, valid := strings.Cut(line, "  ")
		if !valid {
			t.Fatal("invalid checksum line", line)
		}
		name := strings.TrimPrefix(path, "./")
		body, ok := files[name]
		if !ok || digest != fmt.Sprintf("%x", sha256.Sum256(body)) || seen[name] {
			t.Fatal("internal checksum mismatch", name)
		}
		seen[name] = true
	}
	if len(seen) != len(files)-1 {
		t.Fatalf("not every file covered: %d / %d", len(seen), len(files))
	}
	entries, err := os.ReadDir(filepath.Join(f.root, "dist"))
	if err != nil || len(entries) != 2 {
		t.Fatal("staging or lock leaked", err)
	}
}

// TestOfflineBundleInterruptAndConcurrentRun covers DEP-017: concurrent
// writers of one version are refused, and SIGTERM releases owned temporary
// resources while retaining the prior artifacts and a nonzero exit.
func TestOfflineBundleInterruptAndConcurrentRun(t *testing.T) {
	f := newBundleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	first := f.command(ctx, "dev-test", "TEST_HOLD_BUILD=1")
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(filepath.Join(f.root, "release-build"), nil, 0o600)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(f.root, "build-held")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controlled build did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if out, err := f.command(ctx, "dev-test").CombinedOutput(); err == nil {
		t.Fatalf("concurrent writer accepted: %s", out)
	}
	if err := first.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.root, "release-build"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err == nil {
		t.Fatal("interrupted build reported success")
	}
	f.preserved(t)
}
