package contract

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestLocalReproductionRefusesMismatches covers DEP-003 and SEC-016: the
// executable wrapper disables downloads before Go preflight, handles a
// cached digest without its version tag, checks all 12 targets, fails on a
// byte mismatch/wrong SDK and removes its owned container/temporary work.
// Controlled compilers test orchestration; published real builds prove bytes.
func TestLocalReproductionRefusesMismatches(t *testing.T) {
	for _, mode := range []string{"identical", "platform-builder", "mismatch", "wrong-sdk", "unsafe-version"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			write := func(path, body string) {
				t.Helper()
				path = filepath.Join(root, path)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(filepath.Join(repoRoot, "scripts/repro-local.sh"))
			if err != nil {
				t.Fatal(err)
			}
			write("scripts/repro-local.sh", string(data))
			platformFlag := ""
			if mode == "platform-builder" {
				platformFlag = "--platform=$BUILDPLATFORM "
			}
			write("Dockerfile", "FROM "+platformFlag+"golang:1.27.2-trixie@sha256:e58d6f83b3416618d8bcac2b3dde1b7f7e3c4a77d25e88637f8bbae81536c48d AS build\n")
			for _, dir := range []string{"cmd", "internal", "migrations", "module-cache", "sdk", "tmp"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			write("go.mod", "module github.com/proudbase/proudauth\n\ngo 1.27.1\n")
			write("go.sum", "fixture\n")
			write("bin/go", `#!/bin/sh
set -eu
[ "$GOPROXY" = off ] && [ "$GOSUMDB" = off ] && [ "$GOTOOLCHAIN" = local ] && [ "$GOENV" = off ] || exit 21
[ "$GOWORK" = off ] && [ "$GO111MODULE" = on ] && [ -z "$GOFLAGS" ] && [ -z "$GOEXPERIMENT" ] || exit 22
case "$1" in
 env) case "$2" in GOROOT) echo "$REPRO_FIXTURE/sdk";; GOMODCACHE) echo "$REPRO_FIXTURE/module-cache";; *) exit 23;; esac ;;
 version) echo 'go version go1.27.2 fixture/arm64' ;;
 build)
  while [ "$1" != -o ]; do shift; done
  mkdir -p "$(dirname "$2")"
  printf 'controlled %s %s\n' "$GOOS/$GOARCH" "$(basename "$2")" >"$2"
  if [ "$REPRO_MODE" = mismatch ] && [ "${REPRO_BUILDER:-host}" = linux ] && [ "$GOOS/$GOARCH" = darwin/arm64 ] && [ "$(basename "$2")" = identity-cli_darwin_arm64 ]; then echo mismatch >>"$2"; fi
  ;;
 *) exit 24 ;;
esac
`)
			write("bin/docker", `#!/bin/sh
set -eu
case "$1" in
 image)
  case "$*" in *golang:*) exit 31;; esac
  if [ "$3" = -f ]; then
   if [ "$REPRO_MODE" = wrong-sdk ]; then echo GOLANG_VERSION=1.26.0; else echo GOLANG_VERSION=1.27.2; fi
  fi ;;
 create)
  case " $* " in *' --network none '*) ;; *) exit 32;; esac
  case " $* " in *' --pull=never '*) ;; *) exit 33;; esac
  for arg in "$@"; do case "$arg" in *:/work) echo "${arg%:/work}" >"$REPRO_FIXTURE/work";; esac; done
  : >"$REPRO_FIXTURE/created" ;;
 start)
  work=$(cat "$REPRO_FIXTURE/work")
  REPRO_BUILDER=linux /bin/sh "$work/build.sh" "$REPRO_FIXTURE/bin/go" "$work/linux" "$work/source" dev-repro-test ;;
 inspect) echo 0 ;;
 cp) echo go1.27.2 >"$3" ;;
 stop) : >"$REPRO_FIXTURE/stopped" ;;
 rm) : >"$REPRO_FIXTURE/removed" ;;
 *) exit 34 ;;
esac
`)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			version := "dev-repro-test"
			if mode == "unsafe-version" {
				version = "dev -X unsafe=value"
			}
			cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(root, "scripts/repro-local.sh"))
			cmd.Dir = root
			cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin:/opt/homebrew/bin", "TMPDIR="+filepath.Join(root, "tmp"), "REPRO_FIXTURE="+root, "REPRO_MODE="+mode,
				"REPRO_OUT="+filepath.Join(root, "out"), "REPRO_VERSION="+version, "GOPROXY=https://forbidden.invalid", "GOSUMDB=sum.golang.org", "GOTOOLCHAIN=auto",
				"GOFLAGS=-race", "GOEXPERIMENT=invalid", "GOWORK="+filepath.Join(root, "untrusted.work"))
			output, err := cmd.CombinedOutput()
			wantPass := mode == "identical" || mode == "platform-builder"
			if wantPass && err != nil {
				t.Fatalf("controlled reproduction failed: %v: %s", err, output)
			}
			if !wantPass && err == nil {
				t.Fatalf("%s reported success", mode)
			}
			if wantPass || mode == "mismatch" {
				body, err := os.ReadFile(filepath.Join(root, "out/comparison.json"))
				if err != nil {
					t.Fatal(err)
				}
				var r struct {
					Pass    bool `json:"pass"`
					Targets []struct {
						Identical bool `json:"identical"`
					} `json:"targets"`
				}
				if err := json.Unmarshal(body, &r); err != nil {
					t.Fatal(err)
				}
				if len(r.Targets) != 12 || r.Pass != wantPass {
					t.Fatal("incomplete/misclassified comparison")
				}
				matched := 0
				for _, row := range r.Targets {
					if row.Identical {
						matched++
					}
				}
				want := 12
				if mode == "mismatch" {
					want = 11
				}
				if matched != want {
					t.Fatal("mismatch not isolated", matched)
				}
				for _, name := range []string{"stopped", "removed"} {
					if _, err := os.Stat(filepath.Join(root, name)); err != nil {
						t.Fatal("owned container cleanup missing", name)
					}
				}
				work, err := os.ReadFile(filepath.Join(root, "work"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(string(work[:len(work)-1])); !os.IsNotExist(err) {
					t.Fatal("private work directory retained")
				}
			} else if _, err := os.Stat(filepath.Join(root, "created")); !os.IsNotExist(err) {
				t.Fatal("invalid setup created a container")
			}
		})
	}
}
