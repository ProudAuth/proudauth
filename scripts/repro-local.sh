#!/bin/sh
# Two-OS binary reproduction for M0, DEP-003 and SEC-016. Uses the cached
# Dockerfile Go image without pulling, and a host toolchain of that same
# version (bootstrapped from the image's Go source when needed). Both build
# the release's 12 OS/architecture/command targets from one frozen checkout
# snapshot, with separate writable caches and networking disabled in Docker.
# Results are hashes/metadata only; all private SDKs, caches, binaries and
# this invocation's pa-bench- container are removed by the cleanup trap.
# One physical host: this does not attest an official release or image.
set -eu
# Disable downloads before the first go env/version call, and make both
# builders ignore caller-specific workspaces, flags and experiments.
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOENV=off GOWORK=off GO111MODULE=on GOFLAGS= GOEXPERIMENT=
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${REPRO_VERSION:-dev-repro}
case "$VERSION" in ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*) echo 'invalid REPRO_VERSION' >&2; exit 2;; esac
for tool in go docker python3 bash; do command -v "$tool" >/dev/null 2>&1 || { echo "$tool is required" >&2; exit 1; }; done
IMAGE=$(awk '$1=="FROM" {image=$2; if (image ~ /^--platform=/) image=$3; if (image ~ /^golang:/) {print image; exit}}' "$ROOT/Dockerfile")
case "$IMAGE" in *@sha256:*) ;; *) echo 'Dockerfile Go image needs an immutable digest' >&2; exit 1;; esac
# Docker can retain a repository digest after its version tag disappears.
# Resolve that same immutable repository reference without adding a tag.
REPOSITORY=${IMAGE%@*}
REPOSITORY=${REPOSITORY%:*}
CACHE_REF=$REPOSITORY@${IMAGE#*@}
docker image inspect "$CACHE_REF" >/dev/null || { echo 'Go image must already be cached; no pull is allowed' >&2; exit 1; }
EXPECTED=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CACHE_REF" | sed -n 's/^GOLANG_VERSION=//p')
PINNED=$(printf '%s' "$IMAGE" | sed -n 's/^golang:\([0-9][0-9.]*\)-.*/\1/p')
[ -n "$PINNED" ] && [ "$PINNED" = "$EXPECTED" ] || { echo 'cached SDK differs from Dockerfile version' >&2; exit 1; }
BOOTSTRAP_ROOT=$(go env GOROOT)
MODULE_CACHE=$(go env GOMODCACHE)
HOST_GO=$(command -v go)
OUT=${REPRO_OUT:-$ROOT/repro-results/$(date -u +%Y%m%dT%H%M%SZ)}
if [ -e "$OUT" ]; then [ -d "$OUT" ] && [ -z "$(ls -A "$OUT")" ] || { echo 'REPRO_OUT must be fresh or empty' >&2; exit 1; }; fi
mkdir -p "$OUT"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/pa-bench-repro.XXXXXX")
CONTAINER=pa-bench-repro-$$
CREATED=0
cleanup() {
  result=$?
  trap - 0 INT TERM
  if [ "$CREATED" = 1 ]; then docker stop -t 3 "$CONTAINER" >/dev/null 2>&1 || true; docker rm --volumes "$CONTAINER" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
  exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'work: %s\n' "$WORK"
mkdir -p "$WORK/source"
cp -R "$ROOT/cmd" "$ROOT/internal" "$ROOT/migrations" "$WORK/source/"
cp "$ROOT/go.mod" "$ROOT/go.sum" "$WORK/source/"
python3 - "$WORK/source" "$OUT/source-snapshot.json" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);rows=[]
for p in sorted(root.rglob('*')):
    if p.is_file(): rows.append([str(p.relative_to(root)),hashlib.sha256(p.read_bytes()).hexdigest()])
encoded=json.dumps(rows,separators=(',',':')).encode()
pathlib.Path(sys.argv[2]).write_text(json.dumps({'files':len(rows),'snapshot_sha256':hashlib.sha256(encoded).hexdigest(),'file_sha256':dict(rows)},indent=2)+'\n')
PY
cat > "$WORK/build.sh" <<'SH'
#!/bin/sh
set -eu
compiler=$1 output=$2 source=$3 version=$4
mkdir -p "$output"
cd "$source"
for target_os in linux darwin; do
  for target_arch in amd64 arm64; do
    for command in identity-server identity-worker identity-cli; do
      printf 'build %s %s/%s\n' "$command" "$target_os" "$target_arch"
      CGO_ENABLED=0 GOOS=$target_os GOARCH=$target_arch GOAMD64=v1 GOARM64=v8.0 \
        "$compiler" build -mod=readonly -buildvcs=false -trimpath \
        -ldflags "-s -w -buildid= -X main.version=$version" \
        -o "$output/${command}_${target_os}_${target_arch}" "./cmd/$command"
    done
  done
done
SH
# One owned container doubles as the Linux builder and cached SDK source.
docker create --pull=never --network none --name "$CONTAINER" \
  -v "$WORK:/work" -v "$MODULE_CACHE:/module-cache:ro" \
  -e GOPROXY=off -e GOSUMDB=off -e GOTOOLCHAIN=local -e GOENV=off \
  -e GOMODCACHE=/module-cache -e GOCACHE=/work/linux-cache -e GOPATH=/work/linux-gopath \
  "$CACHE_REF" /bin/sh /work/build.sh /usr/local/go/bin/go /work/linux /work/source "$VERSION" >/dev/null
CREATED=1
if [ "$(go version | awk '{print $3}')" != "go$EXPECTED" ]; then
  printf 'bootstrap host Go %s from cached SDK source\n' "$EXPECTED"
  mkdir -p "$WORK/host-sdk"
  docker cp "$CONTAINER:/usr/local/go/." "$WORK/host-sdk/"
  (unset GOOS GOARCH GOFLAGS GOROOT; export CGO_ENABLED=0 GOROOT_BOOTSTRAP="$BOOTSTRAP_ROOT" GOCACHE="$WORK/bootstrap-cache";
    cd "$WORK/host-sdk/src"; bash ./make.bash) >"$WORK/bootstrap.log" 2>&1 || { tail -n 12 "$WORK/bootstrap.log" >&2; exit 1; }
  HOST_GO=$WORK/host-sdk/bin/go
fi
"$HOST_GO" version >"$OUT/host-toolchain.txt"
[ "$("$HOST_GO" version | awk '{print $3}')" = "go$EXPECTED" ] || { echo 'host toolchain differs from pinned image' >&2; exit 1; }
printf 'Linux builder\n'
docker start -a "$CONTAINER"
docker inspect -f '{{.State.ExitCode}}' "$CONTAINER" >"$WORK/linux-exit"
[ "$(cat "$WORK/linux-exit")" = 0 ] || { echo 'Linux build failed' >&2; exit 1; }
docker cp "$CONTAINER:/usr/local/go/VERSION" "$OUT/linux-toolchain-version.txt"
printf 'host builder\n'
GOMODCACHE="$MODULE_CACHE" GOCACHE="$WORK/host-cache" GOPATH="$WORK/host-gopath" \
  /bin/sh "$WORK/build.sh" "$HOST_GO" "$WORK/host" "$WORK/source" "$VERSION"
python3 - "$WORK" "$OUT" "$VERSION" "$IMAGE" <<'PY'
import hashlib,json,pathlib,platform,sys,datetime
work,out=map(pathlib.Path,sys.argv[1:3]);version,image=sys.argv[3:5]
rows=[]
for target_os in ['linux','darwin']:
    for arch in ['amd64','arm64']:
        for command in ['identity-server','identity-worker','identity-cli']:
            name=f'{command}_{target_os}_{arch}';a,b=work/'host'/name,work/'linux'/name
            x,y=a.read_bytes(),b.read_bytes()
            rows.append({'target':name,'host_bytes':len(x),'linux_bytes':len(y),'host_sha256':hashlib.sha256(x).hexdigest(),'linux_sha256':hashlib.sha256(y).hexdigest(),'identical':x==y})
r={'format_version':'1','checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'version':version,'image':image,
   'host':{'os':platform.system(),'architecture':platform.machine(),'toolchain':(out/'host-toolchain.txt').read_text().strip()},
   'linux':{'os':'Linux','toolchain_version':(out/'linux-toolchain-version.txt').read_text().strip(),'network':'none'},
   'source_snapshot_sha256':json.loads((out/'source-snapshot.json').read_text())['snapshot_sha256'],
   'build_flags':'CGO_ENABLED=0 GOAMD64=v1 GOARM64=v8.0; -mod=readonly -buildvcs=false -trimpath; -ldflags=-s -w -buildid= -X main.version='+version,
   'same_physical_host':True,'separate_build_caches':True,'modules':'same populated module cache, Linux mount read-only, proxy/sumdb/toolchain downloads disabled',
   'targets':rows,'pass':all(row['identical'] for row in rows),'limits':['Frozen development checkout, no Git commit/tag or official release attestation.','One physical host, separate OS environments; not an independent organization or machine.','Binary reproduction only; no container-image reproduction, current vulnerability audit or external security review.']}
(out/'comparison.json').write_text(json.dumps(r,indent=2)+'\n')
print('identical',sum(row['identical'] for row in rows),'/',len(rows))
if not r['pass']: raise SystemExit('binary reproduction mismatch; comparison retained')
PY
printf 'results: %s\n' "$OUT"
