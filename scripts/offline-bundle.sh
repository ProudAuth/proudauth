#!/usr/bin/env sh
# Builds an air-gap installation bundle (DEP-017): static binaries for Linux
# amd64/arm64, migrations, deployment manifests, API contracts, documentation,
# license/notice files, an optional container image archive, SHA256 checksums and
# verification instructions. Build/export failures preserve prior artifacts;
# a private staging directory is removed on success, failure or interruption.
#
#   ./scripts/offline-bundle.sh v0.1.0            # binaries + files
#   IMAGE=proudauth:v0.1.0 ./scripts/offline-bundle.sh v0.1.0   # also docker save
set -eu
cd "$(dirname "$0")/.."
[ "$#" -le 1 ] || { echo 'usage: offline-bundle.sh [version]' >&2; exit 2; }
VERSION=${1-dev}
case "$VERSION" in
  ''|[!A-Za-z0-9]*|*[!A-Za-z0-9._+-]*)
    echo 'offline bundle version must start with a letter/digit and contain only letters, digits, dot, underscore, plus or hyphen' >&2
    exit 2 ;;
esac
if [ -n "${IMAGE:-}" ]; then
  command -v docker >/dev/null 2>&1 || { echo 'IMAGE requires Docker; no image was exported' >&2; exit 1; }
  docker image inspect -- "$IMAGE" >/dev/null || { echo 'IMAGE must already exist locally; nothing is pulled' >&2; exit 1; }
fi
NAME="proudauth-${VERSION}-offline"
DIST=${BUNDLE_OUT:-dist}
ARCHIVE="$DIST/${NAME}.tar.gz"
CHECKSUM="$ARCHIVE.sha256"
for path in "$ARCHIVE" "$CHECKSUM"; do
  if [ -L "$path" ] || { [ -e "$path" ] && [ ! -f "$path" ]; }; then
    echo 'offline bundle output must be a regular file, not a directory or symbolic link' >&2
    exit 1
  fi
done
mkdir -p "$DIST"
LOCK="$DIST/.pa-bench-bundle-$VERSION.lock"
mkdir "$LOCK" 2>/dev/null || { echo 'an offline bundle build already owns this version/output directory' >&2; exit 1; }
STAGE=
PUBLISHING=0
PUBLISHED=0
HAD_ARCHIVE=0
HAD_CHECKSUM=0
[ ! -e "$ARCHIVE" ] || HAD_ARCHIVE=1
[ ! -e "$CHECKSUM" ] || HAD_CHECKSUM=1
cleanup() {
  result=$?
  trap - 0 INT TERM
  if [ "$PUBLISHING" = 1 ] && [ "$PUBLISHED" = 0 ]; then
    if [ -f "$STAGE/previous-archive" ]; then mv -f "$STAGE/previous-archive" "$ARCHIVE"; elif [ "$HAD_ARCHIVE" = 0 ]; then rm -f "$ARCHIVE"; fi
    if [ -f "$STAGE/previous-checksum" ]; then mv -f "$STAGE/previous-checksum" "$CHECKSUM"; elif [ "$HAD_CHECKSUM" = 0 ]; then rm -f "$CHECKSUM"; fi
  fi
  [ -z "$STAGE" ] || rm -rf "$STAGE"
  rmdir "$LOCK"
  exit "$result"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
STAGE=$(mktemp -d "$DIST/.pa-bench-bundle.XXXXXX")
STAGE=$(cd "$STAGE" && pwd)
OUT="$STAGE/$NAME"
mkdir -p "$OUT/bin" "$OUT/source-notes"

for arch in amd64 arm64; do
  for cmd in identity-server identity-worker identity-cli; do
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -buildid= -X main.version=${VERSION}" \
      -o "$OUT/bin/linux-${arch}/${cmd}" "./cmd/${cmd}"
  done
done

cp -R migrations deploy api "$OUT/"
rm -f "$OUT/migrations/embed.go"
mkdir -p "$OUT/docs"
for d in architecture-decisions operations threat-models protocols integrations; do
  [ -d "docs/$d" ] && cp -R "docs/$d" "$OUT/docs/"
done
for f in LICENSE NOTICE README.md SECURITY.md CHANGELOG.md; do
  [ -f "$f" ] && cp "$f" "$OUT/"
done
# A production .env filled in this checkout never leaves it: the bundle keeps
# the template with every deployment value emptied.
if [ -f "$OUT/deploy/prod/.env" ]; then
  sed -E 's/^(PROUDAUTH_(PUBLIC_ORIGIN|TRUSTED_PROXIES|DATABASE_URL|ROOT_KEY|SMTP_HOST|SMTP_USERNAME|SMTP_PASSWORD|EMAIL_FROM))=.*/\1=/' \
    "$OUT/deploy/prod/.env" > "$OUT/deploy/prod/.env.template"
  mv -f "$OUT/deploy/prod/.env.template" "$OUT/deploy/prod/.env"
fi

# Record the exact module set the binaries were built from (license review and
# vulnerability triage without network access).
go list -m all > "$OUT/source-notes/modules.txt"
go version > "$OUT/source-notes/toolchain.txt"
git rev-parse HEAD > "$OUT/source-notes/commit.txt" 2>/dev/null || echo "unknown" > "$OUT/source-notes/commit.txt"

if [ -n "${IMAGE:-}" ]; then
  # POSIX sh has no pipefail: saving through a gzip pipeline hides an export
  # failure. Check the local image export before compressing its archive.
  docker save -o "$STAGE/image.tar" -- "$IMAGE"
  docker image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE" > "$OUT/source-notes/image-platform.txt"
  gzip -c "$STAGE/image.tar" > "$OUT/image-${VERSION}.tar.gz"
  rm -f "$STAGE/image.tar"
fi

cat > "$OUT/VERIFY.md" <<VERIFY
# Verifying and installing ProudAuth ${VERSION} offline

1. Verify integrity before copying the bundle into the isolated network:

       sha256sum -c SHA256SUMS

   Compare the SHA256SUMS file itself with the checksum published on the release
   page (and its build provenance attestation) over a trusted channel.
2. Load the image (if included): \`gunzip -c image-${VERSION}.tar.gz | docker load\`.
   Its platform is recorded in \`source-notes/image-platform.txt\`; the official
   release's bundled image is Linux amd64, while the published registry image
   supports Linux amd64 and arm64. Alternatively install the static binaries
   from \`bin/linux-<arch>/\` for either architecture.
3. Follow docs/operations for installation, bootstrap and upgrades. Migrations
   are embedded in the binaries (\`identity-cli migrate\`); the SQL files under
   migrations/ are included for review.
4. No step contacts a project-operated service (OSS-003, OSS-005). Upstream
   identity providers, SMTP and SMS gateways are reached only if you configure them.
VERIFY

hash() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
# Keep each command's exit status: pipelines hide find/hash errors in POSIX
# sh, and xargs would split legitimate filenames containing spaces.
(cd "$OUT" && find . -type f ! -path './SHA256SUMS' -print > "$STAGE/files")
LC_ALL=C sort "$STAGE/files" > "$STAGE/files-sorted"
(cd "$OUT" && while IFS= read -r path; do hash "$path"; done < "$STAGE/files-sorted" > SHA256SUMS)
COPYFILE_DISABLE=1 tar -C "$STAGE" -czf "$STAGE/${NAME}.tar.gz" "$NAME"
(cd "$STAGE" && hash "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256")
# Only the archive and its checksum remain in dist/, so release tooling can
# treat every entry as a release asset.
PUBLISHING=1
[ "$HAD_ARCHIVE" = 0 ] || mv "$ARCHIVE" "$STAGE/previous-archive"
[ "$HAD_CHECKSUM" = 0 ] || mv "$CHECKSUM" "$STAGE/previous-checksum"
mv "$STAGE/${NAME}.tar.gz" "$ARCHIVE"
mv "$STAGE/${NAME}.tar.gz.sha256" "$CHECKSUM"
PUBLISHED=1
echo "bundle: $ARCHIVE"
