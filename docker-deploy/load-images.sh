#!/bin/sh
set -eu
cd "$(dirname "$0")"
archive=images/proudauth-images-linux-arm64.tar.gz
[ -f "$archive" ] || { printf '%s\n' "Missing image archive: $archive" >&2; exit 1; }
# Docker accepts a gzip-compressed image archive directly.
docker load --input "$archive"
