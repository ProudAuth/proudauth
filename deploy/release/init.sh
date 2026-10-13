#!/bin/sh
# DEP-002, DEP-004, DEP-006, OPS-013: stable file secrets and separate DB roles.
set -eu
cd "$(dirname "$0")"
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required for safe configuration generation.' >&2; exit 1; }
exec python3 ./configure.py "$@"
