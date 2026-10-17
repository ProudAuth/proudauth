#!/usr/bin/env bash
# Runs shard INDEX of TOTAL of the end-to-end suite (QA-001): the top-level
# tests of ./tests/e2e, sorted by name and dealt round-robin into TOTAL shards.
# Any further arguments go to go test. CI runs the shards as parallel jobs
# (.github/workflows/ci.yml, job e2e). A test added to the package lands in a
# shard automatically, because the list comes from go test -list.
#
#   scripts/e2e-shard.sh 0 4 -count=1 -race -timeout 25m -json
set -euo pipefail
if [ $# -lt 2 ]; then
  echo "usage: $0 INDEX TOTAL [go test flags]" >&2
  exit 2
fi
index=$1
total=$2
shift 2
if ! [[ "$index" =~ ^[0-9]+$ && "$total" =~ ^[1-9][0-9]*$ ]] || [ "$index" -ge "$total" ]; then
  echo "$0: INDEX must be a number in 0..TOTAL-1" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
# go test -list prints the matching test names and then "ok <package>".
all=$(go test ./tests/e2e -list '^Test' | grep '^Test' | LC_ALL=C sort)
if [ -z "$all" ]; then
  echo "$0: go test -list found no tests in ./tests/e2e" >&2
  exit 1
fi
mine=$(awk -v i="$index" -v n="$total" '(NR - 1) % n == i' <<<"$all")
if [ -z "$mine" ]; then
  echo "$0: shard $index of $total has no tests" >&2
  exit 1
fi
pattern="^($(paste -sd'|' <<<"$mine"))\$"
echo "e2e shard $index of $total: $(wc -l <<<"$mine" | tr -d ' ') of $(wc -l <<<"$all" | tr -d ' ') tests" >&2
exec go test ./tests/e2e -run "$pattern" "$@"
