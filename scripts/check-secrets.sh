#!/usr/bin/env sh
# Fails if likely secrets are committed (SEC-016, QA-002). Test fixtures use
# clearly fake values and are allow-listed by path.
set -eu
cd "$(dirname "$0")/.."

patterns='-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----|pa_(rt|at|ac|it|key|pat|ses|cs)_[A-Za-z0-9_-]{20,}|whsec_[A-Za-z0-9+/=]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{30,}'

files=$( (git ls-files --cached --others --exclude-standard 2>/dev/null || find . -type f -not -path './.git/*') \
  | grep -v -E '^(\./)?(tests/|.*_test\.go$|docs/|scripts/check-secrets\.sh$)' \
  | grep -v -E '\.(png|jpg|ico|woff2?)$' || true)

[ -z "$files" ] && exit 0
found=0
for f in $files; do
  [ -f "$f" ] || continue
  if grep -n -E "$patterns" "$f" >/dev/null 2>&1; then
    echo "possible secret in $f:" >&2
    grep -n -E "$patterns" "$f" | sed 's/\(.\{12\}\).*/\1…/' >&2
    found=1
  fi
done
if [ "$found" -ne 0 ]; then
  echo "secret scan failed: remove the value or move it to a test fixture" >&2
  exit 1
fi
echo "secret scan: ok"
