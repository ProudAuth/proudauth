#!/usr/bin/env sh
# Verifies every module dependency uses an allowed license (GOV-007, QA-002).
# Uses the module cache so it works offline once dependencies are downloaded.
set -eu
cd "$(dirname "$0")/.."

allowed='Apache-2.0|MIT|BSD-2-Clause|BSD-3-Clause|ISC|MPL-2.0'
modcache=$(go env GOMODCACHE)
status=0

# Every module that provides a package to the binaries or their tests: these
# are what ships or runs in CI. `go list -deps` needs them in the module cache,
# so a module missing from the cache is a failure, never a silent skip.
go list -deps -test -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' ./... | sort -u | while read -r mod; do
  [ -z "$mod" ] && continue
  path=${mod%@*}
  # Module cache paths escape upper-case letters as !lower.
  esc=$(printf '%s' "$mod" | sed 's/\([A-Z]\)/!\1/g' | tr 'A-Z' 'a-z')
  dir="$modcache/$esc"
  if [ ! -d "$dir" ]; then
    echo "module not in the module cache (run go mod download): $path" >&2
    echo fail >> "${TMPDIR:-/tmp}/proudauth-license-check.$$"
    continue
  fi
  lic=$(ls "$dir" 2>/dev/null | grep -i -E '^(licen[cs]e|copying)' | head -n1 || true)
  if [ -z "$lic" ]; then
    echo "no license file: $path" >&2
    echo fail >> "${TMPDIR:-/tmp}/proudauth-license-check.$$"
    continue
  fi
  text=$(head -c 4000 "$dir/$lic")
  kind=unknown
  case "$text" in
    *"Apache License"*) kind=Apache-2.0 ;;
    *"Permission is hereby granted, free of charge"*) kind=MIT ;;
    *"Redistribution and use in source and binary forms"*)
      if printf '%s' "$text" | grep -q -i 'neither the name'; then kind=BSD-3-Clause; else kind=BSD-2-Clause; fi ;;
    *"Permission to use, copy, modify, and/or distribute"*) kind=ISC ;;
    *"Mozilla Public License"*) kind=MPL-2.0 ;;
  esac
  if ! printf '%s' "$kind" | grep -q -E "^($allowed)$"; then
    echo "disallowed or unrecognized license ($kind): $path" >&2
    echo fail >> "${TMPDIR:-/tmp}/proudauth-license-check.$$"
  fi
done

if [ -f "${TMPDIR:-/tmp}/proudauth-license-check.$$" ]; then
  rm -f "${TMPDIR:-/tmp}/proudauth-license-check.$$"
  exit 1
fi
echo "license check: ok"
