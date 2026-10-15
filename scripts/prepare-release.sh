#!/bin/sh
# Prepare a release in one step (GOV-005): every published reference to the
# current version moves to the new one, and the CHANGELOG's Unreleased notes
# become the new version's section.
#
#   scripts/prepare-release.sh v0.3.0
#
# Commit the result in a pull request. After it merges, tag main:
#   git tag -a v0.3.0 -m "ProudAuth v0.3.0" && git push origin v0.3.0
# The release workflow refuses a tag that these files do not match, and once it
# has published, both websites pick the release up on their own.
set -eu
cd "$(dirname "$0")/.."
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: scripts/prepare-release.sh vMAJOR.MINOR.PATCH[-prerelease]' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required.' >&2; exit 1; }
exec python3 - "$1" "${RELEASE_DATE:-$(date -u +%Y-%m-%d)}" <<'PY'
import re
import sys
from pathlib import Path

new, date = sys.argv[1:]
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', new):
    raise SystemExit('Version must be vMAJOR.MINOR.PATCH, optionally with a prerelease suffix')
if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', date):
    raise SystemExit('RELEASE_DATE must be YYYY-MM-DD')
image = re.search(r'^PROUDAUTH_IMAGE=ghcr\.io/proudauth/proudauth:(\S+)$', Path('deploy/prod/.env').read_text(), re.M)
if not image:
    raise SystemExit('deploy/prod/.env does not pin ghcr.io/proudauth/proudauth')
old = image.group(1)
if old == new[1:]:
    raise SystemExit(f'{new} is already the current version')

# "0.2.0" must not match inside "0.2.0-alpha.1"; a leading "v" is kept.
pattern = re.compile(r'(?<![\w.])(v?)' + re.escape(old) + r'(?![\w]|\.[0-9]|-(?:alpha|beta|rc|pre|dev))')
# Everything is checked before any file is written.
updates, counts = {}, {}
for name in ('deploy/prod/.env', 'deploy/dev/.env', 'README.md', 'deploy/README.md',
             'docs/operations/docker-compose.md', 'docs/operations/environment.md',
             'docs/operations/installation.md', 'scripts/package-deployment.sh'):
    text, count = pattern.subn(lambda m: m.group(1) + new[1:], Path(name).read_text())
    if count:
        updates[name], counts[name] = text, count
for required in ('deploy/prod/.env', 'docs/operations/docker-compose.md', 'README.md'):
    if required not in updates:
        raise SystemExit(f'{required} does not mention {old}; nothing was changed')

text = Path('CHANGELOG.md').read_text()
section = re.search(r'^## \[Unreleased\]\n(.*?)(?=^## )', text, re.M | re.S)
notes = section.group(1).strip() if section else ''
if not notes or notes.startswith('No changes recorded'):
    raise SystemExit('Write the release notes under "## [Unreleased]" in CHANGELOG.md first; nothing was changed')
updates['CHANGELOG.md'] = text[:section.start()] + (f'## [Unreleased]\n\nNo changes recorded after {new[1:]}.\n\n'
                                                    f'## [{new[1:]}] - {date}\n\n{notes}\n\n') + text[section.end():]
for name, text in updates.items():
    Path(name).write_text(text)
changed = counts

print(f'{old} -> {new[1:]}')
for name, count in changed.items():
    print(f'  {name}: {count}')
print(f'  CHANGELOG.md: [{new[1:]}] - {date}')
print(f'Next: commit in a pull request, merge, then: git tag -a {new} -m "ProudAuth {new}" && git push origin {new}')
PY
