#!/bin/sh
# DEP-002, DEP-003, DEP-006: deterministic, source-free Compose release bundle.
# An explicit allowlist excludes every generated .env, secret, config and state file.
set -eu
cd "$(dirname "$0")/.."
[ "$#" -le 1 ] || { printf '%s\n' 'usage: package-deployment.sh [vVERSION]' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required.' >&2; exit 1; }
exec python3 - "${1:-v0.2.0-alpha.1}" "${DEPLOYMENT_OUT:-dist}" <<'PY'
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile

version, output = sys.argv[1:]
if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', version):
    raise SystemExit('Version must be vMAJOR.MINOR.PATCH, optionally with a prerelease suffix')
root = Path.cwd()
destination = Path(output)
destination.mkdir(parents=True, exist_ok=True)
name = 'proudauth-' + version + '-compose'
archive = destination / (name + '.tar.gz')
checksum = destination / (name + '.tar.gz.sha256')
for path in (archive, checksum):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise SystemExit('Bundle output must be a regular file')
files = {}
for filename in ('docker-compose.yaml', '.env.example', '.env.demo.example', '.gitignore',
                 'init.sh', 'init-database.sh', 'configure.py', 'README.md'):
    source = root / 'deploy/release' / filename
    if source.is_symlink() or not source.is_file():
        raise SystemExit('Missing or unsafe allowlisted deployment source: ' + filename)
    files[filename] = source.read_bytes()
for filename in ('LICENSE', 'NOTICE'):
    source = root / filename
    if source.is_symlink() or not source.is_file():
        raise SystemExit('Missing or unsafe license source: ' + filename)
    files[filename] = source.read_bytes()
environment = (root / 'docs/operations/environment.md').read_text()
for doc in ('configuration', 'keys', 'backup-restore', 'upgrades'):
    environment = environment.replace('](' + doc + '.md)',
        '](https://github.com/proudbase/proudauth/blob/main/docs/operations/' + doc + '.md)')
environment = environment.replace('](docker-compose.md)', '](README.md)')
files['ENVIRONMENT.md'] = environment.encode()
# The examples and README must describe the version being packaged.
for filename, data in list(files.items()):
    if filename.endswith(('.md', '.example')):
        files[filename] = data.replace(b'v0.2.0-alpha.1', version.encode()).replace(
            b':0.2.0-alpha.1', (':' + version[1:]).encode())
files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + filename + '\n'
                             for filename, data in sorted(files.items())).encode()
buffer = io.BytesIO()
with gzip.GzipFile(filename='', mode='wb', fileobj=buffer, mtime=0) as compressed:
    with tarfile.open(mode='w', fileobj=compressed, format=tarfile.PAX_FORMAT) as tar:
        directory = tarfile.TarInfo(name)
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        tar.addfile(directory)
        for filename, data in sorted(files.items()):
            info = tarfile.TarInfo(name + '/' + filename)
            info.size = len(data)
            info.mode = 0o755 if filename.endswith('.sh') else 0o644
            info.uid = info.gid = info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
contents = buffer.getvalue()
digest = hashlib.sha256(contents).hexdigest()
for path, data in ((archive, contents), (checksum, (digest + '  ' + archive.name + '\n').encode())):
    handle, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=destination)
    try:
        with os.fdopen(handle, 'wb') as target:
            target.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
print('Compose installer: ' + str(archive))
print('SHA-256: ' + digest)
PY
