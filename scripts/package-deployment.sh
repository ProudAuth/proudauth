#!/bin/sh
# DEP-002, DEP-003, DEP-006: deterministic, source-free Compose release bundle.
# It is deploy/prod: docker-compose.yaml and .env, with the image pinned to the
# packaged version and every deployment value emptied, plus LICENSE and NOTICE.
set -eu
cd "$(dirname "$0")/.."
[ "$#" -le 1 ] || { printf '%s\n' 'usage: package-deployment.sh [vVERSION]' >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required.' >&2; exit 1; }
exec python3 - "${1:-v0.2.0-alpha.3}" "${DEPLOYMENT_OUT:-dist}" <<'PY'
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

def read(relative):
    source = root / relative
    if source.is_symlink() or not source.is_file():
        raise SystemExit('Missing or unsafe bundle source: ' + relative)
    return source.read_bytes()

# A production .env filled in this checkout never leaves it: only the image
# and non-deployment defaults keep their values.
deployment = re.compile(rb'^(PROUDAUTH_(?:PUBLIC_ORIGIN|TRUSTED_PROXIES|DATABASE_URL|ROOT_KEY|SMTP_HOST|SMTP_USERNAME|SMTP_PASSWORD|EMAIL_FROM))=.*$', re.M)
env = deployment.sub(rb'\1=', read('deploy/prod/.env'))
env, pinned = re.subn(rb'^PROUDAUTH_IMAGE=.*$', b'PROUDAUTH_IMAGE=ghcr.io/proudauth/proudauth:' + version[1:].encode(), env, flags=re.M)
if pinned != 1:
    raise SystemExit('deploy/prod/.env must set PROUDAUTH_IMAGE exactly once')
files = {'docker-compose.yaml': read('deploy/prod/docker-compose.yaml'), '.env': env,
         'LICENSE': read('LICENSE'), 'NOTICE': read('NOTICE')}
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
            # .env receives the operator's secrets once filled in.
            info.mode = 0o600 if filename == '.env' else 0o644
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
