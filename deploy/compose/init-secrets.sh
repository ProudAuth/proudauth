#!/bin/sh
# Creates local, git-ignored secret files for the development stack.
set -eu
cd "$(dirname "$0")"
mkdir -p secrets
chmod 700 secrets
umask 077
[ -f secrets/root_key ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/root_key
[ -f secrets/db_password ] || head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/db_password
printf 'postgres://proudauth:%s@postgres:5432/proudauth?sslmode=disable' "$(cat secrets/db_password)" > secrets/database_url.new
mv secrets/database_url.new secrets/database_url
# File-backed Compose secrets retain host ownership on native Linux. The
# non-root image UID must be able to read its individual read-only mounts.
# The 0700 parent directory keeps these files private on the host.
chmod 444 secrets/root_key secrets/db_password secrets/database_url
echo "secrets written to $(pwd)/secrets (never commit them)"
