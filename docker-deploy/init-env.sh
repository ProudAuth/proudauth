#!/bin/sh
# Initialize private local credentials (DEP-002, DEP-004); preserve an existing installation.
set -eu
cd "$(dirname "$0")"
umask 077
if [ -f .env ]; then
  chmod 600 .env
  printf '%s\n' 'Existing .env preserved.'
  exit 0
fi
env_temp=$(mktemp .env.XXXXXX)
trap 'rm -f "$env_temp"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
deploy_root_key=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
deploy_db_password=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
sed -e "s/^ROOT_KEY_VALUE=.*/ROOT_KEY_VALUE=$deploy_root_key/" \
    -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$deploy_db_password/" \
    .env.example > "$env_temp"
chmod 600 "$env_temp"
# A concurrent initializer cannot overwrite credentials created in the meantime.
ln "$env_temp" .env
printf '%s\n' 'Private .env created; keep it with this database and never commit it.'
