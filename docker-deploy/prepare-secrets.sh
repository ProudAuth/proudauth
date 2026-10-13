#!/bin/sh
# Consume only plain, generated credential fields; never execute .env as shell code.
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { printf '%s\n' 'Missing .env; run ./init-env.sh first.' >&2; exit 1; }
read_value() {
  value=$(sed -n "s/^$1=//p" .env)
  [ -n "$value" ] || { printf 'Missing %s in .env\n' "$1" >&2; exit 1; }
  printf '%s' "$value"
}
deploy_root_key=$(read_value ROOT_KEY_VALUE)
deploy_db_password=$(read_value POSTGRES_PASSWORD)
deploy_db_user=$(read_value POSTGRES_USER)
deploy_db_name=$(read_value POSTGRES_DB)
case "$deploy_root_key" in *[!0-9a-fA-F]*) printf '%s\n' 'ROOT_KEY_VALUE must be 64 hexadecimal characters.' >&2; exit 1 ;; esac
[ "${#deploy_root_key}" -eq 64 ] || { printf '%s\n' 'ROOT_KEY_VALUE must be 64 hexadecimal characters.' >&2; exit 1; }
case "$deploy_db_password" in *[!0-9a-fA-F]*) printf '%s\n' 'Use a nonempty hexadecimal POSTGRES_PASSWORD.' >&2; exit 1 ;; esac
case "$deploy_db_user$deploy_db_name" in *[!a-zA-Z0-9_-]*) printf '%s\n' 'Use simple letters, digits, underscores or dashes for database user/name.' >&2; exit 1 ;; esac
umask 077
mkdir -p secrets
chmod 700 secrets
write_secret() {
  # Keep unchanged files in place: running bind mounts keep their existing inode.
  if [ -f "secrets/$1" ] && [ "$(cat "secrets/$1")" = "$2" ]; then
    chmod 444 "secrets/$1"
    return
  fi
  secret_temp=$(mktemp "secrets/.$1.XXXXXX")
  printf '%s' "$2" > "$secret_temp"
  # Host directory 0700 protects these files; 0444 lets container UID 65532 read them.
  chmod 444 "$secret_temp"
  mv -f "$secret_temp" "secrets/$1"
}
write_secret root_key "$deploy_root_key"
write_secret db_password "$deploy_db_password"
write_secret database_url "postgres://$deploy_db_user:$deploy_db_password@postgres:5432/$deploy_db_name?sslmode=disable"
printf '%s\n' 'Private secret files prepared.'
