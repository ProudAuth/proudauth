#!/bin/sh
# Runs once inside the official PostgreSQL image, on an empty data volume.
set -eu
pa_owner_password=$(cat /run/secrets/owner_password)
pa_app_password=$(cat /run/secrets/app_password)
psql -X -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=owner_password="$pa_owner_password" --set=app_password="$pa_app_password" <<'SQL'
CREATE ROLE proudauth_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'owner_password';
CREATE ROLE proudauth_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';
ALTER DATABASE proudauth OWNER TO proudauth_owner;
ALTER SCHEMA public OWNER TO proudauth_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
