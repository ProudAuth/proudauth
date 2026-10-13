#!/bin/sh
# Start the image-based stack and provision the default realm exactly once.
set -eu
cd "$(dirname "$0")"
./prepare-secrets.sh
docker compose up -d --wait --wait-timeout 180
report=$(docker compose exec -T server /usr/local/bin/identity-cli doctor)
case "$report" in
  *"realm main: issuer "*) printf '%s\n' 'Realm main already initialized.' ;;
  *) docker compose exec -T server /usr/local/bin/identity-cli realm-create -name main -display-name Main ;;
esac
docker compose exec -T server /usr/local/bin/identity-cli doctor
printf '%s\n' 'ProudAuth is ready. See .env for the public origin and README.md for administrator setup.'
