#!/bin/sh
# Smoke test for a running development stack (DEP-002): health, the default
# realm through the operator channel, readiness, discovery, JWKS, and
# refusal of insecure grants. Every check fails the script on error.
set -eu
BASE=${PROUDAUTH_URL:-http://localhost:8080}
COMPOSE="docker compose -f $(dirname "$0")/../deploy/dev/docker-compose.yaml"

fail() { echo "FAIL: $*" >&2; exit 1; }

curl -fsS "$BASE/health/live" >/dev/null || fail "liveness"
echo "live: ok"

# The stack's one-shot realm service creates it; repeating is a no-op.
$COMPOSE exec -T server /usr/local/bin/identity-cli realm-create -if-missing -name main || fail "realm creation"

ready=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -fsS "$BASE/health/ready" >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[ -n "$ready" ] || fail "readiness"
echo "ready: ok"

curl -fsS "$BASE/realms/main/.well-known/openid-configuration" | grep -q '"issuer"' || fail "discovery"
echo "discovery: ok"
curl -fsS "$BASE/realms/main/jwks" | grep -q '"keys"' || fail "jwks"
echo "jwks: ok"

code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/realms/main/oauth/token" -d grant_type=password -d username=a -d password=b)
case "$code" in
  400|401) echo "password grant refused: ok" ;;
  *) fail "password grant answered $code" ;;
esac
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/realms/main/oauth/authorize?response_type=token&client_id=x&redirect_uri=https://evil.test/")
case "$code" in
  400|401|404) echo "implicit flow refused: ok" ;;
  302) curl -s -o /dev/null -w '%{redirect_url}' "$BASE/realms/main/oauth/authorize?response_type=token&client_id=x&redirect_uri=https://evil.test/" | grep -q evil.test && fail "open redirect" ; echo "implicit flow refused: ok" ;;
  *) fail "implicit flow answered $code" ;;
esac
echo "smoke test passed"
