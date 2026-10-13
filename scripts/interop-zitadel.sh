#!/bin/sh
# Third-party interoperability: ZITADEL as a SCIM 2.0 service provider for
# ProudAuth's outbound provisioning (QA-004, PROV-010, PROV-017;
# docs/integrations/outbound-provisioning.md, "Tested downstream services",
# and docs/integrations/interoperability.md, "Third-party products").
#
# What it does, with throwaway containers and the ProudAuth binaries built
# from this checkout and run on the host:
#
#   1. PostgreSQL 18 and ZITADEL (start-from-init, first instance with an
#      IAM_OWNER service account whose personal access token ZITADEL writes
#      to a file). With that token it creates a second organization and, in
#      each of the two organizations, a service account holding only
#      ORG_USER_MANAGER with its own personal access token: the credentials
#      the connectors use. SCIM discovery (/scim/v2/{orgId}/
#      ServiceProviderConfig, ResourceTypes, Schemas) is read with them.
#   2. ProudAuth: migrate, realm-create, bootstrap, the administrator's first
#      sign-in (password, email verification, TOTP enrollment), organizations
#      acme and globex, and accounts with given and family names whose email
#      addresses are verified through the emailed setup link.
#   3. Two outbound SCIM connectors: an organization connector of acme
#      (deprovision_action deactivate) and a realm connector limited to
#      globex (deprovision_action delete), each pointing at its ZITADEL
#      organization's /scim/v2/{orgId} with its token as the credential. The
#      worker runs (identity-worker -once) until the deliveries settle, and
#      every expectation is read back from ZITADEL (SCIM and the v2 user API):
#      initial reconciliation, create on membership, a create ZITADEL refuses
#      (no verified email address yet) delivered once the address is
#      verified, profile and email changes, account and membership suspension
#      and reactivation, deactivation on membership removal and account
#      deletion, DELETE for the delete connector, and a token revoked in
#      ZITADEL (401, dead letter) followed by credential rotation and replay.
#   4. Reconciliation (PROV-017): drift made in ZITADEL, a managed user
#      deleted in ZITADEL and an unmanaged user created there; a dry run
#      reports them, the applied run repairs drift and the lost user and
#      leaves the unmanaged one alone.
#
# ZITADEL v4's SCIM endpoint serves Users only (no /Groups resource type), so
# group pushes are not exercised; see the documents above for what is not
# covered.
#
# Requirements: docker, go, curl, jq, python3 (TOTP and PKCE), and the images
# below already present or pullable. Environment overrides:
# INTEROP_ZITADEL_IMAGE (default ghcr.io/zitadel/zitadel:v4.16.3),
# INTEROP_PG_IMAGE (default postgres:18), INTEROP_PREFIX (container, volume
# and network prefix, default pa-interop-zt), INTEROP_ZITADEL_PORT (default
# 18571), INTEROP_PG_PORT (default 55571), INTEROP_HTTP_PORT /
# INTEROP_INTERNAL_PORT (default 18572 / 18573), INTEROP_BIN (prebuilt
# binaries; default: go build into a temp dir), INTEROP_KEEP=1 (keep the work
# directory, containers, volume and network for inspection).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ZT_IMAGE=${INTEROP_ZITADEL_IMAGE:-ghcr.io/zitadel/zitadel:v4.16.3}
PG_IMAGE=${INTEROP_PG_IMAGE:-postgres:18}
PREFIX=${INTEROP_PREFIX:-pa-interop-zt}
ZT_PORT=${INTEROP_ZITADEL_PORT:-18571}
PG_PORT=${INTEROP_PG_PORT:-55571}
HTTP_PORT=${INTEROP_HTTP_PORT:-18572}
INTERNAL_PORT=${INTEROP_INTERNAL_PORT:-18573}
KEEP=${INTEROP_KEEP:-0}
REALM=main

NET=$PREFIX-net
PG=$PREFIX-pg
ZT=$PREFIX-zitadel
VOL=$PREFIX-pat

# ZITADEL resolves its instance from the Host header: the external domain
# and port it was initialized with. ProudAuth reaches it as localhost.
ZURL=http://localhost:$ZT_PORT
ORIGIN=http://127.0.0.1:$HTTP_PORT
ISSUER=$ORIGIN/realms/$REALM
API=$ORIGIN/api/v1/realms/$REALM
INTERNAL=http://127.0.0.1:$INTERNAL_PORT

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pa-interop-zt.XXXXXX")
SERVER_PID=
ADMIN_TOKEN=

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
ok() { printf '[%s]   ok: %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() {
	printf '\nINTEROP FAILED: %s\n' "$*" >&2
	exit 1
}

docker_cleanup() {
	# -v: the PostgreSQL image's anonymous data volume goes with its container.
	docker rm -f -v "$ZT" "$PG" >/dev/null 2>&1 || true
	docker volume rm "$VOL" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ "$status" -ne 0 ]; then
		for c in ${CONN_A:-} ${CONN_B:-}; do
			if curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" "$API$c/deliveries" -o "$WORK/diag.json" 2>/dev/null; then
				printf '\n--- deliveries of %s ---\n' "$c" >&2
				jq -c '.items[] | {local_id, operation, state, attempts, last_status_code, last_error_category}' "$WORK/diag.json" >&2 || true
			fi
		done
	fi
	if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	if [ "$status" -ne 0 ]; then
		for f in "$WORK"/*.log; do
			[ -f "$f" ] || continue
			printf '\n--- last lines of %s ---\n' "$(basename "$f")" >&2
			tail -n 8 "$f" | cut -c1-400 >&2 || true
		done
		docker logs --tail 8 "$ZT" 2>&1 | cut -c1-400 | sed 's/^/zitadel: /' >&2 || true
	fi
	if [ "$KEEP" = 1 ]; then
		log "INTEROP_KEEP=1: kept $WORK, containers $PG and $ZT, volume $VOL and network $NET"
	else
		docker_cleanup
		rm -rf "$WORK"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for tool in docker go curl jq python3; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
docker info >/dev/null 2>&1 || fail "docker is not reachable"
port_open() { # curl exit status 7: nothing listens on 127.0.0.1:PORT
	_rc=0
	curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$1/" 2>/dev/null || _rc=$?
	[ "$_rc" -ne 7 ]
}
# Leftovers of an earlier run with INTEROP_KEEP=1 (same prefix) go first.
docker_cleanup
for port in "$ZT_PORT" "$PG_PORT" "$HTTP_PORT" "$INTERNAL_PORT"; do
	if port_open "$port"; then
		fail "port $port is in use (set INTEROP_ZITADEL_PORT, INTEROP_PG_PORT, INTEROP_HTTP_PORT or INTEROP_INTERNAL_PORT)"
	fi
done

# ---------------------------------------------------------------- helpers ---

# eventually DESCRIPTION COMMAND...: retries COMMAND (a shell function) for up
# to 30 rounds, running the ProudAuth worker once before each retry.
eventually() {
	_what=$1
	shift
	_i=0
	until "$@"; do
		_i=$((_i + 1))
		[ "$_i" -lt 30 ] || fail "$_what"
		pump
		sleep 0.5
	done
}

# pump: one pass of every worker task (outbox dispatch, notification
# delivery, the directory scheduler with its change scan, runs, outbound
# deliveries).
pump() {
	"$BIN/identity-worker" -once -config "$WORK/config.yaml" >>"$WORK/worker.log" 2>&1 || fail "identity-worker -once failed"
}

totp_at() { # base32-secret step -> 6-digit RFC 6238 code (SHA-1, 30 s)
	python3 -c 'import sys,base64,hmac,hashlib,struct
s=sys.argv[1].upper().rstrip("=");s+="="*(-len(s)%8)
h=hmac.new(base64.b32decode(s),struct.pack(">Q",int(sys.argv[2])),hashlib.sha1).digest();o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))' "$1" "$2"
}

totp_fresh() { # secret: a code for a time step not used before (replay protection)
	_last=$(cat "$WORK/totp.step" 2>/dev/null || echo 0)
	while :; do
		_step=$(($(date +%s) / 30))
		[ "$_step" -gt "$_last" ] && break
		sleep 1
	done
	echo "$_step" >"$WORK/totp.step"
	totp_at "$1" "$_step"
}

pkce() { # -> "verifier challenge"
	python3 -c 'import secrets,hashlib,base64
v=secrets.token_urlsafe(48);print(v,base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode())'
}

# api METHOD PATH [BEARER] [JSON]: ProudAuth realm API; body to
# $WORK/resp.json, prints the status.
api() {
	_m=$1 _p=$2 _t=${3:-} _b=${4:-}
	set -- -sS -o "$WORK/resp.json" -w '%{http_code}' -X "$_m" "$API$_p"
	if [ -n "$_t" ]; then set -- "$@" -H "Authorization: Bearer $_t"; fi
	if [ -n "$_b" ]; then set -- "$@" -H 'Content-Type: application/json' --data "$_b"; fi
	curl "$@"
}

admin() { # METHOD PATH [JSON] EXPECTED-STATUS: administrator call, fails otherwise
	_code=$(api "$1" "$2" "$ADMIN_TOKEN" "${3:-}")
	[ "$_code" = "$4" ] || fail "$1 $2: expected $4, got $_code $(cat "$WORK/resp.json")"
}

# zt METHOD URL-PATH TOKEN [JSON] [ORG]: ZITADEL call (management or SCIM);
# body to $WORK/zt.json, prints the status. SCIM paths get the SCIM media
# type; the Accept header names exactly one media type (ZITADEL refuses a
# list).
zt() {
	_m=$1 _p=$2 _t=$3 _b=${4:-} _o=${5:-}
	_ct=application/json
	case $_p in /scim/*) _ct=application/scim+json ;; esac
	set -- -sS -o "$WORK/zt.json" -w '%{http_code}' -X "$_m" "$ZURL$_p" -H "Authorization: Bearer $_t" -H "Accept: $_ct"
	if [ -n "$_b" ]; then set -- "$@" -H "Content-Type: $_ct" --data "$_b"; fi
	if [ -n "$_o" ]; then set -- "$@" -H "x-zitadel-orgid: $_o"; fi
	curl "$@"
}

ztok() { # EXPECTED METHOD PATH TOKEN [JSON] [ORG]: ZITADEL call that must answer EXPECTED
	_want=$1
	shift
	_code=$(zt "$@")
	[ "$_code" = "$_want" ] || fail "ZITADEL $1 $2: expected $_want, got $_code $(cat "$WORK/zt.json")"
}

# scim_user ORG LOCAL-ID: the ZITADEL SCIM user whose externalId is the
# ProudAuth account ID, to $WORK/scim.json (empty object when there is none).
scim_user() {
	_f=$(jq -rn --arg id "$2" '"externalId eq \"\($id)\"" | @uri')
	_code=$(zt GET "/scim/v2/$1/Users?filter=$_f" "$OWNER_PAT")
	[ "$_code" = 200 ] || fail "ZITADEL SCIM filter: $_code $(cat "$WORK/zt.json")"
	jq '.Resources[0] // {}' "$WORK/zt.json" >"$WORK/scim.json"
	_count=$(jq '.totalResults' "$WORK/zt.json")
	[ "$_count" -le 1 ] || fail "ZITADEL holds $_count users with externalId $2"
}

# has ORG LOCAL-ID JQ-CONDITION: the account's ZITADEL user satisfies the
# condition (evaluated on the SCIM resource).
has() {
	scim_user "$1" "$2"
	jq -e "$3" "$WORK/scim.json" >/dev/null
}
absent() { # ORG LOCAL-ID: no ZITADEL user carries this externalId
	scim_user "$1" "$2"
	[ "$(jq 'length' "$WORK/scim.json")" = 0 ]
}

# zt_state ZITADEL-USER-ID: the user's state through the v2 user API (not
# SCIM), e.g. USER_STATE_ACTIVE, USER_STATE_INACTIVE; empty when not found.
zt_state() {
	_code=$(zt GET "/v2/users/$1" "$OWNER_PAT")
	if [ "$_code" = 200 ]; then jq -r '.user.state' "$WORK/zt.json"; fi
}

tx_step() { # NAME JSON: one interaction step; the new state goes to $WORK/state.json
	_code=$(curl -sS -o "$WORK/step.json" -w '%{http_code}' -X POST "$API/auth/transactions/$TX_ID/$1" \
		-H 'Content-Type: application/json' -H "X-Transaction-Token: $TX_CONT" --data "$2")
	case $_code in
	2*) cp "$WORK/step.json" "$WORK/state.json" ;;
	*)
		LOGIN_ERROR="$1: HTTP $_code $(jq -c '{code, detail}' "$WORK/step.json" 2>/dev/null || cat "$WORK/step.json")"
		return 1
		;;
	esac
}

# mail TEMPLATE RECIPIENT PATTERN: the newest development-sink message of a
# template for a recipient, matched against an extended regular expression.
mail() {
	_i=0
	while [ "$_i" -lt 30 ]; do
		_hit=$(curl -fsS "$INTERNAL/dev/mailbox?realm=$REALM&recipient=$2" 2>/dev/null |
			jq -r --arg t "$1" '[.items[]? | select(.template == $t)][0].body // empty' |
			grep -Eo "$3" | head -n 1 || true)
		if [ -n "$_hit" ] && ! grep -qx "$_hit" "$WORK/mail.used" 2>/dev/null; then
			echo "$_hit" >>"$WORK/mail.used"
			echo "$_hit"
			return 0
		fi
		_i=$((_i + 1))
		pump
	done
	return 1
}

# admin_login: the bootstrap administrator's headless authorization-code +
# PKCE sign-in (password, email verification, TOTP enrollment on the first
# sign-in) through the interaction API, then the token exchange.
admin_login() {
	set -- $(pkce)
	_verifier=$1 _challenge=$2
	_code=$(api POST /auth/transactions "" "$(jq -nc --arg ch "$_challenge" --arg res "$ISSUER/admin" \
		'{client_id:"proudauth-cli", redirect_uri:"http://127.0.0.1/callback", scope:"proudauth:admin", resource:[$res], code_challenge:$ch, code_challenge_method:"S256", state:"interop"}')")
	[ "$_code" = 201 ] || fail "administrator sign-in start: $_code $(cat "$WORK/resp.json")"
	TX_ID=$(jq -r .transaction_id "$WORK/resp.json")
	TX_CONT=$(jq -r .continuation_token "$WORK/resp.json")
	jq .state "$WORK/resp.json" >"$WORK/state.json"
	_n=0
	while [ -z "$(jq -r '.redirect_to // empty' "$WORK/state.json")" ]; do
		_n=$((_n + 1))
		[ "$_n" -lt 20 ] || fail "administrator sign-in: too many steps"
		[ "$(jq -r .status "$WORK/state.json")" = pending ] || fail "administrator sign-in ended: $(jq -c '{status, error}' "$WORK/state.json")"
		_types=" $(jq -r '[.next_actions[]?.type] | join(" ")' "$WORK/state.json") "
		LOGIN_ERROR=
		case $_types in
		*" identify "*) tx_step identify '{"identifier":"interop-admin"}' ;;
		*" password "*) tx_step password "$(jq -nc --arg p "$ADMIN_PW" '{password:$p}')" ;;
		*" verify_email "*)
			tx_step otp/send '{"purpose":"verify_email"}' &&
				_otp=$(mail email_verification admin@interop.test '(^|[^0-9])[0-9]{6}([^0-9]|$)' | grep -Eo '[0-9]{6}') &&
				tx_step otp/verify "$(jq -nc --arg c "$_otp" '{code:$c}')"
			;;
		*" enroll_totp "*)
			tx_step totp/enroll '{}' &&
				jq -r '.one_time.totp.secret' "$WORK/state.json" >"$WORK/totp.secret" &&
				tx_step totp/activate "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')"
			;;
		*" totp "*) tx_step totp "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')" ;;
		*" accept_terms "*) tx_step terms "$(jq -c '{version: .next_actions[0].options.version}' "$WORK/state.json")" ;;
		*" consent "*) tx_step consent '{"approve":true}' ;;
		*) fail "administrator sign-in: unhandled step(s):$_types" ;;
		esac || fail "administrator sign-in: $LOGIN_ERROR"
	done
	_authz=$(jq -r .redirect_to "$WORK/state.json" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
	_code=$(curl -sS -o "$WORK/resp.json" -w '%{http_code}' "$ISSUER/oauth/token" -d grant_type=authorization_code \
		--data-urlencode "code=$_authz" -d client_id=proudauth-cli --data-urlencode "code_verifier=$_verifier" \
		--data-urlencode "redirect_uri=http://127.0.0.1/callback" --data-urlencode "resource=$ISSUER/admin")
	[ "$_code" = 200 ] || fail "administrator token exchange: $_code $(cat "$WORK/resp.json")"
	ADMIN_TOKEN=$(jq -r .access_token "$WORK/resp.json")
}

# new_account NAME GIVEN FAMILY: an administrator-created account whose
# setup link goes to the development mail sink; its email address is not
# verified yet. Prints the account ID.
new_account() {
	admin POST /users "$(jq -nc --arg n "$1" --arg g "$2" --arg f "$3" \
		'{email:($n + "@interop.test"), username:$n, display_name:($g + " " + $f), given_name:$g, family_name:$f}')" 201
	jq -r .user.id "$WORK/resp.json"
}

# complete_setup NAME ID: completes the emailed setup link with a password,
# which verifies the email address (the address the SCIM document carries:
# unverified addresses are never pushed).
complete_setup() {
	_setup=$(mail account_setup "$1@interop.test" 'pa_lnk_[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+') || fail "no setup email for $1"
	_code=$(api POST /account-setup "" "$(jq -nc --arg t "$_setup" --arg p "$1 interop passphrase 2026 zitadel" '{setup_token:$t, password:$p}')")
	[ "$_code" = 200 ] || fail "account setup for $1: $_code $(cat "$WORK/resp.json")"
	admin GET "/users/$2" "" 200
	jq -e '[.identifiers[] | select(.type == "email" and .verified and .is_primary)] | length == 1' "$WORK/resp.json" >/dev/null ||
		fail "$1's email address is not verified after setup: $(cat "$WORK/resp.json")"
}

create_account() { # NAME GIVEN FAMILY: new_account, then complete_setup; prints the account ID
	_uid=$(new_account "$@")
	complete_setup "$1" "$_uid"
	echo "$_uid"
}

add_member() { # ORG USER -> membership ID
	admin POST "/organizations/$1/members" "$(jq -nc --arg u "$2" '{user_id:$u}')" 201
	jq -r .id "$WORK/resp.json"
}

# settled CONNECTOR-PATH: no delivery of the connector is pending or retrying
# and none is dead-lettered, except the deliveries in $EXPECTED_DEAD
# (delivery IDs the scenario dead-letters on purpose).
EXPECTED_DEAD=
settled() {
	admin GET "$1/deliveries" "" 200
	[ "$(jq '[.items[] | select(.state == "pending" or .state == "retrying")] | length' "$WORK/resp.json")" = 0 ] || return 1
	_dead=$(jq -c --arg ok " $EXPECTED_DEAD " '[.items[] | select(.state == "dead_letter") | select(.id as $i | $ok | contains(" " + $i + " ") | not)
		| {local_id, operation, last_status_code, last_error_category}]' "$WORK/resp.json")
	[ "$_dead" = "[]" ] || fail "dead-lettered deliveries on $1: $_dead"
}

# dead_letter CONNECTOR-PATH LOCAL-ID STATUS CATEGORY: the account's newest
# delivery is dead-lettered with this status code and error category; its ID
# is added to $EXPECTED_DEAD.
dead_letter() {
	admin GET "$1/deliveries" "" 200
	_d=$(jq -r --arg id "$2" --argjson st "$3" --arg cat "$4" '[.items[] | select(.local_id == $id)][0]
		| select(.state == "dead_letter" and .last_status_code == $st and .last_error_category == $cat) | .id' "$WORK/resp.json")
	[ -n "$_d" ] || return 1
	case " $EXPECTED_DEAD " in *" $_d "*) ;; *) EXPECTED_DEAD="$EXPECTED_DEAD $_d" ;; esac
	DEAD_ID=$_d
}

# run CONNECTOR-PATH JSON: request a run, pump the worker until it finishes;
# the run goes to $WORK/run.json.
run() {
	admin POST "$1/runs" "$2" 202
	_run=$(jq -r .id "$WORK/resp.json")
	_i=0
	while :; do
		pump
		admin GET "$1/runs/$_run" "" 200
		case $(jq -r .state "$WORK/resp.json") in
		succeeded | failed | partial | cancelled) break ;;
		esac
		_i=$((_i + 1))
		[ "$_i" -lt 30 ] || fail "run $_run did not finish: $(cat "$WORK/resp.json")"
	done
	cp "$WORK/resp.json" "$WORK/run.json"
	admin GET "$1/runs/$_run/findings" "" 200
	cp "$WORK/resp.json" "$WORK/findings.json"
	[ "$(jq -r .state "$WORK/run.json")" = succeeded ] || fail "run $_run: $(cat "$WORK/run.json") $(cat "$WORK/findings.json")"
}

finding() { # KIND [EXTERNAL-ID-OR-LOCAL-ID]: the last run reported such a finding
	jq -e --arg k "$1" --arg id "${2:-}" '[.items[] | select(.kind == $k and ($id == "" or .local_id == $id or .external_id == $id))] | length > 0' \
		"$WORK/findings.json" >/dev/null
}

# ------------------------------------------------------------- 0. set up ---

log "work directory $WORK"
if [ -n "${INTEROP_BIN:-}" ]; then
	BIN=$INTEROP_BIN
else
	BIN=$WORK/bin
	log "building identity-server, identity-worker and identity-cli"
	(cd "$ROOT" && go build -o "$BIN/" ./cmd/identity-server ./cmd/identity-worker ./cmd/identity-cli)
fi
for image in "$PG_IMAGE" "$ZT_IMAGE"; do
	docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image"
done
ZT_VERSION=$(docker run --rm "$ZT_IMAGE" --version 2>/dev/null | head -n 1)
PG_VERSION_STR=$(docker run --rm "$PG_IMAGE" postgres --version)
log "ZITADEL image $ZT_IMAGE ($ZT_VERSION); PostgreSQL image $PG_IMAGE ($PG_VERSION_STR)"

rand() { python3 -c 'import secrets;print(secrets.token_hex(16))'; }
SUPER_PW=$(rand)
APP_PW=$(rand)
ZT_DB_PW=$(rand)
MASTERKEY=$(rand) # 32 characters, as ZITADEL requires
ADMIN_PW="interop administrator passphrase 2026"
mkdir -p "$WORK/secrets"
chmod 700 "$WORK/secrets"

# ------------------------------------------------- 1. PostgreSQL, ZITADEL ---

log "1. PostgreSQL and ZITADEL"
docker network create "$NET" >/dev/null
docker volume create "$VOL" >/dev/null
docker run -d --name "$PG" --network "$NET" -p "127.0.0.1:$PG_PORT:5432" -e POSTGRES_PASSWORD="$SUPER_PW" "$PG_IMAGE" >/dev/null
_i=0
until docker exec "$PG" pg_isready -h 127.0.0.1 -U postgres -q 2>/dev/null; do
	_i=$((_i + 1))
	[ "$_i" -lt 120 ] || fail "PostgreSQL did not become ready"
	sleep 0.5
done
docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -q <<EOF
CREATE ROLE proudauth LOGIN PASSWORD '$APP_PW';
CREATE DATABASE proudauth OWNER proudauth;
EOF
# ZITADEL (a non-root user) writes the first instance's token into this volume.
docker run --rm -v "$VOL:/pat" "$PG_IMAGE" chmod 777 /pat
docker run -d --name "$ZT" --network "$NET" -p "127.0.0.1:$ZT_PORT:8080" -v "$VOL:/pat" \
	-e ZITADEL_DATABASE_POSTGRES_HOST="$PG" -e ZITADEL_DATABASE_POSTGRES_PORT=5432 -e ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel \
	-e ZITADEL_DATABASE_POSTGRES_USER_USERNAME=zitadel -e ZITADEL_DATABASE_POSTGRES_USER_PASSWORD="$ZT_DB_PW" \
	-e ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE=disable -e ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME=postgres \
	-e ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD="$SUPER_PW" -e ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE=disable \
	-e ZITADEL_EXTERNALSECURE=false -e ZITADEL_EXTERNALDOMAIN=localhost -e ZITADEL_EXTERNALPORT="$ZT_PORT" \
	-e ZITADEL_FIRSTINSTANCE_ORG_NAME=Acme -e ZITADEL_FIRSTINSTANCE_PATPATH=/pat/owner.pat \
	-e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME=interop-owner -e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME="Interop owner" \
	-e ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE=2099-01-01T00:00:00Z \
	"$ZT_IMAGE" start-from-init --masterkey "$MASTERKEY" --tlsMode disabled >/dev/null
# Ready means: the health endpoint answers, the token file is written and
# the API (served through ZITADEL's internal gRPC gateway, which connects a
# moment after the listener) accepts the token.
_i=0
until curl -fsS -o /dev/null "http://127.0.0.1:$ZT_PORT/debug/ready" 2>/dev/null &&
	OWNER_PAT=$(docker run --rm -v "$VOL:/pat" "$PG_IMAGE" cat /pat/owner.pat 2>/dev/null) && [ -n "$OWNER_PAT" ] &&
	[ "$(zt GET /management/v1/orgs/me "$OWNER_PAT")" = 200 ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 180 ] || fail "ZITADEL did not become ready: $(cat "$WORK/zt.json" 2>/dev/null)"
	[ "$(docker inspect -f '{{.State.Running}}' "$ZT")" = true ] || fail "ZITADEL exited"
	sleep 1
done
ORG_A=$(jq -r .org.id "$WORK/zt.json")
ztok 201 POST /v2/organizations "$OWNER_PAT" '{"name":"Globex"}'
ORG_B=$(jq -r .organizationId "$WORK/zt.json")
ok "ZITADEL $ZT_VERSION ready at $ZURL; organizations Acme ($ORG_A) and Globex ($ORG_B)"

# service_account ORG USERNAME -> personal access token of a new service
# account of that organization holding only ORG_USER_MANAGER there.
service_account() {
	ztok 200 POST /management/v1/users/machine "$OWNER_PAT" "$(jq -nc --arg u "$2" \
		'{userName:$u, name:"ProudAuth provisioning", description:"SCIM client of the ProudAuth interop test", accessTokenType:"ACCESS_TOKEN_TYPE_BEARER"}')" "$1"
	_mu=$(jq -r .userId "$WORK/zt.json")
	ztok 200 POST /management/v1/orgs/me/members "$OWNER_PAT" "$(jq -nc --arg u "$_mu" '{userId:$u, roles:["ORG_USER_MANAGER"]}')" "$1"
	ztok 200 POST "/management/v1/users/$_mu/pats" "$OWNER_PAT" '{"expirationDate":"2099-01-01T00:00:00Z"}' "$1"
	echo "$1 $_mu $(jq -r .tokenId "$WORK/zt.json")" >"$WORK/sa.$2"
	jq -r .token "$WORK/zt.json"
}
PAT_A=$(service_account "$ORG_A" proudauth-acme)
PAT_B=$(service_account "$ORG_B" proudauth-globex)
scim_ready() { [ "$(zt GET "/scim/v2/$1/ServiceProviderConfig" "$2")" = 200 ]; }
_i=0
until scim_ready "$ORG_A" "$PAT_A" && scim_ready "$ORG_B" "$PAT_B"; do
	_i=$((_i + 1))
	[ "$_i" -lt 30 ] || fail "SCIM with the service-account tokens: $(cat "$WORK/zt.json")"
	sleep 1
done
jq -e '.patch.supported and .filter.supported and (.authenticationSchemes[0].type == "oauthbearertoken")' "$WORK/zt.json" >/dev/null ||
	fail "ServiceProviderConfig: $(cat "$WORK/zt.json")"
ztok 200 GET "/scim/v2/$ORG_A/ResourceTypes" "$PAT_A"
RESOURCE_TYPES=$(jq -r '[.Resources[].name] | join(",")' "$WORK/zt.json")
# ZITADEL's User schema marks name (givenName, familyName) and emails as
# required, beyond RFC 7643's userName; there is no Groups endpoint.
ztok 200 GET "/scim/v2/$ORG_A/Schemas" "$PAT_A"
REQUIRED=$(jq -r '[.Resources[] | select(.id == "urn:ietf:params:scim:schemas:core:2.0:User") | .attributes[] | select(.required) | .name] | join(",")' "$WORK/zt.json")
[ "$(zt GET "/scim/v2/$ORG_A/Groups" "$PAT_A")" = 404 ] || fail "ZITADEL now serves /Groups: extend this test"
[ "$(zt GET "/scim/v2/$ORG_A/Users" "$PAT_B")" = 404 ] || fail "the Globex token reached the Acme organization: $(cat "$WORK/zt.json")"
ok "service accounts with ORG_USER_MANAGER only; SCIM resource types: $RESOURCE_TYPES (no /Groups); required User attributes: $REQUIRED; tokens confined to their organization"

# ------------------------------------------------------------ 2. ProudAuth ---

log "2. ProudAuth"
"$BIN/identity-cli" generate-root-key >"$WORK/secrets/root_key" 2>"$WORK/root-key.err" || fail "generate-root-key"
printf '%s' "postgres://proudauth:$APP_PW@127.0.0.1:$PG_PORT/proudauth?sslmode=disable" >"$WORK/secrets/database_url"
chmod 600 "$WORK/secrets/root_key" "$WORK/secrets/database_url"
cat >"$WORK/config.yaml" <<EOF
# Generated by scripts/interop-zitadel.sh.
mode: development
server:
  public_listen: "127.0.0.1:$HTTP_PORT"
  internal_listen: "127.0.0.1:$INTERNAL_PORT"
  public_origin: "$ORIGIN"
storage:
  database_url: "file:$WORK/secrets/database_url"
keys:
  root_keys:
    - version: 1
      ref: "file:$WORK/secrets/root_key"
  active_version: 1
sessions:
  cookie_insecure_dev: true
delivery:
  # ZITADEL listens on loopback: outbound SCIM to a private or loopback
  # address needs this development allowance and the connector's
  # allow_private_network (docs/operations/configuration.md).
  allow_private_webhooks: true
  email:
    adapter: dev_sink
observability:
  log_format: json
EOF
export PROUDAUTH_CONFIG="$WORK/config.yaml"
cli() { # NAME ARGS...: identity-cli, output in $WORK/NAME.out
	_name=$1
	shift
	"$BIN/identity-cli" "$@" >"$WORK/$_name.out" 2>"$WORK/$_name.err" || {
		cat "$WORK/$_name.out" "$WORK/$_name.err" >&2
		fail "identity-cli $1"
	}
}
cli migrate migrate
cli realm-create realm-create -name "$REALM" -display-name "ZITADEL interop"
cli bootstrap bootstrap -realm "$REALM" -email admin@interop.test -username interop-admin -ttl 10m
SETUP=$(awk '/one-time setup token/ {f=1; next} f && NF {print $1; exit}' "$WORK/bootstrap.out")
[ -n "$SETUP" ] || fail "no setup token in bootstrap output"
"$BIN/identity-server" -config "$WORK/config.yaml" >>"$WORK/server.log" 2>&1 &
SERVER_PID=$!
_i=0
until curl -fsS -o /dev/null "$ORIGIN/health/live" 2>/dev/null; do
	_i=$((_i + 1))
	kill -0 "$SERVER_PID" 2>/dev/null || fail "identity-server exited"
	[ "$_i" -lt 100 ] || fail "identity-server did not start"
	sleep 0.1
done
code=$(api POST /account-setup "" "$(jq -nc --arg t "$SETUP" --arg p "$ADMIN_PW" '{setup_token:$t, password:$p}')")
[ "$code" = 200 ] || fail "administrator account setup: $code $(cat "$WORK/resp.json")"
admin_login
ok "administrator signed in (password, email verification, TOTP enrollment)"

admin POST /organizations '{"slug":"acme","display_name":"Acme"}' 201
ACME=$(jq -r .id "$WORK/resp.json")
admin POST /organizations '{"slug":"globex","display_name":"Globex"}' 201
GLOBEX=$(jq -r .id "$WORK/resp.json")
ALICE=$(create_account alice Alice Anders)
BOB=$(create_account bob Bob Brown)
CAROL=$(create_account carol Carol Clark)
DAVE=$(create_account dave Dave Dunn)
ERIN=$(create_account erin Erin Evans)
FRANK=$(create_account frank Frank Foster)
add_member "$ACME" "$ALICE" >/dev/null
M_BOB=$(add_member "$ACME" "$BOB")
add_member "$ACME" "$FRANK" >/dev/null
M_DAVE=$(add_member "$GLOBEX" "$DAVE")
add_member "$GLOBEX" "$ERIN" >/dev/null
ok "organizations acme and globex; alice, bob and frank in acme, dave and erin in globex, carol in neither (emails verified)"

# -------------------------------------------------- 3. outbound connectors ---

log "3. outbound SCIM connectors to ZITADEL"
admin POST "/organizations/$ACME/directory-connectors" "$(jq -nc --arg u "$ZURL/scim/v2/$ORG_A" --arg t "$PAT_A" \
	'{name:"zitadel-acme", kind:"scim_outbound", credential:$t, config:{base_url:$u, allow_private_network:true}}')" 201
CONN_A=/organizations/$ACME/directory-connectors/$(jq -r .id "$WORK/resp.json")
grep -q "$PAT_A" "$WORK/resp.json" && fail "the ZITADEL token is shown in the connector view"
admin POST /directory-connectors "$(jq -nc --arg u "$ZURL/scim/v2/$ORG_B" --arg t "$PAT_B" --arg g "$GLOBEX" \
	'{name:"zitadel-globex", kind:"scim_outbound", credential:$t, config:{base_url:$u, allow_private_network:true, eligible_organization_ids:[$g], deprovision_action:"delete"}}')" 201
CONN_B=/directory-connectors/$(jq -r .id "$WORK/resp.json")

# The first scheduler pass reconciles each new connector: every eligible
# account is created in ZITADEL with externalId = the ProudAuth account ID.
initial() {
	has "$ORG_A" "$ALICE" '.userName == "alice" and .active == true and .name.givenName == "Alice" and .name.familyName == "Anders"
		and .displayName == "Alice Anders" and ([.emails[] | select(.primary) | .value] == ["alice@interop.test"])' &&
		has "$ORG_A" "$BOB" '.userName == "bob" and .active == true' && has "$ORG_A" "$FRANK" '.userName == "frank"' &&
		has "$ORG_B" "$DAVE" '.userName == "dave" and .active == true' &&
		has "$ORG_B" "$ERIN" '.userName == "erin" and .active == true' &&
		absent "$ORG_A" "$CAROL" && absent "$ORG_A" "$DAVE" && absent "$ORG_B" "$ALICE" &&
		settled "$CONN_A" && settled "$CONN_B"
}
eventually "initial reconciliation did not create alice, bob, frank (Acme), dave and erin (Globex) in ZITADEL" initial
has "$ORG_A" "$ALICE" true
Z_ALICE=$(jq -r .id "$WORK/scim.json")
[ "$(zt_state "$Z_ALICE")" = USER_STATE_ACTIVE ] || fail "alice is not active in ZITADEL's user API"
ok "initial reconciliation: alice, bob and frank in Acme, dave and erin in Globex (userName, name, displayName, verified email, externalId)"

# Create on a membership event.
add_member "$ACME" "$CAROL" >/dev/null
created() { has "$ORG_A" "$CAROL" '.userName == "carol" and .active == true and .name.familyName == "Clark"' && settled "$CONN_A"; }
eventually "carol was not created in ZITADEL after joining acme" created
ok "create: carol pushed when she joined acme"

# An account ZITADEL refuses: gina's email address is not verified yet (her
# setup link is unused), so ProudAuth sends no emails, and ZITADEL requires
# them. The create is rejected (400) and dead-lettered at once. Verifying
# the address (completing the setup link) changes the account; the change
# scan delivers it again and the create succeeds.
GINA=$(new_account gina Gina Green)
add_member "$ACME" "$GINA" >/dev/null
gina_refused() { dead_letter "$CONN_A" "$GINA" 400 rejected; }
eventually "gina's create (no verified email) was not dead-lettered as rejected (400)" gina_refused
absent "$ORG_A" "$GINA" || fail "ZITADEL created gina without an email address"
complete_setup gina "$GINA"
gina_created() { has "$ORG_A" "$GINA" '.userName == "gina" and ([.emails[] | select(.primary) | .value] == ["gina@interop.test"])' && settled "$CONN_A"; }
eventually "gina was not created in ZITADEL after verifying her email address" gina_created
ok "unverified email: gina's create rejected by ZITADEL (400, dead letter), then delivered after she verified her address"

# Profile update (no outbox event: the change scan finds it).
admin PATCH "/users/$ALICE" '{"given_name":"Alicia","family_name":"Anders-Lee","display_name":"Alicia Anders-Lee"}' 200
renamed() { has "$ORG_A" "$ALICE" '.name.givenName == "Alicia" and .name.familyName == "Anders-Lee" and .displayName == "Alicia Anders-Lee"' && settled "$CONN_A"; }
eventually "alice's new name did not reach ZITADEL" renamed
ok "update: alice's given, family and display names replaced in ZITADEL (PUT)"

# Email change: a new address, verified (administrator override with a
# recorded reason), made primary. The SCIM document carries only the
# verified primary address.
admin POST "/users/$BOB/identifiers" '{"type":"email","value":"robert@interop.test","reason":"interop: address change requested by the owner"}' 201
NEW_EMAIL=$(jq -r .id "$WORK/resp.json")
admin POST "/users/$BOB/verification-overrides" "$(jq -nc --arg i "$NEW_EMAIL" '{identifier_id:$i, reason:"interop: verified out of band"}')" 204
admin POST "/users/$BOB/identifiers/$NEW_EMAIL/primary" '{"reason":"interop: address change requested by the owner"}' 204
emailed() { has "$ORG_A" "$BOB" '[.emails[] | select(.primary) | .value] == ["robert@interop.test"]' && settled "$CONN_A"; }
eventually "bob's new primary email address did not reach ZITADEL" emailed
ok "update: bob's new verified primary email address replaced in ZITADEL"

# Suspension and reactivation of the account: active false, then true.
admin POST "/users/$ALICE/suspend" '{"reason":"interop"}' 200
suspended() { has "$ORG_A" "$ALICE" '.active == false' && [ "$(zt_state "$Z_ALICE")" = USER_STATE_INACTIVE ] && settled "$CONN_A"; }
eventually "alice's suspension did not deactivate her ZITADEL user" suspended
admin POST "/users/$ALICE/reactivate" '{"reason":"interop"}' 200
reactivated() { has "$ORG_A" "$ALICE" '.active == true' && [ "$(zt_state "$Z_ALICE")" = USER_STATE_ACTIVE ] && settled "$CONN_A"; }
eventually "alice's reactivation did not reactivate her ZITADEL user" reactivated
ok "suspend and reactivate: alice inactive, then active again in ZITADEL (SCIM and user API)"

# Membership suspension and reactivation (organization connector).
has "$ORG_A" "$BOB" true
Z_BOB=$(jq -r .id "$WORK/scim.json")
admin PATCH "/organizations/$ACME/members/$M_BOB" '{"state":"suspended"}' 200
m_suspended() { has "$ORG_A" "$BOB" '.active == false' && [ "$(zt_state "$Z_BOB")" = USER_STATE_INACTIVE ] && settled "$CONN_A"; }
eventually "bob's suspended membership did not deactivate his ZITADEL user" m_suspended
admin PATCH "/organizations/$ACME/members/$M_BOB" '{"state":"active"}' 200
m_reactivated() { has "$ORG_A" "$BOB" '.active == true' && [ "$(zt_state "$Z_BOB")" = USER_STATE_ACTIVE ] && settled "$CONN_A"; }
eventually "bob's reactivated membership did not reactivate his ZITADEL user" m_reactivated
ok "membership suspend and reactivate: bob inactive, then active again in ZITADEL"

# Deprovisioning by the deactivate connector: membership removal, and the
# deletion of the account.
admin DELETE "/organizations/$ACME/members/$M_BOB" "" 204
bob_off() { has "$ORG_A" "$BOB" '.active == false' && [ "$(zt_state "$Z_BOB")" = USER_STATE_INACTIVE ] && settled "$CONN_A"; }
eventually "bob was not deactivated in ZITADEL after leaving acme" bob_off
admin DELETE "/users/$CAROL" "" 204
carol_off() { has "$ORG_A" "$CAROL" '.active == false' && settled "$CONN_A"; }
eventually "carol's deleted account was not deactivated in ZITADEL" carol_off
ok "deprovision (deactivate): bob after leaving acme and carol after deletion are inactive in ZITADEL, not deleted"

# Deprovisioning by the delete connector: account deletion and membership
# removal both delete the ZITADEL user.
has "$ORG_B" "$ERIN" true
Z_ERIN=$(jq -r .id "$WORK/scim.json")
admin DELETE "/users/$ERIN" "" 204
erin_gone() { absent "$ORG_B" "$ERIN" && [ -z "$(zt_state "$Z_ERIN")" ] && settled "$CONN_B"; }
eventually "erin's deleted account was not deleted from ZITADEL" erin_gone
admin DELETE "/organizations/$GLOBEX/members/$M_DAVE" "" 204
dave_gone() { absent "$ORG_B" "$DAVE" && settled "$CONN_B"; }
eventually "dave was not deleted from ZITADEL after leaving globex" dave_gone
ok "deprovision (delete): erin's deletion and dave's departure deleted their ZITADEL users"

# The bearer token revoked in ZITADEL: the next delivery is refused (401)
# and dead-lettered as unauthorized. A new token is issued in ZITADEL, the
# connector's credential replaced, and the dead letter replayed.
read -r _org SA_B TOKEN_B <"$WORK/sa.proudauth-globex"
ztok 200 DELETE "/management/v1/users/$SA_B/pats/$TOKEN_B" "$OWNER_PAT" "" "$ORG_B"
revoked() { [ "$(zt GET "/scim/v2/$ORG_B/Users" "$PAT_B")" = 401 ]; }
_i=0
until revoked; do
	_i=$((_i + 1))
	[ "$_i" -lt 30 ] || fail "the revoked token still works: $(cat "$WORK/zt.json")"
	sleep 1
done
HANK=$(create_account hank Hank Hill)
add_member "$GLOBEX" "$HANK" >/dev/null
hank_refused() { dead_letter "$CONN_B" "$HANK" 401 unauthorized; }
eventually "hank's create with a revoked token was not dead-lettered as unauthorized (401)" hank_refused
ztok 200 POST "/management/v1/users/$SA_B/pats" "$OWNER_PAT" '{"expirationDate":"2099-01-01T00:00:00Z"}' "$ORG_B"
PAT_B2=$(jq -r .token "$WORK/zt.json")
admin PUT "$CONN_B/credential" "$(jq -nc --arg t "$PAT_B2" '{credential:$t}')" 200
admin POST "$CONN_B/deliveries/$DEAD_ID/replay" "" 202
hank_created() { has "$ORG_B" "$HANK" '.userName == "hank" and .active == true' && settled "$CONN_B"; }
eventually "hank was not created after the credential rotation and replay" hank_created
ok "credential: a revoked ZITADEL token dead-letters as unauthorized (401); the rotated token and a replay deliver"

# ------------------------------------------------------ 4. reconciliation ---

log "4. reconciliation (PROV-017)"
# Drift made in ZITADEL (nothing changed locally, so no delivery is due), a
# managed user deleted there, and a user ProudAuth did not create.
ztok 204 PATCH "/scim/v2/$ORG_A/Users/$Z_ALICE" "$OWNER_PAT" \
	'{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"displayName","value":"Changed in ZITADEL"}]}'
has "$ORG_A" "$ALICE" '.displayName == "Changed in ZITADEL"' || fail "ZITADEL did not apply the drift"
has "$ORG_A" "$FRANK" true
Z_FRANK=$(jq -r .id "$WORK/scim.json")
ztok 204 DELETE "/scim/v2/$ORG_A/Users/$Z_FRANK" "$OWNER_PAT"
ztok 201 POST "/scim/v2/$ORG_A/Users" "$OWNER_PAT" '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"zitadel-only",
	"name":{"givenName":"Zed","familyName":"Only"},"emails":[{"value":"zed@interop.test","primary":true}],"externalId":"not-from-proudauth"}'
Z_ZED=$(jq -r .id "$WORK/zt.json")
# Dry run first (the advice for a new downstream): a plan, nothing applied.
run "$CONN_A" '{"mode":"reconcile","dry_run":true}'
finding drift "$ALICE" || fail "dry run: no drift for alice: $(cat "$WORK/findings.json")"
finding missing_remote "$FRANK" || fail "dry run: frank's deleted ZITADEL user is not reported missing: $(cat "$WORK/findings.json")"
finding unmanaged_remote "$Z_ZED" || fail "dry run: the ZITADEL-only user is not reported unmanaged: $(cat "$WORK/findings.json")"
pump
has "$ORG_A" "$ALICE" '.displayName == "Changed in ZITADEL"' && absent "$ORG_A" "$FRANK" || fail "the dry run changed ZITADEL"
ok "dry run: $(jq -c '.counts' "$WORK/run.json"); ZITADEL unchanged"
run "$CONN_A" '{"mode":"reconcile"}'
repaired() {
	has "$ORG_A" "$ALICE" '.displayName == "Alicia Anders-Lee"' && has "$ORG_A" "$FRANK" '.active == true and .userName == "frank"' &&
		settled "$CONN_A"
}
eventually "reconciliation did not repair alice's drift or recreate frank" repaired
[ "$(zt_state "$Z_ZED")" = USER_STATE_ACTIVE ] || fail "reconciliation changed the user it did not create"
has "$ORG_A" "$BOB" '.active == false' || fail "reconciliation reactivated bob, who left acme"
ok "reconciliation: $(jq -c '.counts' "$WORK/run.json"); drift repaired, frank recreated, the unmanaged ZITADEL user left alone"

admin GET "$CONN_A/health" "" 200
jq -e '(.deliveries.dead_letter // 0) == 1' "$WORK/resp.json" >/dev/null || fail "health (only gina's refused create dead-lettered): $(cat "$WORK/resp.json")"
for p in "$CONN_A" "$CONN_A/health" "$CONN_A/deliveries" "$CONN_B" "$CONN_B/deliveries"; do
	admin GET "$p" "" 200
	if grep -q -e "$PAT_A" -e "$PAT_B" -e "$PAT_B2" "$WORK/resp.json"; then fail "a ZITADEL token appears in $p"; fi
done
admin GET "$CONN_A/deliveries" "" 200
DELIVERED=$(jq '[.items[] | select(.state == "delivered")] | length' "$WORK/resp.json")
OPS=$(jq -r '[.items[] | select(.state == "delivered") | .operation] | unique | join(",")' "$WORK/resp.json")
ok "evidence: $DELIVERED deliveries to Acme ($OPS), no unexpected dead letters; tokens absent from views"

log "PASSED: ProudAuth outbound SCIM against ZITADEL $ZT_VERSION ($PG_VERSION_STR)"
