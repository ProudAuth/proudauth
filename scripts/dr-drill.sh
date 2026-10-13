#!/bin/sh
# Disaster-recovery drill: warm-standby promotion (DEP-019) and point-in-time
# recovery (OPS-007), following docs/operations/backup-restore.md
# ("Promotion runbook", "Restore procedure", "Point-in-time recovery and
# protecting backups").
#
# What it does, with throwaway PostgreSQL containers and the ProudAuth
# binaries built from this checkout and run on the host:
#
#   1. A primary PostgreSQL with WAL archiving (archive_mode=on, archive_command
#      copying segments to an archive volume) and a replication pg_hba entry,
#      and a streaming standby made with pg_basebackup -R (synchronous by
#      default; DRILL_SYNC=off for asynchronous).
#   2. ProudAuth on the primary: migrate, realm-create, bootstrap, the
#      administrator's first sign-in (password, email verification, TOTP
#      enrollment), a resource, a client, an introspecting resource server and
#      users with sessions. A base backup is taken; then one change before and
#      several after a recorded target time (a user created; then a user
#      created, a user's sessions revoked, a user deleted, a user suspended, a
#      refresh token rotated), and the revocation log is exported.
#   3. Failover: a write load runs while the primary is fenced (killed); the
#      standby is promoted, the restore marker set, identity-server started on
#      it with the same keys, doctor's key fingerprint compared, the revocation
#      log reconciled, side effects reviewed, the worker started, and sign-in,
#      token issuance and introspection verified, including that revoked and
#      deleted state stayed revoked and deleted. RPO (acknowledged
#      transactions lost) and RTO (fencing to the first token) are printed.
#   4. Point-in-time recovery: the base backup plus archived WAL restored into
#      a fresh container with recovery_target_time between the two changes,
#      then the same restore procedure; the later changes must be absent and
#      the revocations exported after the target time re-applied.
#
# Requirements: docker, go, curl, jq, python3 (TOTP and PKCE). Nothing else is
# installed. Environment overrides: DRILL_PG_IMAGE (default postgres:18),
# DRILL_PREFIX (container/volume/network prefix, default pa-drill),
# DRILL_PG_PORT_BASE (three consecutive host ports, default 55491),
# DRILL_HTTP_PORT / DRILL_INTERNAL_PORT (default 18491 / 18492), DRILL_SYNC
# (on|off), DRILL_BIN (prebuilt binaries; default: go build into a temp dir),
# DRILL_KEEP=1 (keep the work directory, containers and volumes for
# inspection).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${DRILL_PG_IMAGE:-postgres:18}
PREFIX=${DRILL_PREFIX:-pa-drill}
PORT_BASE=${DRILL_PG_PORT_BASE:-55491}
PRIMARY_PORT=$PORT_BASE
STANDBY_PORT=$((PORT_BASE + 1))
PITR_PORT=$((PORT_BASE + 2))
HTTP_PORT=${DRILL_HTTP_PORT:-18491}
INTERNAL_PORT=${DRILL_INTERNAL_PORT:-18492}
SYNC=${DRILL_SYNC:-on}
KEEP=${DRILL_KEEP:-0}
REALM=main

NET=$PREFIX-net
PRIMARY=$PREFIX-primary
STANDBY=$PREFIX-standby
PITR=$PREFIX-pitr
VOLUMES="$PREFIX-primary-data $PREFIX-standby-data $PREFIX-pitr-data $PREFIX-archive $PREFIX-archive-dr $PREFIX-base"

ORIGIN=http://127.0.0.1:$HTTP_PORT
ISSUER=$ORIGIN/realms/$REALM
API=$ORIGIN/api/v1/realms/$REALM
INTERNAL=http://127.0.0.1:$INTERNAL_PORT
APP_REDIRECT=https://app.drill.test/callback
AUDIENCE=https://api.drill.test

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pa-drill.XXXXXX")
SERVER_PID=
WORKER_PID=
HB_PID=

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
ok() { printf '[%s]   ok: %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() {
	printf '\nDRILL FAILED: %s\n' "$*" >&2
	exit 1
}
now_ms() { jq -n 'now * 1000 | floor'; }
secs() { jq -rn --argjson a "$1" --argjson b "$2" '(($b - $a) / 100 | round) as $d | "\($d / 10 | floor).\($d % 10)"'; }

kill_proc() {
	if [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; then
		kill -9 "$1" 2>/dev/null || true
		wait "$1" 2>/dev/null || true
	fi
}

docker_cleanup() {
	docker rm -f "$PRIMARY" "$STANDBY" "$PITR" >/dev/null 2>&1 || true
	# shellcheck disable=SC2086
	docker volume rm $VOLUMES >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}

cleanup() {
	status=$?
	trap - EXIT INT TERM
	kill_proc "$HB_PID"
	kill_proc "$SERVER_PID"
	kill_proc "$WORKER_PID"
	if [ "$status" -ne 0 ]; then
		for f in "$WORK"/*.log; do
			[ -f "$f" ] || continue
			printf '\n--- last lines of %s ---\n' "$(basename "$f")" >&2
			tail -n 6 "$f" | cut -c1-400 >&2 || true
		done
	fi
	if [ "$KEEP" = 1 ]; then
		log "DRILL_KEEP=1: kept $WORK, containers, volumes and network $NET"
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
# port_open PORT: something accepts TCP connections on 127.0.0.1:PORT (curl
# exit status 7 is "could not connect"; anything else means a listener).
port_open() {
	_rc=0
	curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$1/" 2>/dev/null || _rc=$?
	[ "$_rc" -ne 7 ]
}
docker info >/dev/null 2>&1 || fail "docker is not reachable"
# Leftovers of an earlier run with DRILL_KEEP=1 (same prefix) go first.
docker_cleanup
for port in "$PRIMARY_PORT" "$STANDBY_PORT" "$PITR_PORT" "$HTTP_PORT" "$INTERNAL_PORT"; do
	if port_open "$port"; then
		fail "port $port is in use (set DRILL_PG_PORT_BASE, DRILL_HTTP_PORT or DRILL_INTERNAL_PORT)"
	fi
done

# ---------------------------------------------------------------- helpers ---

# Inside a container: psql as the superuser over the local socket.
psql_in() {
	_c=$1 _db=$2
	shift 2
	docker exec -i "$_c" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$_db" -Atq "$@"
}

wait_pg() { # container: wait until PostgreSQL accepts TCP connections
	_i=0
	until docker exec "$1" pg_isready -h 127.0.0.1 -U postgres -q 2>/dev/null; do
		_i=$((_i + 1))
		[ "$_i" -lt 120 ] || { docker logs --tail 30 "$1" >&2; fail "$1 did not become ready"; }
		[ "$(docker inspect -f '{{.State.Running}}' "$1")" = true ] || { docker logs --tail 30 "$1" >&2; fail "$1 exited"; }
		sleep 0.5
	done
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

# api METHOD PATH [BEARER] [JSON]: body to $WORK/resp.json, prints the status.
api() {
	_m=$1 _p=$2 _t=${3:-} _b=${4:-}
	set -- -sS -o "$WORK/resp.json" -w '%{http_code}' -X "$_m" "$API$_p"
	if [ -n "$_t" ]; then set -- "$@" -H "Authorization: Bearer $_t"; fi
	if [ -n "$_b" ]; then set -- "$@" -H 'Content-Type: application/json' --data "$_b"; fi
	curl "$@"
}

admin() { # METHOD PATH [JSON] EXPECTED-STATUS: administrator call, fails the drill otherwise
	_code=$(api "$1" "$2" "$ADMIN_TOKEN" "${3:-}")
	[ "$_code" = "$4" ] || fail "$1 $2: expected $4, got $_code $(cat "$WORK/resp.json")"
}

form_post() { # PATH-UNDER-ISSUER BASIC-USER:PASS form-args...: body to $WORK/resp.json, prints status
	_p=$1 _u=$2
	shift 2
	if [ -n "$_u" ]; then
		curl -sS -o "$WORK/resp.json" -w '%{http_code}' -u "$_u" "$ISSUER$_p" "$@"
	else
		curl -sS -o "$WORK/resp.json" -w '%{http_code}' "$ISSUER$_p" "$@"
	fi
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

mailbox_code() { # recipient: newest email verification code from the development sink
	_i=0
	while [ "$_i" -lt 40 ]; do
		_code=$(curl -fsS "$INTERNAL/dev/mailbox?realm=$REALM&recipient=$1" 2>/dev/null |
			jq -r '[.items[]? | select(.template == "email_verification")][0].body // empty' |
			grep -Eo '(^|[^0-9])[0-9]{6}([^0-9]|$)' | grep -Eo '[0-9]{6}' | head -n 1 || true)
		if [ -n "$_code" ] && [ "$_code" != "$(cat "$WORK/mail.last" 2>/dev/null)" ]; then
			echo "$_code" >"$WORK/mail.last"
			echo "$_code"
			return 0
		fi
		_i=$((_i + 1))
		sleep 0.5
	done
	return 1
}

# login IDENTIFIER PASSWORD CLIENT SECRET REDIRECT SCOPE RESOURCE OUT:
# headless authorization-code + PKCE sign-in through the interaction API (the
# path a login UI takes), then the token exchange. Tokens go to OUT. Returns 1
# with LOGIN_ERROR set when the sign-in is refused at any step.
login() {
	_id=$1 _pw=$2 _client=$3 _secret=$4 _redirect=$5 _scope=$6 _res=$7 _out=$8
	LOGIN_ERROR=
	set -- $(pkce)
	_verifier=$1 _challenge=$2
	_code=$(api POST /auth/transactions "" "$(jq -nc --arg c "$_client" --arg r "$_redirect" --arg s "$_scope" --arg res "$_res" --arg ch "$_challenge" \
		'{client_id:$c, redirect_uri:$r, scope:$s, resource:[$res], code_challenge:$ch, code_challenge_method:"S256", state:"drill"}')")
	if [ "$_code" != 201 ]; then
		LOGIN_ERROR="start: HTTP $_code $(cat "$WORK/resp.json")"
		return 1
	fi
	TX_ID=$(jq -r .transaction_id "$WORK/resp.json")
	TX_CONT=$(jq -r .continuation_token "$WORK/resp.json")
	jq .state "$WORK/resp.json" >"$WORK/state.json"
	_n=0
	while [ "$_n" -lt 20 ]; do
		_n=$((_n + 1))
		_redir=$(jq -r '.redirect_to // empty' "$WORK/state.json")
		[ -z "$_redir" ] || break
		_status=$(jq -r .status "$WORK/state.json")
		if [ "$_status" != pending ]; then
			LOGIN_ERROR="login ended: $(jq -c '{status, error}' "$WORK/state.json")"
			return 1
		fi
		_types=" $(jq -r '[.next_actions[]?.type] | join(" ")' "$WORK/state.json") "
		case $_types in
		*" identify "*) tx_step identify "$(jq -nc --arg i "$_id" '{identifier:$i}')" || return 1 ;;
		*" password "*) tx_step password "$(jq -nc --arg p "$_pw" '{password:$p}')" || return 1 ;;
		*" verify_email "*)
			tx_step otp/send '{"purpose":"verify_email"}' || return 1
			_otp=$(mailbox_code "${LOGIN_EMAIL:-$_id}") || {
				LOGIN_ERROR="no verification email for ${LOGIN_EMAIL:-$_id} in the development sink"
				return 1
			}
			tx_step otp/verify "$(jq -nc --arg c "$_otp" '{code:$c}')" || return 1
			;;
		*" enroll_totp "*)
			tx_step totp/enroll '{}' || return 1
			jq -r '.one_time.totp.secret' "$WORK/state.json" >"$WORK/totp.secret"
			tx_step totp/activate "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')" || return 1
			;;
		*" totp "*) tx_step totp "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')" || return 1 ;;
		*" accept_terms "*) tx_step terms "$(jq -c '{version: .next_actions[0].options.version}' "$WORK/state.json")" || return 1 ;;
		*" consent "*) tx_step consent '{"approve":true}' || return 1 ;;
		*)
			LOGIN_ERROR="unhandled step(s):$_types"
			return 1
			;;
		esac
	done
	[ -n "$_redir" ] || {
		LOGIN_ERROR="too many steps"
		return 1
	}
	_authz=$(printf '%s' "$_redir" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
	if [ -n "$_secret" ]; then
		_code=$(form_post /oauth/token "$_client:$_secret" -d grant_type=authorization_code --data-urlencode "code=$_authz" \
			--data-urlencode "code_verifier=$_verifier" --data-urlencode "redirect_uri=$_redirect" --data-urlencode "resource=$_res")
	else
		_code=$(form_post /oauth/token "" -d grant_type=authorization_code --data-urlencode "code=$_authz" -d "client_id=$_client" \
			--data-urlencode "code_verifier=$_verifier" --data-urlencode "redirect_uri=$_redirect" --data-urlencode "resource=$_res")
	fi
	if [ "$_code" != 200 ]; then
		LOGIN_ERROR="token exchange: HTTP $_code $(cat "$WORK/resp.json")"
		return 1
	fi
	cp "$WORK/resp.json" "$_out"
}

admin_login() {
	# An unverified email address is not a sign-in identifier yet: the
	# bootstrap administrator identifies by username (installation.md, 7).
	LOGIN_EMAIL=admin@drill.test
	login drill-admin "$ADMIN_PW" proudauth-cli "" http://127.0.0.1/callback proudauth:admin "$ISSUER/admin" "$WORK/admin.json" ||
		fail "administrator sign-in: $LOGIN_ERROR"
	ADMIN_TOKEN=$(jq -r .access_token "$WORK/admin.json")
}

user_login() { # name OUT: sign in to the drill application
	# The setup token was handed over directly (no setup email), so the
	# address is unverified and the username is the sign-in identifier.
	LOGIN_EMAIL=$1@drill.test
	login "$1" "$(pw_of "$1")" drill-web "$WEB_SECRET" "$APP_REDIRECT" drill:read "$AUDIENCE" "$2"
}

pw_of() { echo "$1 drill passphrase 2026 standby"; }

create_user() { # name: admin-created account with a setup token, completed with a password
	admin POST /users "$(jq -nc --arg n "$1" '{email:($n + "@drill.test"), username:$n, display_name:$n, send_setup_email:false}')" 201
	_uid=$(jq -r .user.id "$WORK/resp.json")
	_setup=$(jq -r .setup_token "$WORK/resp.json")
	_code=$(api POST /account-setup "" "$(jq -nc --arg t "$_setup" --arg p "$(pw_of "$1")" '{setup_token:$t, password:$p}')")
	[ "$_code" = 200 ] || fail "account setup for $1: $_code $(cat "$WORK/resp.json")"
	echo "$_uid" >"$WORK/user.$1"
}

introspect() { # token -> prints active (true/false)
	_code=$(form_post /oauth/introspect "drill-rs:$RS_SECRET" --data-urlencode "token=$1")
	[ "$_code" = 200 ] || fail "introspection: HTTP $_code $(cat "$WORK/resp.json")"
	jq -r .active "$WORK/resp.json"
}

refresh() { # refresh-token OUT -> prints the HTTP status; tokens to OUT on success
	_code=$(form_post /oauth/token "drill-web:$WEB_SECRET" -d grant_type=refresh_token --data-urlencode "refresh_token=$1" \
		--data-urlencode "resource=$AUDIENCE")
	[ "$_code" != 200 ] || cp "$WORK/resp.json" "$2"
	echo "$_code"
}

write_config() { # name database-url
	printf '%s' "$2" >"$WORK/secrets/database_url_$1"
	chmod 600 "$WORK/secrets/database_url_$1"
	cat >"$WORK/config-$1.yaml" <<EOF
# Generated by scripts/dr-drill.sh. Same keys and origin on every side; only
# the database differs (docs/operations/backup-restore.md, "The profile").
mode: development
server:
  public_listen: "127.0.0.1:$HTTP_PORT"
  internal_listen: "127.0.0.1:$INTERNAL_PORT"
  public_origin: "$ORIGIN"
storage:
  database_url: "file:$WORK/secrets/database_url_$1"
keys:
  root_keys:
    - version: 1
      ref: "file:$WORK/secrets/root_key"
  active_version: 1
sessions:
  cookie_insecure_dev: true
delivery:
  email:
    adapter: dev_sink
observability:
  log_format: json
EOF
}

# op NAME COMMAND [ARGS]: identity-cli with stdout in $WORK/NAME.out and
# stderr (development-mode warnings, errors) in $WORK/NAME.err; fails the
# drill on error.
op() {
	_name=$1
	shift
	"$BIN/identity-cli" "$@" >"$WORK/$_name.out" 2>"$WORK/$_name.err" || {
		cat "$WORK/$_name.out" "$WORK/$_name.err" >&2
		fail "identity-cli $1 ($_name)"
	}
}

start_server() { # config-name: identity-server in the background
	"$BIN/identity-server" -config "$WORK/config-$1.yaml" >>"$WORK/server-$1.log" 2>&1 &
	SERVER_PID=$!
	_i=0
	until curl -fsS -o /dev/null "$ORIGIN/health/live" 2>/dev/null; do
		_i=$((_i + 1))
		kill -0 "$SERVER_PID" 2>/dev/null || fail "identity-server ($1) exited"
		[ "$_i" -lt 100 ] || fail "identity-server ($1) did not start"
		sleep 0.1
	done
}

start_worker() {
	"$BIN/identity-worker" -config "$WORK/config-$1.yaml" >>"$WORK/worker-$1.log" 2>&1 &
	WORKER_PID=$!
}

ready_status() { curl -s -o "$WORK/ready.json" -w '%{http_code}' "$ORIGIN/health/ready"; }

wait_ready() { # expected-status
	_i=0
	while [ "$(ready_status)" != "$1" ]; do
		_i=$((_i + 1))
		[ "$_i" -lt 100 ] || fail "readiness did not become $1: $(cat "$WORK/ready.json")"
		sleep 0.1
	done
}

fingerprint() { # config-name
	op "doctor-$1" doctor -config "$WORK/config-$1.yaml"
	sed -n 's/^key hierarchy fingerprint: //p' "$WORK/doctor-$1.out"
}

pa_sql() { psql_in "$1" proudauth -c "$2"; } # container sql

# ------------------------------------------------------------- 0. set up ---

log "work directory $WORK"
if [ -n "${DRILL_BIN:-}" ]; then
	BIN=$DRILL_BIN
else
	BIN=$WORK/bin
	log "building identity-server, identity-worker and identity-cli"
	(cd "$ROOT" && go build -o "$BIN/" ./cmd/identity-server ./cmd/identity-worker ./cmd/identity-cli)
fi

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
PGDATA=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" | sed -n 's/^PGDATA=//p')
VOLDIR=$(docker image inspect -f '{{range $k, $v := .Config.Volumes}}{{println $k}}{{end}}' "$IMAGE" | head -n 1)
[ -n "$PGDATA" ] && [ -n "$VOLDIR" ] || fail "cannot read PGDATA and the data volume from $IMAGE"
PG_VERSION_STR=$(docker run --rm "$IMAGE" postgres --version)
log "image $IMAGE ($PG_VERSION_STR), PGDATA $PGDATA"

SUPER_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
APP_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
REPL_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
ADMIN_PW="drill administrator passphrase 2026"
SINCE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$WORK/secrets"
chmod 700 "$WORK/secrets"

docker network create "$NET" >/dev/null
for v in $VOLUMES; do docker volume create "$v" >/dev/null; done
# The archive and base-backup volumes are written by the postgres user.
docker run --rm -v "$PREFIX-archive:/archive" -v "$PREFIX-archive-dr:/archive-dr" -v "$PREFIX-base:/backup" "$IMAGE" \
	chown postgres:postgres /archive /archive-dr /backup

ARCHIVE_CMD='test ! -f /archive/%f && cp %p /archive/%f'
PG_ARGS="-c wal_level=replica -c max_wal_senders=10 -c max_replication_slots=10 -c hot_standby=on"

# ----------------------------------------- 1. primary, archive, standby ---

log "1. primary PostgreSQL with WAL archiving and a streaming standby"
# shellcheck disable=SC2086
docker run -d --name "$PRIMARY" --network "$NET" -p "127.0.0.1:$PRIMARY_PORT:5432" \
	-e POSTGRES_PASSWORD="$SUPER_PW" -v "$PREFIX-primary-data:$VOLDIR" -v "$PREFIX-archive:/archive" \
	"$IMAGE" $PG_ARGS -c archive_mode=on -c "archive_command=$ARCHIVE_CMD" -c archive_timeout=60 >/dev/null
wait_pg "$PRIMARY"
psql_in "$PRIMARY" postgres <<EOF
CREATE ROLE proudauth LOGIN PASSWORD '$APP_PW';
CREATE DATABASE proudauth OWNER proudauth;
CREATE ROLE replicator LOGIN REPLICATION PASSWORD '$REPL_PW';
CREATE DATABASE drill;
EOF
psql_in "$PRIMARY" drill -c 'CREATE TABLE heartbeat (id bigserial PRIMARY KEY, at timestamptz NOT NULL DEFAULT clock_timestamp())'
docker exec "$PRIMARY" sh -c "echo 'host replication replicator all scram-sha-256' >> '$PGDATA/pg_hba.conf'"
psql_in "$PRIMARY" postgres -c 'SELECT pg_reload_conf()' >/dev/null
ok "primary up (archive_mode=on, replication entry in pg_hba.conf)"
if [ "$SYNC" = on ]; then
	# Set before the standby's base backup, as in a cluster configured with
	# ALTER SYSTEM: postgresql.auto.conf, and with it this setting, is copied
	# to the standby and into every base backup.
	psql_in "$PRIMARY" postgres -c "ALTER SYSTEM SET synchronous_standby_names = 'pa_drill_standby'" -c 'SELECT pg_reload_conf()' >/dev/null
fi

docker run --rm --network "$NET" --user postgres -v "$PREFIX-standby-data:$VOLDIR" "$IMAGE" \
	pg_basebackup -d "host=$PRIMARY user=replicator password=$REPL_PW application_name=pa_drill_standby" \
	-D "$PGDATA" -R -X stream -c fast -C -S pa_drill_standby >/dev/null
# shellcheck disable=SC2086
docker run -d --name "$STANDBY" --network "$NET" -p "127.0.0.1:$STANDBY_PORT:5432" \
	-v "$PREFIX-standby-data:$VOLDIR" -v "$PREFIX-archive-dr:/archive" \
	"$IMAGE" $PG_ARGS -c cluster_name=pa_drill_standby -c archive_mode=on -c "archive_command=$ARCHIVE_CMD" >/dev/null
wait_pg "$STANDBY"
_i=0
WANT_STATE="streaming $([ "$SYNC" = on ] && echo sync || echo async)"
until [ "$(psql_in "$PRIMARY" postgres -c "SELECT state || ' ' || sync_state FROM pg_stat_replication WHERE application_name='pa_drill_standby'")" = "$WANT_STATE" ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 60 ] || fail "standby is not $WANT_STATE"
	sleep 0.5
done
ok "standby $WANT_STATE"

# ------------------------------------------------ 2. ProudAuth on primary ---

log "2. ProudAuth on the primary"
op root-key generate-root-key
mv "$WORK/root-key.out" "$WORK/secrets/root_key"
chmod 600 "$WORK/secrets/root_key"
write_config primary "postgres://proudauth:$APP_PW@127.0.0.1:$PRIMARY_PORT/proudauth?sslmode=disable"
write_config standby "postgres://proudauth:$APP_PW@127.0.0.1:$STANDBY_PORT/proudauth?sslmode=disable"
write_config pitr "postgres://proudauth:$APP_PW@127.0.0.1:$PITR_PORT/proudauth?sslmode=disable"
export PROUDAUTH_CONFIG="$WORK/config-primary.yaml"
op migrate migrate
op realm-create realm-create -name "$REALM" -display-name "DR drill"
op bootstrap bootstrap -realm "$REALM" -email admin@drill.test -username drill-admin -ttl 10m
SETUP=$(awk '/one-time setup token/ {f=1; next} f && NF {print $1; exit}' "$WORK/bootstrap.out")
[ -n "$SETUP" ] || fail "no setup token in bootstrap output"
FP_PRIMARY=$(fingerprint primary)
ok "migrated, realm $REALM created, administrator bootstrapped; key fingerprint $FP_PRIMARY"

start_server primary
start_worker primary
wait_ready 200
code=$(api POST /account-setup "" "$(jq -nc --arg t "$SETUP" --arg p "$ADMIN_PW" '{setup_token:$t, password:$p}')")
[ "$code" = 200 ] || fail "administrator account setup: $code $(cat "$WORK/resp.json")"
admin_login
ok "administrator signed in (password, email verification, TOTP enrollment)"

admin POST /resources "$(jq -nc --arg a "$AUDIENCE" '{name:"Drill API", audience:$a, verification_mode:"strict_online", requires_organization:false, scopes:[{name:"drill:read"}]}')" 201
RES_ID=$(jq -r .id "$WORK/resp.json")
admin POST /clients "$(jq -nc --arg r "$APP_REDIRECT" '{client_id:"drill-web", name:"Drill web app", client_type:"confidential", first_party:true,
	grant_types:["authorization_code","refresh_token"], redirect_uris:[$r]}')" 201
WEB_REF=$(jq -r .client.id "$WORK/resp.json")
WEB_SECRET=$(jq -r .client_secret "$WORK/resp.json")
admin PUT "/clients/$WEB_REF/resource-grants/$RES_ID" '{"allowed_scopes":["drill:read"],"subject_types":["user"]}' 204
admin POST /service-principals '{"name":"drill-rs"}' 201
SP_ID=$(jq -r .id "$WORK/resp.json")
admin GET '/roles?boundary_type=realm' "" 200
RS_ROLE=$(jq -r '.items[] | select(.name == "resource-server") | .id' "$WORK/resp.json")
admin POST /role-assignments "$(jq -nc --arg r "$RS_ROLE" --arg s "$SP_ID" '{role_id:$r, subject:{type:"service_principal", id:$s}}')" 201
admin POST /clients "$(jq -nc --arg s "$SP_ID" '{client_id:"drill-rs", name:"Drill resource server", client_type:"machine", service_principal_id:$s, grant_types:["client_credentials"]}')" 201
RS_REF=$(jq -r .client.id "$WORK/resp.json")
RS_SECRET=$(jq -r .client_secret "$WORK/resp.json")
admin POST "/resources/$RES_ID/introspectors" "$(jq -nc --arg c "$RS_REF" '{client:$c}')" 204
for u in alice bob carol dave; do create_user "$u"; done
for u in alice bob carol dave; do
	user_login "$u" "$WORK/tokens.$u.json" || fail "$u sign-in: $LOGIN_ERROR"
done
jq -e '.refresh_token | length > 0' "$WORK/tokens.alice.json" >/dev/null || fail "no refresh token issued"
[ "$(introspect "$(jq -r .access_token "$WORK/tokens.bob.json")")" = true ] || fail "bob's token inactive on the primary"
ok "resource, client, introspector and users alice, bob, carol, dave signed in"

# Base backup for point-in-time recovery (OPS-007).
docker run --rm --network "$NET" --user postgres -v "$PREFIX-base:/backup" "$IMAGE" \
	pg_basebackup -d "host=$PRIMARY user=replicator password=$REPL_PW" -D /backup/base -X stream -c fast -l "pa-drill base" >/dev/null
ok "base backup taken"

# Change A, before the target time.
create_user erin
sleep 1.5
TARGET=$(psql_in "$PRIMARY" postgres -c "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') || '+00'")
sleep 1.5
# Changes after the target time: a new user, revocations and a rotation.
create_user frank
admin POST "/users/$(cat "$WORK/user.bob")/revoke-sessions" '{}' 200
admin DELETE "/users/$(cat "$WORK/user.dave")" "" 204
admin POST "/users/$(cat "$WORK/user.carol")/suspend" '{"reason":"drill: suspected compromise"}' 200
ALICE_R1=$(jq -r .refresh_token "$WORK/tokens.alice.json")
[ "$(refresh "$ALICE_R1" "$WORK/tokens.alice2.json")" = 200 ] || fail "alice's refresh on the primary: $(cat "$WORK/resp.json")"
ALICE_R2=$(jq -r .refresh_token "$WORK/tokens.alice2.json")
BOB_ACCESS=$(jq -r .access_token "$WORK/tokens.bob.json")
BOB_REFRESH=$(jq -r .refresh_token "$WORK/tokens.bob.json")
[ "$(introspect "$BOB_ACCESS")" = false ] || fail "bob's token still active after revocation on the primary"
ok "erin created before target $TARGET; frank created, bob's sessions revoked, dave deleted, carol suspended, alice's refresh token rotated after it"

op revocation-log revocation-log -since "$SINCE" -out "$WORK/revocations.jsonl"
ok "revocation log exported: $(jq -sc 'group_by(.kind) | map({(.[0].kind): length}) | add' "$WORK/revocations.jsonl")"

SEG=$(psql_in "$PRIMARY" postgres -c 'SELECT pg_walfile_name(pg_switch_wal())')
_i=0
until [ "$(psql_in "$PRIMARY" postgres -c "SELECT coalesce(last_archived_wal >= '$SEG', false) FROM pg_stat_archiver")" = t ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 60 ] || fail "WAL segment $SEG was not archived"
	sleep 0.5
done
ok "WAL archived through $SEG"

# ------------------------------------------------------------ 3. failover ---

log "3. failover: fence the primary under write load, promote the standby"
docker exec "$PRIMARY" sh -c 'while psql -X -U postgres -d drill -Atq -F " " -c "INSERT INTO heartbeat DEFAULT VALUES RETURNING id, extract(epoch FROM at)"; do :; done' \
	>"$WORK/heartbeat.acked" 2>/dev/null &
HB_PID=$!
sleep 3
REPL_STATE=$(psql_in "$PRIMARY" postgres -c "SELECT sync_state || ', replay lag ' || coalesce(replay_lag::text, '0') || ', ' || pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) || ' bytes behind' FROM pg_stat_replication WHERE application_name='pa_drill_standby'")

# Fence: the primary region is lost. identity-server and worker die with it,
# then the database is killed without a shutdown checkpoint.
T0=$(now_ms)
kill_proc "$SERVER_PID"
kill_proc "$WORKER_PID"
SERVER_PID= WORKER_PID=
docker kill "$PRIMARY" >/dev/null
wait "$HB_PID" 2>/dev/null || true
HB_PID=
if port_open "$PRIMARY_PORT" || [ "$(docker inspect -f '{{.State.Running}}' "$PRIMARY")" = true ]; then
	fail "the old primary is still reachable after fencing"
fi
ok "primary fenced (killed) at replication state: $REPL_STATE"

[ "$(psql_in "$STANDBY" postgres -c 'SELECT pg_promote(true, 60)')" = t ] || fail "promotion failed"
T_PROMOTED=$(now_ms)
[ "$(psql_in "$STANDBY" postgres -c 'SELECT pg_is_in_recovery()')" = f ] || fail "standby still in recovery"
# A promoted node that inherited synchronous_standby_names waits for a standby
# that no longer exists on every commit (statement_timeout does not end the
# wait): clear it until a new standby is attached (runbook step 2).
INHERITED_SYNC=$(psql_in "$STANDBY" postgres -c 'SHOW synchronous_standby_names')
psql_in "$STANDBY" postgres -c 'ALTER SYSTEM RESET synchronous_standby_names' -c 'SELECT pg_reload_conf()' >/dev/null
_i=0
until [ -z "$(psql_in "$STANDBY" postgres -c 'SHOW synchronous_standby_names')" ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 20 ] || fail "synchronous_standby_names not cleared on the promoted standby"
	sleep 0.1
done
RECOVERY_POINT=$(psql_in "$STANDBY" postgres -c "SELECT pg_last_xact_replay_timestamp() || ' (LSN ' || pg_last_wal_replay_lsn() || '; now on timeline ' || ('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::int || ')'")
ok "standby promoted; recovery point $RECOVERY_POINT; synchronous_standby_names '${INHERITED_SYNC}' cleared"

# Only complete "id epoch" lines count as acknowledged.
grep -E '^[0-9]+ [0-9]+(\.[0-9]+)?$' "$WORK/heartbeat.acked" >"$WORK/heartbeat.ok" || true
ACKED=$(wc -l <"$WORK/heartbeat.ok" | tr -d ' ')
LAST_ACKED=$(tail -n 1 "$WORK/heartbeat.ok")
set -- $LAST_ACKED
LAST_ACKED_ID=${1:-0} LAST_ACKED_AT=${2:-0}
set -- $(psql_in "$STANDBY" drill -F ' ' -c 'SELECT coalesce(max(id), 0), coalesce(extract(epoch FROM max(at)), 0) FROM heartbeat')
STANDBY_MAX_ID=$1 STANDBY_MAX_AT=$2
LOST=$(awk -v max="$STANDBY_MAX_ID" '$1 > max {n++} END {print n + 0}' "$WORK/heartbeat.ok")
WINDOW_MS=$(jq -n --argjson a "$LAST_ACKED_AT" --argjson b "$STANDBY_MAX_AT" 'if $a > $b then (($a - $b) * 1000 | floor) else 0 end')
[ "$ACKED" -gt 0 ] || fail "the write load acknowledged no transaction"
if [ "$SYNC" = on ] && [ "$LOST" -ne 0 ]; then
	fail "synchronous replication lost $LOST acknowledged transactions"
fi
ok "RPO: $LOST of $ACKED acknowledged write-load transactions lost (last acknowledged id $LAST_ACKED_ID, last on standby $STANDBY_MAX_ID), window ${WINDOW_MS} ms"

export PROUDAUTH_CONFIG="$WORK/config-standby.yaml"
op restore-begin-standby restore-begin
op maintenance-unavailable maintenance -mode unavailable -message "Disaster-recovery drill"
start_server standby
T_SERVER=$(now_ms)
[ "$(ready_status)" = 503 ] && jq -e '.reason == "restore_pending"' "$WORK/ready.json" >/dev/null ||
	fail "promoted standby reports ready before reconciliation: $(cat "$WORK/ready.json")"
ok "identity-server started on the promoted standby; readiness 503 restore_pending"
FP_STANDBY=$(fingerprint standby)
[ "$FP_STANDBY" = "$FP_PRIMARY" ] || fail "key fingerprint differs: primary $FP_PRIMARY, standby $FP_STANDBY"
ok "doctor: key fingerprint matches the primary's ($FP_STANDBY)"
"$BIN/identity-worker" -config "$WORK/config-standby.yaml" >"$WORK/worker-refused.log" 2>&1 &
WORKER_PID=$!
_i=0
while kill -0 "$WORKER_PID" 2>/dev/null; do
	_i=$((_i + 1))
	[ "$_i" -lt 100 ] || fail "identity-worker started on a database that is not reconciled"
	sleep 0.1
done
_rc=0
wait "$WORKER_PID" || _rc=$?
WORKER_PID=
[ "$_rc" -ne 0 ] || fail "identity-worker exited 0 on a database that is not reconciled"
ok "identity-worker refuses to start before reconciliation ($(tail -n 1 "$WORK/worker-refused.log" | jq -r '.msg // .error // empty' 2>/dev/null || tail -n 1 "$WORK/worker-refused.log"))"

op reconcile-standby restore-reconcile -log "$WORK/revocations.jsonl"
T_RECONCILED=$(now_ms)
sed -n '/^{/,/^}/p' "$WORK/reconcile-standby.out" >"$WORK/reconcile-standby.json"
jq -e '.restore_marker_cleared == true' "$WORK/reconcile-standby.json" >/dev/null || fail "reconciliation did not clear the restore marker"
ok "reconciled: $(jq -c '{applied, restore_marker_cleared}' "$WORK/reconcile-standby.json")"
wait_ready 200
ok "readiness 200 after reconciliation"
QUEUED=$(pa_sql "$STANDBY" "SELECT (SELECT count(*) FROM notification_jobs WHERE state IN ('queued','attempted')) || ' queued notifications, ' || (SELECT count(*) FROM outbox_events WHERE state='pending') || ' pending outbox events'")
ok "queued side effects reviewed: $QUEUED"
start_worker standby

code=$(api POST /auth/transactions "" '{"client_id":"drill-web"}')
[ "$code" = 503 ] || fail "maintenance mode unavailable did not refuse a sign-in: HTTP $code"
ok "maintenance unavailable refuses sign-in (503)"
op maintenance-restricted maintenance -mode restricted -message "Disaster-recovery drill"
sleep 2.2 # maintenance state is cached for up to 2 s per instance
user_login alice "$WORK/tokens.alice3.json" || fail "alice's sign-in on the promoted standby: $LOGIN_ERROR"
T1=$(now_ms)
ok "first token issued by the promoted standby, $(secs "$T0" "$T1") s after fencing"
[ "$(introspect "$(jq -r .access_token "$WORK/tokens.alice3.json")")" = true ] || fail "new token inactive"
ok "introspection: new token active"
[ "$(refresh "$ALICE_R2" "$WORK/tokens.alice4.json")" = 200 ] || fail "alice's session from the primary did not survive: $(cat "$WORK/resp.json")"
ok "alice's refresh token issued by the primary still works"
[ "$(introspect "$BOB_ACCESS")" = false ] || fail "bob's revoked session is active after failover"
code=$(refresh "$BOB_REFRESH" "$WORK/tokens.bob2.json")
[ "$code" = 400 ] || fail "bob's revoked refresh token answered $code"
ok "bob's revoked session stays revoked (introspection inactive, refresh refused)"
if user_login dave "$WORK/tokens.dave2.json"; then fail "deleted user dave signed in after failover"; fi
ok "deleted user dave cannot sign in ($LOGIN_ERROR)"
if user_login carol "$WORK/tokens.carol2.json"; then fail "suspended user carol signed in after failover"; fi
ok "suspended user carol cannot sign in ($LOGIN_ERROR)"
user_login frank "$WORK/tokens.frank.json" || fail "frank (created before the failure) cannot sign in: $LOGIN_ERROR"
ok "frank, created shortly before the failure, signs in (nothing lost)"
admin_login
admin GET "/users/$(cat "$WORK/user.dave")" "" 200
[ "$(jq -r .state "$WORK/resp.json")" = deleted ] || fail "dave is $(jq -r .state "$WORK/resp.json") after failover"
ok "administrator signs in with TOTP (MFA secrets readable with the same keys); dave is deleted"
op maintenance-off maintenance -mode off
op verify-audit-standby verify-audit
ok "verify-audit: $(jq -c '.report | {ok, batches_checked, events_checked, problems}' "$WORK/verify-audit-standby.out")"
kill_proc "$SERVER_PID"
kill_proc "$WORKER_PID"
SERVER_PID= WORKER_PID=

# ---------------------------------------------- 4. point-in-time recovery ---

log "4. point-in-time recovery to $TARGET from the base backup and the WAL archive"
P0=$(now_ms)
docker run --rm -v "$PREFIX-base:/backup:ro" -v "$PREFIX-pitr-data:$VOLDIR" "$IMAGE" sh -c "
	mkdir -p '$PGDATA' && cp -a /backup/base/. '$PGDATA/' && touch '$PGDATA/recovery.signal' &&
	chown -R postgres:postgres '$VOLDIR' && chmod 700 '$PGDATA'"
# Recovery settings on the command line; a restored cluster must not archive
# into the primary's archive (mounted read-only) and must not wait for a
# synchronous standby that the base backup's postgresql.auto.conf names.
# shellcheck disable=SC2086
docker run -d --name "$PITR" --network "$NET" -p "127.0.0.1:$PITR_PORT:5432" \
	-v "$PREFIX-pitr-data:$VOLDIR" -v "$PREFIX-archive:/archive:ro" \
	"$IMAGE" $PG_ARGS -c archive_mode=off -c "synchronous_standby_names=" \
	-c "restore_command=cp /archive/%f %p" -c "recovery_target_time=$TARGET" -c recovery_target_action=promote >/dev/null
wait_pg "$PITR"
_i=0
until [ "$(psql_in "$PITR" postgres -c 'SELECT pg_is_in_recovery()' 2>/dev/null)" = f ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 120 ] && [ "$(docker inspect -f '{{.State.Running}}' "$PITR")" = true ] || {
		docker logs --tail 30 "$PITR" >&2
		fail "point-in-time recovery did not finish"
	}
	sleep 0.5
done
STOP_LINE=$(docker logs "$PITR" 2>&1 | grep -E 'recovery stopping before' | tail -n 1 | sed 's/.*LOG: *//')
ok "recovered and promoted: ${STOP_LINE:-target reached}"

user_id() { pa_sql "$PITR" "SELECT count(*) FROM user_identifiers WHERE canonical_value='$1@drill.test'"; }
[ "$(user_id erin)" = 1 ] || fail "erin (created before the target) is missing"
[ "$(user_id frank)" = 0 ] || fail "frank (created after the target) is present"
[ "$(user_id dave)" -ge 1 ] || fail "precondition: dave should exist at the target time"
[ "$(pa_sql "$PITR" "SELECT count(*) FROM sessions WHERE user_id='$(cat "$WORK/user.bob")' AND state='active'")" -gt 0 ] ||
	fail "precondition: bob's sessions should be active at the target time"
[ "$(pa_sql "$PITR" "SELECT state FROM users WHERE id='$(cat "$WORK/user.carol")'")" = active ] ||
	fail "precondition: carol should be active at the target time"
ok "state at the target time: erin present, frank absent; dave, bob's sessions and carol active again until reconciliation"

export PROUDAUTH_CONFIG="$WORK/config-pitr.yaml"
op restore-begin-pitr restore-begin
FP_PITR=$(fingerprint pitr)
[ "$FP_PITR" = "$FP_PRIMARY" ] || fail "key fingerprint differs: primary $FP_PRIMARY, restore $FP_PITR"
ok "doctor: key fingerprint matches ($FP_PITR)"
start_server pitr
[ "$(ready_status)" = 503 ] && jq -e '.reason == "restore_pending"' "$WORK/ready.json" >/dev/null ||
	fail "restored database reports ready before reconciliation: $(cat "$WORK/ready.json")"
op reconcile-pitr restore-reconcile -log "$WORK/revocations.jsonl"
sed -n '/^{/,/^}/p' "$WORK/reconcile-pitr.out" >"$WORK/reconcile-pitr.json"
jq -e '(.applied.tombstone // 0) > 0 and (.applied.revocation // 0) > 0 and (.applied.user_state // 0) > 0 and .restore_marker_cleared == true' "$WORK/reconcile-pitr.json" >/dev/null ||
	fail "reconciliation applied too little: $(cat "$WORK/reconcile-pitr.json")"
ok "reconciled: $(jq -c '{applied, sessions_revoked, refresh_families_revoked, restore_marker_cleared}' "$WORK/reconcile-pitr.json")"
wait_ready 200
user_login alice "$WORK/tokens.alice5.json" || fail "alice's sign-in on the restored database: $LOGIN_ERROR"
P1=$(now_ms)
[ "$(introspect "$(jq -r .access_token "$WORK/tokens.alice5.json")")" = true ] || fail "new token inactive after restore"
ok "sign-in, token and introspection work on the restored database"
user_login erin "$WORK/tokens.erin.json" || fail "erin cannot sign in after restore: $LOGIN_ERROR"
if user_login frank "$WORK/tokens.frank2.json"; then fail "frank (created after the target) signed in"; fi
ok "erin signs in; frank does not exist ($LOGIN_ERROR)"
[ "$(introspect "$BOB_ACCESS")" = false ] || fail "bob's session revoked after the target is active again"
code=$(refresh "$BOB_REFRESH" "$WORK/tokens.bob3.json")
[ "$code" = 400 ] || fail "bob's refresh token revoked after the target answered $code"
ok "bob's revocation (after the target) re-applied"
if user_login dave "$WORK/tokens.dave3.json"; then fail "dave, deleted after the target, signed in"; fi
[ "$(user_id dave)" = 0 ] || fail "dave's identifiers are back"
ok "dave's deletion (after the target) re-applied ($LOGIN_ERROR)"
if user_login carol "$WORK/tokens.carol3.json"; then fail "carol, suspended after the target, signed in"; fi
ok "carol's suspension (after the target) re-applied ($LOGIN_ERROR)"
code=$(refresh "$ALICE_R1" "$WORK/tokens.alice6.json")
[ "$code" = 400 ] || fail "alice's refresh token rotated after the target was accepted again ($code)"
ok "alice's refresh-token rotation (after the target) re-applied"
op verify-audit-pitr verify-audit
ok "verify-audit: $(jq -c '.report | {ok, batches_checked, events_checked, problems}' "$WORK/verify-audit-pitr.out")"
kill_proc "$SERVER_PID"
SERVER_PID=

# ---------------------------------------------------------------- report ---

cat <<EOF

DR drill passed ($PG_VERSION_STR, replication $( [ "$SYNC" = on ] && echo synchronous || echo asynchronous ))
  Failover (DEP-019)
    replication at fencing   $REPL_STATE
    recovery point           $RECOVERY_POINT
    RPO                      $LOST of $ACKED acknowledged transactions lost under write load (window ${WINDOW_MS} ms)
    RTO                      $(secs "$T0" "$T1") s from fencing to the first token
                             (promotion $(secs "$T0" "$T_PROMOTED") s, server up $(secs "$T0" "$T_SERVER") s, reconciled $(secs "$T0" "$T_RECONCILED") s)
  Point-in-time recovery (OPS-007)
    target                   $TARGET
    stopped                  ${STOP_LINE:-at the target}
    restore to first token   $(secs "$P0" "$P1") s (base backup copy, WAL replay, reconciliation, first sign-in)
EOF
