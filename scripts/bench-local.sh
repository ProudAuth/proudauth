#!/bin/sh
# Reference benchmark on one machine (NFR-003 workload suite, NFR-004
# cardinality, NFR-005 sustained runs, NFR-006 adversarial resource use,
# NFR-007 consistency stress, NFR-008 portable results), following
# docs/operations/benchmarks.md ("Before you start", "Reproducing with
# make bench", "Reference results").
#
# What it does, with one throwaway PostgreSQL container and the ProudAuth
# binaries built from this checkout and run on the host:
#
#   1. PostgreSQL (default postgres:18) with the settings below, recorded in
#      the results with the server version.
#   2. identity-server and identity-worker with production defaults except
#      what a single-host run needs: development mode (plain-HTTP origin on
#      127.0.0.1 and the development mail sink, which the first administrator
#      sign-in needs for email verification), the per-IP, per-realm and
#      per-client budgets raised for one load source (benchmarks.md), and
#      keys.prepublish_period 2m so that a signing-key rotation started during
#      the soak run activates inside it. migrate, realm-create bench,
#      bootstrap, and the administrator's first sign-in through the headless
#      API (password, email verification, TOTP enrollment); the
#      administrator's access and refresh tokens go to an identity-cli
#      credentials file that identity-bench refreshes
#      (PROUDAUTH_BENCH_ADMIN_CREDENTIALS).
#   3. identity-bench seed with the make bench sizes (10000 users, 500
#      organizations, a 5000-member organization, 20 machine clients, a
#      1000-member group); every workload scenario, import, the adversarial
#      scenarios and refresh-race for BENCH_DURATION at BENCH_CONCURRENCY;
#      email-delivery/mixed-email additionally use the actual SMTP adapter
#      with a loopback-only acceptance sink after administrator bootstrap;
#      webhook-delivery/webhook-retry prove signed callbacks and real retries;
#      mixed-delivery combines both receivers with the other workloads.
#      otp-guess owns a new TOTP account and verifies its unchanged subject
#      and transaction budgets against post-run database/audit counts.
#      metadata-fetch uses a counts-only HTTPS source with an ephemeral CA,
#      valid/bad JWKS responses and a live IPv6 egress-denial control; keys
#      and assertions remain private, fetch budgets stay unchanged.
#      Then a soak run of BENCH_SOAK_SCENARIO (mixed by default;
#      BENCH_SOAK, windows of BENCH_SOAK_WINDOW)
#      during which a planned signing-key rotation, VACUUM (ANALYZE) and a
#      pg_dump are scheduled and their times recorded.
#   4. Per scenario: the result JSON, the pass criteria of benchmarks.md, CPU
#      time of identity-server, identity-worker, PostgreSQL and identity-bench,
#      and PostgreSQL's top statements. Results go to BENCH_OUT; the seed file
#      (client secrets) and the administrator credentials stay in a temporary
#      directory that is removed at the end, and the results are checked for
#      them before the script reports success.
#
# The load generator, the server and the database share one machine: the
# numbers describe that machine and this configuration, not a sizing
# recommendation. Exit status 1 when setup fails, a run fails to complete or
# a scenario misses its pass criteria (the results are kept either way).
#
# Requirements: docker, go, curl, jq, python3 (TOTP and PKCE); the PostgreSQL
# image must be present locally (nothing is downloaded). Environment
# overrides:
#   BENCH_PG_IMAGE (postgres:18), BENCH_PREFIX (container/volume prefix,
#   pa-bench-<pid>), BENCH_PG_PORT (55591), BENCH_HTTP_PORT / BENCH_INTERNAL_PORT /
#   BENCH_WORKER_PORT (18591 / 18592 / 18593), BENCH_PG_SHARED_BUFFERS (2GB),
#   BENCH_PG_MAX_CONNECTIONS (200), BENCH_CONCURRENCY (32), BENCH_DURATION
#   (60s), BENCH_WARMUP (5s), BENCH_SOAK (10m; 0 skips the soak run),
#   BENCH_SOAK_WINDOW (1m), BENCH_SEED (dataset seed, 1), BENCH_USERS (10000),
#   BENCH_SOAK_SCENARIO (mixed; mixed-delivery includes controlled retries),
#   BENCH_ORGS (500), BENCH_LARGE (5000), BENCH_CLIENTS (20),
#   BENCH_GROUP_MEMBERS (1000), BENCH_SCENARIOS (space-separated subset, in
#   the order given), BENCH_LOGIN_PER_IP / BENCH_LOGIN_PER_REALM /
#   BENCH_TOKEN_PER_CLIENT / BENCH_LOGIN_PER_CLIENT (raised budgets,
#   1000000 each), BENCH_OUT (results directory, default
#   bench-results/<UTC time> in the checkout), BENCH_HOST_LABEL (replaces the
#   load generator's host name in the results), BENCH_BIN (directory with
#   prebuilt identity-server, identity-worker, identity-cli and
#   identity-bench), BENCH_KEEP=1 (keep the work directory, container and
#   volume).
# BENCH_SERVER_REPLICAS (1; 1..4) starts independent host server processes.
# With more than one, extra backend ports are allocated automatically and a
# loopback identity-bench replica-proxy routes per request without failover.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${BENCH_PG_IMAGE:-postgres:18}
PREFIX=${BENCH_PREFIX:-pa-bench-$$}
PG_PORT=${BENCH_PG_PORT:-55591}
HTTP_PORT=${BENCH_HTTP_PORT:-18591}
INTERNAL_PORT=${BENCH_INTERNAL_PORT:-18592}
WORKER_PORT=${BENCH_WORKER_PORT:-18593}
REPLICAS=${BENCH_SERVER_REPLICAS:-1}
PG_SHARED_BUFFERS=${BENCH_PG_SHARED_BUFFERS:-2GB}
PG_MAX_CONNECTIONS=${BENCH_PG_MAX_CONNECTIONS:-200}
CONCURRENCY=${BENCH_CONCURRENCY:-32}
DURATION=${BENCH_DURATION:-60s}
WARMUP=${BENCH_WARMUP:-5s}
SOAK=${BENCH_SOAK:-10m}
SOAK_WINDOW=${BENCH_SOAK_WINDOW:-1m}
SOAK_SCENARIO=${BENCH_SOAK_SCENARIO:-mixed}
DATA_SEED=${BENCH_SEED:-1}
USERS=${BENCH_USERS:-10000}
ORGS=${BENCH_ORGS:-500}
LARGE=${BENCH_LARGE:-5000}
CLIENTS=${BENCH_CLIENTS:-20}
GROUP_MEMBERS=${BENCH_GROUP_MEMBERS:-1000}
SCENARIOS=${BENCH_SCENARIOS:-client-credentials introspection password-login passkey-assertion refresh policy audit-query scim email-delivery webhook-delivery webhook-retry mixed mixed-extended mixed-email mixed-delivery import unknown-key failed-password otp-guess complex-filter complex-group-filter complex-audit-filter metadata-fetch oversized-input notification-flood refresh-race}
SELECTED_SCENARIOS=$SCENARIOS
if [ "$SOAK" != 0 ]; then SELECTED_SCENARIOS="$SELECTED_SCENARIOS $SOAK_SCENARIO"; fi
WEBHOOK_EGRESS=
case " $SELECTED_SCENARIOS " in
*" webhook-delivery "*|*" webhook-retry "*|*" mixed-delivery "*) WEBHOOK_EGRESS='  egress_allowlist: ["127.0.0.1/32"]' ;;
esac
LOGIN_PER_IP=${BENCH_LOGIN_PER_IP:-1000000}
LOGIN_PER_REALM=${BENCH_LOGIN_PER_REALM:-1000000}
TOKEN_PER_CLIENT=${BENCH_TOKEN_PER_CLIENT:-1000000}
LOGIN_PER_CLIENT=${BENCH_LOGIN_PER_CLIENT:-1000000}
OUT=${BENCH_OUT:-$ROOT/bench-results/$(date -u +%Y%m%dT%H%M%SZ)}
HOST_LABEL=${BENCH_HOST_LABEL:-}
KEEP=${BENCH_KEEP:-0}
REALM=bench

PG=$PREFIX-pg
PG_VOLUME=$PREFIX-pgdata
ORIGIN=http://127.0.0.1:$HTTP_PORT
ISSUER=$ORIGIN/realms/$REALM
API=$ORIGIN/api/v1/realms/$REALM
INTERNAL=http://127.0.0.1:$INTERNAL_PORT

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pa-bench.XXXXXX")
SERVER_PID=
SERVER_PIDS=
PROXY_PID=
WORKER_PID=
SMTP_PID=
SMTP_PORT=
METADATA_PID=
METADATA_PORT=
METADATA_CONFIG=
EVENTS_PID=
FAILED=0
PG_CREATED=0
VOLUME_CREATED=0

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() {
	printf '\nBENCH FAILED: %s\n' "$*" >&2
	exit 1
}

kill_proc() {
	if [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; then
		kill "$1" 2>/dev/null || true
		wait "$1" 2>/dev/null || true
	fi
}

docker_cleanup() {
	[ "$PG_CREATED" = 0 ] || docker rm -f "$PG" >/dev/null 2>&1 || true
	[ "$VOLUME_CREATED" = 0 ] || docker volume rm "$PG_VOLUME" >/dev/null 2>&1 || true
}

stop_servers() {
	for _stop_pid in $SERVER_PIDS; do kill_proc "$_stop_pid"; done
	SERVER_PID= SERVER_PIDS=
}

start_servers() {
	: >"$WORK/server-pids.tsv"
	while read -r _node _public _internal; do
		awk -v pub="$_public" -v internal="$_internal" '
		$1=="public_listen:" {print "  public_listen: \"127.0.0.1:" pub "\""; next}
		$1=="internal_listen:" {print "  internal_listen: \"127.0.0.1:" internal "\""; next}
		{print}' "$WORK/config.yaml" >"$WORK/config-node-$_node.yaml"
		if [ "$_node" = 1 ]; then _server_log=$WORK/server.log; else _server_log=$WORK/server-node-$_node.log; fi
		"$BIN/identity-server" -config "$WORK/config-node-$_node.yaml" >>"$_server_log" 2>&1 &
		_node_pid=$!
		SERVER_PIDS="$SERVER_PIDS $_node_pid"
		[ "$_node" != 1 ] || SERVER_PID=$_node_pid
		printf '%s\t%s\n' "$_node" "$_node_pid" >>"$WORK/server-pids.tsv"
		sed "s|$WORK|\$WORK|g" "$WORK/config-node-$_node.yaml" >"$OUT/proudauth-config-node-$_node.yaml"
	done <"$WORK/node-ports.tsv"
	while read -r _node _public _internal; do
		_ready=0
		until [ "$(curl -s -o /dev/null -w '%{http_code}' -H "Host: 127.0.0.1:$HTTP_PORT" "http://127.0.0.1:$_public/health/ready")" = 200 ]; do
			_ready=$((_ready+1))
			[ "$_ready" -lt 200 ] || fail "server node $_node did not become ready"
			for _node_pid in $SERVER_PIDS; do kill -0 "$_node_pid" 2>/dev/null || fail "server node process exited"; done
			sleep 0.1
		done
	done <"$WORK/node-ports.tsv"
}

cleanup() {
	status=$?
	trap - 0 INT TERM
	kill_proc "$EVENTS_PID"
	kill_proc "$PROXY_PID"
	stop_servers
	kill_proc "$WORKER_PID"
	kill_proc "$SMTP_PID"
	kill_proc "$METADATA_PID"
	if [ "$status" -ne 0 ]; then
		for f in "$WORK"/server.log "$WORK"/server-node-*.log "$WORK"/worker.log "$WORK"/*.err; do
			[ -f "$f" ] || continue
			printf '\n--- last lines of %s ---\n' "$(basename "$f")" >&2
			tail -n 6 "$f" | cut -c1-400 >&2 || true
		done
	fi
	if [ "$KEEP" = 1 ]; then
		log "BENCH_KEEP=1: kept $WORK, container $PG and volume $PG_VOLUME"
	else
		docker_cleanup
		rm -rf "$WORK"
	fi
	exit "$status"
}
trap cleanup 0
trap 'exit 130' INT TERM

for tool in docker go curl jq python3; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
case $REPLICAS in 1|2|3|4) ;; *) fail "BENCH_SERVER_REPLICAS must be 1..4" ;; esac
port_open() { # PORT: something accepts TCP connections on 127.0.0.1:PORT
	_rc=0
	curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$1/" 2>/dev/null || _rc=$?
	[ "$_rc" -ne 7 ]
}
docker info >/dev/null 2>&1 || fail "docker is not reachable"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "image $IMAGE is not present locally; this runner never downloads images"
case $PREFIX in pa-bench-*) ;; *) fail "BENCH_PREFIX must start with pa-bench-" ;; esac
if docker container inspect "$PG" >/dev/null 2>&1 || docker volume inspect "$PG_VOLUME" >/dev/null 2>&1; then
	fail "container or volume for $PREFIX already exists; choose another BENCH_PREFIX (existing resources are never removed)"
fi
for port in "$PG_PORT" "$HTTP_PORT" "$INTERNAL_PORT" "$WORKER_PORT"; do
	if port_open "$port"; then
		fail "port $port is in use (set BENCH_PG_PORT, BENCH_HTTP_PORT, BENCH_INTERNAL_PORT or BENCH_WORKER_PORT)"
	fi
done
python3 - "$REPLICAS" "$HTTP_PORT" "$INTERNAL_PORT" "$PG_PORT" "$WORKER_PORT" >"$WORK/node-ports.tsv" <<'PY'
import socket,sys
n,http,internal,pg,worker=map(int,sys.argv[1:])
reserved={http,internal,pg,worker}; sockets=[]
def free():
    while True:
        s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        if port in reserved: s.close();continue
        reserved.add(port);sockets.append(s);return port
for node in range(1,n+1):
    print(node,http if n==1 else free(),internal if node==1 else free(),sep='\t')
for s in sockets:s.close()
PY
PRIMARY_PUBLIC_PORT=$(awk '$1==1 {print $2}' "$WORK/node-ports.tsv")
for port in $(awk '{print $2; print $3}' "$WORK/node-ports.tsv"); do
	if port_open "$port"; then fail "allocated server port $port is in use"; fi
done
[ ! -e "$OUT" ] || fail "results directory $OUT already exists; choose a fresh BENCH_OUT"
mkdir -p "$OUT/postgres"
# Cached toolchain and modules only; a missing dependency fails the build.
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local

# ---------------------------------------------------------------- helpers ---

psql_pg() { # DB SQL...: psql as the superuser inside the container
	_db=$1
	shift
	for _psql_arg in "$@"; do
		case $_psql_arg in
		-c|--command|--command=*)
			docker exec "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$_db" -Atq "$@"
			return
			;;
		esac
	done
	docker exec -i "$PG" psql -X -v ON_ERROR_STOP=1 -U postgres -d "$_db" -Atq "$@"
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

api() { # METHOD PATH [BEARER] [JSON]: body to $WORK/resp.json, prints the status
	_m=$1 _p=$2 _t=${3:-} _b=${4:-}
	set -- -sS -o "$WORK/resp.json" -w '%{http_code}' -X "$_m" "$API$_p"
	if [ -n "$_t" ]; then set -- "$@" -H "Authorization: Bearer $_t"; fi
	if [ -n "$_b" ]; then set -- "$@" -H 'Content-Type: application/json' --data "$_b"; fi
	curl "$@"
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
		if [ -n "$_code" ]; then
			echo "$_code"
			return 0
		fi
		_i=$((_i + 1))
		sleep 0.5
	done
	return 1
}

# admin_login OUT: headless authorization code + PKCE sign-in of the
# administrator with the CLI client (the path identity-cli login takes):
# password, then email verification and TOTP enrollment the first time, TOTP
# afterwards. Tokens go to OUT.
admin_login() {
	LOGIN_ERROR=
	set -- "$1" $(pkce)
	_out=$1 _verifier=$2 _challenge=$3
	_code=$(api POST /auth/transactions "" "$(jq -nc --arg ch "$_challenge" --arg res "$ISSUER/admin" \
		'{client_id:"proudauth-cli", redirect_uri:"http://127.0.0.1/callback", scope:"proudauth:admin", resource:[$res], code_challenge:$ch, code_challenge_method:"S256", state:"bench"}')")
	[ "$_code" = 201 ] || fail "administrator sign-in start: HTTP $_code $(cat "$WORK/resp.json")"
	TX_ID=$(jq -r .transaction_id "$WORK/resp.json")
	TX_CONT=$(jq -r .continuation_token "$WORK/resp.json")
	jq .state "$WORK/resp.json" >"$WORK/state.json"
	_n=0 _redir=
	while [ "$_n" -lt 20 ]; do
		_n=$((_n + 1))
		_redir=$(jq -r '.redirect_to // empty' "$WORK/state.json")
		[ -z "$_redir" ] || break
		[ "$(jq -r .status "$WORK/state.json")" = pending ] || fail "administrator sign-in ended: $(jq -c '{status, error}' "$WORK/state.json")"
		_types=" $(jq -r '[.next_actions[]?.type] | join(" ")' "$WORK/state.json") "
		case $_types in
		*" identify "*) tx_step identify '{"identifier":"bench-admin"}' ;;
		*" password "*) tx_step password "$(jq -nc --arg p "$ADMIN_PW" '{password:$p}')" ;;
		*" verify_email "*)
			tx_step otp/send '{"purpose":"verify_email"}' || fail "administrator sign-in: $LOGIN_ERROR"
			_otp=$(mailbox_code admin@bench.test) || fail "no verification email in the development sink"
			tx_step otp/verify "$(jq -nc --arg c "$_otp" '{code:$c}')"
			;;
		*" enroll_totp "*)
			tx_step totp/enroll '{}' || fail "administrator sign-in: $LOGIN_ERROR"
			jq -r '.one_time.totp.secret' "$WORK/state.json" >"$WORK/totp.secret"
			tx_step totp/activate "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')"
			;;
		*" totp "*) tx_step totp "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')" ;;
		*" accept_terms "*) tx_step terms "$(jq -c '{version: .next_actions[0].options.version}' "$WORK/state.json")" ;;
		*" consent "*) tx_step consent '{"approve":true}' ;;
		*) fail "administrator sign-in: unhandled step(s):$_types" ;;
		esac || fail "administrator sign-in: $LOGIN_ERROR"
	done
	[ -n "$_redir" ] || fail "administrator sign-in: too many steps"
	_authz=$(printf '%s' "$_redir" | sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')
	_code=$(curl -sS -o "$WORK/resp.json" -w '%{http_code}' "$ISSUER/oauth/token" -d grant_type=authorization_code \
		--data-urlencode "code=$_authz" -d client_id=proudauth-cli --data-urlencode "code_verifier=$_verifier" \
		--data-urlencode "redirect_uri=http://127.0.0.1/callback" --data-urlencode "resource=$ISSUER/admin")
	[ "$_code" = 200 ] || fail "administrator token exchange: HTTP $_code $(cat "$WORK/resp.json")"
	cp "$WORK/resp.json" "$_out"
}

# write_credentials TOKENS: the administrator's tokens as an identity-cli
# credentials file, which identity-bench refreshes and rewrites.
write_credentials() {
	(
		umask 077
		jq --arg url "$ORIGIN" --arg realm "$REALM" \
			'{url:$url, realm:$realm, audience:"admin", access_token, refresh_token, expiry:((now + .expires_in) | floor | todate)}' \
			"$1" >"$WORK/admin-credentials.json"
	)
	jq -e '.refresh_token | length > 0' "$WORK/admin-credentials.json" >/dev/null || fail "the administrator sign-in issued no refresh token"
}

# cputime PID: CPU seconds (user + system) of a running process, from ps
# ([[DD-]HH:]MM:SS[.ss]); 0 if it is gone.
cputime() {
	ps -o time= -p "$1" 2>/dev/null | awk '{
		n = split($1, d, "-"); days = (n == 2) ? d[1] : 0; t = d[n]
		k = split(t, p, ":"); s = 0
		for (i = 1; i <= k; i++) s = s * 60 + p[i]
		printf "%.2f\n", days * 86400 + s
	}' | grep . || echo 0
}

server_cpu() {
	for _cpu_pid in $SERVER_PIDS; do cputime "$_cpu_pid"; done | awk '{s+=$1} END {printf "%.2f\n",s}'
}

server_cpu_nodes() {
	while read -r _cpu_node _cpu_pid; do
		jq -nc --argjson node "$_cpu_node" --argjson pid "$_cpu_pid" --argjson cpu "$(cputime "$_cpu_pid")" '{node:$node,pid:$pid,cpu_seconds:$cpu}'
	done <"$WORK/server-pids.tsv" | jq -s .
}

# pg_cpu: CPU seconds used by the PostgreSQL container (cgroup v2 cpu.stat).
pg_cpu() {
	docker exec "$PG" cat /sys/fs/cgroup/cpu.stat 2>/dev/null | awk '$1 == "usage_usec" {printf "%.2f\n", $2 / 1e6}' | grep . || echo 0
}

# vm_cpu: on macOS, CPU seconds of Docker Desktop's virtual machine and its
# host-side network proxy (the database's CPU plus virtualization and port
# forwarding overhead); 0 elsewhere.
vm_cpu() {
	ps -A -o time=,comm= 2>/dev/null | awk '/com\.apple\.Virtualization\.VirtualMachine|com\.docker\.backend/ {
		n = split($1, d, "-"); days = (n == 2) ? d[1] : 0; t = d[n]
		k = split(t, p, ":"); s = 0
		for (i = 1; i <= k; i++) s = s * 60 + p[i]
		sum += days * 86400 + s
	} END {printf "%.2f\n", sum}'
}

delta() { jq -n --argjson a "$1" --argjson b "$2" '($b - $a) * 100 | round / 100'; }

# verdict SCENARIO OUTCOMES-JSON: the pass criteria of benchmarks.md.
verdict() {
	printf '%s' "$2" | jq -r --arg s "$1" '
		. as $o | (keys) as $k |
		(if $s == "mixed" or $s == "mixed-extended" or $s == "mixed-email" or $s == "mixed-delivery" then ($k | length) > 0 and all($k[]; endswith(":ok"))
		elif $s == "unknown-key" then ($o.ok // 0) > 0 and ($o.invariant_violation // 0) == 0
		elif $s == "failed-password" then ($o.invariant_violation // 0) == 0 and ($o.http_401 // 0) > 0
			and any($k[]; endswith("http_429")) and all($k[]; . == "http_401" or endswith("http_429"))
		elif $s == "otp-guess" then ($o.invalid_proof // 0) == 10 and ($o.rate_limited // 0) > 0
			and all($k[]; . == "invalid_proof" or . == "rate_limited" or . == "transaction_limit")
		elif $s == "complex-filter" or $s == "complex-group-filter" then ($o.bounded_true // 0)>0 and ($o.bounded_false // 0)>0 and ($o.invalid_filter_nodes // 0)>0 and ($o.invalid_filter_bytes // 0)>0
			and all($k[]; .=="bounded_true" or .=="bounded_false" or .=="invalid_filter_nodes" or .=="invalid_filter_bytes" or .=="rate_limited")
		elif $s == "complex-audit-filter" then $k == ["compound_empty","compound_match","cursor_page","cursor_scope_rejected","invalid_network","invalid_time","literal_prefix_empty"] and all($o[]; .>0)
		elif $s == "metadata-fetch" then $k == ["http_failure_rejected","malformed_rejected","oversized_rejected","private_rejected","redirect_rejected","timeout_rejected","unknown_key_rejected","valid:ok"] and all($o[]; .>0)
		elif $s == "oversized-input" then $k == ["http_413"]
		elif $s == "notification-flood" then ($o.http_429 // 0) > 0
		else $k == ["ok"] end) | if . then "pass" else "FAIL" end'
}

# Verify the independent callback receiver, including completed cycles at a
# soak boundary. Its counters are cumulative; metadata contains no secrets.
receiver_verdict() {
	python3 - "$1" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
ok=True
for r in data.get('windows',[data]):
    if r['scenario']=='metadata-fetch':
        obs=r.get('observations',{})
        ok=ok and obs.get('before',{}).get('receiver_valid',False) and obs.get('after',{}).get('receiver_valid',False)
    names=['webhook-delivery','webhook-retry'] if r['scenario']=='mixed-delivery' else ([r['scenario']] if r['scenario'].startswith('webhook-') else [])
    for name in names:
        obs=r.get('observations',{})
        before=obs.get('before',{}); after=obs.get('after',{})
        if r['scenario']=='mixed-delivery': before=before.get(name,{});after=after.get(name,{})
        b=before.get('cumulative',{});a=after.get('cumulative',{})
        n=r['outcomes'].get(name+':ok',0) if r['scenario']=='mixed-delivery' else r['outcomes'].get('ok',0)
        ok=ok and a.get('invalid',1)==0 and a.get('accepted',0)-b.get('accepted',0)>=2*n
        if name=='webhook-retry':
            ok=ok and a.get('intentional_503',0)-b.get('intentional_503',0)>=2*n and a.get('recovered',0)-b.get('recovered',0)>=2*n
print('pass' if ok else 'FAIL')
PY
}

label_host() { # FILE: replace the load generator's host name (BENCH_HOST_LABEL)
	[ -n "$HOST_LABEL" ] || return 0
	jq --arg h "$HOST_LABEL" 'if .soak then .windows |= map(.environment.host = $h) else .environment.host = $h end' "$1" >"$1.tmp"
	mv "$1.tmp" "$1"
}

pg_top() { # FILE: the statements with the most total execution time since the last reset
	psql_pg postgres -F '	' -c "SELECT calls, round(total_exec_time::numeric, 1), round(mean_exec_time::numeric, 3), rows,
		left(regexp_replace(query, '\\s+', ' ', 'g'), 200)
		FROM pg_stat_statements WHERE dbid = (SELECT oid FROM pg_database WHERE datname = 'proudauth')
		ORDER BY total_exec_time DESC LIMIT 12" >"$1.tmp" || true
	{
		printf 'calls\ttotal_ms\tmean_ms\trows\tquery\n'
		cat "$1.tmp"
	} >"$1"
	rm -f "$1.tmp"
}

bench() { # identity-bench with the administrator credentials file
	PROUDAUTH_BENCH_ADMIN_CREDENTIALS="$WORK/admin-credentials.json" \
		PROUDAUTH_BENCH_ADMIN_TOKEN="$(jq -r .access_token "$WORK/admin-credentials.json")" \
		"$BIN/identity-bench" "$@"
}

# run_scenario NAME OUT-FILE [identity-bench run flags]: one measured run with
# CPU accounting and PostgreSQL statement statistics; appends to the summary.
run_scenario() {
	_s=$1 _f=$2
	shift 2
	log "scenario $_s ($*)"
	if [ -n "$PROXY_PID" ] && [ "$_s" = refresh-race ]; then
		psql_pg proudauth -v "web=$(jq -r .web_client.client_id "$WORK/seed.json")" <<'SQL' >"$WORK/race-families-before.json"
SELECT coalesce(jsonb_agg(f.id),'[]') FROM refresh_families f JOIN clients c ON c.id=f.client_ref
JOIN realms r ON r.id=f.realm_id WHERE r.name='bench' AND c.client_id=:'web';
SQL
	fi
	psql_pg postgres -c 'SELECT pg_stat_statements_reset()' >/dev/null
	_srv0=$(server_cpu) _wrk0=$(cputime "$WORKER_PID") _pg0=$(pg_cpu) _vm0=$(vm_cpu)
	if [ -n "$PROXY_PID" ]; then
		_proxy0=$(cputime "$PROXY_PID")
		server_cpu_nodes >"$WORK/server-cpu-before.json"
		curl -fsS "$ORIGIN/_pa_bench_proxy/stats" >"$WORK/proxy-before.json" || fail "cannot observe replica routing"
	fi
	_smtp0=0
	_metadata0=0
	if [ -n "$METADATA_PID" ]; then _metadata0=$(cputime "$METADATA_PID"); fi
	if [ -n "$SMTP_PID" ]; then
		_smtp0=$(cputime "$SMTP_PID")
		cp "$OUT/smtp-sink.json" "$WORK/smtp-before.json"
	fi
	_t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	_rc=0
	PROUDAUTH_BENCH_ADMIN_CREDENTIALS="$WORK/admin-credentials.json" \
		PROUDAUTH_BENCH_ADMIN_TOKEN="$(jq -r .access_token "$WORK/admin-credentials.json")" \
		/usr/bin/time -p "$BIN/identity-bench" run --url "$ORIGIN" --seed-file "$WORK/seed.json" --scenario "$_s" \
		--concurrency "$CONCURRENCY" --warmup "$WARMUP" --out "$_f" "$@" 2>"$WORK/run-$_s.err" || _rc=$?
	_t1=$(date -u +%Y-%m-%dT%H:%M:%SZ)
	_srv1=$(server_cpu) _wrk1=$(cputime "$WORKER_PID") _pg1=$(pg_cpu) _vm1=$(vm_cpu)
	_wall=$(awk '$1 == "real" {v = $2} END {print v + 0}' "$WORK/run-$_s.err")
	_bcpu=$(awk '$1 == "user" || $1 == "sys" {v += $2} END {printf "%.2f\n", v}' "$WORK/run-$_s.err")
	pg_top "$OUT/postgres/$(basename "$_f" .json)-top-statements.tsv"
	grep -v -E '^(real|user|sys) ' "$WORK/run-$_s.err" | sed 's/^/    /' || true
	_cpu=$(jq -nc --argjson wall "$_wall" --argjson srv "$(delta "$_srv0" "$_srv1")" --argjson wrk "$(delta "$_wrk0" "$_wrk1")" \
		--argjson pg "$(delta "$_pg0" "$_pg1")" --argjson vm "$(delta "$_vm0" "$_vm1")" --argjson bench "$_bcpu" \
		'{wall_s:$wall, identity_server:$srv, identity_worker:$wrk, postgres_container:$pg, docker_vm_and_proxy:$vm, identity_bench:$bench}')
	if [ -n "$PROXY_PID" ]; then
		server_cpu_nodes >"$WORK/server-cpu-after.json"
		_cpu=$(printf '%s' "$_cpu" | jq --argjson proxy "$(delta "$_proxy0" "$(cputime "$PROXY_PID")")" \
			--slurpfile before "$WORK/server-cpu-before.json" --slurpfile after "$WORK/server-cpu-after.json" '
			. + {replica_proxy:$proxy,server_nodes:[range(0;($after[0]|length)) as $i |
			{node:$after[0][$i].node,pid:$after[0][$i].pid,cpu_seconds:(($after[0][$i].cpu_seconds-$before[0][$i].cpu_seconds)*100|round/100)}]}')
		curl -fsS "$ORIGIN/_pa_bench_proxy/stats" >"$WORK/proxy-after.json" || fail "cannot observe completed replica routing"
		jq -nc --arg scenario "$_s" --slurpfile before "$WORK/proxy-before.json" --slurpfile after "$WORK/proxy-after.json" '
			{scenario:$scenario,before:$before[0],after:$after[0],
			deltas:[range(0;($after[0].backends|length)) as $i | {node:($i+1),
			requests:($after[0].backends[$i].assigned_requests-$before[0].backends[$i].assigned_requests),
			transport_errors:($after[0].backends[$i].transport_errors-$before[0].backends[$i].transport_errors),
			response_aborts:($after[0].backends[$i].response_aborts-$before[0].backends[$i].response_aborts),
			client_cancellations:($after[0].backends[$i].client_cancellations-$before[0].backends[$i].client_cancellations)}],
			note:"routing counts include scenario preparation/warm-up and measured HTTP requests; one benchmark operation can span several requests; no paths, headers or bodies are retained"}
			| . + {pass:(all(.deltas[]; .requests>0 and .transport_errors==0 and .response_aborts==0))}' >>"$WORK/replica-routing.jsonl"
		if ! tail -n 1 "$WORK/replica-routing.jsonl" | jq -e '.pass and (.deltas|length)>1' >/dev/null; then
			FAILED=1
			log "  $_s: independent replica routing did not pass"
		fi
	fi
	if [ -n "$PROXY_PID" ] && [ "$_s" = refresh-race ] && [ -s "$_f" ]; then
		psql_pg proudauth -v "web=$(jq -r .web_client.client_id "$WORK/seed.json")" -v "before=$(cat "$WORK/race-families-before.json")" <<'SQL' >"$WORK/refresh-race-database.json"
WITH owned AS (
 SELECT f.*,g.state AS grant_state,g.offline,s.state AS session_state,
 (SELECT count(*) FROM refresh_tokens t WHERE t.family_id=f.id) AS tokens,
 (SELECT count(*) FROM refresh_tokens t WHERE t.family_id=f.id AND t.revoked_at IS NOT NULL) AS revoked_tokens,
 (SELECT count(*) FROM audit_events a WHERE a.realm_id=f.realm_id AND a.grant_id=f.grant_id AND a.type='token.refresh.reuse_detected') AS audits,
 (SELECT count(*) FROM outbox_events o WHERE o.realm_id=f.realm_id AND o.aggregate_id=f.grant_id AND o.event_type='security.refresh_reuse_detected') AS events,
 (SELECT count(*) FROM refresh_tokens t LEFT JOIN refresh_tokens p ON p.id=t.parent_id WHERE t.family_id=f.id AND
   ((t.generation=1 AND t.parent_id IS NOT NULL) OR (t.generation<>1 AND
    (t.generation<>2 OR p.family_id IS DISTINCT FROM f.id OR p.generation IS DISTINCT FROM 1 OR p.consumed_at IS NULL)))) AS bad_lineage
 FROM refresh_families f JOIN authorization_grants g ON g.id=f.grant_id JOIN sessions s ON s.id=g.session_id
 JOIN clients c ON c.id=f.client_ref JOIN realms r ON r.id=f.realm_id
 WHERE r.name='bench' AND c.client_id=:'web' AND NOT(f.id IN(SELECT jsonb_array_elements_text(:'before'::jsonb)))
)
SELECT json_build_object('observed_families',count(*),'compromised_families',count(*) FILTER(WHERE state='compromised'),
 'active_families',count(*) FILTER(WHERE state='active'),'offline_families',count(*) FILTER(WHERE offline),
 'retained_offline_sessions',count(*) FILTER(WHERE offline AND session_state='active'),'max_generation',coalesce(max(current_generation),0),
 'max_tokens_per_family',coalesce(max(tokens),0),'reuse_audits',coalesce(sum(audits),0),'reuse_outbox_events',coalesce(sum(events),0),
 'lineage_violations',count(*) FILTER(WHERE bad_lineage<>0 OR tokens<>current_generation),
 'compromise_violations',count(*) FILTER(WHERE state='compromised' AND
   (current_generation<>2 OR tokens<>2 OR revoked_tokens<>2 OR grant_state<>'revoked'
    OR (NOT offline AND session_state<>'revoked') OR (offline AND session_state<>'active') OR audits<>1 OR events<>1))) FROM owned;
SQL
		jq --slurpfile result "$_f" '. + {completed_measured_races:$result[0].operations,
			pass:(.observed_families >= $result[0].operations and .compromised_families >= $result[0].operations
			and .max_generation<=2 and .max_tokens_per_family<=2 and .lineage_violations==0 and .compromise_violations==0
			and .reuse_audits==.compromised_families and .reuse_outbox_events==.compromised_families),
			note:"counts cover this scenario only by excluding a private pre-run family-ID snapshot; setup/warm-up/interrupted operations may add families beyond completed measured races; no tokens, digests or IDs are published"}' \
			"$WORK/refresh-race-database.json" >"$OUT/refresh-race-database.json"
		if ! jq -e .pass "$OUT/refresh-race-database.json" >/dev/null; then FAILED=1; log "  FAIL: refresh lineage or compromise evidence disagrees"; fi
	fi
	if [ -n "$SMTP_PID" ]; then
		_cpu=$(printf '%s' "$_cpu" | jq --argjson smtp "$(delta "$_smtp0" "$(cputime "$SMTP_PID")")" '. + {smtp_sink:$smtp}')
	fi
	if [ -n "$METADATA_PID" ]; then
		_cpu=$(printf '%s' "$_cpu" | jq --argjson receiver "$(delta "$_metadata0" "$(cputime "$METADATA_PID")")" '. + {metadata_receiver:$receiver}')
	fi
	# A nonzero exit may still leave useful partial evidence. Normalize its
	# host label before recording the failure, never promote it to a pass.
	if [ -s "$_f" ] && jq -e 'type == "object" and (.tool == "identity-bench" or .soak == true)' "$_f" >/dev/null 2>&1; then
		label_host "$_f"
	fi
	if [ "$_rc" -ne 0 ] || [ ! -s "$_f" ]; then
		FAILED=1
		jq -nc --arg s "$_s" --arg t0 "$_t0" --arg t1 "$_t1" --argjson cpu "$_cpu" --arg err "$(grep -v -E '^(real|user|sys) ' "$WORK/run-$_s.err" | tail -n 3)" \
			'{scenario:$s, started:$t0, ended:$t1, verdict:"FAIL", error:$err, cpu_seconds:$cpu}' >>"$WORK/summary.jsonl"
		log "  $_s: identity-bench failed (exit $_rc)"
		return 0
	fi
	if jq -e '.soak == true' "$_f" >/dev/null; then
		_v=pass
		jq -e '.complete == true and (.windows | length) > 0 and all(.windows[]; .complete == true)' "$_f" >/dev/null || _v=FAIL
		for _o in $(jq -c '.windows[].outcomes' "$_f"); do
			[ "$(verdict "$_s" "$_o")" = pass ] || _v=FAIL
		done
		[ "$(receiver_verdict "$_f")" = pass ] || _v=FAIL
		jq -c --arg s "$_s" --arg t0 "$_t0" --arg t1 "$_t1" --arg v "$_v" --argjson cpu "$_cpu" \
			'{scenario:("soak " + $s), started:$t0, ended:$t1, windows:(.windows | length), operations:([.windows[].operations] | add),
			  throughput_per_s:{min:([.windows[].throughput_per_s] | min * 10 | round / 10), max:([.windows[].throughput_per_s] | max * 10 | round / 10)},
			  p99_ms:{min:([.windows[].latency_ms.p99] | min * 100 | round / 100), max:([.windows[].latency_ms.p99] | max * 100 | round / 100)},
			  outcomes:(reduce .windows[].outcomes as $o ({}; reduce ($o | to_entries[]) as $e (.; .[$e.key] += $e.value))),
			  verdict:$v, cpu_seconds:$cpu}' "$_f" >>"$WORK/summary.jsonl"
	else
		_v=$(verdict "$_s" "$(jq -c .outcomes "$_f")")
		jq -e '.complete == true' "$_f" >/dev/null || _v=FAIL
		[ "$(receiver_verdict "$_f")" = pass ] || _v=FAIL
		jq -c --arg t0 "$_t0" --arg t1 "$_t1" --arg v "$_v" --argjson cpu "$_cpu" \
			'{scenario, started:$t0, ended:$t1, duration_s:(.duration_s * 10 | round / 10), concurrency, operations, throughput_per_s:(.throughput_per_s * 10 | round / 10),
			  latency_ms:(.latency_ms | map_values(. * 100 | round / 100)), outcomes, verdict:$v, cpu_seconds:$cpu}' "$_f" >>"$WORK/summary.jsonl"
	fi
	[ "$_v" = pass ] || FAILED=1
	if [ -n "$SMTP_PID" ]; then
		# Drain jobs interrupted by the duration boundary before observing
		# the receiver. The sink counts warm-up/preparation mail as well.
		_i=0
		while [ "$(psql_pg proudauth -c "SELECT count(*) FROM notification_jobs WHERE state IN ('queued','attempted')")" -gt 0 ]; do
			_i=$((_i + 1)); [ "$_i" -lt 40 ] || break
			sleep 0.25
		done
		sleep 1
		jq -nc --arg s "$_s" --slurpfile before "$WORK/smtp-before.json" --slurpfile after "$OUT/smtp-sink.json" --slurpfile result "$_f" '
			{scenario:$s, before:$before[0], after:$after[0], accepted_delta:($after[0].accepted-$before[0].accepted),
			 completed_email_operations:(if $result[0].soak then [$result[0].windows[].outcomes["email-delivery:ok"] // 0] | add
			 else ($result[0].outcomes["email-delivery:ok"] // (if $s=="email-delivery" then $result[0].outcomes.ok else 0 end) // 0) end),
			 note:"receiver counts include preparation, warm-up and messages interrupted at the measurement boundary; only counts and recipient digests are stored"}' >>"$WORK/smtp-observations.jsonl"
		if ! tail -n 1 "$WORK/smtp-observations.jsonl" | jq -e '.accepted_delta >= .completed_email_operations and .after.rejected_sessions == 0' >/dev/null; then
			FAILED=1
			log "  $_s: SMTP receiver did not confirm the completed email operations"
		fi
	fi
	log "  $_s: $_v; CPU seconds $_cpu"
}

# ------------------------------------------------------------- 1. database ---

log "work directory $WORK, results $OUT"
if [ -n "${BENCH_BIN:-}" ]; then
	BIN=$BENCH_BIN
else
	BIN=$WORK/bin
	log "building identity-server, identity-worker, identity-cli and identity-bench"
	(cd "$ROOT" && go build -mod=readonly -buildvcs=false -trimpath -o "$BIN/" ./cmd/identity-server ./cmd/identity-worker ./cmd/identity-cli ./cmd/identity-bench)
fi
# The checkout's identity: there is no tag or commit in a source tree without
# version control, so the results carry a digest of the sources instead.
SOURCE_DIGEST=$(cd "$ROOT" && find cmd internal migrations go.mod go.sum -type f \( -name '*.go' -o -name '*.sql' -o -name 'go.mod' -o -name 'go.sum' \) ! -name '*_test.go' |
	LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -c1-16)
GIT_COMMIT=none
(cd "$BIN" && shasum -a 256 identity-server identity-worker identity-cli identity-bench) >"$OUT/binary-sha256.txt"
go version -m "$BIN/identity-server" | sed "s|$BIN/||g" >"$OUT/build-info.txt"

case " $SELECTED_SCENARIOS " in
*" metadata-fetch "*)
	[ "$REPLICAS" = 1 ] || fail "metadata-fetch records per-process bounds and requires BENCH_SERVER_REPLICAS=1"
	"$BIN/identity-bench" metadata-receiver --listen 127.0.0.1:0 --port-file "$WORK/metadata.port" \
		--ca-out "$WORK/metadata-ca.pem" --out "$OUT/metadata-receiver.json" >"$WORK/metadata.log" 2>"$WORK/metadata.err" &
	METADATA_PID=$!
	_i=0
	while [ ! -s "$WORK/metadata.port" ] || [ ! -s "$OUT/metadata-receiver.json" ]; do
		_i=$((_i+1)); [ "$_i" -lt 100 ] || fail "metadata receiver did not start"
		kill -0 "$METADATA_PID" 2>/dev/null || fail "metadata receiver exited"
		sleep 0.1
	done
	METADATA_PORT=$(cat "$WORK/metadata.port")
	PROUDAUTH_BENCH_METADATA_URL=https://127.0.0.1:$METADATA_PORT
	PROUDAUTH_BENCH_METADATA_CA=$WORK/metadata-ca.pem
	export PROUDAUTH_BENCH_METADATA_URL PROUDAUTH_BENCH_METADATA_CA
	METADATA_CONFIG="federation:
  egress_allowlist: [\"127.0.0.1/32\"]
  ca_file: \"$WORK/metadata-ca.pem\""
	;;
esac

PGDATA=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$IMAGE" | sed -n 's/^PGDATA=//p')
VOLDIR=$(docker image inspect -f '{{range $k, $v := .Config.Volumes}}{{println $k}}{{end}}' "$IMAGE" | head -n 1)
[ -n "$PGDATA" ] && [ -n "$VOLDIR" ] || fail "cannot read PGDATA and the data volume from $IMAGE"
SUPER_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
APP_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
ADMIN_PW="bench administrator passphrase $(python3 -c 'import secrets;print(secrets.token_hex(8))')"
mkdir -p "$WORK/secrets"
chmod 700 "$WORK/secrets"

# PostgreSQL for a laptop: 2 GB of shared buffers, room for the server's and
# the worker's pools, durable commits (fsync and synchronous_commit stay on),
# and pg_stat_statements for the per-scenario statement statistics.
PG_SETTINGS="-c shared_buffers=$PG_SHARED_BUFFERS -c max_connections=$PG_MAX_CONNECTIONS -c effective_cache_size=6GB
	-c work_mem=16MB -c maintenance_work_mem=512MB -c max_wal_size=4GB -c checkpoint_timeout=15min
	-c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.max=10000"
docker volume create "$PG_VOLUME" >/dev/null
VOLUME_CREATED=1
# shellcheck disable=SC2086
docker create --pull=never --name "$PG" --shm-size=1g -p "127.0.0.1:$PG_PORT:5432" -e POSTGRES_PASSWORD="$SUPER_PW" \
	-v "$PG_VOLUME:$VOLDIR" "$IMAGE" $PG_SETTINGS >/dev/null
PG_CREATED=1
docker start "$PG" >/dev/null
_i=0
until docker exec "$PG" pg_isready -h 127.0.0.1 -U postgres -q 2>/dev/null; do
	_i=$((_i + 1))
	[ "$_i" -lt 120 ] || { docker logs --tail 30 "$PG" >&2; fail "$PG did not become ready"; }
	sleep 0.5
done
psql_pg postgres <<EOF
CREATE ROLE proudauth LOGIN PASSWORD '$APP_PW';
CREATE DATABASE proudauth OWNER proudauth;
CREATE EXTENSION pg_stat_statements;
EOF
psql_pg postgres -F '	' -c "SELECT name, setting, coalesce(unit, '') FROM pg_settings WHERE name IN ('server_version', 'shared_buffers',
	'max_connections', 'effective_cache_size', 'work_mem', 'maintenance_work_mem', 'max_wal_size', 'checkpoint_timeout', 'fsync',
	'synchronous_commit', 'wal_level', 'full_page_writes', 'random_page_cost', 'max_worker_processes', 'max_parallel_workers_per_gather',
	'autovacuum', 'shared_preload_libraries', 'huge_pages') ORDER BY name" >"$OUT/postgres/settings.tsv"
PG_VERSION=$(psql_pg postgres -c 'SELECT version()')
log "PostgreSQL: $PG_VERSION"

# ------------------------------------------------------------ 2. ProudAuth ---

"$BIN/identity-cli" generate-root-key >"$WORK/secrets/root_key" 2>"$WORK/root-key.err" || fail "generate-root-key"
printf '%s' "postgres://proudauth:$APP_PW@127.0.0.1:$PG_PORT/proudauth?sslmode=disable" >"$WORK/secrets/database_url"
chmod 600 "$WORK/secrets/root_key" "$WORK/secrets/database_url"
cat >"$WORK/config.yaml" <<EOF
# Generated by scripts/bench-local.sh. Production defaults except: development
# mode (plain-HTTP origin and the bootstrap development mailbox; selected
# email workloads switch to a plain-text loopback SMTP acceptance sink), the
# budgets raised for one load source (docs/operations/benchmarks.md) and a
# short prepublish period so a rotation started during the soak run
# activates inside it.
mode: development
server:
  public_listen: "127.0.0.1:$PRIMARY_PUBLIC_PORT"
  internal_listen: "127.0.0.1:$INTERNAL_PORT"
  public_origin: "$ORIGIN"
storage:
  database_url: "file:$WORK/secrets/database_url"
keys:
  root_keys:
    - version: 1
      ref: "file:$WORK/secrets/root_key"
  active_version: 1
  prepublish_period: 2m
sessions:
  cookie_insecure_dev: true
$METADATA_CONFIG
security:
  rate_limits:
    login_per_ip: $LOGIN_PER_IP
    login_per_realm: $LOGIN_PER_REALM
    login_per_client: $LOGIN_PER_CLIENT
    token_per_client: $TOKEN_PER_CLIENT
delivery:
$WEBHOOK_EGRESS
  email:
    adapter: dev_sink
workers:
  metrics_listen: "127.0.0.1:$WORKER_PORT"
observability:
  log_format: json
EOF
sed "s|$WORK|\$WORK|g" "$WORK/config.yaml" >"$OUT/proudauth-config.yaml"
export PROUDAUTH_CONFIG="$WORK/config.yaml"
"$BIN/identity-cli" migrate >"$WORK/migrate.out" 2>"$WORK/migrate.err" || fail "migrate: $(tail -n 3 "$WORK/migrate.err")"
"$BIN/identity-cli" realm-create -name "$REALM" -display-name "Benchmark" >"$WORK/realm.out" 2>"$WORK/realm.err" || fail "realm-create"
"$BIN/identity-cli" bootstrap -realm "$REALM" -email admin@bench.test -username bench-admin -ttl 10m >"$WORK/bootstrap.out" 2>"$WORK/bootstrap.err" ||
	fail "bootstrap"
SETUP=$(awk '/one-time setup token/ {f=1; next} f && NF {print $1; exit}' "$WORK/bootstrap.out")
[ -n "$SETUP" ] || fail "no setup token in bootstrap output"

start_servers
"$BIN/identity-worker" -config "$WORK/config.yaml" >"$WORK/worker.log" 2>&1 &
WORKER_PID=$!
if [ "$REPLICAS" -gt 1 ]; then
	set -- replica-proxy --listen "127.0.0.1:$HTTP_PORT" --port-file "$WORK/proxy.port" --out "$OUT/proxy-stats.json"
	while read -r _node _public _internal; do set -- "$@" --backend "http://127.0.0.1:$_public"; done <"$WORK/node-ports.tsv"
	"$BIN/identity-bench" "$@" >"$WORK/proxy.log" 2>"$WORK/proxy.err" &
	PROXY_PID=$!
	_i=0
	until curl -fsS "$ORIGIN/_pa_bench_proxy/stats" >"$WORK/proxy-start.json" 2>/dev/null; do
		_i=$((_i+1)); [ "$_i" -lt 200 ] || fail "replica proxy did not become ready"
		kill -0 "$PROXY_PID" 2>/dev/null || fail "replica proxy exited"
		sleep 0.1
	done
	log "$REPLICAS independent server processes behind a loopback per-request proxy"
fi
code=$(api POST /account-setup "" "$(jq -nc --arg t "$SETUP" --arg p "$ADMIN_PW" '{setup_token:$t, password:$p}')")
[ "$code" = 200 ] || fail "administrator account setup: $code $(cat "$WORK/resp.json")"
admin_login "$WORK/admin-tokens.json"
write_credentials "$WORK/admin-tokens.json"
log "administrator signed in (password, email verification, TOTP enrollment); credentials in the work directory"

# Only delivery workloads switch from the bootstrap mailbox to SMTP. The
# sink never relays mail or saves a message body; its port is allocated by
# the OS. Restart our own processes so recorded configuration is effective.
case " $SELECTED_SCENARIOS " in
*" email-delivery "*|*" mixed-email "*|*" mixed-delivery "*)
	"$BIN/identity-bench" smtp-sink --listen 127.0.0.1:0 --port-file "$WORK/smtp.port" --out "$OUT/smtp-sink.json" >"$WORK/smtp.log" 2>"$WORK/smtp.err" &
	SMTP_PID=$!
	_i=0
	while [ ! -s "$WORK/smtp.port" ] || [ ! -s "$OUT/smtp-sink.json" ]; do
		_i=$((_i + 1)); [ "$_i" -lt 100 ] || fail "SMTP sink did not start"
		kill -0 "$SMTP_PID" 2>/dev/null || fail "SMTP sink exited"
		sleep 0.1
	done
	SMTP_PORT=$(cat "$WORK/smtp.port")
	stop_servers
	kill_proc "$WORKER_PID"; WORKER_PID=
	awk -v port="$SMTP_PORT" '$0 == "    adapter: dev_sink" {
		print "    adapter: smtp"; print "    smtp_host: 127.0.0.1"; print "    smtp_port: " port; print "    smtp_tls: none"; print "    from: noreply@bench.test"; next
	} { print }' "$WORK/config.yaml" >"$WORK/config-smtp.yaml"
	mv "$WORK/config-smtp.yaml" "$WORK/config.yaml"
	sed "s|$WORK|\$WORK|g" "$WORK/config.yaml" >"$OUT/proudauth-config.yaml"
	start_servers
	"$BIN/identity-worker" -config "$WORK/config.yaml" >>"$WORK/worker.log" 2>&1 &
	WORKER_PID=$!
	_i=0
	until [ "$(curl -s -o /dev/null -w '%{http_code}' "$ORIGIN/health/ready")" = 200 ]; do
		_i=$((_i + 1)); [ "$_i" -lt 200 ] || fail "SMTP-configured server did not become ready"
		kill -0 "$SERVER_PID" 2>/dev/null || fail "SMTP-configured server exited"
		sleep 0.1
	done
	log "SMTP transport uses a counts-only sink on 127.0.0.1:$SMTP_PORT (development, no TLS/auth, no relay)"
	;;
esac

# Passkeys are opt-in. Enable them only on our dedicated benchmark realm;
# configure a valid localhost RP/origin, preserving all other policy values
# and the optimistic concurrency guard (WebAuthn RP IDs cannot be IPs).
case " $SELECTED_SCENARIOS " in
*" passkey-assertion "*|*" mixed-extended "*|*" mixed-email "*|*" mixed-delivery "*)
	code=$(api GET /settings "$(jq -r .access_token "$WORK/admin-credentials.json")")
	[ "$code" = 200 ] || fail "read realm policy: HTTP $code"
	cp "$WORK/resp.json" "$WORK/realm-settings.json"
	jq --arg origin "http://localhost:$HTTP_PORT" \
		'{policy:(.policy | .login.passkeys = true | .webauthn.rp_id = "localhost" | .webauthn.origins = [$origin]),
		 reason:"isolated passkey benchmark workload"}' "$WORK/realm-settings.json" >"$WORK/passkey-policy.json"
	code=$(curl -sS -o "$WORK/resp.json" -w '%{http_code}' -X PUT "$API/settings" \
		-H "Authorization: Bearer $(jq -r .access_token "$WORK/admin-credentials.json")" \
		-H "If-Match: \"$(jq -r .version "$WORK/realm-settings.json")\"" \
		-H 'Content-Type: application/json' --data-binary "@$WORK/passkey-policy.json")
	[ "$code" = 200 ] || fail "enable benchmark passkeys: HTTP $code"
	jq '{policy_revision, version, login:.policy.login, webauthn:.policy.webauthn,
		note:"login.passkeys enabled; RP ID localhost and explicit HTTP localhost origin; all other policy values preserved"}' "$WORK/resp.json" >"$OUT/realm-benchmark-policy.json"
	log "passkeys enabled with an explicit localhost RP/origin in the dedicated benchmark realm"
	;;
esac

# ------------------------------------------------------------ environment ---

case $(uname -s) in
Darwin)
	MACHINE=$(sysctl -n hw.model)
	CPU=$(sysctl -n machdep.cpu.brand_string)
	NCPU=$(sysctl -n hw.ncpu)
	MEM=$(sysctl -n hw.memsize)
	CORES=$(printf '%s performance + %s efficiency' "$(sysctl -n hw.perflevel0.physicalcpu 2>/dev/null || echo '?')" "$(sysctl -n hw.perflevel1.physicalcpu 2>/dev/null || echo 0)")
	OS="macOS $(sw_vers -productVersion) ($(sw_vers -buildVersion)), Darwin $(uname -r)"
	POWER=$(pmset -g batt 2>/dev/null | head -n 1 | sed "s/^Now drawing from //; s/'//g" || echo unknown)
	;;
*)
	MACHINE=$(cat /sys/devices/virtual/dmi/id/product_name 2>/dev/null || echo unknown)
	CPU=$(awk -F': ' '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)
	NCPU=$(nproc 2>/dev/null || echo 0)
	MEM=$(awk '/MemTotal/ {print $2 * 1024}' /proc/meminfo 2>/dev/null || echo 0)
	CORES=unknown
	OS="$(uname -s) $(uname -r)"
	POWER=unknown
	;;
esac
jq -n --arg date "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg machine "$MACHINE" --arg cpu "$CPU" --argjson ncpu "$NCPU" --arg cores "$CORES" \
	--argjson mem "$MEM" --arg os "$OS" --arg power "$POWER" --arg go "$(go version | awk '{print $3}')" \
	--arg docker "$(docker version -f '{{.Server.Version}}' 2>/dev/null || echo unknown)" \
	--arg dockervm "$(docker info -f '{{.NCPU}} CPUs, {{.MemTotal}} bytes, {{.OperatingSystem}}' 2>/dev/null || echo unknown)" \
	--arg image "$IMAGE" --arg pg "$PG_VERSION" --arg digest "$SOURCE_DIGEST" --arg commit "$GIT_COMMIT" \
	--arg imageid "$(docker image inspect -f '{{.Id}}' "$IMAGE")" \
	--arg version "$(jq -r 'select(.msg == "public listener starting") | .version' "$WORK/server.log" 2>/dev/null | head -n 1)" \
	--argjson c "$CONCURRENCY" --arg d "$DURATION" --arg w "$WARMUP" --arg soak "$SOAK" --arg win "$SOAK_WINDOW" --arg soakscenario "$SOAK_SCENARIO" \
	--argjson ip "$LOGIN_PER_IP" --argjson realm "$LOGIN_PER_REALM" --argjson client "$LOGIN_PER_CLIENT" --argjson tok "$TOKEN_PER_CLIENT" '{
	date:$date,
	machine:{model:$machine, cpu:$cpu, logical_cpus:$ncpu, cores:$cores, memory_bytes:$mem, os:$os, power:$power},
	go:$go, docker:{server:$docker, vm:$dockervm},
	postgresql:{image:$image, image_id:$imageid, version:$pg, settings:"postgres/settings.tsv", topology:"one container on the same machine, data on a Docker volume, port published on 127.0.0.1"},
	proudauth:{build:"identity-server, identity-worker, identity-cli and identity-bench built from the checkout (GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local go build -mod=readonly -buildvcs=false -trimpath)", version:$version,
		source_digest_sha256_16:$digest, git_commit:$commit, configuration:"proudauth-config.yaml",
		processes:"one identity-server and one identity-worker on the host, plain HTTP on 127.0.0.1"},
	raised_budgets:{"security.rate_limits.login_per_ip":$ip, "security.rate_limits.login_per_realm":$realm,
		"security.rate_limits.login_per_client":$client, "security.rate_limits.token_per_client":$tok},
	load_generator:{tool:"identity-bench", host:"the same machine", concurrency:$c, duration:$d, warmup:$w, soak:$soak, soak_window:$win,soak_scenario:$soakscenario}}' >"$OUT/environment.json"
if [ -n "$SMTP_PID" ]; then
	jq --argjson port "$SMTP_PORT" '. + {email_delivery:{adapter:"smtp",host:"127.0.0.1",port:$port,tls:"none (development only)",authentication:"none",receiver:"identity-bench smtp-sink on the same host; counts only, no message persistence or onward relay",bootstrap:"development mailbox only for the first administrator verification, then server/worker restart with SMTP"}}' "$OUT/environment.json" >"$WORK/environment-smtp.json"
	mv "$WORK/environment-smtp.json" "$OUT/environment.json"
fi
if [ -n "$METADATA_PID" ]; then
	jq --argjson port "$METADATA_PORT" --arg ca "$(shasum -a 256 "$WORK/metadata-ca.pem" | cut -d ' ' -f 1)" \
		'. + {metadata_fetch:{receiver:"identity-bench metadata-receiver on the same host",tls:"HTTPS with explicit ephemeral CA; no verification bypass",port:$port,
		ca_sha256:$ca,egress_allowlist:["127.0.0.1/32"],denied_live_destination:"::1/128",good_cache_ttl_s:300,retry_after_s:60,fetch_timeout_s:10,max_response_bytes:1048576,
		private_material:"TLS/signing keys only in receiver memory; assertions/tokens only in benchmark memory; public CA in disposable work directory",scope:"one workload-federation server process"}}' \
		"$OUT/environment.json" >"$WORK/environment-metadata.json"
	mv "$WORK/environment-metadata.json" "$OUT/environment.json"
fi

if [ "$REPLICAS" -gt 1 ]; then
	python3 - "$WORK/node-ports.tsv" "$WORK/server-pids.tsv" "$PROXY_PID" "$WORKER_PID" "$ORIGIN" >"$OUT/replica-topology.json" <<'PY'
import json,sys
ports=[tuple(map(int,line.split())) for line in open(sys.argv[1])]
pids={int(n):int(pid) for n,pid in (line.split() for line in open(sys.argv[2]))}
assert len(set(pids.values()))==len(ports)
json.dump({'server_count':len(ports),'servers':[{'node':n,'process_id':pids[n],
    'public_listen':f'127.0.0.1:{pub}','internal_listen':f'127.0.0.1:{internal}',
    'configuration':f'proudauth-config-node-{n}.yaml'} for n,pub,internal in ports],
    'worker_process_id':int(sys.argv[4]),'proxy':{'process_id':int(sys.argv[3]),'public_origin':sys.argv[5],
    'routing':'round robin per HTTP request, no sticky sessions or cross-backend retries',
    'transport':'plain HTTP/1.1 loopback; outgoing pooled connections; incoming Host and one-use bodies preserved'},
    'shared_state':'one PostgreSQL database; equivalent root-key files read independently; no application memory/cache shared',
    'limits':'all processes, load generator, proxy and database share one machine; not multi-machine or failover evidence'},sys.stdout,indent=2)
print()
PY
	jq --argjson n "$REPLICAS" '.proudauth.server_process_count=$n | .proudauth.replica_topology="replica-topology.json" |
		.proudauth.processes="\($n) independent identity-server processes, one identity-worker and a loopback replica-proxy on the host"' \
		"$OUT/environment.json" >"$WORK/environment-replicas.json"
	mv "$WORK/environment-replicas.json" "$OUT/environment.json"
fi

# ------------------------------------------------------------- 3. seeding ---

log "seeding: $USERS users, $ORGS organizations, a $LARGE-member organization, $CLIENTS clients, a $GROUP_MEMBERS-member group (seed $DATA_SEED)"
_s0=$(date +%s)
bench seed --url "$ORIGIN" --realm "$REALM" --users "$USERS" --orgs "$ORGS" --large "$LARGE" --clients "$CLIENTS" \
	--group-members "$GROUP_MEMBERS" --seed "$DATA_SEED" --out "$WORK/seed.json" 2>"$WORK/seed.err" || fail "seed: $(tail -n 3 "$WORK/seed.err")"
SEED_SECONDS=$(($(date +%s) - _s0))
jq --argjson secs "$SEED_SECONDS" '{spec, realm, prefix, audience, redirect_uri, admin_audience, created_at, seeding_seconds:$secs,
	note:"the seed file itself holds the benchmark clients'"'"' secrets and is not published"}' "$WORK/seed.json" >"$OUT/seed-spec.json"
PFX=$(jq -r .prefix "$WORK/seed.json")
TARGET=${PFX}u$((USERS - 1))@bench.test
log "seeded in ${SEED_SECONDS}s (prefix $PFX)"
"$BIN/identity-cli" support-bundle -out "$WORK/support-bundle.json" >"$WORK/support.out" 2>"$WORK/support.err" || fail "support-bundle"
jq '.configuration' "$WORK/support-bundle.json" >"$OUT/effective-config-redacted.json"

# ----------------------------------------------------------- 4. scenarios ---

for s in $SCENARIOS; do
	run_scenario "$s" "$OUT/$s.json" --duration "$DURATION"
	case $s in
	password-login)
		psql_pg proudauth -F '	' -c "SELECT count(*) FILTER (WHERE verifier LIKE '\$argon2id\$%'), count(*) FILTER (WHERE verifier LIKE '\$legacy-sha256\$%')
			FROM credentials WHERE type = 'password' AND state = 'active'" >"$WORK/rehash.tsv"
		log "  password verifiers after password-login: $(awk -F'\t' '{print $1 " Argon2id (rehashed at first sign-in), " $2 " imported SHA-256"}' "$WORK/rehash.tsv")"
		jq -nc --arg r "$(cat "$WORK/rehash.tsv")" \
			'{scenario:"password-login", notes:["password verifiers after the run (Argon2id, imported SHA-256): " + ($r | gsub("\t"; ", "))]}' >>"$WORK/notes.jsonl"
		;;
	otp-guess)
		# Independent, post-measurement counts; never publish account IDs,
		# guesses, factor seeds or transaction continuation authority.
		psql_pg proudauth -c "WITH owned AS (SELECT user_id FROM user_identifiers WHERE canonical_value LIKE '${PFX}otp-guess-%@bench.test'),
			txs AS (SELECT t.* FROM auth_transactions t JOIN owned o USING (user_id) WHERE t.status IN ('pending','failed'))
			SELECT json_build_object('subject_accounts',(SELECT count(*) FROM owned),'transactions',count(*),
			'evaluated_proofs',coalesce(sum(failure_count),0),'max_transaction_failures',coalesce(max(failure_count),0),
			'pending_transactions',count(*) FILTER (WHERE status='pending'),'failed_transactions',count(*) FILTER (WHERE status='failed'),
			'audited_failed_proofs',(SELECT count(*) FROM audit_events a JOIN owned o ON o.user_id=a.subject_id WHERE a.type='mfa.totp.failed')) FROM txs" >"$WORK/otp-budget.json"
		jq '. + {pass:(.subject_accounts == 1 and .transactions == 8 and .evaluated_proofs == 10 and .audited_failed_proofs == 10
			and .max_transaction_failures <= 5 and .pending_transactions >= 6 and .failed_transactions <= 2)}' "$WORK/otp-budget.json" >"$OUT/otp-budget-evidence.json"
		if ! jq -e .pass "$OUT/otp-budget-evidence.json" >/dev/null; then
			log "  FAIL: OTP account/transaction budgets disagree with stored evidence"
			FAILED=1
		fi
		;;
	notification-flood)
		# Messages actually delivered to the attacked address (development
		# sink), once the worker has drained the queue.
		_transport='development sink'
		if [ -n "$SMTP_PID" ]; then
			_digest=$(printf '%s' "$TARGET" | shasum -a 256 | awk '{print $1}')
			_n=$(jq -r --arg digest "$_digest" '.recipient_sha256[$digest] // 0' "$OUT/smtp-sink.json")
			_transport='loopback SMTP sink'
		else
			_prev=-1 _n=0 _i=0
			while [ "$_i" -lt 30 ]; do
				_n=$(psql_pg proudauth -c "SELECT count(*) FROM dev_mailbox WHERE lower(recipient) = lower('$TARGET')")
				[ "$_n" = "$_prev" ] && break
				_prev=$_n _i=$((_i + 1))
				sleep 2
			done
		fi
		log "  messages delivered to the attacked address: $_n"
		jq -nc --arg n "$_n" --arg transport "$_transport" '{scenario:"notification-flood", notes:["messages delivered to the attacked address (" + $transport + "): " + $n]}' >>"$WORK/notes.jsonl"
		;;
	esac
done

# ------------------------------------------------------------ 5. soak run ---

if [ "$SOAK" != 0 ]; then
	# Events the soak run should cross (benchmarks.md, "Soak runs"), started
	# at fixed offsets; the worker's own periodic tasks and token expiry
	# happen on their own. Times go to soak-events.tsv.
	printf 'utc\tevent\n' >"$OUT/soak-events.tsv"
	event() { printf '%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$OUT/soak-events.tsv"; }
	curl -fsS "http://127.0.0.1:$WORKER_PORT/metrics" 2>/dev/null | grep '^proudauth_worker_runs_total' >"$WORK/worker-runs.before" || true
	(
		exec 2>>"$WORK/soak-events.err"
		sleep 120
		admin_login "$WORK/rotation-tokens.json" >/dev/null 2>&1 || { event "planned signing-key rotation: administrator sign-in failed"; exit 0; }
		code=$(api POST /signing-key-rotations "$(jq -r .access_token "$WORK/rotation-tokens.json")" '{"mode":"planned","reason":"identity-bench soak run"}')
		event "planned signing-key rotation requested: HTTP $code (new key published now, activated by the worker after keys.prepublish_period 2m)"
		sleep 220
		event "VACUUM (ANALYZE) started"
		psql_pg proudauth -c 'VACUUM (ANALYZE)' >/dev/null 2>&1 || true
		event "VACUUM (ANALYZE) finished"
		sleep 60
		event "pg_dump (custom format, to /dev/null) started"
		docker exec "$PG" sh -c 'pg_dump -U postgres -Fc proudauth >/dev/null' 2>/dev/null || true
		event "pg_dump finished"
	) &
	EVENTS_PID=$!
	event "soak run of $SOAK_SCENARIO started (preparation and warm-up first; prepared tokens expire after 300 s unless renewed; mixed-delivery injects a 503 for each webhook-retry event's first attempt)"
	run_scenario "$SOAK_SCENARIO" "$OUT/soak-$SOAK_SCENARIO.json" --soak "$SOAK" --window "$SOAK_WINDOW"
	event "soak run ended"
	kill_proc "$EVENTS_PID"
	EVENTS_PID=
	psql_pg proudauth -F '	' -c "SELECT kid, algorithm, state, to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
		coalesce(to_char(activated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), '') FROM signing_keys
		WHERE realm_id = (SELECT id FROM realms WHERE name = '$REALM') AND purpose = 'token' ORDER BY created_at" |
		awk -F'\t' -v OFS='\t' '{print $4, "signing key " $1 " (" $2 ") created; state " $3 (($5 != "") ? ", activated " $5 : "")}' >>"$OUT/soak-events.tsv"
	curl -fsS "http://127.0.0.1:$WORKER_PORT/metrics" 2>/dev/null | grep '^proudauth_worker_runs_total' >"$WORK/worker-runs.after" || true
	awk 'NR == FNR {b[$1] = $2; next} {d = $2 - b[$1]; if (d > 0) print $1 "\t" d}' "$WORK/worker-runs.before" "$WORK/worker-runs.after" |
		sed 's/^proudauth_worker_runs_total//' >"$OUT/soak-worker-runs.tsv" || true
fi

# ---------------------------------------------------------------- results ---

if [ -n "$SMTP_PID" ]; then
	kill_proc "$SMTP_PID"; SMTP_PID=
	jq -s . "$WORK/smtp-observations.jsonl" >"$OUT/smtp-observations.json"
fi
if [ -n "$METADATA_PID" ]; then kill_proc "$METADATA_PID"; METADATA_PID=; fi

psql_pg proudauth -F '	' -c "SELECT relname, n_live_tup, pg_total_relation_size(relid) FROM pg_stat_user_tables
	ORDER BY pg_total_relation_size(relid) DESC LIMIT 15" >"$OUT/postgres/largest-tables.tsv"
psql_pg proudauth -c "SELECT pg_database_size('proudauth')" >"$OUT/postgres/database-size-bytes.txt"
if [ -s "$WORK/notes.jsonl" ]; then
	jq -s 'reduce .[] as $n ({}; .[$n.scenario] += $n.notes)' "$WORK/notes.jsonl" >"$WORK/notes.json"
else
	echo '{}' >"$WORK/notes.json"
fi
jq -s --slurpfile notes "$WORK/notes.json" 'map(. + (if $notes[0][.scenario] then {notes: $notes[0][.scenario]} else {} end))' \
	"$WORK/summary.jsonl" >"$OUT/summary.json"

if [ -n "$PROXY_PID" ]; then
	kill_proc "$PROXY_PID"; PROXY_PID=
	jq -s . "$WORK/replica-routing.jsonl" >"$OUT/replica-routing.json"
	jq --argjson n "$REPLICAS" --slurpfile routing "$OUT/replica-routing.json" '
		{complete,server_count:(.backends|length),inflight_requests,
		pass:(.complete==true and .inflight_requests==0 and (.backends|length)==$n and
		all(.backends[]; .assigned_requests>0) and ($routing[0]|length)>0 and all($routing[0][]; .pass)),
		note:"per-scenario routing must reach every server without proxy transport errors/response aborts; final proxy shutdown must drain all handlers"}' \
		"$OUT/proxy-stats.json" >"$OUT/replica-validation.json"
	if ! jq -e .pass "$OUT/replica-validation.json" >/dev/null; then FAILED=1; fi
fi

# Nothing secret may be in the results: client secrets of the seed file, the
# administrator's password and tokens, the database passwords, the root key.
{
	jq -r '.. | .client_secret? // empty' "$WORK/seed.json"
	jq -r '.access_token, .refresh_token' "$WORK/admin-credentials.json" "$WORK/admin-tokens.json"
	printf '%s\n%s\n%s\n%s\n' "$ADMIN_PW" "$SUPER_PW" "$APP_PW" "$(cat "$WORK/secrets/root_key")"
} | grep . | sort -u >"$WORK/secrets.list"
if grep -rF -l -f "$WORK/secrets.list" "$OUT" >/dev/null 2>&1; then
	grep -rF -l -f "$WORK/secrets.list" "$OUT" >&2
	fail "the results contain a secret; do not publish them"
fi
if grep -rE -l 'pa_scim_[A-Za-z0-9_-]+|whsec_[A-Za-z0-9+/=]+|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----' "$OUT" >/dev/null 2>&1; then
	fail "the results contain a connector token, webhook secret or private key; do not publish them"
fi

echo
printf '%-20s %9s %10s %9s %9s %9s  %-6s %s\n' scenario ops ops/s p50_ms p99_ms p999_ms result outcomes
jq -r 'def range: if type == "object" then "\(.min)..\(.max)" else tostring end;
	.[] | [.scenario, (.operations // 0), (.throughput_per_s // "-" | range), (.latency_ms.p50 // "-"), (.latency_ms.p99 // .p99_ms // "-" | range),
	(.latency_ms.p999 // "-"), .verdict, (.outcomes // .error | tostring)] | @tsv' "$OUT/summary.json" |
	awk -F'\t' '{printf "%-20s %9s %10s %9s %9s %9s  %-6s %s\n", $1, $2, $3, $4, $5, $6, $7, $8}'
echo
log "results in $OUT"
[ "$FAILED" = 0 ] || fail "a scenario missed its pass criteria or did not complete (see $OUT/summary.json)"
log "every scenario met its pass criteria"
