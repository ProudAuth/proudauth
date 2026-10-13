#!/bin/sh
# Interoperability with Keycloak: QA-004 (publish tested external clients and
# connectors with exact versions) and the M4 exit criterion of docs/plan.md
# section 35.1 (named protocol profiles and compatible counterpart versions),
# in both directions and both protocols:
#
#   1. ProudAuth as OpenID Provider, Keycloak as relying party: a Keycloak
#      "OpenID Connect v1.0" identity provider configured from ProudAuth's
#      discovery document (client_secret_basic, PKCE S256, scope
#      "openid email profile", ID-token signature through the JWKS, UserInfo)
#      brokers a sign-in through ProudAuth's login transaction in browser mode;
#      then RP-initiated logout from Keycloak through ProudAuth's end-session
#      endpoint and back. OIDC-001, OIDC-002, OIDC-003, OIDC-006, OIDC-015,
#      TOK-002, TOK-011, AUT-003, SES-016.
#   2. Keycloak as upstream OpenID Provider for ProudAuth federation: a generic
#      OIDC connection signs a user in through Keycloak's login form with
#      just-in-time provisioning and a linked identity; a second sign-in
#      (prompt=login, Keycloak SSO) reuses the link; upstream logout through
#      Keycloak's end-session endpoint. FED-001, FED-003, FED-013, FED-017,
#      REG-009, OIDC-004.
#   3. SAML 2.0: (a) ProudAuth as identity provider for a Keycloak "SAML v2.0"
#      identity provider, each configured from the other's metadata: signed
#      HTTP-Redirect AuthnRequest, signed response and assertion over
#      HTTP-POST, persistent NameID, attributes, and SP-initiated single logout;
#      (b) a ProudAuth SAML connection to a Keycloak SAML client acting as
#      identity provider: signed HTTP-Redirect AuthnRequest, signed response
#      and assertion, persistent NameID, email attribute, Keycloak's default
#      role list (one Attribute element per role), just-in-time provisioning.
#      SAML-001, SAML-002, SAML-003, SAML-005, SAML-006, SAML-008, SAML-010,
#      APP-018, FED-014.
#   4. Negative checks against the real counterpart (TEST-028, TEST-051): a
#      replayed authorization code (refused, grant revoked), a wrong client
#      secret configured at Keycloak (refused at ProudAuth's token endpoint), a
#      wrong upstream client secret configured at ProudAuth (sign-in fails, no
#      account), a replayed federation callback, a replayed and a tampered
#      Keycloak AuthnRequest, one asking for an HTTP-Redirect response, a
#      replayed and a tampered Keycloak SAML response.
#
# Everything runs in throwaway containers on one Docker network: PostgreSQL,
# identity-server and identity-worker built from this checkout (static Linux
# binaries in a distroless image), and Keycloak in development mode
# (start-dev, H2 database) with TLS. Both servers use certificates from a test
# CA generated here; ProudAuth runs in development mode (dev email sink,
# private-network egress allowed) with TLS on its public listener. This script
# plays the browser with curl and a cookie jar per user, and plays ProudAuth's
# external login UI through the transaction API in browser mode (cookie, CSRF
# token, Origin). Host names resolve to the published ports with
# curl --resolve, so the issuers seen by Keycloak (inside Docker) and by this
# script are identical.
#
# Requirements: docker, go, curl, jq, python3, openssl. Images (pulled when
# missing): INTEROP_KEYCLOAK_IMAGE (default quay.io/keycloak/keycloak:26.8.0),
# INTEROP_PG_IMAGE (postgres:18), INTEROP_RUN_IMAGE
# (gcr.io/distroless/static-debian12:nonroot). Other overrides: INTEROP_PREFIX
# (containers, network; default pa-interop-kc), INTEROP_PA_PORT,
# INTEROP_KC_PORT, INTEROP_INTERNAL_PORT (host ports, default 18643, 18644,
# 18645), INTEROP_BIN (directory with prebuilt static linux identity-server,
# identity-worker and identity-cli for the Docker host's architecture; default:
# go build), INTEROP_KEEP=1 (keep containers and the work directory).
# See docs/integrations/interoperability.md#third-party-products.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
KC_IMAGE=${INTEROP_KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.8.0}
PG_IMAGE=${INTEROP_PG_IMAGE:-postgres:18}
RUN_IMAGE=${INTEROP_RUN_IMAGE:-gcr.io/distroless/static-debian12:nonroot}
PREFIX=${INTEROP_PREFIX:-pa-interop-kc}
PA_PORT=${INTEROP_PA_PORT:-18643}
KC_PORT=${INTEROP_KC_PORT:-18644}
INTERNAL_PORT=${INTEROP_INTERNAL_PORT:-18645}
KEEP=${INTEROP_KEEP:-0}

NET=$PREFIX-net
PG=$PREFIX-pg
SERVER=$PREFIX-proudauth
WORKER=$PREFIX-worker
KEYCLOAK=$PREFIX-keycloak

PA_HOST=proudauth.interop.test
KC_HOST=keycloak.interop.test
REALM=interop
ORIGIN=https://$PA_HOST:$PA_PORT
ISSUER=$ORIGIN/realms/$REALM
API=$ORIGIN/api/v1/realms/$REALM
INTERNAL=http://127.0.0.1:$INTERNAL_PORT
LOGIN_UI=$ORIGIN/login-ui
KC=https://$KC_HOST:$KC_PORT
APP=https://app.interop.test
APP_CALLBACK=$APP/callback
APP_LOGGED_OUT=$APP/logged-out

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pa-interop-kc.XXXXXX")

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
ok() { printf '[%s]   ok: %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() {
	printf '\nINTEROP FAILED: %s\n' "$*" >&2
	exit 1
}

docker_cleanup() {
	docker rm -f -v "$SERVER" "$WORKER" "$KEYCLOAK" "$PG" >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
}

cleanup() {
	status=$?
	trap - EXIT INT TERM
	if [ "$status" -ne 0 ]; then
		for ctr in "$SERVER" "$WORKER" "$KEYCLOAK"; do
			docker inspect "$ctr" >/dev/null 2>&1 || continue
			printf '\n--- last lines of %s ---\n' "$ctr" >&2
			docker logs --tail 12 "$ctr" 2>&1 | cut -c1-600 >&2 || true
		done
		[ ! -f "$WORK/page.html" ] || {
			printf '\n--- last page (%s) ---\n' "${NAV_URL:-}" >&2
			sed -e 's/<[^>]*>/ /g' "$WORK/page.html" | tr -s ' \t' ' ' | grep -v '^ *$' | head -n 25 | cut -c1-300 >&2 || true
		}
	fi
	if [ "$KEEP" = 1 ]; then
		log "INTEROP_KEEP=1: kept $WORK, containers and network $NET"
	else
		docker_cleanup
		rm -rf "$WORK"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

for tool in docker go curl jq python3 openssl; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
docker info >/dev/null 2>&1 || fail "docker is not reachable"
docker_cleanup
for port in "$PA_PORT" "$KC_PORT" "$INTERNAL_PORT"; do
	_rc=0
	curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$port/" 2>/dev/null || _rc=$?
	[ "$_rc" -eq 7 ] || fail "port $port is in use (set INTEROP_PA_PORT, INTEROP_KC_PORT or INTEROP_INTERNAL_PORT)"
done

# ---------------------------------------------------------------- helpers ---

cat >"$WORK/helper.py" <<'PY'
# Small helpers for the interoperability script: TOTP, PKCE, HTML forms,
# SAML messages and URL editing. Standard library only.
import base64, hashlib, hmac, json, secrets, struct, sys, urllib.parse, zlib
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"


class Forms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.cur = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.cur = {"id": a.get("id") or "", "action": a.get("action") or "", "method": (a.get("method") or "get").lower(),
                        "fields": [], "submit": None, "inputs": []}
            self.forms.append(self.cur)
            return
        if self.cur is None or not a.get("name"):
            return
        kind = (a.get("type") or ("submit" if tag == "button" else "text")).lower()
        if tag not in ("input", "button"):
            if tag in ("textarea", "select"):
                self.cur["fields"].append([a["name"], ""])
                self.cur["inputs"].append(a["name"])
            return
        if kind in ("submit", "image"):
            if self.cur["submit"] is None:
                self.cur["submit"] = [a["name"], a.get("value") or ""]
            return
        if kind in ("checkbox", "radio") and "checked" not in a:
            return
        if kind in ("button", "reset"):
            return
        self.cur["fields"].append([a["name"], a.get("value") or ""])
        self.cur["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form":
            self.cur = None


def form(page, base, out, want, *overrides):
    p = Forms()
    p.feed(open(page, encoding="utf-8", errors="replace").read())
    forms = [f for f in p.forms if not want or f["id"] == want or want in f["inputs"]]
    if not forms:
        sys.exit("no form" + (" " + want if want else ""))
    f = forms[0]
    fields = list(f["fields"])
    if f["submit"]:
        fields.append(f["submit"])
    for o in overrides:
        k, _, v = o.partition("=")
        fields = [x for x in fields if x[0] != k] + [[k, v]]
    open(out, "w").write(urllib.parse.urlencode([tuple(x) for x in fields]))
    print(f["method"].upper(), urllib.parse.urljoin(base, f["action"]))


def forminfo(page):
    p = Forms()
    p.feed(open(page, encoding="utf-8", errors="replace").read())
    print(json.dumps([{"id": f["id"], "inputs": f["inputs"]} for f in p.forms]))


def totp(secret, step):
    s = secret.upper().rstrip("=")
    s += "=" * (-len(s) % 8)
    h = hmac.new(base64.b32decode(s), struct.pack(">Q", int(step)), hashlib.sha1).digest()
    o = h[-1] & 15
    print("%06d" % ((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 1000000))


def pkce():
    v = secrets.token_urlsafe(48)
    print(v, base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode())


def field(page, name):
    # The value of a form field (SAMLResponse, RelayState) of the page's first form.
    p = Forms()
    p.feed(open(page, encoding="utf-8", errors="replace").read())
    for f in p.forms:
        for k, v in f["fields"]:
            if k == name:
                sys.stdout.write(v)
                return
    sys.exit("no field " + name)


def samlinfo(b64):
    # NameID, its format, issuers and attributes of a base64 SAML response.
    root = ET.fromstring(base64.b64decode(b64))
    a = root.find("{%s}Assertion" % SAML)
    nid = a.find("{%s}Subject/{%s}NameID" % (SAML, SAML))
    attrs, elements = {}, {}
    for at in a.iter("{%s}Attribute" % SAML):
        attrs.setdefault(at.get("Name"), []).extend([v.text or "" for v in at.findall("{%s}AttributeValue" % SAML)])
        elements[at.get("Name")] = elements.get(at.get("Name"), 0) + 1
    print(json.dumps({"issuer": root.findtext("{%s}Issuer" % SAML), "status": root.find("{%s}Status/{%s}StatusCode" % (SAMLP, SAMLP)).get("Value"),
                      "in_response_to": root.get("InResponseTo"), "destination": root.get("Destination"),
                      "assertion_issuer": a.findtext("{%s}Issuer" % SAML), "name_id": nid.text, "name_id_format": nid.get("Format"),
                      "response_signed": root.find("{%s}Signature" % DS) is not None,
                      "assertion_signed": a.find("{%s}Signature" % DS) is not None,
                      "signature_methods": sorted({m.get("Algorithm") for m in root.iter("{%s}SignatureMethod" % DS)}),
                      "digest_methods": sorted({m.get("Algorithm") for m in root.iter("{%s}DigestMethod" % DS)}),
                      "attributes": attrs, "attribute_elements": elements}))


def samlenc(b64):
    # Whether a base64 SAML response carries an EncryptedAssertion, and its algorithms.
    root = ET.fromstring(base64.b64decode(b64))
    print(json.dumps({"encrypted": root.find("{%s}EncryptedAssertion" % SAML) is not None,
                      "plain_assertion": root.find("{%s}Assertion" % SAML) is not None,
                      "response_signed": root.find("{%s}Signature" % DS) is not None,
                      "encryption_methods": sorted({m.get("Algorithm") for m in root.iter("{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod")})}))


def samlreplace(b64, old, new):
    # The same base64 SAML message with one text value replaced (signatures untouched).
    xml = base64.b64decode(b64)
    if old.encode() not in xml:
        sys.exit("value not found")
    print(base64.b64encode(xml.replace(old.encode(), new.encode(), 1)).decode())


def redirectrequest(url):
    # The decoded AuthnRequest of an HTTP-Redirect binding URL, as JSON.
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    root = ET.fromstring(zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15))
    pol = root.find("{%s}NameIDPolicy" % SAMLP)
    print(json.dumps({"id": root.get("ID"), "destination": root.get("Destination"), "acs": root.get("AssertionConsumerServiceURL"),
                      "binding": root.get("ProtocolBinding"), "issuer": root.findtext("{%s}Issuer" % SAML),
                      "name_id_format": pol.get("Format") if pol is not None else None,
                      "signed": "Signature" in q, "sig_alg": q.get("SigAlg", [None])[0]}))


def qset(url, name, value):
    # The URL with one query parameter replaced, keeping the order of the others.
    u = urllib.parse.urlsplit(url)
    parts = [p for p in u.query.split("&") if p]
    out = [(name + "=" + urllib.parse.quote(value, safe="")) if p.split("=", 1)[0] == name else p for p in parts]
    print(urllib.parse.urlunsplit(u._replace(query="&".join(out))))


def query(url, name):
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    print(q.get(name, [""])[0])


def jwt(token):
    p = token.split(".")[1]
    print(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())


def jwtheader(token):
    p = token.split(".")[0]
    print(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)).decode())


globals()[sys.argv[1]](*sys.argv[2:])
PY
helper() { python3 -I "$WORK/helper.py" "$@"; }

# c: curl with the test CA and the two host names pinned to the published ports.
c() {
	curl -sS --cacert "$WORK/tls/ca.pem" --resolve "$PA_HOST:$PA_PORT:127.0.0.1" --resolve "$KC_HOST:$KC_PORT:127.0.0.1" "$@"
}

totp_fresh() { # secret: a code for a time step not used before (replay protection)
	_last=$(cat "$WORK/totp.step" 2>/dev/null || echo 0)
	while :; do
		_step=$(($(date +%s) / 30))
		[ "$_step" -gt "$_last" ] && break
		sleep 1
	done
	echo "$_step" >"$WORK/totp.step"
	helper totp "$1" "$_step"
}

# api METHOD PATH [BEARER] [JSON]: ProudAuth realm API; body to $WORK/resp.json, prints the status.
api() {
	_m=$1 _p=$2 _t=${3:-} _b=${4:-}
	set -- -o "$WORK/resp.json" -w '%{http_code}' -X "$_m" "$API$_p"
	if [ -n "$_t" ]; then set -- "$@" -H "Authorization: Bearer $_t"; fi
	if [ -n "$_b" ]; then set -- "$@" -H 'Content-Type: application/json' --data "$_b"; fi
	c "$@"
}

admin() { # METHOD PATH [JSON] EXPECTED-STATUS: ProudAuth administrator call
	_code=$(api "$1" "$2" "$ADMIN_TOKEN" "${3:-}")
	[ "$_code" = "$4" ] || fail "ProudAuth $1 $2: expected $4, got $_code $(cat "$WORK/resp.json")"
}

token_post() { # BASIC-USER:PASS form-args...: ProudAuth token endpoint; body to $WORK/token.json, prints the status
	_u=$1
	shift
	c -o "$WORK/token.json" -w '%{http_code}' -u "$_u" "$@" "$ISSUER/oauth/token"
}

kc_bearer() { # a Keycloak master-realm administrator token (cached for 40 s)
	_now=$(date +%s)
	if [ "$_now" -ge "$(cat "$WORK/kc.token.exp" 2>/dev/null || echo 0)" ]; then
		_code=$(c -o "$WORK/kc.tokenresp" -w '%{http_code}' -d grant_type=password -d client_id=admin-cli -d username=admin \
			--data-urlencode "password=$KC_ADMIN_PW" "$KC/realms/master/protocol/openid-connect/token")
		[ "$_code" = 200 ] || fail "Keycloak administrator token: $_code $(cat "$WORK/kc.tokenresp")"
		jq -r .access_token "$WORK/kc.tokenresp" >"$WORK/kc.token"
		echo $((_now + 40)) >"$WORK/kc.token.exp"
	fi
	cat "$WORK/kc.token"
}

# kc METHOD PATH [BODY [CONTENT-TYPE]] EXPECTED-STATUS: Keycloak admin REST call
# under /admin/realms; BODY may be @file. Response body in $WORK/kc.json.
kc() {
	_m=$1 _p=$2
	shift 2
	_want=
	_b=
	_ct=application/json
	case $# in
	1) _want=$1 ;;
	2) _b=$1 _want=$2 ;;
	3) _b=$1 _ct=$2 _want=$3 ;;
	esac
	set -- -o "$WORK/kc.json" -w '%{http_code}' -X "$_m" -H "Authorization: Bearer $(kc_bearer)"
	if [ -n "$_b" ]; then set -- "$@" -H "Content-Type: $_ct" --data-binary "$_b"; fi
	_code=$(c "$@" "$KC/admin/realms$_p")
	case " $_want " in
	*" $_code "*) ;;
	*) fail "Keycloak $_m $_p: expected $_want, got $_code $(head -c 600 "$WORK/kc.json")" ;;
	esac
}

mailbox_code() { # recipient: newest email verification code from the development sink
	_i=0
	while [ "$_i" -lt 40 ]; do
		_code=$(curl -fsS "$INTERNAL/dev/mailbox?realm=$REALM&recipient=$1" 2>/dev/null |
			jq -r '[.items[]? | select(.template == "email_verification")][0].body // empty' |
			grep -Eo '(^|[^0-9])[0-9]{6}([^0-9]|$)' | grep -Eo '[0-9]{6}' | head -n 1 || true)
		if [ -n "$_code" ] && [ "$_code" != "$(cat "$WORK/mail.last.$1" 2>/dev/null)" ]; then
			echo "$_code" >"$WORK/mail.last.$1"
			echo "$_code"
			return 0
		fi
		_i=$((_i + 1))
		sleep 0.5
	done
	return 1
}

# ------------------------------------------------- the browser (curl jar) ---

# nav JAR URL: GET URL in the browser JAR and follow redirects until a
# response that is not a redirect, or a URL under one of the prefixes in STOP
# (the login UI and the application callbacks, which nothing serves). Sets
# NAV_URL and NAV_STATUS ("stop" when a stop prefix was reached); the last
# body is in $WORK/page.html.
nav() {
	_jar=$1 _url=$2
	_n=0
	while :; do
		for _p in $STOP; do
			case $_url in "$_p"*)
				NAV_URL=$_url NAV_STATUS=stop
				return 0
				;;
			esac
		done
		_n=$((_n + 1))
		[ "$_n" -le 25 ] || fail "too many redirects at $_url"
		_out=$(c -b "$_jar" -c "$_jar" -o "$WORK/page.html" -w '%{http_code} %{redirect_url}' "$_url")
		NAV_STATUS=${_out%% *}
		case $NAV_STATUS in
		301 | 302 | 303 | 307) _url=${_out#* } ;;
		*)
			NAV_URL=$_url
			return 0
			;;
		esac
	done
}

# submit JAR [FORM-ID-OR-FIELD] [NAME=VALUE...]: submit the form of the last
# page (first form, or the one with that id or field) with the overrides, then
# follow redirects as nav does.
submit() {
	_jar=$1 _want=${2:-}
	[ $# -lt 2 ] || shift 2
	[ $# -ne 1 ] || shift 1
	_f=$(helper form "$WORK/page.html" "$NAV_URL" "$WORK/form.body" "$_want" "$@") || fail "no form to submit at $NAV_URL"
	_method=${_f%% *} _action=${_f#* }
	if [ "$_method" = POST ]; then
		_out=$(c -b "$_jar" -c "$_jar" -o "$WORK/page.html" -w '%{http_code} %{redirect_url}' -H 'Content-Type: application/x-www-form-urlencoded' \
			--data-binary "@$WORK/form.body" "$_action")
	else
		_out=$(c -b "$_jar" -c "$_jar" -o "$WORK/page.html" -w '%{http_code} %{redirect_url}' "$_action?$(cat "$WORK/form.body")")
	fi
	NAV_STATUS=${_out%% *}
	NAV_URL=$_action
	case $NAV_STATUS in 301 | 302 | 303 | 307) nav "$_jar" "${_out#* }" ;; esac
}

# pages JAR USER PASSWORD: from the current page, complete what the
# counterpart shows (a Keycloak login form, auto-submitting SAML forms) until a
# STOP prefix is reached.
pages() {
	_bjar=$1 _user=$2 _pass=$3
	_steps=0
	while [ "$NAV_STATUS" != stop ]; do
		_steps=$((_steps + 1))
		[ "$_steps" -le 10 ] || fail "too many pages at $NAV_URL"
		[ "$NAV_STATUS" = 200 ] || fail "browser: HTTP $NAV_STATUS at $NAV_URL"
		_forms=$(helper forminfo "$WORK/page.html")
		if printf '%s' "$_forms" | jq -e 'any(.[]; .inputs | index("SAMLResponse") or index("SAMLRequest"))' >/dev/null; then
			submit "$_bjar"
		elif printf '%s' "$_forms" | jq -e 'any(.[]; .inputs | index("password"))' >/dev/null; then
			[ -n "$_user" ] || fail "unexpected login form at $NAV_URL"
			submit "$_bjar" password "username=$_user" "password=$_pass"
			_user=
		else
			fail "unexpected page at $NAV_URL (forms: $_forms)"
		fi
	done
}

browse() { # JAR URL USER PASSWORD: nav, then pages
	nav "$1" "$2"
	pages "$1" "$3" "$4"
}

# ------------------------------------------ ProudAuth login transactions ---

# tx_call NAME [JSON]: a transaction step (POST .../NAME), or the state (GET)
# when NAME is "-". Browser mode (TX_MODE=browser) sends the cookie jar
# TX_JAR, Origin and the CSRF token, as a login UI does; headless mode sends
# the continuation token. The state goes to $WORK/state.json.
tx_call() {
	_name=$1 _body=${2:-}
	set -- -o "$WORK/step.json" -w '%{http_code}'
	if [ "$TX_MODE" = browser ]; then
		set -- "$@" -b "$TX_JAR" -c "$TX_JAR" -H "Origin: $ORIGIN"
		[ "$_name" = - ] || set -- "$@" -H "X-CSRF-Token: $TX_CSRF"
	else
		set -- "$@" -H "X-Transaction-Token: $TX_CONT"
	fi
	if [ "$_name" = - ]; then
		_code=$(c "$@" "$API/auth/transactions/$TX_ID")
	else
		_code=$(c "$@" -X POST -H 'Content-Type: application/json' --data "$_body" "$API/auth/transactions/$TX_ID/$_name")
	fi
	case $_code in
	2*)
		cp "$WORK/step.json" "$WORK/state.json"
		return 0
		;;
	esac
	LOGIN_ERROR="$_name: HTTP $_code $(jq -c '{code, detail, reason}' "$WORK/step.json" 2>/dev/null || cat "$WORK/step.json")"
	return 1
}

# ui_open JAR LOGIN-UI-URL: what a login UI does when the browser arrives:
# read the transaction (cookie) and its CSRF token.
ui_open() {
	TX_MODE=browser TX_JAR=$1
	TX_ID=$(helper query "$2" transaction_id)
	[ -n "$TX_ID" ] || fail "no transaction_id in the login UI URL $2"
	tx_call - || fail "login UI: $LOGIN_ERROR"
	TX_CSRF=$(jq -r '.csrf_token // empty' "$WORK/state.json")
	[ -n "$TX_CSRF" ] || fail "no CSRF token for the browser transaction"
}

# tx_drive IDENTIFIER PASSWORD EMAIL: complete the open transaction with the
# local account's factors (password, email verification through the
# development sink, TOTP for the administrator) until redirect_to. Returns 1
# with LOGIN_ERROR set when refused.
tx_drive() {
	_id=$1 _pw=$2 _email=$3
	LOGIN_ERROR=
	_n=0
	while [ "$_n" -lt 20 ]; do
		_n=$((_n + 1))
		TX_REDIRECT=$(jq -r '.redirect_to // empty' "$WORK/state.json")
		[ -z "$TX_REDIRECT" ] || return 0
		_status=$(jq -r .status "$WORK/state.json")
		if [ "$_status" != pending ]; then
			LOGIN_ERROR="login ended: $(jq -c '{status, error, notice}' "$WORK/state.json")"
			return 1
		fi
		_types=" $(jq -r '[.next_actions[]?.type] | join(" ")' "$WORK/state.json") "
		case $_types in
		*" identify "*) tx_call identify "$(jq -nc --arg i "$_id" '{identifier:$i}')" || return 1 ;;
		*" password "*) tx_call password "$(jq -nc --arg p "$_pw" '{password:$p}')" || return 1 ;;
		*" verify_email "*)
			tx_call otp/send '{"purpose":"verify_email"}' || return 1
			_otp=$(mailbox_code "$_email") || {
				LOGIN_ERROR="no verification email for $_email in the development sink"
				return 1
			}
			tx_call otp/verify "$(jq -nc --arg c "$_otp" '{code:$c}')" || return 1
			;;
		*" enroll_totp "*)
			tx_call totp/enroll '{}' || return 1
			jq -r '.one_time.totp.secret' "$WORK/state.json" >"$WORK/totp.secret"
			tx_call totp/activate "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')" || return 1
			;;
		*" totp "*) tx_call totp "$(jq -nc --arg c "$(totp_fresh "$(cat "$WORK/totp.secret")")" '{code:$c}')" || return 1 ;;
		*" consent "*) tx_call consent '{"approve":true}' || return 1 ;;
		*)
			LOGIN_ERROR="unhandled step(s):$_types $(jq -c '{error, notice}' "$WORK/state.json")"
			return 1
			;;
		esac
	done
	LOGIN_ERROR="too many steps"
	return 1
}

admin_login() {
	set -- $(helper pkce)
	_verifier=$1
	_code=$(api POST /auth/transactions "" "$(jq -nc --arg ch "$2" --arg res "$ISSUER/admin" \
		'{client_id:"proudauth-cli", redirect_uri:"http://127.0.0.1/callback", scope:"proudauth:admin", resource:[$res], code_challenge:$ch, code_challenge_method:"S256", state:"interop"}')")
	[ "$_code" = 201 ] || fail "administrator transaction: $_code $(cat "$WORK/resp.json")"
	TX_MODE=headless
	TX_ID=$(jq -r .transaction_id "$WORK/resp.json")
	TX_CONT=$(jq -r .continuation_token "$WORK/resp.json")
	jq .state "$WORK/resp.json" >"$WORK/state.json"
	# The bootstrap administrator identifies by username until the address is verified.
	tx_drive interop-admin "$ADMIN_PW" admin@interop.test || fail "administrator sign-in: $LOGIN_ERROR"
	_authz=$(helper query "$TX_REDIRECT" code)
	_code=$(c -o "$WORK/admin.json" -w '%{http_code}' -d grant_type=authorization_code -d client_id=proudauth-cli --data-urlencode "code=$_authz" \
		--data-urlencode "code_verifier=$_verifier" --data-urlencode "redirect_uri=http://127.0.0.1/callback" --data-urlencode "resource=$ISSUER/admin" "$ISSUER/oauth/token")
	[ "$_code" = 200 ] || fail "administrator token: $_code $(cat "$WORK/admin.json")"
	ADMIN_TOKEN=$(jq -r .access_token "$WORK/admin.json")
}

pw_of() { echo "$1 interop passphrase 2026 keycloak"; }

create_user() { # name given family: admin-created account that must verify its email at first sign-in
	admin POST /users "$(jq -nc --arg n "$1" --arg g "$2" --arg f "$3" \
		'{email:($n + "@interop.test"), username:$n, display_name:($g + " " + $f), given_name:$g, family_name:$f, send_setup_email:false, required_actions:["verify_email"]}')" 201
	jq -r .user.id "$WORK/resp.json" >"$WORK/user.$1"
	_setup=$(jq -r .setup_token "$WORK/resp.json")
	_code=$(api POST /account-setup "" "$(jq -nc --arg t "$_setup" --arg p "$(pw_of "$1")" '{setup_token:$t, password:$p}')")
	[ "$_code" = 200 ] || fail "account setup for $1: $_code $(cat "$WORK/resp.json")"
}

# pa_authorize JAR [EXTRA-QUERY]: start a browser sign-in at ProudAuth for
# interop-web (authorization code, PKCE S256, openid email profile) and open
# the login UI.
pa_authorize() {
	set -- "$1" "${2:-}" $(helper pkce)
	PA_VERIFIER=$3
	STOP="$LOGIN_UI $APP"
	nav "$1" "$ISSUER/oauth/authorize?response_type=code&client_id=interop-web&redirect_uri=$(printf %s "$APP_CALLBACK" | jq -sRr @uri)&scope=openid%20email%20profile&state=pa-state&nonce=pa-nonce&code_challenge=$4&code_challenge_method=S256$2"
	[ "$NAV_STATUS" = stop ] && case $NAV_URL in "$LOGIN_UI"*) true ;; *) false ;; esac ||
		fail "ProudAuth authorize did not reach the login UI: $NAV_STATUS $NAV_URL"
	ui_open "$1" "$NAV_URL"
}

pa_token() { # REDIRECT-TO OUT: redeem the interop-web code
	_code=$(token_post "interop-web:$WEB_SECRET" -d grant_type=authorization_code --data-urlencode "code=$(helper query "$1" code)" \
		--data-urlencode "code_verifier=$PA_VERIFIER" --data-urlencode "redirect_uri=$APP_CALLBACK")
	[ "$_code" = 200 ] || fail "interop-web token exchange: $_code $(cat "$WORK/token.json")"
	cp "$WORK/token.json" "$2"
}

# federate JAR ALIAS KC-USER KC-PASSWORD: in the open browser transaction, start
# the upstream connection, sign in at Keycloak and come back to the login UI.
federate() {
	tx_call federation/start "$(jq -nc --arg p "$2" '{provider:$p}')" || fail "federation start ($2): $LOGIN_ERROR"
	_ext=$(jq -r '.external_redirect // empty' "$WORK/state.json")
	[ -n "$_ext" ] || fail "no external_redirect for $2: $(cat "$WORK/state.json")"
	STOP="$LOGIN_UI $APP"
	browse "$1" "$_ext" "$3" "$4"
	case $NAV_URL in "$LOGIN_UI"*) ;; *) fail "federation $2 did not return to the login UI: $NAV_URL" ;; esac
	FED_RETURN=$NAV_URL
}

# kc_rp_login JAR IDP: start a sign-in at Keycloak's consumer realm for the
# rp-app client with kc_idp_hint, so Keycloak brokers straight to ProudAuth;
# follows redirects up to a STOP prefix.
kc_rp_login() {
	set -- "$1" "$2" $(helper pkce)
	KC_VERIFIER=$3
	nav "$1" "$KC/realms/consumer/protocol/openid-connect/auth?response_type=code&client_id=rp-app&redirect_uri=$(printf %s "$APP_CALLBACK" | jq -sRr @uri)&scope=openid&state=kc-state&nonce=kc-nonce&code_challenge=$4&code_challenge_method=S256&kc_idp_hint=$2"
}

kc_rp_token() { # REDIRECT OUT: redeem the rp-app code at Keycloak
	_code=$(c -o "$2" -w '%{http_code}' -d grant_type=authorization_code -d client_id=rp-app --data-urlencode "code=$(helper query "$1" code)" \
		--data-urlencode "code_verifier=$KC_VERIFIER" --data-urlencode "redirect_uri=$APP_CALLBACK" "$KC/realms/consumer/protocol/openid-connect/token")
	[ "$_code" = 200 ] || fail "Keycloak rp-app token exchange: $_code $(cat "$2")"
}

kc_user() { # REALM QUERY: the single Keycloak user matching the query, to $WORK/kcuser.json
	kc GET "/$1/users?$2&exact=true&briefRepresentation=false" 200
	[ "$(jq length "$WORK/kc.json")" = 1 ] || fail "Keycloak realm $1: expected one user for $2, got $(cat "$WORK/kc.json")"
	jq '.[0]' "$WORK/kc.json" >"$WORK/kcuser.json"
}

# linked_subjects USER-ID: "issuer subject" of the account's linked identities.
linked_subjects() {
	docker exec "$PG" psql -X -U proudauth -d proudauth -Atq -c "SELECT upstream_issuer || ' ' || upstream_subject FROM external_identities WHERE user_id = '$1' ORDER BY created_at"
}

pa_user_by_email() { # EMAIL: prints the ProudAuth user ID (exactly one match)
	admin GET "/users?q=$(printf %s "$1" | jq -sRr @uri)" "" 200
	[ "$(jq '.items | length' "$WORK/resp.json")" = 1 ] || fail "ProudAuth: expected one user for $1, got $(cat "$WORK/resp.json")"
	jq -r '.items[0].id' "$WORK/resp.json"
}

# ------------------------------------------------------------- 0. set up ---

log "work directory $WORK"
mkdir -p "$WORK/bin"
if [ -n "${INTEROP_BIN:-}" ]; then
	cp "$INTEROP_BIN/identity-server" "$INTEROP_BIN/identity-worker" "$INTEROP_BIN/identity-cli" "$WORK/bin/"
else
	log "building identity-server, identity-worker and identity-cli for linux/$(go env GOARCH)"
	(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=$(go env GOARCH) go build -trimpath -o "$WORK/bin/" ./cmd/identity-server ./cmd/identity-worker ./cmd/identity-cli)
fi
for img in "$KC_IMAGE" "$PG_IMAGE" "$RUN_IMAGE"; do
	docker image inspect "$img" >/dev/null 2>&1 || docker pull "$img"
done

# A test CA and one server certificate for both host names. The extensions
# come from config files written here, not from the platform's openssl.cnf.
mkdir -p "$WORK/tls" "$WORK/secrets"
chmod 700 "$WORK/secrets"
(
	cd "$WORK/tls"
	printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = ProudAuth interop test CA\n[ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n' >ca.cnf
	printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = %s\n' "$PA_HOST" >leaf.cnf
	printf 'subjectAltName = DNS:%s,DNS:%s\nextendedKeyUsage = serverAuth\nbasicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature,keyEncipherment\n' "$PA_HOST" "$KC_HOST" >ext.cnf
	openssl req -x509 -config ca.cnf -extensions ca -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 2 >/dev/null 2>&1
	openssl req -new -config leaf.cnf -newkey rsa:2048 -nodes -keyout tls.key -out tls.csr >/dev/null 2>&1
	openssl x509 -req -in tls.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile ext.cnf -out tls.pem >/dev/null 2>&1
	# Keycloak runs as its own user: the throwaway key must be readable.
	chmod 644 tls.key tls.pem ca.pem
	rm -f ca.key tls.csr ca.cnf leaf.cnf ext.cnf ca.srl
) || fail "cannot create the test certificates with openssl"
openssl verify -CAfile "$WORK/tls/ca.pem" "$WORK/tls/tls.pem" >/dev/null 2>&1 || fail "the test server certificate does not verify"
ok "test CA and server certificate for $PA_HOST and $KC_HOST"

PG_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
KC_ADMIN_PW=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
ADMIN_PW="interop administrator passphrase 2026"
KC_CLIENT_SECRET=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
KC_USER_PW="keycloak user passphrase 2026"
RUN_AS="$(id -u):$(id -g)"

docker network create "$NET" >/dev/null
docker run -d --name "$PG" --network "$NET" -e POSTGRES_USER=proudauth -e POSTGRES_PASSWORD="$PG_PW" -e POSTGRES_DB=proudauth "$PG_IMAGE" >/dev/null
docker run -d --name "$KEYCLOAK" --network "$NET" --network-alias "$KC_HOST" -p "127.0.0.1:$KC_PORT:$KC_PORT" -v "$WORK/tls:/tls:ro" \
	-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PW" \
	"$KC_IMAGE" start-dev --http-enabled=false --https-port="$KC_PORT" --https-certificate-file=/tls/tls.pem \
	--https-certificate-key-file=/tls/tls.key --truststore-paths=/tls/ca.pem >/dev/null

printf '%s' "postgres://proudauth:$PG_PW@$PG:5432/proudauth?sslmode=disable" >"$WORK/secrets/database_url"
chmod 600 "$WORK/secrets/database_url"
cat >"$WORK/config.yaml" <<EOF
# Generated by scripts/interop-keycloak.sh.
mode: development
server:
  public_listen: "0.0.0.0:$PA_PORT"
  internal_listen: "0.0.0.0:9090"
  public_origin: "$ORIGIN"
  tls_cert_file: /work/tls/tls.pem
  tls_key_file: /work/tls/tls.key
storage:
  database_url: "file:/work/secrets/database_url"
keys:
  root_keys:
    - version: 1
      ref: "file:/work/secrets/root_key"
  active_version: 1
delivery:
  email:
    adapter: dev_sink
  # Back-channel logout to Keycloak on the Docker network. Delivery trusts the
  # system roots, which SSL_CERT_FILE points at the test CA.
  allow_private_webhooks: true
federation:
  allow_private_network: true
  ca_file: /work/tls/ca.pem
saml:
  enabled: true
observability:
  log_format: json
EOF

# cli NAME ARGS...: identity-cli in a container on the network; output in $WORK/NAME.out.
cli() {
	_name=$1
	shift
	docker run --rm --network "$NET" --user "$RUN_AS" -v "$WORK:/work" -e PROUDAUTH_CONFIG=/work/config.yaml "$RUN_IMAGE" \
		/work/bin/identity-cli "$@" >"$WORK/$_name.out" 2>"$WORK/$_name.err" || {
		cat "$WORK/$_name.out" "$WORK/$_name.err" >&2
		fail "identity-cli $1 ($_name)"
	}
}

_i=0
until docker exec "$PG" pg_isready -h 127.0.0.1 -U proudauth -q 2>/dev/null; do
	_i=$((_i + 1))
	[ "$_i" -lt 120 ] || fail "PostgreSQL did not become ready"
	sleep 0.5
done
cli root-key generate-root-key
mv "$WORK/root-key.out" "$WORK/secrets/root_key"
chmod 600 "$WORK/secrets/root_key"
cli migrate migrate
cli realm-create realm-create -name "$REALM" -display-name "Interop" -login-ui-url "$LOGIN_UI"
cli bootstrap bootstrap -realm "$REALM" -email admin@interop.test -username interop-admin -ttl 10m
SETUP=$(awk '/one-time setup token/ {f=1; next} f && NF {print $1; exit}' "$WORK/bootstrap.out")
[ -n "$SETUP" ] || fail "no setup token in bootstrap output"

docker run -d --name "$SERVER" --network "$NET" --network-alias "$PA_HOST" --user "$RUN_AS" -v "$WORK:/work" -e SSL_CERT_FILE=/work/tls/ca.pem \
	-p "127.0.0.1:$PA_PORT:$PA_PORT" -p "127.0.0.1:$INTERNAL_PORT:9090" "$RUN_IMAGE" /work/bin/identity-server -config /work/config.yaml >/dev/null
docker run -d --name "$WORKER" --network "$NET" --user "$RUN_AS" -v "$WORK:/work" -e SSL_CERT_FILE=/work/tls/ca.pem \
	"$RUN_IMAGE" /work/bin/identity-worker -config /work/config.yaml >/dev/null
_i=0
until [ "$(c -o /dev/null -w '%{http_code}' "$ORIGIN/health/ready" 2>/dev/null)" = 200 ]; do
	_i=$((_i + 1))
	[ "$(docker inspect -f '{{.State.Running}}' "$SERVER")" = true ] || fail "identity-server exited"
	[ "$_i" -lt 120 ] || fail "identity-server did not become ready"
	sleep 0.5
done
ok "ProudAuth ready at $ORIGIN (realm $REALM, login UI $LOGIN_UI)"

code=$(api POST /account-setup "" "$(jq -nc --arg t "$SETUP" --arg p "$ADMIN_PW" '{setup_token:$t, password:$p}')")
[ "$code" = 200 ] || fail "administrator account setup: $code $(cat "$WORK/resp.json")"
admin_login
ok "ProudAuth administrator signed in (password, email verification, TOTP enrollment)"

_i=0
until [ "$(c -o /dev/null -w '%{http_code}' "$KC/realms/master/.well-known/openid-configuration" 2>/dev/null)" = 200 ]; do
	_i=$((_i + 1))
	[ "$(docker inspect -f '{{.State.Running}}' "$KEYCLOAK")" = true ] || fail "Keycloak exited"
	[ "$_i" -lt 240 ] || fail "Keycloak did not become ready"
	sleep 0.5
done
kc GET /master 200
KC_VERSION=$(docker logs "$KEYCLOAK" 2>&1 | sed -n 's/.*Keycloak \([0-9][0-9.]*\) on JVM.*/\1/p' | head -n 1)
ok "Keycloak ${KC_VERSION:-?} ready at $KC (start-dev, TLS, trusts the test CA)"

# Keycloak realms: "consumer" relies on ProudAuth (scenarios 1 and 3a);
# "upstream" is an identity provider for ProudAuth (scenarios 2 and 3b).
kc POST "" "$(jq -nc --arg cb "$APP_CALLBACK" --arg out "$APP_LOGGED_OUT" '{realm:"consumer", enabled:true,
	clients:[{clientId:"rp-app", publicClient:true, standardFlowEnabled:true, directAccessGrantsEnabled:false, redirectUris:[$cb],
		attributes:{"pkce.code.challenge.method":"S256", "post.logout.redirect.uris":$out}}]}')" 201
kc POST "" "$(jq -nc --arg pw "$KC_USER_PW" --arg sec "$KC_CLIENT_SECRET" --arg cb "$API/federation/kc-oidc/callback" \
	--arg cb2 "$API/federation/kc-oidc-wrong-secret/callback" --arg ret "$ISSUER/oidc/logout/upstream-return" '{realm:"upstream", enabled:true,
	users:[{username:"grace", email:"grace@upstream.test", emailVerified:true, firstName:"Grace", lastName:"Hopper", enabled:true,
			credentials:[{type:"password", value:$pw, temporary:false}]},
		{username:"linus", email:"linus@upstream.test", emailVerified:true, firstName:"Linus", lastName:"Pauling", enabled:true,
			realmRoles:["default-roles-upstream", "chemist", "reviewer"], credentials:[{type:"password", value:$pw, temporary:false}]}],
	roles:{realm:[{name:"chemist"}, {name:"reviewer"}]},
	clients:[{clientId:"proudauth", protocol:"openid-connect", publicClient:false, clientAuthenticatorType:"client-secret", secret:$sec,
		standardFlowEnabled:true, directAccessGrantsEnabled:false, redirectUris:[$cb, $cb2],
		attributes:{"pkce.code.challenge.method":"S256", "post.logout.redirect.uris":$ret}}]}')" 201
ok "Keycloak realms consumer (client rp-app) and upstream (users grace, linus; client proudauth) created"

# ProudAuth objects shared by the scenarios.
admin POST /clients "$(jq -nc --arg cb "$APP_CALLBACK" --arg out "$APP_LOGGED_OUT" '{client_id:"interop-web", name:"Interop web app",
	client_type:"confidential", first_party:true, grant_types:["authorization_code"], redirect_uris:[$cb], post_logout_redirect_uris:[$out]}')" 201
WEB_SECRET=$(jq -r .client_secret "$WORK/resp.json")
create_user ada Ada Lovelace
create_user alan Alan Turing
create_user edsger Edsger Dijkstra
ok "ProudAuth client interop-web and users ada, alan, edsger created"

# ---------------------------- 1. ProudAuth as OP, Keycloak as relying party ---

log "1. ProudAuth as OpenID Provider for a Keycloak OIDC identity provider"
BROKER=$KC/realms/consumer/broker
admin POST /clients "$(jq -nc --arg r1 "$BROKER/proudauth/endpoint" --arg r2 "$BROKER/proudauth-wrong-secret/endpoint" \
	--arg out "$BROKER/proudauth/endpoint/logout_response" --arg bc "$KC/realms/consumer/protocol/openid-connect/logout/backchannel-logout" \
	'{client_id:"keycloak-broker", name:"Keycloak consumer realm", client_type:"confidential", token_endpoint_auth_method:"client_secret_basic",
	first_party:true, grant_types:["authorization_code"], redirect_uris:[$r1, $r2], post_logout_redirect_uris:[$out], backchannel_logout_uri:$bc}')" 201
BROKER_SECRET=$(jq -r .client_secret "$WORK/resp.json")
kc POST /consumer/identity-provider/import-config "$(jq -nc --arg u "$ISSUER/.well-known/openid-configuration" '{providerId:"oidc", fromUrl:$u}')" 200
jq . "$WORK/kc.json" >"$WORK/kc-oidc-import.json"
[ "$(jq -r .issuer "$WORK/kc-oidc-import.json")" = "$ISSUER" ] || fail "Keycloak imported issuer $(jq -r .issuer "$WORK/kc-oidc-import.json")"
for alias in proudauth proudauth-wrong-secret; do
	secret=$BROKER_SECRET bc=true
	[ "$alias" = proudauth ] || secret=wrong-$BROKER_SECRET bc=false
	kc POST /consumer/identity-provider/instances "$(jq -c --arg a "$alias" --arg s "$secret" --arg bc "$bc" '{alias:$a, providerId:"oidc", enabled:true,
		trustEmail:false, firstBrokerLoginFlowAlias:"first broker login",
		config:(. + {clientId:"keycloak-broker", clientSecret:$s, clientAuthMethod:"client_secret_basic", defaultScope:"openid email profile",
			pkceEnabled:"true", pkceMethod:"S256", validateSignature:"true", useJwksUrl:"true", syncMode:"IMPORT", backchannelSupported:$bc})}' \
		"$WORK/kc-oidc-import.json")" 201
done
ok "Keycloak identity providers proudauth and proudauth-wrong-secret configured from ProudAuth discovery ($(jq -c '{authorizationUrl, tokenUrl, jwksUrl, logoutUrl}' "$WORK/kc-oidc-import.json"))"

JAR1=$WORK/jar.ada
STOP="$LOGIN_UI $APP"
kc_rp_login "$JAR1" proudauth
case $NAV_URL in "$LOGIN_UI"*) ;; *) fail "Keycloak did not send the browser to the ProudAuth login UI: $NAV_STATUS $NAV_URL" ;; esac
ui_open "$JAR1" "$NAV_URL"
tx_drive ada "$(pw_of ada)" ada@interop.test || fail "ada's sign-in at ProudAuth: $LOGIN_ERROR"
case $TX_REDIRECT in "$BROKER/proudauth/endpoint?"*) ;; *) fail "redirect_to is not Keycloak's broker endpoint: $TX_REDIRECT" ;; esac
BROKER_CODE=$(helper query "$TX_REDIRECT" code)
[ "$(helper query "$TX_REDIRECT" iss)" = "$ISSUER" ] || fail "authorization response without iss"
ok "ada signed in at ProudAuth through the login transaction (browser mode: cookie, CSRF, Origin; password, email verification)"
STOP="$LOGIN_UI $APP"
browse "$JAR1" "$TX_REDIRECT" "" ""
case $NAV_URL in "$APP_CALLBACK?"*) ;; *) fail "Keycloak did not complete the brokered sign-in: $NAV_URL" ;; esac
kc_rp_token "$NAV_URL" "$WORK/kc-ada.json"
ADA_ID=$(cat "$WORK/user.ada")
kc_user consumer "email=ada@interop.test"
KC_ADA=$(jq -r .id "$WORK/kcuser.json")
jq -e '.firstName == "Ada" and .lastName == "Lovelace" and .username == "ada"' "$WORK/kcuser.json" >/dev/null ||
	fail "brokered Keycloak user: $(jq -c '{username, email, firstName, lastName}' "$WORK/kcuser.json")"
kc GET "/consumer/users/$KC_ADA/federated-identity" 200
jq -e --arg s "$ADA_ID" 'length == 1 and .[0].identityProvider == "proudauth" and .[0].userId == $s' "$WORK/kc.json" >/dev/null ||
	fail "federated identity link: $(cat "$WORK/kc.json") (ProudAuth sub $ADA_ID)"
[ "$(helper jwt "$(jq -r .id_token "$WORK/kc-ada.json")" | jq -r .email)" = ada@interop.test ] || fail "Keycloak ID token email"
ok "Keycloak exchanged the code, validated the ID token, created user ada (email, names) linked to ProudAuth sub $ADA_ID"
admin GET "/users/$ADA_ID/sessions" "" 200
jq -e '[.items[] | select(.state == "active")] | length == 1' "$WORK/resp.json" >/dev/null || fail "ProudAuth sessions of ada: $(cat "$WORK/resp.json")"

# RP-initiated logout at Keycloak propagates to ProudAuth's end-session endpoint.
STOP="$APP $LOGIN_UI"
nav "$JAR1" "$KC/realms/consumer/protocol/openid-connect/logout?id_token_hint=$(jq -r .id_token "$WORK/kc-ada.json")&post_logout_redirect_uri=$(printf %s "$APP_LOGGED_OUT" | jq -sRr @uri)&state=bye"
case $NAV_URL in "$APP_LOGGED_OUT?"*) ;; *) fail "logout did not return to the application: $NAV_STATUS $NAV_URL" ;; esac
[ "$(helper query "$NAV_URL" state)" = bye ] || fail "logout state lost: $NAV_URL"
admin GET "/users/$ADA_ID/sessions" "" 200
jq -e '[.items[] | select(.state == "active")] | length == 0' "$WORK/resp.json" >/dev/null || fail "ProudAuth session of ada still active after logout: $(cat "$WORK/resp.json")"
kc GET "/consumer/users/$KC_ADA/sessions" 200
[ "$(jq length "$WORK/kc.json")" = 0 ] || fail "Keycloak session of ada still active"
ok "RP-initiated logout: Keycloak -> ProudAuth end_session_endpoint (id_token_hint, post_logout_redirect_uri, state) -> Keycloak -> application; both sessions ended"

# Negative: the code Keycloak redeemed is refused on replay, which revokes its grant.
code=$(token_post "keycloak-broker:$BROKER_SECRET" -d grant_type=authorization_code --data-urlencode "code=$BROKER_CODE" \
	--data-urlencode "code_verifier=$(helper pkce | cut -d' ' -f1)" --data-urlencode "redirect_uri=$BROKER/proudauth/endpoint")
[ "$code" = 400 ] && jq -e '.error == "invalid_grant" and (.error_description | test("already used"))' "$WORK/token.json" >/dev/null ||
	fail "replayed authorization code: $code $(cat "$WORK/token.json")"
ok "replayed authorization code refused (invalid_grant: $(jq -r .error_description "$WORK/token.json"))"

# Negative: Keycloak configured with a wrong client secret is refused at the token endpoint.
JAR1B=$WORK/jar.ada-wrong
STOP="$LOGIN_UI $APP"
kc_rp_login "$JAR1B" proudauth-wrong-secret
ui_open "$JAR1B" "$NAV_URL"
tx_drive ada "$(pw_of ada)" ada@interop.test || fail "ada's second sign-in: $LOGIN_ERROR"
STOP="$LOGIN_UI $APP"
nav "$JAR1B" "$TX_REDIRECT"
[ "$NAV_STATUS" != stop ] || fail "Keycloak completed a sign-in with a wrong client secret"
grep -qi 'error\|unexpected' "$WORK/page.html" || fail "Keycloak did not show an error page: HTTP $NAV_STATUS"
kc GET "/consumer/users?idpAlias=proudauth-wrong-secret" 200
[ "$(jq length "$WORK/kc.json")" = 0 ] || fail "Keycloak created a user through the identity provider with the wrong secret"
code=$(token_post "keycloak-broker:wrong" -d grant_type=authorization_code -d code=x -d code_verifier=x -d redirect_uri=x)
[ "$code" = 401 ] && [ "$(jq -r .error "$WORK/token.json")" = invalid_client ] || fail "wrong client secret: $code $(cat "$WORK/token.json")"
ok "wrong client secret at Keycloak: ProudAuth's token endpoint answered invalid_client and Keycloak showed an error (HTTP $NAV_STATUS)"

# Back-channel logout (SES-017): revoking ada's sessions at ProudAuth sends a
# logout token to Keycloak, which ends the brokered session.
JAR1C=$WORK/jar.ada-bc
STOP="$LOGIN_UI $APP"
kc_rp_login "$JAR1C" proudauth
ui_open "$JAR1C" "$NAV_URL"
tx_drive ada "$(pw_of ada)" ada@interop.test || fail "ada's third sign-in: $LOGIN_ERROR"
STOP="$LOGIN_UI $APP"
browse "$JAR1C" "$TX_REDIRECT" "" ""
case $NAV_URL in "$APP_CALLBACK?"*) ;; *) fail "Keycloak did not complete the brokered sign-in: $NAV_URL" ;; esac
kc GET "/consumer/users/$KC_ADA/sessions" 200
[ "$(jq length "$WORK/kc.json")" = 1 ] || fail "expected one Keycloak session for ada: $(cat "$WORK/kc.json")"
admin POST "/users/$ADA_ID/revoke-sessions" '{}' 200
_i=0
until kc GET "/consumer/users/$KC_ADA/sessions" 200 && [ "$(jq length "$WORK/kc.json")" = 0 ]; do
	_i=$((_i + 1))
	[ "$_i" -lt 60 ] || fail "Keycloak session of ada survived ProudAuth's back-channel logout"
	sleep 0.5
done
ok "back-channel logout: ProudAuth revoked ada's sessions and delivered a logout token; Keycloak ended its brokered session"

# ------------------------------- 2. Keycloak as upstream OP for ProudAuth ---

log "2. Keycloak as upstream OpenID Provider for a ProudAuth OIDC connection"
for alias in kc-oidc kc-oidc-wrong-secret; do
	secret=$KC_CLIENT_SECRET
	[ "$alias" = kc-oidc ] || secret=wrong-$KC_CLIENT_SECRET
	admin POST /identity-providers "$(jq -nc --arg a "$alias" --arg i "$KC/realms/upstream" --arg s "$secret" '{alias:$a, display_name:"Keycloak upstream",
		issuer:$i, client_secret:$s, config:{client_id:"proudauth"}, jit_provisioning:true}')" 201
done
admin GET /identity-providers "" 200
KC_OIDC_ID=$(jq -r '.items[] | select(.alias == "kc-oidc") | .id' "$WORK/resp.json")
admin POST "/identity-providers/$KC_OIDC_ID/test" "" 200
jq -e '.ok == true' "$WORK/resp.json" >/dev/null || fail "connection diagnostics: $(cat "$WORK/resp.json")"
ok "connections kc-oidc and kc-oidc-wrong-secret created; diagnostics against Keycloak's discovery: $(jq -c . "$WORK/resp.json" | cut -c1-200)"

JAR2=$WORK/jar.grace
pa_authorize "$JAR2"
federate "$JAR2" kc-oidc grace "$KC_USER_PW"
[ -z "$(helper query "$FED_RETURN" federation_error)" ] || fail "federation error: $FED_RETURN"
tx_call resume '{}' || fail "resume: $LOGIN_ERROR"
tx_drive "" "" "" || fail "grace's federated sign-in: $LOGIN_ERROR"
pa_token "$TX_REDIRECT" "$WORK/pa-grace.json"
GRACE_ID=$(pa_user_by_email grace@upstream.test)
helper jwt "$(jq -r .id_token "$WORK/pa-grace.json")" >"$WORK/grace-id.json"
jq -e --arg s "$GRACE_ID" '.sub == $s and .email == "grace@upstream.test" and .email_verified == true' "$WORK/grace-id.json" >/dev/null ||
	fail "ProudAuth ID token after federation: $(cat "$WORK/grace-id.json")"
kc_user upstream "username=grace"
KC_GRACE=$(jq -r .id "$WORK/kcuser.json")
admin GET "/users/$GRACE_ID/linked-identities" "" 200
jq -e '[.items[] | select(.provider == "kc-oidc" and .provenance == "jit")] | length == 1' "$WORK/resp.json" >/dev/null ||
	fail "ProudAuth linked identities of grace: $(cat "$WORK/resp.json")"
# The administration view leaves the upstream subject out; read it from the database.
[ "$(linked_subjects "$GRACE_ID")" = "$KC/realms/upstream $KC_GRACE" ] ||
	fail "ProudAuth linked identity: $(linked_subjects "$GRACE_ID") (Keycloak subject $KC_GRACE)"
ok "grace signed in through Keycloak's login form; JIT account $GRACE_ID (verified email) linked to $KC/realms/upstream subject $KC_GRACE"

# Negative: the callback URL cannot be used twice. prompt=login skips
# ProudAuth's SSO session; Keycloak's session answers without a form.
pa_authorize "$JAR2" "&prompt=login"
tx_call federation/start '{"provider":"kc-oidc"}' || fail "federation start: $LOGIN_ERROR"
STOP="$API/federation/kc-oidc/callback $LOGIN_UI $APP"
nav "$JAR2" "$(jq -r .external_redirect "$WORK/state.json")"
case $NAV_URL in "$API/federation/kc-oidc/callback?"*) CALLBACK=$NAV_URL ;; *) fail "Keycloak SSO did not return to the callback: $NAV_URL" ;; esac
STOP="$LOGIN_UI $APP"
nav "$JAR2" "$CALLBACK"
[ -z "$(helper query "$NAV_URL" federation_error)" ] || fail "second federated sign-in: $NAV_URL"
tx_call resume '{}' || fail "resume: $LOGIN_ERROR"
tx_drive "" "" "" || fail "grace's second sign-in: $LOGIN_ERROR"
pa_token "$TX_REDIRECT" "$WORK/pa-grace2.json"
[ "$(pa_user_by_email grace@upstream.test)" = "$GRACE_ID" ] || fail "second sign-in created another account"
ok "second sign-in (Keycloak SSO, no form) reuses the link: same account"
code=$(c -b "$JAR2" -o "$WORK/page.html" -w '%{http_code}' "$CALLBACK")
[ "$code" = 400 ] || fail "replayed federation callback answered $code"
ok "replayed federation callback refused (400)"

# Negative: a wrong upstream client secret fails the sign-in and creates nothing.
JAR2B=$WORK/jar.linus-wrong
pa_authorize "$JAR2B"
federate "$JAR2B" kc-oidc-wrong-secret linus "$KC_USER_PW"
FED_ERR=$(helper query "$FED_RETURN" federation_error)
[ "$FED_ERR" = upstream_invalid_response ] || fail "a wrong upstream client secret: $FED_RETURN"
admin GET "/users?q=linus%40upstream.test" "" 200
[ "$(jq '.items | length' "$WORK/resp.json")" = 0 ] || fail "an account was created despite the refused upstream token request"
ok "wrong upstream client secret: Keycloak refused ProudAuth's token request, federation_error=$FED_ERR, no account"

# Upstream logout (FED-013): ProudAuth ends its session, then Keycloak's.
STOP="$APP $LOGIN_UI"
nav "$JAR2" "$ISSUER/oidc/logout?id_token_hint=$(jq -r .id_token "$WORK/pa-grace2.json")&post_logout_redirect_uri=$(printf %s "$APP_LOGGED_OUT" | jq -sRr @uri)&state=bye&upstream_logout=true"
_pages=0
while [ "$NAV_STATUS" != stop ] && [ "$_pages" -lt 3 ]; do
	_pages=$((_pages + 1))
	[ "$NAV_STATUS" = 200 ] || fail "upstream logout: HTTP $NAV_STATUS at $NAV_URL"
	submit "$JAR2" # Keycloak asks to confirm a logout request without id_token_hint
done
case $NAV_URL in "$APP_LOGGED_OUT?"*) ;; *) fail "upstream logout did not return to the application: $NAV_URL" ;; esac
[ "$(helper query "$NAV_URL" upstream_logout)" = returned ] && [ "$(helper query "$NAV_URL" state)" = bye ] || fail "upstream logout return: $NAV_URL"
kc GET "/upstream/users/$KC_GRACE/sessions" 200
[ "$(jq length "$WORK/kc.json")" = 0 ] || fail "grace's Keycloak session survived the upstream logout"
GRACE_SID=$(helper jwt "$(jq -r .id_token "$WORK/pa-grace2.json")" | jq -r .sid)
admin GET "/users/$GRACE_ID/sessions" "" 200
jq -e --arg sid "$GRACE_SID" '[.items[] | select(.id == $sid and .state == "active")] | length == 0' "$WORK/resp.json" >/dev/null ||
	fail "ProudAuth session $GRACE_SID of grace after logout: $(cat "$WORK/resp.json")"
ok "upstream logout: ProudAuth (session ended) -> Keycloak end_session_endpoint (confirmation form) -> upstream-return -> application (upstream_logout=returned); Keycloak session ended"

# ------------------- 3a. ProudAuth as SAML IdP, Keycloak as SAML SP ---

log "3a. ProudAuth as SAML identity provider for a Keycloak SAML v2.0 identity provider"
kc POST /consumer/identity-provider/import-config "$(jq -nc --arg u "$ISSUER/saml/metadata" '{providerId:"saml", fromUrl:$u}')" 200
jq . "$WORK/kc.json" >"$WORK/kc-saml-import.json"
kc POST /consumer/identity-provider/instances "$(jq -c '{alias:"pa-saml", providerId:"saml", enabled:true, trustEmail:false,
	firstBrokerLoginFlowAlias:"first broker login",
	config:(. + {postBindingResponse:"true", postBindingAuthnRequest:"false", postBindingLogout:"false", wantAuthnRequestsSigned:"true",
		signatureAlgorithm:"RSA_SHA256", validateSignature:"true", wantAssertionsSigned:"true", wantAssertionsEncrypted:"false",
		nameIDPolicyFormat:"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", principalType:"SUBJECT", syncMode:"IMPORT"})}' \
	"$WORK/kc-saml-import.json")" 201
for m in email:email firstName:firstName lastName:lastName; do
	kc POST /consumer/identity-provider/instances/pa-saml/mappers "$(jq -nc --arg a "${m%%:*}" --arg u "${m#*:}" '{name:$a, identityProviderAlias:"pa-saml",
		identityProviderMapper:"saml-user-attribute-idp-mapper", config:{syncMode:"INHERIT", "attribute.name":$a, "user.attribute":$u}}')" 201
done
c -o "$WORK/kc-sp.xml" "$KC/realms/consumer/broker/pa-saml/endpoint/descriptor"
admin POST /saml/applications "$(jq -n --rawfile md "$WORK/kc-sp.xml" '{name:"Keycloak consumer realm", metadata_xml:$md, first_party:true,
	attributes:[{name:"email", source:"email"}, {name:"firstName", source:"given_name"}, {name:"lastName", source:"family_name"}]}')" 201
jq '{entity_id, require_signed_requests, name_id_format, assertion_consumer_services}' "$WORK/resp.json" >"$WORK/pa-saml-app.json"
ok "Keycloak SAML identity provider pa-saml (from ProudAuth IdP metadata) and ProudAuth SAML application (from Keycloak SP metadata): $(jq -c . "$WORK/pa-saml-app.json" | cut -c1-300)"

# Negative: with "HTTP-POST binding response" off, Keycloak asks for the
# response over HTTP-Redirect, which ProudAuth's applications do not offer.
kc GET /consumer/identity-provider/instances/pa-saml 200
jq -c '.config.postBindingResponse = "false"' "$WORK/kc.json" >"$WORK/kc-saml-idp-redirect.json"
jq -c . "$WORK/kc.json" >"$WORK/kc-saml-idp.json"
kc PUT /consumer/identity-provider/instances/pa-saml "@$WORK/kc-saml-idp-redirect.json" 204
STOP="$LOGIN_UI $APP $ISSUER/saml/sso?"
kc_rp_login "$WORK/jar.alan-redirect" pa-saml
case $NAV_URL in "$ISSUER/saml/sso?"*) ;; *) fail "Keycloak did not send an AuthnRequest to ProudAuth: $NAV_STATUS $NAV_URL" ;; esac
helper redirectrequest "$NAV_URL" | jq -e '.binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"' >/dev/null ||
	fail "Keycloak's AuthnRequest without HTTP-POST binding response: $(helper redirectrequest "$NAV_URL")"
code=$(c -o "$WORK/neg.json" -w '%{http_code}' "$NAV_URL")
[ "$code" = 400 ] && grep -q saml_unregistered_acs "$WORK/neg.json" || fail "AuthnRequest asking for HTTP-Redirect: $code $(head -c 300 "$WORK/neg.json")"
kc PUT /consumer/identity-provider/instances/pa-saml "@$WORK/kc-saml-idp.json" 204
ok "Keycloak without \"HTTP-POST binding response\" asks for ProtocolBinding HTTP-Redirect: refused locally (400 saml_unregistered_acs)"

JAR3=$WORK/jar.alan
STOP="$LOGIN_UI $APP $ISSUER/saml/sso?"
kc_rp_login "$JAR3" pa-saml
case $NAV_URL in "$ISSUER/saml/sso?"*) AUTHN_URL=$NAV_URL ;; *) fail "Keycloak did not send an HTTP-Redirect AuthnRequest to ProudAuth: $NAV_STATUS $NAV_URL" ;; esac
helper redirectrequest "$AUTHN_URL" >"$WORK/authn.json"
jq -e '.signed and .binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"' "$WORK/authn.json" >/dev/null || fail "Keycloak AuthnRequest: $(cat "$WORK/authn.json")"
# Negative: a modified RelayState breaks the request's signature.
code=$(c -b "$JAR3" -o "$WORK/neg.json" -w '%{http_code}' "$(helper qset "$AUTHN_URL" RelayState tampered)")
[ "$code" = 400 ] && grep -q saml_signature "$WORK/neg.json" || fail "tampered AuthnRequest: $code $(head -c 300 "$WORK/neg.json")"
STOP="$LOGIN_UI $APP"
nav "$JAR3" "$AUTHN_URL"
case $NAV_URL in "$LOGIN_UI"*) ;; *) fail "ProudAuth SSO did not reach the login UI: $NAV_STATUS $NAV_URL" ;; esac
code=$(c -b "$JAR3" -o "$WORK/neg.json" -w '%{http_code}' "$AUTHN_URL")
[ "$code" = 400 ] && grep -q saml_request_replay "$WORK/neg.json" || fail "replayed AuthnRequest: $code $(head -c 300 "$WORK/neg.json")"
ok "Keycloak's signed HTTP-Redirect AuthnRequest ($(jq -r .sig_alg "$WORK/authn.json"), NameIDPolicy $(jq -r .name_id_format "$WORK/authn.json")) accepted; tampered (saml_signature) and replayed (saml_request_replay) copies refused"
ui_open "$JAR3" "$NAV_URL"
tx_drive alan "$(pw_of alan)" alan@interop.test || fail "alan's sign-in at ProudAuth: $LOGIN_ERROR"
STOP="$LOGIN_UI $APP"
nav "$JAR3" "$TX_REDIRECT"
[ "$NAV_STATUS" = 200 ] || fail "SAML continuation: HTTP $NAV_STATUS at $NAV_URL"
helper samlinfo "$(helper field "$WORK/page.html" SAMLResponse)" >"$WORK/saml-a.json"
pages "$JAR3" "" ""
case $NAV_URL in "$APP_CALLBACK?"*) ;; *) fail "Keycloak did not complete the SAML brokered sign-in: $NAV_URL" ;; esac
kc_rp_token "$NAV_URL" "$WORK/kc-alan.json"
NAMEID=$(jq -r .name_id "$WORK/saml-a.json")
jq -e '.response_signed and .assertion_signed and .name_id_format == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" and (.name_id | startswith("sps_"))
	and .attributes.email == ["alan@interop.test"]' "$WORK/saml-a.json" >/dev/null || fail "ProudAuth SAML response: $(cat "$WORK/saml-a.json")"
kc_user consumer "email=alan@interop.test"
KC_ALAN=$(jq -r .id "$WORK/kcuser.json")
jq -e '.firstName == "Alan" and .lastName == "Turing"' "$WORK/kcuser.json" >/dev/null || fail "brokered SAML user: $(jq -c '{username, email, firstName, lastName}' "$WORK/kcuser.json")"
kc GET "/consumer/users/$KC_ALAN/federated-identity" 200
jq -e --arg n "$NAMEID" 'length == 1 and .[0].identityProvider == "pa-saml" and .[0].userId == $n' "$WORK/kc.json" >/dev/null ||
	fail "SAML federated identity link: $(cat "$WORK/kc.json") (NameID $NAMEID)"
ok "Keycloak accepted ProudAuth's signed response and assertion (persistent NameID $NAMEID, attributes email/firstName/lastName) and created user alan linked to it"
ALAN_ID=$(cat "$WORK/user.alan")
admin GET "/users/$ALAN_ID/sessions" "" 200
jq -e '[.items[] | select(.state == "active")] | length == 1' "$WORK/resp.json" >/dev/null || fail "ProudAuth sessions of alan: $(cat "$WORK/resp.json")"

# Single logout (SAML-008): Keycloak's logout sends a signed LogoutRequest to
# ProudAuth's SLO endpoint, which ends the session and answers with a signed
# LogoutResponse to Keycloak's registered logout endpoint.
STOP="$APP $LOGIN_UI $ISSUER/saml/slo?"
nav "$JAR3" "$KC/realms/consumer/protocol/openid-connect/logout?id_token_hint=$(jq -r .id_token "$WORK/kc-alan.json")&post_logout_redirect_uri=$(printf %s "$APP_LOGGED_OUT" | jq -sRr @uri)&state=bye"
case $NAV_URL in "$ISSUER/saml/slo?"*) SLO_URL=$NAV_URL ;; *) fail "Keycloak did not send a LogoutRequest to ProudAuth: $NAV_STATUS $NAV_URL" ;; esac
helper query "$SLO_URL" Signature | grep -q . || fail "Keycloak's LogoutRequest is not signed: $SLO_URL"
STOP="$APP $LOGIN_UI"
browse "$JAR3" "$SLO_URL" "" ""
case $NAV_URL in "$APP_LOGGED_OUT?"*) ;; *) fail "SAML logout did not return to the application: $NAV_URL" ;; esac
admin GET "/users/$ALAN_ID/sessions" "" 200
jq -e '[.items[] | select(.state == "active")] | length == 0' "$WORK/resp.json" >/dev/null || fail "ProudAuth session of alan still active after SAML logout: $(cat "$WORK/resp.json")"
kc GET "/consumer/users/$KC_ALAN/sessions" 200
[ "$(jq length "$WORK/kc.json")" = 0 ] || fail "Keycloak session of alan still active"
ok "SAML single logout: Keycloak -> signed HTTP-Redirect LogoutRequest -> ProudAuth (session ended) -> signed LogoutResponse -> Keycloak -> application"

# Encrypted assertions (SAML-009): a second Keycloak SAML identity provider,
# with its own SP entity ID, that wants encrypted assertions; ProudAuth
# encrypts for the key in its metadata (AES-256-GCM, RSA-OAEP).
kc POST /consumer/identity-provider/instances "$(jq -c --arg e "$KC/realms/consumer/pa-saml-enc" '{alias:"pa-saml-enc", providerId:"saml", enabled:true,
	trustEmail:false, firstBrokerLoginFlowAlias:"first broker login",
	config:(. + {entityId:$e, postBindingResponse:"true", postBindingAuthnRequest:"false", postBindingLogout:"false", wantAuthnRequestsSigned:"true",
		signatureAlgorithm:"RSA_SHA256", validateSignature:"true", wantAssertionsSigned:"true", wantAssertionsEncrypted:"true",
		nameIDPolicyFormat:"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", principalType:"SUBJECT", syncMode:"IMPORT"})}' \
	"$WORK/kc-saml-import.json")" 201
for m in email:email firstName:firstName lastName:lastName; do
	kc POST /consumer/identity-provider/instances/pa-saml-enc/mappers "$(jq -nc --arg a "${m%%:*}" --arg u "${m#*:}" '{name:$a, identityProviderAlias:"pa-saml-enc",
		identityProviderMapper:"saml-user-attribute-idp-mapper", config:{syncMode:"INHERIT", "attribute.name":$a, "user.attribute":$u}}')" 201
done
c -o "$WORK/kc-sp-enc.xml" "$KC/realms/consumer/broker/pa-saml-enc/endpoint/descriptor"
grep -q 'use="encryption"' "$WORK/kc-sp-enc.xml" || fail "Keycloak SP metadata without an encryption key"
admin POST /saml/applications "$(jq -n --rawfile md "$WORK/kc-sp-enc.xml" '{name:"Keycloak consumer realm (encrypted)", metadata_xml:$md, first_party:true,
	encrypt_assertions:true, attributes:[{name:"email", source:"email"}, {name:"firstName", source:"given_name"}, {name:"lastName", source:"family_name"}]}')" 201
jq -c '{encrypt_assertions, data_encryption_algorithm, key_transport_algorithm}' "$WORK/resp.json" >"$WORK/pa-saml-enc.json"
JAR5=$WORK/jar.edsger
STOP="$LOGIN_UI $APP"
kc_rp_login "$JAR5" pa-saml-enc
case $NAV_URL in "$LOGIN_UI"*) ;; *) fail "ProudAuth SSO (encrypted) did not reach the login UI: $NAV_STATUS $NAV_URL" ;; esac
ui_open "$JAR5" "$NAV_URL"
tx_drive edsger "$(pw_of edsger)" edsger@interop.test || fail "edsger's sign-in at ProudAuth: $LOGIN_ERROR"
nav "$JAR5" "$TX_REDIRECT"
[ "$NAV_STATUS" = 200 ] || fail "SAML continuation (encrypted): HTTP $NAV_STATUS at $NAV_URL"
helper samlenc "$(helper field "$WORK/page.html" SAMLResponse)" >"$WORK/saml-enc.json"
jq -e '.encrypted and (.plain_assertion | not)' "$WORK/saml-enc.json" >/dev/null || fail "ProudAuth did not encrypt the assertion: $(cat "$WORK/saml-enc.json")"
pages "$JAR5" "" ""
case $NAV_URL in "$APP_CALLBACK?"*) ;; *) fail "Keycloak did not complete the sign-in with an encrypted assertion: $NAV_URL" ;; esac
kc_user consumer "email=edsger@interop.test"
kc GET "/consumer/users/$(jq -r .id "$WORK/kcuser.json")/federated-identity" 200
jq -e 'length == 1 and .[0].identityProvider == "pa-saml-enc" and (.[0].userId | startswith("sps_"))' "$WORK/kc.json" >/dev/null ||
	fail "encrypted SAML federated identity link: $(cat "$WORK/kc.json")"
ok "Keycloak decrypted ProudAuth's encrypted assertion ($(jq -r '.encryption_methods | map(sub(".*#"; "")) | join(", ")' "$WORK/saml-enc.json")) and created user edsger"

# ------------------- 3b. Keycloak as SAML IdP, ProudAuth SAML connection ---

log "3b. Keycloak as SAML identity provider for a ProudAuth SAML connection"
c -o "$WORK/kc-idp.xml" "$KC/realms/upstream/protocol/saml/descriptor"
admin POST /saml/connections "$(jq -n --rawfile md "$WORK/kc-idp.xml" '{alias:"kc-saml", display_name:"Keycloak SAML", metadata_xml:$md,
	name_id_format:"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", email_attribute:"email", trust_email_verified:true,
	require_signed_assertions:true, jit_provisioning:true}')" 201
jq '{saml: (.saml | {idp_entity_id, sso_url, sign_authn_requests, name_id_format}), service_provider}' "$WORK/resp.json" >"$WORK/pa-saml-conn.json"
KC_IDP_ENTITY=$(jq -r .saml.idp_entity_id "$WORK/pa-saml-conn.json")
c -o "$WORK/pa-sp.xml" "$ISSUER/saml/sp/kc-saml"
kc POST /upstream/client-description-converter "@$WORK/pa-sp.xml" application/xml 200
jq '. + {protocolMappers: [
	{name:"email", protocol:"saml", protocolMapper:"saml-user-property-mapper", config:{"user.attribute":"email", "attribute.name":"email", "attribute.nameformat":"Basic"}},
	{name:"givenName", protocol:"saml", protocolMapper:"saml-user-property-mapper", config:{"user.attribute":"firstName", "attribute.name":"givenName", "attribute.nameformat":"Basic"}},
	{name:"sn", protocol:"saml", protocolMapper:"saml-user-property-mapper", config:{"user.attribute":"lastName", "attribute.name":"sn", "attribute.nameformat":"Basic"}}]}' \
	"$WORK/kc.json" >"$WORK/kc-saml-client.json"
kc POST /upstream/clients "@$WORK/kc-saml-client.json" 201
ok "ProudAuth SAML connection kc-saml (from Keycloak IdP metadata, entity $KC_IDP_ENTITY) and Keycloak SAML client (from ProudAuth SP metadata): $(jq -c '.saml' "$WORK/pa-saml-conn.json" | cut -c1-300)"

# saml_attempt JAR USER: ProudAuth sign-in through kc-saml up to Keycloak's
# auto-submitting response form (not yet posted). Response in $WORK/kc-saml.b64.
saml_attempt() {
	pa_authorize "$1"
	tx_call federation/start '{"provider":"kc-saml"}' || fail "federation start (kc-saml): $LOGIN_ERROR"
	helper redirectrequest "$(jq -r .external_redirect "$WORK/state.json")" >"$WORK/pa-authn.json"
	STOP="$ISSUER/saml/acs/ $LOGIN_UI $APP"
	nav "$1" "$(jq -r .external_redirect "$WORK/state.json")"
	if [ "$NAV_STATUS" = 200 ] && helper forminfo "$WORK/page.html" | jq -e 'any(.[]; .inputs | index("password"))' >/dev/null; then
		submit "$1" password "username=$2" "password=$KC_USER_PW"
	fi
	[ "$NAV_STATUS" = 200 ] || fail "Keycloak SAML sign-in: HTTP $NAV_STATUS at $NAV_URL"
	helper field "$WORK/page.html" SAMLResponse >"$WORK/kc-saml.b64" || fail "no SAMLResponse from Keycloak at $NAV_URL"
	helper field "$WORK/page.html" RelayState >"$WORK/kc-saml.relay"
}

post_acs() { # JAR B64-FILE: post a SAMLResponse with the attempt's RelayState to ProudAuth's ACS
	_code=$(c -b "$1" -c "$1" -o "$WORK/page.html" -w '%{http_code} %{redirect_url}' --data-urlencode "SAMLResponse@$2" \
		--data-urlencode "RelayState@$WORK/kc-saml.relay" "$ISSUER/saml/acs/kc-saml")
	NAV_STATUS=${_code%% *}
	NAV_URL=${_code#* }
}

JAR4=$WORK/jar.linus
saml_attempt "$JAR4" linus
jq -e '.signed and .sig_alg == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"' "$WORK/pa-authn.json" >/dev/null || fail "ProudAuth AuthnRequest: $(cat "$WORK/pa-authn.json")"
helper samlinfo "$(cat "$WORK/kc-saml.b64")" >"$WORK/saml-b.json"
# Keycloak's default role_list client scope sends one Role element per role.
jq -e --arg e "$KC_IDP_ENTITY" '.status == "urn:oasis:names:tc:SAML:2.0:status:Success" and .assertion_issuer == $e and .attributes.email == ["linus@upstream.test"]
	and .attribute_elements.Role >= 2 and (.attributes.Role | index("chemist"))' "$WORK/saml-b.json" >/dev/null || fail "Keycloak SAML response: $(cat "$WORK/saml-b.json")"
# Negative: the response with the email attribute changed is refused and creates nothing.
helper samlreplace "$(cat "$WORK/kc-saml.b64")" linus@upstream.test mallory@upstream.test >"$WORK/kc-saml-tampered.b64"
post_acs "$JAR4" "$WORK/kc-saml-tampered.b64"
case $NAV_STATUS in 30*) ;; *) fail "tampered SAML response: HTTP $NAV_STATUS $(head -c 300 "$WORK/page.html")" ;; esac
[ "$(helper query "$NAV_URL" federation_error)" = upstream_invalid_response ] || fail "tampered SAML response accepted: $NAV_URL"
admin GET "/users?q=mallory%40upstream.test" "" 200
[ "$(jq '.items | length' "$WORK/resp.json")" = 0 ] || fail "an account was created from a tampered SAML response"
admin GET "/audit-events?type_prefix=saml.response.rejected" "" 200
REJECT_REASON=$(jq -r '[.items[]? | .reason_code // .metadata.reason // empty][0] // empty' "$WORK/resp.json")
ok "tampered Keycloak SAML response refused (federation_error=upstream_invalid_response, audit saml.response.rejected ${REJECT_REASON:-}), no account"

saml_attempt "$JAR4" linus
cp "$WORK/kc-saml.b64" "$WORK/kc-saml-good.b64"
post_acs "$JAR4" "$WORK/kc-saml-good.b64"
case $NAV_URL in "$LOGIN_UI"*) ;; *) fail "ProudAuth ACS did not return to the login UI: $NAV_STATUS $NAV_URL $(head -c 300 "$WORK/page.html")" ;; esac
[ -z "$(helper query "$NAV_URL" federation_error)" ] || fail "SAML federation error: $NAV_URL"
tx_call resume '{}' || fail "resume: $LOGIN_ERROR"
tx_drive "" "" "" || fail "linus's SAML sign-in: $LOGIN_ERROR"
pa_token "$TX_REDIRECT" "$WORK/pa-linus.json"
LINUS_ID=$(pa_user_by_email linus@upstream.test)
helper samlinfo "$(cat "$WORK/kc-saml-good.b64")" >"$WORK/saml-b.json"
KC_NAMEID=$(jq -r .name_id "$WORK/saml-b.json")
admin GET "/users/$LINUS_ID/linked-identities" "" 200
jq -e '[.items[] | select(.provider == "kc-saml" and .provenance == "jit")] | length == 1' "$WORK/resp.json" >/dev/null ||
	fail "ProudAuth linked identities of linus: $(cat "$WORK/resp.json")"
[ "$(linked_subjects "$LINUS_ID")" = "$KC_IDP_ENTITY $KC_NAMEID" ] ||
	fail "ProudAuth linked identity for the SAML connection: $(linked_subjects "$LINUS_ID") (NameID $KC_NAMEID)"
helper jwt "$(jq -r .id_token "$WORK/pa-linus.json")" | jq -e --arg s "$LINUS_ID" '.sub == $s and .email == "linus@upstream.test"' >/dev/null ||
	fail "ProudAuth ID token after SAML federation"
ok "linus signed in through Keycloak's SAML IdP ($(jq -r .name_id_format "$WORK/saml-b.json") NameID $KC_NAMEID, response signed: $(jq -r .response_signed "$WORK/saml-b.json"), assertion signed: $(jq -r .assertion_signed "$WORK/saml-b.json"), $(jq -r .attribute_elements.Role "$WORK/saml-b.json") Role attribute elements); JIT account $LINUS_ID linked"
post_acs "$JAR4" "$WORK/kc-saml-good.b64"
[ "$NAV_STATUS" = 400 ] || fail "replayed SAML response: HTTP $NAV_STATUS $NAV_URL"
ok "replayed Keycloak SAML response refused (400 $(jq -r '.code // empty' "$WORK/page.html" 2>/dev/null))"

# ---------------------------------------------------------------- report ---

short_alg() { sed 's|.*#||'; } # an XML-DSig algorithm URI -> rsa-sha256
PA_IDT_ALG=$(helper jwtheader "$(jq -r .id_token "$WORK/pa-grace.json")" | jq -r .alg)
kc GET /upstream 200
KC_IDT_ALG=$(jq -r '.defaultSignatureAlgorithm // "RS256"' "$WORK/kc.json")
cat <<REPORT

Keycloak interoperability passed
  Keycloak  ${KC_VERSION:-?} ($KC_IMAGE), start-dev (H2), HTTPS with a test CA
  ProudAuth built from this checkout ($(go env GOVERSION), linux/$(go env GOARCH)), mode development, HTTPS public listener,
            PostgreSQL $(docker exec "$PG" postgres --version | awk '{print $3}')
  1.  ProudAuth OP -> Keycloak OIDC identity provider: authorization code, PKCE S256, client_secret_basic,
      scope openid email profile, ID token $PA_IDT_ALG (JWKS), UserInfo; RP-initiated logout Keycloak -> ProudAuth -> Keycloak,
      back-channel logout ProudAuth -> Keycloak
  2.  Keycloak OP -> ProudAuth OIDC connection: authorization code, PKCE S256, client_secret_basic, ID token $KC_IDT_ALG,
      just-in-time account and link, link reused, upstream logout ProudAuth -> Keycloak
  3a. ProudAuth SAML IdP -> Keycloak SAML identity provider: AuthnRequest HTTP-Redirect $(jq -r .sig_alg "$WORK/authn.json" | short_alg),
      response HTTP-POST, response and assertion signed $(jq -r '.signature_methods | join(",")' "$WORK/saml-a.json" | short_alg),
      persistent NameID, attributes, encrypted assertion $(jq -r '.encryption_methods | map(sub(".*#"; "")) | join(" + ")' "$WORK/saml-enc.json");
      single logout HTTP-Redirect both ways
  3b. Keycloak SAML IdP -> ProudAuth SAML connection: AuthnRequest HTTP-Redirect $(jq -r .sig_alg "$WORK/pa-authn.json" | short_alg),
      response HTTP-POST, response and assertion signed $(jq -r '.signature_methods | join(",")' "$WORK/saml-b.json" | short_alg),
      persistent NameID, email attribute, repeated Role attributes, just-in-time account and link
  4.  Refused: replayed code, wrong client secret (both directions), replayed federation callback,
      tampered, replayed and HTTP-Redirect-response AuthnRequests, tampered and replayed SAML response
REPORT
