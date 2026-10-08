#!/usr/bin/env bash
#
# console-smoke.sh — drive jay's web console end to end with curl, and confirm
# every effect through a path the console does not own.
#
# The console is a thin layer over the admin API and the S3 handler. A test that
# reads the console's own answer back proves nothing, so each check here does
# something through /console/ and then looks at the result with the native
# client (`jay ls`, `jay cp`) or the admin API with the bearer token. A status
# code alone is never the assertion.
#
# Usage:
#   scripts/console-smoke.sh          # run every check
#   scripts/console-smoke.sh --keep   # keep the work dir and the jay logs
#
# Exit codes:
#   0  every check passed
#   1  a check FAILED (the run stops there) or setup broke

set -uo pipefail
# No `set -e`: a check that is EXPECTED to see a non-2xx must record it, not
# abort. Every failure goes through `fail`, which exits.

KEEP=0
while [ $# -gt 0 ]; do
	case "$1" in
	--keep) KEEP=1 ;;
	-h | --help)
		sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*)
		echo "unknown option: $1" >&2
		exit 64
		;;
	esac
	shift
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	C_RESET=$'\033[0m' C_PASS=$'\033[32m' C_FAIL=$'\033[31m' C_DIM=$'\033[2m' C_BOLD=$'\033[1m'
else
	C_RESET='' C_PASS='' C_FAIL='' C_DIM='' C_BOLD=''
fi

say() { printf '%s\n' "$*"; }
info() { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die() {
	printf '%sfatal:%s %s\n' "$C_FAIL" "$C_RESET" "$*" >&2
	exit 1
}
pass() { printf '  %sPASS%s  %s\n' "$C_PASS" "$C_RESET" "$1"; }
fail() {
	printf '  %sFAIL%s  %s\n' "$C_FAIL" "$C_RESET" "$1"
	[ -n "${2:-}" ] && printf '        %s%s%s\n' "$C_DIM" "$2" "$C_RESET"
	exit 1
}

# assert_eq NAME WANT GOT
assert_eq() {
	if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "want [$2], got [$3]"; fi
}

# ---------------------------------------------------------------------------
# Work dir and cleanup: one temp dir, one trap, no jay outlives the script.
# ---------------------------------------------------------------------------

WORK="$(mktemp -d "${TMPDIR:-/tmp}/jay-console-smoke.XXXXXX")" || die "mktemp failed"
JAY_PID=""

# Registered on EXIT/INT/TERM below; shellcheck cannot see a trap as a call.
# shellcheck disable=SC2329
cleanup() {
	stop_jay
	if [ "$KEEP" -eq 1 ]; then
		printf '\nwork dir kept at %s\n' "$WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT INT TERM

LOGS="$WORK/logs"
mkdir -p "$LOGS"

port_free() {
	(exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1 && {
		exec 3>&- 2>/dev/null
		return 1
	}
	return 0
}

pick_port() {
	local p
	for _ in $(seq 1 100); do
		p=$((20000 + RANDOM % 20000))
		if port_free "$p"; then
			printf '%s' "$p"
			return 0
		fi
	done
	die "no free TCP port found in 20000-40000"
}

# json_str JSON FIELD — one string field out of a flat JSON object. jq when it
# is installed; otherwise a sed that is enough for the compact objects the
# admin API and the console answer with on these routes.
json_str() {
	if command -v jq >/dev/null 2>&1; then
		printf '%s' "$1" | jq -r --arg f "$2" '.[$f] // empty'
	else
		printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"
	fi
}

for tool in go curl openssl cmp; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required and was not found"
done

say ""
say "${C_BOLD}jay console smoke${C_RESET}"
say ""

info "building jay from $REPO_ROOT ..."
(cd "$REPO_ROOT" && go build -o "$WORK/jay" ./cmd/jay) || die "go build failed"

S3_PORT="$(pick_port)"
ADMIN_PORT="$(pick_port)"
NATIVE_PORT="$(pick_port)"
ADMIN_TOKEN="$(openssl rand -hex 24)"
SIGNING_SECRET="$(openssl rand -hex 24)"
DATA="$WORK/data"
mkdir -p "$DATA"

ADMIN="http://127.0.0.1:$ADMIN_PORT"
CONSOLE="$ADMIN/console"
JAR="$WORK/cookies.txt"

# start_jay CONSOLE_ENABLED LOGNAME — boots jay on the fixed ports and data dir.
# Two boots share the data dir on purpose: the second must see what the first
# left, and the console switch is the only thing that differs.
start_jay() {
	local enabled="$1" logname="$2"
	(
		export JAY_DATA_DIR="$DATA"
		export JAY_LISTEN_ADDR="127.0.0.1:$S3_PORT"
		export JAY_ADMIN_ADDR="127.0.0.1:$ADMIN_PORT"
		export JAY_NATIVE_ADDR="127.0.0.1:$NATIVE_PORT"
		export JAY_ADMIN_TOKEN="$ADMIN_TOKEN"
		export JAY_SIGNING_SECRET="$SIGNING_SECRET"
		export JAY_CONSOLE_ENABLED="$enabled"
		export JAY_RATE_LIMIT=100000
		export JAY_RATE_BURST=200000
		export JAY_LOG_LEVEL=info
		exec "$WORK/jay" >"$LOGS/$logname.log" 2>&1
	) &
	JAY_PID="$!"
	local i
	for i in $(seq 1 60); do
		curl -fsS -o /dev/null "$ADMIN/health/ready" 2>/dev/null && return 0
		kill -0 "$JAY_PID" 2>/dev/null || break
		sleep 0.5
	done
	cat "$LOGS/$logname.log" >&2
	die "jay ($logname) never became ready"
}

stop_jay() {
	[ -n "$JAY_PID" ] || return 0
	kill "$JAY_PID" 2>/dev/null
	local waited=0
	while kill -0 "$JAY_PID" 2>/dev/null && [ "$waited" -lt 50 ]; do
		sleep 0.1
		waited=$((waited + 1))
	done
	kill -9 "$JAY_PID" 2>/dev/null
	wait "$JAY_PID" 2>/dev/null
	JAY_PID=""
}

# ---------------------------------------------------------------------------
# 1. Console off: a 404 that names the switch
# ---------------------------------------------------------------------------

start_jay false jay-disabled
body="$(curl -sS -o - -w '\n%{http_code}' "$CONSOLE/")"
code="${body##*$'\n'}"
body="${body%$'\n'*}"
assert_eq "1. disabled console answers 404" "404" "$code"
case "$body" in
*JAY_CONSOLE_ENABLED*) pass "1. the 404 names JAY_CONSOLE_ENABLED" ;;
*) fail "1. the 404 names JAY_CONSOLE_ENABLED" "body: $body" ;;
esac
stop_jay

# ---------------------------------------------------------------------------
# 2. Console on: sign in with a cookie jar, take the CSRF token from the body
# ---------------------------------------------------------------------------

start_jay true jay-enabled

# console_curl METHOD PATH [CURL ARGS...] — a signed-in, CSRF-bearing request.
# Prints the body, then a newline and the status code.
console_curl() {
	local method="$1" path="$2"
	shift 2
	curl -sS -X "$method" -b "$JAR" -H "X-Jay-Console-CSRF: $CSRF" \
		-w '\n%{http_code}' "$@" "$CONSOLE$path"
}
status_of() { printf '%s' "${1##*$'\n'}"; }
body_of() { printf '%s' "${1%$'\n'*}"; }

login="$(curl -sS -c "$JAR" -X POST -H 'Content-Type: application/json' \
	-d "{\"token\":\"$ADMIN_TOKEN\"}" -w '\n%{http_code}' "$CONSOLE/api/session")"
assert_eq "2. login with the admin token answers 201" "201" "$(status_of "$login")"
CSRF="$(json_str "$(body_of "$login")" csrf_token)"
[ -n "$CSRF" ] || fail "2. login body carries a csrf_token" "body: $(body_of "$login")"
pass "2. login body carries a csrf_token"

session="$(curl -sS -b "$JAR" -o /dev/null -w '%{http_code}' "$CONSOLE/api/session")"
assert_eq "2. the cookie jar holds a live session" "200" "$session"

# ---------------------------------------------------------------------------
# 4. Account, token and bucket through the admin proxy
# ---------------------------------------------------------------------------

r="$(console_curl POST /api/admin/accounts -H 'Content-Type: application/json' -d '{"name":"smoke"}')"
assert_eq "4. create account through the proxy answers 201" "201" "$(status_of "$r")"
ACCOUNT_ID="$(json_str "$(body_of "$r")" account_id)"
[ -n "$ACCOUNT_ID" ] || fail "4. account response carries account_id" "body: $(body_of "$r")"

r="$(console_curl POST /api/admin/tokens -H 'Content-Type: application/json' \
	-d "{\"account_id\":\"$ACCOUNT_ID\",\"name\":\"smoke\",\"allowed_actions\":[\"*\"]}")"
assert_eq "4. create token through the proxy answers 201" "201" "$(status_of "$r")"
TOKEN_ID="$(json_str "$(body_of "$r")" token_id)"
TOKEN_SECRET="$(json_str "$(body_of "$r")" secret)"
[ -n "$TOKEN_ID" ] && [ -n "$TOKEN_SECRET" ] ||
	fail "4. token response carries token_id and secret" "body: $(body_of "$r")"

BUCKET="smoke-bucket"
r="$(console_curl POST /api/admin/buckets -H 'Content-Type: application/json' \
	-d "{\"name\":\"$BUCKET\",\"owner_account_id\":\"$ACCOUNT_ID\"}")"
assert_eq "4. create bucket through the proxy answers 201" "201" "$(status_of "$r")"

# Effect, by another road: the admin API with the bearer, not the console.
buckets="$(curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$ADMIN/_jay/buckets")"
case "$buckets" in
*"\"$BUCKET\""*) pass "4. the bucket exists for the admin API (bearer)" ;;
*) fail "4. the bucket exists for the admin API (bearer)" "buckets: $buckets" ;;
esac

# native_jay ARGS... — the native client as the new token, never via the console.
native_jay() {
	JAY_NATIVE_ADDR="127.0.0.1:$NATIVE_PORT" JAY_TOKEN_ID="$TOKEN_ID" \
		JAY_TOKEN_SECRET="$TOKEN_SECRET" "$WORK/jay" "$@"
}

# ---------------------------------------------------------------------------
# 5. Upload through the S3 proxy, verified with the native client
# ---------------------------------------------------------------------------

KEY="hello/smoke.bin"
head -c 70000 /dev/urandom >"$WORK/payload.bin"
r="$(console_curl PUT "/api/s3/$BUCKET/$KEY?as_token=$TOKEN_ID" \
	-H 'Content-Type: application/octet-stream' --data-binary "@$WORK/payload.bin")"
assert_eq "5. upload through the S3 proxy answers 200" "200" "$(status_of "$r")"

listing="$(native_jay ls -r "jay://$BUCKET/" 2>&1)" || fail "5. jay ls (native) works" "$listing"
case "$listing" in
*"smoke.bin"*) pass "5. jay ls (native) lists the uploaded key" ;;
*) fail "5. jay ls (native) lists the uploaded key" "listing: $listing" ;;
esac

native_jay cp "jay://$BUCKET/$KEY" "$WORK/roundtrip.bin" >"$LOGS/cp.log" 2>&1 ||
	fail "5. jay cp (native) downloads the key" "$(cat "$LOGS/cp.log")"
if cmp -s "$WORK/payload.bin" "$WORK/roundtrip.bin"; then
	pass "5. the native download is byte-identical to the upload"
else
	fail "5. the native download is byte-identical to the upload" "cmp: bytes differ"
fi

# ---------------------------------------------------------------------------
# 6. The admin API (bearer) counts the object
# ---------------------------------------------------------------------------

if command -v jq >/dev/null 2>&1; then
	count="$(curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$ADMIN/_jay/buckets" |
		jq -r --arg b "$BUCKET" '[.[] | select(.name == $b)][0].object_count // "missing"')"
else
	# No jq: take the object_count that follows the bucket's name in the
	# compact array. Each bucket is one flat object, and there is one bucket.
	count="$(curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$ADMIN/_jay/buckets" |
		grep -o "\"name\":\"$BUCKET\"[^}]*\"object_count\":[0-9]*" | grep -o '[0-9]*$' || echo missing)"
fi
assert_eq "6. GET /_jay/buckets (bearer) reports object_count 1" "1" "$count"

# ---------------------------------------------------------------------------
# 7. Unsafe requests without the CSRF header change nothing
# ---------------------------------------------------------------------------

before="$(native_jay ls -r "jay://$BUCKET/" 2>&1)"
code="$(curl -sS -b "$JAR" -X PUT -o /dev/null -w '%{http_code}' \
	-H 'Content-Type: application/octet-stream' --data-binary 'sneaky' \
	"$CONSOLE/api/s3/$BUCKET/sneaky.txt?as_token=$TOKEN_ID")"
assert_eq "7. S3 PUT without the CSRF header answers 403" "403" "$code"
code="$(curl -sS -b "$JAR" -X POST -o /dev/null -w '%{http_code}' \
	-H 'Content-Type: application/json' -d "{\"name\":\"smoke-nocsrf\",\"owner_account_id\":\"$ACCOUNT_ID\"}" \
	"$CONSOLE/api/admin/buckets")"
assert_eq "7. admin POST without the CSRF header answers 403" "403" "$code"
after="$(native_jay ls -r "jay://$BUCKET/" 2>&1)"
assert_eq "7. jay ls shows nothing changed" "$before" "$after"
buckets="$(curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$ADMIN/_jay/buckets")"
case "$buckets" in
*smoke-nocsrf*) fail "7. the refused admin POST created no bucket" "buckets: $buckets" ;;
*) pass "7. the refused admin POST created no bucket" ;;
esac

# ---------------------------------------------------------------------------
# 8. Delete through the proxy, confirmed by the native client
# ---------------------------------------------------------------------------

r="$(console_curl DELETE "/api/s3/$BUCKET/$KEY?as_token=$TOKEN_ID")"
assert_eq "8. delete through the S3 proxy answers 204" "204" "$(status_of "$r")"
listing="$(native_jay ls -r "jay://$BUCKET/" 2>&1)"
case "$listing" in
*"smoke.bin"*) fail "8. jay ls no longer lists the key" "listing: $listing" ;;
*) pass "8. jay ls no longer lists the key" ;;
esac

# ---------------------------------------------------------------------------
# 9. Logout kills the session server-side
# ---------------------------------------------------------------------------

cp "$JAR" "$WORK/cookies-before-logout.txt"
r="$(console_curl DELETE /api/session)"
assert_eq "9. logout answers 204" "204" "$(status_of "$r")"
# The old cookie, replayed from the copy taken before logout: the jar itself
# was cleared by the Set-Cookie, so only a server-side delete makes this 401.
code="$(curl -sS -b "$WORK/cookies-before-logout.txt" -o /dev/null -w '%{http_code}' "$CONSOLE/api/session")"
assert_eq "9. the old cookie is rejected after logout" "401" "$code"

# ---------------------------------------------------------------------------
# 3. Backoff shared with the admin API (last: it locks this address out)
# ---------------------------------------------------------------------------

for i in 1 2 3 4 5; do
	code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
		-d '{"token":"definitely-not-the-admin-token-0000000000"}' "$CONSOLE/api/session")"
	[ "$code" = "401" ] || fail "3. bad login #$i answers 401" "got $code"
done
pass "3. five bad logins answer 401"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
	-d "{\"token\":\"$ADMIN_TOKEN\"}" "$CONSOLE/api/session")"
assert_eq "3. the sixth login, with the GOOD token, answers 429" "429" "$code"
say ""
say "${C_PASS}console smoke: all checks passed${C_RESET}"
