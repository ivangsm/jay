#!/usr/bin/env bash
#
# conformance.sh — exercise jay's S3 surface with S3 clients jay did not write.
#
# Why this exists: the README claims S3 compatibility, and ~640 Go tests prove
# only that jay agrees with itself. A test that builds the request with the same
# code that parses it measures internal consistency, not compatibility. So this
# script boots a throwaway jay and drives it with the real thing: aws-cli
# (botocore), mc and warp (both minio-go).
#
# What it does NOT do: fix anything, or paper over a failure. Every check either
# asserts an effect (bytes on the wire, an object present or absent, a status
# code) or it does not run. A confirmation message is never the assertion.
#
# Usage:
#   scripts/conformance.sh                # run everything that is installed
#   scripts/conformance.sh --require-all  # a missing client is a failure (CI)
#   scripts/conformance.sh --keep         # keep the work dir and the jay logs
#
# Exit codes:
#   0  every check that ran passed (some may have been skipped)
#   1  at least one check FAILED
#   2  nothing ran, or every check was skipped — a green run that proved nothing
#   3  --require-all was given and a client was missing
#
# Requirements: go, curl, openssl. The S3 clients are optional unless
# --require-all is given:
#   aws  — https://docs.aws.amazon.com/cli/  (botocore; the reference client)
#   mc   — https://min.io/docs/minio/linux/reference/minio-mc.html (minio-go)
#   warp — https://github.com/minio/warp     (minio-go, benchmark harness)
#
# warp is looked up on PATH and in $(go env GOPATH)/bin, because `go install`
# puts it in the latter and CI runners rarely have that on PATH.

set -uo pipefail
# Deliberately NOT `set -e`: half of the checks below run a command that is
# EXPECTED to fail, and an abort on the first non-zero exit would hide the
# result instead of recording it. Setup steps call `die` explicitly.

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

REQUIRE_ALL=0
KEEP=0

while [ $# -gt 0 ]; do
	case "$1" in
	--require-all) REQUIRE_ALL=1 ;;
	--keep) KEEP=1 ;;
	-h | --help)
		# Up to the first blank line, so the header can grow without this
		# range going stale and printing shell code as documentation.
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

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	C_RESET=$'\033[0m'
	C_PASS=$'\033[32m'
	C_FAIL=$'\033[31m'
	C_SKIP=$'\033[33m'
	C_DIM=$'\033[2m'
	C_BOLD=$'\033[1m'
else
	C_RESET='' C_PASS='' C_FAIL='' C_SKIP='' C_DIM='' C_BOLD=''
fi

say() { printf '%s\n' "$*"; }
info() { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }
die() {
	printf '%sfatal:%s %s\n' "$C_FAIL" "$C_RESET" "$*" >&2
	exit 1
}

# ---------------------------------------------------------------------------
# Result bookkeeping
#
# Three states, and they are not interchangeable. PASS means the check ran and
# the assertion held. FAIL means it ran and the assertion broke. SKIP means it
# never ran — it is not a success, and a run made only of SKIPs exits non-zero
# rather than reporting a green wall of nothing.
# ---------------------------------------------------------------------------

RESULTS=()
N_PASS=0
N_FAIL=0
N_SKIP=0
# Passes driven by a real S3 client, as opposed to the raw-curl "integrity"
# group. The exit-2 guard counts THESE, not the total: this harness exists to
# measure compatibility with clients jay did not write, and a run made only of
# curl checks has not measured that however green it looks.
N_CLIENT_PASS=0
GROUP="setup"

record() {
	local status="$1" name="$2" detail="${3:-}"
	RESULTS+=("$status|$GROUP|$name|$detail")
	case "$status" in
	PASS)
		N_PASS=$((N_PASS + 1))
		[ "$GROUP" != "integrity" ] && N_CLIENT_PASS=$((N_CLIENT_PASS + 1))
		printf '  %sPASS%s  %s\n' "$C_PASS" "$C_RESET" "$name"
		;;
	FAIL)
		N_FAIL=$((N_FAIL + 1))
		printf '  %sFAIL%s  %s\n' "$C_FAIL" "$C_RESET" "$name"
		[ -n "$detail" ] && printf '        %s%s%s\n' "$C_DIM" "$detail" "$C_RESET"
		;;
	SKIP)
		N_SKIP=$((N_SKIP + 1))
		printf '  %sSKIP%s  %s\n' "$C_SKIP" "$C_RESET" "$name"
		[ -n "$detail" ] && printf '        %s%s%s\n' "$C_DIM" "$detail" "$C_RESET"
		;;
	esac
}

pass() { record PASS "$1" "${2:-}"; }
fail() { record FAIL "$1" "${2:-}"; }
skip() { record SKIP "$1" "${2:-}"; }

# assert_eq NAME EXPECTED ACTUAL — the workhorse for value comparisons.
assert_eq() {
	local name="$1" want="$2" got="$3"
	if [ "$want" = "$got" ]; then
		pass "$name"
	else
		fail "$name" "want [$want], got [$got]"
	fi
}

# ---------------------------------------------------------------------------
# Work dir and cleanup
#
# Everything the run creates lives under one temp dir: the built binary, both
# data dirs, the TLS material, every client's config and every captured log.
# The trap fires on success, on failure and on Ctrl-C, so a jay never outlives
# the script.
# ---------------------------------------------------------------------------

WORK="$(mktemp -d "${TMPDIR:-/tmp}/jay-conformance.XXXXXX")" || die "mktemp failed"
JAY_PIDS=()

# Registered on EXIT/INT/TERM below; shellcheck cannot see a trap as a call.
# shellcheck disable=SC2329
cleanup() {
	local pid
	for pid in ${JAY_PIDS[@]+"${JAY_PIDS[@]}"}; do
		kill "$pid" 2>/dev/null
	done
	for pid in ${JAY_PIDS[@]+"${JAY_PIDS[@]}"}; do
		local waited=0
		while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 50 ]; do
			sleep 0.1
			waited=$((waited + 1))
		done
		kill -9 "$pid" 2>/dev/null
	done
	if [ "$KEEP" -eq 1 ]; then
		printf '\nwork dir kept at %s\n' "$WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup EXIT INT TERM

LOGS="$WORK/logs"
mkdir -p "$LOGS"

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

# json_str JSON FIELD — pull one string field out of a flat JSON object.
# The admin API answers compact objects with no nested strings on these routes,
# so this avoids a jq dependency that CI would otherwise have to install.
json_str() {
	printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"
}

# b64sha256 FILE — the digest exactly as S3 defines x-amz-checksum-sha256:
# raw SHA-256, base64. Not hex. This is the shape PND-0184 got wrong.
b64sha256() { openssl dgst -sha256 -binary "$1" | openssl base64 -A; }

# hexsha256 FILE — for comparing two local files byte for byte.
hexsha256() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }

file_size() { wc -c <"$1" | tr -d ' '; }

port_free() {
	# bash's /dev/tcp: a successful connect means something is already there.
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

TIMEOUT_BIN="$(command -v timeout || command -v gtimeout || true)"
# run_limited SECONDS CMD... — a hung client must not hang the whole run. When
# neither timeout nor gtimeout exists (stock macOS), the command runs unbounded
# rather than not running at all.
run_limited() {
	local secs="$1"
	shift
	if [ -n "$TIMEOUT_BIN" ]; then
		"$TIMEOUT_BIN" "$secs" "$@"
	else
		"$@"
	fi
}

# ---------------------------------------------------------------------------
# Preflight: the tools this script cannot run without
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}jay S3 conformance${C_RESET}"
say ""

for tool in go curl openssl; do
	command -v "$tool" >/dev/null 2>&1 || die "$tool is required and was not found"
done

AWS_BIN="$(command -v aws || true)"
MC_BIN="$(command -v mc || true)"
WARP_BIN="$(command -v warp || true)"
if [ -z "$WARP_BIN" ]; then
	for candidate in "$(go env GOPATH 2>/dev/null)/bin/warp" "$HOME/go/bin/warp"; do
		if [ -x "$candidate" ]; then
			WARP_BIN="$candidate"
			break
		fi
	done
fi

info "aws:  ${AWS_BIN:-(not found)}"
info "mc:   ${MC_BIN:-(not found)}"
info "warp: ${WARP_BIN:-(not found)}"

if [ "$REQUIRE_ALL" -eq 1 ]; then
	missing=""
	[ -z "$AWS_BIN" ] && missing="$missing aws"
	[ -z "$MC_BIN" ] && missing="$missing mc"
	[ -z "$WARP_BIN" ] && missing="$missing warp"
	if [ -n "$missing" ]; then
		printf '%sfatal:%s --require-all given but these clients are missing:%s\n' \
			"$C_FAIL" "$C_RESET" "$missing" >&2
		exit 3
	fi
fi

# ---------------------------------------------------------------------------
# Build the server under test
# ---------------------------------------------------------------------------

info "building jay from $REPO_ROOT ..."
(cd "$REPO_ROOT" && go build -o "$WORK/jay" .) || die "go build failed"

# ---------------------------------------------------------------------------
# Boot: two instances, because minio-go behaves differently on each
#
# minio-go signs a plain-HTTP PutObject with the SigV4 *streaming* signature
# (aws-chunked framing), which jay refuses with 501; over TLS it sends an
# unframed body instead. One listener cannot be both, so the harness runs two:
# the HTTP one carries the bulk of the suite, the TLS one proves the minio-go
# upload path that HTTP cannot reach.
# ---------------------------------------------------------------------------

S3_PORT="$(pick_port)"
ADMIN_PORT="$(pick_port)"
NATIVE_PORT="$(pick_port)"
TLS_S3_PORT="$(pick_port)"
TLS_ADMIN_PORT="$(pick_port)"
TLS_NATIVE_PORT="$(pick_port)"

ADMIN_TOKEN="$(openssl rand -base64 32)"
SIGNING_SECRET="$(openssl rand -base64 32)"

A_ID="conformance-a"
A_SECRET="$(openssl rand -hex 24)"
TLS_ID="conformance-tls"
TLS_SECRET="$(openssl rand -hex 24)"

# start_jay NAME DATADIR S3PORT ADMINPORT NATIVEPORT SEEDID SEEDSECRET [TLS]
start_jay() {
	local name="$1" datadir="$2" s3p="$3" adminp="$4" nativep="$5"
	local seed_id="$6" seed_secret="$7" tls="${8:-}"
	mkdir -p "$datadir"

	# The rate limiter defaults to 100 rps per token. aws-cli fires 10 parallel
	# part uploads and warp runs hundreds of ops a second, so the default would
	# make the run measure the limiter instead of the S3 surface.
	(
		export JAY_DATA_DIR="$datadir"
		export JAY_LISTEN_ADDR="127.0.0.1:$s3p"
		export JAY_ADMIN_ADDR="127.0.0.1:$adminp"
		export JAY_NATIVE_ADDR="127.0.0.1:$nativep"
		export JAY_ADMIN_TOKEN="$ADMIN_TOKEN"
		export JAY_SIGNING_SECRET="$SIGNING_SECRET"
		export JAY_SEED_TOKEN_ACCOUNT="$name"
		export JAY_SEED_TOKEN_ID="$seed_id"
		export JAY_SEED_TOKEN_SECRET="$seed_secret"
		export JAY_RATE_LIMIT=100000
		export JAY_RATE_BURST=200000
		export JAY_LOG_LEVEL=info
		if [ -n "$tls" ]; then
			export JAY_TLS_CERT="$WORK/tls.crt"
			export JAY_TLS_KEY="$WORK/tls.key"
		fi
		exec "$WORK/jay" >"$LOGS/jay-$name.log" 2>&1
	) &
	JAY_PIDS+=("$!")
}

# wait_ready URL CURLOPTS...
wait_ready() {
	local url="$1"
	shift
	for _ in $(seq 1 60); do
		if curl -fsS "$@" -o /dev/null "$url" 2>/dev/null; then
			return 0
		fi
		sleep 0.5
	done
	return 1
}

# The TLS instance needs a certificate before it can start. One RSA key, valid
# for a day, for 127.0.0.1 — the clients are told to skip verification.
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/tls.key" -out "$WORK/tls.crt" \
	-days 1 -nodes -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >"$LOGS/openssl.log" 2>&1 ||
	die "could not generate the self-signed certificate (see $LOGS/openssl.log)"

start_jay "http" "$WORK/data-http" "$S3_PORT" "$ADMIN_PORT" "$NATIVE_PORT" "$A_ID" "$A_SECRET"
start_jay "tls" "$WORK/data-tls" "$TLS_S3_PORT" "$TLS_ADMIN_PORT" "$TLS_NATIVE_PORT" "$TLS_ID" "$TLS_SECRET" tls

S3="http://127.0.0.1:$S3_PORT"
ADMIN="http://127.0.0.1:$ADMIN_PORT"
TLS_S3="https://127.0.0.1:$TLS_S3_PORT"

wait_ready "$ADMIN/health/ready" || {
	cat "$LOGS/jay-http.log" >&2
	die "the plain-HTTP jay never became ready"
}
wait_ready "https://127.0.0.1:$TLS_ADMIN_PORT/health/ready" -k || {
	cat "$LOGS/jay-tls.log" >&2
	die "the TLS jay never became ready"
}
info "jay is up on $S3 (admin $ADMIN) and $TLS_S3"

# ---------------------------------------------------------------------------
# Accounts and tokens
#
# Account A comes from the seed variables. Account B and the prefix-scoped
# token come from the admin API, because the suite needs three distinct
# authorities: a full one, one that belongs to a different account (PND-0185)
# and one that can only reach part of a bucket (the partial batch delete).
# ---------------------------------------------------------------------------

admin_post() {
	curl -sS -X POST "$ADMIN$1" \
		-H "Authorization: Bearer $ADMIN_TOKEN" \
		-H "Content-Type: application/json" \
		-d "$2"
}

# Account A's id has to be read back BEFORE any other account exists. The token
# listing is a flat array with no per-token filter, so with two accounts in it
# "the first account_id" is whichever bbolt returns first — and a scoped token
# created under the wrong account turns the partial-delete check into a
# whole-request AccessDenied that looks like a jay defect.
acct_a_id="$(curl -sS "$ADMIN/_jay/tokens" -H "Authorization: Bearer $ADMIN_TOKEN" |
	sed -n 's/.*"account_id":"\([^"]*\)".*/\1/p' | sort -u)"
case "$acct_a_id" in
"" | *" "* | *"
"*) die "expected exactly one account before bootstrapping, got: [$acct_a_id]" ;;
esac

tok_scoped_json="$(admin_post /_jay/tokens "{\"account_id\":\"$acct_a_id\",\"name\":\"conformance-scoped\",\"allowed_actions\":[\"*\"],\"prefix_scope\":[\"allowed/\"]}")"
SCOPED_ID="$(json_str "$tok_scoped_json" token_id)"
SCOPED_SECRET="$(json_str "$tok_scoped_json" secret)"
[ -n "$SCOPED_ID" ] && [ -n "$SCOPED_SECRET" ] || die "could not create the scoped token: $tok_scoped_json"

acct_b_json="$(admin_post /_jay/accounts '{"name":"conformance-b"}')"
B_ACCOUNT="$(json_str "$acct_b_json" account_id)"
[ -n "$B_ACCOUNT" ] || die "could not create the second account: $acct_b_json"
[ "$B_ACCOUNT" != "$acct_a_id" ] || die "the second account came back with account A's id"

tok_b_json="$(admin_post /_jay/tokens "{\"account_id\":\"$B_ACCOUNT\",\"name\":\"conformance-b\",\"allowed_actions\":[\"*\"]}")"
B_ID="$(json_str "$tok_b_json" token_id)"
B_SECRET="$(json_str "$tok_b_json" secret)"
[ -n "$B_ID" ] && [ -n "$B_SECRET" ] || die "could not create the second token: $tok_b_json"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIX="$WORK/fixtures"
mkdir -p "$FIX/syncdir/nested"
printf 'jay conformance fixture\n' >"$FIX/small.txt"
printf 'one\n' >"$FIX/syncdir/a.txt"
printf 'two\n' >"$FIX/syncdir/nested/b.txt"
# 12 MiB: above the AWS CLI's 8 MiB threshold, so the upload becomes multipart
# and the download becomes ranged GETs. Both halves matter — the checksum
# defect of PND-0184 only ever showed up on the way down.
dd if=/dev/urandom of="$FIX/big.bin" bs=1048576 count=12 >/dev/null 2>&1 ||
	die "could not create the 12 MiB fixture"

SMALL_B64="$(b64sha256 "$FIX/small.txt")"
BIG_SHA="$(hexsha256 "$FIX/big.bin")"

BUCKET_A="conformance-a"
BUCKET_B="conformance-b"
BUCKET_RB="conformance-rb"

# ---------------------------------------------------------------------------
# aws-cli plumbing
#
# AWS_ENDPOINT_URL, not --endpoint-url: a flag pair stored in a variable does
# not word-split under zsh, so the URL silently ends up as one argument and the
# CLI talks to real AWS. The config files are pinned inside the work dir so a
# developer's ~/.aws profile cannot leak into the run.
# ---------------------------------------------------------------------------

: >"$WORK/aws-config"
: >"$WORK/aws-credentials"
export AWS_CONFIG_FILE="$WORK/aws-config"
export AWS_SHARED_CREDENTIALS_FILE="$WORK/aws-credentials"
export AWS_DEFAULT_REGION="us-east-1"
export AWS_EC2_METADATA_DISABLED=true
export AWS_PAGER=""
unset AWS_PROFILE

aws_as() { # aws_as ID SECRET ARGS...
	local id="$1" secret="$2"
	shift 2
	AWS_ACCESS_KEY_ID="$id" AWS_SECRET_ACCESS_KEY="$secret" \
		AWS_ENDPOINT_URL="$S3" "$AWS_BIN" "$@"
}
aws_a() { aws_as "$A_ID" "$A_SECRET" "$@"; }
aws_b() { aws_as "$B_ID" "$B_SECRET" "$@"; }
aws_scoped() { aws_as "$SCOPED_ID" "$SCOPED_SECRET" "$@"; }

# object_exists BUCKET KEY — head-object's exit code, which cannot be confused
# with an empty listing or a swallowed error message.
object_exists() {
	aws_a s3api head-object --bucket "$1" --key "$2" >/dev/null 2>&1
}

# bucket_state BUCKET — prints "empty", "populated" or "unreadable(<code>)",
# asking jay over plain HTTP with the bearer form.
#
# Deliberately not built on aws-cli: the warp group has to run when aws-cli is
# absent, and a listing command that fails to launch also produces no output.
# "the bucket is empty" and "I could not look" have to be different answers, or
# the check passes without having checked — which is the whole point of this
# script.
bucket_state() {
	local body code
	body="$(curl -sS -H "Authorization: Bearer $A_ID:$A_SECRET" \
		-w '\n%{http_code}' "$S3/$1?list-type=2" 2>/dev/null)"
	code="${body##*$'\n'}"
	if [ "$code" != "200" ]; then
		# Never "empty": a 403, a 404 or a dead connection all mean the state
		# is unknown, and unknown must not read as "nothing was written".
		printf 'unreadable(%s)' "$code"
		return
	fi
	case "$body" in
	*"<Contents>"*) printf 'populated' ;;
	*) printf 'empty' ;;
	esac
}

# ---------------------------------------------------------------------------
# GROUP: aws-cli
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}aws-cli (botocore)${C_RESET}"
GROUP="aws-cli"

if [ -z "$AWS_BIN" ]; then
	skip "whole group" "aws-cli is not installed"
else
	# --- buckets and a small object ---------------------------------------
	if aws_a s3 mb "s3://$BUCKET_A" >"$LOGS/aws-mb.log" 2>&1; then
		pass "CreateBucket (s3 mb)"
	else
		fail "CreateBucket (s3 mb)" "$(tail -2 "$LOGS/aws-mb.log")"
	fi

	if aws_a s3 cp "$FIX/small.txt" "s3://$BUCKET_A/small.txt" --quiet >"$LOGS/aws-put.log" 2>&1 &&
		object_exists "$BUCKET_A" small.txt; then
		pass "PutObject (s3 cp, small)"
	else
		fail "PutObject (s3 cp, small)" "$(tail -2 "$LOGS/aws-put.log")"
	fi

	got_len="$(aws_a s3api head-object --bucket "$BUCKET_A" --key small.txt --query ContentLength --output text 2>/dev/null)"
	assert_eq "HeadObject reports the stored length" "$(file_size "$FIX/small.txt")" "$got_len"

	# PND-0184: S3 defines every x-amz-checksum-* header as the raw digest in
	# base64. jay stored it hex and shipped it hex, so every aws-cli download
	# aborted on a checksum mismatch over bytes that were in fact intact.
	got_sum="$(aws_a s3api head-object --bucket "$BUCKET_A" --key small.txt --query ChecksumSHA256 --output text 2>/dev/null)"
	assert_eq "x-amz-checksum-sha256 is base64, not hex (PND-0184)" "$SMALL_B64" "$got_sum"

	if aws_a s3 cp "s3://$BUCKET_A/small.txt" "$WORK/small.dl" --quiet >"$LOGS/aws-get.log" 2>&1 &&
		cmp -s "$FIX/small.txt" "$WORK/small.dl"; then
		pass "GetObject (s3 cp, small, checksum verified by the client)"
	else
		fail "GetObject (s3 cp, small)" "$(tail -2 "$LOGS/aws-get.log")"
	fi

	# --- checksum header shape, straight off the wire ----------------------
	hdrs="$(curl -sS -D - -o /dev/null -H "Authorization: Bearer $A_ID:$A_SECRET" \
		"$S3/$BUCKET_A/small.txt" 2>/dev/null)"
	wire_sum="$(printf '%s' "$hdrs" | tr -d '\r' | sed -n 's/^[Xx]-[Aa]mz-[Cc]hecksum-[Ss]ha256: //p')"
	assert_eq "200 carries the whole-object checksum" "$SMALL_B64" "$wire_sum"

	# The 206 must NOT carry it: the digest covers the whole object, and a
	# client checking it against a slice rejects a perfectly good transfer.
	# That is every aws-cli download above 8 MiB.
	rng="$(curl -sS -D - -o /dev/null -H "Authorization: Bearer $A_ID:$A_SECRET" \
		-H "Range: bytes=0-4" "$S3/$BUCKET_A/small.txt" 2>/dev/null | tr -d '\r')"
	rng_status="$(printf '%s' "$rng" | sed -n '1s#HTTP/[0-9.]* \([0-9]*\).*#\1#p')"
	rng_sum="$(printf '%s' "$rng" | sed -n 's/^[Xx]-[Aa]mz-[Cc]hecksum-[Ss]ha256: //p')"
	if [ "$rng_status" = "206" ] && [ -z "$rng_sum" ]; then
		pass "206 carries no checksum header (PND-0184)"
	else
		fail "206 carries no checksum header (PND-0184)" \
			"status=$rng_status checksum=[$rng_sum]"
	fi

	# --- the algorithm the client asked for is the one it gets back --------
	#
	# --checksum-algorithm is the client saying "verify my bytes with THIS".
	# jay used to ignore it and answer ChecksumSHA256 whatever was asked, which
	# botocore tolerates and a client that checks the algorithm does not. Every
	# algorithm S3 defines for objects is exercised, because jay implements all
	# five and a gap would otherwise go unnoticed until someone hit it.
	for alg in CRC32 CRC32C CRC64NVME SHA1 SHA256; do
		field="Checksum$alg"
		got_alg="$(aws_a s3api put-object --bucket "$BUCKET_A" --key "sum-$alg.txt" \
			--body "$FIX/small.txt" --checksum-algorithm "$alg" \
			--query "$field" --output text 2>"$LOGS/aws-sum-$alg.log")"
		if [ -n "$got_alg" ] && [ "$got_alg" != "None" ]; then
			pass "put-object --checksum-algorithm $alg answers $field (PND-0189)"
		else
			fail "put-object --checksum-algorithm $alg answers $field (PND-0189)" \
				"got [$got_alg]: $(tail -2 "$LOGS/aws-sum-$alg.log")"
			continue
		fi

		# The same promise through the other door (PND-0194). A copy has no
		# digest to verify — the bytes never left the server — but the client can
		# still ask for one, and jay used to answer 200 with none at all. The
		# expected value is the digest put-object just returned for the SAME
		# bytes, so a copy that hashed the wrong thing, or answered in hex where
		# S3 wants base64, fails even though the response looks checksum-shaped.
		copied_alg="$(aws_a s3api copy-object --bucket "$BUCKET_A" --key "copy-sum-$alg.txt" \
			--copy-source "$BUCKET_A/sum-$alg.txt" --checksum-algorithm "$alg" \
			--query "CopyObjectResult.$field" --output text 2>"$LOGS/aws-copysum-$alg.log")"
		assert_eq "copy-object --checksum-algorithm $alg returns $field (PND-0194)" \
			"$got_alg" "$copied_alg"
	done

	# An algorithm jay cannot compute is refused on a copy the way it is on an
	# upload — and, the part that matters, nothing is copied.
	if aws_a s3api copy-object --bucket "$BUCKET_A" --key "copy-sum-bad.txt" \
		--copy-source "$BUCKET_A/small.txt" --checksum-algorithm SHA512 \
		>"$LOGS/aws-copysum-bad.log" 2>&1; then
		fail "copy-object with an unknown checksum algorithm is refused (PND-0194)" \
			"the copy was accepted"
	elif object_exists "$BUCKET_A" "copy-sum-bad.txt"; then
		fail "copy-object with an unknown checksum algorithm writes nothing (PND-0194)" \
			"copy-sum-bad.txt exists"
	else
		pass "copy-object with an unknown checksum algorithm is refused and writes nothing (PND-0194)"
	fi

	# --- multipart up, ranged down ----------------------------------------
	if aws_a s3 cp "$FIX/big.bin" "s3://$BUCKET_A/big.bin" --quiet >"$LOGS/aws-put-big.log" 2>&1; then
		etag="$(aws_a s3api head-object --bucket "$BUCKET_A" --key big.bin --query ETag --output text 2>/dev/null)"
		case "$etag" in
		*-[0-9]*) pass "multipart upload of 12 MiB (ETag $etag)" ;;
		*) fail "multipart upload of 12 MiB" "ETag $etag has no part count: the CLI did not split it, so multipart went untested" ;;
		esac
	else
		fail "multipart upload of 12 MiB" "$(tail -3 "$LOGS/aws-put-big.log")"
	fi

	if aws_a s3 cp "s3://$BUCKET_A/big.bin" "$WORK/big.dl" --quiet >"$LOGS/aws-get-big.log" 2>&1; then
		assert_eq "ranged download of 12 MiB round-trips (PND-0184)" "$BIG_SHA" "$(hexsha256 "$WORK/big.dl")"
	else
		fail "ranged download of 12 MiB (PND-0184)" "$(tail -3 "$LOGS/aws-get-big.log")"
	fi

	# --- listing, sync, recursive delete -----------------------------------
	aws_a s3 sync "$FIX/syncdir" "s3://$BUCKET_A/synced/" --quiet >"$LOGS/aws-sync.log" 2>&1
	synced="$(aws_a s3api list-objects-v2 --bucket "$BUCKET_A" --prefix synced/ \
		--query 'Contents[].Key' --output text 2>/dev/null | tr '\t' ' ')"
	assert_eq "sync uploads the whole tree" "synced/a.txt synced/nested/b.txt" "$synced"

	top="$(aws_a s3api list-objects-v2 --bucket "$BUCKET_A" --prefix synced/ --delimiter / \
		--query 'Contents[].Key' --output text 2>/dev/null | tr '\t' ' ')"
	pre="$(aws_a s3api list-objects-v2 --bucket "$BUCKET_A" --prefix synced/ --delimiter / \
		--query 'CommonPrefixes[].Prefix' --output text 2>/dev/null | tr '\t' ' ')"
	if [ "$top" = "synced/a.txt" ] && [ "$pre" = "synced/nested/" ]; then
		pass "ListObjectsV2 honours prefix and delimiter"
	else
		fail "ListObjectsV2 honours prefix and delimiter" "keys=[$top] prefixes=[$pre]"
	fi

	aws_a s3 rm --recursive "s3://$BUCKET_A/synced/" --quiet >"$LOGS/aws-rm.log" 2>&1
	left="$(aws_a s3api list-objects-v2 --bucket "$BUCKET_A" --prefix synced/ \
		--query 'Contents[].Key' --output text 2>/dev/null)"
	if [ -z "$left" ] || [ "$left" = "None" ]; then
		pass "rm --recursive empties the prefix"
	else
		fail "rm --recursive empties the prefix" "still there: $left"
	fi

	# --- presigned URL, minted by the client (PND-0161) --------------------
	purl="$(aws_a s3 presign "s3://$BUCKET_A/small.txt" --expires-in 300 2>"$LOGS/aws-presign.log")"
	if [ -z "$purl" ]; then
		fail "SigV4 presigned GET (PND-0161)" "$(tail -2 "$LOGS/aws-presign.log")"
	else
		pcode="$(curl -sS -o "$WORK/presign.dl" -w '%{http_code}' "$purl" 2>/dev/null)"
		if [ "$pcode" = "200" ] && cmp -s "$FIX/small.txt" "$WORK/presign.dl"; then
			pass "SigV4 presigned GET minted by aws-cli (PND-0161)"
		else
			fail "SigV4 presigned GET minted by aws-cli (PND-0161)" "http=$pcode"
		fi
	fi

	# An expired URL has to be refused, or the deadline is decoration.
	eurl="$(aws_a s3 presign "s3://$BUCKET_A/small.txt" --expires-in 1 2>/dev/null)"
	sleep 2
	ecode="$(curl -sS -o /dev/null -w '%{http_code}' "$eurl" 2>/dev/null)"
	if [ "$ecode" = "403" ] || [ "$ecode" = "400" ]; then
		pass "an expired presigned URL is refused (http $ecode)"
	else
		fail "an expired presigned URL is refused" "http=$ecode"
	fi

	# --- operations that answered 501 until PND-0165 -----------------------
	if aws_a s3api get-bucket-location --bucket "$BUCKET_A" >"$LOGS/aws-location.log" 2>&1; then
		pass "GetBucketLocation (PND-0165)"
	else
		fail "GetBucketLocation (PND-0165)" "$(tail -2 "$LOGS/aws-location.log")"
	fi

	upload_id="$(aws_a s3api create-multipart-upload --bucket "$BUCKET_A" \
		--key pending/part.bin --query UploadId --output text 2>"$LOGS/aws-mpu.log")"
	if [ -z "$upload_id" ] || [ "$upload_id" = "None" ]; then
		fail "ListMultipartUploads (PND-0165)" "CreateMultipartUpload failed: $(tail -2 "$LOGS/aws-mpu.log")"
	else
		listed="$(aws_a s3api list-multipart-uploads --bucket "$BUCKET_A" \
			--query 'Uploads[].UploadId' --output text 2>/dev/null)"
		case "$listed" in
		*"$upload_id"*) pass "ListMultipartUploads shows the pending upload (PND-0165)" ;;
		*) fail "ListMultipartUploads shows the pending upload (PND-0165)" "listed=[$listed] want=[$upload_id]" ;;
		esac
		if aws_a s3api abort-multipart-upload --bucket "$BUCKET_A" --key pending/part.bin \
			--upload-id "$upload_id" >"$LOGS/aws-abort.log" 2>&1; then
			pass "AbortMultipartUpload"
		else
			fail "AbortMultipartUpload" "$(tail -2 "$LOGS/aws-abort.log")"
		fi
	fi

	# --- batch delete, whole and partial (PND-0165) ------------------------
	aws_a s3 cp "$FIX/small.txt" "s3://$BUCKET_A/batch/one.txt" --quiet >/dev/null 2>&1
	aws_a s3 cp "$FIX/small.txt" "s3://$BUCKET_A/batch/two.txt" --quiet >/dev/null 2>&1
	aws_a s3api delete-objects --bucket "$BUCKET_A" \
		--delete 'Objects=[{Key=batch/one.txt},{Key=batch/two.txt}]' >"$LOGS/aws-delete-objects.log" 2>&1
	if ! object_exists "$BUCKET_A" batch/one.txt && ! object_exists "$BUCKET_A" batch/two.txt; then
		pass "DeleteObjects removes every key in the batch (PND-0165)"
	else
		fail "DeleteObjects removes every key in the batch (PND-0165)" \
			"$(tail -5 "$LOGS/aws-delete-objects.log")"
	fi

	# The half that matters: one key the caller may delete, one it may not.
	# A partial delete reported as a success is the exact failure this repo
	# exists to avoid, so the denied key must come back in <Error> AND still
	# be there afterwards.
	aws_a s3 cp "$FIX/small.txt" "s3://$BUCKET_A/allowed/a.txt" --quiet >/dev/null 2>&1
	aws_a s3 cp "$FIX/small.txt" "s3://$BUCKET_A/denied/b.txt" --quiet >/dev/null 2>&1
	aws_scoped s3api delete-objects --bucket "$BUCKET_A" \
		--delete 'Objects=[{Key=allowed/a.txt},{Key=denied/b.txt}]' \
		>"$LOGS/aws-delete-partial.log" 2>&1
	partial_ok=1
	grep -q '"Key": "allowed/a.txt"' "$LOGS/aws-delete-partial.log" || partial_ok=0
	grep -q '"Code": "AccessDenied"' "$LOGS/aws-delete-partial.log" || partial_ok=0
	object_exists "$BUCKET_A" allowed/a.txt && partial_ok=0
	object_exists "$BUCKET_A" denied/b.txt || partial_ok=0
	if [ "$partial_ok" -eq 1 ]; then
		pass "a partial DeleteObjects reports the failed key and keeps it (PND-0165)"
	else
		fail "a partial DeleteObjects reports the failed key and keeps it (PND-0165)" \
			"$(tr '\n' ' ' <"$LOGS/aws-delete-partial.log" | cut -c1-220)"
	fi

	# --- what jay does not implement says so --------------------------------
	aws_a s3api get-bucket-versioning --bucket "$BUCKET_A" >"$LOGS/aws-versioning.log" 2>&1
	if grep -q "NotImplemented" "$LOGS/aws-versioning.log"; then
		pass "an unimplemented sub-resource answers NotImplemented, not 200"
	else
		fail "an unimplemented sub-resource answers NotImplemented, not 200" \
			"$(tail -2 "$LOGS/aws-versioning.log")"
	fi

	# --- rb --force: recursive delete plus DeleteBucket ---------------------
	aws_a s3 mb "s3://$BUCKET_RB" >/dev/null 2>&1
	aws_a s3 cp "$FIX/small.txt" "s3://$BUCKET_RB/leftover.txt" --quiet >/dev/null 2>&1
	if aws_a s3 rb --force "s3://$BUCKET_RB" >"$LOGS/aws-rb.log" 2>&1 &&
		! aws_a s3api head-bucket --bucket "$BUCKET_RB" >/dev/null 2>&1; then
		pass "rb --force empties and deletes the bucket"
	else
		fail "rb --force empties and deletes the bucket" "$(tail -2 "$LOGS/aws-rb.log")"
	fi
fi

# ---------------------------------------------------------------------------
# GROUP: integrity — a checksum the client declares is verified (PND-0189)
#
# Until 2026-09-02 jay read none of them. A PUT carrying a deliberately wrong
# x-amz-checksum-sha256 answered 200, stored the object, and echoed back the
# digest it had computed itself — an unconditional success to the one request
# that is explicitly about integrity. The AWS CLI declares a CRC64NVME on every
# upload it makes, so this was not an edge case: it was every upload.
#
# Driven with curl and the bearer form on purpose. These assertions have to run
# even when no S3 client is installed, and they need to send a digest that is
# wrong — which no correct client will do for us. They are excluded from the
# client-pass counter so they cannot mask a run where nothing else ran.
#
# Every check asserts the EFFECT, twice over: the status code, that the key is
# unreadable afterwards, and — for the first one — that the data directory did
# not gain a single file. A 400 that still wrote the object would be worse than
# no 400 at all, and only the last assertion can tell them apart.
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}integrity: declared checksums (PND-0189)${C_RESET}"
GROUP="integrity"

BUCKET_INT="conformance-int"

# curl_a METHOD PATH [CURL ARGS...] — prints the status code, body in $WORK/int.body.
curl_a() {
	local method="$1" path="$2"
	shift 2
	curl -sS -o "$WORK/int.body" -w '%{http_code}' \
		-X "$method" -H "Authorization: Bearer $A_ID:$A_SECRET" \
		"$@" "$S3$path" 2>/dev/null
}

# data_files — how many regular files the plain-HTTP jay holds under buckets/.
data_files() { find "$WORK/data-http/buckets" -type f 2>/dev/null | wc -l | tr -d ' '; }

# refused_and_absent NAME KEY WANT_CODE CURL ARGS... — the workhorse: a PUT that
# must be refused with WANT_CODE in the XML, after which the key must not exist.
refused_and_absent() {
	local name="$1" key="$2" want_code="$3"
	shift 3
	local http body get_code
	http="$(curl_a PUT "/$BUCKET_INT/$key" --data-binary "conformance payload" "$@")"
	body="$(cat "$WORK/int.body" 2>/dev/null)"
	get_code="$(curl -sS -o /dev/null -w '%{http_code}' \
		-H "Authorization: Bearer $A_ID:$A_SECRET" "$S3/$BUCKET_INT/$key" 2>/dev/null)"

	if [ "$http" != "400" ]; then
		fail "$name" "http=$http body=$(printf '%s' "$body" | tr -d '\n' | cut -c1-160)"
		return
	fi
	case "$body" in
	*"<Code>$want_code</Code>"*) ;;
	*)
		fail "$name" "want $want_code, got $(printf '%s' "$body" | tr -d '\n' | cut -c1-160)"
		return
		;;
	esac
	if [ "$get_code" != "404" ]; then
		fail "$name" "refused with 400 but the object is readable (GET $get_code)"
		return
	fi
	pass "$name"
}

if [ "$(curl_a PUT "/$BUCKET_INT")" != "200" ]; then
	skip "whole group" "could not create $BUCKET_INT: $(cat "$WORK/int.body" | tr -d '\n' | cut -c1-160)"
else
	# The one that also counts the files on disk. A rejection that leaves the
	# object (or a temp file) behind is the failure mode this whole change is
	# about, and the response cannot show it.
	files_before="$(data_files)"
	refused_and_absent "a wrong x-amz-checksum-sha256 is refused" wrong-sha256.txt BadDigest \
		-H "x-amz-checksum-sha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	files_after="$(data_files)"
	assert_eq "a refused upload leaves nothing on disk" "$files_before" "$files_after"

	refused_and_absent "a wrong Content-MD5 is refused" wrong-md5.txt BadDigest \
		-H "Content-MD5: AAAAAAAAAAAAAAAAAAAAAA=="

	# CRC64NVME is what the AWS CLI declares by default, so this is the header
	# that carried the defect in practice.
	refused_and_absent "a wrong x-amz-checksum-crc64nvme is refused" wrong-crc64.txt BadDigest \
		-H "x-amz-checksum-crc64nvme: AAAAAAAAAAA="

	# An algorithm jay cannot compute must say so instead of answering 200 with
	# a SHA-256 nobody asked for.
	refused_and_absent "an algorithm jay does not compute is refused" alg-sha512.txt InvalidRequest \
		-H "x-amz-sdk-checksum-algorithm: SHA512"

	refused_and_absent "a malformed Content-MD5 is refused" bad-md5.txt InvalidDigest \
		-H "Content-MD5: not-base64"

	# The control. Without it a jay that refused every upload would pass every
	# check above, and the group would prove the opposite of what it claims.
	good_sum="$(printf 'conformance payload' | openssl dgst -sha256 -binary | openssl base64 -A)"
	ok_http="$(curl_a PUT "/$BUCKET_INT/right-sha256.txt" --data-binary "conformance payload" \
		-H "x-amz-checksum-sha256: $good_sum")"
	ok_get="$(curl -sS -o /dev/null -w '%{http_code}' \
		-H "Authorization: Bearer $A_ID:$A_SECRET" "$S3/$BUCKET_INT/right-sha256.txt" 2>/dev/null)"
	if [ "$ok_http" = "200" ] && [ "$ok_get" = "200" ]; then
		pass "control: a correct x-amz-checksum-sha256 is accepted"
	else
		fail "control: a correct x-amz-checksum-sha256 is accepted" "put=$ok_http get=$ok_get"
	fi

	# A part with a false digest corrupts the assembled object just as much, and
	# a part that is refused must not be registered either.
	int_upload="$(curl -sS -X POST -H "Authorization: Bearer $A_ID:$A_SECRET" \
		"$S3/$BUCKET_INT/mp.bin?uploads" 2>/dev/null |
		sed -n 's/.*<UploadId>\([^<]*\)<\/UploadId>.*/\1/p')"
	if [ -z "$int_upload" ]; then
		fail "a wrong part checksum is refused and the part is not registered" \
			"CreateMultipartUpload returned no UploadId"
	else
		part_http="$(curl_a PUT "/$BUCKET_INT/mp.bin?uploadId=$int_upload&partNumber=1" \
			--data-binary "part payload" -H "x-amz-checksum-crc32: AAAAAA==")"
		parts="$(curl -sS -H "Authorization: Bearer $A_ID:$A_SECRET" \
			"$S3/$BUCKET_INT/mp.bin?uploadId=$int_upload" 2>/dev/null | grep -c "<Part>")"
		if [ "$part_http" = "400" ] && [ "$parts" = "0" ]; then
			pass "a wrong part checksum is refused and the part is not registered"
		else
			fail "a wrong part checksum is refused and the part is not registered" \
				"http=$part_http parts_registered=$parts"
		fi
		curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $A_ID:$A_SECRET" \
			"$S3/$BUCKET_INT/mp.bin?uploadId=$int_upload" 2>/dev/null
	fi
fi

# ---------------------------------------------------------------------------
# GROUP: cross-account (PND-0185)
#
# Until 2026-09-02 a token of account B could read, write and delete inside a
# bucket of account A: only DeleteBucket, HeadBucket and GetBucketLocation
# checked ownership. Every check here asserts the EFFECT as account A, not just
# the error message account B received — a 403 that still wrote the object
# would be worse than no 403 at all.
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}cross-account isolation${C_RESET}"
GROUP="cross-account"

if [ -z "$AWS_BIN" ]; then
	skip "whole group" "aws-cli is not installed"
elif ! object_exists "$BUCKET_A" small.txt; then
	skip "whole group" "the aws-cli group did not leave $BUCKET_A/small.txt in place"
else
	if aws_b s3api list-objects-v2 --bucket "$BUCKET_A" >"$LOGS/xacct-list.log" 2>&1; then
		fail "B cannot list A's bucket" "the listing succeeded"
	else
		pass "B cannot list A's bucket"
	fi

	if aws_b s3api get-object --bucket "$BUCKET_A" --key small.txt "$WORK/stolen.txt" >"$LOGS/xacct-get.log" 2>&1; then
		fail "B cannot read A's object" "the download succeeded"
	else
		pass "B cannot read A's object"
	fi

	# --quiet swallows the failure line, so never trust the message here: the
	# exit code plus A's own view of the bucket are the assertion.
	aws_b s3api put-object --bucket "$BUCKET_A" --key intruder.txt --body "$FIX/small.txt" \
		>"$LOGS/xacct-put.log" 2>&1
	put_rc=$?
	if [ "$put_rc" -ne 0 ] && ! object_exists "$BUCKET_A" intruder.txt; then
		pass "B cannot write into A's bucket, and nothing was written"
	else
		fail "B cannot write into A's bucket" "rc=$put_rc, object present=$(object_exists "$BUCKET_A" intruder.txt && echo yes || echo no)"
	fi

	aws_b s3api delete-object --bucket "$BUCKET_A" --key small.txt >"$LOGS/xacct-del.log" 2>&1
	del_rc=$?
	if [ "$del_rc" -ne 0 ] && object_exists "$BUCKET_A" small.txt; then
		pass "B cannot delete A's object, and it is still there"
	else
		fail "B cannot delete A's object" "rc=$del_rc"
	fi

	aws_b s3api delete-objects --bucket "$BUCKET_A" --delete 'Objects=[{Key=small.txt}]' \
		>"$LOGS/xacct-batch.log" 2>&1
	batch_rc=$?
	if [ "$batch_rc" -ne 0 ] && object_exists "$BUCKET_A" small.txt; then
		pass "B cannot batch-delete A's objects, and they are still there"
	else
		fail "B cannot batch-delete A's objects" "rc=$batch_rc"
	fi

	if aws_b s3api head-bucket --bucket "$BUCKET_A" >"$LOGS/xacct-head.log" 2>&1; then
		fail "B cannot HeadBucket A's bucket" "it succeeded"
	else
		pass "B cannot HeadBucket A's bucket"
	fi

	# The control. Without it, a token that is simply broken would pass every
	# check above and the group would prove nothing.
	if aws_b s3 mb "s3://$BUCKET_B" >"$LOGS/xacct-own.log" 2>&1 &&
		aws_b s3 cp "$FIX/small.txt" "s3://$BUCKET_B/ok.txt" --quiet >>"$LOGS/xacct-own.log" 2>&1 &&
		aws_b s3api head-object --bucket "$BUCKET_B" --key ok.txt >/dev/null 2>&1; then
		pass "control: B works normally in its own bucket"
	else
		fail "control: B works normally in its own bucket" "$(tail -3 "$LOGS/xacct-own.log")"
	fi
fi

# ---------------------------------------------------------------------------
# GROUP: mc over plain HTTP (minio-go)
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}mc / minio-go over HTTP${C_RESET}"
GROUP="mc-http"

export MC_CONFIG_DIR="$WORK/mc"
mkdir -p "$MC_CONFIG_DIR"
mc_() { "$MC_BIN" --no-color "$@"; }

if [ -z "$MC_BIN" ]; then
	skip "whole group" "mc is not installed"
elif [ -z "$AWS_BIN" ]; then
	skip "whole group" "the fixtures this group reads are uploaded by the aws-cli group"
else
	if mc_ alias set jayhttp "$S3" "$A_ID" "$A_SECRET" --api S3v4 >"$LOGS/mc-alias.log" 2>&1; then
		pass "mc alias set"
	else
		fail "mc alias set" "$(tail -2 "$LOGS/mc-alias.log")"
	fi

	buckets="$(mc_ ls jayhttp 2>"$LOGS/mc-lsb.log" | awk '{print $NF}' | tr -d '/' | sort | tr '\n' ' ')"
	case "$buckets" in
	*"$BUCKET_A"*) pass "ListBuckets" ;;
	*) fail "ListBuckets" "got [$buckets]" ;;
	esac

	keys="$(mc_ ls jayhttp/"$BUCKET_A" 2>"$LOGS/mc-ls.log" | awk '{print $NF}' | sort | tr '\n' ' ')"
	case "$keys" in
	*small.txt*) pass "ListObjects" ;;
	*) fail "ListObjects" "got [$keys]" ;;
	esac

	mc_ stat jayhttp/"$BUCKET_A"/small.txt >"$LOGS/mc-stat.log" 2>&1
	mc_sum="$(sed -n 's/^Checksum *: *SHA256://p' "$LOGS/mc-stat.log" | tr -d ' ')"
	assert_eq "stat reports the SHA-256 checksum minio-go can parse" "$SMALL_B64" "$mc_sum"

	if mc_ get jayhttp/"$BUCKET_A"/small.txt "$WORK/mc.dl" >"$LOGS/mc-get.log" 2>&1 &&
		cmp -s "$FIX/small.txt" "$WORK/mc.dl"; then
		pass "GetObject round-trips"
	else
		fail "GetObject round-trips" "$(tail -2 "$LOGS/mc-get.log")"
	fi

	if mc_ mb jayhttp/conformance-mc >"$LOGS/mc-mb.log" 2>&1 &&
		mc_ rb --force jayhttp/conformance-mc >>"$LOGS/mc-mb.log" 2>&1; then
		pass "CreateBucket and DeleteBucket"
	else
		fail "CreateBucket and DeleteBucket" "$(tail -2 "$LOGS/mc-mb.log")"
	fi

	if mc_ rm jayhttp/"$BUCKET_A"/denied/b.txt >"$LOGS/mc-rm.log" 2>&1 &&
		! object_exists "$BUCKET_A" denied/b.txt; then
		pass "DeleteObject"
	else
		fail "DeleteObject" "$(tail -2 "$LOGS/mc-rm.log")"
	fi

	# minio-go mints a SigV4 query-string URL of its own — a second, independent
	# implementation of the form PND-0161 added.
	share="$(mc_ share download --expire 5m jayhttp/"$BUCKET_A"/small.txt 2>"$LOGS/mc-share.log" | sed -n 's/^Share: //p')"
	if [ -z "$share" ]; then
		fail "SigV4 presigned GET minted by minio-go (PND-0161)" "$(tail -2 "$LOGS/mc-share.log")"
	else
		scode="$(curl -sS -o "$WORK/mc-presign.dl" -w '%{http_code}' "$share" 2>/dev/null)"
		if [ "$scode" = "200" ] && cmp -s "$FIX/small.txt" "$WORK/mc-presign.dl"; then
			pass "SigV4 presigned GET minted by minio-go (PND-0161)"
		else
			fail "SigV4 presigned GET minted by minio-go (PND-0161)" "http=$scode"
		fi
	fi

	# KNOWN LIMIT — asserted, not tolerated.
	#
	# Over plain HTTP minio-go signs every PutObject with the SigV4 *streaming*
	# signature and frames the body as aws-chunked. jay has no decoder for that
	# framing and refuses the request with 501 rather than storing the framing
	# as the object, which is what it used to do (PND-0186).
	#
	# The day the decoder lands (PND-0188) this check goes red on purpose: the
	# upload will succeed and the assertion below will stop holding, forcing
	# whoever implements it to come back here and to the README.
	mc_ cp "$FIX/small.txt" jayhttp/"$BUCKET_A"/via-mc.txt >"$LOGS/mc-cp.log" 2>&1
	mc_rc=$?
	if [ "$mc_rc" -ne 0 ] &&
		grep -qi "not implemented" "$LOGS/mc-cp.log" &&
		! object_exists "$BUCKET_A" via-mc.txt; then
		pass "known limit: an mc upload is refused with 501 and writes nothing (PND-0186/PND-0188)"
	else
		fail "known limit: an mc upload is refused with 501 and writes nothing (PND-0186/PND-0188)" \
			"rc=$mc_rc, object present=$(object_exists "$BUCKET_A" via-mc.txt && echo yes || echo no). If the aws-chunked decoder landed, update this check and the README."
	fi
fi

# ---------------------------------------------------------------------------
# GROUP: mc over TLS (minio-go)
#
# Same client, same version, opposite outcome: minio-go only reaches for the
# streaming signature when the connection is NOT secure, so over HTTPS it sends
# an unframed body and jay stores it. This is why the README cannot say
# "minio-go uploads fail" without saying over what.
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}mc / minio-go over TLS${C_RESET}"
GROUP="mc-tls"

if [ -z "$MC_BIN" ]; then
	skip "whole group" "mc is not installed"
else
	mc_tls() { "$MC_BIN" --no-color --insecure "$@"; }

	if mc_tls alias set jaytls "$TLS_S3" "$TLS_ID" "$TLS_SECRET" --api S3v4 >"$LOGS/mctls-alias.log" 2>&1 &&
		mc_tls mb jaytls/conformance-tls >"$LOGS/mctls-mb.log" 2>&1; then
		pass "alias and CreateBucket over HTTPS"
	else
		fail "alias and CreateBucket over HTTPS" "$(tail -2 "$LOGS/mctls-mb.log")"
	fi

	if mc_tls cp "$FIX/small.txt" jaytls/conformance-tls/small.txt >"$LOGS/mctls-cp.log" 2>&1 &&
		mc_tls get jaytls/conformance-tls/small.txt "$WORK/mctls.dl" >>"$LOGS/mctls-cp.log" 2>&1 &&
		cmp -s "$FIX/small.txt" "$WORK/mctls.dl"; then
		pass "PutObject over HTTPS round-trips (minio-go sends no aws-chunked framing here)"
	else
		fail "PutObject over HTTPS round-trips" "$(tail -3 "$LOGS/mctls-cp.log")"
	fi

	if mc_tls cp "$FIX/big.bin" jaytls/conformance-tls/big.bin >"$LOGS/mctls-big.log" 2>&1 &&
		mc_tls get jaytls/conformance-tls/big.bin "$WORK/mctls-big.dl" >>"$LOGS/mctls-big.log" 2>&1; then
		assert_eq "12 MiB upload over HTTPS round-trips byte for byte" "$BIG_SHA" "$(hexsha256 "$WORK/mctls-big.dl")"
	else
		fail "12 MiB upload over HTTPS round-trips byte for byte" "$(tail -3 "$LOGS/mctls-big.log")"
	fi
fi

# ---------------------------------------------------------------------------
# GROUP: warp (minio-go under load)
#
# warp exits 0 even when every single operation failed — its exit code reports
# "the benchmark ran", not "the benchmark worked". So both checks below read the
# report and the bucket, never the exit status.
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}warp${C_RESET}"
GROUP="warp"

if [ -z "$WARP_BIN" ]; then
	skip "whole group" "warp is not installed (go install github.com/minio/warp@latest)"
else
	# KNOWN LIMIT, same framing as mc: over plain HTTP every PUT is refused.
	run_limited 120 "$WARP_BIN" put --host="127.0.0.1:$S3_PORT" \
		--access-key="$A_ID" --secret-key="$A_SECRET" --bucket=warp-http \
		--duration=3s --obj.size=1KiB --concurrent=2 --noclear --no-color \
		--benchdata="$WORK/warp-http" >"$LOGS/warp-http.log" 2>&1
	warp_http_state="$(bucket_state warp-http)"
	if grep -qi "not implemented" "$LOGS/warp-http.log" && [ "$warp_http_state" = "empty" ]; then
		pass "known limit: warp cannot upload over HTTP and leaves the bucket empty (PND-0186/PND-0188)"
	else
		fail "known limit: warp cannot upload over HTTP and leaves the bucket empty (PND-0186/PND-0188)" \
			"bucket warp-http is [$warp_http_state], refusal in the log=$(grep -qi 'not implemented' "$LOGS/warp-http.log" && echo yes || echo no). If the aws-chunked decoder landed, update this check and the README."
	fi

	# And the real smoke test: the same tool, over TLS, doing PUT/GET/DELETE/STAT
	# concurrently for ten seconds. The number it prints is the one PND-0176 can
	# publish; the assertion is that it ran with zero errors.
	run_limited 180 "$WARP_BIN" mixed --host="127.0.0.1:$TLS_S3_PORT" --tls --insecure \
		--access-key="$TLS_ID" --secret-key="$TLS_SECRET" --bucket=warp-tls \
		--duration=10s --obj.size=256KiB --concurrent=4 --no-color \
		--benchdata="$WORK/warp-tls" >"$LOGS/warp-tls.log" 2>&1
	warp_total="$(sed -n 's/^ \* Average: \(.*\)$/\1/p' "$LOGS/warp-tls.log" | tail -1)"
	if grep -qi "error" "$LOGS/warp-tls.log"; then
		fail "warp mixed over TLS runs clean" "$(grep -i error "$LOGS/warp-tls.log" | head -2)"
	elif [ -z "$warp_total" ]; then
		fail "warp mixed over TLS runs clean" "warp printed no report: $(tail -3 "$LOGS/warp-tls.log")"
	else
		pass "warp mixed over TLS runs clean — $warp_total"
	fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

say ""
say "${C_BOLD}Results${C_RESET}"
say ""
printf '  %-6s  %-14s  %s\n' "STATUS" "GROUP" "CHECK"
printf '  %-6s  %-14s  %s\n' "------" "--------------" "--------------------------------------------"
for row in ${RESULTS[@]+"${RESULTS[@]}"}; do
	status="${row%%|*}"
	rest="${row#*|}"
	group="${rest%%|*}"
	rest="${rest#*|}"
	name="${rest%%|*}"
	detail="${rest#*|}"
	case "$status" in
	PASS) color="$C_PASS" ;;
	FAIL) color="$C_FAIL" ;;
	*) color="$C_SKIP" ;;
	esac
	printf '  %s%-6s%s  %-14s  %s\n' "$color" "$status" "$C_RESET" "$group" "$name"
	if [ "$status" != "PASS" ] && [ -n "$detail" ]; then
		printf '  %s%-6s  %-14s  → %s%s\n' "$C_DIM" "" "" "$detail" "$C_RESET"
	fi
done

TOTAL=$((N_PASS + N_FAIL + N_SKIP))
say ""
printf '  %d checks: %s%d passed%s, %s%d failed%s, %s%d skipped%s\n' \
	"$TOTAL" "$C_PASS" "$N_PASS" "$C_RESET" "$C_FAIL" "$N_FAIL" "$C_RESET" \
	"$C_SKIP" "$N_SKIP" "$C_RESET"
say ""

if [ "$TOTAL" -eq 0 ] || [ "$N_CLIENT_PASS" -eq 0 ]; then
	printf '%sNOTHING WAS PROVEN%s: no check driven by a real S3 client ran. A green exit\n' \
		"$C_FAIL" "$C_RESET" >&2
	printf 'here would be a lie about the only thing this harness measures.\n' >&2
	exit 2
fi

if [ "$N_FAIL" -gt 0 ]; then
	printf '%sFAILED%s: %d check(s) broke a promise the README makes.\n' "$C_FAIL" "$C_RESET" "$N_FAIL" >&2
	exit 1
fi

if [ "$N_SKIP" -gt 0 ]; then
	printf '%sPASSED WITH %d SKIPPED%s — a skip is not a pass. Install the missing\n' \
		"$C_SKIP" "$N_SKIP" "$C_RESET"
	printf 'client, or run with --require-all to make a missing one fail the run.\n'
fi

exit 0
