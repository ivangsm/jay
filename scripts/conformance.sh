#!/usr/bin/env bash
#
# conformance.sh — exercise jay's S3 surface with S3 clients jay did not write.
#
# The Go tests prove only that jay agrees with itself. This script boots a
# throwaway jay and drives it with a real client: aws-cli (botocore). MinIO's
# clients (mc, warp, minio-go) are not supported and not exercised here.
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
# Requirements: go, curl, openssl. The S3 client is optional unless
# --require-all is given:
#   aws  — https://docs.aws.amazon.com/cli/  (botocore; the reference client)

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
# Everything the run creates lives under one temp dir: the built binary, the
# data dir, the client's config and every captured log.
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
# raw SHA-256, base64. Not hex.
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

info "aws:  ${AWS_BIN:-(not found)}"

if [ "$REQUIRE_ALL" -eq 1 ]; then
	missing=""
	[ -z "$AWS_BIN" ] && missing="$missing aws"
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
(cd "$REPO_ROOT" && go build -o "$WORK/jay" ./cmd/jay) || die "go build failed"

# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

S3_PORT="$(pick_port)"
ADMIN_PORT="$(pick_port)"
NATIVE_PORT="$(pick_port)"

ADMIN_TOKEN="$(openssl rand -base64 32)"
SIGNING_SECRET="$(openssl rand -base64 32)"

A_ID="conformance-a"
A_SECRET="$(openssl rand -hex 24)"

# start_jay NAME DATADIR S3PORT ADMINPORT NATIVEPORT SEEDID SEEDSECRET
start_jay() {
	local name="$1" datadir="$2" s3p="$3" adminp="$4" nativep="$5"
	local seed_id="$6" seed_secret="$7"
	mkdir -p "$datadir"

	# The rate limiter defaults to 100 rps per token. aws-cli fires 10 parallel
	# part uploads, so the default would make the run measure the limiter
	# instead of the S3 surface.
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

start_jay "http" "$WORK/data-http" "$S3_PORT" "$ADMIN_PORT" "$NATIVE_PORT" "$A_ID" "$A_SECRET"

S3="http://127.0.0.1:$S3_PORT"
ADMIN="http://127.0.0.1:$ADMIN_PORT"

wait_ready "$ADMIN/health/ready" || {
	cat "$LOGS/jay-http.log" >&2
	die "jay never became ready"
}
info "jay is up on $S3 (admin $ADMIN)"

# ---------------------------------------------------------------------------
# Accounts and tokens
#
# Account A comes from the seed variables. Account B and the prefix-scoped
# token come from the admin API, because the suite needs three distinct
# authorities: a full one, one that belongs to a different account and one
# that can only reach part of a bucket (the partial batch delete).
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
# and the download becomes ranged GETs. Both halves matter: the checksum
# header is verified on the way down.
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

	# S3 defines every x-amz-checksum-* header as the raw digest in base64;
	# aws-cli aborts a download whose header is hex, over intact bytes.
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
	# --checksum-algorithm is the client saying "verify my bytes with THIS";
	# answering ChecksumSHA256 whatever was asked is tolerated by botocore and
	# not by a client that checks the algorithm. All five S3 algorithms are
	# exercised so a gap cannot go unnoticed.
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

		# The same promise through the other door. A copy has no digest to
		# verify — the bytes never left the server — but the client can still
		# ask for one. The expected value is the digest put-object just returned
		# for the SAME bytes, so a copy that hashed the wrong thing, or answered
		# in hex where S3 wants base64, fails even though the response looks
		# checksum-shaped.
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

	# --- presigned URL, minted by the client ------------------------------
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

	# --- bucket-level operations ------------------------------------------
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

	# --- batch delete, whole and partial ----------------------------------
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
# GROUP: integrity — a checksum the client declares is verified
#
# The AWS CLI declares a CRC64NVME on every upload it makes, so a PUT whose
# declared digest is wrong must be refused, not stored under a 200.
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
	# The one that also counts the files on disk: a rejection that leaves the
	# object (or a temp file) behind is invisible in the response.
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

	# SigV4's streaming mode frames the body as aws-chunked. jay has no decoder
	# for it, so the request is answered 501 before a byte is read — never a 200
	# that stores the chunk headers as part of the object.
	files_before="$(data_files)"
	chunked_http="$(curl_a PUT "/$BUCKET_INT/chunked.txt" --data-binary "conformance payload" \
		-H "Content-Encoding: aws-chunked" -H "x-amz-decoded-content-length: 19")"
	chunked_body="$(tr -d '\n' <"$WORK/int.body" 2>/dev/null)"
	chunked_get="$(curl -sS -o /dev/null -w '%{http_code}' \
		-H "Authorization: Bearer $A_ID:$A_SECRET" "$S3/$BUCKET_INT/chunked.txt" 2>/dev/null)"
	if [ "$chunked_http" = "501" ] && [ "$chunked_get" = "404" ] &&
		[ "$(data_files)" = "$files_before" ] &&
		case "$chunked_body" in *"<Code>NotImplemented</Code>"*) true ;; *) false ;; esac; then
		pass "an aws-chunked body is refused with 501 and writes nothing"
	else
		fail "an aws-chunked body is refused with 501 and writes nothing" \
			"put=$chunked_http get=$chunked_get body=$(printf '%s' "$chunked_body" | cut -c1-160)"
	fi

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
# GROUP: cross-account
#
# A token of account B must not read, write or delete inside a bucket of
# account A. Every check here asserts the EFFECT as account A, not just the
# error message account B received — a 403 that still wrote the object would
# be worse than no 403 at all.
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
