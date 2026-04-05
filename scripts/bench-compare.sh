#!/usr/bin/env bash
#
# bench-compare.sh — Run S3 vs Native protocol benchmarks and display a comparison.
#
# Usage:
#   ./scripts/bench-compare.sh              # run all benchmarks
#   ./scripts/bench-compare.sh -count 5     # 5 iterations per benchmark
#   ./scripts/bench-compare.sh -short       # shorter run
#
set -euo pipefail

COUNT="${1:-}"
BENCH_ARGS=()
if [[ "$COUNT" == "-count" && -n "${2:-}" ]]; then
    BENCH_ARGS+=("-count" "$2")
    shift 2
elif [[ "$COUNT" == "-short" ]]; then
    BENCH_ARGS+=("-benchtime" "1s")
    shift
fi

cd "$(git rev-parse --show-toplevel)"

echo "=============================================="
echo " Jay Benchmark: S3 HTTP vs Native Protocol"
echo "=============================================="
echo ""
echo "Running benchmarks... this may take a few minutes."
echo ""

TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

go test -bench='Benchmark(S3|Native)' -benchmem -timeout 30m "${BENCH_ARGS[@]}" "$@" 2>&1 | tee "$TMPFILE"

echo ""
echo "=============================================="
echo " Comparison Summary"
echo "=============================================="
echo ""

# Parse results and build comparison table
awk '
BEGIN {
    # Column widths
    printf "%-42s %14s %14s %10s\n", "Operation", "S3 (ns/op)", "Native (ns/op)", "Speedup"
    printf "%-42s %14s %14s %10s\n", "─────────", "──────────", "──────────────", "───────"
}

/^Benchmark/ {
    name = $1
    nsop = $3

    # Strip "Benchmark" prefix and "-N" suffix
    sub(/^Benchmark/, "", name)
    sub(/-[0-9]+$/, "", name)

    # Determine protocol and normalize the operation name
    if (name ~ /^S3/) {
        proto = "s3"
        op = name
        sub(/^S3/, "", op)
    } else if (name ~ /^Native/) {
        proto = "native"
        op = name
        sub(/^Native/, "", op)
    } else {
        next
    }

    if (proto == "s3") {
        s3[op] = nsop
    } else {
        native[op] = nsop
    }

    # Track order of operations
    if (!(op in seen)) {
        seen[op] = 1
        ops[++nops] = op
    }
}

END {
    for (i = 1; i <= nops; i++) {
        op = ops[i]
        s = s3[op]
        n = native[op]
        if (s != "" && n != "") {
            if (n > 0) {
                speedup = s / n
                printf "%-42s %14s %14s %9.1fx\n", op, s, n, speedup
            }
        } else if (s != "") {
            printf "%-42s %14s %14s %10s\n", op, s, "—", "—"
        } else if (n != "") {
            printf "%-42s %14s %14s %10s\n", op, "—", n, "—"
        }
    }
}
' "$TMPFILE"

echo ""
echo "(Speedup = S3 ns/op ÷ Native ns/op; higher is better for Native)"
