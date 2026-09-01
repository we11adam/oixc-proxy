#!/bin/sh
set -eu

rust_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
listen=${BENCH_LISTEN:-127.0.0.1:19090}
trace_sample_every=${TRACE_SAMPLE_EVERY:-0}
bench_tmp=$(mktemp -d "${TMPDIR:-/tmp}/oixc-gateway-bench.XXXXXX")
server_pid=

cleanup() {
    if [ -n "$server_pid" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$bench_tmp"
}
trap cleanup EXIT HUP INT TERM

cargo build \
    --manifest-path "$rust_root/Cargo.toml" \
    --release \
    --features benchmark \
    --example snell-bench-server \
    --example snell-bench-client

server="$rust_root/target/release/examples/snell-bench-server"
client="$rust_root/target/release/examples/snell-bench-client"
ready_file="$bench_tmp/server-ready.json"
error_file="$bench_tmp/server-error.log"
results_file="$bench_tmp/results.ndjson"

"$server" --listen "$listen" >"$ready_file" 2>"$error_file" &
server_pid=$!

attempt=0
while [ ! -s "$ready_file" ]; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        sed -n '1,120p' "$error_file" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 100 ]; then
        echo "benchmark server did not become ready" >&2
        exit 1
    fi
    sleep 0.05
done

run_case() {
    scenario=$1
    requests=$2
    warmup=$3
    concurrency=$4
    payload_bytes=$5
    application_chunk_bytes=$6
    reuse=$7

    result=$("$client" \
        --server "$listen" \
        --requests "$requests" \
        --warmup "$warmup" \
        --concurrency "$concurrency" \
        --payload-bytes "$payload_bytes" \
        --application-chunk-bytes "$application_chunk_bytes" \
        --reuse "$reuse" \
        --gateway true \
        --trace-sample-every "$trace_sample_every")
    printf '%s\n' "$result" |
        jq -c --arg scenario "$scenario" '. + {scenario: $scenario}' |
        tee -a "$results_file"
}

run_case gateway-fresh-1k 500 25 1 1024 1024 false
run_case gateway-reuse-1k 2000 100 1 1024 1024 true
run_case gateway-parallel-reuse-1k 2000 100 16 1024 1024 true
run_case gateway-parallel-stream-1m 200 10 4 1048576 32768 true

echo
printf '%-34s %13s %12s %12s %12s\n' \
    scenario operations_s p50_us p95_us p99_us
jq -s -r '
    .[] |
    [
        .scenario,
        (.operations_per_second | tostring),
        (.latency_p50_us | tostring),
        (.latency_p95_us | tostring),
        (.latency_p99_us | tostring)
    ] |
    @tsv
' "$results_file" |
while IFS='	' read -r scenario operations p50 p95 p99; do
    printf '%-34s %13.1f %12.1f %12.1f %12.1f\n' \
        "$scenario" "$operations" "$p50" "$p95" "$p99"
done

if [ -n "${RESULTS_FILE:-}" ]; then
    cp "$results_file" "$RESULTS_FILE"
    echo
    echo "Raw results: $RESULTS_FILE"
fi
