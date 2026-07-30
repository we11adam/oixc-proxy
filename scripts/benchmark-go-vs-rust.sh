#!/bin/sh
set -eu

rust_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
go_root=${GO_OIXC_ROOT:-/Users/adam/Projects/oixc}
listen=${BENCH_LISTEN:-127.0.0.1:19090}
bench_tmp=$(mktemp -d "${TMPDIR:-/tmp}/oixc-snell-bench.XXXXXX")
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
(
    cd "$go_root"
    go build \
        -trimpath \
        -ldflags="-s -w" \
        -o "$bench_tmp/go-bench-client" \
        ./tools/snell-bench-client
)

rust_server="$rust_root/target/release/examples/snell-bench-server"
rust_client="$rust_root/target/release/examples/snell-bench-client"
ready_file="$bench_tmp/server-ready.json"
error_file="$bench_tmp/server-error.log"
results_file="$bench_tmp/results.ndjson"

"$rust_server" --listen "$listen" >"$ready_file" 2>"$error_file" &
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
    reuse=$6

    "$bench_tmp/go-bench-client" \
        -server "$listen" \
        -requests "$requests" \
        -warmup "$warmup" \
        -concurrency "$concurrency" \
        -payload-bytes "$payload_bytes" \
        -reuse="$reuse" |
        jq -c --arg scenario "$scenario" '. + {scenario: $scenario}' |
        tee -a "$results_file"

    "$rust_client" \
        --server "$listen" \
        --requests "$requests" \
        --warmup "$warmup" \
        --concurrency "$concurrency" \
        --payload-bytes "$payload_bytes" \
        --reuse "$reuse" |
        jq -c --arg scenario "$scenario" '. + {scenario: $scenario}' |
        tee -a "$results_file"
}

run_case fresh-1k 1000 50 1 1024 false
run_case reuse-1k 10000 500 1 1024 true
run_case parallel-reuse-1k 10000 500 16 1024 true
run_case parallel-reuse-1m 500 20 4 1048576 true

echo
printf '%-22s %13s %13s %10s %12s %12s\n' \
    scenario go_ops_s rust_ops_s rust_go go_p50_us rust_p50_us
jq -s -r '
    group_by(.scenario)[] |
    (map(select(.implementation == "go"))[0]) as $go |
    (map(select(.implementation == "rust"))[0]) as $rust |
    [
        .[0].scenario,
        ($go.operations_per_second | tostring),
        ($rust.operations_per_second | tostring),
        (($rust.operations_per_second / $go.operations_per_second) | tostring),
        ($go.latency_p50_us | tostring),
        ($rust.latency_p50_us | tostring)
    ] |
    @tsv
' "$results_file" |
while IFS='	' read -r scenario go_ops rust_ops ratio go_p50 rust_p50; do
    printf '%-22s %13.1f %13.1f %9.3fx %12.1f %12.1f\n' \
        "$scenario" "$go_ops" "$rust_ops" "$ratio" "$go_p50" "$rust_p50"
done

if [ -n "${RESULTS_FILE:-}" ]; then
    cp "$results_file" "$RESULTS_FILE"
    echo
    echo "Raw results: $RESULTS_FILE"
fi
