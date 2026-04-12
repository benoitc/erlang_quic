#!/bin/bash
#
# Distribution Benchmark: QUIC vs TCP
#
# Usage: ./scripts/run_dist_bench.sh [tcp|quic|both]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CERT_DIR="$PROJECT_DIR/certs"
COOKIE="benchcookie$$"
HOST=$(hostname -s)

# Build first
echo "Building..."
cd "$PROJECT_DIR"
rebar3 as test compile

# Ensure certs exist
if [ ! -f "$CERT_DIR/cert.pem" ]; then
    echo "Generating test certificates..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/priv.key" -out "$CERT_DIR/cert.pem" \
        -days 365 -nodes -subj '/CN=localhost' 2>/dev/null
fi

MODE=${1:-both}

cleanup() {
    echo "Cleaning up..."
    pkill -f "bench_server@$HOST" 2>/dev/null || true
    pkill -f "bench_client@$HOST" 2>/dev/null || true
}

trap cleanup EXIT

run_tcp_bench() {
    echo ""
    echo "========================================"
    echo "TCP Distribution Benchmark"
    echo "========================================"

    # Start server node in background
    erl -sname bench_server -setcookie "$COOKIE" \
        -pa _build/test/lib/quic/ebin \
        -pa _build/test/lib/quic/test \
        -noshell -eval "quic_dist_bench:server_loop()." &
    SERVER_PID=$!
    sleep 2

    # Run client benchmark
    erl -sname bench_client -setcookie "$COOKIE" \
        -pa _build/test/lib/quic/ebin \
        -pa _build/test/lib/quic/test \
        -noshell -eval "
            quic_dist_bench:run('bench_server@$HOST', #{iterations => 5000}),
            init:stop().
        "

    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}

run_quic_bench() {
    echo ""
    echo "========================================"
    echo "QUIC Distribution Benchmark"
    echo "========================================"

    # Create sys.config for QUIC
    cat > /tmp/quic_bench_sys.config <<EOF
[
    {quic, [
        {dist, [
            {cert_file, "$CERT_DIR/cert.pem"},
            {key_file, "$CERT_DIR/priv.key"},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, [
                {'bench_server@$HOST', {"127.0.0.1", 9100}},
                {'bench_client@$HOST', {"127.0.0.1", 9101}}
            ]}
        ]}
    ]}
].
EOF

    # Start QUIC server node
    erl -sname bench_server -setcookie "$COOKIE" \
        -proto_dist quic \
        -epmd_module quic_epmd \
        -start_epmd false \
        -quic_dist_port 9100 \
        -config /tmp/quic_bench_sys \
        -pa _build/test/lib/quic/ebin \
        -pa _build/test/lib/quic/test \
        -noshell -eval "
            application:ensure_all_started(quic),
            quic_dist_bench:server_loop().
        " &
    SERVER_PID=$!
    sleep 4

    # Run QUIC client benchmark
    erl -sname bench_client -setcookie "$COOKIE" \
        -proto_dist quic \
        -epmd_module quic_epmd \
        -start_epmd false \
        -quic_dist_port 9101 \
        -config /tmp/quic_bench_sys \
        -pa _build/test/lib/quic/ebin \
        -pa _build/test/lib/quic/test \
        -noshell -eval "
            application:ensure_all_started(quic),
            quic_dist_bench:run('bench_server@$HOST', #{iterations => 5000}),
            init:stop().
        "

    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
}

case "$MODE" in
    tcp)
        run_tcp_bench
        ;;
    quic)
        run_quic_bench
        ;;
    both)
        run_tcp_bench
        run_quic_bench
        ;;
    *)
        echo "Usage: $0 [tcp|quic|both]"
        exit 1
        ;;
esac

echo ""
echo "Benchmark complete."
