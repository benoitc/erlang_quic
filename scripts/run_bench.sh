#!/bin/bash
# QUIC Benchmark Comparison Runner
#
# Usage:
#   ./scripts/run_bench.sh          # Run full benchmark
#   ./scripts/run_bench.sh quick    # Quick test with small sizes
#   ./scripts/run_bench.sh stop     # Stop benchmark servers

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_DIR/docker/docker-compose.bench.yml"

cd "$PROJECT_DIR"

case "${1:-run}" in
    stop)
        echo "Stopping benchmark servers..."
        docker compose -f "$COMPOSE_FILE" down
        ;;
    quick)
        echo "Starting benchmark servers..."
        docker compose -f "$COMPOSE_FILE" up -d --build

        echo "Waiting for servers to be ready..."
        sleep 5

        echo "Running quick benchmark..."
        rebar3 compile
        erl -pa _build/default/lib/*/ebin -noshell \
            -eval "quic_comparison_bench:run(#{sizes => [1024, 10240], iterations => 3}), halt()."
        ;;
    run|*)
        echo "Starting benchmark servers..."
        docker compose -f "$COMPOSE_FILE" up -d --build

        echo "Waiting for servers to be ready..."
        sleep 10

        echo "Running full benchmark..."
        rebar3 compile
        erl -pa _build/default/lib/*/ebin -noshell \
            -eval "quic_comparison_bench:run(), halt()."
        ;;
esac
