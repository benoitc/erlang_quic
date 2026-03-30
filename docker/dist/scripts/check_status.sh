#!/bin/bash
# Check status of running QUIC distribution tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DIST_DIR"

# Parse arguments
CLUSTER_SIZE=""
WAIT_MODE=""

for arg in "$@"; do
    case $arg in
        --wait)
            WAIT_MODE="--wait"
            ;;
        --help|-h)
            CLUSTER_SIZE="--help"
            ;;
        [0-9]*)
            CLUSTER_SIZE="$arg"
            ;;
    esac
done

# Try to read cluster size from saved state
if [ -z "$CLUSTER_SIZE" ] && [ -f "$DIST_DIR/.cluster_size" ]; then
    CLUSTER_SIZE=$(cat "$DIST_DIR/.cluster_size")
fi

CLUSTER_SIZE=${CLUSTER_SIZE:-2}

usage() {
    echo "Usage: $0 [2|3|5] [--wait]"
    echo ""
    echo "Check status of running QUIC distribution tests."
    echo ""
    echo "Arguments:"
    echo "  CLUSTER_SIZE  Number of nodes (2, 3, or 5). Default: from .cluster_size or 2"
    echo "  --wait        Block until tests complete (with timeout)"
    echo ""
    echo "Examples:"
    echo "  $0              # Check current status"
    echo "  $0 3            # Check 3-node cluster status"
    echo "  $0 --wait       # Wait for completion"
    echo "  $0 3 --wait     # Wait for 3-node completion"
    exit 1
}

case $CLUSTER_SIZE in
    2) PROFILE="two"; EXPECTED_PEERS=1 ;;
    3) PROFILE="three"; EXPECTED_PEERS=2 ;;
    5) PROFILE="five"; EXPECTED_PEERS=4 ;;
    --help|-h) usage ;;
    *) echo "ERROR: Invalid cluster size: $CLUSTER_SIZE"; usage ;;
esac

# Check if containers are running
check_containers_running() {
    local running=0
    for i in $(seq 1 $CLUSTER_SIZE); do
        if docker compose ps "node$i" 2>/dev/null | grep -q "Up"; then
            running=$((running + 1))
        fi
    done
    echo $running
}

# Count test completions
count_test_complete() {
    local complete=0
    for i in $(seq 1 $CLUSTER_SIZE); do
        local cnt
        cnt=$(docker compose logs "node$i" 2>&1 | grep -c "\[DIST_TEST\].*test_complete" || true)
        cnt=${cnt:-0}
        cnt=$(echo "$cnt" | tr -d '[:space:]')
        if [ "$cnt" -ge 1 ] 2>/dev/null; then
            complete=$((complete + 1))
        fi
    done
    echo $complete
}

# Count mesh completions
count_mesh_complete() {
    local complete=0
    for i in $(seq 1 $CLUSTER_SIZE); do
        local cnt
        cnt=$(docker compose logs "node$i" 2>&1 | grep -c "\[DIST_TEST\].*mesh_complete" || true)
        cnt=${cnt:-0}
        cnt=$(echo "$cnt" | tr -d '[:space:]')
        if [ "$cnt" -ge 1 ] 2>/dev/null; then
            complete=$((complete + 1))
        fi
    done
    echo $complete
}

# Count nodeup events per node
get_connections() {
    local total=0
    for i in $(seq 1 $CLUSTER_SIZE); do
        local conns=$(docker compose logs "node$i" 2>&1 | grep -c "\[DIST_TEST\].*nodeup" || echo 0)
        total=$((total + conns))
    done
    # Total expected connections: each node connects to (n-1) peers
    local expected=$((CLUSTER_SIZE * EXPECTED_PEERS))
    echo "$total/$expected"
}

# Show current status
show_status() {
    local running=$(check_containers_running)
    local mesh=$(count_mesh_complete)
    local tests=$(count_test_complete)
    local conns=$(get_connections)

    echo "=== QUIC Distribution Test Status ==="
    echo "Cluster Size: $CLUSTER_SIZE nodes"
    echo ""
    echo "Containers running: $running/$CLUSTER_SIZE"
    echo "Node connections:   $conns"
    echo "Mesh complete:      $mesh/$CLUSTER_SIZE"
    echo "Tests complete:     $tests/$CLUSTER_SIZE"
    echo ""

    if [ "$running" -lt "$CLUSTER_SIZE" ]; then
        echo "Status: CONTAINERS NOT RUNNING"
        return 2
    elif [ "$tests" -ge "$CLUSTER_SIZE" ]; then
        echo "Status: TESTS COMPLETE"
        return 0
    elif [ "$mesh" -ge "$CLUSTER_SIZE" ]; then
        echo "Status: RUNNING TESTS (mesh formed)"
        return 1
    elif [ "$running" -ge "$CLUSTER_SIZE" ]; then
        echo "Status: FORMING MESH"
        return 1
    else
        echo "Status: STARTING"
        return 1
    fi
}

# Wait for completion
wait_for_completion() {
    local timeout=${1:-300}
    local interval=5
    local elapsed=0

    echo "Waiting for tests to complete (timeout: ${timeout}s)..."
    echo ""

    while [ $elapsed -lt $timeout ]; do
        local tests=$(count_test_complete)
        local mesh=$(count_mesh_complete)
        local running=$(check_containers_running)

        printf "\r[%3ds] Containers: %d/%d | Mesh: %d/%d | Tests: %d/%d" \
            "$elapsed" "$running" "$CLUSTER_SIZE" "$mesh" "$CLUSTER_SIZE" "$tests" "$CLUSTER_SIZE"

        if [ "$running" -lt "$CLUSTER_SIZE" ]; then
            echo ""
            echo ""
            echo "ERROR: Some containers stopped unexpectedly"
            return 2
        fi

        if [ "$tests" -ge "$CLUSTER_SIZE" ]; then
            echo ""
            echo ""
            echo "All tests complete!"
            return 0
        fi

        sleep $interval
        elapsed=$((elapsed + interval))
    done

    echo ""
    echo ""
    echo "ERROR: Timeout waiting for tests to complete"
    return 1
}

# Main
if [ -n "$WAIT_MODE" ]; then
    wait_for_completion 300
    RESULT=$?
    echo ""
    if [ $RESULT -eq 0 ]; then
        echo "Running verification..."
        "$SCRIPT_DIR/verify_distribution.sh" "$CLUSTER_SIZE"
        exit $?
    fi
    exit $RESULT
else
    show_status
    exit $?
fi
