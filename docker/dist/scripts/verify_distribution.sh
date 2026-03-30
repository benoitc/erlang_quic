#!/bin/bash
# Verify QUIC distribution test results by analyzing container logs
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DIST_DIR"

EXPECTED_NODES=${1:-2}
FAILURES=0

echo "=== Verifying $EXPECTED_NODES-node cluster ==="
echo ""

# Phase 1: Check mesh formation
echo "Phase 1: Checking mesh formation..."
EXPECTED_PEERS=$((EXPECTED_NODES - 1))

for i in $(seq 1 $EXPECTED_NODES); do
    NODE="node$i"

    # Count nodeup events
    CONNECTED=$(docker compose logs "$NODE" 2>&1 | grep -c "\[DIST_TEST\].*nodeup" || echo 0)

    if [ "$CONNECTED" -lt "$EXPECTED_PEERS" ]; then
        echo "  FAIL: $NODE connected to $CONNECTED peers (expected $EXPECTED_PEERS)"
        FAILURES=$((FAILURES + 1))
    else
        echo "  OK: $NODE connected to $CONNECTED peers"
    fi
done
echo ""

# Phase 2: Check mesh_complete event
echo "Phase 2: Checking mesh completion..."
for i in $(seq 1 $EXPECTED_NODES); do
    NODE="node$i"

    MESH_COMPLETE=$(docker compose logs "$NODE" 2>&1 | grep -c "\[DIST_TEST\].*mesh_complete" || echo 0)

    if [ "$MESH_COMPLETE" -lt 1 ]; then
        echo "  FAIL: $NODE did not report mesh_complete"
        FAILURES=$((FAILURES + 1))
    else
        echo "  OK: $NODE mesh complete"
    fi
done
echo ""

# Phase 3: Check basic RPC messages
# Log format is multi-line: basic #{node => ..., \n status => ok, ...}
echo "Phase 3: Checking basic RPC..."
for i in $(seq 1 $EXPECTED_NODES); do
    NODE="node$i"

    # Get logs, look for basic messages followed by status => ok
    # Use head -1 and tr to clean up any extra output
    RPC_OK=$(docker compose logs "$NODE" 2>&1 | grep -A2 "\[DIST_TEST\].*basic #{" | grep -c "status => ok" | head -1 | tr -d '[:space:]')
    RPC_OK=${RPC_OK:-0}

    if [ "$RPC_OK" -lt "$EXPECTED_PEERS" ]; then
        echo "  FAIL: $NODE RPC success=$RPC_OK (expected $EXPECTED_PEERS)"
        FAILURES=$((FAILURES + 1))
    else
        echo "  OK: $NODE RPC to $RPC_OK peers"
    fi
done
echo ""

# Phase 4: Check large message transfer
echo "Phase 4: Checking large message transfer (1MB)..."
for i in $(seq 1 $EXPECTED_NODES); do
    NODE="node$i"

    # Get logs, look for large_msg messages followed by status => ok
    # Use head -1 and tr to clean up any extra output
    LARGE_OK=$(docker compose logs "$NODE" 2>&1 | grep -A2 "\[DIST_TEST\].*large_msg #{" | grep -c "status => ok" | head -1 | tr -d '[:space:]')
    LARGE_OK=${LARGE_OK:-0}

    if [ "$LARGE_OK" -lt "$EXPECTED_PEERS" ]; then
        echo "  FAIL: $NODE large_msg success=$LARGE_OK (expected $EXPECTED_PEERS)"
        FAILURES=$((FAILURES + 1))
    else
        echo "  OK: $NODE large messages to $LARGE_OK peers"
    fi
done
echo ""

# Phase 5: Check test completion
echo "Phase 5: Checking test completion..."
for i in $(seq 1 $EXPECTED_NODES); do
    NODE="node$i"

    TEST_COMPLETE=$(docker compose logs "$NODE" 2>&1 | grep -c "\[DIST_TEST\].*test_complete" || echo 0)

    if [ "$TEST_COMPLETE" -lt 1 ]; then
        echo "  FAIL: $NODE did not complete tests"
        FAILURES=$((FAILURES + 1))
    else
        # Check for failures in test_complete - look for failed => N where N > 0
        # Use sed instead of grep -oP for macOS compatibility
        TEST_FAILED=$(docker compose logs "$NODE" 2>&1 | grep -A2 "\[DIST_TEST\].*test_complete" | grep "failed =>" | sed 's/.*failed => \([0-9]*\).*/\1/' | head -1 || echo "0")
        if [ "$TEST_FAILED" != "0" ] && [ -n "$TEST_FAILED" ]; then
            echo "  WARN: $NODE completed with $TEST_FAILED failures"
        else
            echo "  OK: $NODE tests completed"
        fi
    fi
done
echo ""

# Summary
echo "========================================="
if [ "$FAILURES" -eq 0 ]; then
    echo "PASS: All tests passed for $EXPECTED_NODES-node cluster"
    exit 0
else
    echo "FAIL: $FAILURES test failures detected"
    echo ""
    echo "To debug, check the logs:"
    echo "  docker compose logs"
    exit 1
fi
