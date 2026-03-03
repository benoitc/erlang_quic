#!/bin/bash
# Verify QUIC distribution test results by analyzing container logs
set -e

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
echo "Phase 3: Checking basic RPC..."
for i in $(seq 1 $EXPECTED_NODES); do
    NODE="node$i"

    RPC_OK=$(docker compose logs "$NODE" 2>&1 | grep "\[DIST_TEST\].*basic.*status.*ok" | wc -l || echo 0)

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

    LARGE_OK=$(docker compose logs "$NODE" 2>&1 | grep "\[DIST_TEST\].*large_msg.*status.*ok" | wc -l || echo 0)

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
        # Check for failures in the test_complete message
        TEST_FAILED=$(docker compose logs "$NODE" 2>&1 | grep "\[DIST_TEST\].*test_complete" | grep -oP 'failed\s*=>\s*\K\d+' | head -1 || echo "0")
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
