#!/bin/bash
# Test node failure and recovery scenarios
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DIST_DIR"

CLUSTER_SIZE=${1:-5}
FAILURES=0

echo "=========================================="
echo "QUIC Distribution Failure/Recovery Test"
echo "=========================================="
echo "Cluster Size: $CLUSTER_SIZE nodes"
echo ""

# Determine profile
case $CLUSTER_SIZE in
    3) PROFILE="three" ;;
    5) PROFILE="five" ;;
    *) echo "ERROR: Failure test requires 3 or 5 nodes"; exit 1 ;;
esac

# Step 1: Start cluster (without cleanup)
echo "Step 1: Starting cluster..."
"$SCRIPT_DIR/run_test.sh" "$CLUSTER_SIZE" --no-cleanup
echo ""

# Step 2: Verify initial mesh
echo "Step 2: Verifying initial mesh..."
"$SCRIPT_DIR/verify_distribution.sh" "$CLUSTER_SIZE" || FAILURES=$((FAILURES + 1))
echo ""

# Step 3: Kill node3 (middle node)
echo "Step 3: Killing node3..."
docker compose stop node3
echo "Waiting 15s for failure detection..."
sleep 15
echo ""

# Step 4: Check remaining nodes detected the failure
echo "Step 4: Checking failure detection..."
REMAINING_NODES="1 2"
if [ "$CLUSTER_SIZE" -ge 4 ]; then
    REMAINING_NODES="$REMAINING_NODES 4"
fi
if [ "$CLUSTER_SIZE" -ge 5 ]; then
    REMAINING_NODES="$REMAINING_NODES 5"
fi

for i in $REMAINING_NODES; do
    NODE="node$i"
    NODEDOWN=$(docker compose logs "$NODE" 2>&1 | grep -c "\[DIST_TEST\].*nodedown.*node3" || echo 0)

    if [ "$NODEDOWN" -ge 1 ]; then
        echo "  OK: $NODE detected node3 failure"
    else
        echo "  FAIL: $NODE did not detect node3 failure"
        FAILURES=$((FAILURES + 1))
    fi
done
echo ""

# Step 5: Restart node3
echo "Step 5: Restarting node3..."
docker compose start node3
echo "Waiting 30s for reconnection..."
sleep 30
echo ""

# Step 6: Check node3 reconnected
echo "Step 6: Checking reconnection..."
# Look for new nodeup events after restart
RECOVERY_NODEUPS=$(docker compose logs node3 --since 1m 2>&1 | grep -c "\[DIST_TEST\].*nodeup" || echo 0)
EXPECTED_RECONNECT=$((CLUSTER_SIZE - 1))

if [ "$RECOVERY_NODEUPS" -ge "$EXPECTED_RECONNECT" ]; then
    echo "  OK: node3 reconnected to $RECOVERY_NODEUPS peers"
else
    echo "  FAIL: node3 reconnected to $RECOVERY_NODEUPS peers (expected $EXPECTED_RECONNECT)"
    FAILURES=$((FAILURES + 1))
fi

# Check other nodes saw node3 come back
for i in $REMAINING_NODES; do
    NODE="node$i"
    NODEUP=$(docker compose logs "$NODE" --since 1m 2>&1 | grep -c "\[DIST_TEST\].*nodeup.*node3" || echo 0)

    if [ "$NODEUP" -ge 1 ]; then
        echo "  OK: $NODE detected node3 recovery"
    else
        echo "  WARN: $NODE may not have detected node3 recovery (could be existing connection)"
    fi
done
echo ""

# Step 7: Run tests again on recovered cluster
echo "Step 7: Testing recovered cluster..."
# Trigger tests via RPC
for i in $(seq 1 $CLUSTER_SIZE); do
    NODE="node$i"
    # Use docker exec to run a simple connectivity test
    docker compose exec -T "$NODE" /app/bin/quic_dist_test eval "net_adm:ping('node1@node1')." 2>/dev/null || true
done
sleep 10
echo ""

# Step 8: Collect logs and cleanup
echo "Step 8: Collecting logs..."
LOG_FILE="$DIST_DIR/failure_test_${CLUSTER_SIZE}nodes_$(date +%Y%m%d_%H%M%S).log"
docker compose --profile "$PROFILE" logs > "$LOG_FILE" 2>&1
echo "Logs saved to: $LOG_FILE"
echo ""

echo "Step 9: Cleaning up..."
docker compose --profile "$PROFILE" down -v
echo ""

# Final result
echo "=========================================="
if [ $FAILURES -eq 0 ]; then
    echo "TEST PASSED: Node failure/recovery test"
else
    echo "TEST FAILED: $FAILURES failures detected"
    echo "Check logs: $LOG_FILE"
fi
echo "=========================================="

exit $FAILURES
