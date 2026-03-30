#!/bin/bash
# Main test runner for QUIC distribution tests
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DIST_DIR"

# Parse arguments
CLUSTER_SIZE=""
NO_CLEANUP=""
BACKGROUND=""

for arg in "$@"; do
    case $arg in
        --no-cleanup)
            NO_CLEANUP="--no-cleanup"
            ;;
        --background)
            BACKGROUND="--background"
            ;;
        --help|-h)
            CLUSTER_SIZE="--help"
            ;;
        [0-9]*)
            CLUSTER_SIZE="$arg"
            ;;
    esac
done

CLUSTER_SIZE=${CLUSTER_SIZE:-2}

# OTP version (default: 28, supports 26, 27, 28)
export OTP_VERSION=${OTP_VERSION:-28}

usage() {
    echo "Usage: $0 [2|3|5] [--no-cleanup] [--background]"
    echo ""
    echo "Run QUIC distribution tests with specified cluster size."
    echo ""
    echo "Arguments:"
    echo "  CLUSTER_SIZE  Number of nodes (2, 3, or 5). Default: 2"
    echo "  --no-cleanup  Don't stop containers after test (for debugging)"
    echo "  --background  Start containers and exit immediately (non-blocking)"
    echo ""
    echo "Environment Variables:"
    echo "  OTP_VERSION   Erlang/OTP version (26, 27, or 28). Default: 28"
    echo ""
    echo "Examples:"
    echo "  $0 2                        # Run 2-node test with OTP 28"
    echo "  $0 5                        # Run 5-node test"
    echo "  $0 3 --no-cleanup           # Run 3-node test, keep containers running"
    echo "  $0 2 --background           # Start test in background, exit immediately"
    echo "  OTP_VERSION=27 $0 5         # Run with OTP 27"
    exit 1
}

case $CLUSTER_SIZE in
    2) PROFILE="two" ;;
    3) PROFILE="three" ;;
    5) PROFILE="five" ;;
    --help|-h) usage ;;
    *) echo "ERROR: Invalid cluster size: $CLUSTER_SIZE"; usage ;;
esac

echo "=========================================="
echo "QUIC Distribution Test"
echo "=========================================="
echo "Cluster Size: $CLUSTER_SIZE nodes"
echo "Profile: $PROFILE"
echo "OTP Version: $OTP_VERSION"
echo "Directory: $DIST_DIR"
echo ""

# Step 1: Generate certificates
echo "Step 1: Generating certificates..."
"$SCRIPT_DIR/generate_certs.sh" "$DIST_DIR/certs"
echo ""

# Step 2: Clean up any previous containers
echo "Step 2: Cleaning up previous containers..."
docker compose --profile two --profile three --profile five down -v 2>/dev/null || true
echo ""

# Step 3: Build the images
echo "Step 3: Building Docker images..."
export EXPECTED_NODES=$CLUSTER_SIZE
docker compose --profile "$PROFILE" build
echo ""

# Step 4: Start the cluster
echo "Step 4: Starting $CLUSTER_SIZE-node cluster..."
docker compose --profile "$PROFILE" up -d
echo ""

# Step 5: Wait for cluster health
echo "Step 5: Waiting for cluster to be healthy..."
"$SCRIPT_DIR/wait_for_cluster.sh" "$CLUSTER_SIZE" 180
echo ""

# If background mode, exit now
if [ -n "$BACKGROUND" ]; then
    # Save cluster info for other scripts
    echo "$CLUSTER_SIZE" > "$DIST_DIR/.cluster_size"
    echo "$PROFILE" > "$DIST_DIR/.cluster_profile"

    echo "=========================================="
    echo "Cluster started in background mode"
    echo "=========================================="
    echo ""
    echo "To check test status:"
    echo "  ./scripts/check_status.sh $CLUSTER_SIZE"
    echo ""
    echo "To wait for completion:"
    echo "  ./scripts/check_status.sh $CLUSTER_SIZE --wait"
    echo ""
    echo "To stop and cleanup:"
    echo "  ./scripts/stop_tests.sh"
    echo ""
    exit 0
fi

# Step 6: Wait for tests to complete
echo "Step 6: Waiting for tests to complete..."
# Give extra time for mesh formation and test execution
WAIT_TIME=$((30 + CLUSTER_SIZE * 10))
echo "Waiting ${WAIT_TIME}s for tests to run..."
sleep "$WAIT_TIME"
echo ""

# Step 7: Verify results
echo "Step 7: Verifying test results..."
"$SCRIPT_DIR/verify_distribution.sh" "$CLUSTER_SIZE"
RESULT=$?
echo ""

# Step 8: Collect logs
echo "Step 8: Collecting logs..."
LOG_FILE="$DIST_DIR/cluster_test_${CLUSTER_SIZE}nodes_$(date +%Y%m%d_%H%M%S).log"
docker compose --profile "$PROFILE" logs > "$LOG_FILE" 2>&1
echo "Logs saved to: $LOG_FILE"
echo ""

# Step 9: Cleanup
if [ "$NO_CLEANUP" != "--no-cleanup" ]; then
    echo "Step 9: Cleaning up..."
    docker compose --profile "$PROFILE" down -v
    echo ""
fi

# Final result
echo "=========================================="
if [ $RESULT -eq 0 ]; then
    echo "TEST PASSED: $CLUSTER_SIZE-node QUIC distribution test"
else
    echo "TEST FAILED: $CLUSTER_SIZE-node QUIC distribution test"
    echo "Check logs: $LOG_FILE"
fi
echo "=========================================="

exit $RESULT
