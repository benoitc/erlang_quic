#!/bin/bash
# Wait for all cluster nodes to become healthy
set -e

EXPECTED_NODES=${1:-2}
TIMEOUT=${2:-120}
CHECK_INTERVAL=5

echo "Waiting for $EXPECTED_NODES nodes to become healthy (timeout: ${TIMEOUT}s)..."

start_time=$(date +%s)

while true; do
    current_time=$(date +%s)
    elapsed=$((current_time - start_time))

    if [ $elapsed -ge $TIMEOUT ]; then
        echo "ERROR: Timeout waiting for cluster health after ${TIMEOUT}s"
        docker compose ps
        exit 1
    fi

    # Count healthy nodes
    healthy_count=0

    for i in $(seq 1 $EXPECTED_NODES); do
        node="node$i"
        status=$(docker compose ps --format json "$node" 2>/dev/null | grep -o '"Health":"[^"]*"' | cut -d'"' -f4 || echo "unknown")

        if [ "$status" = "healthy" ]; then
            healthy_count=$((healthy_count + 1))
            echo "  $node: healthy"
        else
            echo "  $node: $status"
        fi
    done

    if [ $healthy_count -ge $EXPECTED_NODES ]; then
        echo "All $EXPECTED_NODES nodes are healthy!"
        return 0
    fi

    echo "Healthy: $healthy_count/$EXPECTED_NODES (elapsed: ${elapsed}s)"
    sleep $CHECK_INTERVAL
done
