#!/bin/bash
#
# Docker Distribution Benchmark: QUIC
#
# Runs the distribution benchmark between two Docker containers.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "=== Docker QUIC Distribution Benchmark ==="
echo ""

# Clean up any existing containers
echo "Cleaning up existing containers..."
docker compose -f docker/dist/docker-compose.yml --profile two down -v 2>/dev/null || true

# Build the Docker image (includes new benchmark code)
echo "Building Docker image..."
docker compose -f docker/dist/docker-compose.yml --profile two build

# Start the two-node cluster
echo ""
echo "Starting QUIC cluster (2 nodes)..."
EXPECTED_NODES=2 docker compose -f docker/dist/docker-compose.yml --profile two up -d

# Wait for throughput tests to complete
echo "Running benchmark (this may take a minute)..."
for i in $(seq 1 120); do
    if docker logs quic_dist_node2 2>&1 | grep -q "throughput_complete"; then
        echo "Benchmark completed."
        break
    fi
    if [ $i -eq 120 ]; then
        echo "Timeout waiting for benchmark."
        docker logs quic_dist_node2 2>&1 | tail -30
        exit 1
    fi
    sleep 1
done

# Extract and display results
echo ""
echo "=== QUIC Distribution Benchmark Results ==="
echo ""
echo "Protocol: QUIC (quic_dist)"
echo "Network: Docker bridge (172.30.1.x)"
echo ""
echo "Size       Throughput    Bandwidth     Latency"
echo "----------------------------------------------------"

docker logs quic_dist_node2 2>&1 | grep "throughput_result" | while read line; do
    # Extract values using sed
    size=$(echo "$line" | sed -n 's/.*size => \([0-9]*\).*/\1/p')
    throughput=$(echo "$line" | sed -n 's/.*throughput => \([0-9]*\).*/\1/p')
    bandwidth=$(echo "$line" | sed -n 's/.*bandwidth_mbps => \([0-9.]*\).*/\1/p')
    latency=$(echo "$line" | sed -n 's/.*latency_us => \([0-9.]*\).*/\1/p')

    # Format size
    if [ "$size" -ge 1048576 ]; then
        size_str="$((size / 1048576))MB"
    elif [ "$size" -ge 1024 ]; then
        size_str="$((size / 1024))KB"
    else
        size_str="${size}B"
    fi

    printf "%-10s %-13s %-13s %s us\n" "$size_str" "${throughput}/s" "${bandwidth} MB/s" "$latency"
done

echo ""
echo "Connection test results:"
docker logs quic_dist_node2 2>&1 | grep -E "(basic|large_msg)" | head -4

echo ""
echo "Cleaning up..."
docker compose -f docker/dist/docker-compose.yml --profile two down -v

echo ""
echo "Done."
