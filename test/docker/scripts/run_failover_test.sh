#!/bin/bash
# Run failover test
# Tests node failure detection and mesh recovery

set -e

echo "=== QUIC Distribution Failover Test ==="
echo ""

# Wait for cluster to be ready
echo "Waiting for cluster..."
sleep 10

NODES=(
    "node1@node1"
    "node2@node2"
    "node3@node3"
    "node4@node4"
    "node5@node5"
)

# Function to run Erlang command on a node
run_erl() {
    local node=$1
    local cmd=$2
    erl_call -n "$node" -c quic_dist_test -a "$cmd" 2>/dev/null
}

# Function to count peers
count_peers() {
    local node=$1
    local peers=$(run_erl "$node" "erlang nodes []" 2>/dev/null || echo "[]")
    echo "$peers" | tr ',' '\n' | grep -c "@" || echo 0
}

# Form initial mesh
echo "Step 1: Forming initial mesh..."
for target in "${NODES[@]:1}"; do
    run_erl "node1@node1" "net_adm ping ['$target']"
done
sleep 3

# Verify initial state
echo "Step 2: Verifying initial state..."
for node in "${NODES[@]}"; do
    peers=$(count_peers "$node")
    echo "  $node: $peers peers"
done
echo ""

# Test failover scenarios
echo "Step 3: Testing failover scenarios..."
echo ""

# Scenario A: Kill one node
echo "Scenario A: Single node failure"
echo "  Killing node3..."
docker-compose kill node3 2>/dev/null || true
sleep 5

echo "  Checking remaining nodes..."
for node in "node1@node1" "node2@node2" "node4@node4" "node5@node5"; do
    peers=$(count_peers "$node")
    echo "    $node: $peers peers"
    if [[ "$peers" -ne 3 ]]; then
        echo "    WARNING: Expected 3 peers"
    fi
done

# Restart node3
echo "  Restarting node3..."
docker-compose start node3 2>/dev/null || true
sleep 10

# Reconnect
run_erl "node1@node1" "net_adm ping ['node3@node3']"
sleep 3

peers=$(count_peers "node3@node3")
echo "  node3 reconnected with $peers peers"
echo ""

# Scenario B: Network partition
echo "Scenario B: Network partition simulation"
echo "  Creating partition: {node1,node2} | {node4,node5}"
echo "  (node3 bridges both partitions)"

# Disconnect node1,node2 from node4,node5
run_erl "node1@node1" "erlang disconnect_node ['node4@node4']"
run_erl "node1@node1" "erlang disconnect_node ['node5@node5']"
run_erl "node2@node2" "erlang disconnect_node ['node4@node4']"
run_erl "node2@node2" "erlang disconnect_node ['node5@node5']"
sleep 3

echo "  Partition state:"
for node in "${NODES[@]}"; do
    peers=$(run_erl "$node" "erlang nodes []" 2>/dev/null || echo "[]")
    echo "    $node: $peers"
done

# Heal partition
echo "  Healing partition..."
run_erl "node1@node1" "net_adm ping ['node4@node4']"
run_erl "node1@node1" "net_adm ping ['node5@node5']"
sleep 3

echo "  After healing:"
for node in "${NODES[@]}"; do
    peers=$(count_peers "$node")
    echo "    $node: $peers peers"
done
echo ""

# Scenario C: Rapid reconnection (0-RTT test)
echo "Scenario C: Rapid reconnection test"
echo "  Disconnecting and reconnecting node5 multiple times..."

for i in {1..3}; do
    echo "  Round $i:"
    run_erl "node1@node1" "erlang disconnect_node ['node5@node5']"
    sleep 1

    start_time=$(date +%s%N)
    run_erl "node1@node1" "net_adm ping ['node5@node5']"
    end_time=$(date +%s%N)

    elapsed=$(( (end_time - start_time) / 1000000 ))
    echo "    Reconnection time: ${elapsed}ms"
done
echo ""

# Final verification
echo "Step 4: Final mesh verification..."
for node in "${NODES[@]}"; do
    peers=$(count_peers "$node")
    if [[ "$peers" -eq 4 ]]; then
        echo "  OK: $node has full mesh ($peers peers)"
    else
        echo "  WARN: $node has $peers peers (expected 4)"
    fi
done
echo ""

echo "=== Failover Tests Completed ==="
exit 0
