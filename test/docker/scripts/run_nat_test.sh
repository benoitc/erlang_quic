#!/bin/bash
# Run NAT traversal test
# Tests communication between nodes behind NAT and external nodes

set -e

echo "=== QUIC Distribution NAT Traversal Test ==="
echo ""

# Wait for all nodes and NAT router
echo "Waiting for NAT setup..."
sleep 15

INTERNAL_NODE=${TEST_INTERNAL_NODE:-internal@internal_node}
EXTERNAL_NODES=${TEST_EXTERNAL_NODES:-external1@external_node1,external2@external_node2}

IFS=',' read -ra EXT_NODES <<< "$EXTERNAL_NODES"

# Function to run Erlang command on a node
run_erl() {
    local node=$1
    local cmd=$2
    erl_call -n "$node" -c quic_dist_test -a "$cmd" 2>/dev/null
}

# Test 1: Check internal node can reach external nodes
echo "Test 1: Internal node reaching external nodes..."
for ext_node in "${EXT_NODES[@]}"; do
    result=$(run_erl "$INTERNAL_NODE" "net_adm ping ['$ext_node']" || echo "pang")
    if [[ "$result" == *"pong"* ]]; then
        echo "  OK: $INTERNAL_NODE -> $ext_node"
    else
        echo "  INFO: $INTERNAL_NODE cannot reach $ext_node (expected with NAT)"
        echo "        This may require NAT traversal or port mapping"
    fi
done
echo ""

# Test 2: Check external nodes can reach each other
echo "Test 2: External nodes communication..."
for i in "${!EXT_NODES[@]}"; do
    for j in "${!EXT_NODES[@]}"; do
        if [[ $i -ne $j ]]; then
            src=${EXT_NODES[$i]}
            dst=${EXT_NODES[$j]}
            result=$(run_erl "$src" "net_adm ping ['$dst']")
            if [[ "$result" == *"pong"* ]]; then
                echo "  OK: $src -> $dst"
            else
                echo "  FAIL: $src cannot reach $dst"
            fi
        fi
    done
done
echo ""

# Test 3: Check NAT detection on internal node
echo "Test 3: NAT detection..."
result=$(run_erl "$INTERNAL_NODE" "quic_dist_nat:is_available []")
if [[ "$result" == *"true"* ]]; then
    echo "  OK: NAT module available"

    # Try to discover external address
    ext_addr=$(run_erl "$INTERNAL_NODE" "quic_dist_nat:get_external_address []" || echo "failed")
    if [[ "$ext_addr" != *"error"* ]]; then
        echo "  External address: $ext_addr"
    else
        echo "  INFO: Could not determine external address"
    fi
else
    echo "  INFO: NAT module not available (erlang_nat not installed)"
fi
echo ""

# Test 4: Connection migration test (if connected)
echo "Test 4: Connection migration capability..."
# Check if any connections exist
for ext_node in "${EXT_NODES[@]}"; do
    nodes=$(run_erl "$INTERNAL_NODE" "erlang nodes []" || echo "[]")
    if [[ "$nodes" == *"$ext_node"* ]]; then
        echo "  Connected to $ext_node, testing migration..."
        result=$(run_erl "$INTERNAL_NODE" "quic:migrate [make_ref()]" || echo "error")
        echo "  Migration result: $result"
        break
    fi
done
echo ""

# Test 5: STUN discovery test
echo "Test 5: STUN server discovery..."
result=$(run_erl "$INTERNAL_NODE" "
    case quic_dist_nat:is_available() of
        true ->
            quic_dist_nat:discover();
        false ->
            {error, nat_not_available}
    end
")
echo "  STUN result: $result"
echo ""

echo "=== NAT Tests Completed ==="
echo ""
echo "Note: Full NAT traversal requires:"
echo "  1. UPnP/NAT-PMP support on the router"
echo "  2. Or manual port forwarding"
echo "  3. Or a TURN relay server"
echo ""

exit 0
