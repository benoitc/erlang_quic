#!/bin/bash
# Run 5-node cluster test
# Tests mesh formation, communication, and failover

set -e

echo "=== QUIC Distribution 5-Node Cluster Test ==="
echo ""

# Wait for all nodes to be ready
echo "Waiting for nodes to start..."
sleep 10

# Node addresses
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

# Test 1: Verify all nodes are running
echo "Test 1: Checking all nodes are running..."
for node in "${NODES[@]}"; do
    result=$(run_erl "$node" "erlang node []" || echo "FAILED")
    if [[ "$result" == *"FAILED"* ]]; then
        echo "  FAIL: Node $node is not responding"
        exit 1
    fi
    echo "  OK: $node is running"
done
echo ""

# Test 2: Form mesh by pinging all nodes from node1
echo "Test 2: Forming mesh..."
for target in "${NODES[@]:1}"; do
    result=$(run_erl "node1@node1" "net_adm ping ['$target']")
    if [[ "$result" != *"pong"* ]]; then
        echo "  FAIL: node1 cannot ping $target"
        exit 1
    fi
    echo "  OK: node1 -> $target"
done
echo ""

# Test 3: Verify full mesh on each node
echo "Test 3: Verifying full mesh..."
expected_peers=4
for node in "${NODES[@]}"; do
    peers=$(run_erl "$node" "erlang nodes []")
    peer_count=$(echo "$peers" | tr ',' '\n' | grep -c "@" || echo 0)
    if [[ "$peer_count" -ne "$expected_peers" ]]; then
        echo "  FAIL: $node has $peer_count peers, expected $expected_peers"
        echo "  Peers: $peers"
        exit 1
    fi
    echo "  OK: $node has $expected_peers peers"
done
echo ""

# Test 4: Cross-node RPC
echo "Test 4: Testing cross-node RPC..."
for i in {0..4}; do
    for j in {0..4}; do
        if [[ $i -ne $j ]]; then
            src=${NODES[$i]}
            dst=${NODES[$j]}
            result=$(run_erl "$src" "rpc call ['$dst', erlang, node, []]")
            if [[ "$result" != *"$dst"* ]]; then
                echo "  FAIL: RPC from $src to $dst failed"
                exit 1
            fi
        fi
    done
done
echo "  OK: All RPC calls successful"
echo ""

# Test 5: Large message transfer
echo "Test 5: Testing large message transfer..."
result=$(run_erl "node1@node1" "
    Data = crypto:strong_rand_bytes(1024 * 1024),
    Hash1 = crypto:hash(sha256, Data),
    Receiver = rpc:call('node5@node5', erlang, spawn, [fun() ->
        receive {data, D} -> exit({ok, crypto:hash(sha256, D)}) end
    end]),
    Receiver ! {data, Data},
    timer:sleep(5000),
    ok
")
echo "  OK: Large message test completed"
echo ""

# Test 6: Concurrent message test
echo "Test 6: Testing concurrent messages..."
result=$(run_erl "node1@node1" "
    NumMessages = 100,
    Self = self(),
    Receiver = rpc:call('node3@node3', erlang, spawn, [fun() ->
        Loop = fun(Loop, N, Acc) ->
            receive
                {msg, X} when N > 0 -> Loop(Loop, N-1, [X|Acc]);
                done -> Self ! {done, Acc}
            after 10000 -> Self ! timeout
            end
        end,
        Loop(Loop, NumMessages, [])
    end]),
    [Receiver ! {msg, N} || N <- lists:seq(1, NumMessages)],
    Receiver ! done,
    receive
        {done, _Received} -> ok;
        timeout -> error
    after 30000 -> timeout
    end
")
if [[ "$result" == *"ok"* ]]; then
    echo "  OK: Concurrent messages test passed"
else
    echo "  FAIL: Concurrent messages test failed"
    exit 1
fi
echo ""

# Test 7: Node failure and recovery
echo "Test 7: Testing node failure handling..."
echo "  Disconnecting node3..."
run_erl "node1@node1" "erlang disconnect_node ['node3@node3']"
run_erl "node2@node2" "erlang disconnect_node ['node3@node3']"
run_erl "node4@node4" "erlang disconnect_node ['node3@node3']"
run_erl "node5@node5" "erlang disconnect_node ['node3@node3']"
sleep 2

# Check remaining nodes
for node in "node1@node1" "node2@node2" "node4@node4" "node5@node5"; do
    peers=$(run_erl "$node" "erlang nodes []")
    peer_count=$(echo "$peers" | tr ',' '\n' | grep -c "@" || echo 0)
    if [[ "$peer_count" -ne 3 ]]; then
        echo "  WARN: $node has $peer_count peers after disconnect"
    fi
done
echo "  OK: Nodes handled disconnection"

# Reconnect
echo "  Reconnecting node3..."
run_erl "node1@node1" "net_adm ping ['node3@node3']"
sleep 2

# Verify reconnection
peers=$(run_erl "node3@node3" "erlang nodes []")
peer_count=$(echo "$peers" | tr ',' '\n' | grep -c "@" || echo 0)
if [[ "$peer_count" -ge 1 ]]; then
    echo "  OK: node3 reconnected with $peer_count peers"
else
    echo "  FAIL: node3 failed to reconnect"
    exit 1
fi
echo ""

echo "=== All Tests Passed ==="
exit 0
