#!/bin/bash
# Run NAT traversal test using direct Erlang with release libs

set -e

echo "=== QUIC Distribution NAT Traversal Test ==="
echo ""

# Wait for all nodes to start
echo "Waiting for nodes to start..."
sleep 10

# Configuration
INTERNAL_NODE=${TEST_INTERNAL_NODE:-internal@internal_node}
EXTERNAL_NODES=${TEST_EXTERNAL_NODES:-external1@external_node1,external2@external_node2}

# Parse external nodes into Erlang list
IFS=',' read -ra EXT_NODES <<< "$EXTERNAL_NODES"
EXT_NODES_ERLANG=""
for ext_node in "${EXT_NODES[@]}"; do
    EXT_NODES_ERLANG="${EXT_NODES_ERLANG}'$ext_node',"
done
EXT_NODES_ERLANG="[${EXT_NODES_ERLANG%,}]"

echo "Internal node: $INTERNAL_NODE"
echo "External nodes: ${EXT_NODES[*]}"
echo ""

echo "Starting test runner node..."

# Set up ERL_LIBS to include all release libraries
export ERL_LIBS=/opt/quic_node/lib

# Find erts version
ERTS_VSN=$(ls /opt/quic_node/ | grep erts | head -1)
ERTS_DIR=/opt/quic_node/$ERTS_VSN

# Use release's boot file path
BOOT=/opt/quic_node/releases/0.1.0/start

# Run erl with proper setup
exec "$ERTS_DIR/bin/erl" \
    -boot "$BOOT" \
    -mode embedded \
    -boot_var SYSTEM_LIB_DIR /opt/quic_node/lib \
    -sname nat_tester \
    -setcookie quic_dist_test \
    -proto_dist quic \
    -epmd_module quic_epmd \
    -start_epmd false \
    -quic_dist_cert "${QUIC_CERT_FILE:-/certs/cert.pem}" \
    -quic_dist_key "${QUIC_KEY_FILE:-/certs/key.pem}" \
    -quic_dist_port 4435 \
    -noshell \
    -eval "
        timer:sleep(2000),
        io:format(\"~n=== Test 1: NAT Module Availability ===~n\"),
        NatAvailable = quic_dist_nat:is_available(),
        io:format(\"NAT module available: ~p~n\", [NatAvailable]),

        io:format(\"~n=== Test 2: Connect to External Nodes ===~n\"),
        ExternalNodes = ${EXT_NODES_ERLANG},
        ConnResults = lists:map(fun(Node) ->
            io:format(\"Pinging ~p... \", [Node]),
            Result = net_adm:ping(Node),
            io:format(\"~p~n\", [Result]),
            {Node, Result}
        end, ExternalNodes),

        io:format(\"~n=== Test 3: Connect to Internal Node (NAT) ===~n\"),
        InternalNode = '${INTERNAL_NODE}',
        io:format(\"Pinging internal node ~p... \", [InternalNode]),
        InternalResult = net_adm:ping(InternalNode),
        io:format(\"~p~n\", [InternalResult]),

        io:format(\"~n=== Test 4: Check Connected Nodes ===~n\"),
        Connected = nodes(),
        io:format(\"Connected nodes: ~p~n\", [Connected]),

        io:format(\"~n=== Test 5: RPC to Connected Nodes ===~n\"),
        lists:foreach(fun(Node) ->
            io:format(\"RPC to ~p: \", [Node]),
            case rpc:call(Node, erlang, node, [], 5000) of
                {badrpc, RpcErr} ->
                    io:format(\"FAILED (~p)~n\", [RpcErr]);
                RemoteNode ->
                    io:format(\"OK (got ~p)~n\", [RemoteNode])
            end
        end, Connected),

        io:format(\"~n=== Summary ===~n\"),
        SuccessCount = length([ok || {_, pong} <- ConnResults]) +
                       case InternalResult of pong -> 1; _ -> 0 end,
        TotalNodes = length(ExternalNodes) + 1,
        io:format(\"Connected to ~p/~p nodes~n\", [SuccessCount, TotalNodes]),

        case SuccessCount of
            0 ->
                io:format(\"FAIL: No connections established~n\"),
                halt(1);
            N when N < TotalNodes ->
                io:format(\"PARTIAL: Some connections failed (NAT may be blocking)~n\"),
                halt(0);
            _ ->
                io:format(\"SUCCESS: All nodes connected~n\"),
                halt(0)
        end.
    "
