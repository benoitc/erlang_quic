#!/bin/bash
# Start an Erlang node with QUIC distribution

set -e

# Set up default gateway if specified (for NAT testing)
if [ -n "$DEFAULT_GATEWAY" ]; then
    echo "Setting up default route through $DEFAULT_GATEWAY"
    ip route add default via "$DEFAULT_GATEWAY" 2>/dev/null || true
fi

NODE_NAME=${NODE_NAME:-node@localhost}
QUIC_DIST_PORT=${QUIC_DIST_PORT:-4433}
CLUSTER_NODES=${CLUSTER_NODES:-}
NAT_ENABLED=${NAT_ENABLED:-false}
STUN_SERVERS=${STUN_SERVERS:-"stun.l.google.com:19302"}

# Build the nodes configuration
NODES_CONFIG=""
if [ -n "$CLUSTER_NODES" ]; then
    IFS=',' read -ra NODES <<< "$CLUSTER_NODES"
    NODES_CONFIG="["
    for node in "${NODES[@]}"; do
        # Extract host from node name (format: name@host)
        host=$(echo "$node" | cut -d'@' -f2)
        NODES_CONFIG="${NODES_CONFIG}{'$node', {\"$host\", $QUIC_DIST_PORT}},"
    done
    NODES_CONFIG="${NODES_CONFIG%,}]"
fi

# Build STUN servers list
STUN_CONFIG="[]"
if [ "$NAT_ENABLED" = "true" ] && [ -n "$STUN_SERVERS" ]; then
    IFS=',' read -ra SERVERS <<< "$STUN_SERVERS"
    STUN_CONFIG="["
    for server in "${SERVERS[@]}"; do
        STUN_CONFIG="${STUN_CONFIG}\"$server\","
    done
    STUN_CONFIG="${STUN_CONFIG%,}]"
fi

# Create sys.config
cat > /app/sys.config << EOF
[
    {quic, [
        {dist, [
            {cert_file, "${QUIC_CERT_FILE:-/certs/cert.pem}"},
            {key_file, "${QUIC_KEY_FILE:-/certs/key.pem}"},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, ${NODES_CONFIG:-[]}},
            {nat_enabled, ${NAT_ENABLED}},
            {stun_servers, ${STUN_CONFIG}}
        ]},
        {dist_port, ${QUIC_DIST_PORT}}
    ]}
].
EOF

# Create vm.args
cat > /app/vm.args << EOF
-sname ${NODE_NAME}
-proto_dist quic
-epmd_module quic_epmd
-start_epmd false
-quic_dist_port ${QUIC_DIST_PORT}
-setcookie quic_dist_test
-config /app/sys.config
-pa /app/_build/default/lib/quic/ebin
EOF

echo "Starting node ${NODE_NAME} on port ${QUIC_DIST_PORT}"
echo "Cluster nodes: ${CLUSTER_NODES}"
echo "NAT enabled: ${NAT_ENABLED}"

# Build NAT start code
NAT_START=""
if [ "$NAT_ENABLED" = "true" ]; then
    NAT_START="quic_dist_nat:start_link([{stun_servers, ${STUN_CONFIG}}]),"
fi

# Start the node
exec erl \
    -sname "$NODE_NAME" \
    -proto_dist quic \
    -epmd_module quic_epmd \
    -start_epmd false \
    -quic_dist_port "$QUIC_DIST_PORT" \
    -setcookie quic_dist_test \
    -config /app/sys.config \
    -pa /app/_build/default/lib/quic/ebin \
    -noshell \
    -eval "
        application:ensure_all_started(quic),
        ${NAT_START}
        register(test_node, self()),
        io:format(\"Node ~p started~n\", [node()]),
        receive stop -> ok end
    "
