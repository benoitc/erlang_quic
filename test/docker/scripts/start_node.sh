#!/bin/bash
# Start an Erlang node with QUIC distribution

set -e

NODE_NAME=${NODE_NAME:-node@localhost}
QUIC_DIST_PORT=${QUIC_DIST_PORT:-4433}
CLUSTER_NODES=${CLUSTER_NODES:-}

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

# Create sys.config
cat > /app/sys.config << EOF
[
    {quic, [
        {dist, [
            {cert_file, "${QUIC_CERT_FILE:-/certs/cert.pem}"},
            {key_file, "${QUIC_KEY_FILE:-/certs/key.pem}"},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, ${NODES_CONFIG:-[]}}
        ]},
        {dist_port, ${QUIC_DIST_PORT}}
    ]}
].
EOF

# Create vm.args
cat > /app/vm.args << EOF
-name ${NODE_NAME}
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

# Start the node
exec erl \
    -name "$NODE_NAME" \
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
        io:format(\"Node ~p started~n\", [node()]),
        receive stop -> ok end
    "
