#!/bin/bash
set -e

echo "=== QUIC Distribution Test Node ==="
echo "Node Name: $NODE_NAME"
echo "QUIC Port: $QUIC_DIST_PORT"
echo "Expected Nodes: $EXPECTED_NODES"
echo "Seed Node: $SEED_NODE"
echo "Cluster Nodes: $CLUSTER_NODES"

# Wait for certificates to be available
if [ ! -f "$QUIC_CERT_FILE" ]; then
    echo "Waiting for certificates..."
    for i in $(seq 1 30); do
        if [ -f "$QUIC_CERT_FILE" ]; then
            break
        fi
        sleep 1
    done
fi

if [ ! -f "$QUIC_CERT_FILE" ] || [ ! -f "$QUIC_KEY_FILE" ]; then
    echo "ERROR: Certificates not found!"
    echo "Expected: $QUIC_CERT_FILE and $QUIC_KEY_FILE"
    exit 1
fi

echo "Certificates found."

# Build the cluster nodes config for sys.config
# Format: [{node1@host1, {"host1", 9100}}, ...]
build_cluster_config() {
    local config="["
    local first=true

    # Parse CLUSTER_NODES (comma-separated node names)
    if [ -n "$CLUSTER_NODES" ]; then
        IFS=',' read -ra NODES <<< "$CLUSTER_NODES"
        for node in "${NODES[@]}"; do
            node=$(echo "$node" | tr -d ' ')
            if [ -n "$node" ]; then
                # Extract hostname from node name (node1@host -> host)
                hostname=$(echo "$node" | cut -d'@' -f2)
                if [ "$first" = true ]; then
                    first=false
                else
                    config+=", "
                fi
                config+="{$node, {\"$hostname\", 9100}}"
            fi
        done
    fi

    config+="]"
    echo "$config"
}

export CLUSTER_NODES_CONFIG=$(build_cluster_config)
echo "Cluster Config: $CLUSTER_NODES_CONFIG"

# Start the node in foreground
echo "Starting Erlang node..."
exec /app/bin/quic_dist_test foreground
