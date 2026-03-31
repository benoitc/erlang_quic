#!/bin/bash
# Start the QUIC distribution release

set -e

# Set up default gateway if specified (for NAT testing)
if [ -n "$DEFAULT_GATEWAY" ]; then
    echo "Setting up default route through $DEFAULT_GATEWAY"
    # Delete existing default route first (Docker may have added one)
    ip route del default 2>/dev/null || true
    ip route add default via "$DEFAULT_GATEWAY"
    echo "Current routing table:"
    ip route
fi

echo "Starting node ${NODE_NAME} on port ${QUIC_DIST_PORT}"
echo "NAT enabled: ${NAT_ENABLED}"
echo "Cert file: ${QUIC_CERT_FILE}"

# If NAT is enabled, try to verify gateway is reachable
if [ "${NAT_ENABLED}" = "true" ] && [ -n "$DEFAULT_GATEWAY" ]; then
    echo "Testing gateway connectivity..."
    ping -c 1 -W 2 "$DEFAULT_GATEWAY" || echo "Warning: gateway not responding to ping"
fi

# Export all required environment variables for the release
export NODE_NAME="${NODE_NAME:-node}"
export ERLANG_COOKIE="${ERLANG_COOKIE:-quic_dist_test}"
export QUIC_CERT_FILE="${QUIC_CERT_FILE:-/certs/cert.pem}"
export QUIC_KEY_FILE="${QUIC_KEY_FILE:-/certs/key.pem}"
export QUIC_DIST_PORT="${QUIC_DIST_PORT:-4433}"
export NAT_ENABLED="${NAT_ENABLED:-false}"

# Start the release in foreground mode
exec /opt/quic_node/bin/quic_node foreground
