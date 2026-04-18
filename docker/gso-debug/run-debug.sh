#!/usr/bin/env bash
# Run the failing GSO CT case inside the container with packet capture.
# Outputs are written to /logs (bind-mounted to docker/gso-debug/out/).
set -euo pipefail

mkdir -p /logs

echo "==> starting tcpdump (/logs/gso.pcap)"
tcpdump -i any -U -n -w /logs/gso.pcap 'udp' &
TCPDUMP_PID=$!

# Give tcpdump a moment to start capturing before the test opens sockets.
sleep 0.3

echo "==> running quic_server_batching_SUITE:server_download_uses_gso_on_linux"
# Pass CT regardless of result so we always tear down tcpdump + copy logs.
set +e
QUIC_ENABLE_GSO_TEST=1 rebar3 ct \
    --suite=quic_server_batching_SUITE \
    --case=server_download_uses_gso_on_linux
CT_RC=$?
set -e

echo "==> stopping tcpdump"
kill -INT "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "==> copying CT logs to /logs/ct-logs"
rm -rf /logs/ct-logs
mkdir -p /logs/ct-logs
cp -r _build/test/logs/. /logs/ct-logs/ 2>/dev/null || true

echo "==> done (ct exit $CT_RC); artifacts in host docker/gso-debug/out/"
exit "$CT_RC"
