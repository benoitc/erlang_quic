#!/bin/sh
# Run Common Test suites on Linux from any host, via docker.
#
#   docker/run-ct.sh quic_bulk_run_send_SUITE
#
# Needed for suites that exercise the OTP `socket' backend: it depends
# on GRO and per-message GSO, so those cases cannot run on macOS or
# FreeBSD. On a Linux host `rebar3 ct' runs them directly and this is
# unnecessary.
set -e

if [ "$#" -eq 0 ]; then
    echo "usage: $0 <suite> [suite...]" >&2
    exit 2
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IMAGE=${QUIC_CT_IMAGE:-quic-ct}
OTP=${QUIC_CT_OTP:-28}

docker build -q -f "$ROOT/docker/Dockerfile.ct" \
    --build-arg "OTP_VERSION=$OTP" -t "$IMAGE" "$ROOT" >/dev/null

# --network host so loopback behaves as the suites expect, and the
# sysctl knobs the entrypoint sets need the capability.
#
# The mounted tree carries the host's _build, built for another OS. A
# fresh volume over /app/_build keeps the two apart while leaving _build
# where it always is: suites find certs/ and test/qifs by walking up from
# it, and moving it elsewhere sends them looking in the wrong place.
exec docker run --rm --network host --privileged \
    -v "$ROOT":/app -v /app/_build -w /app "$IMAGE" "$@"
