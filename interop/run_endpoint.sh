#!/bin/bash
set -e

# Set up the routes for the simulated network.
source /setup.sh

if [ "$ROLE" == "client" ]; then
    /wait-for-it.sh sim:57832 -s -t 30
    LD_LIBRARY_PATH=/opt/ossl exec /app/quic_interop_client
else
    LD_LIBRARY_PATH=/opt/ossl exec /app/quic_interop_server
fi
