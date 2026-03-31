#!/bin/bash
# Stop and cleanup QUIC distribution test containers
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST_DIR="$(dirname "$SCRIPT_DIR")"
cd "$DIST_DIR"

# Parse arguments
SAVE_LOGS=""
LOG_DIR=""

for arg in "$@"; do
    case $arg in
        --save-logs)
            SAVE_LOGS="--save-logs"
            ;;
        --log-dir=*)
            LOG_DIR="${arg#*=}"
            ;;
        --help|-h)
            echo "Usage: $0 [--save-logs] [--log-dir=PATH]"
            echo ""
            echo "Stop QUIC distribution test containers and cleanup."
            echo ""
            echo "Options:"
            echo "  --save-logs      Save container logs before stopping"
            echo "  --log-dir=PATH   Directory for logs (default: current dir)"
            echo ""
            echo "Examples:"
            echo "  $0                           # Stop and cleanup"
            echo "  $0 --save-logs               # Save logs then cleanup"
            echo "  $0 --save-logs --log-dir=/tmp  # Save logs to /tmp"
            exit 0
            ;;
    esac
done

# Read cluster info if available
CLUSTER_SIZE=""
PROFILE=""

if [ -f "$DIST_DIR/.cluster_size" ]; then
    CLUSTER_SIZE=$(cat "$DIST_DIR/.cluster_size")
fi
if [ -f "$DIST_DIR/.cluster_profile" ]; then
    PROFILE=$(cat "$DIST_DIR/.cluster_profile")
fi

echo "=== Stopping QUIC Distribution Tests ==="
echo ""

# Save logs if requested
if [ -n "$SAVE_LOGS" ]; then
    LOG_DIR=${LOG_DIR:-$DIST_DIR}
    LOG_FILE="$LOG_DIR/cluster_test_$(date +%Y%m%d_%H%M%S).log"

    echo "Saving logs to: $LOG_FILE"
    docker compose --profile two --profile three --profile five logs > "$LOG_FILE" 2>&1 || true
    echo ""
fi

# Stop all containers
echo "Stopping containers..."
docker compose --profile two --profile three --profile five down -v 2>/dev/null || true
echo ""

# Cleanup state files
if [ -f "$DIST_DIR/.cluster_size" ]; then
    rm -f "$DIST_DIR/.cluster_size"
fi
if [ -f "$DIST_DIR/.cluster_profile" ]; then
    rm -f "$DIST_DIR/.cluster_profile"
fi

echo "Cleanup complete."
if [ -n "$SAVE_LOGS" ]; then
    echo "Logs saved to: $LOG_FILE"
fi
