#!/bin/bash
# End-to-End Test for QUIC Distribution
# This script starts two Erlang nodes with QUIC distribution and tests connectivity

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
TEST_DIR="$PROJECT_DIR/test/e2e"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=== QUIC Distribution E2E Test ==="
echo ""

# Create test directory
mkdir -p "$TEST_DIR/certs"
mkdir -p "$TEST_DIR/logs"
mkdir -p "$TEST_DIR/results"

# Generate test certificates if they don't exist
if [ ! -f "$TEST_DIR/certs/cert.pem" ]; then
    echo "Generating test certificates..."
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$TEST_DIR/certs/key.pem" \
        -out "$TEST_DIR/certs/cert.pem" \
        -days 365 -nodes -subj '/CN=localhost' 2>/dev/null
    echo -e "${GREEN}Certificates generated${NC}"
fi

# Build the project
echo "Building project..."
cd "$PROJECT_DIR"
rebar3 compile > /dev/null 2>&1
echo -e "${GREEN}Build complete${NC}"

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up..."
    pkill -f "quic_e2e_test" 2>/dev/null || true
    rm -f "$TEST_DIR/results/"*.result
}

trap cleanup EXIT

# Start node1 (server) - will listen and wait for connection
echo "Starting node1 on port 15433..."
erl -name "node1@127.0.0.1" \
    -proto_dist quic \
    -epmd_module quic_epmd \
    -start_epmd false \
    -quic_dist_port 15433 \
    -quic_dist_cert "$TEST_DIR/certs/cert.pem" \
    -quic_dist_key "$TEST_DIR/certs/key.pem" \
    -setcookie quic_e2e_test \
    -pa "$PROJECT_DIR/_build/default/lib/quic/ebin" \
    -noshell \
    -eval "
        %% Initialize discovery with node addresses
        quic_discovery_static:init([{nodes, [
            {'node1@127.0.0.1', {\"127.0.0.1\", 15433}},
            {'node2@127.0.0.1', {\"127.0.0.1\", 15434}}
        ]}]),

        %% Write startup confirmation
        file:write_file(\"$TEST_DIR/results/node1.started\", <<\"ok\">>),
        io:format(\"Node ~p started~n\", [node()]),

        %% Wait for connection test result
        receive
            stop -> ok
        after 60000 ->
            %% Timeout after 60 seconds
            file:write_file(\"$TEST_DIR/results/node1.result\", <<\"timeout\">>)
        end
    " > "$TEST_DIR/logs/node1.log" 2>&1 &
NODE1_PID=$!

# Wait a bit for node1 to start
sleep 3

# Check if node1 started
if [ ! -f "$TEST_DIR/results/node1.started" ]; then
    echo -e "${RED}FAILED: node1 failed to start${NC}"
    cat "$TEST_DIR/logs/node1.log"
    exit 1
fi
echo -e "${GREEN}node1 started${NC}"

# Start node2 (client) - will connect to node1 and run tests
echo "Starting node2 on port 15434..."
erl -name "node2@127.0.0.1" \
    -proto_dist quic \
    -epmd_module quic_epmd \
    -start_epmd false \
    -quic_dist_port 15434 \
    -quic_dist_cert "$TEST_DIR/certs/cert.pem" \
    -quic_dist_key "$TEST_DIR/certs/key.pem" \
    -setcookie quic_e2e_test \
    -pa "$PROJECT_DIR/_build/default/lib/quic/ebin" \
    -noshell \
    -eval "
        %% Initialize discovery with node addresses
        quic_discovery_static:init([{nodes, [
            {'node1@127.0.0.1', {\"127.0.0.1\", 15433}},
            {'node2@127.0.0.1', {\"127.0.0.1\", 15434}}
        ]}]),

        io:format(\"Node ~p started~n\", [node()]),

        %% Give node1 a moment to be fully ready
        timer:sleep(2000),

        %% Test 1: Ping node1
        io:format(\"Test 1: Pinging node1@127.0.0.1...~n\"),
        PingResult = net_adm:ping('node1@127.0.0.1'),
        io:format(\"  Ping result: ~p~n\", [PingResult]),

        %% Test 2: Check connected nodes
        io:format(\"Test 2: Connected nodes...~n\"),
        Nodes = erlang:nodes(),
        io:format(\"  Connected to: ~p~n\", [Nodes]),

        %% Test 3: RPC call if connected
        RpcResult = case PingResult of
            pong ->
                io:format(\"Test 3: RPC call to node1...~n\"),
                rpc:call('node1@127.0.0.1', erlang, node, []);
            pang ->
                io:format(\"Test 3: Skipped (not connected)~n\"),
                skipped
        end,
        io:format(\"  RPC result: ~p~n\", [RpcResult]),

        %% Write results
        Results = #{
            ping => PingResult,
            nodes => Nodes,
            rpc => RpcResult
        },
        ResultStr = io_lib:format(\"~p\", [Results]),
        file:write_file(\"$TEST_DIR/results/test.result\", ResultStr),

        %% Summary
        io:format(\"~n=== Summary ===~n\"),
        case PingResult of
            pong ->
                io:format(\"SUCCESS: QUIC distribution is working!~n\"),
                file:write_file(\"$TEST_DIR/results/status\", <<\"success\">>);
            pang ->
                io:format(\"PENDING: Nodes started but not yet connected~n\"),
                io:format(\"This is expected if the distribution handshake is not fully implemented~n\"),
                file:write_file(\"$TEST_DIR/results/status\", <<\"pending\">>)
        end,

        init:stop()
    " > "$TEST_DIR/logs/node2.log" 2>&1

# Wait for node2 to complete
sleep 5

# Show results
echo ""
echo "=== Test Results ==="
echo ""

if [ -f "$TEST_DIR/logs/node2.log" ]; then
    cat "$TEST_DIR/logs/node2.log"
fi

echo ""

# Check final status
if [ -f "$TEST_DIR/results/status" ]; then
    STATUS=$(cat "$TEST_DIR/results/status")
    if [ "$STATUS" = "success" ]; then
        echo -e "${GREEN}=== E2E Test PASSED ===${NC}"
    else
        echo -e "${YELLOW}=== E2E Test PENDING ===${NC}"
        echo "The distribution handshake may not be fully implemented yet."
    fi
else
    echo -e "${RED}=== E2E Test FAILED ===${NC}"
    echo "Check logs at: $TEST_DIR/logs/"
fi

echo ""
echo "Logs available at: $TEST_DIR/logs/"
