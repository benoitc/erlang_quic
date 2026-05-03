# QUIC Distribution for Erlang

This document describes `quic_dist`, the Erlang distribution protocol implementation over QUIC.

## Overview

`quic_dist` enables Erlang nodes to communicate using QUIC (RFC 9000) as the transport layer instead of TCP. This provides several advantages:

- **TLS 1.3 built-in**: All connections are encrypted by default
- **0-RTT reconnection**: Fast session resumption for previously connected nodes
- **Connection migration**: Seamless handling of IP address changes
- **No head-of-line blocking**: Multiple streams allow parallel message delivery
- **Stream prioritization**: Control messages get higher priority than data
- **QUIC-level liveness**: Transport activity proves peer is alive (no tick blocking)

## Quick Start

### Prerequisites

1. Erlang/OTP 26 or later
2. TLS certificates (self-signed for testing, CA-signed for production)

### Generate Test Certificates

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj '/CN=localhost'
```

### Configuration

Create `sys.config`:

```erlang
[
    {quic, [
        {dist, [
            {cert_file, "/path/to/cert.pem"},
            {key_file, "/path/to/key.pem"},
            {verify, verify_none},  % Use verify_peer in production
            {discovery_module, quic_discovery_static},
            {nodes, [
                {'node1@host1', {"192.168.1.1", 4433}},
                {'node2@host2', {"192.168.1.2", 4433}}
            ]}
        ]},
        {dist_port, 4433}
    ]}
].
```

### Starting a Node

```bash
erl -name node1@host1 \
    -proto_dist quic \
    -epmd_module quic_epmd \
    -start_epmd false \
    -quic_dist_port 4433 \
    -config sys.config \
    -pa _build/default/lib/quic/ebin
```

### Connecting Nodes

From the Erlang shell:

```erlang
%% On node1
net_adm:ping('node2@host2').
%% => pong

%% Check connected nodes
nodes().
%% => ['node2@host2']
```

### Debugging a Running Node

`erl_call` only speaks `inet_tcp_dist`, so it cannot attach to a node
running with `-proto_dist quic`. Two replacements work over QUIC:

**Interactive remote shell** — same as `erl_call -i`:

```bash
erl -name debug@host \
    -proto_dist quic -epmd_module quic_epmd -start_epmd false \
    -quic_dist_cert /path/to/cert.pem \
    -quic_dist_key  /path/to/key.pem \
    -setcookie <cookie> \
    -config sys.config \
    -pa _build/default/lib/quic/ebin \
    -remsh node1@host1
```

**One-shot RPC** — same role as `erl_call -a`. The hex package ships
`priv/bin/quic_call.sh`:

```bash
SCRIPT="$(erl -noshell -eval \
    'io:format("~s",[filename:join([code:priv_dir(quic),"bin","quic_call.sh"])]),halt().')"

"$SCRIPT" -c <cookie> -C sys.config \
    node1@host1 erlang memory '[]'
```

The script auto-parses `cert_file` and `key_file` from the `sys.config`
you pass via `-C`; pass `--cert` / `--key` directly to override. Output
is the Erlang term as printed by `io:format("~p~n", [Result])`. Before
halting, the probe asks the target to disconnect it (an RPC of
`erlang:disconnect_node/1` against the probe's own name) so the target
reaps the hidden-node entry synchronously rather than waiting on the
QUIC idle timeout. See `quic_call.sh -h` for the full flag list.

## Architecture

### Module Overview

| Module | Description |
|--------|-------------|
| `quic_dist` | Distribution protocol callbacks for `net_kernel` |
| `quic_dist_controller` | Per-connection state machine (gen_statem) |
| `quic_dist_sup` | Supervisor for distribution components |
| `quic_dist_tickets` | Session ticket storage for 0-RTT |
| `quic_epmd` | EPMD replacement for node discovery |
| `quic_discovery` | Discovery behaviour definition |
| `quic_discovery_static` | Static node configuration |
| `quic_discovery_dns` | DNS SRV-based discovery |

### Stream Layout

QUIC distribution uses multiple streams for different purposes:

| Stream | Type | Urgency | Purpose |
|--------|------|---------|---------|
| 0 | Bidirectional | 0 (highest) | Control: handshake, tick, link/monitor signals |
| 4, 8, 12... | Bidirectional | 4-6 | Data: distribution messages |

The control stream (stream 0) has the highest priority (urgency 0), ensuring that:
- Handshake messages are delivered promptly
- Tick frames for liveness detection bypass congestion
- Critical signals are not blocked by bulk data transfers

### User Streams API

QUIC distribution supports user-accessible streams, allowing applications to open bidirectional streams over existing distribution connections. This leverages QUIC's multiplexing while keeping distribution traffic separate.

#### Stream ID Allocation

QUIC stream IDs encode the initiator in bit 0:
- Even IDs (0, 4, 8...): Client-initiated bidirectional
- Odd IDs (1, 5, 9...): Server-initiated bidirectional

Distribution reserves low stream IDs:
- Stream 0: Control (handshake, ticks)
- Streams 4, 8, 12, 16: Client data (4 streams)
- Streams 1, 5, 9, 13: Server data (4 streams)

User streams start at:
- Client-initiated: StreamId >= 20 (first available: 20, 24, 28...)
- Server-initiated: StreamId >= 17 (first available: 17, 21, 25...)

#### API Reference

**Opening and Closing Streams**

```erlang
%% Open a bidirectional stream to a connected node
{ok, StreamRef} = quic_dist:open_stream(Node).

%% Open with priority (16-255, lower = higher priority)
{ok, StreamRef} = quic_dist:open_stream(Node, [{priority, 64}]).

%% Close a stream gracefully (sends FIN)
ok = quic_dist:close_stream(StreamRef).

%% Reset a stream immediately (notifies peer)
ok = quic_dist:reset_stream(StreamRef).
ok = quic_dist:reset_stream(StreamRef, ErrorCode).
```

**Sending Data**

```erlang
%% Send data on a user stream
ok = quic_dist:send(StreamRef, <<"Hello">>).

%% Send data with FIN flag (marks end of stream)
ok = quic_dist:send(StreamRef, <<"World">>, true).
```

**Receiving Streams**

Register as an acceptor to receive incoming streams. Incoming streams are assigned to acceptors via round-robin:

```erlang
%% Join acceptor pool for a node
ok = quic_dist:accept_streams(Node).

%% Leave acceptor pool
ok = quic_dist:stop_accepting(Node).

%% Transfer stream ownership to another process
ok = quic_dist:controlling_process(StreamRef, NewOwner).
```

**Listing Streams**

```erlang
%% List all user streams
Streams = quic_dist:list_streams().

%% List user streams for a specific node
Streams = quic_dist:list_streams(Node).
```

Returns a list of maps:
```erlang
#{ref => StreamRef,
  node => 'node@host',
  stream_id => 20,
  owner => <0.123.0>,
  priority => 128,
  recv_fin => false,
  send_fin => false}
```

#### Messages to Owner

Stream owners receive the following messages:

```erlang
%% Data received (Fin=true means end of stream from peer)
{quic_dist_stream, StreamRef, {data, Data :: binary(), Fin :: boolean()}}

%% Stream was reset by peer
{quic_dist_stream, StreamRef, {reset, ErrorCode :: non_neg_integer()}}

%% Stream fully closed (both sides sent FIN)
{quic_dist_stream, StreamRef, closed}
```

#### Priority

User streams have priority range 16-255 (lower = higher priority). Distribution reserves priority 0-15 for internal use:
- Priority 0: Control stream (highest)
- Priority 1-15: Distribution data streams
- Priority 16-255: User streams (default: 128)

#### Example: Request/Response

```erlang
%% Node A: Send request
{ok, Stream} = quic_dist:open_stream('nodeB@host'),
ok = quic_dist:send(Stream, <<"GET /data">>, true),
receive
    {quic_dist_stream, Stream, {data, Response, true}} ->
        io:format("Response: ~p~n", [Response])
end.

%% Node B: Accept and respond
ok = quic_dist:accept_streams('nodeA@host'),
receive
    {quic_dist_stream, Stream, {data, Request, true}} ->
        Response = handle_request(Request),
        quic_dist:send(Stream, Response, true)
end.
```

#### Example: Acceptor Pool

```erlang
%% Start multiple acceptors for load distribution
start_acceptor_pool(Node, N) ->
    [spawn(fun() -> acceptor_loop(Node) end) || _ <- lists:seq(1, N)].

acceptor_loop(Node) ->
    ok = quic_dist:accept_streams(Node),
    receive
        {quic_dist_stream, Stream, {data, Data, Fin}} ->
            handle_request(Stream, Data, Fin),
            acceptor_loop(Node)
    end.
```

#### Error Handling

When no acceptor is available for an incoming stream, the stream is immediately reset with error code `0x100` (`STREAM_REFUSED`). The peer's owner receives:

```erlang
{quic_dist_stream, StreamRef, {reset, 16#100}}
```

### Message Framing

During handshake (stream 0):
```
+--------+--------+------------------+
| Length (16-bit) | Handshake Data   |
+--------+--------+------------------+
```

Post-handshake (data streams):
```
+--------+--------+--------+--------+------------------+
|        Length (32-bit)            | Distribution Msg |
+--------+--------+--------+--------+------------------+
```

## Module Internals

### quic_dist

The main distribution protocol module implementing callbacks required by `net_kernel`:

- `listen/1,2` - Start QUIC listener for incoming connections
- `accept/1` - Accept incoming distribution connections
- `accept_connection/5` - Complete connection acceptance with handshake
- `setup/5` - Initiate outgoing connection to remote node
- `close/1` - Close distribution connection
- `select/1` - Check if module handles given node name
- `address/0` - Return local address information

### quic_dist_controller

A `gen_statem` managing a single distribution connection. States:

1. **init_state** - Initial state, waiting for connection setup
2. **handshaking** - TLS/distribution handshake in progress
3. **connected** - Fully connected, handling distribution traffic

Key responsibilities:
- Stream management (control + data streams)
- Message framing and delivery
- Tick handling for liveness detection
- Backpressure management
- Statistics tracking for `net_kernel`
- Connection migration logging

### Connection Migration Logging

When a QUIC connection migrates to a new network path (e.g., IP address change due to network switch), the controller logs the event:

```
=INFO REPORT====
    what: connection_migrated
    node: 'node@host'
    old_path: {192.168.1.10, 54321}
    new_path: {10.0.0.5, 62000}
```

This helps operators debug connectivity issues. Note that NAT rebinding (same IP, different port) is not logged as it represents minor network changes.

### Liveness Detection

QUIC distribution uses transport-level packet counts for liveness detection instead of relying solely on application-level tick frames:

```
net_kernel                quic_dist_controller              quic_connection
    |                            |                                |
    |------ getstat ------------>|                                |
    |                            |------ get_stats -------------->|
    |                            |<----- {ok, packets_recv/sent} -|
    |<----- {ok, recv, send} ----|                                |
```

**Why this matters:**
- Application tick frames (`<<0:32>>`) are subject to QUIC flow control
- Under heavy load, ticks can be blocked, causing false `net_tick_timeout`
- QUIC packets (ACKs, PINGs, data) always flow at the transport level
- Any received QUIC packet proves the peer is alive

The controller also sends QUIC PING frames on tick, which:
- Bypass congestion control (transport-level frames)
- Elicit ACK responses from the peer
- Ensure transport activity even when streams are blocked

### Backpressure

The controller implements backpressure to prevent overwhelming the QUIC connection:

1. **Send queue monitoring** - Tracks bytes queued for sending
2. **Congestion detection** - Checks if queue exceeds cwnd threshold
3. **Retry mechanism** - Backs off and retries when congested
4. **Tick handling** - Pending ticks retry aggressively (10ms interval)

Configuration options (in `quic_dist.hrl`):
```erlang
-define(DEFAULT_MAX_PULL_PER_NOTIFICATION, 16).
-define(DEFAULT_BACKPRESSURE_RETRY_MS, 50).
```

### Input Handler

A dedicated process handles incoming distribution data:

```erlang
input_handler_loop(DHandle, Controller, ConnRef, ControlStream) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, _Fin}} ->
            %% Batch process messages to prevent blocking
            deliver_to_vm(DHandle, Data),
            input_handler_loop(...)
    end.
```

The input handler:
- Runs in a separate process to avoid blocking the controller
- Batches message delivery (32 messages per batch)
- Filters control stream data (handled by controller)

## Configuration Reference

### TLS Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert_file` | string | - | Path to PEM certificate file |
| `key_file` | string | - | Path to PEM private key file |
| `cacert_file` | string | - | Path to CA certificate (for verify_peer) |
| `cert` | binary | - | DER-encoded certificate (alternative to file) |
| `key` | term | - | Private key term (alternative to file) |
| `verify` | atom | `verify_none` | `verify_none` or `verify_peer` |

### Discovery Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `discovery_module` | atom | `quic_discovery_static` | Discovery backend module |
| `nodes` | list | `[]` | Static node list for `quic_discovery_static` |
| `dns_domain` | string | - | Domain for `quic_discovery_dns` |
| `dns_ttl` | integer | 30 | DNS cache TTL in seconds |

### Performance Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keep_alive_interval` | integer/atom | `disabled` | Keep-alive PING interval (ms), or `auto` for half idle timeout |
| `idle_timeout` | integer | 30000 | Connection idle timeout (ms) |
| `max_data` | integer | 10485760 | Connection flow control limit (bytes) |
| `max_stream_data` | integer | 1048576 | Stream flow control limit (bytes) |

### Extension Hooks

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `auth_callback` | `{Mod,Fun}` \| `fun/3` | `undefined` | Optional auth handshake run after the QUIC handshake but before `dist_util` |
| `auth_handshake_timeout` | integer | 10000 | Deadline (ms) passed to the callback; gatekeeper aborts at expiry |
| `register_with_epmd` | boolean | `false` | When `true`, register the listening port via the configured `epmd_module` so external tooling (e.g. `epmd -names`) can resolve it |

#### `auth_callback`

The callback runs on both sides with the freshly-established QUIC
connection pid:

```erlang
authenticate(Conn, Side :: client | server, Timeout) ->
    {ok, Info :: term()} | {error, Reason :: term()}.
```

`{error, Reason}` closes the QUIC connection without ever starting
the dist controller; the peer's `net_kernel:connect_node/1` returns
`false`. Implementations typically open a user stream
(`quic_dist:open_stream/2`) for a challenge/response. See the
`quic_dist_auth` behaviour module.

On the server, the callback is hosted by a short-lived gatekeeper
process that owns the connection until the callback resolves. Any
QUIC events buffered in its mailbox (e.g. the first stream-data) are
forwarded to the dist controller after a successful handoff.

Boot-arg form: `-quic_dist auth_callback Mod:Fun`.

#### `register_with_epmd`

By default, `quic_dist` skips `epmd` registration entirely and uses
its own discovery. With `register_with_epmd = true`, the listener
calls `EpmdMod:register_node/3` (where `EpmdMod` is whatever
`net_kernel:epmd_module/0` returns) so the node appears in the
configured registry. Useful in mixed-protocol clusters and for
tools that scrape `epmd` directly.

## Discovery Backends

### Static Discovery (`quic_discovery_static`)

Uses a statically configured list of nodes:

```erlang
{discovery_module, quic_discovery_static},
{nodes, [
    {'node1@host1', {"192.168.1.1", 4433}},
    {'node2@host2', {"192.168.1.2", 4433}}
]}
```

### DNS SRV Discovery (`quic_discovery_dns`)

Uses DNS SRV records for node discovery:

```erlang
{discovery_module, quic_discovery_dns},
{dns_domain, "cluster.example.com"}
```

Required DNS records:
```
_erlang-dist._quic.cluster.example.com. SRV 0 0 4433 node1.cluster.example.com.
_erlang-dist._quic.cluster.example.com. SRV 0 0 4433 node2.cluster.example.com.
```

### Custom Discovery

Implement the `quic_discovery` behaviour:

```erlang
-module(my_discovery).
-behaviour(quic_discovery).

-export([init/1, lookup/2, register/3, list_nodes/1]).

init(Opts) ->
    {ok, State}.

lookup(NodeName, Host) ->
    %% Return {ok, {IP, Port}} or {error, not_found}
    {ok, {{192,168,1,1}, 4433}}.

register(NodeName, Port, State) ->
    {ok, State}.

list_nodes(Host) ->
    {ok, [{'node1@host1', 4433}]}.
```

## 0-RTT Session Resumption

QUIC distribution automatically stores session tickets for fast reconnection:

1. After successful connection, the server sends session tickets
2. Tickets are stored in `quic_dist_tickets` ETS table
3. On reconnection, the client uses the ticket for 0-RTT handshake
4. This significantly reduces connection latency

Tickets expire after their lifetime (default 7 days) and are automatically cleaned up.

## Troubleshooting

### Connection Failures

1. **Certificate issues**: Ensure certificates are valid and accessible
2. **Port blocked**: Check firewall allows UDP traffic on the QUIC port
3. **Discovery failure**: Verify node addresses are correct in static config or DNS

### Tick Timeouts

If you see `net_tick_timeout` errors:

1. **Check network**: Ensure UDP packets can flow between nodes
2. **Enable keep-alive**: Set `keep_alive_interval` to `auto` or a specific interval
3. **Check congestion**: Heavy traffic may delay tick responses
4. **Verify liveness**: The fix in 0.11.0 uses QUIC packet counts for liveness

### Debugging

Enable distribution debug logging:

```erlang
logger:set_module_level(quic_dist, debug).
logger:set_module_level(quic_dist_controller, debug).
```

### Common Issues

**"no_credentials" error**:
- Ensure `cert_file` and `key_file` are set and files exist

**"discovery_failed" error**:
- Check `nodes` configuration or DNS records
- Verify network connectivity to target host

**Connection timeout**:
- Check UDP port is open (QUIC uses UDP)
- Verify target node is running and listening

## Security Considerations

1. **Use verify_peer in production**: Always verify peer certificates in production
2. **Certificate management**: Use short-lived certificates with auto-renewal
3. **Distribution cookie**: The Erlang distribution cookie is still used for application-level authentication
4. **ALPN**: Connections use `erlang-dist` ALPN to prevent protocol confusion

## Performance Tuning

### Stream Count

Adjust the number of data streams (default 4):

```erlang
%% In quic_dist.hrl
-define(QUIC_DIST_DATA_STREAMS, 8).  % Increase for high throughput
```

### Flow Control

QUIC's flow control prevents overwhelming receivers. Adjust in `quic.hrl`:

```erlang
-define(DEFAULT_INITIAL_MAX_DATA, 10485760).  % 10MB
-define(DEFAULT_INITIAL_MAX_STREAM_DATA, 1048576).  % 1MB
```

### Keep-Alive

Enable keep-alive for long-lived connections:

```erlang
{quic, [
    {dist, [
        {keep_alive_interval, auto}  % Half of idle_timeout
    ]}
]}
```

## Docker Testing

Run the 2-node cluster test:

```bash
cd docker/dist
EXPECTED_NODES=2 docker compose --profile two build
EXPECTED_NODES=2 docker compose --profile two up
```

Run the 5-node cluster test:

```bash
cd docker/dist
EXPECTED_NODES=5 docker compose --profile five build
EXPECTED_NODES=5 docker compose --profile five up
```

## Comparison with ssl_dist

| Feature | ssl_dist | quic_dist |
|---------|----------|-----------|
| Transport | TCP + TLS | QUIC (UDP + TLS 1.3) |
| Head-of-line blocking | Yes | No (multiplexed streams) |
| 0-RTT | No | Yes |
| Connection migration | No | Yes |
| EPMD dependency | Yes (can replace) | No (built-in discovery) |
| Liveness detection | TCP keepalive + ticks | QUIC packets + PING |

## References

- [RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001 - Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002 - QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)
- [Erlang Distribution Protocol](https://www.erlang.org/doc/apps/erts/erl_dist_protocol.html)
