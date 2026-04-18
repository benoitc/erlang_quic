# QUIC Server Guide

This guide covers setting up and configuring QUIC servers in Erlang applications.

## Quick Start

```erlang
%% Start the QUIC application
application:ensure_all_started(quic).

%% Start a server with TLS certificates
{ok, _Pid} = quic:start_server(my_server, 4433, #{
    cert => CertDer,
    key => PrivateKey,
    alpn => [<<"h3">>, <<"myproto">>]
}).

%% Get the listening port (useful when using port 0)
{ok, Port} = quic:get_server_port(my_server).
```

## Server Configuration Options

### Required Options

| Option | Type | Description |
|--------|------|-------------|
| `cert` | binary | DER-encoded certificate |
| `key` | term | Private key (RSA or EC) |

### TLS Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `alpn` | [binary()] | `[<<"h3">>]` | ALPN protocols to advertise |
| `cert_chain` | [binary()] | `[]` | Additional certificate chain |

### Connection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `idle_timeout` | integer | 30000 | Idle timeout in ms (0 = disabled) |
| `max_data` | integer | 10485760 | Connection-level flow control limit |
| `max_stream_data` | integer | 1048576 | Per-stream flow control limit |
| `max_streams_bidi` | integer | 100 | Max bidirectional streams |
| `max_streams_uni` | integer | 100 | Max unidirectional streams |
| `max_datagram_frame_size` | integer | 0 | Datagram support (0 = disabled, RFC 9221) |

### Server Pool Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `pool_size` | integer | 1 | Number of listener processes |
| `connection_handler` | function | - | Callback for new connections |

### Advanced Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keep_alive_interval` | integer/atom | `auto` | PING interval (`disabled`, `auto`, or ms) |
| `pmtu_enabled` | boolean | true | Enable Path MTU Discovery |
| `pmtu_max_mtu` | integer | 1500 | Maximum MTU to probe |
| `preferred_ipv4` | tuple | - | Preferred IPv4 address for migration |
| `preferred_ipv6` | tuple | - | Preferred IPv6 address for migration |
| `lb_config` | map | - | QUIC-LB configuration (RFC 9312) |
| `server_send_batching` | boolean | true | Per-connection send batching over the shared listener socket. On Linux + `socket_backend => socket` with UDP_SEGMENT, coalesces outgoing packets into GSO super-datagrams; no-op on macOS / gen_udp. Set to `false` to fall back to direct `gen_udp:send/4`. |

## Observability

Server connections expose batching counters via `quic_connection:get_stats/1`:

- `batch_flushes` — number of times the per-connection batch was flushed
- `packets_coalesced` — packets that left the socket in a multi-packet flush

On `socket_backend => socket` + Linux with UDP_SEGMENT support,
`packets_coalesced / batch_flushes` is the effective coalesce ratio
(GSO super-datagrams). `quic_socket:info/1` exposes the same counters
plus `backend`, `gso_supported`, `gso_size`, `gro_enabled`, and
`max_batch_packets`.

## Loading Certificates

### From PEM Files

```erlang
load_cert_and_key(CertFile, KeyFile) ->
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem} = file:read_file(KeyFile),

    %% Decode certificate
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),

    %% Decode private key
    KeyDer = case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] ->
            public_key:der_decode('PrivateKeyInfo', Der)
    end,

    {CertDer, KeyDer}.
```

### Generating Test Certificates

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj '/CN=localhost'
```

## Connection Handling

### Using connection_handler Callback

```erlang
%% Define a connection handler
handle_connection(ConnPid, Info) ->
    %% Info contains: peer_address, alpn_protocol, etc.
    io:format("New connection from ~p~n", [maps:get(peer_address, Info)]),

    %% Spawn a process to handle this connection
    spawn(fun() -> connection_loop(ConnPid) end).

%% Start server with handler
quic:start_server(my_server, 4433, #{
    cert => Cert,
    key => Key,
    connection_handler => fun handle_connection/2
}).
```

### Manual Connection Handling

```erlang
%% Get all active connections
{ok, Connections} = quic:get_server_connections(my_server).

%% Each connection is a pid that can be used with quic API
[ConnPid | _] = Connections,
{ok, StreamId} = quic:open_stream(ConnPid),
ok = quic:send_data(ConnPid, StreamId, <<"Hello">>, true).
```

## Message Handling

The connection owner process receives these messages:

```erlang
receive
    %% Connection established
    {quic, ConnRef, {connected, Info}} ->
        handle_connected(ConnRef, Info);

    %% New stream opened by peer
    {quic, ConnRef, {stream_opened, StreamId}} ->
        handle_stream_opened(ConnRef, StreamId);

    %% Data received on stream
    {quic, ConnRef, {stream_data, StreamId, Data, Fin}} ->
        handle_data(ConnRef, StreamId, Data, Fin);

    %% Stream reset by peer
    {quic, ConnRef, {stream_reset, StreamId, ErrorCode}} ->
        handle_reset(ConnRef, StreamId, ErrorCode);

    %% Datagram received (RFC 9221)
    {quic, ConnRef, {datagram, Data}} ->
        handle_datagram(ConnRef, Data);

    %% Connection closed
    {quic, ConnRef, {closed, Reason}} ->
        handle_closed(ConnRef, Reason)
end.
```

## Server Pool for High Concurrency

```erlang
%% Start a server pool with multiple listener processes
{ok, _} = quic:start_server(high_perf_server, 4433, #{
    cert => Cert,
    key => Key,
    pool_size => erlang:system_info(schedulers),  % One per scheduler
    alpn => [<<"h3">>]
}).
```

## Load Balancer Integration (RFC 9312)

```erlang
%% Configure QUIC-LB for load balancer routing
LBConfig = #{
    server_id => <<1, 2, 3, 4>>,        % Unique server identifier
    algorithm => stream_cipher,          % plaintext | stream_cipher | block_cipher
    key => crypto:strong_rand_bytes(16), % Encryption key (not for plaintext)
    config_rotation => 0                 % Config rotation bits (0-7)
},

{ok, _} = quic:start_server(lb_server, 4433, #{
    cert => Cert,
    key => Key,
    lb_config => LBConfig
}).
```

## Connection Migration (RFC 9000 Section 9)

The server automatically handles connection migration when clients change
their network addresses (e.g., WiFi to cellular, NAT rebinding).

**Key concept: The server address stays the same.**

Migration means the *client's address* changed, not the server's. The server
receives packets from a new source address but continues listening on the
same port:

```
BEFORE: Client {192.168.1.10:54321} ───> Server {203.0.113.50:4433}

AFTER:  Client {10.0.0.5:62000} ───────> Server {203.0.113.50:4433}
               ▲                                (same server!)
               └── Client's address changed (NAT rebind or network switch)
```

### How It Works

When the server receives a packet from an address different from the current
`remote_addr`, it:

1. **Detects the change type:**
   - **NAT rebinding**: Same IP, different port (common with NAT timeouts)
   - **Active migration**: Different IP address (network change)

2. **Validates the new path** by sending PATH_CHALLENGE:

```
Server state machine:

  idle ──────────────────────────────────────────────────────┐
    │                                                        │
    │ packet from new address                                │
    ▼                                                        │
  validating_peer ───────────────────────────────────────────┤
    │                                                        │
    │ PATH_RESPONSE received          │ timeout (3*PTO)     │
    │ (matching challenge)            │ retry up to 3x      │
    ▼                                 ▼                      │
  complete_migration()            stay on current path ──────┘
    │
    │ - Reset congestion control
    │ - Reset loss detection
    │ - Reset PMTU to 1200
    │ - Switch to fresh CID
    ▼
  idle (new path active)
```

3. **Completes migration** if PATH_RESPONSE matches:
   - Updates `remote_addr` to the new address
   - Resets congestion control (new path may have different RTT/bandwidth)
   - Resets PMTU discovery (new path may have different MTU)
   - Switches to a fresh Connection ID (prevents path linkability)

### Preferred Address

Servers can advertise a preferred address for clients to migrate to:

```erlang
%% Server advertises preferred address in transport params
{ok, _} = quic:start_server(my_server, 4433, #{
    cert => Cert,
    key => Key,
    %% Client will validate and migrate to this address
    preferred_ipv4 => {{203, 0, 113, 10}, 4433},
    preferred_ipv6 => {{16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, 4433}
}).

%% Client automatically validates and migrates to preferred address
%% after receiving server's transport parameters
```

### Disabling Migration

To disable active migration (e.g., for load balancer compatibility):

```erlang
%% Advertise disable_active_migration in transport params
{ok, _} = quic:start_server(my_server, 4433, #{
    cert => Cert,
    key => Key,
    disable_active_migration => true
}).

%% Clients will receive {error, migration_disabled} if they call migrate/1
%% Server will still handle NAT rebinding (port-only changes)
```

### State Tracking

The server tracks migration state in the connection record:

| Field | Description |
|-------|-------------|
| `migration_state` | `idle` or `validating_peer` |
| `pending_peer_validation` | Path being validated |
| `path_validation_timer` | Timer reference (3 * PTO timeout) |
| `peer_disable_migration` | Peer's transport param setting |
| `current_path` | Active path with dcid, bytes_sent/received |

## Best Practices

### 1. Certificate Management

- Use proper CA-signed certificates in production
- Implement certificate rotation before expiry
- Store private keys securely (consider HSM for production)

### 2. Resource Limits

```erlang
%% Set appropriate limits to prevent resource exhaustion
#{
    max_streams_bidi => 100,       % Limit concurrent streams
    max_streams_uni => 100,
    max_data => 10 * 1024 * 1024,  % 10 MB connection limit
    max_stream_data => 1024 * 1024, % 1 MB per stream
    idle_timeout => 30000           % Close idle connections
}
```

### 3. Connection Supervision

```erlang
%% Embed server in your supervision tree
init([]) ->
    ServerSpec = quic:server_spec(my_server, 4433, #{
        cert => get_cert(),
        key => get_key(),
        alpn => [<<"myproto">>]
    }),

    {ok, {{one_for_one, 10, 60}, [ServerSpec]}}.
```

### 4. Graceful Shutdown

```erlang
%% Stop server gracefully (allows draining)
ok = quic:stop_server(my_server).

%% Close individual connections
ok = quic:close(ConnRef, normal).
```

### 5. Monitoring

```erlang
%% Get server information
{ok, Info} = quic:get_server_info(my_server).
%% Info = #{pid => Pid, port => Port, opts => Opts}

%% List all active servers
Servers = quic:which_servers().

%% Get connection statistics
{ok, Stats} = quic:get_stats(ConnRef).
%% Stats = #{packets_sent => N, packets_received => N, ...}
```

### 6. Enable QLOG for Debugging

```erlang
%% Enable QLOG tracing for debugging
#{
    qlog => #{
        enabled => true,
        dir => "/var/log/quic/qlog",
        events => all  % or specific: [packet_sent, packet_received]
    }
}
```

## Example: Echo Server

```erlang
-module(echo_server).
-export([start/1, stop/0]).

start(Port) ->
    {ok, CertPem} = file:read_file("cert.pem"),
    {ok, KeyPem} = file:read_file("key.pem"),
    [{'Certificate', Cert, _}] = public_key:pem_decode(CertPem),
    [{'RSAPrivateKey', KeyDer, _}] = public_key:pem_decode(KeyPem),
    Key = public_key:der_decode('RSAPrivateKey', KeyDer),

    quic:start_server(echo, Port, #{
        cert => Cert,
        key => Key,
        alpn => [<<"echo">>],
        connection_handler => fun handle_connection/2
    }).

stop() ->
    quic:stop_server(echo).

handle_connection(ConnPid, _Info) ->
    spawn(fun() -> echo_loop(ConnPid) end).

echo_loop(ConnPid) ->
    receive
        {quic, _, {stream_data, StreamId, Data, Fin}} ->
            %% Echo data back
            quic:send_data(ConnPid, StreamId, Data, Fin),
            echo_loop(ConnPid);
        {quic, _, {closed, _}} ->
            ok
    end.
```

## Troubleshooting

### Server Won't Start

1. Check certificate/key format (must be DER-encoded or properly decoded)
2. Verify port is available: `netstat -an | grep <port>`
3. Check for proper permissions on low ports (<1024)

### Connections Dropping

1. Check `idle_timeout` setting
2. Enable keep-alive: `keep_alive_interval => 15000`
3. Review flow control limits

### Performance Issues

1. Increase `pool_size` for high connection counts
2. Tune `max_streams_*` limits
3. Consider enabling BBR congestion control (if available)
4. Use QLOG to identify bottlenecks
5. Check UDP buffer sizes (see Performance Tuning below)

## Performance Tuning

### UDP Buffer Sizing

QUIC performance depends heavily on UDP socket buffer sizes. By default, erlang_quic requests 7MB buffers (matching quic-go, quiche, lsquic). Undersized buffers can reduce throughput by 40%+.

**Check actual buffer sizes:**
```erlang
%% After starting a server
{ok, Socket} = gen_udp:open(0, [{recbuf, 7340032}, {sndbuf, 7340032}]),
{ok, Opts} = inet:getopts(Socket, [recbuf, sndbuf]),
io:format("Actual buffers: ~p~n", [Opts]).
```

**Linux: Increase system limits**
```bash
# Check current limits
sysctl net.core.rmem_max
sysctl net.core.wmem_max

# Increase to 7MB (requires root)
sudo sysctl -w net.core.rmem_max=7340032
sudo sysctl -w net.core.wmem_max=7340032

# Make persistent in /etc/sysctl.conf
echo "net.core.rmem_max=7340032" | sudo tee -a /etc/sysctl.conf
echo "net.core.wmem_max=7340032" | sudo tee -a /etc/sysctl.conf
```

**macOS: System limits**
macOS typically caps UDP buffers at 2-4MB. While lower than Linux, this is still much better than the ~128KB defaults.

**Custom buffer sizes:**
```erlang
%% Server with custom buffers
quic:start_server(my_server, 4433, #{
    cert => Cert,
    key => Key,
    recbuf => 4194304,  % 4MB
    sndbuf => 4194304
}).

%% Client with custom buffers
quic:connect("example.com", 4433, #{
    recbuf => 4194304,
    sndbuf => 4194304
}).
```

**Benchmark buffer impact:**
```erlang
%% Compare different buffer sizes
quic_throughput_bench:compare_buffer_sizes().
```
