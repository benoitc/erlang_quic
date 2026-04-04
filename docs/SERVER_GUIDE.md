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
