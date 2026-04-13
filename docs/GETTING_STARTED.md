# Getting Started

This guide walks you through setting up and using erlang_quic in your application.

## Requirements

- Erlang/OTP 26.0 or later
- rebar3

## Installation

Add erlang_quic to your `rebar.config` dependencies:

```erlang
{deps, [
    {quic, {git, "https://github.com/benoitc/erlang_quic.git", {tag, "0.11.0"}}}
]}.
```

Then fetch dependencies:

```bash
rebar3 get-deps
rebar3 compile
```

## Your First QUIC Client

Create a simple client that connects to a QUIC server:

```erlang
-module(hello_client).
-export([run/2]).

run(Host, Port) ->
    %% Start the quic application
    application:ensure_all_started(quic),

    %% Connect to server
    Opts = #{
        alpn => [<<"example">>],
        verify => verify_none
    },
    {ok, Conn} = quic:connect(Host, Port, Opts, self()),

    %% Wait for connection
    receive
        {quic, Conn, {connected, Info}} ->
            io:format("Connected to ~s:~p~n", [Host, Port]),
            io:format("ALPN: ~p~n", [maps:get(alpn, Info, undefined)])
    after 5000 ->
        error(connection_timeout)
    end,

    %% Open a stream and send data
    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, <<"Hello, QUIC!">>, true),

    %% Wait for response
    receive
        {quic, Conn, {stream_data, StreamId, Response, _Fin}} ->
            io:format("Response: ~s~n", [Response])
    after 5000 ->
        io:format("No response received~n")
    end,

    %% Close connection
    quic:close(Conn),
    ok.
```

## Your First QUIC Server

Create a server that echoes back received data:

```erlang
-module(echo_server).
-export([start/1, stop/0]).

start(Port) ->
    %% Start the quic application
    application:ensure_all_started(quic),

    %% Generate self-signed certificate for testing
    {Cert, Key} = generate_test_cert(),

    %% Start the server
    Opts = #{
        cert => Cert,
        key => Key,
        alpn => [<<"example">>],
        connection_handler => fun handle_connection/3
    },
    quic:start_server(echo_server, Port, Opts).

stop() ->
    quic:stop_server(echo_server).

handle_connection(Conn, _Opts, _Owner) ->
    spawn(fun() -> connection_loop(Conn) end).

connection_loop(Conn) ->
    ok = quic:set_owner(Conn, self()),
    loop(Conn).

loop(Conn) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} ->
            %% Echo back the data
            quic:send_data(Conn, StreamId, Data, true),
            loop(Conn);
        {quic, Conn, {closed, _Reason}} ->
            ok;
        _ ->
            loop(Conn)
    end.

generate_test_cert() ->
    %% For testing only - use proper certificates in production
    {ok, CertDer} = file:read_file("cert.pem"),
    {ok, KeyDer} = file:read_file("key.pem"),
    {CertDer, KeyDer}.
```

## Generating Test Certificates

For development, generate self-signed certificates:

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj '/CN=localhost'
```

## Running the Example

1. Start the server:

```erlang
1> c(echo_server).
{ok,echo_server}
2> echo_server:start(4433).
{ok,<0.123.0>}
```

2. In another shell, run the client:

```erlang
1> c(hello_client).
{ok,hello_client}
2> hello_client:run("localhost", 4433).
Connected to localhost:4433
ALPN: <<"example">>
Response: Hello, QUIC!
ok
```

## Key Concepts

### Connections

QUIC connections are multiplexed over UDP. Each connection:
- Has a unique Connection ID
- Is encrypted with TLS 1.3
- Can have multiple streams
- Supports connection migration

### Streams

Streams are lightweight channels within a connection:
- **Bidirectional**: Both sides can send and receive
- **Unidirectional**: One side sends, other receives
- Streams have flow control
- Streams can be prioritized

### Events

The owner process receives events as messages:

```erlang
{quic, Conn, Event}
```

Common events:
- `{connected, Info}` - Connection established
- `{stream_opened, StreamId}` - Peer opened a stream
- `{stream_data, StreamId, Data, Fin}` - Data received
- `{closed, Reason}` - Connection closed

### Flow Control

QUIC has built-in flow control at both connection and stream levels. The library handles this automatically, but you can configure limits:

```erlang
Opts = #{
    max_data => 10485760,        %% 10MB connection limit
    max_stream_data => 1048576   %% 1MB per-stream limit
}.
```

## Next Steps

- [Developer Guide](DEVELOPER_GUIDE.md) - Detailed API usage and patterns
- [Features](features.md) - Complete feature list and API reference
- [HTTP/3](HTTP3.md) - HTTP/3 client/server API, internals, benchmarks
- [Design](DESIGN.md) - Architecture and protocol details
- [QUIC Distribution](QUIC_DIST.md) - Using QUIC for Erlang distribution
- [QLOG Guide](QLOG_GUIDE.md) - Debugging with QLOG tracing

## Common Issues

### Connection Timeout

If connections fail to establish:
1. Check that the server is running and port is correct
2. Verify UDP traffic is allowed (QUIC uses UDP, not TCP)
3. Check certificate configuration

### Certificate Errors

For development, use `verify => verify_none`. In production:
- Use CA-signed certificates
- Set `verify => verify_peer`
- Configure `cacert_file` with CA bundle

### ALPN Mismatch

Both client and server must agree on ALPN:

```erlang
%% Server
#{alpn => [<<"h3">>, <<"myproto">>]}

%% Client must use one of the server's protocols
#{alpn => [<<"myproto">>]}
```
