# erlang_quic

Pure Erlang QUIC implementation (RFC 9000/9001).

## Features

- TLS 1.3 handshake (RFC 8446)
- Stream multiplexing (bidirectional and unidirectional)
- Key update support (RFC 9001 Section 6)
- Connection migration (RFC 9000 Section 9)
- 0-RTT early data support (RFC 9001 Section 4.6)
- Server mode with listener
- Flow control (connection and stream level)
- Congestion control (NewReno)
- Loss detection and packet retransmission (RFC 9002)

## Requirements

- Erlang/OTP 26.0 or later
- rebar3

## Installation

Add to your `rebar.config` dependencies:

```erlang
{deps, [
    {quic, {git, "https://github.com/benoitc/erlang_quic.git", {branch, "main"}}}
]}.
```

## Quick Start

### Client

```erlang
%% Connect to a QUIC server
{ok, ConnRef} = quic:connect(<<"example.com">>, 443, #{
    alpn => [<<"h3">>],
    verify => false
}, self()),

%% Wait for connection
receive
    {quic, ConnRef, {connected, Info}} ->
        io:format("Connected: ~p~n", [Info])
end,

%% Open a bidirectional stream
{ok, StreamId} = quic:open_stream(ConnRef),

%% Send data on the stream
ok = quic:send_data(ConnRef, StreamId, <<"Hello, QUIC!">>, true),

%% Receive data
receive
    {quic, ConnRef, {stream_data, StreamId, Data, _Fin}} ->
        io:format("Received: ~p~n", [Data])
end,

%% Close connection
quic:close(ConnRef, normal).
```

### Server

```erlang
%% Load certificate and key
{ok, CertDer} = file:read_file("server.crt"),
{ok, KeyDer} = file:read_file("server.key"),

%% Start listener
{ok, Listener} = quic_listener:start_link(4433, #{
    cert => CertDer,
    key => KeyDer,
    alpn => [<<"h3">>]
}),

%% Get the port (useful if 0 was specified)
Port = quic_listener:get_port(Listener),
io:format("Listening on port ~p~n", [Port]),

%% Incoming connections are handled automatically
%% The listener spawns quic_connection processes for each client
```

## Messages

The owner process receives messages in the format `{quic, ConnRef, Event}`:

| Event | Description |
|-------|-------------|
| `{connected, Info}` | Connection established |
| `{stream_opened, StreamId}` | New stream opened by peer |
| `{stream_data, StreamId, Data, Fin}` | Data received on stream |
| `{stream_reset, StreamId, ErrorCode}` | Stream reset by peer |
| `{closed, Reason}` | Connection closed |
| `{transport_error, Code, Reason}` | Transport error |
| `{session_ticket, Ticket}` | Session ticket for 0-RTT |

## API Reference

### Connection

- `quic:connect/4` - Connect to a QUIC server
- `quic:close/2` - Close a connection
- `quic:peername/1` - Get remote address
- `quic:sockname/1` - Get local address

### Streams

- `quic:open_stream/1` - Open bidirectional stream
- `quic:open_unidirectional_stream/1` - Open unidirectional stream
- `quic:send_data/4` - Send data on stream
- `quic:reset_stream/3` - Reset a stream

### Server

- `quic_listener:start_link/2` - Start a QUIC listener
- `quic_listener:stop/1` - Stop listener
- `quic_listener:get_port/1` - Get listening port
- `quic_listener:get_connections/1` - List active connections

## Building

```bash
rebar3 compile
```

## Testing

```bash
# Run unit tests
rebar3 eunit

# Run property-based tests
rebar3 proper

# Run all tests
rebar3 eunit && rebar3 proper
```

## Interoperability

This implementation passes all [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner) test cases:

| Test Case | Status |
|-----------|--------|
| handshake | ✓ |
| transfer | ✓ |
| retry | ✓ |
| keyupdate | ✓ |
| chacha20 | ✓ |
| multiconnect | ✓ |
| v2 | ✓ |

See [interop/README.md](interop/README.md) for details on running interop tests.

## Documentation

Generate documentation with:

```bash
rebar3 ex_doc
```

## License

Apache License 2.0

## Author

Benoit Chesneau
