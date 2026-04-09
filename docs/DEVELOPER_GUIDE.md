# Developer Guide

This guide covers practical usage patterns for building applications with erlang_quic.

## Installation

Add to your `rebar.config`:

```erlang
{deps, [
    {quic, {git, "https://github.com/benoitc/erlang_quic.git", {tag, "0.11.0"}}}
]}.
```

## Client Connections

### Basic Client

```erlang
-module(my_client).
-export([connect/2, send_request/3]).

connect(Host, Port) ->
    Opts = #{
        alpn => [<<"h3">>],
        verify => verify_none
    },
    {ok, Conn} = quic:connect(Host, Port, Opts, self()),
    receive
        {quic, Conn, {connected, _Info}} -> {ok, Conn};
        {quic, Conn, {closed, Reason}} -> {error, Reason}
    after 5000 ->
        quic:close(Conn),
        {error, timeout}
    end.

send_request(Conn, Data, Fin) ->
    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, Data, Fin),
    {ok, StreamId}.
```

### Client with Session Resumption (0-RTT)

```erlang
-module(resumable_client).
-export([connect/3, connect_with_ticket/4]).

%% First connection - save the ticket
connect(Host, Port, Owner) ->
    {ok, Conn} = quic:connect(Host, Port, #{alpn => [<<"h3">>]}, Owner),
    receive
        {quic, Conn, {connected, _}} -> ok
    end,
    %% Wait for session ticket
    receive
        {quic, Conn, {session_ticket, Ticket}} ->
            {ok, Conn, Ticket}
    after 5000 ->
        {ok, Conn, undefined}
    end.

%% Subsequent connections - use saved ticket for 0-RTT
connect_with_ticket(Host, Port, Owner, Ticket) ->
    Opts = #{
        alpn => [<<"h3">>],
        session_ticket => Ticket
    },
    {ok, Conn} = quic:connect(Host, Port, Opts, Owner),
    %% Can send early data before handshake completes
    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, <<"early request">>, true),
    {ok, Conn, StreamId}.
```

### Client with Connection Migration

```erlang
%% Trigger migration when network changes (e.g., WiFi to cellular)
handle_network_change(Conn) ->
    case quic:migrate(Conn) of
        ok ->
            %% Migration initiated, path validation in progress
            receive
                {quic, Conn, path_validated} -> ok;
                {quic, Conn, {path_validation_failed, Reason}} -> {error, Reason}
            after 10000 ->
                {error, migration_timeout}
            end;
        {error, Reason} ->
            {error, Reason}
    end.
```

## Server Implementation

### Basic Server

```erlang
-module(my_server).
-behaviour(gen_server).
-export([start_link/2, init/1, handle_info/2]).

start_link(Port, CertKey) ->
    gen_server:start_link(?MODULE, {Port, CertKey}, []).

init({Port, {Cert, Key}}) ->
    Opts = #{
        cert => Cert,
        key => Key,
        alpn => [<<"h3">>]
    },
    {ok, _} = quic:start_server(my_quic_server, Port, Opts),
    {ok, #{}}.

handle_info({quic, Conn, {connected, Info}}, State) ->
    io:format("New connection from ~p~n", [maps:get(peer, Info)]),
    {noreply, State};

handle_info({quic, Conn, {stream_opened, StreamId}}, State) ->
    io:format("Stream ~p opened~n", [StreamId]),
    {noreply, State};

handle_info({quic, Conn, {stream_data, StreamId, Data, Fin}}, State) ->
    %% Process request
    Response = process_request(Data),
    %% Send response
    quic:send_data(Conn, StreamId, Response, true),
    {noreply, State};

handle_info({quic, Conn, {closed, Reason}}, State) ->
    io:format("Connection closed: ~p~n", [Reason]),
    {noreply, State}.
```

### Server with Connection Handler

```erlang
%% Custom handler for each connection
-module(connection_handler).
-export([start/3]).

start(Conn, Opts, Owner) ->
    spawn_link(fun() -> init(Conn, Opts, Owner) end).

init(Conn, _Opts, _Owner) ->
    %% Take ownership of the connection
    ok = quic:set_owner(Conn, self()),
    loop(Conn, #{}).

loop(Conn, State) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            Response = handle_request(Data),
            quic:send_data(Conn, StreamId, Response, true),
            loop(Conn, State);
        {quic, Conn, {closed, _}} ->
            ok
    end.

%% Start server with custom handler
start_server(Port, Cert, Key) ->
    quic:start_server(my_server, Port, #{
        cert => Cert,
        key => Key,
        alpn => [<<"myproto">>],
        connection_handler => fun connection_handler:start/3
    }).
```

### Server with Load Balancer (QUIC-LB)

```erlang
%% Configure server for load balancer routing
start_lb_server(Port, Cert, Key, ServerId) ->
    LbConfig = #{
        algorithm => stream_cipher,
        server_id => ServerId,       % Unique ID for this server (binary)
        key => crypto:strong_rand_bytes(16),
        nonce_len => 8
    },
    quic:start_server(lb_server, Port, #{
        cert => Cert,
        key => Key,
        lb_config => LbConfig
    }).
```

## Stream Management

### Bidirectional Streams

```erlang
%% Open stream and send request
{ok, StreamId} = quic:open_stream(Conn),
ok = quic:send_data(Conn, StreamId, <<"request">>, false),
ok = quic:send_data(Conn, StreamId, <<" data">>, true),  % FIN

%% Receive response
receive
    {quic, Conn, {stream_data, StreamId, Response, true}} ->
        {ok, Response}
end.
```

### Unidirectional Streams

```erlang
%% Send-only stream (client to server)
{ok, StreamId} = quic:open_unidirectional_stream(Conn),
ok = quic:send_data(Conn, StreamId, <<"push data">>, true).

%% Server receives on unidirectional stream
receive
    {quic, Conn, {stream_opened, StreamId}} when StreamId band 3 =:= 2 ->
        %% Client-initiated unidirectional stream
        ok
end.
```

### Stream Prioritization

```erlang
%% Set stream priority (urgency 0-7, lower = higher priority)
ok = quic:set_stream_priority(Conn, StreamId, 0, false),  % Highest priority

%% Incremental delivery for large responses
ok = quic:set_stream_priority(Conn, StreamId, 4, true),   % Incremental

%% Get current priority
{ok, {Urgency, Incremental}} = quic:get_stream_priority(Conn, StreamId).
```

### Stream Reset

```erlang
%% Abort sending on a stream
ok = quic:reset_stream(Conn, StreamId, ?QUIC_CANCEL).

%% Request peer to stop sending
ok = quic:stop_sending(Conn, StreamId, ?QUIC_CANCEL).
```

## Datagrams (RFC 9221)

Datagrams provide unreliable, unordered message delivery:

```erlang
%% Enable datagrams (both sides must enable)
Opts = #{
    alpn => [<<"h3">>],
    max_datagram_frame_size => 65535
},
{ok, Conn} = quic:connect(Host, Port, Opts, self()),

%% Check if peer supports datagrams
case quic:datagram_max_size(Conn) of
    0 -> {error, not_supported};
    MaxSize ->
        %% Send datagram (not retransmitted on loss)
        ok = quic:send_datagram(Conn, <<"game state update">>)
end.

%% Receive datagrams
receive
    {quic, Conn, {datagram, Data}} ->
        handle_datagram(Data)
end.
```

## Event Handling

### All Connection Events

```erlang
handle_quic_event({quic, Conn, Event}) ->
    case Event of
        {connected, Info} ->
            %% Connection established
            #{peer := {IP, Port}, alpn := ALPN} = Info;

        {stream_opened, StreamId} ->
            %% Peer opened a new stream
            ok;

        {stream_data, StreamId, Data, Fin} ->
            %% Data received on stream
            %% Fin=true means end of stream
            ok;

        {stream_reset, StreamId, ErrorCode} ->
            %% Peer reset the stream
            ok;

        {stop_sending, StreamId, ErrorCode} ->
            %% Peer requested we stop sending
            ok;

        {send_ready, StreamId} ->
            %% Stream ready for writing (after flow control block)
            ok;

        {datagram, Data} ->
            %% Unreliable datagram received
            ok;

        {session_ticket, Ticket} ->
            %% Save for 0-RTT resumption
            ok;

        {closed, Reason} ->
            %% Connection closed
            ok;

        {transport_error, Code, Reason} ->
            %% Protocol error
            ok
    end.
```

## Configuration Options

### Connection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `alpn` | `[binary()]` | `[]` | ALPN protocols |
| `verify` | `verify_none \| verify_peer` | `verify_none` | Certificate verification |
| `idle_timeout` | `integer()` | `30000` | Idle timeout (ms), 0 to disable |
| `max_data` | `integer()` | `10485760` | Connection flow control (bytes) |
| `max_stream_data` | `integer()` | `1048576` | Stream flow control (bytes) |
| `max_datagram_frame_size` | `integer()` | `0` | Max datagram size (0 = disabled) |
| `session_ticket` | `binary()` | - | Ticket for 0-RTT resumption |
| `congestion_control` | `newreno \| cubic \| bbr` | `newreno` | CC algorithm |
| `disable_active_migration` | `boolean()` | `false` | Disable migration |

### Server Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `cert` | `binary()` | - | DER-encoded certificate |
| `key` | `term()` | - | Private key |
| `pool_size` | `integer()` | `1` | Listener pool size |
| `connection_handler` | `fun/3` | - | Custom connection handler |
| `lb_config` | `map()` | - | QUIC-LB configuration |
| `preferred_ipv4` | `{ip(), port()}` | - | Preferred IPv4 address |
| `preferred_ipv6` | `{ip(), port()}` | - | Preferred IPv6 address |

### Performance Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `recbuf` | `integer()` | `7340032` | UDP receive buffer (bytes) |
| `sndbuf` | `integer()` | `7340032` | UDP send buffer (bytes) |
| `keep_alive_interval` | `integer() \| auto \| disabled` | `disabled` | PING interval |
| `pmtu_enabled` | `boolean()` | `true` | Enable PMTU discovery |
| `pmtu_max_mtu` | `integer()` | `1500` | Maximum MTU to probe |

## Error Handling

### Connection Errors

```erlang
case quic:connect(Host, Port, Opts, self()) of
    {ok, Conn} ->
        receive
            {quic, Conn, {connected, _}} -> {ok, Conn};
            {quic, Conn, {transport_error, Code, Reason}} ->
                {error, {transport, Code, Reason}};
            {quic, Conn, {closed, Reason}} ->
                {error, Reason}
        end;
    {error, Reason} ->
        {error, Reason}
end.
```

### Graceful Shutdown

```erlang
%% Close with application error code
quic:close(Conn, app_error, <<"shutting down">>).

%% Normal close
quic:close(Conn).
```

## Debugging

### QLOG Tracing

Enable QLOG for debugging:

```erlang
Opts = #{
    alpn => [<<"h3">>],
    qlog_dir => "/tmp/qlogs"
},
{ok, Conn} = quic:connect(Host, Port, Opts, self()).
%% View logs with qvis: https://qvis.quictools.info/
```

### Connection Statistics

```erlang
{ok, Stats} = quic:get_stats(Conn).
%% Returns: #{packets_sent, packets_recv, bytes_sent, bytes_recv, ...}
```

### Logger Configuration

```erlang
%% Enable debug logging for QUIC modules
logger:set_module_level(quic_connection, debug).
logger:set_module_level(quic_crypto, debug).
```

## Best Practices

1. **Always handle connection close events** - Connections can close at any time
2. **Use stream priorities** - Set urgency 0-2 for control, 4-6 for data
3. **Enable 0-RTT for latency-sensitive apps** - Save and reuse session tickets
4. **Configure flow control** - Increase `max_data` for high-throughput apps
5. **Use datagrams for real-time data** - Game state, voice, video
6. **Set idle timeout appropriately** - Balance resource cleanup vs reconnection cost
7. **Enable PMTU discovery** - Optimal packet sizes improve throughput
