# QUIC Client Guide

This guide covers connecting to QUIC servers and using client features.

## Quick Start

```erlang
%% Start the QUIC application
application:ensure_all_started(quic).

%% Connect to a server
{ok, ConnRef} = quic:connect("example.com", 443, #{
    alpn => [<<"h3">>],
    verify => false  % For testing only!
}, self()).

%% Wait for connection
receive
    {quic, ConnRef, {connected, Info}} ->
        io:format("Connected! ALPN: ~p~n", [maps:get(alpn_protocol, Info)])
end.

%% Open a stream and send data
{ok, StreamId} = quic:open_stream(ConnRef),
ok = quic:send_data(ConnRef, StreamId, <<"Hello, QUIC!">>, true).

%% Receive response
receive
    {quic, ConnRef, {stream_data, StreamId, Data, _Fin}} ->
        io:format("Received: ~p~n", [Data])
end.

%% Close connection
quic:close(ConnRef, normal).
```

## Connection Options

### TLS Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `alpn` | [binary()] | `[<<"h3">>]` | ALPN protocols to offer |
| `verify` | boolean | false | Verify server certificate |
| `server_name` | binary | Host | Server Name Indication |
| `cert` | binary | - | Client certificate (for mTLS) |
| `key` | term | - | Client private key (for mTLS) |

### Connection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `idle_timeout` | integer | 30000 | Idle timeout in ms |
| `max_data` | integer | 10485760 | Connection-level receive limit |
| `max_stream_data` | integer | 1048576 | Per-stream receive limit |
| `max_streams_bidi` | integer | 100 | Max bidirectional streams |
| `max_streams_uni` | integer | 100 | Max unidirectional streams |

### Datagram Options (RFC 9221)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_datagram_frame_size` | integer | 0 | Max datagram size (0 = disabled) |

### Socket Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `socket` | gen_udp:socket() | - | Pre-opened UDP socket |
| `extra_socket_opts` | list() | `[]` | Options for socket creation |

### Advanced Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keep_alive_interval` | integer/atom | `auto` | PING interval |
| `pmtu_enabled` | boolean | true | Enable Path MTU Discovery |

## Features

### Stream Management

```erlang
%% Open bidirectional stream
{ok, BidiStreamId} = quic:open_stream(ConnRef).

%% Open unidirectional stream (send-only)
{ok, UniStreamId} = quic:open_unidirectional_stream(ConnRef).

%% Send data (Fin=true closes the send side)
ok = quic:send_data(ConnRef, StreamId, <<"data">>, false),
ok = quic:send_data(ConnRef, StreamId, <<"more">>, true).  % Final

%% Send with timeout
case quic:send_data(ConnRef, StreamId, Data, true, 5000) of
    ok -> sent;
    {error, timeout} -> handle_timeout()
end.

%% Reset a stream with error code
ok = quic:reset_stream(ConnRef, StreamId, 0).

%% Request peer to stop sending
ok = quic:stop_sending(ConnRef, StreamId, 0).
```

### Stream Prioritization (RFC 9218)

```erlang
%% Set stream priority
%% Urgency: 0-7 (0 = most urgent, default 3)
%% Incremental: true if data can be processed incrementally
ok = quic:set_stream_priority(ConnRef, StreamId, 0, false).

%% Get current priority
{ok, {Urgency, Incremental}} = quic:get_stream_priority(ConnRef, StreamId).
```

### Stream Deadlines

```erlang
%% Set a 5-second deadline on a stream
ok = quic:set_stream_deadline(ConnRef, StreamId, 5000).

%% Set deadline with custom action
ok = quic:set_stream_deadline(ConnRef, StreamId, 5000, #{
    action => notify,  % notify | reset | both
    error_code => 16#FF
}).

%% Check remaining time
{ok, {RemainingMs, Action}} = quic:get_stream_deadline(ConnRef, StreamId).

%% Cancel deadline
ok = quic:cancel_stream_deadline(ConnRef, StreamId).

%% Handle deadline expiration
receive
    {quic, ConnRef, {stream_deadline, StreamId}} ->
        handle_deadline_expired(StreamId)
end.
```

### Unreliable Datagrams (RFC 9221)

```erlang
%% Enable datagrams (both client and server must enable)
{ok, ConnRef} = quic:connect(Host, Port, #{
    max_datagram_frame_size => 65535  % Accept any size
}, self()).

%% Check if datagrams are supported
MaxSize = quic:datagram_max_size(ConnRef),
case MaxSize of
    0 -> io:format("Datagrams not supported~n");
    _ -> io:format("Max datagram size: ~p~n", [MaxSize])
end.

%% Send a datagram (unreliable, not retransmitted)
case quic:send_datagram(ConnRef, <<"game_state">>) of
    ok -> sent;
    {error, datagrams_not_supported} -> not_supported;
    {error, datagram_too_large} -> too_big;
    {error, congestion_limited} -> dropped  % Normal for datagrams
end.

%% Receive datagrams
receive
    {quic, ConnRef, {datagram, Data}} ->
        handle_datagram(Data)
end.
```

### Connection Migration

```erlang
%% Trigger migration to a new local address
%% (e.g., when switching from WiFi to cellular)
ok = quic:migrate(ConnRef).

%% The connection will:
%% 1. Bind to a new local socket
%% 2. Send PATH_CHALLENGE to peer
%% 3. Wait for PATH_RESPONSE
%% 4. Reset congestion controller for new path
```

### Socket Binding

```erlang
%% Bind to a specific local IP using extra_socket_opts
{ok, ConnRef} = quic:connect(Host, Port, #{
    extra_socket_opts => [{ip, {192,168,1,10}}]
}, self()).

%% Use a pre-opened socket for full control
{ok, Sock} = gen_udp:open(0, [binary, inet, {ip, {192,168,1,10}}]),
{ok, ConnRef} = quic:connect(Host, Port, #{
    socket => Sock
}, self()).

%% Note: When using socket option, the connection does not own the socket.
%% You must close it yourself after the connection terminates.
```

### 0-RTT Session Resumption

```erlang
%% First connection - receive session ticket
receive
    {quic, ConnRef, {session_ticket, Ticket}} ->
        %% Store ticket for later use
        store_ticket(Host, Ticket)
end.

%% Later connection - use stored ticket
StoredTicket = get_ticket(Host),
{ok, ConnRef2} = quic:connect(Host, Port, #{
    session_ticket => StoredTicket,
    early_data => <<"request">>  % Sent with 0-RTT
}, self()).
```

### Connection Information

```erlang
%% Get peer address
{ok, {IP, Port}} = quic:peername(ConnRef).

%% Get local address
{ok, {LocalIP, LocalPort}} = quic:sockname(ConnRef).

%% Get peer certificate
{ok, CertDer} = quic:peercert(ConnRef).

%% Get current MTU
{ok, MTU} = quic:get_mtu(ConnRef).

%% Get connection statistics
{ok, Stats} = quic:get_stats(ConnRef).
%% Stats = #{
%%     packets_sent => 150,
%%     packets_received => 148,
%%     data_sent => 50000,
%%     data_received => 45000
%% }
```

### Backpressure and Congestion

```erlang
%% Check send queue status for backpressure
{ok, Info} = quic:get_send_queue_info(ConnRef).
%% Info = #{
%%     bytes => 5000,        % Bytes queued
%%     cwnd => 14720,        % Congestion window
%%     in_flight => 10000,   % Unacked bytes
%%     in_recovery => false, % In loss recovery?
%%     congested => false    % Should apply backpressure?
%% }

case maps:get(congested, Info) of
    true -> pause_sending();
    false -> continue_sending()
end.
```

## Message Reference

Messages sent to the owner process:

| Message | Description |
|---------|-------------|
| `{quic, Ref, {connected, Info}}` | Connection established |
| `{quic, Ref, {stream_opened, StreamId}}` | Peer opened a stream |
| `{quic, Ref, {stream_data, StreamId, Data, Fin}}` | Data received |
| `{quic, Ref, {stream_reset, StreamId, Code}}` | Stream reset by peer |
| `{quic, Ref, {stop_sending, StreamId, Code}}` | Stop sending requested |
| `{quic, Ref, {datagram, Data}}` | Datagram received |
| `{quic, Ref, {session_ticket, Ticket}}` | Session ticket for 0-RTT |
| `{quic, Ref, {stream_deadline, StreamId}}` | Stream deadline expired |
| `{quic, Ref, {send_ready, StreamId}}` | Stream ready to write |
| `{quic, Ref, {closed, Reason}}` | Connection closed |
| `{quic, Ref, {transport_error, Code, Reason}}` | Transport error |

## Error Handling

```erlang
%% Connection errors
case quic:connect(Host, Port, Opts, self()) of
    {ok, ConnRef} ->
        wait_for_connection(ConnRef);
    {error, Reason} ->
        handle_connect_error(Reason)
end.

%% Stream errors
case quic:send_data(ConnRef, StreamId, Data, true) of
    ok -> ok;
    {error, not_found} -> connection_gone();
    {error, stream_closed} -> stream_gone();
    {error, flow_control} -> apply_backpressure()
end.

%% Handle connection close
receive
    {quic, ConnRef, {closed, normal}} ->
        ok;
    {quic, ConnRef, {closed, idle_timeout}} ->
        reconnect();
    {quic, ConnRef, {transport_error, Code, Reason}} ->
        log_error(Code, Reason)
end.
```

## Best Practices

### 1. Certificate Verification

```erlang
%% Production: always verify certificates
#{
    verify => true,
    cacertfile => "/etc/ssl/certs/ca-certificates.crt"
}

%% Development only: disable verification
#{verify => false}
```

### 2. Connection Pooling

```erlang
%% For multiple requests to same server, reuse connections
%% Open multiple streams on single connection
{ok, ConnRef} = quic:connect(Host, Port, Opts, self()),

%% Concurrent requests on same connection
{ok, Stream1} = quic:open_stream(ConnRef),
{ok, Stream2} = quic:open_stream(ConnRef),
{ok, Stream3} = quic:open_stream(ConnRef).
```

### 3. Graceful Shutdown

```erlang
%% Close streams before closing connection
lists:foreach(fun(StreamId) ->
    quic:send_data(ConnRef, StreamId, <<>>, true)
end, OpenStreams),

%% Wait for acknowledgment, then close
timer:sleep(100),
quic:close(ConnRef, normal).
```

### 4. Timeout Handling

```erlang
%% Set appropriate timeouts
connect_with_timeout(Host, Port) ->
    {ok, ConnRef} = quic:connect(Host, Port, #{
        idle_timeout => 30000
    }, self()),

    receive
        {quic, ConnRef, {connected, _}} ->
            {ok, ConnRef}
    after 10000 ->
        quic:close(ConnRef, timeout),
        {error, connection_timeout}
    end.
```

### 5. Enable QLOG for Debugging

```erlang
%% Enable QLOG to debug connection issues
quic:connect(Host, Port, #{
    qlog => #{
        enabled => true,
        dir => "/tmp/qlog"
    }
}, self()).

%% View with: qvis or Wireshark
```

## Example: HTTP/3-style Client

```erlang
-module(h3_client).
-export([request/3]).

request(Host, Port, Path) ->
    %% Connect
    {ok, ConnRef} = quic:connect(Host, Port, #{
        alpn => [<<"h3">>],
        verify => false
    }, self()),

    receive
        {quic, ConnRef, {connected, _}} -> ok
    after 5000 ->
        quic:close(ConnRef, timeout),
        exit(connection_timeout)
    end,

    %% Open request stream
    {ok, StreamId} = quic:open_stream(ConnRef),

    %% Send request (simplified, not real H3)
    Request = <<"GET ", Path/binary, " HTTP/3\r\n\r\n">>,
    ok = quic:send_data(ConnRef, StreamId, Request, true),

    %% Receive response
    Response = receive_response(ConnRef, StreamId, <<>>),

    quic:close(ConnRef, normal),
    Response.

receive_response(ConnRef, StreamId, Acc) ->
    receive
        {quic, ConnRef, {stream_data, StreamId, Data, false}} ->
            receive_response(ConnRef, StreamId, <<Acc/binary, Data/binary>>);
        {quic, ConnRef, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, ConnRef, {closed, _}} ->
            Acc
    after 10000 ->
        Acc
    end.
```

## Troubleshooting

### Connection Fails

1. Check server is reachable: `nc -u <host> <port>`
2. Verify ALPN matches server's protocols
3. Check certificate issues with `verify => false` first
4. Enable QLOG to see handshake details

### Slow Performance

1. Check for packet loss with QLOG
2. Verify MTU discovery is working: `quic:get_mtu(ConnRef)`
3. Monitor congestion: `quic:get_send_queue_info(ConnRef)`
4. Consider datagram API for latency-sensitive data

### Connection Drops

1. Check `idle_timeout` settings on both ends
2. Enable keep-alive: `keep_alive_interval => 15000`
3. Monitor for transport errors in messages
