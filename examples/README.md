# erlang_quic Examples

This directory contains runnable examples demonstrating erlang_quic features.

## Prerequisites

1. Generate test certificates:
   ```bash
   cd certs
   ./generate_certs.sh
   ```

2. Start the Erlang shell with the QUIC application:
   ```bash
   rebar3 shell
   ```

## Echo Server and Client

Basic example showing server setup and client connection.

### Start the Server

```erlang
%% Start on port 4433
echo_server:start(4433).
%% Output: Echo server started on port 4433

%% Or use port 0 for random port
echo_server:start(0).
```

### Run the Client

```erlang
%% Send a message and receive echo
echo_client:run("localhost", 4433, <<"Hello, QUIC!">>).
%% Output:
%% Connecting to localhost:4433
%% Connected! ALPN: <<"echo">>
%% Opened stream 0
%% Sent 12 bytes
%% Received 12 bytes
%% {ok,<<"Hello, QUIC!">>}
```

### Test Datagrams

```erlang
%% Send unreliable datagram
echo_client:datagram("localhost", 4433, <<"Fast data!">>).
%% Output:
%% Sent datagram: 10 bytes
%% Received datagram: 10 bytes
%% {ok,<<"Fast data!">>}
```

### Benchmark

```erlang
%% Send 100 concurrent requests
echo_client:benchmark("localhost", 4433, <<"test">>, 100).
%% Output:
%% Starting benchmark: 100 requests, 4 bytes each
%% Benchmark results:
%%   Requests: 100 successful, 0 failed
%%   Duration: 150 ms
%%   Throughput: 5333 bytes/sec
```

### Stop the Server

```erlang
echo_server:stop().
```

## QLOG Tracing Example

Demonstrates QLOG for debugging and performance analysis.

### Start Server with QLOG

```erlang
qlog_example:start_server(4433).
%% Output:
%% QLOG server started on port 4433
%% QLOG files will be written to: /tmp/qlog
```

### Run Client with QLOG

```erlang
qlog_example:run_client("localhost", 4433).
%% Output:
%% Connecting to localhost:4433 with QLOG enabled
%% Connected!
%% Sent: <<"QLOG test data - Hello World!">>
%% Received: <<"QLOG test data - Hello World!">>
%% Connection closed. QLOG file written to: /tmp/qlog
```

### List QLOG Files

```erlang
qlog_example:list_qlogs().
%% Output:
%% /tmp/qlog/a1b2c3d4_client_1712345678901.qlog (4532 bytes)
%% /tmp/qlog/a1b2c3d4_server_1712345678902.qlog (3210 bytes)
```

### Analyze QLOG

```erlang
qlog_example:analyze("/tmp/qlog/somefile.qlog").
%% Output:
%% QLOG Analysis: /tmp/qlog/somefile.qlog
%% =====================================
%% Total events: 45
%%
%% Event counts:
%%   quic:connection_started: 1
%%   quic:connection_state_updated: 2
%%   quic:packet_received: 15
%%   quic:packet_sent: 18
%%   quic:packets_acked: 8
%%   quic:metrics_updated: 1
%%
%% Packets lost: 0
%% Average RTT: 12.50 ms
```

### View with External Tools

QLOG files can be viewed with:
- **qvis**: https://qvis.quictools.info/ (upload the .qlog file)
- **Wireshark**: Correlate with packet captures

## Server Options Example

```erlang
%% Start server with all options
echo_server:start(4433, #{
    %% Flow control
    max_data => 10 * 1024 * 1024,           % 10 MB
    max_stream_data => 1 * 1024 * 1024,     % 1 MB
    max_streams_bidi => 100,
    max_streams_uni => 100,

    %% Timeouts
    idle_timeout => 30000,                   % 30 seconds
    keep_alive_interval => 15000,            % 15 seconds

    %% Datagrams (RFC 9221)
    max_datagram_frame_size => 65535,

    %% QLOG tracing
    qlog => #{
        enabled => true,
        dir => "/tmp/qlog",
        events => all
    },

    %% Server pool
    pool_size => 4
}).
```

## Cleanup

```erlang
%% Stop server
echo_server:stop().

%% Or
qlog_example:stop_server().

%% Clean QLOG files
os:cmd("rm -f /tmp/qlog/*.qlog").
```

## See Also

- [Server Guide](../docs/SERVER_GUIDE.md) - Server configuration reference
- [Client Guide](../docs/CLIENT_GUIDE.md) - Client features reference
- [QLOG Guide](../docs/QLOG_GUIDE.md) - QLOG tracing reference
