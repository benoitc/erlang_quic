# QLOG Tracing Guide

QLOG is a standardized logging format for QUIC connections that enables debugging and performance analysis using tools like Wireshark and qvis.

## Quick Start

```erlang
%% Enable QLOG for a client connection
{ok, ConnRef} = quic:connect("example.com", 443, #{
    qlog => #{
        enabled => true,
        dir => "/tmp/qlog"
    }
}, self()).

%% Enable QLOG for a server
quic:start_server(my_server, 4433, #{
    cert => Cert,
    key => Key,
    qlog => #{
        enabled => true,
        dir => "/tmp/qlog"
    }
}).
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | false | Enable QLOG tracing |
| `dir` | string | "/tmp/qlog" | Directory for QLOG files |
| `events` | all or [atom()] | all | Events to log |

### Event Types

Available event types for selective logging:

| Event | Description |
|-------|-------------|
| `packet_sent` | Outgoing packets |
| `packet_received` | Incoming packets |
| `frames_processed` | Frame processing details |
| `connection_started` | Connection initiation |
| `connection_state_updated` | State machine transitions |
| `connection_closed` | Connection termination |
| `packets_acked` | ACK processing |
| `packet_lost` | Loss detection events |
| `metrics_updated` | Congestion/RTT metrics |

### Selective Logging

```erlang
%% Log only packet events
#{
    qlog => #{
        enabled => true,
        dir => "/tmp/qlog",
        events => [packet_sent, packet_received, packet_lost]
    }
}

%% Log everything (default)
#{
    qlog => #{
        enabled => true,
        events => all
    }
}
```

## Application-wide Configuration

Enable QLOG globally via application environment:

```erlang
%% In sys.config
[
    {quic, [
        {qlog, #{
            enabled => true,
            dir => "/var/log/quic/qlog"
        }}
    ]}
].
```

```erlang
%% Or programmatically
application:set_env(quic, qlog, #{
    enabled => true,
    dir => "/var/log/quic/qlog"
}).
```

Connection-level options override application-level settings.

## QLOG File Format

Files are written in JSON-SEQ format (one JSON object per line):

```
{"qlog_format":"JSON-SEQ","qlog_version":"0.4",...}
{"time":0,"name":"quic:connection_started",...}
{"time":15,"name":"quic:packet_sent",...}
{"time":23,"name":"quic:packet_received",...}
```

### Filename Convention

```
{odcid_hex}_{vantage}_{timestamp}.qlog

Example: a1b2c3d4e5f6_client_1712345678901.qlog
```

- `odcid_hex`: Original Destination Connection ID in hex
- `vantage`: `client` or `server`
- `timestamp`: Unix timestamp in milliseconds

## Viewing QLOG Files

### Using qvis (Web-based)

1. Visit https://qvis.quictools.info/
2. Upload your `.qlog` file
3. Explore connection timeline, congestion graphs, and frame details

### Using Wireshark

1. Open Wireshark
2. Go to Analyze > Follow > QUIC Stream
3. Import QLOG for correlation with packet captures

### Command Line Analysis

```bash
# View raw QLOG
cat connection.qlog | jq .

# Extract packet events
cat connection.qlog | jq 'select(.name | startswith("quic:packet"))'

# Count events by type
cat connection.qlog | jq -r '.name' | sort | uniq -c
```

## Example QLOG Events

### Packet Sent

```json
{
  "time": 150,
  "name": "quic:packet_sent",
  "data": {
    "packet_type": "1rtt",
    "packet_number": 42,
    "length": 1200,
    "frames": [
      {"frame_type": "stream", "stream_id": 0, "offset": 0, "length": 1150, "fin": false}
    ]
  }
}
```

### Packet Lost

```json
{
  "time": 500,
  "name": "quic:packet_lost",
  "data": {
    "packet_number": 38,
    "reason": "time_threshold"
  }
}
```

### Metrics Updated

```json
{
  "time": 600,
  "name": "quic:metrics_updated",
  "data": {
    "cwnd": 14720,
    "bytes_in_flight": 8500,
    "smoothed_rtt": 25,
    "rtt_variance": 5
  }
}
```

### Connection State Updated

```json
{
  "time": 50,
  "name": "quic:connection_state_updated",
  "data": {
    "old": "handshaking",
    "new": "connected"
  }
}
```

## Performance Considerations

QLOG adds overhead due to:
- JSON encoding for each event
- File I/O (buffered with periodic flushes)
- Memory for event buffering

### Recommendations

1. **Production**: Disable by default, enable selectively for debugging
2. **Staging**: Enable with selective events
3. **Development**: Enable all events

```erlang
%% Production: disabled
#{qlog => #{enabled => false}}

%% Staging: selective
#{qlog => #{enabled => true, events => [packet_lost, connection_closed]}}

%% Development: full
#{qlog => #{enabled => true, events => all}}
```

### Buffer Settings

The QLOG writer uses:
- 64KB buffer before forced flush
- 100ms periodic flush interval
- Async writer process to avoid blocking connection

## Debugging Common Issues

### High Latency

Look for in QLOG:
1. Large gaps between `packet_sent` and `packets_acked`
2. High `smoothed_rtt` in `metrics_updated`
3. Frequent `packet_lost` events

### Packet Loss

Check QLOG for:
1. `packet_lost` events with `reason`
2. `metrics_updated` showing `bytes_in_flight` > `cwnd`
3. Congestion window drops after loss

### Handshake Failures

Examine:
1. `connection_started` event
2. `frames_processed` for CRYPTO frames
3. `connection_closed` with error code

### Example Analysis Script

```erlang
-module(qlog_analyzer).
-export([analyze/1]).

analyze(Filename) ->
    {ok, Data} = file:read_file(Filename),
    Lines = binary:split(Data, <<"\n">>, [global, trim]),
    Events = [jsx:decode(L, [return_maps]) || L <- Lines, L =/= <<>>],

    %% Count events
    Counts = lists:foldl(fun(#{<<"name">> := Name}, Acc) ->
        maps:update_with(Name, fun(V) -> V + 1 end, 1, Acc)
    end, #{}, Events),

    %% Find lost packets
    Lost = [E || #{<<"name">> := <<"quic:packet_lost">>} = E <- Events],

    %% Calculate average RTT
    RTTs = [maps:get(<<"smoothed_rtt">>, D) ||
            #{<<"name">> := <<"quic:metrics_updated">>, <<"data">> := D} <- Events,
            maps:is_key(<<"smoothed_rtt">>, D)],
    AvgRTT = case RTTs of
        [] -> undefined;
        _ -> lists:sum(RTTs) / length(RTTs)
    end,

    #{
        event_counts => Counts,
        packets_lost => length(Lost),
        average_rtt => AvgRTT
    }.
```

## Integration with Monitoring

### Export to Prometheus

```erlang
%% Parse QLOG metrics for Prometheus export
extract_metrics(QlogFile) ->
    %% Read final metrics_updated event
    {ok, Data} = file:read_file(QlogFile),
    Lines = lists:reverse(binary:split(Data, <<"\n">>, [global, trim])),

    %% Find last metrics event
    case find_metrics(Lines) of
        {ok, Metrics} ->
            #{
                quic_cwnd => maps:get(<<"cwnd">>, Metrics, 0),
                quic_rtt_ms => maps:get(<<"smoothed_rtt">>, Metrics, 0),
                quic_bytes_in_flight => maps:get(<<"bytes_in_flight">>, Metrics, 0)
            };
        error ->
            #{}
    end.
```

### Alerting on Issues

```erlang
%% Monitor QLOG for anomalies
monitor_qlog(Dir) ->
    Files = filelib:wildcard(Dir ++ "/*.qlog"),
    lists:foreach(fun(F) ->
        #{packets_lost := Lost} = qlog_analyzer:analyze(F),
        case Lost > 100 of
            true -> alert("High packet loss in " ++ F);
            false -> ok
        end
    end, Files).
```
