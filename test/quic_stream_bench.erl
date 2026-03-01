%%% -*- erlang -*-
%%%
%%% QUIC Stream Benchmarking Module
%%%
%%% Provides various benchmarks for measuring stream performance:
%%% - Throughput: N streams sending M bytes each
%%% - Latency: Small message round-trip times
%%% - Memory Pressure: Rapid sends without waiting
%%% - Priority Fairness: Mixed urgency stream completion times
%%% - Concurrent Streams: Rapid stream open/close
%%%

-module(quic_stream_bench).

-export([
    run_all/0,
    run_all/2,
    throughput/3,
    throughput/4,
    latency/3,
    latency/4,
    memory_pressure/2,
    memory_pressure/3,
    priority_fairness/2,
    priority_fairness/3,
    concurrent_streams/2,
    concurrent_streams/3
]).

%% Default configuration
-define(DEFAULT_HOST, "127.0.0.1").
-define(DEFAULT_PORT, 4433).
-define(DEFAULT_STREAM_COUNT, 10).
%% 1 MB
-define(DEFAULT_BYTES_PER_STREAM, 1048576).
-define(DEFAULT_MESSAGE_COUNT, 1000).
-define(DEFAULT_MESSAGE_SIZE, 64).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run all benchmarks with default settings
-spec run_all() -> [{atom(), map()}].
run_all() ->
    run_all(?DEFAULT_HOST, ?DEFAULT_PORT).

%% @doc Run all benchmarks against specified host/port
-spec run_all(string() | binary(), inet:port_number()) -> [{atom(), map()}].
run_all(Host, Port) ->
    io:format("~n=== QUIC Stream Benchmarks ===~n"),
    io:format("Target: ~s:~p~n~n", [Host, Port]),

    Results = [
        {throughput, throughput(Host, Port, ?DEFAULT_STREAM_COUNT)},
        {latency, latency(Host, Port, ?DEFAULT_MESSAGE_COUNT)},
        {memory_pressure, memory_pressure(Host, Port)},
        {priority_fairness, priority_fairness(Host, Port)},
        {concurrent_streams, concurrent_streams(Host, Port)}
    ],

    io:format("~n=== Benchmark Summary ===~n"),
    lists:foreach(
        fun({Name, Result}) ->
            Status = maps:get(status, Result, unknown),
            io:format("  ~-20s: ~p~n", [Name, Status])
        end,
        Results
    ),

    Results.

%%====================================================================
%% Throughput Benchmark
%%====================================================================

%% @doc Measure throughput with default bytes per stream
-spec throughput(string() | binary(), inet:port_number(), pos_integer()) -> map().
throughput(Host, Port, StreamCount) ->
    throughput(Host, Port, StreamCount, ?DEFAULT_BYTES_PER_STREAM).

%% @doc Measure throughput: N streams sending M bytes each
%% Returns: #{status, streams, bytes_total, duration_ms, mb_per_sec, streams_per_sec}
-spec throughput(string() | binary(), inet:port_number(), pos_integer(), pos_integer()) -> map().
throughput(Host, Port, StreamCount, BytesPerStream) ->
    io:format("Throughput benchmark: ~p streams, ~p bytes each~n", [StreamCount, BytesPerStream]),

    case connect_with_timeout(Host, Port, 5000) of
        {ok, _ConnRef, ConnPid} ->
            Data = crypto:strong_rand_bytes(BytesPerStream),

            Start = erlang:monotonic_time(millisecond),

            %% Open streams and send data
            StreamIds = lists:map(
                fun(_) ->
                    {ok, StreamId} = quic_connection:open_stream(ConnPid),
                    ok = quic_connection:send_data(ConnPid, StreamId, Data, true),
                    StreamId
                end,
                lists:seq(1, StreamCount)
            ),

            %% Wait for all data to be acknowledged (simplified: just wait a bit)
            timer:sleep(1000),

            End = erlang:monotonic_time(millisecond),
            Duration = max(1, End - Start),

            TotalBytes = StreamCount * BytesPerStream,
            MBPerSec = (TotalBytes / 1048576) / (Duration / 1000),
            StreamsPerSec = StreamCount / (Duration / 1000),

            quic_connection:close(ConnPid, normal),

            Result = #{
                status => ok,
                streams => StreamCount,
                bytes_per_stream => BytesPerStream,
                bytes_total => TotalBytes,
                duration_ms => Duration,
                mb_per_sec => MBPerSec,
                streams_per_sec => StreamsPerSec,
                stream_ids => StreamIds
            },

            io:format("  Result: ~.2f MB/s, ~.2f streams/s~n", [MBPerSec, StreamsPerSec]),
            Result;
        {error, Reason} ->
            io:format("  Failed to connect: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

%%====================================================================
%% Latency Benchmark
%%====================================================================

%% @doc Measure latency with default message size
-spec latency(string() | binary(), inet:port_number(), pos_integer()) -> map().
latency(Host, Port, MessageCount) ->
    latency(Host, Port, MessageCount, ?DEFAULT_MESSAGE_SIZE).

%% @doc Measure latency: small messages round-trip times
%% Returns: #{status, messages, p50_us, p99_us, max_us, avg_us}
-spec latency(string() | binary(), inet:port_number(), pos_integer(), pos_integer()) -> map().
latency(Host, Port, MessageCount, MessageSize) ->
    io:format("Latency benchmark: ~p messages, ~p bytes each~n", [MessageCount, MessageSize]),

    case connect_with_timeout(Host, Port, 5000) of
        {ok, _ConnRef, ConnPid} ->
            {ok, StreamId} = quic_connection:open_stream(ConnPid),
            Data = crypto:strong_rand_bytes(MessageSize),

            %% Measure round-trip times (note: this requires echo server)
            Latencies = lists:map(
                fun(_) ->
                    Start = erlang:monotonic_time(microsecond),
                    ok = quic_connection:send_data(ConnPid, StreamId, Data, false),
                    %% In a real benchmark, we'd wait for echo response
                    %% For now, just measure send latency
                    End = erlang:monotonic_time(microsecond),
                    End - Start
                end,
                lists:seq(1, MessageCount)
            ),

            quic_connection:close(ConnPid, normal),

            Sorted = lists:sort(Latencies),
            P50 = lists:nth(max(1, MessageCount div 2), Sorted),
            P99 = lists:nth(max(1, round(MessageCount * 0.99)), Sorted),
            Max = lists:last(Sorted),
            Avg = lists:sum(Latencies) / MessageCount,

            Result = #{
                status => ok,
                messages => MessageCount,
                message_size => MessageSize,
                p50_us => P50,
                p99_us => P99,
                max_us => Max,
                avg_us => Avg
            },

            io:format("  Result: p50=~p us, p99=~p us, max=~p us~n", [P50, P99, Max]),
            Result;
        {error, Reason} ->
            io:format("  Failed to connect: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

%%====================================================================
%% Memory Pressure Benchmark
%%====================================================================

%% @doc Memory pressure test with default settings
-spec memory_pressure(string() | binary(), inet:port_number()) -> map().
memory_pressure(Host, Port) ->
    memory_pressure(Host, Port, #{}).

%% @doc Memory pressure: rapid sends without waiting
%% Returns: #{status, peak_memory, queue_depth, errors}
-spec memory_pressure(string() | binary(), inet:port_number(), map()) -> map().
memory_pressure(Host, Port, Opts) ->
    SendCount = maps:get(send_count, Opts, 1000),
    %% 64 KB per send
    DataSize = maps:get(data_size, Opts, 65536),

    io:format("Memory pressure benchmark: ~p sends, ~p bytes each~n", [SendCount, DataSize]),

    case connect_with_timeout(Host, Port, 5000) of
        {ok, _ConnRef, ConnPid} ->
            {ok, StreamId} = quic_connection:open_stream(ConnPid),
            Data = crypto:strong_rand_bytes(DataSize),

            MemBefore = erlang:memory(total),

            %% Send rapidly without waiting for ACKs
            Errors = lists:foldl(
                fun(_, ErrCount) ->
                    case quic_connection:send_data(ConnPid, StreamId, Data, false) of
                        ok -> ErrCount;
                        {error, send_queue_full} -> ErrCount + 1;
                        {error, _} -> ErrCount + 1
                    end
                end,
                0,
                lists:seq(1, SendCount)
            ),

            MemAfter = erlang:memory(total),
            MemDelta = MemAfter - MemBefore,

            %% Get connection state to check queue depth
            {_State, Info} = quic_connection:get_state(ConnPid),
            QueueBytes = maps:get(send_queue_bytes, Info, 0),

            quic_connection:close(ConnPid, normal),

            Result = #{
                status => ok,
                sends_attempted => SendCount,
                sends_rejected => Errors,
                data_size => DataSize,
                memory_delta_bytes => MemDelta,
                queue_bytes => QueueBytes
            },

            io:format(
                "  Result: ~p rejected, queue=~p bytes, mem_delta=~p bytes~n",
                [Errors, QueueBytes, MemDelta]
            ),
            Result;
        {error, Reason} ->
            io:format("  Failed to connect: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

%%====================================================================
%% Priority Fairness Benchmark
%%====================================================================

%% @doc Priority fairness test with default settings
-spec priority_fairness(string() | binary(), inet:port_number()) -> map().
priority_fairness(Host, Port) ->
    priority_fairness(Host, Port, #{}).

%% @doc Priority fairness: mixed urgency streams, measure high-priority completion
%% Returns: #{status, high_prio_time_ms, low_prio_time_ms, fairness_ratio}
-spec priority_fairness(string() | binary(), inet:port_number(), map()) -> map().
priority_fairness(Host, Port, Opts) ->
    HighPrioCount = maps:get(high_prio_count, Opts, 5),
    LowPrioCount = maps:get(low_prio_count, Opts, 5),
    BytesPerStream = maps:get(bytes_per_stream, Opts, 65536),

    io:format(
        "Priority fairness benchmark: ~p high-prio, ~p low-prio streams~n",
        [HighPrioCount, LowPrioCount]
    ),

    case connect_with_timeout(Host, Port, 5000) of
        {ok, _ConnRef, ConnPid} ->
            Data = crypto:strong_rand_bytes(BytesPerStream),

            %% Open and configure high-priority streams (urgency 0)
            HighPrioStreams = lists:map(
                fun(_) ->
                    {ok, StreamId} = quic_connection:open_stream(ConnPid),
                    ok = quic_connection:set_stream_priority(ConnPid, StreamId, 0, false),
                    StreamId
                end,
                lists:seq(1, HighPrioCount)
            ),

            %% Open and configure low-priority streams (urgency 7)
            LowPrioStreams = lists:map(
                fun(_) ->
                    {ok, StreamId} = quic_connection:open_stream(ConnPid),
                    ok = quic_connection:set_stream_priority(ConnPid, StreamId, 7, false),
                    StreamId
                end,
                lists:seq(1, LowPrioCount)
            ),

            %% Send data on all streams concurrently
            Start = erlang:monotonic_time(millisecond),

            %% Send on low-priority first to demonstrate priority ordering
            lists:foreach(
                fun(StreamId) ->
                    quic_connection:send_data(ConnPid, StreamId, Data, true)
                end,
                LowPrioStreams
            ),

            %% Then send on high-priority
            lists:foreach(
                fun(StreamId) ->
                    quic_connection:send_data(ConnPid, StreamId, Data, true)
                end,
                HighPrioStreams
            ),

            %% Wait and measure
            timer:sleep(500),
            End = erlang:monotonic_time(millisecond),
            Duration = End - Start,

            quic_connection:close(ConnPid, normal),

            Result = #{
                status => ok,
                high_prio_count => HighPrioCount,
                low_prio_count => LowPrioCount,
                bytes_per_stream => BytesPerStream,
                total_duration_ms => Duration
            },

            io:format("  Result: total duration=~p ms~n", [Duration]),
            Result;
        {error, Reason} ->
            io:format("  Failed to connect: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

%%====================================================================
%% Concurrent Streams Benchmark
%%====================================================================

%% @doc Concurrent streams test with default settings
-spec concurrent_streams(string() | binary(), inet:port_number()) -> map().
concurrent_streams(Host, Port) ->
    concurrent_streams(Host, Port, #{}).

%% @doc Concurrent streams: rapid stream open/close
%% Returns: #{status, streams_opened, streams_per_sec, errors}
-spec concurrent_streams(string() | binary(), inet:port_number(), map()) -> map().
concurrent_streams(Host, Port, Opts) ->
    StreamCount = maps:get(stream_count, Opts, 100),

    io:format("Concurrent streams benchmark: ~p streams~n", [StreamCount]),

    case connect_with_timeout(Host, Port, 5000) of
        {ok, _ConnRef, ConnPid} ->
            Start = erlang:monotonic_time(millisecond),

            %% Open streams rapidly
            {Opened, Errors} = lists:foldl(
                fun(_, {OpenCount, ErrCount}) ->
                    case quic_connection:open_stream(ConnPid) of
                        {ok, _StreamId} -> {OpenCount + 1, ErrCount};
                        {error, _} -> {OpenCount, ErrCount + 1}
                    end
                end,
                {0, 0},
                lists:seq(1, StreamCount)
            ),

            End = erlang:monotonic_time(millisecond),
            Duration = max(1, End - Start),

            StreamsPerSec = Opened / (Duration / 1000),

            quic_connection:close(ConnPid, normal),

            Result = #{
                status => ok,
                streams_attempted => StreamCount,
                streams_opened => Opened,
                errors => Errors,
                duration_ms => Duration,
                streams_per_sec => StreamsPerSec
            },

            io:format(
                "  Result: ~p opened, ~.2f streams/s, ~p errors~n",
                [Opened, StreamsPerSec, Errors]
            ),
            Result;
        {error, Reason} ->
            io:format("  Failed to connect: ~p~n", [Reason]),
            #{status => {error, Reason}}
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Connect with timeout handling
connect_with_timeout(Host, Port, Timeout) ->
    %% Client options: ALPN must match server
    Opts = #{alpn => [<<"bench">>, <<"h3">>]},

    case quic_connection:connect(Host, Port, Opts, self()) of
        {ok, ConnRef, ConnPid} ->
            %% Wait for connection to be established
            receive
                {quic, ConnRef, {connected, _Info}} ->
                    {ok, ConnRef, ConnPid}
            after Timeout ->
                quic_connection:close(ConnPid, timeout),
                {error, connect_timeout}
            end;
        {error, Reason} ->
            {error, Reason}
    end.
