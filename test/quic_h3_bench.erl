%%% -*- erlang -*-
%%%
%%% HTTP/3 Performance Benchmarking Module
%%%
%%% Measures HTTP/3 performance characteristics:
%%% - Request/response latency (small payloads)
%%% - Throughput (large body transfers)
%%% - Concurrent requests (multiple streams)
%%% - Connection setup time
%%% - QPACK header encoding efficiency
%%%
%%% Usage:
%%%   quic_h3_bench:run().                    % Run all benchmarks
%%%   quic_h3_bench:latency(1000).            % 1000 requests
%%%   quic_h3_bench:throughput(10485760).     % 10MB transfer
%%%   quic_h3_bench:concurrent(100).          % 100 concurrent streams
%%%   quic_h3_bench:qpack_bench().            % QPACK micro-benchmarks
%%%

-module(quic_h3_bench).

-export([
    run/0,
    run/1,
    latency/0,
    latency/1,
    latency/2,
    throughput/0,
    throughput/1,
    throughput/2,
    concurrent/0,
    concurrent/1,
    concurrent/2,
    connection_setup/0,
    connection_setup/1,
    qpack_bench/0,
    qpack_bench/1
]).

-include("quic.hrl").
-include("quic_h3.hrl").

%% Default configuration
-define(DEFAULT_PORT, 14433).
-define(DEFAULT_LATENCY_REQUESTS, 1000).
% 5MB
-define(DEFAULT_THROUGHPUT_SIZE, 5242880).
-define(DEFAULT_CONCURRENT_STREAMS, 50).
-define(DEFAULT_CONNECTION_ITERATIONS, 100).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run all HTTP/3 benchmarks with default settings
-spec run() -> [{atom(), map()}].
run() ->
    run(#{}).

%% @doc Run all benchmarks with options
%% Options:
%%   - port: Server port (default: 14433)
%%   - latency_requests: Number of requests for latency test
%%   - throughput_size: Bytes to transfer for throughput test
%%   - concurrent_streams: Number of concurrent streams
-spec run(map()) -> [{atom(), map()}].
run(Opts) ->
    Port = maps:get(port, Opts, ?DEFAULT_PORT),

    io:format("~n========================================~n"),
    io:format("       HTTP/3 Performance Benchmarks~n"),
    io:format("========================================~n~n"),

    %% Start server
    case start_h3_server(Port) of
        {ok, ServerName, ActualPort} ->
            Results = [
                run_bench(connection_setup, fun() ->
                    connection_setup(
                        maps:get(connection_iterations, Opts, ?DEFAULT_CONNECTION_ITERATIONS)
                    )
                end),
                run_bench(latency, fun() ->
                    latency(ActualPort, maps:get(latency_requests, Opts, ?DEFAULT_LATENCY_REQUESTS))
                end),
                run_bench(throughput, fun() ->
                    throughput(
                        ActualPort, maps:get(throughput_size, Opts, ?DEFAULT_THROUGHPUT_SIZE)
                    )
                end),
                run_bench(concurrent, fun() ->
                    concurrent(
                        ActualPort, maps:get(concurrent_streams, Opts, ?DEFAULT_CONCURRENT_STREAMS)
                    )
                end),
                run_bench(qpack, fun() -> qpack_bench() end)
            ],

            %% Stop server
            quic_h3:stop_server(ServerName),

            print_summary(Results),
            Results;
        {error, Reason} ->
            io:format("Failed to start server: ~p~n", [Reason]),
            [{error, #{reason => Reason}}]
    end.

%%====================================================================
%% Latency Benchmark
%%====================================================================

%% @doc Measure request/response latency with defaults
-spec latency() -> map().
latency() ->
    latency(?DEFAULT_LATENCY_REQUESTS).

%% @doc Measure latency over N requests
-spec latency(pos_integer()) -> map().
latency(RequestCount) ->
    case start_h3_server(?DEFAULT_PORT) of
        {ok, ServerName, ActualPort} ->
            Result = latency(ActualPort, RequestCount),
            quic_h3:stop_server(ServerName),
            Result;
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%% @doc Measure latency against running server
-spec latency(inet:port_number(), pos_integer()) -> map().
latency(Port, RequestCount) ->
    io:format("Latency benchmark: ~p requests~n", [RequestCount]),

    case quic_h3:connect("127.0.0.1", Port, #{verify => none}) of
        {ok, Conn} ->
            wait_connected(Conn),

            %% Warm up
            _ = [
                do_request(Conn, <<"/">>, <<>>)
             || _ <- lists:seq(1, min(10, RequestCount div 10))
            ],

            %% Measure latencies
            Latencies = lists:map(
                fun(_) ->
                    Start = erlang:monotonic_time(microsecond),
                    case do_request(Conn, <<"/">>, <<>>) of
                        {ok, _Status, _Headers, _Body} ->
                            erlang:monotonic_time(microsecond) - Start;
                        {error, _} ->
                            0
                    end
                end,
                lists:seq(1, RequestCount)
            ),

            quic_h3:close(Conn),

            %% Calculate statistics
            ValidLatencies = [L || L <- Latencies, L > 0],
            case ValidLatencies of
                [] ->
                    #{status => error, reason => no_valid_requests};
                _ ->
                    Stats = calculate_stats(ValidLatencies),
                    io:format(
                        "  p50: ~p us, p99: ~p us, avg: ~.1f us~n",
                        [maps:get(p50, Stats), maps:get(p99, Stats), maps:get(avg, Stats)]
                    ),
                    Stats#{
                        status => ok,
                        request_count => length(ValidLatencies),
                        failed => RequestCount - length(ValidLatencies)
                    }
            end;
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%%====================================================================
%% Throughput Benchmark
%%====================================================================

%% @doc Measure throughput with defaults
-spec throughput() -> map().
throughput() ->
    throughput(?DEFAULT_THROUGHPUT_SIZE).

%% @doc Measure throughput for N bytes
-spec throughput(pos_integer()) -> map().
throughput(DataSize) ->
    case start_h3_server(?DEFAULT_PORT) of
        {ok, ServerName, ActualPort} ->
            Result = throughput(ActualPort, DataSize),
            quic_h3:stop_server(ServerName),
            Result;
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%% @doc Measure throughput against running server
-spec throughput(inet:port_number(), pos_integer()) -> map().
throughput(Port, DataSize) ->
    io:format("Throughput benchmark: ~.2f MB~n", [DataSize / 1048576]),

    case quic_h3:connect("127.0.0.1", Port, #{verify => none}) of
        {ok, Conn} ->
            wait_connected(Conn),

            %% Generate random body
            Body = crypto:strong_rand_bytes(DataSize),

            %% Upload benchmark (POST)
            Start1 = erlang:monotonic_time(millisecond),
            case do_request(Conn, <<"/echo">>, Body) of
                {ok, _Status, _Headers, ResponseBody} ->
                    End1 = erlang:monotonic_time(millisecond),
                    Duration1 = max(1, End1 - Start1),

                    UploadMBps = (DataSize / 1048576) / (Duration1 / 1000),
                    DownloadMBps = (byte_size(ResponseBody) / 1048576) / (Duration1 / 1000),
                    TotalMBps =
                        ((DataSize + byte_size(ResponseBody)) / 1048576) / (Duration1 / 1000),

                    quic_h3:close(Conn),

                    io:format(
                        "  Upload: ~.2f MB/s, Download: ~.2f MB/s, Total: ~.2f MB/s~n",
                        [UploadMBps, DownloadMBps, TotalMBps]
                    ),

                    #{
                        status => ok,
                        data_size => DataSize,
                        response_size => byte_size(ResponseBody),
                        duration_ms => Duration1,
                        upload_mbps => UploadMBps,
                        download_mbps => DownloadMBps,
                        total_mbps => TotalMBps
                    };
                {error, Reason} ->
                    quic_h3:close(Conn),
                    #{status => error, reason => Reason}
            end;
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%%====================================================================
%% Concurrent Streams Benchmark
%%====================================================================

%% @doc Measure concurrent stream handling with defaults
-spec concurrent() -> map().
concurrent() ->
    concurrent(?DEFAULT_CONCURRENT_STREAMS).

%% @doc Measure N concurrent streams
-spec concurrent(pos_integer()) -> map().
concurrent(StreamCount) ->
    case start_h3_server(?DEFAULT_PORT) of
        {ok, ServerName, ActualPort} ->
            Result = concurrent(ActualPort, StreamCount),
            quic_h3:stop_server(ServerName),
            Result;
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%% @doc Measure concurrent streams against running server
-spec concurrent(inet:port_number(), pos_integer()) -> map().
concurrent(Port, StreamCount) ->
    io:format("Concurrent streams benchmark: ~p streams~n", [StreamCount]),

    case quic_h3:connect("127.0.0.1", Port, #{verify => none}) of
        {ok, Conn} ->
            wait_connected(Conn),

            Parent = self(),
            Start = erlang:monotonic_time(millisecond),

            %% Launch concurrent requests
            Pids = [
                spawn_link(fun() ->
                    Result = do_request(Conn, <<"/">>, <<>>),
                    Parent ! {done, self(), Result}
                end)
             || _ <- lists:seq(1, StreamCount)
            ],

            %% Collect results
            Results = [
                receive
                    {done, Pid, Result} -> Result
                after 30000 ->
                    {error, timeout}
                end
             || Pid <- Pids
            ],

            End = erlang:monotonic_time(millisecond),
            Duration = max(1, End - Start),

            quic_h3:close(Conn),

            Successful = length([R || R <- Results, element(1, R) =:= ok]),
            Failed = StreamCount - Successful,
            StreamsPerSec = (Successful * 1000) / Duration,

            io:format(
                "  Completed: ~p/~p in ~p ms (~.1f streams/sec)~n",
                [Successful, StreamCount, Duration, StreamsPerSec]
            ),

            #{
                status => ok,
                stream_count => StreamCount,
                successful => Successful,
                failed => Failed,
                duration_ms => Duration,
                streams_per_sec => StreamsPerSec
            };
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%%====================================================================
%% Connection Setup Benchmark
%%====================================================================

%% @doc Measure connection setup time with defaults
-spec connection_setup() -> map().
connection_setup() ->
    connection_setup(?DEFAULT_CONNECTION_ITERATIONS).

%% @doc Measure connection setup time over N iterations
-spec connection_setup(pos_integer()) -> map().
connection_setup(Iterations) ->
    io:format("Connection setup benchmark: ~p iterations~n", [Iterations]),

    case start_h3_server(?DEFAULT_PORT) of
        {ok, ServerName, ActualPort} ->
            %% Measure connection setup times
            Times = lists:filtermap(
                fun(_) ->
                    Start = erlang:monotonic_time(microsecond),
                    case quic_h3:connect("127.0.0.1", ActualPort, #{verify => none}) of
                        {ok, Conn} ->
                            case wait_connected_timeout(Conn, 5000) of
                                ok ->
                                    End = erlang:monotonic_time(microsecond),
                                    quic_h3:close(Conn),
                                    {true, End - Start};
                                {error, _} ->
                                    quic_h3:close(Conn),
                                    false
                            end;
                        {error, _} ->
                            false
                    end
                end,
                lists:seq(1, Iterations)
            ),

            quic_h3:stop_server(ServerName),

            case Times of
                [] ->
                    #{status => error, reason => no_successful_connections};
                _ ->
                    Stats = calculate_stats(Times),
                    io:format(
                        "  p50: ~p us, p99: ~p us, avg: ~.1f us~n",
                        [maps:get(p50, Stats), maps:get(p99, Stats), maps:get(avg, Stats)]
                    ),
                    Stats#{
                        status => ok,
                        iterations => length(Times),
                        failed => Iterations - length(Times)
                    }
            end;
        {error, Reason} ->
            #{status => error, reason => Reason}
    end.

%%====================================================================
%% QPACK Micro-benchmarks
%%====================================================================

%% @doc Run QPACK encoding/decoding benchmarks
-spec qpack_bench() -> map().
qpack_bench() ->
    qpack_bench(#{}).

%% @doc Run QPACK benchmarks with options
-spec qpack_bench(map()) -> map().
qpack_bench(_Opts) ->
    io:format("QPACK micro-benchmarks~n"),

    %% Test headers
    SmallHeaders = [
        {<<":method">>, <<"GET">>},
        {<<":path">>, <<"/">>},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"example.com">>}
    ],

    LargeHeaders =
        SmallHeaders ++
            [
                {<<"accept">>,
                    <<"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8">>},
                {<<"accept-encoding">>, <<"gzip, deflate, br">>},
                {<<"accept-language">>, <<"en-US,en;q=0.5">>},
                {<<"cache-control">>, <<"no-cache">>},
                {<<"connection">>, <<"keep-alive">>},
                {<<"user-agent">>, <<"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)">>},
                {<<"cookie">>, binary:copy(<<"session=abc123;">>, 10)},
                {<<"x-custom-header">>, binary:copy(<<"value">>, 50)}
            ],

    Iterations = 10000,

    %% Benchmark small header encoding
    Encoder = quic_qpack:new(#{max_dynamic_size => 4096}),
    {SmallEncodeTime, _} = timer:tc(fun() ->
        lists:foldl(
            fun(_, Enc) ->
                {_Encoded, Enc1} = quic_qpack:encode(SmallHeaders, 0, Enc),
                Enc1
            end,
            Encoder,
            lists:seq(1, Iterations)
        )
    end),

    %% Benchmark large header encoding
    {LargeEncodeTime, _} = timer:tc(fun() ->
        lists:foldl(
            fun(_, Enc) ->
                {_Encoded, Enc1} = quic_qpack:encode(LargeHeaders, 0, Enc),
                Enc1
            end,
            Encoder,
            lists:seq(1, Iterations)
        )
    end),

    %% Benchmark decoding
    {Encoded, _} = quic_qpack:encode(LargeHeaders, 0, Encoder),
    Decoder = quic_qpack:new(#{max_dynamic_size => 4096}),
    {DecodeTime, _} = timer:tc(fun() ->
        lists:foreach(
            fun(_) ->
                quic_qpack:decode(Encoded, Decoder)
            end,
            lists:seq(1, Iterations)
        )
    end),

    SmallEncodeUs = SmallEncodeTime / Iterations,
    LargeEncodeUs = LargeEncodeTime / Iterations,
    DecodeUs = DecodeTime / Iterations,

    io:format("  Small headers encode: ~.2f us/op~n", [SmallEncodeUs]),
    io:format("  Large headers encode: ~.2f us/op~n", [LargeEncodeUs]),
    io:format("  Large headers decode: ~.2f us/op~n", [DecodeUs]),

    #{
        status => ok,
        iterations => Iterations,
        small_encode_us => SmallEncodeUs,
        large_encode_us => LargeEncodeUs,
        decode_us => DecodeUs,
        small_headers_count => length(SmallHeaders),
        large_headers_count => length(LargeHeaders)
    }.

%%====================================================================
%% Internal Functions
%%====================================================================

start_h3_server(Port) ->
    case get_test_certs() of
        {ok, Cert, Key} ->
            ServerName = list_to_atom("h3_bench_" ++ integer_to_list(Port)),
            Handler = fun(Conn, StreamId, Method, Path, _Headers) ->
                handle_bench_request(Conn, StreamId, Method, Path)
            end,
            Opts = #{
                cert => Cert,
                key => Key,
                handler => Handler,
                verify => none
            },
            case quic_h3:start_server(ServerName, Port, Opts) of
                {ok, _Pid} ->
                    {ok, ActualPort} = quic:get_server_port(ServerName),
                    {ok, ServerName, ActualPort};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, {cert_error, Reason}}
    end.

handle_bench_request(Conn, StreamId, _Method, <<"/echo">>) ->
    %% Echo: collect body then send it back
    spawn(fun() -> echo_body(Conn, StreamId, <<>>) end);
handle_bench_request(Conn, StreamId, _Method, _Path) ->
    %% Simple OK response
    quic_h3:send_response(Conn, StreamId, 200, [{<<"content-type">>, <<"text/plain">>}]),
    quic_h3:send_data(Conn, StreamId, <<"OK">>, true).

echo_body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            echo_body(Conn, StreamId, <<Acc/binary, Data/binary>>);
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            Body = <<Acc/binary, Data/binary>>,
            quic_h3:send_response(Conn, StreamId, 200, [
                {<<"content-type">>, <<"application/octet-stream">>}
            ]),
            quic_h3:send_data(Conn, StreamId, Body, true);
        {quic_h3, Conn, {stream_closed, StreamId}} ->
            %% Stream closed without FIN, send what we have
            quic_h3:send_response(Conn, StreamId, 200, [
                {<<"content-type">>, <<"application/octet-stream">>}
            ]),
            quic_h3:send_data(Conn, StreamId, Acc, true)
    after 30000 ->
        ok
    end.

do_request(Conn, Path, Body) ->
    Headers = [
        {<<":method">>,
            case Body of
                <<>> -> <<"GET">>;
                _ -> <<"POST">>
            end},
        {<<":path">>, Path},
        {<<":scheme">>, <<"https">>},
        {<<":authority">>, <<"127.0.0.1">>}
    ],
    EndStream = Body =:= <<>>,
    case quic_h3:request(Conn, Headers, #{end_stream => EndStream}) of
        {ok, StreamId} ->
            %% Send body if present
            case Body of
                <<>> -> ok;
                _ -> quic_h3:send_data(Conn, StreamId, Body, true)
            end,
            %% Wait for response
            wait_response(Conn, StreamId, <<>>, 10000);
        {error, Reason} ->
            {error, Reason}
    end.

wait_response(Conn, StreamId, AccBody, Timeout) ->
    receive
        {quic_h3, Conn, {response, StreamId, Status, Headers}} ->
            wait_response_body(Conn, StreamId, Status, Headers, AccBody, Timeout);
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            wait_response(Conn, StreamId, <<AccBody/binary, Data/binary>>, Timeout);
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {ok, undefined, [], <<AccBody/binary, Data/binary>>};
        {quic_h3, Conn, {stream_closed, StreamId}} ->
            {ok, undefined, [], AccBody}
    after Timeout ->
        {error, timeout}
    end.

wait_response_body(Conn, StreamId, Status, Headers, AccBody, Timeout) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            wait_response_body(
                Conn, StreamId, Status, Headers, <<AccBody/binary, Data/binary>>, Timeout
            );
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            {ok, Status, Headers, <<AccBody/binary, Data/binary>>};
        {quic_h3, Conn, {stream_closed, StreamId}} ->
            {ok, Status, Headers, AccBody}
    after Timeout ->
        {ok, Status, Headers, AccBody}
    end.

wait_connected(Conn) ->
    wait_connected_timeout(Conn, 5000).

wait_connected_timeout(Conn, Timeout) ->
    receive
        {quic_h3, Conn, connected} -> ok;
        {quic_h3, Conn, {connected, _}} -> ok
    after Timeout ->
        {error, connect_timeout}
    end.

get_test_certs() ->
    PrivDir = code:priv_dir(quic),
    ProjectRoot = filename:dirname(
        filename:dirname(filename:dirname(filename:dirname(filename:dirname(PrivDir))))
    ),
    CertDir = filename:join(ProjectRoot, "certs"),
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "priv.key"),

    case {file:read_file(CertFile), file:read_file(KeyFile)} of
        {{ok, CertPem}, {ok, KeyPem}} ->
            [{_, CertDer, _}] = public_key:pem_decode(CertPem),
            [KeyEntry] = public_key:pem_decode(KeyPem),
            KeyTerm = public_key:pem_entry_decode(KeyEntry),
            {ok, CertDer, KeyTerm};
        {{error, Reason}, _} ->
            {error, {cert_read, Reason}};
        {_, {error, Reason}} ->
            {error, {key_read, Reason}}
    end.

calculate_stats(Values) ->
    Sorted = lists:sort(Values),
    Len = length(Sorted),
    Sum = lists:sum(Sorted),
    #{
        min => hd(Sorted),
        max => lists:last(Sorted),
        avg => Sum / Len,
        p50 => lists:nth(max(1, Len div 2), Sorted),
        p90 => lists:nth(max(1, round(Len * 0.9)), Sorted),
        p99 => lists:nth(max(1, round(Len * 0.99)), Sorted)
    }.

run_bench(Name, Fun) ->
    io:format("~n--- ~s ---~n", [Name]),
    try
        Result = Fun(),
        {Name, Result}
    catch
        Class:Reason:Stack ->
            io:format("  ERROR: ~p:~p~n  ~p~n", [Class, Reason, Stack]),
            {Name, #{status => error, reason => {Class, Reason}}}
    end.

print_summary(Results) ->
    io:format("~n========================================~n"),
    io:format("              Summary~n"),
    io:format("========================================~n"),
    lists:foreach(
        fun({Name, Result}) ->
            Status = maps:get(status, Result, unknown),
            StatusStr =
                case Status of
                    ok -> "OK";
                    error -> "FAILED";
                    _ -> io_lib:format("~p", [Status])
                end,
            io:format("  ~-20s: ~s~n", [Name, StatusStr])
        end,
        Results
    ),
    io:format("~n").
