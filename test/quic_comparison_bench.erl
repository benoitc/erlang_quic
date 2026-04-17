%%% -*- erlang -*-
%%%
%%% QUIC Comparison Benchmark Module
%%%
%%% Compares throughput across erlang_quic, quiche, and quic-go with
%%% web-typical transfer sizes in both directions.
%%%
%%% Two methodologies are exposed:
%%%
%%%   run/0,1 - Per-connection: each iteration opens a fresh connection,
%%%             so small-size results are dominated by handshake cost.
%%%
%%%   run_persistent/0,1 - Persistent-connection: one connection per
%%%             (implementation, direction, size) test, reused across
%%%             iterations via separate streams. Excludes handshake cost
%%%             from the measured duration and amortises setup over N
%%%             iterations, giving a cleaner steady-state transport
%%%             throughput number.
%%%
%%% Usage:
%%%   quic_comparison_bench:run().
%%%   quic_comparison_bench:run_persistent().
%%%   quic_comparison_bench:run_persistent(#{sizes => [1024, 10240]}).
%%%   quic_comparison_bench:run_persistent(#{iterations => 20}).
%%%
%%% Prerequisites:
%%%   docker compose -f docker/docker-compose.bench.yml up -d

-module(quic_comparison_bench).

-export([
    run/0,
    run/1,
    run_persistent/0,
    run_persistent/1
]).

-include("quic.hrl").

%% Default configuration
-define(DEFAULT_SIZES, [1024, 10240, 102400, 1048576]).
-define(DEFAULT_ITERATIONS, 5).
-define(DEFAULT_ERLANG_PORT, 14436).
-define(QUICHE_HOST, "127.0.0.1").
-define(QUICHE_PORT, 4435).
-define(QUIC_GO_HOST, "127.0.0.1").
-define(QUIC_GO_PORT, 4434).

%%====================================================================
%% Public API
%%====================================================================

%% @doc Run comparison benchmark with default settings
-spec run() -> ok.
run() ->
    run(#{}).

%% @doc Run comparison benchmark with custom options
%% Options:
%%   - sizes: List of byte sizes to test (default: [1KB, 10KB, 100KB, 1MB])
%%   - iterations: Number of iterations per test (default: 5)
%%   - directions: [upload, download] (default: both)
-spec run(map()) -> ok.
run(Opts) ->
    %% Ensure application is started
    application:ensure_all_started(quic),

    Sizes = maps:get(sizes, Opts, ?DEFAULT_SIZES),
    Iterations = maps:get(iterations, Opts, ?DEFAULT_ITERATIONS),
    Directions = maps:get(directions, Opts, [upload, download]),

    io:format("~n=== QUIC Throughput Comparison ===~n"),
    io:format("Sizes: ~s~n", [string:join([format_size(S) || S <- Sizes], ", ")]),
    io:format("Iterations: ~p~n", [Iterations]),
    io:format("~n"),

    %% Start local erlang server
    {ok, ErlangServer} = start_erlang_server(?DEFAULT_ERLANG_PORT),

    %% Run benchmarks
    Results = run_all_benchmarks(Sizes, Iterations, Directions),

    %% Stop local server
    stop_erlang_server(ErlangServer),

    %% Print results
    print_results(Results, Sizes, Directions),

    ok.

%% @doc Run persistent-connection throughput benchmark with defaults.
-spec run_persistent() -> ok.
run_persistent() ->
    run_persistent(#{}).

%% @doc Run persistent-connection throughput benchmark with custom options.
%% One connection is opened per (implementation, direction, size) and reused
%% across Iterations via separate streams. A warm-up iteration is performed
%% before timing to avoid cold-start (slow-start) effects. Total bytes over
%% the timed window are divided by its duration to report MB/s.
-spec run_persistent(map()) -> ok.
run_persistent(Opts) ->
    application:ensure_all_started(quic),

    Sizes = maps:get(sizes, Opts, ?DEFAULT_SIZES),
    Iterations = maps:get(iterations, Opts, ?DEFAULT_ITERATIONS),
    Directions = maps:get(directions, Opts, [upload, download]),

    io:format("~n=== QUIC Persistent-Connection Throughput ===~n"),
    io:format("Sizes: ~s~n", [string:join([format_size(S) || S <- Sizes], ", ")]),
    io:format("Iterations: ~p (streams reused on one connection)~n", [Iterations]),
    io:format("~n"),

    {ok, ErlangServer} = start_erlang_server(?DEFAULT_ERLANG_PORT),

    Results = run_all_persistent(Sizes, Iterations, Directions),

    stop_erlang_server(ErlangServer),

    print_results(Results, Sizes, Directions),

    ok.

%%====================================================================
%% Internal Functions
%%====================================================================

run_all_benchmarks(Sizes, Iterations, Directions) ->
    Implementations = [
        {erlang, "127.0.0.1", ?DEFAULT_ERLANG_PORT},
        {quiche, ?QUICHE_HOST, ?QUICHE_PORT},
        {quic_go, ?QUIC_GO_HOST, ?QUIC_GO_PORT}
    ],

    lists:foldl(
        fun({Name, Host, Port}, Acc) ->
            io:format("Testing ~p (~s:~p)...~n", [Name, Host, Port]),
            ImplResults = run_impl_benchmarks(Name, Host, Port, Sizes, Iterations, Directions),
            maps:put(Name, ImplResults, Acc)
        end,
        #{},
        Implementations
    ).

run_impl_benchmarks(_Name, Host, Port, Sizes, Iterations, Directions) ->
    lists:foldl(
        fun(Direction, Acc) ->
            DirResults = lists:foldl(
                fun(Size, DAcc) ->
                    io:format("  ~s ~s... ", [Direction, format_size(Size)]),
                    case run_single_benchmark(Host, Port, Size, Direction, Iterations) of
                        {ok, MBps} ->
                            io:format("~.2f MB/s~n", [MBps]),
                            maps:put(Size, MBps, DAcc);
                        {error, Reason} ->
                            io:format("ERROR: ~p~n", [Reason]),
                            maps:put(Size, error, DAcc)
                    end
                end,
                #{},
                Sizes
            ),
            maps:put(Direction, DirResults, Acc)
        end,
        #{},
        Directions
    ).

run_single_benchmark(Host, Port, Size, Direction, Iterations) ->
    %% Large flow control windows for benchmarking (16MB)
    FlowWindow = 16777216,
    ClientOpts = #{
        alpn => [<<"bench">>],
        recbuf => 7340032,
        sndbuf => 7340032,
        max_data => FlowWindow,
        max_stream_data_bidi_local => FlowWindow,
        max_stream_data_bidi_remote => FlowWindow,
        max_stream_data_uni => FlowWindow
    },

    Results = lists:filtermap(
        fun(_) ->
            case run_single_iteration(Host, Port, ClientOpts, Size, Direction) of
                {ok, MBps} -> {true, MBps};
                {error, _} -> false
            end
        end,
        lists:seq(1, Iterations)
    ),

    case Results of
        [] ->
            {error, all_failed};
        _ ->
            %% Return average, excluding outliers
            Sorted = lists:sort(Results),
            %% Remove top and bottom if we have enough samples
            Trimmed =
                if
                    length(Sorted) >= 5 ->
                        lists:sublist(tl(Sorted), length(Sorted) - 2);
                    true ->
                        Sorted
                end,
            Avg = lists:sum(Trimmed) / length(Trimmed),
            {ok, Avg}
    end.

run_single_iteration(Host, Port, ClientOpts, Size, Direction) ->
    case quic:connect(Host, Port, ClientOpts, self()) of
        {ok, Conn} ->
            Result =
                try
                    receive
                        {quic, Conn, {connected, _Info}} -> ok
                    after 5000 ->
                        throw({error, connect_timeout})
                    end,

                    {ok, StreamId} = quic:open_stream(Conn),

                    case Direction of
                        upload -> run_upload(Conn, StreamId, Size);
                        download -> run_download(Conn, StreamId, Size)
                    end
                catch
                    throw:Err -> Err
                after
                    quic:close(Conn)
                end,
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

run_all_persistent(Sizes, Iterations, Directions) ->
    Implementations = [
        {erlang, "127.0.0.1", ?DEFAULT_ERLANG_PORT},
        {quiche, ?QUICHE_HOST, ?QUICHE_PORT},
        {quic_go, ?QUIC_GO_HOST, ?QUIC_GO_PORT}
    ],

    lists:foldl(
        fun({Name, Host, Port}, Acc) ->
            io:format("Testing ~p (~s:~p)...~n", [Name, Host, Port]),
            ImplResults = run_impl_persistent(Host, Port, Sizes, Iterations, Directions),
            maps:put(Name, ImplResults, Acc)
        end,
        #{},
        Implementations
    ).

run_impl_persistent(Host, Port, Sizes, Iterations, Directions) ->
    lists:foldl(
        fun(Direction, Acc) ->
            DirResults = lists:foldl(
                fun(Size, DAcc) ->
                    io:format("  ~s ~s... ", [Direction, format_size(Size)]),
                    case run_persistent_benchmark(Host, Port, Size, Direction, Iterations) of
                        {ok, MBps} ->
                            io:format("~.2f MB/s~n", [MBps]),
                            maps:put(Size, MBps, DAcc);
                        {error, Reason} ->
                            io:format("ERROR: ~p~n", [Reason]),
                            maps:put(Size, error, DAcc)
                    end
                end,
                #{},
                Sizes
            ),
            maps:put(Direction, DirResults, Acc)
        end,
        #{},
        Directions
    ).

run_persistent_benchmark(Host, Port, Size, Direction, Iterations) ->
    FlowWindow = 16777216,
    ClientOpts = #{
        alpn => [<<"bench">>],
        recbuf => 7340032,
        sndbuf => 7340032,
        max_data => FlowWindow,
        max_stream_data_bidi_local => FlowWindow,
        max_stream_data_bidi_remote => FlowWindow,
        max_stream_data_uni => FlowWindow
    },

    case quic:connect(Host, Port, ClientOpts, self()) of
        {ok, Conn} ->
            Result =
                try
                    receive
                        {quic, Conn, {connected, _Info}} -> ok
                    after 5000 ->
                        throw({error, connect_timeout})
                    end,

                    %% Pre-generate the upload payload ONCE, outside
                    %% the timed window. crypto:strong_rand_bytes/1
                    %% used to run per-iteration inside the timing
                    %% loop; a constant fill is sufficient for
                    %% throughput measurement and keeps the window
                    %% transport-only.
                    UploadPayload =
                        case Direction of
                            upload -> binary:copy(<<16#42>>, Size);
                            download -> undefined
                        end,

                    %% Warm-up iteration (not timed) to avoid slow-start
                    %% effects on the first stream of the connection.
                    case transfer_once(Conn, Size, Direction, UploadPayload) of
                        ok -> ok;
                        {error, WErr} -> throw({error, {warmup, WErr}})
                    end,

                    Start = erlang:monotonic_time(microsecond),
                    lists:foreach(
                        fun(_) ->
                            case transfer_once(Conn, Size, Direction, UploadPayload) of
                                ok -> ok;
                                {error, Err} -> throw({error, Err})
                            end
                        end,
                        lists:seq(1, Iterations)
                    ),
                    End = erlang:monotonic_time(microsecond),
                    Duration = max(1, End - Start),
                    Total = Size * Iterations,
                    MBps = (Total / 1048576) / (Duration / 1000000),
                    {ok, MBps}
                catch
                    throw:Err -> Err
                after
                    quic:close(Conn)
                end,
            Result;
        {error, Reason} ->
            {error, {connect_failed, Reason}}
    end.

transfer_once(Conn, _Size, upload, Payload) when is_binary(Payload) ->
    {ok, StreamId} = quic:open_stream(Conn),
    ok = quic:send_data(Conn, StreamId, Payload, true),
    wait_for_completion(Conn, StreamId, 30000);
transfer_once(Conn, Size, download, _Payload) ->
    {ok, StreamId} = quic:open_stream(Conn),
    SizeReq = <<Size:64/big-unsigned-integer>>,
    ok = quic:send_data(Conn, StreamId, SizeReq, true),
    Timeout = max(60000, Size div 1000),
    case wait_for_data(Conn, StreamId, Size, Timeout) of
        {ok, _} -> ok;
        Err -> Err
    end.

run_upload(Conn, StreamId, Size) ->
    Data = crypto:strong_rand_bytes(Size),
    Start = erlang:monotonic_time(microsecond),
    ok = quic:send_data(Conn, StreamId, Data, true),

    %% Wait for server acknowledgment (FIN or stream close)
    case wait_for_completion(Conn, StreamId, 30000) of
        ok ->
            End = erlang:monotonic_time(microsecond),
            Duration = max(1, End - Start),
            MBps = (Size / 1048576) / (Duration / 1000000),
            {ok, MBps};
        {error, Reason} ->
            {error, Reason}
    end.

run_download(Conn, StreamId, Size) ->
    %% Send 8-byte size request
    SizeReq = <<Size:64/big-unsigned-integer>>,
    Start = erlang:monotonic_time(microsecond),
    ok = quic:send_data(Conn, StreamId, SizeReq, true),

    %% Wait to receive all data (60s timeout for larger transfers)
    Timeout = max(60000, Size div 1000),
    case wait_for_data(Conn, StreamId, Size, Timeout) of
        {ok, _BytesRecv} ->
            End = erlang:monotonic_time(microsecond),
            Duration = max(1, End - Start),
            MBps = (Size / 1048576) / (Duration / 1000000),
            {ok, MBps};
        {error, Reason} ->
            {error, Reason}
    end.

wait_for_completion(Conn, StreamId, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, _Data, true}} ->
            ok;
        {quic, Conn, {stream_closed, StreamId}} ->
            ok;
        {quic, Conn, {stream_data, StreamId, _Data, false}} ->
            wait_for_completion(Conn, StreamId, Timeout);
        {quic, Conn, {closed, _Reason}} ->
            ok
    after Timeout ->
        {error, timeout}
    end.

wait_for_data(Conn, StreamId, _ExpectedSize, Timeout) ->
    wait_for_data_loop(Conn, StreamId, 0, Timeout).

wait_for_data_loop(Conn, StreamId, BytesRecv, Timeout) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            {ok, BytesRecv + byte_size(Data)};
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            wait_for_data_loop(Conn, StreamId, BytesRecv + byte_size(Data), Timeout);
        {quic, Conn, {stream_closed, StreamId}} ->
            {ok, BytesRecv};
        {quic, Conn, {closed, _Reason}} ->
            {ok, BytesRecv}
    after Timeout ->
        {error, timeout}
    end.

start_erlang_server(Port) ->
    case get_test_certs() of
        {ok, Cert, Key} ->
            ServerName = list_to_atom("bench_server_" ++ integer_to_list(Port)),
            FlowWindow = 16777216,
            Handler = fun(Conn) ->
                Pid = spawn(fun() -> bench_handler(Conn) end),
                {ok, Pid}
            end,
            ServerOpts = #{
                cert => Cert,
                key => Key,
                alpn => [<<"bench">>],
                recbuf => 7340032,
                sndbuf => 7340032,
                max_data => FlowWindow,
                max_stream_data_bidi_local => FlowWindow,
                max_stream_data_bidi_remote => FlowWindow,
                max_stream_data_uni => FlowWindow,
                connection_handler => Handler
            },
            case quic:start_server(ServerName, Port, ServerOpts) of
                {ok, Pid} ->
                    {ok, {ServerName, Pid}};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, {cert_error, Reason}}
    end.

stop_erlang_server({ServerName, _Pid}) ->
    quic:stop_server(ServerName).

%% Benchmark handler that supports both upload (sink) and download modes
bench_handler(Conn) ->
    bench_handler_loop(Conn, #{}).

bench_handler_loop(Conn, Streams) ->
    receive
        {quic, Conn, {connected, _Info}} ->
            bench_handler_loop(Conn, Streams);
        {quic, Conn, {stream_opened, StreamId}} ->
            bench_handler_loop(
                Conn, maps:put(StreamId, #{bytes => 0, mode => undefined, buffer => <<>>}, Streams)
            );
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            StreamState = maps:get(StreamId, Streams, #{
                bytes => 0, mode => undefined, buffer => <<>>
            }),
            NewState = handle_stream_data(Conn, StreamId, Data, Fin, StreamState),
            bench_handler_loop(Conn, maps:put(StreamId, NewState, Streams));
        {quic, Conn, {closed, _Reason}} ->
            ok;
        _Other ->
            bench_handler_loop(Conn, Streams)
    end.

handle_stream_data(
    Conn, StreamId, Data, Fin, #{bytes := Bytes, mode := Mode, buffer := Buffer} = State
) ->
    DataSize = byte_size(Data),
    NewBytes = Bytes + DataSize,
    NewBuffer = <<Buffer/binary, Data/binary>>,

    case Mode of
        undefined ->
            %% Check if we have a complete download request (8 bytes + FIN)
            case {byte_size(NewBuffer), Fin} of
                {8, true} ->
                    %% Download request: 8-byte size with FIN
                    <<Size:64/big-unsigned-integer>> = NewBuffer,
                    %% Send all data at once - let connection handle flow control
                    DownloadData = binary:copy(<<16#42>>, Size),
                    quic:send_data(Conn, StreamId, DownloadData, true),
                    State#{mode => download, bytes => 0, buffer => <<>>};
                {N, true} when N > 8 ->
                    %% Upload mode (too much data for download request)
                    quic:send_data(Conn, StreamId, <<>>, true),
                    State#{mode => upload, bytes => NewBytes, buffer => <<>>};
                {_, true} ->
                    %% Upload with small data
                    quic:send_data(Conn, StreamId, <<>>, true),
                    State#{mode => upload, bytes => NewBytes, buffer => <<>>};
                {N, false} when N > 8 ->
                    %% Upload mode (more than 8 bytes without FIN)
                    State#{mode => upload, bytes => NewBytes, buffer => <<>>};
                {_, false} ->
                    %% Wait for more data to determine mode
                    State#{bytes => NewBytes, buffer => NewBuffer}
            end;
        upload ->
            if
                Fin ->
                    quic:send_data(Conn, StreamId, <<>>, true),
                    State#{bytes => NewBytes, buffer => <<>>};
                true ->
                    State#{bytes => NewBytes}
            end;
        download ->
            State
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

format_size(Size) when Size >= 1048576 ->
    lists:flatten(io_lib:format("~pMB", [Size div 1048576]));
format_size(Size) when Size >= 1024 ->
    lists:flatten(io_lib:format("~pKB", [Size div 1024]));
format_size(Size) ->
    lists:flatten(io_lib:format("~pB", [Size])).

print_results(Results, Sizes, Directions) ->
    io:format("~n"),
    lists:foreach(
        fun(Direction) ->
            DirStr =
                case Direction of
                    upload -> "Upload (Client -> Server)";
                    download -> "Download (Server -> Client)"
                end,
            io:format("~s MB/s:~n", [DirStr]),
            print_table(Results, Sizes, Direction)
        end,
        Directions
    ).

print_table(Results, Sizes, Direction) ->
    %% Header
    io:format(
        "| ~-8s | ~-8s | ~-8s | ~-8s |~n",
        ["Size", "erlang", "quiche", "quic-go"]
    ),
    io:format(
        "|~s|~s|~s|~s|~n",
        [
            lists:duplicate(10, $-),
            lists:duplicate(10, $-),
            lists:duplicate(10, $-),
            lists:duplicate(10, $-)
        ]
    ),

    %% Data rows
    lists:foreach(
        fun(Size) ->
            ErlangVal = get_result(Results, erlang, Direction, Size),
            QuicheVal = get_result(Results, quiche, Direction, Size),
            QuicGoVal = get_result(Results, quic_go, Direction, Size),
            io:format(
                "| ~-8s | ~8s | ~8s | ~8s |~n",
                [
                    format_size(Size),
                    format_value(ErlangVal),
                    format_value(QuicheVal),
                    format_value(QuicGoVal)
                ]
            )
        end,
        Sizes
    ),
    io:format("~n").

get_result(Results, Impl, Direction, Size) ->
    case maps:get(Impl, Results, #{}) of
        #{Direction := DirResults} ->
            maps:get(Size, DirResults, error);
        _ ->
            error
    end.

format_value(error) -> "ERR";
format_value(Val) when is_number(Val) -> io_lib:format("~.2f", [Val]).
