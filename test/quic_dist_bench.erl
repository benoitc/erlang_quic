%%% -*- erlang -*-
%%%
%%% Distribution Benchmark: QUIC vs TCP
%%%
%%% Compares message throughput and latency between quic_dist and inet_dist.
%%%
%%% Usage (run on a single machine with two nodes):
%%%   1. Start server node:
%%%      erl -sname bench_server -setcookie bench
%%%   2. Start client and run benchmark:
%%%      erl -sname bench_client -setcookie bench
%%%      > quic_dist_bench:run('bench_server@hostname').
%%%
%%% For QUIC distribution, start nodes with:
%%%   erl -sname bench_server -proto_dist quic -epmd_module quic_epmd ...

-module(quic_dist_bench).

-export([
    run/1,
    run/2,
    server_loop/0
]).

-define(DEFAULT_MSG_SIZES, [64, 256, 1024, 4096, 16384, 65536]).
-define(DEFAULT_ITERATIONS, 1000).
-define(DEFAULT_WARMUP, 100).

%% @doc Run benchmark with default settings
-spec run(node()) -> ok.
run(ServerNode) ->
    run(ServerNode, #{}).

%% @doc Run benchmark with options
%% Options:
%%   - sizes: List of message sizes in bytes (default: [64, 256, 1K, 4K, 16K, 64K])
%%   - iterations: Messages per size (default: 1000)
%%   - warmup: Warmup iterations (default: 100)
-spec run(node(), map()) -> ok.
run(ServerNode, Opts) ->
    Sizes = maps:get(sizes, Opts, ?DEFAULT_MSG_SIZES),
    Iterations = maps:get(iterations, Opts, ?DEFAULT_ITERATIONS),
    Warmup = maps:get(warmup, Opts, ?DEFAULT_WARMUP),

    io:format("~n=== Erlang Distribution Benchmark ===~n"),
    io:format("Server: ~p~n", [ServerNode]),
    io:format("Protocol: ~s~n", [detect_protocol()]),
    io:format("Sizes: ~s~n", [format_sizes(Sizes)]),
    io:format("Iterations: ~p (warmup: ~p)~n~n", [Iterations, Warmup]),

    %% Connect to server
    case net_adm:ping(ServerNode) of
        pong ->
            io:format("Connected to ~p~n~n", [ServerNode]);
        pang ->
            io:format("ERROR: Cannot connect to ~p~n", [ServerNode]),
            io:format("Make sure the server is running with:~n"),
            io:format("  quic_dist_bench:server_loop().~n"),
            error(connection_failed)
    end,

    %% Spawn server process
    ServerPid = spawn(ServerNode, ?MODULE, server_loop, []),

    %% Run benchmarks
    Results = lists:map(
        fun(Size) ->
            io:format("Testing ~s messages...~n", [format_size(Size)]),

            %% Warmup
            run_iterations(ServerPid, Size, Warmup),

            %% Benchmark
            {Throughput, AvgLatency, P99Latency} =
                benchmark_size(ServerPid, Size, Iterations),

            io:format(
                "  Throughput: ~.2f msg/s, ~.2f MB/s~n",
                [Throughput, Throughput * Size / 1048576]
            ),
            io:format(
                "  Latency: avg=~.1f us, p99=~p us~n~n",
                [AvgLatency, P99Latency]
            ),

            {Size, Throughput, AvgLatency, P99Latency}
        end,
        Sizes
    ),

    %% Stop server
    ServerPid ! stop,

    %% Print summary table
    print_summary(Results),
    ok.

%% @doc Server loop - echoes messages back
server_loop() ->
    receive
        {echo, From, Ref, Data} ->
            From ! {echo_reply, Ref, Data},
            server_loop();
        stop ->
            ok
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

benchmark_size(ServerPid, Size, Iterations) ->
    Data = crypto:strong_rand_bytes(Size),

    %% Measure individual latencies
    Latencies = lists:map(
        fun(_) ->
            Ref = make_ref(),
            Start = erlang:monotonic_time(microsecond),
            ServerPid ! {echo, self(), Ref, Data},
            receive
                {echo_reply, Ref, _} ->
                    erlang:monotonic_time(microsecond) - Start
            after 5000 ->
                error(timeout)
            end
        end,
        lists:seq(1, Iterations)
    ),

    %% Calculate stats
    TotalTime = lists:sum(Latencies),
    Throughput = Iterations / (TotalTime / 1000000),
    AvgLatency = TotalTime / Iterations,

    Sorted = lists:sort(Latencies),
    P99Index = max(1, round(Iterations * 0.99)),
    P99Latency = lists:nth(P99Index, Sorted),

    {Throughput, AvgLatency, P99Latency}.

run_iterations(ServerPid, Size, Count) ->
    Data = crypto:strong_rand_bytes(Size),
    lists:foreach(
        fun(_) ->
            Ref = make_ref(),
            ServerPid ! {echo, self(), Ref, Data},
            receive
                {echo_reply, Ref, _} -> ok
            after 5000 ->
                error(timeout)
            end
        end,
        lists:seq(1, Count)
    ).

detect_protocol() ->
    case init:get_argument(proto_dist) of
        {ok, [["quic"]]} -> "QUIC (quic_dist)";
        {ok, [["inet_tls"]]} -> "TLS (inet_tls_dist)";
        _ -> "TCP (inet_dist)"
    end.

format_size(Size) when Size >= 1048576 ->
    io_lib:format("~pMB", [Size div 1048576]);
format_size(Size) when Size >= 1024 ->
    io_lib:format("~pKB", [Size div 1024]);
format_size(Size) ->
    io_lib:format("~pB", [Size]).

format_sizes(Sizes) ->
    string:join([lists:flatten(format_size(S)) || S <- Sizes], ", ").

print_summary(Results) ->
    io:format("~n=== Summary ===~n"),
    io:format(
        "~-10s ~-14s ~-14s ~-12s ~-10s~n",
        ["Size", "Throughput", "Bandwidth", "Avg Lat", "P99 Lat"]
    ),
    io:format("~s~n", [lists:duplicate(60, $-)]),

    lists:foreach(
        fun({Size, Throughput, AvgLatency, P99Latency}) ->
            Bandwidth = Throughput * Size / 1048576,
            SizeStr = lists:flatten(format_size(Size)),
            ThroughputStr = integer_to_list(round(Throughput)) ++ "/s",
            BandwidthStr = lists:flatten(io_lib:format("~.2f MB/s", [Bandwidth])),
            LatAvgStr = lists:flatten(io_lib:format("~.1f us", [AvgLatency])),
            LatP99Str = integer_to_list(P99Latency) ++ " us",
            io:format(
                "~-10s ~-14s ~-14s ~-12s ~-10s~n",
                [SizeStr, ThroughputStr, BandwidthStr, LatAvgStr, LatP99Str]
            )
        end,
        Results
    ),
    io:format("~n").
