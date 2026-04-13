#!/usr/bin/env escript
%%! -pa /app/lib/quic/ebin -pa /app/lib/quic/test

%% Distribution Benchmark Script
%% Run on node2 after cluster is formed

-mode(compile).

main([TargetNodeStr]) ->
    TargetNode = list_to_atom(TargetNodeStr),
    run_benchmark(TargetNode);
main(_) ->
    io:format("Usage: benchmark.escript <target_node>~n"),
    halt(1).

run_benchmark(TargetNode) ->
    io:format("~n=== QUIC Distribution Benchmark ===~n"),
    io:format("Target: ~p~n", [TargetNode]),
    io:format("Protocol: QUIC (quic_dist)~n~n"),

    %% Verify connection
    case net_adm:ping(TargetNode) of
        pong -> ok;
        pang ->
            io:format("ERROR: Cannot connect to ~p~n", [TargetNode]),
            halt(1)
    end,

    %% Spawn echo server on target
    ServerPid = spawn(TargetNode, fun server_loop/0),

    Sizes = [64, 256, 1024, 4096, 16384, 65536],
    Iterations = 5000,
    Warmup = 100,

    io:format("Sizes: ~s~n", [format_sizes(Sizes)]),
    io:format("Iterations: ~p (warmup: ~p)~n~n", [Iterations, Warmup]),

    Results = lists:map(
        fun(Size) ->
            io:format("Testing ~s messages...~n", [format_size(Size)]),

            %% Warmup
            run_iterations(ServerPid, Size, Warmup),

            %% Benchmark
            {Throughput, AvgLatency, P99Latency} =
                benchmark_size(ServerPid, Size, Iterations),

            io:format("  Throughput: ~.0f msg/s, ~.2f MB/s~n",
                [Throughput, Throughput * Size / 1048576]),
            io:format("  Latency: avg=~.1f us, p99=~p us~n~n",
                [AvgLatency, P99Latency]),

            {Size, Throughput, AvgLatency, P99Latency}
        end,
        Sizes
    ),

    ServerPid ! stop,

    print_summary(Results),
    halt(0).

server_loop() ->
    receive
        {echo, From, Ref, Data} ->
            From ! {echo_reply, Ref, Data},
            server_loop();
        stop ->
            ok
    end.

benchmark_size(ServerPid, Size, Iterations) ->
    Data = crypto:strong_rand_bytes(Size),

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
    io:format("~-10s ~-14s ~-14s ~-12s ~-10s~n",
        ["Size", "Throughput", "Bandwidth", "Avg Lat", "P99 Lat"]),
    io:format("~s~n", [lists:duplicate(60, $-)]),

    lists:foreach(
        fun({Size, Throughput, AvgLatency, P99Latency}) ->
            Bandwidth = Throughput * Size / 1048576,
            SizeStr = lists:flatten(format_size(Size)),
            ThroughputStr = integer_to_list(round(Throughput)) ++ "/s",
            BandwidthStr = lists:flatten(io_lib:format("~.2f MB/s", [Bandwidth])),
            LatAvgStr = lists:flatten(io_lib:format("~.1f us", [AvgLatency])),
            LatP99Str = integer_to_list(P99Latency) ++ " us",
            io:format("~-10s ~-14s ~-14s ~-12s ~-10s~n",
                [SizeStr, ThroughputStr, BandwidthStr, LatAvgStr, LatP99Str])
        end,
        Results
    ),
    io:format("~n").
