#!/usr/bin/env escript
%%! -pa _build/default/lib/quic/ebin -pa _build/test/lib/quic/test
%% Sink-upload benchmark driver.
%%
%%   ./bench/run_sink_bench.erl [SizeMB] [Runs]
%%
%% Discards a warmup run, then reports the median of Runs timed runs with
%% the spread, because a single number off a loaded machine is not a
%% measurement. Runs that fail delivery verification are reported as
%% failures and excluded rather than folded in as 0 MB/s.

main(Args) ->
    application:ensure_all_started(quic),
    {SizeMB, Runs} = parse(Args),
    Size = SizeMB * 1024 * 1024,
    io:format("~nSink upload: ~p MB x ~p runs (plus 1 warmup)~n", [SizeMB, Runs]),
    _ = one(Size),
    Results = [one(Size) || _ <- lists:seq(1, Runs)],
    report(SizeMB, Results),
    halt(0).

parse([]) -> {10, 5};
parse([S]) -> {list_to_integer(S), 5};
parse([S, R]) -> {list_to_integer(S), list_to_integer(R)}.

one(Size) ->
    R = quic_throughput_bench:run_sink(#{data_size => Size}),
    timer:sleep(500),
    case maps:get(status, R, undefined) of
        ok -> {ok, maps:get(mb_per_sec, R), maps:get(client_stats, R, #{})};
        Other -> {failed, Other}
    end.

report(SizeMB, Results) ->
    Ok = [{V, S} || {ok, V, S} <- Results],
    Failed = [W || {failed, W} <- Results],
    case Ok of
        [] ->
            io:format("~nAll runs failed: ~p~n", [Failed]);
        _ ->
            Rates = lists:sort([V || {V, _} <- Ok]),
            io:format(
                "~n==> ~p MB  median ~.2f MB/s  (min ~.2f, max ~.2f, n=~p)~n",
                [SizeMB, median(Rates), hd(Rates), lists:last(Rates), length(Rates)]
            ),
            {_, Stats} = hd(Ok),
            case maps:get(packets_sent, Stats, undefined) of
                undefined ->
                    ok;
                Packets ->
                    io:format(
                        "    packets_sent=~p retransmits=~p~n",
                        [Packets, maps:get(retransmits, Stats, 0)]
                    )
            end
    end,
    case Failed of
        [] -> ok;
        _ -> io:format("    ~p run(s) FAILED: ~p~n", [length(Failed), Failed])
    end.

median(Sorted) ->
    N = length(Sorted),
    case N rem 2 of
        1 -> lists:nth((N div 2) + 1, Sorted);
        0 -> (lists:nth(N div 2, Sorted) + lists:nth((N div 2) + 1, Sorted)) / 2
    end.
