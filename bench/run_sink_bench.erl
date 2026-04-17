#!/usr/bin/env escript
%%! -pa _build/default/lib/quic/ebin -pa _build/test/lib/quic/test
%% Sink-upload benchmark driver: 1 MB, 5 MB, 10 MB, 3 runs each, report mean MB/s.

main(_) ->
    application:ensure_all_started(quic),
    Sizes = [
        {1 * 1024 * 1024, "1 MB"},
        {5 * 1024 * 1024, "5 MB"},
        {10 * 1024 * 1024, "10 MB"}
    ],
    lists:foreach(fun({Size, Label}) -> run_size(Size, Label) end, Sizes),
    halt(0).

run_size(Size, Label) ->
    Results = [run_once(Size) || _ <- lists:seq(1, 3)],
    Mean = lists:sum(Results) / length(Results),
    Formatted = [io_lib:format("~.2f", [X]) || X <- Results],
    io:format("~n==> ~s mean: ~.2f MB/s  (runs: ~s)~n~n",
        [Label, Mean, string:join([lists:flatten(F) || F <- Formatted], ", ")]).

run_once(Size) ->
    R = quic_throughput_bench:run_sink(#{data_size => Size}),
    timer:sleep(500),
    maps:get(mb_per_sec, R, 0.0).
