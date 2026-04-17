#!/usr/bin/env escript
%%! -pa _build/default/lib/quic/ebin -pa _build/test/lib/quic/test
%% Server-to-client download benchmark driver.

main(_) ->
    application:ensure_all_started(quic),
    Sizes = [
        {1 * 1024 * 1024, "1 MB"},
        {5 * 1024 * 1024, "5 MB"},
        {10 * 1024 * 1024, "10 MB"}
    ],
    lists:foreach(
        fun({Size, Label}) ->
            R = quic_throughput_bench:run_download_sink(#{data_size => Size}),
            io:format("==> ~s : ~.2f MB/s flushes=~p coalesced=~p ratio=~.2f~n", [
                Label,
                maps:get(mb_per_sec, R, 0.0),
                maps:get(batch_flushes, R, 0),
                maps:get(packets_coalesced, R, 0),
                float(maps:get(coalesce_ratio, R, 0.0))
            ]),
            timer:sleep(1000)
        end,
        Sizes
    ),
    halt(0).
