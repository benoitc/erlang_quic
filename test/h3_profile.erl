%%% -*- erlang -*-
%%%
%%% Test-only HTTP/3 profiling harness (not part of the shipped app).
%%%
%%% Drives a sequential GET request/response loop against the in-process
%%% H3 test server over one persistent connection, and measures it three
%%% ways so a per-call-instrumentation artifact (fprof) can be told apart
%%% from a real CPU cost (wall-clock / eprof):
%%%
%%%   - timer:tc wall-clock for the whole loop (ground truth),
%%%   - eprof flat per-function time,
%%%   - fprof call graph + own-time + call counts (the lens the original
%%%     header-validation report used).
%%%
%%% Usage:
%%%   rebar3 as test shell
%%%   h3_profile:run().            %% default 2000 wall/eprof iters
%%%   h3_profile:run(5000).
%%%
%%% Writes /tmp/h3_eprof.txt and /tmp/h3_fprof_analysis.txt.

-module(h3_profile).

-export([run/0, run/1]).

-define(HOST, <<"127.0.0.1">>).

run() -> run(2000).

run(N) ->
    {ok, _} = application:ensure_all_started(quic),
    {ok, Server} = quic_test_h3_server:start(),
    Port = maps:get(port, Server),
    {ok, Conn} = quic_h3:connect(?HOST, Port, #{verify => false, sync => true}),

    %% Warm up so the server-side connection processes exist before we
    %% snapshot processes() for eprof.
    ok = one_request(Conn),

    io:format("~n=== wall-clock (no profiler) ===~n"),
    {WallUs, ok} = timer:tc(fun() -> loop(Conn, N) end),
    UsPerReq = WallUs div N,
    ReqPerSec = (N * 1000000) div WallUs,
    io:format("~p requests in ~p ms => ~p us/req, ~p req/s~n", [
        N, WallUs div 1000, UsPerReq, ReqPerSec
    ]),

    io:format("~n=== eprof (flat time, all current processes) ===~n"),
    run_eprof(Conn, N),

    io:format("~n=== fprof (own-time + call counts) ===~n"),
    %% fprof slows everything ~10-20x; use fewer iterations.
    run_fprof(Conn, max(50, N div 10)),

    quic_h3:close(Conn),
    quic_test_h3_server:stop(Server),
    io:format("~neprof: /tmp/h3_eprof.txt   fprof: /tmp/h3_fprof_analysis.txt~n"),
    ok.

run_eprof(Conn, N) ->
    eprof:start(),
    profiling = eprof:start_profiling(processes()),
    loop(Conn, N),
    eprof:stop_profiling(),
    %% Total view across all profiled processes.
    eprof:analyze(total, [{sort, time}]),
    eprof:log("/tmp/h3_eprof.txt"),
    eprof:analyze(total, [{sort, time}, {filter, [{time, 1000}]}]),
    eprof:stop().

run_fprof(Conn, N) ->
    fprof:trace([start, {procs, all}]),
    loop(Conn, N),
    fprof:trace(stop),
    fprof:profile(),
    fprof:analyse([{dest, "/tmp/h3_fprof_analysis.txt"}, {totals, true}, {sort, own}]),
    io:format("(fprof analysis written; top own-time functions in the file)~n").

loop(_Conn, 0) ->
    ok;
loop(Conn, N) ->
    ok = one_request(Conn),
    loop(Conn, N - 1).

one_request(Conn) ->
    Headers = [
        {<<":method">>, <<"GET">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/test.txt">>},
        {<<":authority">>, ?HOST},
        {<<"user-agent">>, <<"h3-profile/1.0">>},
        {<<"accept">>, <<"text/plain">>},
        {<<"accept-encoding">>, <<"gzip, deflate, br">>}
    ],
    {ok, StreamId} = quic_h3:request(Conn, Headers),
    drain(Conn, StreamId).

drain(Conn, StreamId) ->
    receive
        {quic_h3, Conn, {response, StreamId, _S, _H}} -> drain(Conn, StreamId);
        {quic_h3, Conn, {headers, StreamId, _S, _H}} -> drain(Conn, StreamId);
        {quic_h3, Conn, {data, StreamId, _D, true}} -> ok;
        {quic_h3, Conn, {data, StreamId, _D, false}} -> drain(Conn, StreamId);
        {quic_h3, Conn, {trailers, StreamId, _T}} -> ok;
        {quic_h3, Conn, {stream_end, StreamId}} -> ok
    after 10000 ->
        error({response_timeout, StreamId})
    end.
