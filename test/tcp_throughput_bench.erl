%%% -*- erlang -*-
%%%
%%% Plain TCP sink benchmark.
%%%
%%% Mirrors the shape of quic_throughput_bench:run_sink/1 so the MB/s
%%% numbers are directly comparable: client opens one connection, sends
%%% a 4-byte length header followed by N bytes, waits for the server to
%%% signal "received it all" via a 1-byte completion marker, closes.
%%% Elapsed time is end-to-end.
%%%
%%% Plain gen_tcp only (no TLS). Buffer sizes match the QUIC bench so
%%% the comparison isn't skewed by kernel buffer tuning.
%%%
%%% Usage:
%%%   tcp_throughput_bench:run().                         % 10 MB default
%%%   tcp_throughput_bench:run(#{data_size => 50*1024*1024}).
%%%

-module(tcp_throughput_bench).

-export([run/0, run/1]).

-define(DEFAULT_PORT, 14434).
-define(DEFAULT_DATA_SIZE, 10 * 1024 * 1024).
-define(BUF_SIZE, 7 * 1024 * 1024).

%%====================================================================
%% Public API
%%====================================================================

run() -> run(#{}).

run(Opts) ->
    DataSize = maps:get(data_size, Opts, ?DEFAULT_DATA_SIZE),
    Port = maps:get(port, Opts, ?DEFAULT_PORT),

    io:format("~n=== TCP Sink Benchmark ===~n"),
    io:format("Data size: ~.2f MB~n", [DataSize / 1048576]),

    {ok, Server} = start_server(Port),
    Result =
        try
            run_client(Port, DataSize)
        after
            stop_server(Server)
        end,

    io:format("Result: ~.2f MB/s (~p ms)~n", [
        maps:get(mb_per_sec, Result),
        maps:get(duration_ms, Result)
    ]),
    Result.

%%====================================================================
%% Server
%%====================================================================

start_server(Port) ->
    ListenOpts = [
        binary,
        {packet, 0},
        {active, false},
        {reuseaddr, true},
        {nodelay, true},
        {recbuf, ?BUF_SIZE},
        {sndbuf, ?BUF_SIZE}
    ],
    {ok, LSock} = gen_tcp:listen(Port, ListenOpts),
    Pid = spawn_link(fun() -> accept_loop(LSock) end),
    {ok, {Pid, LSock}}.

accept_loop(LSock) ->
    case gen_tcp:accept(LSock) of
        {ok, Sock} ->
            Pid = spawn(fun() ->
                receive
                    go -> sink(Sock)
                end
            end),
            ok = gen_tcp:controlling_process(Sock, Pid),
            Pid ! go,
            accept_loop(LSock);
        {error, _} ->
            ok
    end.

sink(Sock) ->
    %% Read 4-byte big-endian length prefix, then exactly that many bytes.
    {ok, <<N:32>>} = gen_tcp:recv(Sock, 4, 30000),
    ok = drain_n(Sock, N),
    _ = gen_tcp:send(Sock, <<0>>),
    gen_tcp:close(Sock),
    ok.

drain_n(_Sock, 0) ->
    ok;
drain_n(Sock, Remaining) ->
    %% Ask for whatever the kernel has; 0 = whatever's available.
    case gen_tcp:recv(Sock, 0, 30000) of
        {ok, Data} ->
            drain_n(Sock, Remaining - byte_size(Data));
        {error, Reason} ->
            error({drain_failed, Reason, Remaining})
    end.

stop_server({Pid, LSock}) ->
    unlink(Pid),
    gen_tcp:close(LSock),
    exit(Pid, shutdown).

%%====================================================================
%% Client
%%====================================================================

run_client(Port, DataSize) ->
    ConnectOpts = [
        binary,
        {packet, 0},
        {active, false},
        {nodelay, true},
        {recbuf, ?BUF_SIZE},
        {sndbuf, ?BUF_SIZE}
    ],
    {ok, Sock} = gen_tcp:connect("127.0.0.1", Port, ConnectOpts),
    Data = crypto:strong_rand_bytes(DataSize),

    T0 = erlang:monotonic_time(microsecond),
    ok = gen_tcp:send(Sock, <<DataSize:32>>),
    ok = gen_tcp:send(Sock, Data),

    %% Wait for the 1-byte completion marker.
    {ok, <<_>>} = gen_tcp:recv(Sock, 1, 60000),
    T1 = erlang:monotonic_time(microsecond),

    gen_tcp:close(Sock),

    DurationUs = max(1, T1 - T0),
    MBps = (DataSize / 1048576) / (DurationUs / 1000000),

    #{
        status => ok,
        data_size => DataSize,
        duration_ms => DurationUs div 1000,
        mb_per_sec => MBps
    }.
