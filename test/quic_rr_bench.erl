%%% -*- erlang -*-
%%%
%%% QUIC request/response allocation benchmark
%%%
%%% Echoes small messages over several loopback connections and reports
%%% the garbage the connection processes produce per round trip, which
%%% is dominated by copies of the connection #state{} record.
%%%
%%% Usage:
%%%   quic_rr_bench:run().
%%%   quic_rr_bench:run(#{conns => 8, msgs => 2000, size => 200, profile => true}).
%%%

-module(quic_rr_bench).

-export([run/0, run/1]).

-define(SERVER, quic_rr_bench_server).

run() ->
    run(#{}).

%% Returns a map with words per round trip, state record size, msg/s and,
%% with `profile => true', the top allocating functions.
run(Opts) ->
    NConns = maps:get(conns, Opts, 8),
    Msgs = maps:get(msgs, Opts, 2000),
    Size = maps:get(size, Opts, 200),
    Profile = maps:get(profile, Opts, false),
    {ok, _} = application:ensure_all_started(quic),
    {ok, Port} = start_server(),
    Parent = self(),
    Clients = [
        spawn_link(fun() -> client(Parent, Port, Size, Msgs) end)
     || _ <- lists:seq(1, NConns)
    ],
    [
        receive
            {ready, C} -> ok
        end
     || C <- Clients
    ],
    Conns = connection_pids(),
    StateWords = state_words(hd(Conns)),
    Profile andalso start_profile(Conns),
    erlang:garbage_collect(),
    {_, W0, _} = erlang:statistics(garbage_collection),
    T0 = erlang:monotonic_time(microsecond),
    [C ! go || C <- Clients],
    [
        receive
            {done, C} -> ok
        end
     || C <- Clients
    ],
    T1 = erlang:monotonic_time(microsecond),
    {_, W1, _} = erlang:statistics(garbage_collection),
    Total = NConns * Msgs,
    Top =
        case Profile of
            true -> stop_profile(Total);
            false -> []
        end,
    [C ! stop || C <- Clients],
    ok = quic:stop_server(?SERVER),
    Result = #{
        round_trips => Total,
        gc_words_per_rt => (W1 - W0) / Total,
        state_words => StateWords,
        rt_per_s => Total / ((T1 - T0) / 1.0e6),
        top => Top
    },
    print(Result),
    Result.

start_server() ->
    {Cert, Key} = load_cert(),
    Handler = fun(ConnPid, _Ref) ->
        H = spawn(fun() -> echo(ConnPid) end),
        ok = quic:set_owner_sync(ConnPid, H),
        {ok, H}
    end,
    {ok, _} = quic:start_server(?SERVER, 0, #{
        cert => Cert,
        key => Key,
        alpn => [<<"rr">>],
        connection_handler => Handler
    }),
    quic:get_server_port(?SERVER).

load_cert() ->
    %% priv -> quic -> lib -> profile -> _build -> project root
    PrivDir = code:priv_dir(quic),
    Root = lists:foldl(fun(_, D) -> filename:dirname(D) end, PrivDir, lists:seq(1, 5)),
    {ok, CertPem} = file:read_file(filename:join([Root, "certs", "cert.pem"])),
    {ok, KeyPem} = file:read_file(filename:join([Root, "certs", "priv.key"])),
    [{_, CertDer, _}] = public_key:pem_decode(CertPem),
    [KeyEntry] = public_key:pem_decode(KeyPem),
    {CertDer, public_key:pem_entry_decode(KeyEntry)}.

client(Parent, Port, Size, Msgs) ->
    {ok, C} = quic:connect("127.0.0.1", Port, #{alpn => [<<"rr">>], verify => false}, self()),
    receive
        {quic, C, {connected, _}} -> ok
    after 5000 -> exit(no_connect)
    end,
    {ok, S} = quic:open_stream(C),
    Payload = binary:copy(<<"x">>, Size),
    loop(C, S, Payload, 200),
    Parent ! {ready, self()},
    receive
        go -> ok
    end,
    loop(C, S, Payload, Msgs),
    Parent ! {done, self()},
    receive
        stop -> quic:close(C, normal)
    end.

loop(_C, _S, _P, 0) ->
    ok;
loop(C, S, P, N) ->
    ok = quic:send_data(C, S, P, false),
    wait(C, S, byte_size(P)),
    loop(C, S, P, N - 1).

wait(_C, _S, 0) ->
    ok;
wait(C, S, Left) ->
    receive
        {quic, C, {stream_data, S, D, _}} -> wait(C, S, Left - byte_size(D));
        {quic, C, _} -> wait(C, S, Left)
    after 5000 -> exit(timeout)
    end.

echo(Conn) ->
    receive
        {quic, Conn, {stream_data, S, D, Fin}} ->
            _ = quic:send_data_async(Conn, S, D, Fin),
            echo(Conn);
        {quic, Conn, {closed, _}} ->
            ok;
        _ ->
            echo(Conn)
    end.

connection_pids() ->
    [
        P
     || P <- processes(),
        proc_lib:initial_call(P) =:= {quic_connection, init, ['Argument__1']}
    ].

%% Words one copy of the connection record costs (tuple header included).
state_words(Pid) ->
    {_StateName, Data} = sys:get_state(Pid),
    tuple_size(Data) + 1.

start_profile(Conns) ->
    {ok, _} = tprof:start(#{type => call_memory}),
    [
        tprof:set_pattern(M, '_', '_')
     || {M, _} <- code:all_loaded(), lists:prefix("quic", atom_to_list(M))
    ],
    [tprof:enable_trace(P) || P <- Conns],
    true.

stop_profile(Total) ->
    tprof:pause(),
    Sampled = tprof:collect(),
    tprof:stop(),
    #{all := {call_memory, _, Rows}} = tprof:inspect(Sampled, total, measurement),
    Sorted = lists:reverse(lists:keysort(4, Rows)),
    [
        {{M, F, A}, C / Total, W / max(C, 1), W / Total}
     || {M, {F, A}, C, W, _, _} <- lists:sublist(Sorted, 25)
    ].

print(#{gc_words_per_rt := W, state_words := SW, rt_per_s := R, top := Top}) ->
    io:format("gc words/rt ~.1f  state words ~p  rt/s ~.1f~n", [W, SW, R]),
    [
        io:format("  ~-55s ~6.2f calls/rt ~7.1f w/call ~8.1f w/rt~n", [
            io_lib:format("~w:~w/~w", [M, F, A]), C, WC, WR
        ])
     || {{M, F, A}, C, WC, WR} <- Top
    ],
    ok.
