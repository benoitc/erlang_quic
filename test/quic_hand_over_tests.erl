%%% -*- erlang -*-
%%%
%%% A live connection handed to a new owner. Events the old owner already
%%% holds and events the connection sends later must reach the new owner
%%% in the order the connection sent them, whatever the old owner is doing
%%% at the switch. The hook below holds the old owner suspended from the
%%% moment the connection takes its owner-change call, and queues a probe
%%% (`send_ready') behind that call to show what the connection sends next.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_hand_over_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% An address nothing answers on: the connection stays in the handshake.
-define(DEAD, {{127, 0, 0, 1}, 1}).
-define(HELD, {stream_data, 3, <<0>>, false}).

%%====================================================================
%% The hand-over itself
%%====================================================================

an_old_owner_killed_mid_hand_over_test_() ->
    {timeout, 30, fun() ->
        {Old, Conn} = old_owner(),
        New = collector(),
        slow_old_owner(Conn, Old, kill),
        hand_over_async(Old, New),
        ok = wait_for(New, fun(Ms) -> lists:member({quic, Conn, send_ready}, Ms) end),
        quic_connection:notify_send_ready(Conn),
        ok = wait_for(New, fun(Ms) -> count({quic, Conn, send_ready}, Ms) =:= 2 end),
        ?assert(is_process_alive(Conn)),
        quic:safe_close(Conn)
    end}.

%% The old owner never sends what it holds: the connection closes rather
%% than go on without it, and what the old owner held never arrives.
a_stuck_old_owner_closes_the_connection_test_() ->
    {timeout, 30, fun() ->
        {Old, Conn} = old_owner(),
        New = collector(),
        Old ! {quic, Conn, ?HELD},
        Holder = slow_old_owner(Conn, Old, forever),
        hand_over_async(Old, New),
        try
            ok = wait_for(
                New,
                fun(Ms) -> lists:member({quic, Conn, {closed, hand_over_timeout}}, Ms) end,
                10000
            ),
            ?assertNot(lists:member({quic, Conn, ?HELD}, collected(New)))
        after
            Holder ! release,
            exit(Old, kill)
        end
    end}.

%% A process that does not own the connection holds none of its events,
%% so the swap is immediate.
a_caller_that_is_not_the_owner_swaps_at_once_test_() ->
    {timeout, 30, fun() ->
        {_Old, Conn} = old_owner(),
        New = collector(),
        {Ms, Result} = timer:tc(quic_connection, hand_over, [Conn, New, []], millisecond),
        ?assertEqual(ok, Result),
        ?assert(Ms < 1000),
        quic_connection:notify_send_ready(Conn),
        ok = wait_for(New, fun(Msgs) -> lists:member({quic, Conn, send_ready}, Msgs) end),
        quic:safe_close(Conn)
    end}.

%%====================================================================
%% Happy Eyeballs: the coordinator hands the winner to the owner
%%====================================================================

%% The winner delivered Early to the coordinator before the hand-off. The
%% owner must get it before anything the winner sends after the switch.
the_winner_reaches_its_owner_in_order_test_() ->
    {timeout, 30, fun() ->
        {ok, _} = application:ensure_all_started(quic),
        Owner = collector(),
        Before = conn_children(),
        {IP, Port} = ?DEAD,
        {ok, Coord} = quic_happy:start_coordinator(#{
            addrs => [{IP, inet}],
            port => Port,
            opts => #{verify => false},
            owner => Owner,
            caller => self(),
            delay => 100,
            timeout => 10000
        }),
        try
            Attempt = wait_new_child(Before, 50),
            slow_old_owner(Attempt, Coord, 100),
            Early = {quic, Attempt, ?HELD},
            Coord ! Early,
            Coord ! {quic, Attempt, {connected, #{}}},
            receive
                {quic_happy_result, Coord, Result} -> ?assertEqual({ok, Attempt}, Result)
            after 5000 -> error(no_result)
            end,
            ok = wait_for(Owner, fun(Ms) -> length(from(Attempt, Ms)) >= 2 end),
            ?assertMatch([Early, {quic, Attempt, send_ready} | _], from(Attempt, collected(Owner))),
            quic:safe_close(Attempt)
        after
            exit(Coord, kill)
        end
    end}.

%%====================================================================
%% HTTP/3: the caller hands the connection to the HTTP/3 process
%%====================================================================

%% The caller already holds the start of the server's control stream.
take_over_keeps_the_callers_events_first_test_() ->
    {timeout, 30, fun() ->
        {Old, Conn} = old_owner(),
        H3 = collector(),
        Old ! {quic, Conn, ?HELD},
        slow_old_owner(Conn, Old, 100),
        Old ! {take_over, H3},
        ok = wait_for(H3, fun(Ms) -> length(from(Conn, Ms)) >= 2 end),
        ?assertMatch(
            [{quic, Conn, ?HELD}, {quic, Conn, send_ready} | _], from(Conn, collected(H3))
        ),
        quic:safe_close(Conn)
    end}.

%% The server sends its control stream type byte, then SETTINGS 50 ms
%% later. The type byte is with the caller when it hands the connection
%% over, and the caller is held up for 100 ms right after: SETTINGS must
%% still reach the HTTP/3 process after the type byte, or it ignores the
%% stream and connect/3 times out.
h3_connect_reads_the_control_stream_in_order_test_() ->
    {timeout, 30, fun() ->
        {ok, _} = application:ensure_all_started(quic),
        {Cert, Key} = server_creds(),
        Name = list_to_atom("hand_over_h3_" ++ integer_to_list(erlang:unique_integer([positive]))),
        {ok, _} = quic:start_server(Name, 0, #{
            cert => Cert,
            key => Key,
            alpn => [<<"h3">>],
            connection_handler => fun(Conn) -> {ok, spawn(fun() -> h3_server(Conn) end)} end
        }),
        {ok, Port} = quic:get_server_port(Name),
        ok = meck:new(quic, [passthrough]),
        try
            meck:expect(quic, connect, fun(Host, P, Opts, Owner) ->
                {ok, Conn} = meck:passthrough([Host, P, Opts, Owner]),
                ok = wait_type_byte(Conn, 5000),
                _ = slow_old_owner(Conn, self(), 100, none),
                {ok, Conn}
            end),
            {Result, Settings} = h3_connect(Port),
            ?assertMatch({ok, _}, Result),
            ?assert(is_map(Settings))
        after
            meck:unload(quic),
            quic:stop_server(Name)
        end
    end}.

h3_connect(Port) ->
    Test = self(),
    {Pid, MRef} = spawn_monitor(fun() ->
        R = quic_h3:connect(<<"127.0.0.1">>, Port, #{
            sync => true, verify => verify_none, connect_timeout => 1000
        }),
        Settings =
            case R of
                {ok, H} -> quic_h3_connection:get_peer_settings(H);
                _ -> undefined
            end,
        Test ! {self(), R, Settings},
        receive
            stop -> ok
        end
    end),
    receive
        {Pid, R, Settings} ->
            erlang:demonitor(MRef, [flush]),
            Pid ! stop,
            {R, Settings};
        {'DOWN', MRef, process, Pid, Reason} ->
            {{crashed, Reason}, undefined}
    after 10000 ->
        exit(Pid, kill),
        {timeout, undefined}
    end.

%% The first flight of an HTTP/3 server, with SETTINGS held back 50 ms.
h3_server(Conn) ->
    receive
        {quic, Conn, {connected, _}} -> ok
    after 5000 -> exit(no_connect)
    end,
    {ok, Ctrl} = quic:open_unidirectional_stream(Conn),
    ok = quic:send_data(Conn, Ctrl, quic_h3_frame:encode_stream_type(control), false),
    {ok, Enc} = quic:open_unidirectional_stream(Conn),
    ok = quic:send_data(Conn, Enc, quic_h3_frame:encode_stream_type(qpack_encoder), false),
    {ok, Dec} = quic:open_unidirectional_stream(Conn),
    ok = quic:send_data(Conn, Dec, quic_h3_frame:encode_stream_type(qpack_decoder), false),
    timer:sleep(50),
    Settings = quic_h3_frame:encode_settings(quic_h3_frame:default_settings()),
    ok = quic:send_data(Conn, Ctrl, Settings, false),
    h3_server_loop(Conn).

h3_server_loop(Conn) ->
    receive
        {quic, Conn, {closed, _}} -> ok;
        _ -> h3_server_loop(Conn)
    after 10000 -> ok
    end.

%% Looks without taking: the hand-off must find the type byte.
wait_type_byte(_Conn, Left) when Left =< 0 ->
    timeout;
wait_type_byte(Conn, Left) ->
    {messages, Msgs} = process_info(self(), messages),
    case [x || {quic, C, {stream_data, 3, <<0>>, _}} <- Msgs, C =:= Conn] of
        [_ | _] ->
            ok;
        [] ->
            timer:sleep(1),
            wait_type_byte(Conn, Left - 1)
    end.

server_creds() ->
    #{server_config := S} = public_key:pkix_test_data(#{
        server_chain => chain([{dNSName, "localhost"}]),
        client_chain => chain([{dNSName, "client.example"}])
    }),
    {KeyType, KeyDer} = proplists:get_value(key, S),
    {proplists:get_value(cert, S), public_key:der_decode(KeyType, KeyDer)}.

chain(SanNames) ->
    Key = {key, {namedCurve, secp256r1}},
    San = #'Extension'{
        extnID = ?'id-ce-subjectAltName', critical = false, extnValue = SanNames
    },
    %% The default digest is SHA-1, which TLS 1.3 refuses.
    Digest = {digest, sha256},
    #{root => [Key, Digest], intermediates => [], peer => [Key, Digest, {extensions, [San]}]}.

%%====================================================================
%% Helpers
%%====================================================================

%% A process that owns a connection to nowhere and hands it over on demand.
old_owner() ->
    {ok, _} = application:ensure_all_started(quic),
    Test = self(),
    Old = spawn(fun() ->
        {IP, Port} = ?DEAD,
        {ok, Conn} = quic:connect(IP, Port, #{verify => false}, self()),
        Test ! {conn, self(), Conn},
        old_owner_loop(Conn)
    end),
    receive
        {conn, Old, Conn} -> {Old, Conn}
    after 5000 -> error(no_connection)
    end.

old_owner_loop(Conn) ->
    receive
        {hand_over, New} ->
            _ = quic_connection:hand_over(Conn, New, []),
            old_owner_loop(Conn);
        {take_over, H3} ->
            _ = quic_h3_connection:take_over(Conn, H3),
            old_owner_loop(Conn)
    end.

hand_over_async(Old, New) ->
    Old ! {hand_over, New},
    ok.

%% From the moment Conn takes Old's owner-change call (set_owner_sync/2 or
%% hand_over/3), Old is held suspended: for Hold ms, until it is killed, or
%% until the holder is told `release'. Returns the holder.
slow_old_owner(Conn, Old, Hold) ->
    slow_old_owner(Conn, Old, Hold, probe).

slow_old_owner(Conn, Old, Hold, Probe) ->
    Holder = spawn(fun() -> holder(Old, Hold) end),
    Hook = fun
        (armed, {in, {{call, {Caller, _}}, {Req, _}}, _}, _) when
            Caller =:= Old, (Req =:= set_owner orelse Req =:= hand_over)
        ->
            Holder ! {suspend, self()},
            receive
                {suspended, Holder} -> ok
            end,
            _ = probe(Probe),
            done;
        (HookState, _Event, _ProcState) ->
            HookState
    end,
    ok = sys:install(Conn, {Hook, armed}),
    Holder.

probe(probe) -> quic_connection:notify_send_ready(self());
probe(none) -> ok.

holder(Old, Hold) ->
    receive
        {suspend, Conn} ->
            true = erlang:suspend_process(Old),
            Conn ! {suspended, self()},
            hold(Old, Hold)
    end.

hold(Old, kill) ->
    timer:sleep(50),
    exit(Old, kill);
hold(Old, forever) ->
    receive
        release -> erlang:resume_process(Old)
    end;
hold(Old, Ms) when is_integer(Ms) ->
    timer:sleep(Ms),
    erlang:resume_process(Old).

collector() ->
    spawn(fun() -> collector([]) end).

collector(Acc) ->
    receive
        {get, From} ->
            From ! {got, self(), lists:reverse(Acc)},
            collector(Acc);
        Msg ->
            collector([Msg | Acc])
    end.

collected(Collector) ->
    Collector ! {get, self()},
    receive
        {got, Collector, Msgs} -> Msgs
    after 1000 -> error(no_collector)
    end.

wait_for(Collector, Pred) ->
    wait_for(Collector, Pred, 5000).

wait_for(Collector, _Pred, Left) when Left =< 0 ->
    {timeout, collected(Collector)};
wait_for(Collector, Pred, Left) ->
    case Pred(collected(Collector)) of
        true ->
            ok;
        false ->
            timer:sleep(10),
            wait_for(Collector, Pred, Left - 10)
    end.

count(Msg, Msgs) ->
    length([M || M <- Msgs, M =:= Msg]).

from(Conn, Msgs) ->
    [M || {quic, C, _} = M <- Msgs, C =:= Conn].

conn_children() ->
    [P || {_, P, _, _} <- supervisor:which_children(quic_conn_sup), is_pid(P)].

wait_new_child(_Before, 0) ->
    error(no_attempt_started);
wait_new_child(Before, N) ->
    case conn_children() -- Before of
        [Pid | _] ->
            Pid;
        [] ->
            timer:sleep(20),
            wait_new_child(Before, N - 1)
    end.
