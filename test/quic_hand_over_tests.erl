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
