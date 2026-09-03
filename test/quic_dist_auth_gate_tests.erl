%%% -*- erlang -*-
%%%
%%% Tests for the distribution auth gate and the connection handoff.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_auth_gate_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_dist.hrl").

%%====================================================================
%% Fake connection
%%====================================================================

%% Answers the handful of gen_statem calls a controller makes during
%% startup, and reports every ownership change to Watcher so a test can
%% tell when it happened relative to start_link/2 returning.
fake_conn(Watcher) ->
    fake_conn(Watcher, 0).

fake_conn(Watcher, SetOwnerDelay) ->
    spawn(fun() -> fake_conn_loop(Watcher, SetOwnerDelay, 0) end).

fake_conn_loop(Watcher, Delay, NextStream) ->
    receive
        {'$gen_call', From, {set_owner, Owner}} ->
            %% Announce before replying, and hold the reply, so a caller
            %% can tell whether it was blocked on this call.
            Watcher ! {owner_set, Owner},
            timer:sleep(Delay),
            gen_statem:reply(From, ok),
            fake_conn_loop(Watcher, Delay, NextStream);
        {'$gen_call', From, open_stream} ->
            gen_statem:reply(From, {ok, NextStream}),
            fake_conn_loop(Watcher, Delay, NextStream + 4);
        {'$gen_call', From, _Other} ->
            gen_statem:reply(From, ok),
            fake_conn_loop(Watcher, Delay, NextStream);
        stop ->
            ok;
        _ ->
            fake_conn_loop(Watcher, Delay, NextStream)
    end.

start_server_controller(Conn, Auth) ->
    quic_dist_controller:start_link(Conn, server, Auth).

%%====================================================================
%% Server auth gate
%%====================================================================

%% Without a `connected' event the controller must not admit the peer,
%% and it must not run the callback either.
auth_gate_waits_for_connected_test() ->
    Conn = fake_conn(self()),
    Marker = self(),
    Cb = fun(_C, _Side, _T) ->
        Marker ! callback_ran,
        {ok, ok}
    end,
    {ok, Ctrl} = start_server_controller(Conn, {Cb, 5000}),
    timer:sleep(200),
    ?assertEqual(init_state, current_state(Ctrl)),
    ?assertNot(got(callback_ran)),
    gen_statem:stop(Ctrl),
    Conn ! stop.

auth_gate_admits_on_ok_test() ->
    Conn = fake_conn(self()),
    Cb = fun(_C, Side, _T) -> {ok, Side} end,
    {ok, Ctrl} = start_server_controller(Conn, {Cb, 5000}),
    Ctrl ! {quic, Conn, {connected, #{}}},
    ?assertEqual(handshaking, wait_for_state(Ctrl, handshaking, 40)),
    gen_statem:stop(Ctrl),
    Conn ! stop.

%% A refusal is an outcome, not a crash: the controller stops `normal' so
%% it produces no crash report and cannot take a trapping listener with it.
auth_gate_refuses_on_error_test() ->
    Conn = fake_conn(self()),
    Cb = fun(_C, _Side, _T) -> {error, denied} end,
    {ok, Ctrl} = start_server_controller(Conn, {Cb, 5000}),
    MRef = erlang:monitor(process, Ctrl),
    Ctrl ! {quic, Conn, {connected, #{}}},
    receive
        {'DOWN', MRef, process, Ctrl, Reason} ->
            ?assertEqual(normal, Reason)
    after 2000 ->
        ?assert(false)
    end,
    Conn ! stop.

%% The deadline guards the wait for the QUIC handshake. It is what the
%% gatekeeper's `after Timeout' used to be.
auth_gate_times_out_without_connected_test() ->
    Conn = fake_conn(self()),
    Cb = fun(_C, _Side, _T) -> {ok, ok} end,
    {ok, Ctrl} = start_server_controller(Conn, {Cb, 150}),
    MRef = erlang:monitor(process, Ctrl),
    receive
        {'DOWN', MRef, process, Ctrl, Reason} ->
            ?assertEqual(normal, Reason)
    after 2000 ->
        ?assert(false)
    end,
    Conn ! stop.

%% No callback configured: no gate at all.
no_auth_proceeds_without_connected_test() ->
    Conn = fake_conn(self()),
    {ok, Ctrl} = start_server_controller(Conn, undefined),
    ?assertEqual(handshaking, wait_for_state(Ctrl, handshaking, 40)),
    gen_statem:stop(Ctrl),
    Conn ! stop.

%%====================================================================
%% Client handoff
%%====================================================================

%% The whole client fix rests on this: ownership must move inside init/1,
%% not in the state_enter callback, so that the setup process's drain
%% cannot race the connection. An `after 0' receive proves the ownership
%% message was already in our mailbox when start_link/2 returned.
client_takes_ownership_before_start_link_returns_test() ->
    flush_owner_sets(),
    %% The fake connection holds the set_owner reply. If the swap were in
    %% the state_enter callback, start_link/2 would answer first and this
    %% mailbox would still be empty.
    Conn = fake_conn(self(), 150),
    {ok, Ctrl} = quic_dist_controller:start_link(Conn, client),
    Moved =
        receive
            {owner_set, Owner} -> Owner
        after 0 ->
            none
        end,
    ?assertEqual(Ctrl, Moved),
    gen_statem:stop(Ctrl),
    Conn ! stop.

%%====================================================================
%% Selective drain
%%====================================================================

%% Distribution events cross to the controller; an auth callback's own
%% stream data does not, because forward_pending_data/1 would feed it to
%% the VM's dist input. Exit signals the setup process still needs stay
%% where they are.
forward_owner_events_is_selective_test() ->
    Conn = self(),
    Parent = self(),
    Collector = spawn(fun() -> collect([], Parent) end),
    Timer = spawn(fun() -> ok end),
    Loser = spawn(fun() -> ok end),
    Drainer = spawn(fun() ->
        receive
            go -> ok
        end,
        N = quic_dist_controller:adopt_owner_events(Conn, Collector),
        Left = element(2, process_info(self(), messages)),
        Parent ! {drained, N, Left}
    end),
    Drainer ! {quic, Conn, {stream_opened, ?QUIC_DIST_CONTROL_STREAM}},
    Drainer ! {quic, Conn, {stream_data, ?QUIC_DIST_CONTROL_STREAM, <<"name">>, false}},
    Drainer ! {quic, Conn, {stream_data, ?USER_STREAM_THRESHOLD_SERVER, <<"auth">>, true}},
    Drainer ! {'EXIT', Timer, setup_timer_timeout},
    Drainer ! {'EXIT', Loser, remarked},
    Drainer ! {quic, Conn, {session_ticket, <<"t">>}},
    Drainer ! go,

    {N, Left} =
        receive
            {drained, Count, Rest} -> {Count, Rest}
        after 2000 ->
            {timeout, []}
        end,
    ?assertEqual(3, N),
    ?assertEqual(
        [
            {'EXIT', Timer, setup_timer_timeout},
            {'EXIT', Loser, remarked},
            {quic, Conn, {stream_data, ?USER_STREAM_THRESHOLD_SERVER, <<"auth">>, true}}
        ],
        lists:sort(Left)
    ),

    Collector ! flush,
    Forwarded =
        receive
            {collected, Msgs} -> Msgs
        after 2000 ->
            []
        end,
    ?assertEqual(
        [
            {quic, Conn, {stream_opened, ?QUIC_DIST_CONTROL_STREAM}},
            {quic, Conn, {stream_data, ?QUIC_DIST_CONTROL_STREAM, <<"name">>, false}},
            {quic, Conn, {session_ticket, <<"t">>}}
        ],
        Forwarded
    ).

collect(Acc, Parent) ->
    receive
        flush -> Parent ! {collected, lists:reverse(Acc)};
        Msg -> collect([Msg | Acc], Parent)
    end.

%%====================================================================
%% Helpers
%%====================================================================

current_state(Pid) ->
    {State, _Data} = sys:get_state(Pid),
    State.

wait_for_state(_Pid, Want, 0) ->
    {timeout, Want};
wait_for_state(Pid, Want, N) ->
    case current_state(Pid) of
        Want ->
            Want;
        _ ->
            timer:sleep(25),
            wait_for_state(Pid, Want, N - 1)
    end.

flush_owner_sets() ->
    receive
        {owner_set, _} -> flush_owner_sets()
    after 0 ->
        ok
    end.

got(Msg) ->
    receive
        Msg -> true
    after 0 ->
        false
    end.
