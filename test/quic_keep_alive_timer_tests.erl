%%% -*- erlang -*-
%%%
%%% What a firing keep-alive timer does to the idle timer and to its own
%%% next expiry.

-module(quic_keep_alive_timer_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(IDLE, 20000).
-define(INTERVAL, 8000).

%% The idle timer is moved to the idle deadline itself (RFC 9000 Section
%% 10.1), so it does not fire only to find the connection was kept alive.
moves_the_idle_timer_to_its_deadline_test() ->
    [
        begin
            S0 = quic_connection:set_idle_timer(state(client, 0)),
            Old = S0#state.idle_timer,
            S1 = fire(S0#state{last_activity = erlang:monotonic_time(millisecond) - Idle}),
            ?assertEqual(false, erlang:read_timer(Old)),
            Left = erlang:read_timer(S1#state.idle_timer),
            ?assert(Left =< ?IDLE - Idle),
            ?assert(Left > ?IDLE - Idle - 1000),
            cancel(S1)
        end
     || Idle <- [1000, ?INTERVAL]
    ].

fire(State) ->
    Ref = make_ref(),
    {keep_state, S} = quic_connection:handle_common_event(
        info, {timeout, Ref, keep_alive_timeout}, connected, State#state{keep_alive_timer = Ref}
    ),
    S.

state(Role, Idle) ->
    #state{cfg = Cfg} = S = quic_connection_test_support:state_for_role(Role),
    S#state{
        loss_state = quic_loss:new(),
        last_activity = erlang:monotonic_time(millisecond) - Idle,
        cfg = Cfg#conn_cfg{idle_timeout = ?IDLE, keep_alive_interval = ?INTERVAL}
    }.

cancel(#state{idle_timer = Idle, keep_alive_timer = KeepAlive}) ->
    erlang:cancel_timer(Idle),
    erlang:cancel_timer(KeepAlive).
