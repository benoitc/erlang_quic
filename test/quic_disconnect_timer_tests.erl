%%% -*- erlang -*-
%%%
%%% The disconnect check runs while there is something to time out on: a
%%% handshake, or data in flight. A confirmed connection with nothing in
%%% flight lets it lapse, and the first PTO of a later flight arms it
%%% again.

-module(quic_disconnect_timer_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

lapses_when_confirmed_with_nothing_in_flight_test() ->
    {keep_state, S} = check(connected, state(confirmed())),
    ?assertEqual(undefined, S#state.disconnect_timer).

stays_armed_with_data_in_flight_test() ->
    {keep_state, S} = check(connected, state(in_flight(confirmed()))),
    ?assert(is_integer(erlang:read_timer(S#state.disconnect_timer))),
    cancel(S).

%% No PTO runs for Application Data until the handshake is confirmed, so
%% nothing would arm the check again.
stays_armed_until_the_handshake_is_confirmed_test() ->
    {keep_state, S} = check(connected, state(quic_loss:new())),
    ?assert(is_integer(erlang:read_timer(S#state.disconnect_timer))),
    cancel(S).

stays_armed_during_the_handshake_test() ->
    {keep_state, S} = check(handshaking, state(confirmed())),
    ?assert(is_integer(erlang:read_timer(S#state.disconnect_timer))),
    cancel(S).

a_timeout_arms_a_lapsed_check_test() ->
    S0 = state(in_flight(confirmed())),
    S1 = quic_connection:ensure_disconnect_timer(S0),
    Ref = S1#state.disconnect_timer,
    ?assert(is_integer(erlang:read_timer(Ref))),
    ?assertEqual(S1, quic_connection:ensure_disconnect_timer(S1)),
    cancel(S1).

%% A connection whose check has lapsed still gives up on a peer that
%% stops answering.
lapsed_check_still_finds_a_dead_peer_test_() ->
    {timeout, 60, fun lapsed_check_still_finds_a_dead_peer/0}.

lapsed_check_still_finds_a_dead_peer() ->
    {ok, #{name := Name, port := Port} = Echo} = quic_test_echo_server:start(),
    try
        Opts = maps:merge(quic_test_echo_server:client_opts(), #{
            disconnect_timeout => 1000, idle_timeout => 0
        }),
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        ?assert(quic_test_wait:until(fun() -> disconnect_timer(Conn) =:= undefined end, 10000)),
        {ok, [ServerPid | _]} = quic:get_server_connections(Name),
        ok = sys:suspend(ServerPid),
        {ok, StreamId} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, StreamId, <<"are you there?">>, false),
        receive
            {quic, Conn, {closed, Reason}} -> ?assertEqual(disconnect_timeout, Reason)
        after 20000 -> error(not_closed)
        end,
        ok = sys:resume(ServerPid)
    after
        quic_test_echo_server:stop(Echo)
    end.

disconnect_timer(Conn) ->
    {_, #state{disconnect_timer = Timer}} = sys:get_state(Conn),
    Timer.

check(StateName, State) ->
    Ref = make_ref(),
    quic_connection:handle_common_event(
        info, {timeout, Ref, disconnect_check}, StateName, State#state{disconnect_timer = Ref}
    ).

state(LossState) ->
    S = quic_connection_test_support:state_for_role(client),
    S#state{loss_state = LossState, last_activity = erlang:monotonic_time(millisecond)}.

confirmed() ->
    quic_loss:on_handshake_confirmed(quic_loss:new()).

in_flight(LossState) ->
    quic_loss:on_packet_sent(
        app, LossState, 0, 1200, true, [], erlang:monotonic_time(millisecond)
    ).

cancel(#state{disconnect_timer = Ref}) ->
    erlang:cancel_timer(Ref).
