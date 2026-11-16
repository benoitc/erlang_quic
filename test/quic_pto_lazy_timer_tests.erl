%%% -*- erlang -*-
%%%
%%% The PTO timer is re-armed lazily: a deadline that moves later leaves
%%% the armed timer alone, and the fire handler waits the remainder.
%%%

-module(quic_pto_lazy_timer_tests).

-include_lib("eunit/include/eunit.hrl").

state_with_flight() ->
    L0 = quic_loss:new(),
    L1 = quic_loss:on_packet_sent(app, L0, 0, 1200, true, [], erlang:monotonic_time(millisecond)),
    quic_connection_test_support:state_with_loss(L1, app).

deadline_moving_later_keeps_the_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    Ref = pto_timer(S1),
    ?assert(is_reference(Ref)),
    timer:sleep(5),
    S2 = quic_connection:set_pto_timer(S1),
    ?assertEqual(Ref, pto_timer(S2)),
    ?assert(pto_scheduled_at(S2) >= pto_scheduled_at(S1)),
    ?assertEqual(
        {later, pto_scheduled_at(S2) - erlang:monotonic_time(millisecond)}, pto_due_shape(S2)
    ),
    erlang:cancel_timer(Ref).

%% Nothing left in flight and the peer has validated the address: there
%% is nothing to probe (RFC 9002 Appendix A.8). The armed timer is left
%% alone and its fire does nothing.
drained_flight_keeps_the_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    Ref = pto_timer(S1),
    S2 = quic_connection:set_pto_timer(drained(S1)),
    ?assertEqual(Ref, pto_timer(S2)),
    ?assert(is_integer(erlang:read_timer(Ref))),
    ?assertEqual(undefined, pto_scheduled_at(S2)),
    ?assertEqual(idle, quic_connection:pto_due(S2)),
    erlang:cancel_timer(Ref).

%% The next flight reuses the timer left armed by a drained one, and its
%% deadline is its own.
next_flight_reuses_the_drained_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    Ref = pto_timer(S1),
    S2 = quic_connection:set_pto_timer(drained(S1)),
    timer:sleep(5),
    S3 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(S2, loss_state, flight_sent_now())
    ),
    ?assertEqual(Ref, pto_timer(S3)),
    {later, Remaining} = quic_connection:pto_due(S3),
    ?assert(Remaining > 0),
    erlang:cancel_timer(Ref).

%% The timer reference is the timer itself: a re-arm for another space
%% stops the timer it replaces.
rearm_stops_the_replaced_timer_test() ->
    Now = erlang:monotonic_time(millisecond),
    Handshake = quic_loss:on_packet_sent(handshake, quic_loss:new(), 0, 1200, true, [ping], Now),
    S1 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(state_with_flight(), loss_state, Handshake)
    ),
    First = pto_timer(S1),
    ?assert(is_integer(erlang:read_timer(First))),
    S2 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(S1, loss_state, flight_sent_now())
    ),
    Second = pto_timer(S2),
    ?assertNotEqual(First, Second),
    ?assertEqual(false, erlang:read_timer(First)),
    erlang:cancel_timer(Second).

flight_sent_now() ->
    quic_loss:on_packet_sent(
        app,
        quic_loss:on_handshake_confirmed(quic_loss:new()),
        0,
        1200,
        true,
        [],
        erlang:monotonic_time(millisecond)
    ).

drained(S) ->
    quic_connection_test_support:state_set(
        S, loss_state, quic_loss:on_handshake_confirmed(quic_loss:new())
    ).

past_deadline_is_due_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    ?assertEqual(
        due,
        quic_connection:pto_due(
            quic_connection_test_support:state_set(
                S1, pto_scheduled_at, erlang:monotonic_time(millisecond) - 1
            )
        )
    ),
    erlang:cancel_timer(pto_timer(S1)).

pto_due_shape(S) ->
    case quic_connection:pto_due(S) of
        {later, _} -> {later, pto_scheduled_at(S) - erlang:monotonic_time(millisecond)};
        Other -> Other
    end.

pto_timer(S) -> quic_connection_test_support:state_get(S, pto_timer).
pto_scheduled_at(S) -> quic_connection_test_support:state_get(S, pto_scheduled_at).
