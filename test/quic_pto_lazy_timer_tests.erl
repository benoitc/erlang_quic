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
%% is nothing to probe, so RFC 9002 Appendix A.8 cancels rather than
%% leaving an armed timer to fire and find itself idle.
drained_flight_cancels_the_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    Ref = pto_timer(S1),
    S2 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(
            S1, loss_state, quic_loss:on_handshake_confirmed(quic_loss:new())
        )
    ),
    ?assertEqual(undefined, pto_timer(S2)),
    ?assertEqual(idle, quic_connection:pto_due(S2)),
    erlang:cancel_timer(Ref).

%% The timer reference is the timer itself, so cancelling it stops it.
drained_flight_stops_the_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    Ref = pto_timer(S1),
    ?assert(is_integer(erlang:read_timer(Ref))),
    S2 = quic_connection:set_pto_timer(drained(S1)),
    ?assertEqual(undefined, pto_timer(S2)),
    ?assertEqual(false, erlang:read_timer(Ref)).

%% A flight that drains again shortly after the last one did leaves the
%% timer armed for the next send. Until then a fire finds nothing to
%% probe (RFC 9002 Appendix A.8), and the next flight's deadline is its
%% own.
flight_draining_again_keeps_the_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    S2 = quic_connection:set_pto_timer(drained(S1)),
    ?assertEqual(undefined, pto_timer(S2)),
    S3 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(
            S2, loss_state, quic_connection_test_support:state_get(S1, loss_state)
        )
    ),
    Ref = pto_timer(S3),
    ?assert(is_reference(Ref)),
    S4 = quic_connection:set_pto_timer(drained(S3)),
    ?assertEqual(Ref, pto_timer(S4)),
    ?assertEqual(idle, quic_connection:pto_due(S4)),
    S5 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(S4, loss_state, flight_sent_now())
    ),
    ?assertEqual(Ref, pto_timer(S5)),
    {later, Remaining} = quic_connection:pto_due(S5),
    ?assert(Remaining > 0),
    erlang:cancel_timer(Ref).

%% A drain long after the previous one cancels: a connection going quiet
%% is not woken by a timer with nothing to probe.
flight_draining_after_a_pause_cancels_the_timer_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    S2 = quic_connection:set_pto_timer(drained(S1)),
    timer:sleep(120),
    S3 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(S2, loss_state, flight_sent_now())
    ),
    Ref = pto_timer(S3),
    S4 = quic_connection:set_pto_timer(drained(S3)),
    ?assertEqual(undefined, pto_timer(S4)),
    ?assertEqual(false, erlang:read_timer(Ref)).

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
