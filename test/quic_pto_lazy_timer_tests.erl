%%% -*- erlang -*-
%%%
%%% The PTO timer is re-armed lazily: a deadline that moves later leaves
%%% the armed timer alone, and the fire handler waits the remainder.
%%%

-module(quic_pto_lazy_timer_tests).

-include_lib("eunit/include/eunit.hrl").

state_with_flight() ->
    L0 = quic_loss:new(),
    L1 = quic_loss:on_packet_sent(L0, 0, 1200, true, [], erlang:monotonic_time(millisecond)),
    quic_connection:test_state_with_loss(L1).

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

drained_flight_makes_the_fire_idle_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    S2 = quic_connection:set_pto_timer(
        quic_connection:test_state_set(S1, loss_state, quic_loss:new())
    ),
    ?assertEqual(pto_timer(S1), pto_timer(S2)),
    ?assertEqual(idle, quic_connection:pto_due(S2)),
    erlang:cancel_timer(pto_timer(S1)).

past_deadline_is_due_test() ->
    S1 = quic_connection:set_pto_timer(state_with_flight()),
    ?assertEqual(
        due,
        quic_connection:pto_due(
            quic_connection:test_state_set(
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

pto_timer(S) -> quic_connection:test_state_get(S, pto_timer).
pto_scheduled_at(S) -> quic_connection:test_state_get(S, pto_scheduled_at).
