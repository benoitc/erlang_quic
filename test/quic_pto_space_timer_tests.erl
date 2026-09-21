%%% -*- erlang -*-
%%%
%%% What the connection arms its one loss-detection timer for.
%%%
%%% RFC 9002 Appendix A.8 decides in a fixed order, and each step is a
%%% case here because getting any of them wrong is silent: the timer
%%% still fires, just for the wrong space or when it should not exist.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_pto_space_timer_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Section 6.2.1: no application probe before confirmation
%%====================================================================

%% The defect, at the connection level. A client with early data in
%% flight and an unconfirmed handshake arms nothing at all: the
%% application space is not eligible, and no other space has anything.
unconfirmed_app_flight_arms_no_timer_test() ->
    S = quic_connection:set_pto_timer(state_with(app_flight(), handshake)),
    ?assertEqual(undefined, quic_connection_test_support:state_get(S, pto_timer)),
    ?assertEqual(undefined, quic_connection_test_support:state_get(S, pto_scheduled_at)).

%% The same flight arms once the handshake is confirmed.
confirmed_app_flight_arms_the_timer_test() ->
    S = quic_connection:set_pto_timer(state_with(app_flight(), app)),
    Ref = quic_connection_test_support:state_get(S, pto_timer),
    ?assert(is_reference(Ref)),
    erlang:cancel_timer(Ref).

%%====================================================================
%% Appendix A.8: a change of space forces a re-arm
%%====================================================================

%% The lazy rule leaves a timer alone when the deadline moves later.
%% That is only safe within one space: a later application deadline must
%% still displace an armed handshake probe, or the handshake space is
%% never probed and the connection stalls with a timer running.
later_deadline_in_another_space_rearms_test() ->
    Now = erlang:monotonic_time(millisecond),
    Handshake = quic_loss:on_packet_sent(handshake, quic_loss:new(), 0, 1200, true, [ping], Now),
    S1 = quic_connection:set_pto_timer(state_with(Handshake, handshake)),
    First = quic_connection_test_support:state_get(S1, pto_timer),
    ?assert(is_reference(First)),
    %% The handshake flight is acknowledged and its space discarded, so
    %% only the application space is left, with a deadline well after the
    %% one already armed.
    {Discarded, _Bytes} = quic_loss:discard_space(handshake, Handshake),
    AppOnly = quic_loss:on_handshake_confirmed(
        quic_loss:on_packet_sent(app, Discarded, 0, 1200, true, [ping], Now + 5000)
    ),
    S2 = quic_connection:set_pto_timer(
        quic_connection_test_support:state_set(S1, loss_state, AppOnly)
    ),
    Second = quic_connection_test_support:state_get(S2, pto_timer),
    ?assertNotEqual(First, Second),
    erlang:cancel_timer(First),
    erlang:cancel_timer(Second).

%%====================================================================
%% Helpers
%%====================================================================

app_flight() ->
    quic_loss:on_packet_sent(
        app, quic_loss:new(), 0, 1200, true, [ping], erlang:monotonic_time(millisecond)
    ).

state_with(LossState, Space) ->
    quic_connection_test_support:state_with_loss(LossState, Space).
