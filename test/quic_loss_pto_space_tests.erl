%%% -*- erlang -*-
%%%
%%% Which packet number space the loss-detection timer is armed for.
%%%
%%% RFC 9002 Appendix A.8 picks one deadline across the three spaces and
%%% reports which space it belongs to, because the fire handler has to
%%% probe at that encryption level. Two rules in it are easy to get
%%% backwards and are what these cases pin:
%%%
%%%   - the Application Data space is skipped entirely until the
%%%     handshake is confirmed (Section 6.2.1 makes that a MUST NOT),
%%%   - with nothing ack-eliciting in flight anywhere, the anti-deadlock
%%%     timer still arms, and it is the client's, to keep it sending so
%%%     a server blocked by the anti-amplification limit is unblocked.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_loss_pto_space_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(NOW, 1000).

%%====================================================================
%% Section 6.2.1: no application PTO before confirmation
%%====================================================================

%% The defect this work exists to fix. An ack-eliciting application
%% packet is in flight and the handshake is not confirmed, so there is
%% nothing to arm.
app_pto_not_armed_before_confirmation_test() ->
    S = sent(app, quic_loss:new()),
    ?assertEqual(none, quic_loss:get_pto_time_and_space(S, ?NOW, validated())).

%% Once confirmed the same state arms for app.
app_pto_armed_after_confirmation_test() ->
    S = quic_loss:on_handshake_confirmed(sent(app, quic_loss:new())),
    ?assertMatch({_, app}, quic_loss:get_pto_time_and_space(S, ?NOW, validated())).

%% A handshake flight is probed while the application one waits, so an
%% unconfirmed connection with both in flight arms for handshake.
handshake_preempts_app_before_confirmation_test() ->
    S = sent(app, sent(handshake, quic_loss:new())),
    ?assertMatch({_, handshake}, quic_loss:get_pto_time_and_space(S, ?NOW, validated())).

%% The earliest deadline wins across spaces. Initial went out first, so
%% its deadline comes first.
earliest_deadline_wins_test() ->
    S0 = quic_loss:on_packet_sent(initial, quic_loss:new(), 0, 1200, true, [ping], 100),
    S1 = quic_loss:on_packet_sent(handshake, S0, 0, 1200, true, [ping], 500),
    ?assertMatch({_, initial}, quic_loss:get_pto_time_and_space(S1, ?NOW, validated())).

%% Initial and Handshake use max_ack_delay 0, application adds it
%% (Section 6.2.1), so the two differ by exactly that, backoff included.
app_pto_adds_max_ack_delay_test() ->
    S = quic_loss:on_handshake_confirmed(quic_loss:set_peer_ack_params(quic_loss:new(), 3, 10)),
    ?assertEqual(10, quic_loss:get_pto(S, app) - quic_loss:get_pto(S, handshake)),
    S2 = quic_loss:on_pto_expired(quic_loss:on_pto_expired(S)),
    ?assertEqual(10 bsl 2, quic_loss:get_pto(S2, app) - quic_loss:get_pto(S2, handshake)).

%% The backoff is connection-wide, not per space.
backoff_is_shared_across_spaces_test() ->
    S0 = quic_loss:new(),
    Before = [quic_loss:get_pto(S0, Sp) || Sp <- [initial, handshake, app]],
    S1 = quic_loss:on_pto_expired(S0),
    After = [quic_loss:get_pto(S1, Sp) || Sp <- [initial, handshake, app]],
    ?assertEqual([B * 2 || B <- Before], After).

%%====================================================================
%% Appendix A.8: the anti-deadlock timer
%%====================================================================

%% Nothing in flight anywhere and the peer has not validated our
%% address: a client must keep probing or the handshake stalls. With
%% Handshake keys the probe belongs to that space.
anti_deadlock_uses_handshake_when_keys_exist_test() ->
    ?assertMatch(
        {_, handshake},
        quic_loss:get_pto_time_and_space(quic_loss:new(), ?NOW, #handshake_status{
            has_handshake_keys = true, peer_completed_address_validation = false
        })
    ).

%% Without them it is the Initial space.
anti_deadlock_uses_initial_without_keys_test() ->
    ?assertMatch(
        {_, initial},
        quic_loss:get_pto_time_and_space(quic_loss:new(), ?NOW, #handshake_status{
            has_handshake_keys = false, peer_completed_address_validation = false
        })
    ).

%% Anchored at now, not at a send that never happened.
anti_deadlock_is_anchored_at_now_test() ->
    {Deadline, _} = quic_loss:get_pto_time_and_space(quic_loss:new(), ?NOW, #handshake_status{
        has_handshake_keys = true, peer_completed_address_validation = false
    }),
    ?assertEqual(?NOW + quic_loss:get_pto(quic_loss:new(), handshake), Deadline).

%% Once the peer has validated our address there is nothing to unblock,
%% so an empty connection arms nothing.
nothing_in_flight_and_validated_arms_nothing_test() ->
    ?assertEqual(none, quic_loss:get_pto_time_and_space(quic_loss:new(), ?NOW, validated())).

%%====================================================================
%% Helpers
%%====================================================================

%% Peer has completed address validation, which is always true for a
%% server and true for a client once a Handshake ACK has arrived.
validated() ->
    #handshake_status{has_handshake_keys = true, peer_completed_address_validation = true}.

sent(Space, State) ->
    quic_loss:on_packet_sent(Space, State, 0, 1200, true, [ping], 100).
