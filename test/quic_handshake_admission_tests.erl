%%% -*- erlang -*-
%%%
%%% Handshake packets against the congestion window (RFC 9002 Section 7).
%%%
%%% Once Initial and Handshake packets are tracked they count against the
%%% window like any other, so they have to be admitted like any other.
%%% What makes that safe is the two exceptions: a refusal holds the
%%% frames rather than the encoded packet, so no packet number is spent
%%% and nothing is lost; and a probe is exempt, which is what stops a
%%% blocked connection deadlocking on its own window.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_handshake_admission_tests).

-include_lib("eunit/include/eunit.hrl").

%% A window with no room refuses, and the refusal costs nothing: the
%% packet number is still there to be used when the window reopens.
refusal_does_not_spend_a_packet_number_test() ->
    S0 = blocked_state(),
    Before = next_pn(S0),
    S1 = quic_connection:send_handshake_packet(payload(), frames(), S0),
    ?assertEqual(Before, next_pn(S1)),
    ?assertEqual(1, queued(handshake, S1)).

%% The frames are kept, not the encoded packet, so the packet is rebuilt
%% against whatever the window and packet number are by then.
refusal_queues_the_frames_test() ->
    S1 = quic_connection:send_handshake_packet(payload(), frames(), blocked_state()),
    ?assertEqual([{payload(), frames()}], pending(handshake, S1)).

%% Draining with the window still shut leaves the queue as it was, in
%% order, rather than dropping what it cannot send.
drain_into_a_shut_window_keeps_the_queue_test() ->
    S1 = quic_connection:send_handshake_packet(payload(), frames(), blocked_state()),
    S2 = quic_connection:send_handshake_packet(<<"second">>, [ping], S1),
    ?assertEqual(2, queued(handshake, S2)),
    S3 = quic_connection:drain_pending_hs(S2),
    ?assertEqual(
        [{payload(), frames()}, {<<"second">>, [ping]}],
        pending(handshake, S3)
    ).

%% A probe ignores the window entirely. Without this a connection whose
%% window is full of the very packets it needs to probe for could never
%% send the probe that would free it.
probe_bypasses_a_shut_window_test() ->
    S0 = quic_connection_test_support:state_set(blocked_state(), hs_probe, true),
    S1 = quic_connection:send_handshake_packet(payload(), frames(), S0),
    ?assertEqual(0, queued(handshake, S1)),
    ?assertEqual(next_pn(S0) + 1, next_pn(S1)).

%% Each space queues separately: an Initial refusal does not hold up
%% Handshake, and the drain visits both.
spaces_queue_separately_test() ->
    S1 = quic_connection:send_handshake_packet(payload(), frames(), blocked_state()),
    ?assertEqual(0, queued(initial, S1)),
    ?assertEqual(1, queued(handshake, S1)).

%%====================================================================
%% Helpers
%%====================================================================

payload() -> <<"handshake-crypto-payload">>.

frames() -> [{crypto, 0, <<"handshake-crypto-payload">>}].

%% A connection whose congestion window is entirely spoken for, so
%% admission refuses anything above the control allowance.
blocked_state() ->
    S = quic_connection_test_support:state_with_keys(server),
    CC = quic_cc:new(#{algorithm => newreno, initial_window => 1200}),
    quic_connection_test_support:state_set(
        S, cc_state, quic_cc:on_packet_sent(CC, 100000)
    ).

next_pn(State) ->
    quic_connection_test_support:state_get(State, handshake_next_pn).

pending(Space, State) ->
    maps:get(Space, quic_connection_test_support:state_get(State, pending_hs), []).

queued(Space, State) ->
    length(pending(Space, State)).
