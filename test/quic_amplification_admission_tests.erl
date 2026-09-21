%%% -*- erlang -*-
%%%
%%% The two gates a pre-handshake packet has to pass.
%%%
%%% RFC 9000 Section 8.1 caps what an unvalidated server may send at
%%% three times what it received; RFC 9002 Section 7 caps what any
%%% sender may put in flight. They refuse for unrelated reasons, so a
%%% packet has to clear both, and clearing one says nothing about the
%%% other. In particular a flight accumulated while amplification-limited
%%% must not leave as a burst the moment the address is validated.
%%%
%%% Neither refusal may cost anything. A refused packet keeps its place
%%% in one queue, holding frames rather than an encoded packet, so the
%%% packet number, the send counter and the pacing allowance are spent
%%% once, when it actually goes out.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_amplification_admission_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% A refusal costs nothing
%%====================================================================

%% The window is wide open here, so the amplification budget is the only
%% thing refusing.
amplification_refusal_spends_nothing_test() ->
    S0 = amp_limited(),
    S1 = quic_connection:send_handshake_packet(payload(), frames(), S0),
    ?assertEqual(next_pn(S0), next_pn(S1)),
    ?assertEqual(packets_sent(S0), packets_sent(S1)),
    ?assertEqual(0, amp_tx(S1)),
    ?assertEqual(1, queued(handshake, S1)).

%% And it is charged exactly once, when it finally goes out: a packet
%% counted at both the deferral and the send would double-charge pacing
%% and the window.
a_released_packet_is_registered_once_test() ->
    S1 = quic_connection:send_handshake_packet(payload(), frames(), amp_limited()),
    ?assertEqual([], in_flight(S1)),
    S2 = quic_connection:drain_pending_hs(validated(S1)),
    ?assertEqual([0], in_flight(S2)),
    ?assertEqual(next_pn(S1) + 1, next_pn(S2)).

%%====================================================================
%% Both gates, every time
%%====================================================================

%% Set up in this order on purpose: a shut window refuses first, so the
%% packet would never reach the amplification check and the test would
%% not be testing anything. Defer on amplification with the window open,
%% then shut it before releasing.
a_released_packet_is_still_window_checked_test() ->
    S1 = quic_connection:send_handshake_packet(payload(), frames(), amp_limited()),
    ?assertEqual(1, queued(handshake, S1)),
    S2 = quic_connection:drain_pending_hs(shut_window(validated(S1))),
    %% Still held, by the window this time.
    ?assertEqual(1, queued(handshake, S2)),
    ?assertEqual(next_pn(S1), next_pn(S2)),
    ?assertEqual([], in_flight(S2)).

%%====================================================================
%% Order
%%====================================================================

%% One queue, so a flight comes back out in the order it was written,
%% once each. Two queues fed by two gates could not promise that.
drain_preserves_order_test() ->
    Flight = flight(5),
    S1 = lists:foldl(
        fun({P, F}, Acc) -> quic_connection:send_handshake_packet(P, F, Acc) end,
        amp_limited(),
        Flight
    ),
    ?assertEqual(Flight, pending(handshake, S1)),
    S2 = quic_connection:drain_pending_hs(validated(S1)),
    ?assertEqual([], pending(handshake, S2)),
    ?assertEqual(next_pn(S1) + 5, next_pn(S2)),
    ?assertEqual([0, 1, 2, 3, 4], in_flight(S2)).

%%====================================================================
%% Helpers
%%====================================================================

payload() -> <<"handshake-crypto-payload">>.

frames() -> [{crypto, 0, <<"handshake-crypto-payload">>}].

flight(Count) ->
    [
        begin
            Payload = <<"crypto-", (integer_to_binary(I))/binary>>,
            {Payload, [{crypto, I * 1000, Payload}]}
        end
     || I <- lists:seq(0, Count - 1)
    ].

%% A server that has not validated the peer address and has no budget
%% yet, with the default congestion window: whatever it refuses, it
%% refuses on amplification.
amp_limited() ->
    S = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(server)
    ),
    quic_connection_test_support:state_set(
        quic_connection_test_support:state_set(S, address_validated, false),
        amp_rx,
        0
    ).

validated(State) ->
    quic_connection_test_support:state_set(State, address_validated, true).

shut_window(State) ->
    CC = quic_cc:new(#{algorithm => newreno, initial_window => 1200}),
    quic_connection_test_support:state_set(
        State, cc_state, quic_cc:on_packet_sent(CC, 100000)
    ).

next_pn(State) ->
    quic_connection_test_support:state_get(State, handshake_next_pn).

packets_sent(State) ->
    quic_connection_test_support:state_get(State, packets_sent).

amp_tx(State) ->
    quic_connection_test_support:state_get(State, amp_tx).

%% Packet numbers currently tracked in the Handshake space, in order.
in_flight(State) ->
    lists:sort(
        maps:keys(
            quic_loss:sent_packets(handshake, quic_connection_test_support:loss_state(State))
        )
    ).

pending(Space, State) ->
    lists:reverse(maps:get(Space, quic_connection_test_support:state_get(State, pending_hs), [])).

queued(Space, State) ->
    length(pending(Space, State)).
