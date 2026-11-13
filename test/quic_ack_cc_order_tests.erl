%%% -*- erlang -*-
%%%
%%% RFC 9002 Appendix A.7: an ACK's ECN counts and the losses it reveals
%%% reach the congestion controller before the packets it acknowledges.
%%% A packet sent before the recovery this ACK starts does not grow the
%%% window.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_ack_cc_order_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SIZE, 1200).

%% Packets 0 to 4 in flight; the ACK of packet 4 declares 0 and 1 lost.
ack_that_declares_a_loss_does_not_grow_cwnd_test() ->
    S0 = in_flight(5),
    %% The window after the cut alone.
    Cut = quic_cc:cwnd(quic_cc:on_congestion_event(cc(S0), erlang:monotonic_time(millisecond))),
    S1 = quic_connection:process_frame(initial, {ack, [{4, 0}], 0, undefined}, S0),
    CC = cc(S1),
    ?assert(quic_cc:in_recovery(CC)),
    ?assertEqual(Cut, quic_cc:cwnd(CC)),
    ?assertEqual(2 * ?SIZE, quic_cc:bytes_in_flight(CC)).

%% Without a loss the same ACK grows the window in slow start.
ack_without_loss_grows_cwnd_test() ->
    S0 = in_flight(5),
    Cwnd = quic_cc:cwnd(cc(S0)),
    S1 = quic_connection:process_frame(initial, {ack, [{4, 4}], 0, undefined}, S0),
    ?assertEqual(Cwnd + 5 * ?SIZE, quic_cc:cwnd(cc(S1))).

%%====================================================================
%% Helpers
%%====================================================================

in_flight(N) ->
    S0 = quic_connection_test_support:state_with_keys(client),
    Sent = erlang:monotonic_time(millisecond) - 100,
    L = lists:foldl(
        fun(PN, Acc) -> quic_loss:on_packet_sent(initial, Acc, PN, ?SIZE, true, [ping], Sent) end,
        quic_connection_test_support:loss_state(S0),
        lists:seq(0, N - 1)
    ),
    CC = lists:foldl(
        fun(_, Acc) -> quic_cc:on_packet_sent(Acc, ?SIZE) end, quic_cc:new(#{}), lists:seq(1, N)
    ),
    #state{hs = #hs{pn_initial = PNI} = HS} = S0,
    S1 = S0#state{hs = HS#hs{pn_initial = PNI#pn_space{next_pn = N}}},
    quic_connection_test_support:state_set(
        quic_connection_test_support:state_set(S1, loss_state, L), cc_state, CC
    ).

cc(#state{cc_state = CC}) -> CC.
