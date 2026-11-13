%%% -*- erlang -*-
%%%
%%% Packets sent on the old path MUST NOT contribute to congestion
%%% control or RTT estimation for the new path (RFC 9000 Section 9.4).
%%% They stay tracked, so their data is still retransmitted if lost.

-module(quic_old_path_packets_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

no_rtt_sample_from_an_old_path_packet_test() ->
    S = quic_loss:reset_for_new_path(in_flight()),
    {S1, Acked, _, _} = quic_loss:on_ack_received(app, S, {ack, 3, 0, 2, []}, 1100),
    ?assertEqual(3, length(Acked)),
    ?assertNot(quic_rtt:has_sample(quic_loss:rtt(S1))).

rtt_sample_from_a_new_path_packet_test() ->
    S0 = quic_loss:reset_for_new_path(in_flight()),
    S = quic_loss:on_packet_sent(app, S0, 4, 1200, true, [], 1050),
    {S1, _, _, _} = quic_loss:on_ack_received(app, S, {ack, 4, 0, 0, []}, 1100),
    ?assert(quic_rtt:has_sample(quic_loss:rtt(S1))).

old_path_acks_do_not_grow_the_window_test() ->
    S = quic_loss:reset_for_new_path(in_flight()),
    CC0 = quic_cc:on_packet_sent(quic_cc:new(#{}), 3400),
    {S1, Acked, _, _} = quic_loss:on_ack_received(app, S, {ack, 3, 0, 2, []}, 1100),
    CC = quic_connection:cc_after_ack(CC0, 3400, 1020, true, Acked, app, S1),
    ?assertEqual(quic_cc:cwnd(CC0), quic_cc:cwnd(CC)),
    ?assertEqual(0, quic_cc:bytes_in_flight(CC)).

old_path_losses_are_no_congestion_event_test() ->
    S = quic_loss:reset_for_new_path(in_flight()),
    CC0 = quic_cc:on_packet_sent(quic_cc:new(#{}), 3400),
    Lost = [
        #sent_packet{
            pn = N, time_sent = T, ack_eliciting = true, in_flight = true, size = Sz, frames = []
        }
     || {N, T, Sz} <- [{1, 1000, 1200}, {2, 1010, 1200}, {3, 1020, 1000}]
    ],
    CC = quic_connection:cc_after_loss(CC0, 3400, 1020, Lost, S),
    ?assertEqual(quic_cc:cwnd(CC0), quic_cc:cwnd(CC)),
    ?assertEqual(0, quic_cc:bytes_in_flight(CC)).

in_flight() ->
    S0 = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, S0, 1, 1200, true, [], 1000),
    S2 = quic_loss:on_packet_sent(app, S1, 2, 1200, true, [], 1010),
    quic_loss:on_packet_sent(app, S2, 3, 1000, true, [], 1020).
