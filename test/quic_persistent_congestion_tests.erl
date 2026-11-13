%%% -*- erlang -*-
%%%
%%% The persistent congestion period does not start until there is an RTT
%%% sample (RFC 9002 Section 7.6.2): only packets sent after the first
%%% sample count towards it.

-module(quic_persistent_congestion_tests).

-include_lib("eunit/include/eunit.hrl").

lost_handshake_probes_are_not_persistent_congestion_test() ->
    T0 = erlang:monotonic_time(millisecond),
    L0 = sent_at(initial, quic_loss:new(), T0, [0, 300, 900, 2100, 2200]),
    {_L, CC} = ack(initial, L0, quic_cc:new(), 4, T0 + 2250),
    ?assert(quic_cc:cwnd(CC) > minimum_window()).

blackout_after_the_first_sample_is_persistent_congestion_test() ->
    T0 = erlang:monotonic_time(millisecond),
    L0 = sent_at(app, quic_loss:new(), T0, [0]),
    {L1, CC1} = ack(app, L0, quic_cc:new(), 0, T0 + 50),
    L2 = sent_at(app, L1, T0, [100, 400, 1000, 1100], 1),
    {_L, CC} = ack(app, L2, CC1, 4, T0 + 1150),
    ?assertEqual(minimum_window(), quic_cc:cwnd(CC)).

sent_at(Space, L, T0, Offsets) ->
    sent_at(Space, L, T0, Offsets, 0).

sent_at(Space, L0, T0, Offsets, FirstPN) ->
    {L, _} = lists:foldl(
        fun(Offset, {L1, PN}) ->
            {quic_loss:on_packet_sent(Space, L1, PN, 1200, true, [ping], T0 + Offset), PN + 1}
        end,
        {L0, FirstPN},
        Offsets
    ),
    L.

ack(Space, L0, CC0, PN, Now) ->
    {L, _Acked, Lost, Meta} = quic_loss:on_ack_received(Space, L0, {ack, PN, 0, 0, []}, Now),
    CC1 = quic_cc:on_packets_acked(CC0, maps:get(acked_bytes, Meta), Now),
    CC = quic_connection:cc_after_loss(
        CC1,
        maps:get(lost_bytes, Meta, 0),
        maps:get(largest_lost_sent_time, Meta, undefined),
        Lost,
        L
    ),
    {L, CC}.

minimum_window() ->
    2 * 1200.
