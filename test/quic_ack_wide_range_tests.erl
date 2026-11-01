%%% -*- erlang -*-
%%%
%%% An ACK range may cover any number of packets (RFC 9000 Section
%%% 19.3.1). A peer that keeps acknowledging everything it has received
%%% sends a first range above 65536 after about 90 MB without loss.

-module(quic_ack_wide_range_tests).

-include_lib("eunit/include/eunit.hrl").

wide_first_range_test() ->
    ?assertEqual([{0, 100000}], quic_ack:ack_frame_to_ranges(100000, 100000, [])).

wide_later_range_test() ->
    ?assertEqual(
        [{200000, 200000}, {0, 199998}],
        quic_ack:ack_frame_to_ranges(200000, 0, [{0, 199998}])
    ).

acks_packets_under_a_wide_range_test() ->
    LS0 = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 1200, true),
    LS1 = quic_loss:on_packet_sent(app, LS0, 100000, 1200, true),
    {_, Acked, [], _} = quic_loss:on_ack_received(
        app, LS1, {ack, 100000, 0, 100000, []}, erlang:monotonic_time(millisecond)
    ),
    ?assertEqual(2, length(Acked)).
