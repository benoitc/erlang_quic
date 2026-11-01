%%% -*- erlang -*-
%%%
%%% An ACK whose largest acknowledged packet is ACK-only still gives an
%%% RTT sample when it newly acknowledges an ack-eliciting packet (RFC
%%% 9002 Section 5.1).

-module(quic_rtt_sample_ack_only_tests).

-include_lib("eunit/include/eunit.hrl").

samples_when_largest_is_ack_only_test() ->
    ?assertEqual(30, smoothed_after(false)).

samples_when_largest_is_ack_eliciting_test() ->
    ?assertEqual(30, smoothed_after(true)).

%% Packet 1 ack-eliciting, sent 100 ms ago; packet 2 sent 30 ms ago.
smoothed_after(LargestAckEliciting) ->
    Now = erlang:monotonic_time(millisecond),
    LS0 = quic_loss:on_packet_sent(app, quic_loss:new(), 1, 1200, true, [ping], Now - 100),
    LS1 = quic_loss:on_packet_sent(
        app, LS0, 2, 50, LargestAckEliciting, [{ack, 0, 0, 0, []}], Now - 30
    ),
    {LS, _, _, _} = quic_loss:on_ack_received(app, LS1, {ack, 2, 0, 1, []}, Now),
    quic_rtt:smoothed(quic_loss:rtt(LS)).
