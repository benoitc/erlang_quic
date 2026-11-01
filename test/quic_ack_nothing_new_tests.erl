%%% -*- erlang -*-
%%%
%%% An ACK that acknowledges no new packet leaves the PTO backoff alone
%%% (RFC 9002 Appendix A.7: OnAckReceived returns early when nothing is
%%% newly acknowledged).

-module(quic_ack_nothing_new_tests).

-include_lib("eunit/include/eunit.hrl").

keeps_backoff_test() ->
    {LS, Acked, _, _} = ack(3, backed_off()),
    ?assertEqual([], Acked),
    ?assertEqual(2, quic_loss:pto_count(LS)).

resets_backoff_on_new_ack_test() ->
    {LS, [_], _, _} = ack(5, backed_off()),
    ?assertEqual(0, quic_loss:pto_count(LS)).

%% Packet 3 acknowledged, packet 5 in flight, two PTOs since.
backed_off() ->
    Now = erlang:monotonic_time(millisecond),
    LS0 = quic_loss:on_packet_sent(app, quic_loss:new(), 3, 1200, true, [ping], Now),
    LS1 = quic_loss:on_packet_sent(app, LS0, 5, 1200, true, [ping], Now),
    {LS2, [_], _, _} = quic_loss:on_ack_received(app, LS1, {ack, 3, 0, 0, []}, Now),
    quic_loss:on_pto_expired(quic_loss:on_pto_expired(LS2)).

ack(PN, LS) ->
    quic_loss:on_ack_received(app, LS, {ack, PN, 0, 0, []}, erlang:monotonic_time(millisecond)).
