%%% -*- erlang -*-
%%%
%%% 0-RTT shares the application packet number space, and its
%%% ack-eliciting packets are acknowledged like 1-RTT ones. A client
%%% whose early data goes unacknowledged has it all in flight, and a
%%% full congestion window holds back its Finished.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_zero_rtt_ack_tests).

-include_lib("eunit/include/eunit.hrl").

-define(S, quic_connection_test_support).

zero_rtt_stream_is_acked_like_1rtt_test() ->
    Frames = [{stream, 0, 0, <<"GET /\r\n">>, true}],
    S0 = ?S:state_owing_ack(0, false),
    App = ?S:ack_counters(quic_connection:maybe_send_ack(app, Frames, S0)),
    ZeroRTT = ?S:ack_counters(quic_connection:maybe_send_ack(zero_rtt, Frames, S0)),
    ?assertMatch(#{ack_elicited_count := 1}, ZeroRTT),
    ?assertEqual(maps:remove(ack_timer, App), maps:remove(ack_timer, ZeroRTT)),
    ?assertNotEqual(undefined, maps:get(ack_timer, ZeroRTT)).

zero_rtt_padding_is_not_acked_test() ->
    S0 = ?S:state_owing_ack(0, false),
    S1 = quic_connection:maybe_send_ack(zero_rtt, [padding], S0),
    ?assertEqual(?S:ack_counters(S0), ?S:ack_counters(S1)).
