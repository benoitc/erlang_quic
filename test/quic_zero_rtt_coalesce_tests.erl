%%% -*- erlang -*-
%%%
%%% Queued 0-RTT sends share packets, as 1-RTT sends do: a client that
%%% opens a stream per request must not send a datagram per request.

-module(quic_zero_rtt_coalesce_tests).

-include_lib("eunit/include/eunit.hrl").

queued_sends_share_a_packet_test() ->
    S0 = quic_connection_test_support:zero_rtt_client([0, 4, 8]),
    PN0 = quic_connection_test_support:next_app_pn(S0),
    self() ! {'$gen_call', {self(), make_ref()}, {send_data, 4, <<"GET /b\r\n">>, true}},
    self() ! {'$gen_call', {self(), make_ref()}, {send_data, 8, <<"GET /c\r\n">>, true}},
    From = {self(), make_ref()},
    {keep_state, S1, Replies} =
        quic_connection:zero_rtt_sends([{From, 0, <<"GET /a\r\n">>, true}], S0),
    ?assertEqual(3, length(Replies)),
    ?assertEqual([ok, ok, ok], [R || {reply, _, R} <- Replies]),
    ?assertEqual(PN0 + 1, quic_connection_test_support:next_app_pn(S1)).

large_batch_fills_packets_test() ->
    Ids = [4 * N || N <- lists:seq(0, 39)],
    S0 = quic_connection_test_support:zero_rtt_client(Ids),
    PN0 = quic_connection_test_support:next_app_pn(S0),
    Req = <<"GET /", (binary:copy(<<"x">>, 250))/binary, "\r\n">>,
    [self() ! {'$gen_call', {self(), make_ref()}, {send_data, Id, Req, true}} || Id <- tl(Ids)],
    {keep_state, S1, _} =
        quic_connection:zero_rtt_sends([{{self(), make_ref()}, hd(Ids), Req, true}], S0),
    Packets = quic_connection_test_support:next_app_pn(S1) - PN0,
    ?assert(Packets =< 10),
    ?assert(Packets >= 9).

pack_frames_keeps_order_and_budget_test() ->
    F = fun(Id) -> {stream, Id, 0, binary:copy(<<"y">>, 100), true} end,
    Frames = [F(Id) || Id <- lists:seq(0, 9)],
    Packets = quic_connection:pack_frames(Frames, 350),
    ?assertEqual(Frames, lists:append(Packets)),
    [
        ?assert(iolist_size([quic_frame:encode(Fr) || Fr <- P]) =< 350)
     || P <- Packets
    ],
    ?assertEqual(4, length(Packets)).

oversized_frame_goes_alone_test() ->
    Big = {stream, 0, 0, binary:copy(<<"z">>, 500), false},
    Small = {stream, 4, 0, <<"a">>, true},
    ?assertEqual([[Small], [Big], [Small]], quic_connection:pack_frames([Small, Big, Small], 100)).

queued_async_sends_share_a_packet_test() ->
    S0 = quic_connection_test_support:zero_rtt_client([0, 4, 8]),
    PN0 = quic_connection_test_support:next_app_pn(S0),
    self() ! {'$gen_cast', {send_data_async, 4, <<"GET /b\r\n">>, true}},
    self() ! {'$gen_cast', {send_data_async, 8, <<"GET /c\r\n">>, true}},
    {keep_state, S1, Replies} =
        quic_connection:zero_rtt_sends([{async, 0, <<"GET /a\r\n">>, true}], S0),
    ?assertEqual([], Replies),
    ?assertEqual(PN0 + 1, quic_connection_test_support:next_app_pn(S1)).
