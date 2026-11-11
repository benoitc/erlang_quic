%%% -*- erlang -*-
%%%
%%% An ACK frame whose ranges reach below packet number 0 is a
%%% FRAME_ENCODING_ERROR (RFC 9000 Section 19.3.1).

-module(quic_ack_negative_pn_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

first_range_below_zero_test_() ->
    [
        ?_assertMatch(
            {transport, ?QUIC_FRAME_ENCODING_ERROR, _}, close_reason(Level, <<2, 2, 0, 0, 3>>)
        )
     || Level <- [initial, handshake, app]
    ].

later_range_below_zero_test_() ->
    [
        ?_assertMatch(
            {transport, ?QUIC_FRAME_ENCODING_ERROR, _},
            close_reason(Level, <<2, 2, 0, 1, 0, 0, 1>>)
        )
     || Level <- [initial, handshake, app]
    ].

ranges_down_to_zero_test_() ->
    [
        ?_assertEqual(undefined, close_reason(Level, <<2, 2, 0, 1, 0, 0, 0>>))
     || Level <- [initial, handshake, app]
    ].

%% Packets 0..2 sent in every space.
close_reason(Level, Bin) ->
    {Frame, <<>>} = quic_frame:decode(Bin),
    Now = erlang:monotonic_time(millisecond),
    L0 = quic_loss:new(),
    L = lists:foldl(
        fun(PN, Acc) -> quic_loss:on_packet_sent(Level, Acc, PN, 1200, true, [], Now) end,
        L0,
        [0, 1, 2]
    ),
    S0 = quic_connection_test_support:state_with_sent_pns(
        quic_connection_test_support:with_keys_and_socket(
            quic_connection_test_support:state_with_loss(L)
        ),
        3
    ),
    quic_connection_test_support:close_reason(quic_connection:process_frame(Level, Frame, S0)).
