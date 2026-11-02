%%% -*- erlang -*-
%%%
%%% An ACK for a packet number not yet sent in its space is a
%%% PROTOCOL_VIOLATION (RFC 9000 Section 13.1).

-module(quic_ack_unsent_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

ack_of_unsent_packet_test_() ->
    [
        ?_assertMatch(
            {transport, ?QUIC_PROTOCOL_VIOLATION, _}, close_reason(Level, ack(3))
        )
     || Level <- [initial, handshake, app]
    ].

ack_of_last_sent_packet_test_() ->
    [?_assertEqual(undefined, close_reason(Level, ack(2))) || Level <- [initial, handshake, app]].

ack(Largest) ->
    {ack, [{Largest, 0}], 0, undefined}.

%% Packets 0..2 sent in every space.
close_reason(Level, Frame) ->
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
