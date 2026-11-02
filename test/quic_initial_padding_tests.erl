%%% -*- erlang -*-
%%%
%%% RFC 9000 Section 14.1: an Initial datagram reaches 1200 bytes through
%%% PADDING frames in the packet, so the packet's Length field covers the
%%% whole datagram.

-module(quic_initial_padding_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).

small_initial_is_padded_inside_the_packet_test() ->
    Datagram = send_initial(<<>>),
    ?assertEqual(1200, byte_size(Datagram)),
    ?assertEqual(byte_size(Datagram), packet_end(Datagram)).

token_does_not_push_the_packet_short_test() ->
    Datagram = send_initial(crypto:strong_rand_bytes(100)),
    ?assertEqual(1200, byte_size(Datagram)),
    ?assertEqual(byte_size(Datagram), packet_end(Datagram)).

send_initial(Token) ->
    {ok, Rx} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Rx),
    try
        S0 = ?S:with_keys_and_socket(?S:state_for_role(client)),
        #state{hs = #hs{pn_handshake = PN} = HS} = S0,
        S1 = S0#state{
            remote_addr = {{127, 0, 0, 1}, Port},
            hs = HS#hs{pn_initial = PN, retry_token = Token}
        },
        S2 = quic_connection:send_initial_packet(quic_frame:encode(ping), [ping], S1),
        _ = quic_connection:flush_socket_batch(S2),
        {ok, {_, _, Datagram}} = gen_udp:recv(Rx, 0, 1000),
        Datagram
    after
        gen_udp:close(Rx)
    end.

%% Offset just past the first packet, from its Length field.
packet_end(<<_, _:32, DL, _:DL/binary, SL, _:SL/binary, Rest0/binary>> = Datagram) ->
    {TokenLen, Rest1} = quic_varint:decode(Rest0),
    <<_:TokenLen/binary, Rest2/binary>> = Rest1,
    {Len, Rest3} = quic_varint:decode(Rest2),
    byte_size(Datagram) - byte_size(Rest3) + Len.
