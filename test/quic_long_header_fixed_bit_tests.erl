%%% -*- erlang -*-
%%%
%%% A long-header packet with the fixed bit (0x40) cleared is not a QUIC
%%% version 1 packet and is discarded (RFC 9000 Section 17.2); only
%%% Version Negotiation leaves it unset.

-module(quic_long_header_fixed_bit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

discarded_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(handshake_packet(16#E0 band bnot 16#40, S0), S0),
    ?assertEqual(undefined, handshake_largest(S)).

accepted_with_the_bit_set_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(handshake_packet(16#E0, S0), S0),
    ?assertEqual(0, handshake_largest(S)).

client() ->
    quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ).

handshake_packet(FirstByte, #state{hs = #hs{handshake_keys = {_, ServerKeys}}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    Payload = <<16#01, 0, 0, 0, 0>>,
    Prefix =
        <<FirstByte, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, "peer-cid",
            (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, 0, Prefix, Payload).

handshake_largest(#state{hs = #hs{pn_handshake = #pn_space{largest_recv = L}}}) -> L.
