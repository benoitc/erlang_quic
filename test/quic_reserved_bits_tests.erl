%%% -*- erlang -*-
%%%
%%% Reserved header bits that are set once packet and header protection
%%% are removed are a PROTOCOL_VIOLATION (RFC 9000 Sections 17.2 and
%%% 17.3.1).

-module(quic_reserved_bits_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

short_header_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(app_packet(6, 16#40 bor 16#08, S0), S0),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

short_header_clear_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(app_packet(6, 16#40, S0), S0),
    ?assertEqual(undefined, S#state.close_reason).

long_header_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(handshake_packet(6, 16#E0 bor 16#04, S0), S0),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

batch_test() ->
    S = quic_connection:fold_opened([{8, 16#48, [ping]}], client()),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

contiguous_batch_test() ->
    S = quic_connection:fold_opened([{6, 16#40, [ping]}, {7, 16#50, [ping]}], client()),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

client() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    S1 = quic_connection_test_support:state_with_pn_app(S0, 5),
    #state{hs = HS} = S1,
    S1#state{hs = HS#hs{pn_handshake = S1#state.pn_app}}.

app_packet(PN, FirstByte, #state{app_keys = {_, ServerKeys}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, FirstByte, <<"own-cid0">>, [
        <<16#01, 0, 0, 0, 0>>
    ]).

handshake_packet(PN, FirstByte, #state{hs = #hs{handshake_keys = {_, ServerKeys}}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    Payload = <<16#01, 0, 0, 0, 0>>,
    Prefix =
        <<FirstByte, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, "peer-cid",
            (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, PN, Prefix, Payload).
