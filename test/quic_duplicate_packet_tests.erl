%%% -*- erlang -*-
%%%
%%% A packet whose number was already received is discarded after
%%% decryption (RFC 9000 Section 12.3).

-module(quic_duplicate_packet_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

duplicate_short_header_packet_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(app_packet(3, S0), S0),
    ?assertEqual(100, S#state.max_data_remote).

fresh_short_header_packet_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(app_packet(6, S0), S0),
    ?assertEqual(1000, S#state.max_data_remote).

duplicate_in_a_batch_test() ->
    S = quic_connection:fold_opened([{3, 16#40, [{max_data, 1000}]}], client()),
    ?assertEqual(100, S#state.max_data_remote).

duplicate_handshake_packet_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(handshake_packet(3, S0), S0),
    ?assertEqual(0, ((S#state.hs)#hs.pn_handshake)#pn_space.recv_time).

client() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    S1 = quic_connection_test_support:state_with_pn_app(S0, 5),
    #state{hs = HS} = S1,
    S1#state{
        max_data_remote = 100,
        hs = HS#hs{
            pn_handshake = #pn_space{
                next_pn = 0,
                largest_recv = 5,
                recv_time = 0,
                ack_ranges = [{0, 5}],
                ack_eliciting_in_flight = 0
            }
        }
    }.

app_packet(PN, #state{app_keys = {_, ServerKeys}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    Payload = quic_frame:encode({max_data, 1000}),
    quic_aead:protect_short_packet(Cipher, Key, IV, HP, PN, 16#40, <<"own-cid0">>, [
        Payload, <<0, 0, 0>>
    ]).

handshake_packet(PN, #state{hs = #hs{handshake_keys = {_, ServerKeys}}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    Payload = <<16#01, 0, 0, 0, 0>>,
    Prefix =
        <<16#E0, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, "peer-cid",
            (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, PN, Prefix, Payload).
