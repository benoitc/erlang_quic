%%% -*- erlang -*-
%%%
%%% A long-header packet that cannot be decrypted does not take the
%%% packets coalesced after it down with it (RFC 9000 Section 12.2).

-module(quic_coalesced_undecryptable_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

handshake_after_initial_without_keys_test() ->
    #state{hs = HS} = S0 = client(),
    S = quic_connection:handle_packet_loop(
        <<(initial_packet())/binary, (handshake_packet(S0))/binary>>,
        S0#state{hs = HS#hs{initial_keys = undefined}}
    ),
    ?assertEqual(0, handshake_largest_recv(S)).

handshake_after_initial_failing_decryption_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(
        <<(initial_packet())/binary, (handshake_packet(S0))/binary>>, S0
    ),
    ?assertEqual(0, handshake_largest_recv(S)).

%% Once Handshake keys are discarded a late Handshake packet is dropped,
%% and the 1-RTT packet after it is still read.
app_after_handshake_with_discarded_keys_test() ->
    #state{hs = HS} = S0 = quic_connection_test_support:state_with_pn_app(client(), 0),
    Datagram = <<(handshake_packet(S0))/binary, (app_packet(S0, 3))/binary>>,
    S = quic_connection:handle_packet_loop(Datagram, S0#state{
        hs = HS#hs{handshake_keys = undefined}
    }),
    ?assertEqual(3, quic_connection:get_largest_recv(app, S)).

app_packet(#state{app_keys = {_, ServerKeys}}, PN) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, PN, 16#40, <<"own-cid0">>, <<1, 0:(8 * 20)>>
    ).

client() ->
    quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ).

initial_packet() ->
    Junk = crypto:strong_rand_bytes(40),
    <<16#C0, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, "peer-cid", 0,
        (quic_varint:encode(byte_size(Junk)))/binary, Junk/binary>>.

handshake_packet(#state{hs = #hs{handshake_keys = {_, ServerKeys}}}) ->
    #crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher} = ServerKeys,
    Payload = <<16#01, 0, 0, 0, 0>>,
    Len = 1 + byte_size(Payload) + 16,
    Prefix =
        <<16#E0, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, "peer-cid",
            (quic_varint:encode(Len))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, 0, Prefix, Payload).

handshake_largest_recv(#state{hs = #hs{pn_handshake = #pn_space{largest_recv = L}}}) ->
    L.
