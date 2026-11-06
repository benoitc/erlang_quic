%%% -*- erlang -*-
%%%
%%% Once a client has a valid Initial from the server, it discards packets
%%% with another Source Connection ID (RFC 9000 Section 7.2), and it
%%% discards a server Initial that carries a token (Section 17.2.2).

-module(quic_client_server_scid_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SERVER_CID, <<"server-c">>).

other_scid_discarded_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(handshake_packet(<<"other-sc">>, S0), S0),
    ?assertEqual(undefined, handshake_largest(S)).

same_scid_accepted_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(handshake_packet(?SERVER_CID, S0), S0),
    ?assertEqual(0, handshake_largest(S)).

server_initial_with_token_discarded_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(initial_packet(<<"token">>, S0), S0),
    ?assertEqual(0, initial_largest(S)).

%% A client that has processed the server's Initial 0 from ?SERVER_CID.
client() ->
    #state{hs = HS, cid_pool_state = Pool} =
        S = quic_connection_test_support:state_sending(
            quic_connection_test_support:state_with_keys(client)
        ),
    S#state{
        dcid = ?SERVER_CID,
        cid_pool_state = quic_cid:set_initial_peer_cid(
            quic_cid_pool(Pool), ?SERVER_CID, undefined
        ),
        hs = HS#hs{pn_initial = (HS#hs.pn_handshake)#pn_space{largest_recv = 0}}
    }.

quic_cid_pool(undefined) -> quic_cid:new(<<"own-cid0">>, 2);
quic_cid_pool(Pool) -> Pool.

handshake_packet(SCID, #state{hs = #hs{handshake_keys = {_, ServerKeys}}}) ->
    protect(ServerKeys, <<16#E0, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, SCID/binary>>).

initial_packet(Token, #state{hs = #hs{initial_keys = {_, ServerKeys}}}) ->
    protect(
        ServerKeys,
        <<16#C0, ?QUIC_VERSION_1:32, 8, "own-cid0", 8, ?SERVER_CID/binary,
            (quic_varint:encode(byte_size(Token)))/binary, Token/binary>>,
        1
    ).

protect(Keys, Header) ->
    protect(Keys, Header, 0).

protect(#crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher}, Header, PN) ->
    Payload = <<16#01, 0, 0, 0, 0>>,
    Prefix = <<Header/binary, (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, PN, Prefix, Payload).

handshake_largest(#state{hs = #hs{pn_handshake = #pn_space{largest_recv = L}}}) -> L.

initial_largest(#state{hs = #hs{pn_initial = #pn_space{largest_recv = L}}}) -> L.
