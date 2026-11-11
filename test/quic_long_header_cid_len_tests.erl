%%% -*- erlang -*-
%%%
%%% A version 1 long header with a Destination or Source Connection ID
%%% longer than 20 bytes is dropped (RFC 9000 Section 17.2). Version
%%% Negotiation is exempt: RFC 8999 allows up to 255 bytes there.

-module(quic_long_header_cid_len_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(ODCID, <<"orig-dci">>).
-define(SERVER_CID, <<"server-c">>).

client_drops_server_initial_with_long_scid_test() ->
    S0 = fresh_client(),
    S = handle(initial(server, <<"own-cid0">>, cid(21)), S0),
    ?assertEqual(?ODCID, S#state.dcid),
    ?assertEqual(undefined, initial_largest(S)).

client_accepts_server_initial_with_20_byte_scid_test() ->
    S0 = fresh_client(),
    S = handle(initial(server, <<"own-cid0">>, cid(20)), S0),
    ?assertEqual(cid(20), S#state.dcid),
    ?assertEqual(0, initial_largest(S)).

client_drops_handshake_with_long_dcid_test() ->
    S0 = client(),
    S = handle(handshake(server, cid(21), ?SERVER_CID), S0),
    ?assertEqual(undefined, handshake_largest(S)).

server_drops_client_initial_with_long_scid_test() ->
    S0 = (quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(server)
    ))#state{
        dcid = <<>>
    },
    S = handle(initial(client, <<"own-cid0">>, cid(21)), S0),
    ?assertEqual(<<>>, S#state.dcid),
    ?assertEqual(undefined, initial_largest(S)).

listener_drops_v1_long_dcid_test() ->
    ?assertMatch({error, _}, quic_listener:parse_packet_header(long_header(cid(21), cid(8)), 8)).

listener_drops_v1_long_scid_test() ->
    ?assertMatch({error, _}, quic_listener:parse_packet_header(long_header(cid(8), cid(21)), 8)).

listener_accepts_v1_20_byte_cids_test() ->
    ?assertMatch(
        {initial, _, _, ?QUIC_VERSION_1, _},
        quic_listener:parse_packet_header(long_header(cid(20), cid(20)), 8)
    ).

listener_negotiates_unknown_version_with_long_cids_test() ->
    Packet = <<16#C0, 16#0a0a0a0a:32, 255, (cid(255))/binary, 255, (cid(255))/binary>>,
    ?assertMatch(
        {unsupported_version, _, _, 16#0a0a0a0a}, quic_listener:parse_packet_header(Packet, 8)
    ).

handle(Packet, State) ->
    quic_connection:handle_packet_loop(Packet, State).

fresh_client() ->
    S = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(client)
    ),
    S#state{
        dcid = ?ODCID,
        cid_pool_state = quic_cid:new(<<"own-cid0">>, 2),
        cfg = (S#state.cfg)#conn_cfg{original_dcid = ?ODCID}
    }.

client() ->
    #state{hs = HS} = S = fresh_client(),
    S#state{
        dcid = ?SERVER_CID,
        cid_pool_state = quic_cid:set_initial_peer_cid(
            S#state.cid_pool_state, ?SERVER_CID, undefined
        ),
        hs = HS#hs{pn_initial = (HS#hs.pn_initial)#pn_space{largest_recv = 0}}
    }.

cid(Len) ->
    binary:copy(<<$c>>, Len).

long_header(DCID, SCID) ->
    <<16#C0, ?QUIC_VERSION_1:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary, 0,
        0>>.

initial(From, DCID, SCID) ->
    Keys = quic_connection:derive_initial_keys(<<"discard-cid">>, ?QUIC_VERSION_1),
    protect(
        sender_keys(From, Keys),
        <<16#C0, ?QUIC_VERSION_1:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)), SCID/binary,
            0>>
    ).

handshake(From, DCID, SCID) ->
    Keys = quic_connection:derive_initial_keys(<<"discard-cid">>, ?QUIC_VERSION_1),
    protect(
        sender_keys(From, Keys),
        <<16#E0, ?QUIC_VERSION_1:32, (byte_size(DCID)), DCID/binary, (byte_size(SCID)),
            SCID/binary>>
    ).

sender_keys(client, {ClientKeys, _}) -> ClientKeys;
sender_keys(server, {_, ServerKeys}) -> ServerKeys.

protect(#crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher}, Header) ->
    Payload = <<16#01, 0, 0, 0, 0>>,
    Prefix = <<Header/binary, (quic_varint:encode(1 + byte_size(Payload) + 16))/binary>>,
    quic_aead:protect_long_packet(Cipher, Key, IV, HP, 0, Prefix, Payload).

initial_largest(#state{hs = #hs{pn_initial = #pn_space{largest_recv = L}}}) -> L.

handshake_largest(#state{hs = #hs{pn_handshake = #pn_space{largest_recv = L}}}) -> L.
