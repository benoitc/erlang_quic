%%% -*- erlang -*-
%%%
%%% "A client MUST discard a Retry packet that contains a Source
%%% Connection ID field that is identical to the Destination Connection
%%% ID field of its Initial packet" (RFC 9000 Section 17.2.5.1).

-module(quic_retry_scid_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(ODCID, <<"orig-dci">>).
-define(SCID, <<"own-cid0">>).

retry_echoing_our_dcid_discarded_test() ->
    S0 = quic_connection:send_client_hello(client()),
    S = quic_connection:handle_packet_loop(retry(?ODCID), S0),
    ?assertEqual(?ODCID, S#state.dcid),
    ?assertNot((S#state.hs)#hs.retry_received).

retry_with_a_new_scid_accepted_test() ->
    S0 = quic_connection:send_client_hello(client()),
    S = quic_connection:handle_packet_loop(retry(<<"retry-sc">>), S0),
    ?assertEqual(<<"retry-sc">>, S#state.dcid),
    ?assert((S#state.hs)#hs.retry_received).

%% "A client MUST use the same cryptographic handshake message it
%% included in this packet" (RFC 9000 Section 17.2.5.3): the Initial
%% sent after a Retry carries the ClientHello of the first one, and the
%% key share and random behind it are kept.
retry_keeps_the_client_hello_test() ->
    S0 = quic_connection:send_client_hello(client()),
    #hs{tls_transcript = ClientHello, tls_private_key = PrivKey, tls_ch1_random = Random} =
        S0#state.hs,
    ?assertEqual(ClientHello, initial_crypto(S0)),
    S = quic_connection:handle_packet_loop(retry(<<"retry-sc">>), S0),
    ?assert((S#state.hs)#hs.retry_received),
    ?assertEqual(ClientHello, initial_crypto(S)),
    ?assertMatch(
        #hs{tls_transcript = ClientHello, tls_private_key = PrivKey, tls_ch1_random = Random},
        S#state.hs
    ).

%% The CRYPTO data of the Initial packets in flight, in offset order.
initial_crypto(#state{loss_state = LossState}) ->
    Chunks = lists:keysort(1, [
        {Offset, Data}
     || #sent_packet{frames = Frames} <- maps:values(quic_loss:sent_packets(initial, LossState)),
        {crypto, Offset, Data} <- Frames
    ]),
    iolist_to_binary([Data || {_, Data} <- Chunks]).

client() ->
    #state{cfg = Cfg, hs = HS} =
        S = quic_connection_test_support:state_sending(
            quic_connection_test_support:state_with_keys(client)
        ),
    S#state{
        dcid = ?ODCID,
        version = ?QUIC_VERSION_1,
        max_data_local = 65536,
        max_streams_bidi_local = 10,
        max_streams_uni_local = 10,
        cfg = Cfg#conn_cfg{
            original_dcid = ?ODCID,
            scid = ?SCID,
            alpn_list = [<<"t">>],
            max_stream_data_bidi_local = 65536,
            max_stream_data_bidi_remote = 65536,
            max_stream_data_uni = 65536,
            idle_timeout = 30000
        },
        hs = HS#hs{retry_received = false}
    }.

retry(RetrySCID) ->
    quic_packet:encode_retry(?ODCID, ?SCID, RetrySCID, <<"token">>, ?QUIC_VERSION_1).
