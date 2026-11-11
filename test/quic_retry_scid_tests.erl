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
    S0 = client(),
    S = quic_connection:handle_packet_loop(retry(?ODCID), S0),
    ?assertEqual(?ODCID, S#state.dcid),
    ?assertNot((S#state.hs)#hs.retry_received).

retry_with_a_new_scid_accepted_test() ->
    S0 = client(),
    S = quic_connection:handle_packet_loop(retry(<<"retry-sc">>), S0),
    ?assertEqual(<<"retry-sc">>, S#state.dcid),
    ?assert((S#state.hs)#hs.retry_received).

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
