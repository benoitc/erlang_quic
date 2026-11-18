%%% -*- erlang -*-
%%%
%%% "A server will always reject 0-RTT if it sends a TLS
%%% HelloRetryRequest" (RFC 9001 Section 4.6.2). The client kept its
%%% 0-RTT keys until EncryptedExtensions, so a write in between still
%%% went out as 0-RTT.

-module(quic_hrr_early_data_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

hrr_rejects_early_data_test() ->
    S0 = client_with_early_write(),
    ?assertMatch({_, _}, (S0#state.hs)#hs.early_keys),
    S1 = quic_connection:handle_hello_retry_request(
        #{cipher => aes_128_gcm, selected_group => secp256r1, cookie => undefined}, hrr(), S0
    ),
    ?assert((S1#state.hs)#hs.hrr_sent),
    ?assertEqual(undefined, (S1#state.hs)#hs.early_keys),
    ?assertEqual([[0]], rejections()),
    %% EncryptedExtensions without early_data finds nothing left to do.
    S2 = quic_connection:finalize_zero_rtt_state(S1),
    ?assertEqual(undefined, (S2#state.hs)#hs.early_keys),
    ?assertEqual([], rejections()).

%% Without 0-RTT a HelloRetryRequest tells the owner nothing.
hrr_without_early_data_test() ->
    S0 = quic_connection:send_client_hello(client()),
    S1 = quic_connection:handle_hello_retry_request(
        #{cipher => aes_128_gcm, selected_group => secp256r1, cookie => undefined}, hrr(), S0
    ),
    ?assert((S1#state.hs)#hs.hrr_sent),
    ?assertEqual([], rejections()).

rejections() ->
    receive
        {quic, _, {early_data_rejected, Ids}} -> [Ids | rejections()]
    after 0 -> []
    end.

hrr() ->
    quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, secp256r1).

%% A client that has sent its ClientHello and then Data on stream 0 as
%% 0-RTT.
client_with_early_write() ->
    S0 = quic_connection:send_client_hello(client()),
    #state{streams = Streams, pn_app = PNApp, hs = #hs{early_keys = EarlyKeys}} =
        quic_connection_test_support:zero_rtt_client([0]),
    S1 = S0#state{
        streams = Streams,
        pn_app = PNApp,
        max_data_remote = 1000000,
        hs = (S0#state.hs)#hs{early_keys = EarlyKeys}
    },
    {keep_state, S2, _} = quic_connection:zero_rtt_sends([{async, 0, <<"early">>, false}], S1),
    S2.

client() ->
    #state{cfg = Cfg} =
        S = quic_connection_test_support:state_sending(
            quic_connection_test_support:state_with_keys(client)
        ),
    S#state{
        owner = self(),
        version = ?QUIC_VERSION_1,
        max_data_local = 65536,
        max_streams_bidi_local = 10,
        max_streams_uni_local = 10,
        cfg = Cfg#conn_cfg{
            alpn_list = [<<"t">>],
            tls_groups = [x25519, secp256r1],
            max_stream_data_bidi_local = 65536,
            max_stream_data_bidi_remote = 65536,
            max_stream_data_uni = 65536,
            idle_timeout = 30000
        }
    }.
