%%% -*- erlang -*-
%%%
%%% A ClientHello, ServerHello or HelloRetryRequest that breaks a rule of
%%% RFC 9846 Sections 4.2 and 4.3 ends the handshake with the alert the
%%% RFC names for it.

-module(quic_tls_hello_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%%====================================================================
%% supported_versions (RFC 9846 Section 4.3.1)
%%====================================================================

server_hello_naming_tls13_test() ->
    ?assertEqual(undefined, client_close(server_hello())).

server_hello_without_supported_versions_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        client_close(without_ext(?EXT_SUPPORTED_VERSIONS, server_hello()))
    ).

server_hello_selecting_tls12_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        client_close(set_ext(?EXT_SUPPORTED_VERSIONS, <<?TLS_VERSION_1_2:16>>, server_hello()))
    ).

hello_retry_request_without_supported_versions_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        client_close(without_ext(?EXT_SUPPORTED_VERSIONS, hello_retry_request()))
    ).

hello_retry_request_selecting_tls12_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER},
        client_close(
            set_ext(?EXT_SUPPORTED_VERSIONS, <<?TLS_VERSION_1_2:16>>, hello_retry_request())
        )
    ).

client_hello_without_supported_versions_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        server_close(without_ext(?EXT_SUPPORTED_VERSIONS, client_hello()))
    ).

client_hello_offering_only_tls12_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_PROTOCOL_VERSION},
        server_close(set_ext(?EXT_SUPPORTED_VERSIONS, <<2, ?TLS_VERSION_1_2:16>>, client_hello()))
    ).

%%====================================================================
%% Messages
%%====================================================================

server_hello() ->
    {Msg, _} = quic_tls:build_server_hello(#{
        cipher_suite => ?TLS_AES_128_GCM_SHA256,
        key_pair => quic_crypto:generate_key_pair(x25519),
        key_share_group => x25519
    }),
    Msg.

hello_retry_request() ->
    quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, secp256r1).

client_hello() ->
    {CH, _, _} = quic_tls:build_client_hello(client_hello_opts()),
    CH.

client_hello_opts() ->
    #{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        transport_params => #{},
        groups => [x25519, secp256r1],
        ciphers => [aes_128_gcm]
    }.

without_ext(Type, Msg) ->
    map_exts(fun(Exts) -> lists:keydelete(Type, 1, Exts) end, Msg).

set_ext(Type, Data, Msg) ->
    map_exts(fun(Exts) -> lists:keyreplace(Type, 1, Exts, {Type, Data}) end, Msg).

%% Msg with its extension list passed through F.
map_exts(F, <<Type, _Len:24, Body/binary>>) ->
    {Head, Exts} = split_exts(Type, Body),
    {ok, Ordered} = quic_tls:parse_extensions_ordered(Exts),
    NewExts = iolist_to_binary([
        <<T:16, (byte_size(D)):16, D/binary>>
     || {T, D} <- F([{T, D} || {T, D, _, _} <- Ordered])
    ]),
    NewBody = <<Head/binary, (byte_size(NewExts)):16, NewExts/binary>>,
    <<Type, (byte_size(NewBody)):24, NewBody/binary>>.

split_exts(
    ?TLS_CLIENT_HELLO,
    <<V:16, R:32/binary, SL, S:SL/binary, CL:16, C:CL/binary, ML, M:ML/binary, EL:16, E:EL/binary>>
) ->
    {<<V:16, R/binary, SL, S/binary, CL:16, C/binary, ML, M/binary>>, E};
split_exts(
    ?TLS_SERVER_HELLO,
    <<V:16, R:32/binary, SL, S:SL/binary, Suite:16, M, EL:16, E:EL/binary>>
) ->
    {<<V:16, R/binary, SL, S/binary, Suite:16, M>>, E}.

%%====================================================================
%% Connections
%%====================================================================

%% How a client that sent client_hello/0 closes on Msg.
client_close(Msg) ->
    {CH1, Priv, Random} = quic_tls:build_client_hello(client_hello_opts()),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    S = quic_connection:process_tls_messages(initial, Msg, S0#state{
        cfg = Cfg#conn_cfg{cipher_preference = [aes_128_gcm], tls_groups = [x25519, secp256r1]},
        hs = HS#hs{
            pn_initial = HS#hs.pn_handshake,
            tls_state = awaiting_server_hello,
            tls_group = x25519,
            tls_private_key = Priv,
            tls_transcript = CH1,
            tls_ch1_random = Random,
            tls_ch1_opts = client_hello_opts()
        }
    }),
    S#state.close_reason.

%% How a server waiting for a ClientHello closes on Msg.
server_close(Msg) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    S = quic_connection:process_tls_messages(initial, Msg, S0#state{
        cfg = Cfg#conn_cfg{
            cipher_preference = [aes_128_gcm], tls_groups = [x25519], alpn_list = [<<"h3">>]
        },
        hs = HS#hs{tls_state = awaiting_client_hello, tls_transcript = <<>>}
    }),
    S#state.close_reason.
