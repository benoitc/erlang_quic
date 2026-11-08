%%% -*- erlang -*-
%%%
%%% A cipher suite is only used when both sides allow it (RFC 8446
%%% Section 4.1.1), never taken as a default when they do not.

-module(quic_cipher_suite_fallback_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

no_common_suite_test() ->
    ?assertEqual(
        none, quic_tls_negotiation:select_cipher([?TLS_AES_256_GCM_SHA384], [aes_128_gcm])
    ).

server_without_a_common_suite_aborts_test() ->
    {CH, _, _} = quic_tls:build_client_hello(#{
        server_name => <<"localhost">>,
        alpn => [<<"h3">>],
        ciphers => [aes_256_gcm],
        transport_params => #{}
    }),
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    S = quic_connection:process_tls_messages(initial, CH, S0#state{
        cfg = Cfg#conn_cfg{
            cipher_preference = [aes_128_gcm], tls_groups = [x25519], alpn_list = [<<"h3">>]
        },
        hs = HS#hs{tls_state = awaiting_client_hello, tls_transcript = <<>>}
    }),
    ?assertEqual({tls_alert, ?TLS_ALERT_HANDSHAKE_FAILURE}, S#state.close_reason).
