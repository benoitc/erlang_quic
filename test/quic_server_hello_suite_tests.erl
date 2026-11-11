%%% -*- erlang -*-
%%%
%%% A ServerHello selecting a cipher suite the client did not offer is an
%%% illegal_parameter (RFC 9846 Section 4.2.3), whether or not the suite
%%% is one the client knows.

-module(quic_server_hello_suite_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

offered_suite_test() ->
    ?assertEqual(undefined, close(?TLS_AES_128_GCM_SHA256)).

unknown_suite_test() ->
    ?assertEqual({tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER}, close(16#1304)).

unknown_suite_in_hello_retry_request_test() ->
    ?assertEqual({tls_alert, ?TLS_ALERT_ILLEGAL_PARAMETER}, close_hrr(16#1304)).

close(Suite) ->
    {Msg, _} = quic_tls:build_server_hello(#{}),
    process(with_suite(Msg, Suite)).

close_hrr(Suite) ->
    Msg = quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, x25519),
    process(with_suite(Msg, Suite)).

with_suite(
    <<Type, Len:24, V:16, Random:32/binary, SidLen, Sid:SidLen/binary, _:16, Rest/binary>>, Suite
) ->
    <<Type, Len:24, V:16, Random/binary, SidLen, Sid/binary, Suite:16, Rest/binary>>.

process(Msg) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS, cfg = Cfg} = S0,
    {_, Priv} = quic_crypto:generate_key_pair(x25519),
    S = quic_connection:process_tls_messages(initial, Msg, S0#state{
        cfg = Cfg#conn_cfg{cipher_preference = [aes_128_gcm], tls_groups = [x25519]},
        hs = HS#hs{
            pn_initial = HS#hs.pn_handshake,
            tls_state = awaiting_server_hello,
            tls_group = x25519,
            tls_private_key = Priv,
            tls_transcript = <<>>,
            tls_ch1_opts = #{}
        }
    }),
    S#state.close_reason.
