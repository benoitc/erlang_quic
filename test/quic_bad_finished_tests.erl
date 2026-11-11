%%% -*- erlang -*-
%%%
%%% A Finished that fails verification ends the handshake with a
%%% decrypt_error alert (RFC 8446 Section 4.4.4), QUIC error 0x0133.
%%% One of the wrong length ends it with decode_error, 0x0132, since
%%% verify_data is Hash.length bytes (RFC 9846 Section 4.5.3).

-module(quic_bad_finished_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SECRET, <<7:256>>).

server_finished_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECRYPT_ERROR}, close(client, awaiting_finished)
    ).

client_finished_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECRYPT_ERROR}, close(server, awaiting_client_finished)
    ).

short_server_finished_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR}, close(client, awaiting_finished, <<0:248>>)
    ).

short_client_finished_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR}, close(server, awaiting_client_finished, <<0:248>>)
    ).

long_client_finished_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR}, close(server, awaiting_client_finished, <<0:384>>)
    ).

close(Role, TlsState) ->
    close(Role, TlsState, <<0:256>>).

close(Role, TlsState, VerifyData) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(Role)
    ),
    #state{hs = HS} = S0,
    S = quic_connection:process_tls_messages(
        handshake, quic_tls:build_finished(VerifyData), S0#state{
            hs = HS#hs{
                tls_state = TlsState,
                tls_transcript = <<>>,
                handshake_secret = ?SECRET,
                client_hs_secret = ?SECRET,
                server_hs_secret = ?SECRET,
                master_secret = ?SECRET
            }
        }
    ),
    S#state.close_reason.
