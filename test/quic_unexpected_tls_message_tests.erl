%%% -*- erlang -*-
%%%
%%% A handshake message the TLS state machine is not waiting for is an
%%% unexpected_message (RFC 8446 Section 4; QUIC error 0x010a, RFC 9001
%%% Section 4.8), not something to ignore.

-module(quic_unexpected_tls_message_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

finished_before_server_hello_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_UNEXPECTED_MESSAGE},
        close(client, awaiting_server_hello, handshake, ?TLS_FINISHED)
    ).

second_client_hello_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_UNEXPECTED_MESSAGE},
        close(server, awaiting_client_finished, initial, ?TLS_CLIENT_HELLO)
    ).

close(Role, TlsState, Level, Type) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(Role)
    ),
    #state{hs = HS} = S0,
    S = quic_connection:process_tls_messages(Level, <<Type, 0:24>>, S0#state{
        hs = HS#hs{pn_initial = HS#hs.pn_handshake, tls_state = TlsState}
    }),
    S#state.close_reason.
