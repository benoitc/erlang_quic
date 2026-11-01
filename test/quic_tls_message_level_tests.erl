%%% -*- erlang -*-
%%%
%%% Each TLS handshake message travels at one encryption level (RFC 9001
%%% Section 4.1.3, Figure 5); one at another level, and any KeyUpdate
%%% (RFC 9001 Section 6), is an unexpected_message, QUIC error 0x010a.

-module(quic_tls_message_level_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

rejected_test_() ->
    [
        {lists:flatten(io_lib:format("type ~p at ~p", [Type, Level])), fun() ->
            ?assertEqual({tls_alert, ?TLS_ALERT_UNEXPECTED_MESSAGE}, close(Role, Level, Type))
        end}
     || {Role, Level, Type} <- [
            {client, initial, ?TLS_ENCRYPTED_EXTENSIONS},
            {client, initial, ?TLS_CERTIFICATE},
            {client, initial, ?TLS_FINISHED},
            {client, handshake, ?TLS_SERVER_HELLO},
            {client, handshake, ?TLS_NEW_SESSION_TICKET},
            {client, app, ?TLS_KEY_UPDATE},
            {server, handshake, ?TLS_CLIENT_HELLO},
            {server, app, ?TLS_CERTIFICATE_REQUEST},
            {server, handshake, ?TLS_END_OF_EARLY_DATA}
        ]
    ].

close(Role, Level, Type) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(Role)
    ),
    #state{hs = HS} = S0,
    S = quic_connection:process_tls_messages(Level, <<Type, 0:24>>, S0#state{
        hs = HS#hs{pn_initial = HS#hs.pn_handshake}
    }),
    S#state.close_reason.
