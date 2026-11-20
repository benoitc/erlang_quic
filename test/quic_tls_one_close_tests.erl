%%% -*- erlang -*-
%%%
%%% A closing connection repeats the CONNECTION_CLOSE it sent rather than
%%% sending a different one (RFC 9000 Section 10.2.1).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_tls_one_close_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

%% certificate_request_context <<>>, certificate_list <<>>.
-define(EMPTY_CERTIFICATE, <<?TLS_CERTIFICATE, 4:24, 0, 0:24>>).
-define(FINISHED, <<?TLS_FINISHED, 32:24, 0:256>>).

a_second_close_sends_nothing_test() ->
    S0 = server(),
    S1 = quic_connection:send_tls_alert(?TLS_ALERT_CERTIFICATE_REQUIRED, S0),
    Sent = packets_sent(S1),
    ?assert(Sent > 0),
    S2 = quic_connection:send_tls_alert(?TLS_ALERT_UNEXPECTED_MESSAGE, S1),
    ?assertEqual({tls_alert, ?TLS_ALERT_CERTIFICATE_REQUIRED}, close_reason(S2)),
    ?assertEqual(Sent, packets_sent(S2)),
    ?assertEqual(S1#state.closing_frame, S2#state.closing_frame).

%%====================================================================
%% Helpers
%%====================================================================

%% Built anew each time: the packet counter is shared by copies of a state.
server() ->
    quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ).

close_reason(#state{close_reason = Reason}) -> Reason.

packets_sent(State) ->
    quic_connection_test_support:state_get(State, packets_sent).
