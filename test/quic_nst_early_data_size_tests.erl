%%% -*- erlang -*-
%%%
%%% "A client MUST treat receipt of a NewSessionTicket that contains an
%%% early_data extension with any other value [than 0xffffffff] as a
%%% connection error of type PROTOCOL_VIOLATION" (RFC 9001 Section 4.6.1).
%%% One that does not decode is a decode_error.

-module(quic_nst_early_data_size_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

other_size_test() ->
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, close(1000)).

sentinel_size_test() ->
    ?assertEqual(undefined, close(16#ffffffff)).

%% RFC 9846 Section 4.7.1: a NewSessionTicket that does not decode.
truncated_ticket_test() ->
    ?assertEqual(
        {tls_alert, ?TLS_ALERT_DECODE_ERROR},
        close_on(<<7200:32, 0:32, 4, "nonc", 4:16, "tick", 0>>)
    ).

close(MaxEarlyData) ->
    Ext = <<16#00, 16#2a, 4:16, MaxEarlyData:32>>,
    close_on(<<7200:32, 0:32, 4, "nonc", 4:16, "tick", (byte_size(Ext)):16, Ext/binary>>).

close_on(Body) ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS} = S0,
    S = quic_connection:process_tls_messages(
        app, <<4, (byte_size(Body)):24, Body/binary>>, S0#state{
            owner = self(),
            alpn = <<"h3">>,
            hs = HS#hs{
                tls_state = handshake_complete,
                server_name = <<"example">>,
                master_secret = binary:copy(<<1>>, 32),
                tls_transcript = <<"transcript">>
            }
        }
    ),
    S#state.close_reason.
