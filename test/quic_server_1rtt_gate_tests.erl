%%% -*- erlang -*-
%%%
%%% RFC 9001 §5.7: a server must not process 1-RTT packets before the
%%% handshake completes, even when it already holds the keys.

-module(quic_server_1rtt_gate_tests).

-include_lib("eunit/include/eunit.hrl").

-define(SHORT_HEADER, <<16#40, "own-cid0", 0:(8 * 40)>>).

state(Role, TlsState) ->
    S0 = quic_connection_test_support:state_with_keys(Role),
    S1 = quic_connection_test_support:state_with_pn_app(S0, 0),
    quic_connection_test_support:state_set(S1, tls_state, TlsState).

server_drops_1rtt_before_client_finished_test() ->
    ?assertEqual(
        {error, handshake_incomplete},
        quic_connection:decode_short_header_packet(
            ?SHORT_HEADER, state(server, awaiting_client_finished)
        )
    ).

server_decrypts_1rtt_after_handshake_complete_test() ->
    ?assertNotEqual(
        {error, handshake_incomplete},
        quic_connection:decode_short_header_packet(
            ?SHORT_HEADER, state(server, handshake_complete)
        )
    ).

client_decrypts_1rtt_before_handshake_complete_test() ->
    ?assertNotEqual(
        {error, handshake_incomplete},
        quic_connection:decode_short_header_packet(
            ?SHORT_HEADER, state(client, awaiting_finished)
        )
    ).
