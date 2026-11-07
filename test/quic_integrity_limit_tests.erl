%%% -*- erlang -*-
%%%
%%% Received packets that fail authentication are counted over the
%%% connection; past the AEAD's integrity limit it closes with
%%% AEAD_LIMIT_REACHED (RFC 9001 Section 6.6).

-module(quic_integrity_limit_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

failed_packets_are_counted_test() ->
    S = quic_connection:handle_packet_loop(forged(state()), state()),
    ?assertEqual(1, S#state.auth_failures),
    ?assertEqual(undefined, S#state.close_reason).

past_the_limit_closes_test() ->
    S0 = (state())#state{auth_failures = 1 bsl 52},
    S = quic_connection:handle_packet_loop(forged(S0), S0),
    ?assertMatch({transport, ?QUIC_AEAD_LIMIT_REACHED, _}, S#state.close_reason).

state() ->
    S0 = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_pn_app(
            quic_connection_test_support:state_with_keys(server), 10
        )
    ),
    S0#state{hs = (S0#state.hs)#hs{tls_state = handshake_complete}}.

forged(#state{cfg = #conn_cfg{scid = SCID}}) ->
    <<16#40, SCID/binary, (binary:copy(<<7>>, 40))/binary>>.
