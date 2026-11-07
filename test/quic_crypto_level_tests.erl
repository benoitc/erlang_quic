%%% -*- erlang -*-
%%%
%%% Once TLS has moved to a higher encryption level, CRYPTO data at a
%%% previous level must not extend past what was received there; that is
%%% a PROTOCOL_VIOLATION (RFC 9001 Section 4.1.3). Retransmissions within
%%% it are ignored.

-module(quic_crypto_level_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

fragment_past_end_test() ->
    S = crypto(initial, 10, <<?TLS_CLIENT_HELLO, 0, 0>>, server_past_initial()),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

message_past_end_test() ->
    S = crypto(initial, 10, <<?TLS_CLIENT_HELLO, 0:24>>, server_past_initial()),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

retransmission_test() ->
    S = crypto(initial, 0, <<0:80>>, server_past_initial()),
    ?assertEqual(undefined, S#state.close_reason).

straddling_retransmission_test() ->
    S = crypto(initial, 4, <<0:48>>, server_past_initial()),
    ?assertEqual(undefined, S#state.close_reason).

crypto(Level, Offset, Data, State) ->
    quic_connection:process_frame(Level, {crypto, Offset, Data}, State).

server_past_initial() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ),
    #state{hs = HS} = S0,
    S0#state{
        hs = HS#hs{
            pn_initial = HS#hs.pn_handshake,
            tls_state = awaiting_client_finished,
            crypto_offset = #{initial => 10, handshake => 0, app => 0}
        }
    }.
