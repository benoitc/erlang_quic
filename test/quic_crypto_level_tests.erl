%%% -*- erlang -*-
%%%
%%% Once TLS has moved to a higher encryption level, CRYPTO data at a
%%% previous level must not extend past what was received there, and
%%% none of it may be left unconsumed; either is a PROTOCOL_VIOLATION
%%% (RFC 9001 Section 4.1.3). Retransmissions within it are ignored.

-module(quic_crypto_level_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SECRET, <<7:256>>).

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

finished_completes_test() ->
    S = crypto(handshake, 0, finished(), client_awaiting_finished()),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual(handshake_complete, (S#state.hs)#hs.tls_state).

finished_retransmission_test() ->
    Finished = finished(),
    S1 = crypto(handshake, 0, Finished, client_awaiting_finished()),
    S = crypto(handshake, 0, Finished, S1),
    ?assertEqual(undefined, S#state.close_reason).

fragment_after_finished_test() ->
    S = crypto(
        handshake, 0, <<(finished())/binary, ?TLS_FINISHED, 0, 0>>, client_awaiting_finished()
    ),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

message_after_finished_test() ->
    S = crypto(
        handshake, 0, <<(finished())/binary, ?TLS_FINISHED, 0:24>>, client_awaiting_finished()
    ),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

out_of_order_data_after_finished_test() ->
    S1 = crypto(handshake, 100, <<?TLS_FINISHED, 0:24>>, client_awaiting_finished()),
    ?assertEqual(undefined, S1#state.close_reason),
    S = crypto(handshake, 0, finished(), S1),
    ?assertMatch({transport, ?QUIC_PROTOCOL_VIOLATION, _}, S#state.close_reason).

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

client_awaiting_finished() ->
    S0 = quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(client)
    ),
    #state{hs = HS} = S0,
    S0#state{
        hs = HS#hs{
            tls_state = awaiting_finished,
            tls_transcript = <<>>,
            handshake_secret = ?SECRET,
            client_hs_secret = ?SECRET,
            server_hs_secret = ?SECRET
        }
    }.

finished() ->
    Key = quic_crypto:derive_finished_key(aes_128_gcm, ?SECRET),
    Hash = quic_crypto:transcript_hash(aes_128_gcm, <<>>),
    quic_tls:build_finished(quic_crypto:compute_finished_verify(aes_128_gcm, Key, Hash)).
