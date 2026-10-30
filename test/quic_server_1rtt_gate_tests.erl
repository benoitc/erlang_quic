%%% -*- erlang -*-
%%%
%%% RFC 9001 §5.7: a server must not process 1-RTT packets before the
%%% handshake completes, even when it already holds the keys. It may
%%% buffer them, and does: a client whose request went out with its
%%% Finished need not retransmit what was never acknowledged, and quinn
%%% does not.

-module(quic_server_1rtt_gate_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

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

%% The batched fast path opens 1-RTT runs on its own, so it is gated too.
batched_open_waits_for_handshake_complete_test() ->
    ?assertEqual(no, quic_connection:fused_run_keys(state(server, awaiting_client_finished))).

held_1rtt_is_processed_once_complete_test() ->
    S0 = quic_connection:handle_packet_loop(
        client_1rtt(1), state(server, awaiting_client_finished)
    ),
    ?assertEqual(0, largest_recv(S0)),
    S1 = quic_connection:replay_early_1rtt(
        quic_connection_test_support:state_set(S0, tls_state, handshake_complete)
    ),
    ?assertEqual(1, largest_recv(S1)),
    ?assertEqual(S1, quic_connection:replay_early_1rtt(S1)).

held_1rtt_waits_while_incomplete_test() ->
    S0 = quic_connection:handle_packet_loop(
        client_1rtt(1), state(server, awaiting_client_finished)
    ),
    ?assertEqual(0, largest_recv(quic_connection:replay_early_1rtt(S0))).

%% Only a few are held; a peer cannot make the server store more.
holding_is_bounded_test() ->
    S0 = lists:foldl(
        fun(PN, Acc) -> quic_connection:handle_packet_loop(client_1rtt(PN), Acc) end,
        state(server, awaiting_client_finished),
        lists:seq(1, 20)
    ),
    S1 = quic_connection:replay_early_1rtt(
        quic_connection_test_support:state_set(S0, tls_state, handshake_complete)
    ),
    ?assertEqual(8, largest_recv(S1)).

client_1rtt(PN) ->
    {#crypto_keys{key = Key, iv = IV, hp = HP, cipher = Cipher}, _} =
        quic_connection:derive_initial_keys(<<"discard-cid">>, ?QUIC_VERSION_1),
    quic_aead:protect_short_packet(
        Cipher, Key, IV, HP, PN, 16#40, <<"own-cid0">>, <<1, 0:(8 * 20)>>
    ).

largest_recv(State) ->
    quic_connection:get_largest_recv(app, State).
