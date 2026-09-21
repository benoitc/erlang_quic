%%% -*- erlang -*-
%%%
%%% Discarding keys for a packet number space (RFC 9001 Section 4.9).
%%%
%%% The two roles discard Initial keys on different events, and getting
%%% them the wrong way round is silent: a server that discarded on
%%% sending its first Handshake packet could no longer retransmit the
%%% Initial-level ServerHello it may still owe the client.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_key_discard_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Section 4.9.1: Initial keys, per role
%%====================================================================

%% A client discards when it first sends a Handshake packet; the hook is
%% in send_handshake_crypto/2, which reaches discard_initial/1 here.
client_discards_initial_test() ->
    S0 = quic_connection_test_support:state_with_keys(client),
    ?assertNotEqual(undefined, keys(S0, initial)),
    ?assertEqual(undefined, keys(quic_connection:discard_initial(S0), initial)).

%% A server's trigger is receiving a Handshake packet, not sending one:
%% until then it may still owe the client an Initial-level ServerHello.
server_discards_initial_on_handshake_receive_test() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    S1 = quic_connection:server_discard_initial(handshake, S0),
    ?assertEqual(undefined, keys(S1, initial)).

%% A packet at any other level leaves them alone.
server_keeps_initial_on_other_levels_test() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    ?assertNotEqual(undefined, keys(quic_connection:server_discard_initial(initial, S0), initial)),
    ?assertNotEqual(undefined, keys(quic_connection:server_discard_initial(app, S0), initial)).

%%====================================================================
%% Section 4.9.2: Handshake keys at confirmation
%%====================================================================

confirmation_discards_handshake_keys_test() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    ?assertNotEqual(undefined, keys(S0, handshake)),
    S1 = quic_connection:confirm_handshake(S0),
    ?assertEqual(undefined, keys(S1, handshake)).

%%====================================================================
%% Nothing is sent at a discarded level
%%====================================================================

%% A send that races the discard is dropped rather than crashing on the
%% missing keys, which is what a late acknowledgement would otherwise do.
send_at_a_discarded_level_is_dropped_test() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    S1 = quic_connection:confirm_handshake(S0),
    ?assertEqual(S1, quic_connection:send_handshake_packet(<<0>>, [ping], S1)),
    S2 = quic_connection:server_discard_initial(handshake, S1),
    ?assertEqual(S2, quic_connection:send_initial_packet(<<0>>, [ping], S2)).

keys(State, initial) -> quic_connection_test_support:state_get(State, initial_keys);
keys(State, handshake) -> quic_connection_test_support:state_get(State, handshake_keys).
