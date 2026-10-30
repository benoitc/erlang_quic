%%% -*- erlang -*-
%%%
%%% RFC 9002 Section 6.2.4: probe packets from several packet number
%%% spaces may be coalesced. With a flight outstanding in both the
%%% Initial and Handshake spaces, the peer may be missing either, and the
%%% two spaces share one backoff: probing only the space whose deadline
%%% came first leaves each space probed at every other expiry, its own
%%% interval growing fourfold rather than twofold.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_handshake_probe_tests).

-include_lib("eunit/include/eunit.hrl").

initial_probe_also_probes_handshake_test() ->
    S0 = with_both_flights(),
    S1 = probe(initial, S0),
    ?assertEqual(next_pn(initial, S0) + 1, next_pn(initial, S1)),
    ?assertEqual(next_pn(handshake, S0) + 1, next_pn(handshake, S1)).

handshake_probe_also_probes_initial_test() ->
    S0 = with_both_flights(),
    S1 = probe(handshake, S0),
    ?assertEqual(next_pn(initial, S0) + 1, next_pn(initial, S1)),
    ?assertEqual(next_pn(handshake, S0) + 1, next_pn(handshake, S1)).

%% Nothing outstanding in the other space, nothing to probe there.
probe_stays_in_its_space_alone_test() ->
    S0 = with_initial_flight(validated_server()),
    S1 = probe(initial, S0),
    ?assertEqual(next_pn(initial, S0) + 1, next_pn(initial, S1)),
    ?assertEqual(next_pn(handshake, S0), next_pn(handshake, S1)).

%%====================================================================
%% Helpers
%%====================================================================

validated_server() ->
    S0 = quic_connection_test_support:state_sending(
        quic_connection_test_support:state_with_keys(server)
    ),
    quic_connection_test_support:state_set(S0, address_validated, true).

with_initial_flight(State) ->
    quic_connection:send_initial_packet(
        quic_frame:encode({crypto, 0, <<"server-hello">>}),
        [{crypto, 0, <<"server-hello">>}],
        State
    ).

with_both_flights() ->
    quic_connection:send_handshake_packet(
        quic_frame:encode({crypto, 0, <<"finished">>}),
        [{crypto, 0, <<"finished">>}],
        with_initial_flight(validated_server())
    ).

probe(Space, State) ->
    quic_connection:handle_pto_timeout(
        quic_connection_test_support:state_set(State, pto_space, Space)
    ).

next_pn(initial, State) ->
    quic_connection_test_support:state_get(State, initial_next_pn);
next_pn(handshake, State) ->
    quic_connection_test_support:state_get(State, handshake_next_pn).
