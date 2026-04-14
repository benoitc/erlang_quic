%%% -*- erlang -*-
%%%
%%% Unit tests for the latency spin bit (RFC 9000 §17.4).

-module(quic_spin_bit_tests).

-include_lib("eunit/include/eunit.hrl").

%% A client mirrors the received spin bit on its outgoing packets.
client_mirrors_received_spin_test() ->
    S0 = quic_connection:test_spin_state_for(client, true),
    %% Received packet with spin = 1 (bit 5 set) and PN 1 (> -1).
    S1 = quic_connection:update_spin_from_recv(2#00100000 bor 16#40, 1, S0),
    ?assertMatch(
        #{outgoing := 1, recv := 1, largest_pn := 1, enabled := true},
        quic_connection:test_spin_state(S1)
    ).

%% A server inverts the received spin bit.
server_inverts_received_spin_test() ->
    S0 = quic_connection:test_spin_state_for(server, true),
    S1 = quic_connection:update_spin_from_recv(2#00100000 bor 16#40, 1, S0),
    ?assertMatch(
        #{outgoing := 0, recv := 1},
        quic_connection:test_spin_state(S1)
    ).

%% A reordered packet (PN below the high-water mark) must not move the
%% spin state, preventing spurious RTT edge detection.
reordered_packet_does_not_update_test() ->
    S0 = quic_connection:test_spin_state_for(client, true),
    S1 = quic_connection:update_spin_from_recv(2#00100000 bor 16#40, 5, S0),
    %% A later-arriving, earlier-PN packet with spin=0 must NOT flip us.
    S2 = quic_connection:update_spin_from_recv(16#40, 3, S1),
    ?assertEqual(
        quic_connection:test_spin_state(S1),
        quic_connection:test_spin_state(S2)
    ).

%% When disabled, outgoing stays at 0 regardless of what we receive.
disabled_keeps_outgoing_at_zero_test() ->
    S0 = quic_connection:test_spin_state_for(client, false),
    S1 = quic_connection:update_spin_from_recv(2#00100000 bor 16#40, 1, S0),
    ?assertMatch(
        #{outgoing := 0, enabled := false},
        quic_connection:test_spin_state(S1)
    ).

%% The encoded first byte encodes the spin bit in position 5.
first_byte_encodes_spin_test() ->
    %% Set spin_outgoing = 1 on a client state, then encode.
    S0 = quic_connection:test_spin_state_for(client, true),
    S1 = quic_connection:update_spin_from_recv(2#00100000 bor 16#40, 1, S0),
    %% PN len 1, key phase 0 → expected byte = 0x40 | (1<<5) | 0 | 0 = 0x60.
    ?assertEqual(16#60, quic_connection:short_header_first_byte(0, 1, S1)).

first_byte_respects_disable_test() ->
    S = quic_connection:test_spin_state_for(client, false),
    ?assertEqual(16#40, quic_connection:short_header_first_byte(0, 1, S)).
