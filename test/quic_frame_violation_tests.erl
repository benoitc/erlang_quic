%%% -*- erlang -*-
%%%
%%% Frame-level RFC 9000 violations that must produce CONNECTION_CLOSE.
%%% Replaces the h3spec-driven checks for these cases with deterministic,
%%% in-process assertions against the server's state machine.

-module(quic_frame_violation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% RFC 9000 §19.20: HANDSHAKE_DONE is server-to-client only. A server
%% that receives one MUST close with PROTOCOL_VIOLATION.
server_rejects_handshake_done_at_app_level_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:process_frame(app, handshake_done, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §19.20: HANDSHAKE_DONE MUST be sent in 1-RTT packets.
%% Anywhere else is PROTOCOL_VIOLATION.
handshake_done_at_handshake_level_is_protocol_violation_test() ->
    S0 = quic_connection:test_state_for_role(client),
    S1 = quic_connection:process_frame(handshake, handshake_done, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

handshake_done_at_initial_level_is_protocol_violation_test() ->
    S0 = quic_connection:test_state_for_role(client),
    S1 = quic_connection:process_frame(initial, handshake_done, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).
