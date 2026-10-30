%%% -*- erlang -*-
%%%
%%% RFC 9002 Section 6.2.1: an acknowledgement resets the PTO backoff,
%%% except at a client not yet sure the server has validated its address.
%%% A server holding back a lost flight answers each client probe with
%%% an ACK, and a reset there turns the client's probes into a flood at
%%% the initial PTO for as long as the flight stays lost.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_client_pto_backoff_tests).

-include_lib("eunit/include/eunit.hrl").

initial_ack_keeps_unvalidated_client_backoff_test() ->
    S = quic_connection:process_frame(initial, ack(), backed_off(client)),
    ?assertEqual(3, pto_count(S)).

handshake_ack_resets_client_backoff_test() ->
    S = quic_connection:process_frame(handshake, ack(), backed_off(client)),
    ?assertEqual(0, pto_count(S)).

initial_ack_resets_server_backoff_test() ->
    S = quic_connection:process_frame(initial, ack(), backed_off(server)),
    ?assertEqual(0, pto_count(S)).

%%====================================================================
%% Helpers
%%====================================================================

ack() -> {ack, [{0, 0}], 0, undefined}.

%% One ack-eliciting packet outstanding in each handshake space, and
%% three expiries behind it.
backed_off(Role) ->
    S0 = quic_connection_test_support:state_with_keys(Role),
    Now = erlang:monotonic_time(millisecond),
    L0 = quic_connection_test_support:loss_state(S0),
    L1 = quic_loss:on_packet_sent(initial, L0, 0, 1200, true, [ping], Now),
    L2 = quic_loss:on_packet_sent(handshake, L1, 0, 1200, true, [ping], Now),
    L3 = lists:foldl(fun(_, L) -> quic_loss:on_pto_expired(L) end, L2, [1, 2, 3]),
    quic_connection_test_support:state_set(S0, loss_state, L3).

pto_count(State) ->
    quic_loss:pto_count(quic_connection_test_support:loss_state(State)).
