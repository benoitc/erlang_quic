%%% -*- erlang -*-
%%%
%%% What an unvalidated server spends its amplification budget on
%%% (RFC 9000 Section 8.1). A probe it cannot afford is dropped rather
%%% than queued, and none is armed again until the client sends more
%%% (RFC 9002 Appendix A.8).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_amplification_budget_tests).

-include_lib("eunit/include/eunit.hrl").

%% A probe the budget cannot cover is not queued: its data is still
%% outstanding, so a queued copy per expiry only fills the queue. Nothing
%% is armed until the client sends more.
refused_probe_is_not_queued_test() ->
    S0 = probe(initial, blocked_with_flight_outstanding()),
    ?assertEqual([], quic_connection_test_support:pending_hs(S0, initial)),
    ?assertEqual(undefined, quic_connection_test_support:state_get(S0, pto_timer)).

%% The client's next datagram makes room, and the probe is armed again:
%% receiving it sends nothing in flight, so without this nothing would.
probe_armed_when_budget_grows_test() ->
    S0 = probe(initial, blocked_with_flight_outstanding()),
    S1 = quic_connection:amp_account_recv(binary:copy(<<0>>, 1200), S0),
    S2 = quic_connection:flush_event(S1, event),
    ?assertNotEqual(undefined, quic_connection_test_support:state_get(S2, pto_timer)).

%% A probe that fits what is left goes out, however little that is.
small_probe_fits_what_is_left_test() ->
    S0 = blocked_with_flight_outstanding(),
    ?assert(3600 - amp_tx(S0) < 1200),
    S1 = probe(handshake, S0),
    ?assert(amp_tx(S1) > amp_tx(S0)),
    ?assertEqual([], quic_connection_test_support:pending_hs(S1, handshake)).

%%====================================================================
%% Helpers
%%====================================================================

crypto_payload() -> quic_frame:encode({crypto, 0, <<"server-hello">>}).

crypto_frames() -> [{crypto, 0, <<"server-hello">>}].

blocked_with_flight_outstanding() ->
    {_Sink, S0} = capturing(unvalidated_server()),
    S1 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S0),
    S2 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S1),
    quic_connection:send_handshake_packet(
        binary:copy(<<0>>, 400), [{crypto, 0, binary:copy(<<0>>, 400)}], S2
    ).

unvalidated_server() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    S1 = quic_connection_test_support:state_set(S0, address_validated, false),
    with_initial_ack_ranges(quic_connection_test_support:state_set(S1, amp_rx, 1200)).

with_initial_ack_ranges(State) ->
    quic_connection_test_support:state_set(State, initial_ack_ranges, [{0, 0}]).

capturing(State) ->
    {ok, Sink} = gen_udp:open(0, [binary, {active, false}, {ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(Sink),
    {ok, Socket} = gen_udp:open(0, [binary, {active, false}]),
    {Sink,
        quic_connection_test_support:state_set(
            quic_connection_test_support:state_set(State, socket, Socket),
            remote_addr,
            {{127, 0, 0, 1}, Port}
        )}.

probe(Space, State) ->
    quic_connection:handle_pto_timeout(
        quic_connection_test_support:state_set(State, pto_space, Space)
    ).

amp_tx(State) ->
    quic_connection_test_support:state_get(State, amp_tx).
