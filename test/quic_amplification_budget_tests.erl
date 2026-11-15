%%% -*- erlang -*-
%%%
%%% What an unvalidated server spends its amplification budget on
%%% (RFC 9000 Section 8.1). A probe it cannot afford that replays sent
%%% data is dropped rather than queued, one taken from the queue stays
%%% there, and none is armed again until the client sends more (RFC 9002
%%% Appendix A.8). An ACK-only Initial from a server is not
%%% padded (RFC 9000 Section 14.1). Either mistake can leave the server
%%% unable to repair a lost flight.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_amplification_budget_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

server_ack_only_initial_is_not_padded_test() ->
    {Sink, S0} = capturing(unvalidated_server()),
    S1 = quic_connection:send_initial_ack(S0),
    Datagram = recv(Sink),
    ?assert(byte_size(Datagram) < 1200),
    ?assertEqual(byte_size(Datagram), amp_tx(S1)).

server_crypto_initial_is_padded_test() ->
    {Sink, S0} = capturing(unvalidated_server()),
    S1 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S0),
    ?assertEqual(1200, byte_size(recv(Sink))),
    ?assertEqual(1200, amp_tx(S1)).

client_ack_only_initial_is_padded_test() ->
    {Sink, S0} = capturing(with_initial_ack_ranges(client())),
    _ = quic_connection:send_initial_ack(S0),
    ?assertEqual(1200, byte_size(recv(Sink))).

%% The sequence a lossy handshake produced: a server that has received
%% one 1200-byte Initial answers with its Initial and Handshake flight
%% and acknowledges the client's Initial on its own. The probe that
%% repairs a lost ServerHello must still fit the remaining budget.
probe_fits_after_flight_and_ack_test() ->
    {_Sink, S0} = capturing(unvalidated_server()),
    S1 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S0),
    S2 = quic_connection:send_handshake_packet(
        binary:copy(<<0>>, 700), [{crypto, 0, binary:copy(<<0>>, 700)}], S1
    ),
    S3 = quic_connection:send_initial_ack(S2),
    S4 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S3),
    ?assertEqual([], quic_connection_test_support:pending_hs(S4, initial)).

%% A probe the budget cannot cover is not queued: its data is still
%% outstanding, so a queued copy per expiry only fills the queue. Nothing
%% is armed until the client sends more.
refused_probe_is_not_queued_test() ->
    S0 = probe(initial, blocked_with_flight_outstanding()),
    ?assertEqual([], quic_connection_test_support:pending_hs(S0, initial)),
    ?assertEqual(undefined, quic_connection_test_support:state_get(S0, pto_timer)).

%% A probe can also come from the queue of packets never sent. One the
%% budget refuses stays queued, or the handshake loses those bytes for good
%% (RFC 9000 Section 13.3).
refused_probe_of_a_queued_packet_keeps_it_test() ->
    S0 = with_queued_handshake(),
    [Queued] = quic_connection_test_support:pending_hs(S0, handshake),
    S1 = probe(handshake, S0),
    ?assertEqual([Queued], quic_connection_test_support:pending_hs(S1, handshake)),
    ?assert(amp_tx(S1) =< 3600),
    ?assertEqual(
        quic_connection_test_support:state_get(S0, handshake_next_pn),
        quic_connection_test_support:state_get(S1, handshake_next_pn)
    ).

%% Once the client sends more, the same packet goes out first.
kept_packet_goes_out_when_the_budget_grows_test() ->
    S1 = probe(handshake, with_queued_handshake()),
    S2 = quic_connection:drain_pending_hs(
        quic_connection:amp_account_recv(binary:copy(<<0>>, 1200), S1)
    ),
    ?assertEqual([], quic_connection_test_support:pending_hs(S2, handshake)),
    [#{frames := Frames}] = sent_handshake(S2),
    ?assertEqual([queued_crypto()], Frames).

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

%% Two Initials spend 2400 of the 3600-byte budget, so the Handshake
%% packet after them does not fit and waits in the queue.
with_queued_handshake() ->
    {_Sink, S0} = capturing(unvalidated_server()),
    S1 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S0),
    S2 = quic_connection:send_initial_packet(crypto_payload(), crypto_frames(), S1),
    S3 = quic_connection:send_handshake_packet(
        quic_frame:encode(queued_crypto()), [queued_crypto()], S2
    ),
    [_] = quic_connection_test_support:pending_hs(S3, handshake),
    S3.

queued_crypto() ->
    {crypto, 1000, binary:copy(<<7>>, 1300)}.

sent_handshake(State) ->
    [
        #{pn => PN, frames => F}
     || #sent_packet{pn = PN, frames = F} <- maps:values(
            quic_loss:sent_packets(handshake, quic_connection_test_support:loss_state(State))
        )
    ].

unvalidated_server() ->
    S0 = quic_connection_test_support:state_with_keys(server),
    S1 = quic_connection_test_support:state_set(S0, address_validated, false),
    with_initial_ack_ranges(quic_connection_test_support:state_set(S1, amp_rx, 1200)).

client() ->
    quic_connection_test_support:state_with_keys(client).

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

recv(Sink) ->
    {ok, {_, _, Datagram}} = gen_udp:recv(Sink, 0, 1000),
    Datagram.

amp_tx(State) ->
    quic_connection_test_support:state_get(State, amp_tx).
