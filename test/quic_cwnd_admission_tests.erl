%%% -*- erlang -*-
%%%
%%% Every ack-eliciting packet waits for the congestion window (RFC 9002
%%% Section 7). The exceptions are a PTO probe (Section 7.5) and the one
%%% packet a sender may send on entering recovery (Section 7.3.2).
%%% Packets that are not in flight, ACK-only and CONNECTION_CLOSE, are
%%% never held back.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cwnd_admission_tests).

-include_lib("eunit/include/eunit.hrl").

-define(CWND, 12000).

%%====================================================================
%% No allowance above the window
%%====================================================================

%% Urgency 0 orders a stream first, it does not let it past the window.
urgency_zero_stream_waits_for_cwnd_test() ->
    S0 = full(quic_connection_test_support:state_with_send_windows([{0, 0, 1000000}], 1000000)),
    Out = quic_connection_test_support:datagrams_out(S0),
    {ok, S1} = quic_connection:do_send_data(0, <<"tick">>, false, S0, check),
    ?assertEqual(Out, quic_connection_test_support:datagrams_out(S1)),
    ?assertEqual([{0, 0, 4}], quic_connection_test_support:queued_entries(S1)),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S1))).

%% An HTTP/3 peer's u=0 (RFC 9218) reaches the stream through
%% set_stream_priority; it gets no more room than any other stream.
peer_priority_zero_waits_for_cwnd_test() ->
    S0 = full(quic_connection_test_support:state_with_send_windows([{0, 3, 1000000}], 1000000)),
    {ok, S1} = quic_connection:do_set_stream_priority(0, 0, false, S0),
    Out = quic_connection_test_support:datagrams_out(S1),
    {ok, S2} = quic_connection:do_send_data(0, <<"request">>, false, S1, check),
    ?assertEqual(Out, quic_connection_test_support:datagrams_out(S2)),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S2))).

%% A small Handshake packet with the window exactly full is held.
handshake_packet_waits_for_cwnd_test() ->
    S0 = quic_connection_test_support:state_set(
        full(
            quic_connection_test_support:state_sending(
                quic_connection_test_support:state_with_keys(server)
            )
        ),
        address_validated,
        true
    ),
    Frames = [{crypto, 0, <<"fin">>}],
    S1 = quic_connection:send_handshake_packet(<<6, 0, 3, "fin">>, Frames, S0),
    ?assertEqual(1, length(quic_connection_test_support:pending_hs(S1, handshake))),
    ?assertEqual(?CWND, quic_cc:bytes_in_flight(cc(S1))).

%% A queued retransmission is taken off the queue only when the packet
%% the send builds for it fits: the gate and the send agree.
retransmit_stream_gate_matches_the_send_test() ->
    Data = binary:copy(<<"r">>, 100),
    S0 = quic_connection_test_support:state_with_send_windows([{0, 3, 1000000}], 1000000),
    S1 = quic_connection:enqueue_retransmit_stream(0, 5000, Data, false, S0),
    %% send_retransmit_packet/3 sizes it as the frame plus 50 bytes.
    Size = iolist_size(quic_frame:encode({stream, 0, 5000, Data, false})) + 50,
    %% One byte short: left queued, untouched.
    Short = with_room(S1, Size - 1),
    Version = quic_connection_test_support:state_get(Short, send_queue_version),
    S2 = quic_connection:process_send_queue(Short),
    ?assertEqual(Version, quic_connection_test_support:state_get(S2, send_queue_version)),
    ?assertEqual([{0, 5000, 100}], quic_connection_test_support:queued_entries(S2)),
    %% Exactly enough: sent, and the window is then full.
    S3 = quic_connection:process_send_queue(with_room(S1, Size)),
    ?assertEqual([], quic_connection_test_support:queued_entries(S3)),
    CC3 = cc(S3),
    ?assert(quic_cc:bytes_in_flight(CC3) =< quic_cc:cwnd(CC3)).

%%====================================================================
%% Helpers
%%====================================================================

cc(State) ->
    quic_connection_test_support:state_get(State, cc_state).

%% The window exactly full.
full(State) ->
    with_room(State, 0).

%% A window with Room bytes left.
with_room(State, Room) ->
    CC = quic_cc:new(#{algorithm => newreno, initial_window => ?CWND}),
    quic_connection_test_support:state_set(
        State, cc_state, quic_cc:on_packet_sent(CC, ?CWND - Room)
    ).
