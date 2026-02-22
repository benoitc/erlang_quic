%%% -*- erlang -*-
%%%
%%% Tests for QUIC ACK Frame Processing
%%%

-module(quic_ack_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Basic State Tests
%%====================================================================

new_state_test() ->
    State = quic_ack:new(),
    ?assertEqual(undefined, quic_ack:largest_received(State)),
    ?assertEqual(undefined, quic_ack:largest_acked(State)),
    ?assertEqual([], quic_ack:ack_ranges(State)),
    ?assertEqual(0, quic_ack:ack_eliciting_in_flight(State)).

%%====================================================================
%% Packet Reception Tracking Tests
%%====================================================================

record_single_packet_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    ?assertEqual(0, quic_ack:largest_received(S1)),
    ?assertEqual([{0, 0}], quic_ack:ack_ranges(S1)).

record_sequential_packets_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    S2 = quic_ack:record_received(S1, 1),
    S3 = quic_ack:record_received(S2, 2),
    ?assertEqual(2, quic_ack:largest_received(S3)),
    ?assertEqual([{0, 2}], quic_ack:ack_ranges(S3)).

record_out_of_order_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 2),
    S2 = quic_ack:record_received(S1, 0),
    S3 = quic_ack:record_received(S2, 1),
    ?assertEqual(2, quic_ack:largest_received(S3)),
    %% All should be in one range
    ?assertEqual([{0, 2}], quic_ack:ack_ranges(S3)).

record_with_gap_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    S2 = quic_ack:record_received(S1, 1),
    %% Skip packet 2
    S3 = quic_ack:record_received(S2, 3),
    S4 = quic_ack:record_received(S3, 4),
    ?assertEqual(4, quic_ack:largest_received(S4)),
    %% Should have two ranges
    Ranges = quic_ack:ack_ranges(S4),
    ?assertEqual(2, length(Ranges)),
    ?assert(lists:member({3, 4}, Ranges)),
    ?assert(lists:member({0, 1}, Ranges)).

record_multiple_gaps_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    S2 = quic_ack:record_received(S1, 2),
    S3 = quic_ack:record_received(S2, 4),
    S4 = quic_ack:record_received(S3, 6),
    ?assertEqual(6, quic_ack:largest_received(S4)),
    Ranges = quic_ack:ack_ranges(S4),
    ?assertEqual(4, length(Ranges)).

fill_gap_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    S2 = quic_ack:record_received(S1, 2),
    ?assertEqual([{2, 2}, {0, 0}], quic_ack:ack_ranges(S2)),
    %% Fill the gap
    S3 = quic_ack:record_received(S2, 1),
    ?assertEqual([{0, 2}], quic_ack:ack_ranges(S3)).

duplicate_packet_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 5),
    S2 = quic_ack:record_received(S1, 5),
    ?assertEqual([{5, 5}], quic_ack:ack_ranges(S2)).

large_packet_numbers_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 1000000),
    S2 = quic_ack:record_received(S1, 1000001),
    ?assertEqual(1000001, quic_ack:largest_received(S2)),
    ?assertEqual([{1000000, 1000001}], quic_ack:ack_ranges(S2)).

%%====================================================================
%% ACK Generation Tests
%%====================================================================

generate_ack_empty_test() ->
    State = quic_ack:new(),
    ?assertEqual({error, no_packets}, quic_ack:generate_ack(State)).

generate_ack_single_packet_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    {ok, {ack, Largest, _Delay, FirstRange, Ranges}} = quic_ack:generate_ack(S1),
    ?assertEqual(0, Largest),
    % 1 packet - 1 = 0
    ?assertEqual(0, FirstRange),
    ?assertEqual([], Ranges).

generate_ack_range_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    S2 = quic_ack:record_received(S1, 1),
    S3 = quic_ack:record_received(S2, 2),
    {ok, {ack, Largest, _Delay, FirstRange, Ranges}} = quic_ack:generate_ack(S3),
    ?assertEqual(2, Largest),
    % 3 packets - 1 = 2
    ?assertEqual(2, FirstRange),
    ?assertEqual([], Ranges).

generate_ack_with_gap_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    S2 = quic_ack:record_received(S1, 1),
    S3 = quic_ack:record_received(S2, 5),
    S4 = quic_ack:record_received(S3, 6),
    {ok, {ack, Largest, _Delay, FirstRange, AckRanges}} = quic_ack:generate_ack(S4),
    ?assertEqual(6, Largest),
    % 2 packets (5,6) - 1 = 1
    ?assertEqual(1, FirstRange),
    ?assertEqual(1, length(AckRanges)).

%%====================================================================
%% Needs ACK Tests
%%====================================================================

needs_ack_initially_false_test() ->
    State = quic_ack:new(),
    ?assertNot(quic_ack:needs_ack(State)).

needs_ack_after_ack_eliciting_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0, true),
    ?assert(quic_ack:needs_ack(S1)).

needs_ack_after_non_ack_eliciting_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0, false),
    ?assertNot(quic_ack:needs_ack(S1)).

mark_ack_sent_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0, true),
    ?assert(quic_ack:needs_ack(S1)),
    S2 = quic_ack:mark_ack_sent(S1),
    ?assertNot(quic_ack:needs_ack(S2)).

%%====================================================================
%% ACK Processing Tests
%%====================================================================

process_ack_simple_test() ->
    State = quic_ack:new(),
    % Acks packets 0-5
    AckFrame = {ack, 5, 0, 5, []},
    {NewState, AckedPNs} = quic_ack:process_ack(State, AckFrame),
    ?assertEqual(5, quic_ack:largest_acked(NewState)),
    ?assertEqual([0, 1, 2, 3, 4, 5], lists:sort(AckedPNs)).

process_ack_with_sent_packets_test() ->
    State = quic_ack:new(),
    SentPackets = #{
        0 => #{ack_eliciting => true},
        1 => #{ack_eliciting => true},
        2 => #{ack_eliciting => false}
    },
    % Acks 0-2
    AckFrame = {ack, 2, 0, 2, []},
    {_NewState, AckedPNs} = quic_ack:process_ack(State, AckFrame, SentPackets),
    ?assertEqual([0, 1, 2], lists:sort(AckedPNs)).

process_ack_with_gap_test() ->
    State = quic_ack:new(),
    %% ACK frame with gap: acks 8-10 and 3-5
    %% Gap = PrevStart - End - 2 = 8 - 5 - 2 = 1
    AckFrame = {ack, 10, 0, 2, [{1, 2}]},
    {NewState, AckedPNs} = quic_ack:process_ack(State, AckFrame),
    ?assertEqual(10, quic_ack:largest_acked(NewState)),
    Sorted = lists:sort(AckedPNs),
    ?assertEqual([3, 4, 5, 8, 9, 10], Sorted).

process_ack_updates_largest_test() ->
    State = quic_ack:new(),
    Ack1 = {ack, 5, 0, 0, []},
    {S1, _} = quic_ack:process_ack(State, Ack1),
    ?assertEqual(5, quic_ack:largest_acked(S1)),

    %% Larger ACK
    Ack2 = {ack, 10, 0, 0, []},
    {S2, _} = quic_ack:process_ack(S1, Ack2),
    ?assertEqual(10, quic_ack:largest_acked(S2)),

    %% Smaller ACK shouldn't decrease
    Ack3 = {ack, 7, 0, 0, []},
    {S3, _} = quic_ack:process_ack(S2, Ack3),
    ?assertEqual(10, quic_ack:largest_acked(S3)).

process_ack_ecn_test() ->
    State = quic_ack:new(),
    AckFrame = {ack_ecn, 5, 0, 5, [], 10, 20, 5},
    %% ECN ACKs return {State, AckedPNs, {ecn, ECT0, ECT1, ECNCE}}
    {NewState, AckedPNs, {ecn, ECT0, ECT1, ECNCE}} = quic_ack:process_ack(State, AckFrame),
    ?assertEqual(5, quic_ack:largest_acked(NewState)),
    ?assertEqual(6, length(AckedPNs)),
    ?assertEqual(10, ECT0),
    ?assertEqual(20, ECT1),
    ?assertEqual(5, ECNCE).

%%====================================================================
%% Range Management Tests
%%====================================================================

ranges_sorted_descending_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 100),
    S2 = quic_ack:record_received(S1, 50),
    S3 = quic_ack:record_received(S2, 75),
    Ranges = quic_ack:ack_ranges(S3),
    %% Should be sorted descending by start
    [{R1Start, _}, {R2Start, _}, {R3Start, _}] = Ranges,
    ?assert(R1Start >= R2Start),
    ?assert(R2Start >= R3Start).

%%====================================================================
%% Integration Tests
%%====================================================================

full_cycle_test() ->
    %% Simulate receiving packets and generating ACKs
    State = quic_ack:new(),

    %% Receive some packets
    S1 = quic_ack:record_received(State, 0, true),
    S2 = quic_ack:record_received(S1, 1, true),
    % ACK-only
    S3 = quic_ack:record_received(S2, 2, false),

    ?assert(quic_ack:needs_ack(S3)),

    %% Generate ACK
    {ok, AckFrame} = quic_ack:generate_ack(S3),

    %% Mark ACK as sent
    S4 = quic_ack:mark_ack_sent(S3),
    ?assertNot(quic_ack:needs_ack(S4)),

    %% Process our own ACK being acknowledged (by peer)
    {S5, _Acked} = quic_ack:process_ack(S4, AckFrame),
    ?assertEqual(2, quic_ack:largest_acked(S5)).
