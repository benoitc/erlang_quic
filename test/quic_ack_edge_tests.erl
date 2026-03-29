%%% -*- erlang -*-
%%%
%%% Tests for QUIC ACK Frame Edge Cases
%%%
%%% These tests validate ACK encoding/decoding and processing edge cases
%%% that may cause issues in large transfers.
%%%

-module(quic_ack_edge_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% ACK Range Encoding/Decoding Tests
%%====================================================================

ack_single_packet_roundtrip_test() ->
    %% ACK for single packet
    Frame = {ack, [{100, 100}], 0, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_contiguous_range_roundtrip_test() ->
    %% ACK for contiguous range (no gaps)
    Frame = {ack, [{0, 100}], 50, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_many_ranges_roundtrip_test() ->
    %% ACK with many ranges (10 gaps)
    Ranges = [
        {100, 105},
        {90, 95},
        {80, 85},
        {70, 75},
        {60, 65},
        {50, 55},
        {40, 45},
        {30, 35},
        {20, 25},
        {10, 15},
        {0, 5}
    ],
    Frame = {ack, Ranges, 10, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_large_packet_numbers_roundtrip_test() ->
    %% ACK with large packet numbers (near 62-bit limit)

    % Max varint value
    LargePN = 16#3FFFFFFFFFFFFFFF,
    Frame = {ack, [{LargePN, LargePN}], 0, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_large_gap_roundtrip_test() ->
    %% ACK with large gap between ranges
    Frame = {ack, [{1000000, 1000010}, {0, 10}], 0, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_with_ecn_roundtrip_test() ->
    %% ACK with ECN counts
    Ranges = [{100, 110}, {50, 60}],
    % ECT0, ECT1, ECNCE
    ECN = {1000, 500, 10},
    Frame = {ack, Ranges, 100, ECN},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_zero_delay_roundtrip_test() ->
    %% ACK with zero delay
    Frame = {ack, [{50, 100}], 0, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_large_delay_roundtrip_test() ->
    %% ACK with large delay value

    % Large varint
    LargeDelay = 16#3FFFFFFF,
    Frame = {ack, [{0, 10}], LargeDelay, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% ACK Processing Tests
%%====================================================================

process_ack_many_ranges_test() ->
    %% Process ACK with many ranges
    State = quic_ack:new(),
    AckFrame =
        {ack, 100, 0, 5, [
            % Gap 3, range 5 -> packets 87-92
            {3, 5},
            % Gap 3, range 5 -> packets 75-80
            {3, 5},
            % Gap 3, range 5 -> packets 63-68
            {3, 5}
        ]},
    {NewState, AckedPNs} = quic_ack:process_ack(State, AckFrame),

    %% Verify largest acked
    ?assertEqual(100, quic_ack:largest_acked(NewState)),

    %% Verify we got expected packets
    ?assert(lists:member(100, AckedPNs)),
    ?assert(lists:member(95, AckedPNs)).

process_ack_updates_correctly_test() ->
    %% Verify ACK processing updates state correctly
    State = quic_ack:new(),

    %% Process first ACK
    Ack1 = {ack, 50, 0, 10, []},
    {S1, Acked1} = quic_ack:process_ack(State, Ack1),
    ?assertEqual(50, quic_ack:largest_acked(S1)),
    % 40-50
    ?assertEqual(11, length(Acked1)),

    %% Process larger ACK
    Ack2 = {ack, 100, 0, 20, []},
    {S2, Acked2} = quic_ack:process_ack(S1, Ack2),
    ?assertEqual(100, quic_ack:largest_acked(S2)),
    % 80-100
    ?assertEqual(21, length(Acked2)),

    %% Process smaller ACK (shouldn't decrease largest)
    Ack3 = {ack, 75, 0, 5, []},
    {S3, _Acked3} = quic_ack:process_ack(S2, Ack3),
    ?assertEqual(100, quic_ack:largest_acked(S3)).

process_ack_with_sent_packets_test() ->
    %% Process ACK filtering by sent packets
    State = quic_ack:new(),
    SentPackets = #{
        10 => #{ack_eliciting => true},
        11 => #{ack_eliciting => true},
        12 => #{ack_eliciting => false},
        15 => #{ack_eliciting => true}
    },
    %% ACK range 5-15 (11 packets)
    AckFrame = {ack, 15, 0, 10, []},
    {_NewState, AckedPNs} = quic_ack:process_ack(State, AckFrame, SentPackets),

    %% Should only return packets we sent
    ?assertEqual([10, 11, 12, 15], lists:sort(AckedPNs)).

%%====================================================================
%% ACK Range Management Tests
%%====================================================================

record_many_packets_test() ->
    %% Test recording many packets
    State = quic_ack:new(),
    NumPackets = 1000,

    FinalState = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        lists:seq(0, NumPackets - 1)
    ),

    ?assertEqual(NumPackets - 1, quic_ack:largest_received(FinalState)),
    %% Should be single contiguous range
    ?assertEqual([{0, NumPackets - 1}], quic_ack:ack_ranges(FinalState)).

record_reverse_order_test() ->
    %% Test recording packets in reverse order
    State = quic_ack:new(),
    Packets = lists:seq(100, 0, -1),

    FinalState = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        Packets
    ),

    ?assertEqual(100, quic_ack:largest_received(FinalState)),
    ?assertEqual([{0, 100}], quic_ack:ack_ranges(FinalState)).

record_random_order_test() ->
    %% Test recording packets in random order
    State = quic_ack:new(),
    %% Shuffled sequence 0-99
    Packets = lists:sort(
        fun(_, _) -> rand:uniform() > 0.5 end,
        lists:seq(0, 99)
    ),

    FinalState = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        Packets
    ),

    ?assertEqual(99, quic_ack:largest_received(FinalState)),
    ?assertEqual([{0, 99}], quic_ack:ack_ranges(FinalState)).

record_with_many_gaps_test() ->
    %% Record only even packets to create many gaps
    State = quic_ack:new(),
    EvenPackets = lists:seq(0, 100, 2),

    FinalState = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        EvenPackets
    ),

    Ranges = quic_ack:ack_ranges(FinalState),
    %% Should have 51 single-packet ranges
    ?assertEqual(51, length(Ranges)).

merge_adjacent_ranges_test() ->
    %% Test that ranges merge correctly when gaps are filled
    State = quic_ack:new(),

    %% Create gap: 0-5, 10-15
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        lists:seq(0, 5) ++ lists:seq(10, 15)
    ),
    ?assertEqual(2, length(quic_ack:ack_ranges(S1))),

    %% Fill gap: 6-9
    S2 = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        S1,
        lists:seq(6, 9)
    ),
    ?assertEqual([{0, 15}], quic_ack:ack_ranges(S2)).

%%====================================================================
%% ACK Generation Edge Cases
%%====================================================================

generate_ack_single_packet_test() ->
    State = quic_ack:new(),
    S1 = quic_ack:record_received(State, 0),
    {ok, {ack, Largest, _Delay, FirstRange, Ranges}} = quic_ack:generate_ack(S1),
    ?assertEqual(0, Largest),
    ?assertEqual(0, FirstRange),
    ?assertEqual([], Ranges).

generate_ack_many_ranges_test() ->
    State = quic_ack:new(),
    %% Create 5 ranges with gaps
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        [0, 1, 2, 10, 11, 12, 20, 21, 22, 30, 31, 32, 40, 41, 42]
    ),

    {ok, {ack, Largest, _Delay, FirstRange, Ranges}} = quic_ack:generate_ack(S1),
    ?assertEqual(42, Largest),
    % 40-42 is 3 packets, so FirstRange = 2
    ?assertEqual(2, FirstRange),
    % 4 additional ranges
    ?assertEqual(4, length(Ranges)).

%%====================================================================
%% ACK Frame To PN List Tests (used in loss detection)
%%====================================================================

ack_frame_to_pn_list_simple_test() ->
    %% Simple single range
    PNs = quic_ack:ack_frame_to_pn_list(10, 5, []),
    ?assertEqual([5, 6, 7, 8, 9, 10], PNs).

ack_frame_to_pn_list_with_ranges_test() ->
    %% With gap: acks 95-100 and 85-90
    %% Gap = PrevStart - End - 2 = 95 - 90 - 2 = 3
    AckRanges = [{3, 5}],
    PNs = quic_ack:ack_frame_to_pn_list(100, 5, AckRanges),
    Expected = lists:seq(95, 100) ++ lists:seq(85, 90),
    ?assertEqual(lists:sort(Expected), lists:sort(PNs)).

ack_frame_to_pn_list_many_ranges_test() ->
    %% Multiple ranges

    % 3 additional ranges with gap 2
    AckRanges = [{2, 3}, {2, 3}, {2, 3}],
    PNs = quic_ack:ack_frame_to_pn_list(100, 4, AckRanges),
    ?assert(length(PNs) > 0),
    ?assert(lists:max(PNs) =:= 100).

ack_frame_to_pn_list_range_limit_test() ->
    %% Test that excessively large ranges are rejected
    %% This protects against memory exhaustion
    Result = quic_ack:ack_frame_to_pn_list(1000000, 100000, []),
    ?assertMatch({error, ack_range_too_large}, Result).

%%====================================================================
%% ACK Eliciting Tracking Tests
%%====================================================================

ack_eliciting_counter_test() ->
    State = quic_ack:new(),

    %% Record ACK-eliciting packets
    S1 = quic_ack:record_received(State, 0, true),
    S2 = quic_ack:record_received(S1, 1, true),
    % Not ACK-eliciting
    S3 = quic_ack:record_received(S2, 2, false),

    ?assert(quic_ack:needs_ack(S3)),

    %% Mark ACK sent
    S4 = quic_ack:mark_ack_sent(S3),
    ?assertNot(quic_ack:needs_ack(S4)).

%%====================================================================
%% Stress Tests
%%====================================================================

stress_many_packets_test() ->
    %% Stress test with many packets
    State = quic_ack:new(),
    NumPackets = 10000,

    FinalState = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        lists:seq(0, NumPackets - 1)
    ),

    {ok, _AckFrame} = quic_ack:generate_ack(FinalState),
    ?assertEqual(NumPackets - 1, quic_ack:largest_received(FinalState)).

stress_many_gaps_test() ->
    %% Stress test with many gaps
    State = quic_ack:new(),
    %% Every 3rd packet (creates many gaps)
    Packets = lists:seq(0, 3000, 3),

    FinalState = lists:foldl(
        fun(PN, Acc) ->
            quic_ack:record_received(Acc, PN)
        end,
        State,
        Packets
    ),

    {ok, _AckFrame} = quic_ack:generate_ack(FinalState),
    Ranges = quic_ack:ack_ranges(FinalState),
    ?assertEqual(length(Packets), length(Ranges)).
