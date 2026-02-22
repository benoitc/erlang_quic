%%% -*- erlang -*-
%%%
%%% Tests for QUIC Congestion Control (NewReno)
%%%

-module(quic_cc_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Basic State Tests
%%====================================================================

new_state_test() ->
    State = quic_cc:new(),
    %% Initial window should be ~14720 or 10 * max_datagram_size
    Cwnd = quic_cc:cwnd(State),
    ?assert(Cwnd >= 12000),
    ?assertEqual(infinity, quic_cc:ssthresh(State)),
    ?assertEqual(0, quic_cc:bytes_in_flight(State)),
    ?assert(quic_cc:in_slow_start(State)),
    ?assertNot(quic_cc:in_recovery(State)).

new_state_with_opts_test() ->
    State = quic_cc:new(#{max_datagram_size => 1400}),
    Cwnd = quic_cc:cwnd(State),
    %% min(10 * 1400, max(14720, 2 * 1400)) = min(14000, 14720) = 14000
    ?assertEqual(14000, Cwnd).

%%====================================================================
%% Packet Sent Tests
%%====================================================================

on_packet_sent_test() ->
    State = quic_cc:new(),
    S1 = quic_cc:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc:bytes_in_flight(S1)).

on_packet_sent_multiple_test() ->
    State = quic_cc:new(),
    S1 = quic_cc:on_packet_sent(State, 1000),
    S2 = quic_cc:on_packet_sent(S1, 500),
    S3 = quic_cc:on_packet_sent(S2, 300),
    ?assertEqual(1800, quic_cc:bytes_in_flight(S3)).

%%====================================================================
%% Can Send Tests
%%====================================================================

can_send_within_cwnd_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),
    ?assert(quic_cc:can_send(State, Cwnd)),
    ?assert(quic_cc:can_send(State, Cwnd - 100)).

can_send_exceeds_cwnd_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),
    ?assertNot(quic_cc:can_send(State, Cwnd + 1)).

can_send_with_in_flight_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),
    S1 = quic_cc:on_packet_sent(State, Cwnd - 1000),
    ?assert(quic_cc:can_send(S1, 1000)),
    ?assertNot(quic_cc:can_send(S1, 1001)).

available_cwnd_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),
    ?assertEqual(Cwnd, quic_cc:available_cwnd(State)),

    S1 = quic_cc:on_packet_sent(State, 5000),
    ?assertEqual(Cwnd - 5000, quic_cc:available_cwnd(S1)).

%%====================================================================
%% Slow Start Tests
%%====================================================================

in_slow_start_initially_test() ->
    State = quic_cc:new(),
    ?assert(quic_cc:in_slow_start(State)).

slow_start_increases_cwnd_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    %% Send and ACK some packets
    S1 = quic_cc:on_packet_sent(State, 5000),
    S2 = quic_cc:on_packets_acked(S1, 5000),

    %% In slow start, cwnd should increase by bytes_acked
    NewCwnd = quic_cc:cwnd(S2),
    ?assertEqual(InitialCwnd + 5000, NewCwnd).

slow_start_exponential_growth_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    %% Simulate multiple RTTs of slow start
    S1 = quic_cc:on_packet_sent(State, InitialCwnd),
    S2 = quic_cc:on_packets_acked(S1, InitialCwnd),
    %% cwnd doubles
    ?assertEqual(InitialCwnd * 2, quic_cc:cwnd(S2)),

    S3 = quic_cc:on_packet_sent(S2, InitialCwnd * 2),
    S4 = quic_cc:on_packets_acked(S3, InitialCwnd * 2),
    %% cwnd doubles again
    ?assertEqual(InitialCwnd * 4, quic_cc:cwnd(S4)).

%%====================================================================
%% Congestion Avoidance Tests
%%====================================================================

congestion_avoidance_after_recovery_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    %% Trigger congestion event to set ssthresh and enter recovery
    S1 = quic_cc:on_packet_sent(State, 5000),
    Now = erlang:monotonic_time(millisecond),
    S2 = quic_cc:on_congestion_event(S1, Now),

    %% Should be in congestion avoidance (not slow start) but still in recovery
    ?assertNot(quic_cc:in_slow_start(S2)),
    ?assert(quic_cc:in_recovery(S2)),

    %% Verify ssthresh was set
    SSThresh = quic_cc:ssthresh(S2),
    ?assertEqual(max(trunc(InitialCwnd * 0.5), 2400), SSThresh),

    %% During recovery, cwnd doesn't increase on ACKs
    Cwnd = quic_cc:cwnd(S2),
    S3 = quic_cc:on_packet_sent(S2, 1200),
    S4 = quic_cc:on_packets_acked(S3, 1200),

    %% cwnd should stay the same during recovery
    ?assertEqual(Cwnd, quic_cc:cwnd(S4)).

%%====================================================================
%% Congestion Event Tests
%%====================================================================

congestion_event_reduces_cwnd_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),

    NewCwnd = quic_cc:cwnd(S1),
    %% cwnd should be reduced by loss reduction factor (0.5)
    ExpectedCwnd = trunc(InitialCwnd * 0.5),
    ?assertEqual(max(ExpectedCwnd, 2400), NewCwnd).

congestion_event_sets_ssthresh_test() ->
    State = quic_cc:new(),
    ?assertEqual(infinity, quic_cc:ssthresh(State)),

    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),

    SSThresh = quic_cc:ssthresh(S1),
    ?assertNotEqual(infinity, SSThresh).

congestion_event_enters_recovery_test() ->
    State = quic_cc:new(),
    ?assertNot(quic_cc:in_recovery(State)),

    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),

    ?assert(quic_cc:in_recovery(S1)).

multiple_losses_same_recovery_test() ->
    State = quic_cc:new(),
    Now = erlang:monotonic_time(millisecond),

    %% First congestion event
    S1 = quic_cc:on_congestion_event(State, Now),
    Cwnd1 = quic_cc:cwnd(S1),

    %% Second event with same sent time shouldn't reduce again

    % Earlier than recovery start
    S2 = quic_cc:on_congestion_event(S1, Now - 10),
    Cwnd2 = quic_cc:cwnd(S2),

    ?assertEqual(Cwnd1, Cwnd2).

%%====================================================================
%% Recovery Tests
%%====================================================================

no_cwnd_increase_in_recovery_test() ->
    State = quic_cc:new(),

    %% Enter recovery
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    S2 = quic_cc:on_packet_sent(S1, 1000),
    Cwnd = quic_cc:cwnd(S2),

    %% ACK packets - should not increase cwnd during recovery
    S3 = quic_cc:on_packets_acked(S2, 1000),
    ?assertEqual(Cwnd, quic_cc:cwnd(S3)).

%%====================================================================
%% Lost Packets Tests
%%====================================================================

on_packets_lost_reduces_in_flight_test() ->
    State = quic_cc:new(),
    S1 = quic_cc:on_packet_sent(State, 5000),
    ?assertEqual(5000, quic_cc:bytes_in_flight(S1)),

    S2 = quic_cc:on_packets_lost(S1, 2000),
    ?assertEqual(3000, quic_cc:bytes_in_flight(S2)).

on_packets_lost_floor_zero_test() ->
    State = quic_cc:new(),
    S1 = quic_cc:on_packet_sent(State, 1000),
    % More than in flight
    S2 = quic_cc:on_packets_lost(S1, 2000),
    ?assertEqual(0, quic_cc:bytes_in_flight(S2)).

%%====================================================================
%% Minimum Window Tests
%%====================================================================

cwnd_minimum_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    %% Trigger many congestion events
    S1 = lists:foldl(
        fun(_, Acc) ->
            Now = erlang:monotonic_time(millisecond),
            quic_cc:on_congestion_event(Acc, Now + 1000)
        end,
        State,
        lists:seq(1, 10)
    ),

    %% cwnd should not go below minimum (2 * max_datagram_size)
    FinalCwnd = quic_cc:cwnd(S1),
    ?assert(FinalCwnd >= 2400),
    ?assert(FinalCwnd < InitialCwnd).

%%====================================================================
%% Persistent Congestion Tests (RFC 9002 Section 7.6)
%%====================================================================

detect_persistent_congestion_empty_test() ->
    State = quic_cc:new(),
    ?assertNot(quic_cc:detect_persistent_congestion([], 100, State)).

detect_persistent_congestion_single_packet_test() ->
    State = quic_cc:new(),
    %% Single packet cannot establish a time span
    LostPackets = [{1, 1000}],
    ?assertNot(quic_cc:detect_persistent_congestion(LostPackets, 100, State)).

detect_persistent_congestion_below_threshold_test() ->
    State = quic_cc:new(),
    % 100ms
    PTO = 100,
    %% Lost packets span 200ms, but threshold is PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {2, 1200}],
    ?assertNot(quic_cc:detect_persistent_congestion(LostPackets, PTO, State)).

detect_persistent_congestion_at_threshold_test() ->
    State = quic_cc:new(),
    % 100ms
    PTO = 100,
    %% Lost packets span exactly PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {2, 1300}],
    ?assert(quic_cc:detect_persistent_congestion(LostPackets, PTO, State)).

detect_persistent_congestion_above_threshold_test() ->
    State = quic_cc:new(),
    % 100ms
    PTO = 100,
    %% Lost packets span 500ms, threshold is PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {5, 1500}],
    ?assert(quic_cc:detect_persistent_congestion(LostPackets, PTO, State)).

detect_persistent_congestion_multiple_packets_test() ->
    State = quic_cc:new(),
    PTO = 100,
    %% Multiple lost packets spanning > threshold
    LostPackets = [{1, 1000}, {2, 1100}, {3, 1200}, {4, 1400}],
    ?assert(quic_cc:detect_persistent_congestion(LostPackets, PTO, State)).

on_persistent_congestion_resets_cwnd_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    %% Persistent congestion should reset to minimum window
    S1 = quic_cc:on_persistent_congestion(State),
    NewCwnd = quic_cc:cwnd(S1),

    %% Minimum window is 2 * max_datagram_size = 2400
    ?assertEqual(2400, NewCwnd),
    ?assert(NewCwnd < InitialCwnd).

on_persistent_congestion_sets_ssthresh_test() ->
    State = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(State),

    S1 = quic_cc:on_persistent_congestion(State),
    SSThresh = quic_cc:ssthresh(S1),

    %% ssthresh = cwnd * 0.5
    ExpectedSSThresh = max(trunc(InitialCwnd * 0.5), 2400),
    ?assertEqual(ExpectedSSThresh, SSThresh).

on_persistent_congestion_clears_recovery_test() ->
    State = quic_cc:new(),

    %% Enter recovery first
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    ?assert(quic_cc:in_recovery(S1)),

    %% Persistent congestion should clear recovery state
    S2 = quic_cc:on_persistent_congestion(S1),
    ?assertNot(quic_cc:in_recovery(S2)).

%%====================================================================
%% Integration Tests
%%====================================================================

full_cycle_test() ->
    State = quic_cc:new(),

    %% Slow start
    S1 = quic_cc:on_packet_sent(State, 5000),
    S2 = quic_cc:on_packets_acked(S1, 5000),
    ?assert(quic_cc:in_slow_start(S2)),

    %% Congestion event
    Now = erlang:monotonic_time(millisecond),
    S3 = quic_cc:on_congestion_event(S2, Now),
    ?assertNot(quic_cc:in_slow_start(S3)),
    ?assert(quic_cc:in_recovery(S3)),

    %% Continue sending in congestion avoidance
    S4 = quic_cc:on_packet_sent(S3, 1200),
    S5 = quic_cc:on_packets_acked(S4, 1200),

    %% Should stay in congestion avoidance
    ?assertNot(quic_cc:in_slow_start(S5)).

send_until_blocked_test() ->
    State = quic_cc:new(),
    Cwnd = quic_cc:cwnd(State),

    %% Send packets until we can't send anymore
    {FinalState, Sent} = send_until_full(State, 0),

    ?assert(Sent >= Cwnd),
    ?assertNot(quic_cc:can_send(FinalState, 1200)).

%%====================================================================
%% Helper Functions
%%====================================================================

send_until_full(State, Sent) ->
    case quic_cc:can_send(State, 1200) of
        true ->
            NewState = quic_cc:on_packet_sent(State, 1200),
            send_until_full(NewState, Sent + 1200);
        false ->
            {State, Sent}
    end.
