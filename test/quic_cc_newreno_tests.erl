%%% -*- erlang -*-
%%%
%%% Tests for QUIC NewReno Congestion Control
%%%

-module(quic_cc_newreno_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% State Initialization Tests
%%====================================================================

newreno_new_state_test() ->
    State = quic_cc_newreno:new(#{}),
    %% Initial window should be 32 packets (32 * 1200 = 38400)
    Cwnd = quic_cc_newreno:cwnd(State),
    ?assertEqual(38400, Cwnd),
    ?assertEqual(infinity, quic_cc_newreno:ssthresh(State)),
    ?assertEqual(0, quic_cc_newreno:bytes_in_flight(State)),
    ?assert(quic_cc_newreno:in_slow_start(State)),
    ?assertNot(quic_cc_newreno:in_recovery(State)).

newreno_new_state_with_opts_test() ->
    State = quic_cc_newreno:new(#{max_datagram_size => 1400}),
    Cwnd = quic_cc_newreno:cwnd(State),
    ?assertEqual(32 * 1400, Cwnd),
    ?assertEqual(1400, quic_cc_newreno:max_datagram_size(State)).

newreno_new_state_custom_initial_window_test() ->
    State = quic_cc_newreno:new(#{initial_window => 65536}),
    ?assertEqual(65536, quic_cc_newreno:cwnd(State)).

newreno_algorithm_via_facade_test() ->
    State = quic_cc:new(newreno, #{}),
    ?assertEqual(newreno, quic_cc:algorithm(State)),
    ?assert(quic_cc:in_slow_start(State)).

%%====================================================================
%% Bytes Tracking Tests
%%====================================================================

newreno_on_packet_sent_test() ->
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc_newreno:bytes_in_flight(S1)).

newreno_on_packet_sent_multiple_test() ->
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 1000),
    S2 = quic_cc_newreno:on_packet_sent(S1, 500),
    S3 = quic_cc_newreno:on_packet_sent(S2, 300),
    ?assertEqual(1800, quic_cc_newreno:bytes_in_flight(S3)).

newreno_on_packets_lost_test() ->
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 5000),
    ?assertEqual(5000, quic_cc_newreno:bytes_in_flight(S1)),
    S2 = quic_cc_newreno:on_packets_lost(S1, 2000),
    ?assertEqual(3000, quic_cc_newreno:bytes_in_flight(S2)).

newreno_on_packets_lost_floor_zero_test() ->
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 1000),
    S2 = quic_cc_newreno:on_packets_lost(S1, 2000),
    ?assertEqual(0, quic_cc_newreno:bytes_in_flight(S2)).

%%====================================================================
%% Slow Start Tests
%%====================================================================

newreno_slow_start_growth_test() ->
    State = quic_cc_newreno:new(#{}),
    InitialCwnd = quic_cc_newreno:cwnd(State),
    S1 = quic_cc_newreno:on_packet_sent(State, 5000),
    S2 = quic_cc_newreno:on_packets_acked(S1, 5000),
    %% In slow start, cwnd should increase by acked bytes
    NewCwnd = quic_cc_newreno:cwnd(S2),
    ?assertEqual(InitialCwnd + 5000, NewCwnd).

newreno_congestion_avoidance_test() ->
    State = quic_cc_newreno:new(#{initial_window => 10000, min_recovery_duration => 0}),
    %% Set ssthresh to put us in congestion avoidance
    S1 = quic_cc_newreno:on_congestion_event(State, 0),
    ?assertNot(quic_cc_newreno:in_slow_start(S1)),
    %% Exit recovery by ACKing packets sent after recovery started
    Cwnd1 = quic_cc_newreno:cwnd(S1),
    S2 = quic_cc_newreno:on_packet_sent(S1, 1200),
    %% Wait a bit and ACK - this should exit recovery
    timer:sleep(10),
    Now = erlang:monotonic_time(millisecond),
    S3 = quic_cc_newreno:on_packets_acked(S2, 1200, Now),
    ?assertNot(quic_cc_newreno:in_recovery(S3)),
    Cwnd2 = quic_cc_newreno:cwnd(S3),
    %% Linear growth should be much smaller than acked bytes
    ?assert(Cwnd2 > Cwnd1),
    ?assert((Cwnd2 - Cwnd1) < 1200).

%%====================================================================
%% HyStart++ Tests (RFC 9406)
%%====================================================================

newreno_hystart_enabled_by_default_test() ->
    %% HyStart++ should be enabled by default
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 1200),
    S2 = quic_cc_newreno:on_packets_acked(S1, 1200),
    %% Should still be in slow start
    ?assert(quic_cc_newreno:in_slow_start(S2)).

newreno_hystart_disabled_test() ->
    %% Test with HyStart++ disabled
    State = quic_cc_newreno:new(#{hystart_enabled => false}),
    InitialCwnd = quic_cc_newreno:cwnd(State),
    S1 = quic_cc_newreno:on_packet_sent(State, 5000),
    S2 = quic_cc_newreno:on_packets_acked(S1, 5000),
    %% Standard slow start growth
    NewCwnd = quic_cc_newreno:cwnd(S2),
    ?assertEqual(InitialCwnd + 5000, NewCwnd),
    ?assert(quic_cc_newreno:in_slow_start(S2)).

newreno_hystart_rtt_tracking_test() ->
    %% Test that RTT samples are tracked during slow start
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 5000),
    %% Simulate RTT update
    S2 = quic_cc_newreno:update_pacing_rate(S1, 50),
    %% Should still be in slow start
    ?assert(quic_cc_newreno:in_slow_start(S2)).

newreno_hystart_slow_start_continues_test() ->
    %% Test that slow start continues normally with stable RTT
    State = quic_cc_newreno:new(#{}),
    %% Multiple rounds with stable RTT should stay in slow start
    S1 = simulate_stable_rounds(State, 5),
    ?assert(quic_cc_newreno:in_slow_start(S1)).

newreno_hystart_reset_on_congestion_test() ->
    %% Test that HyStart++ state resets on congestion event
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_packet_sent(State, 10000),
    S2 = quic_cc_newreno:on_packets_acked(S1, 5000),
    Now = erlang:monotonic_time(millisecond),
    S3 = quic_cc_newreno:on_congestion_event(S2, Now),
    %% Should be in recovery
    ?assert(quic_cc_newreno:in_recovery(S3)).

newreno_hystart_reset_on_persistent_congestion_test() ->
    %% Test that HyStart++ state resets on persistent congestion
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_persistent_congestion(State),
    %% Should be back in slow start with minimum window
    ?assertEqual(2400, quic_cc_newreno:cwnd(S1)),
    ?assert(quic_cc_newreno:in_slow_start(S1)).

%%====================================================================
%% HyStart++ Dynamic RTT Threshold Tests (RFC 9406)
%%====================================================================

newreno_hystart_dynamic_threshold_low_rtt_test() ->
    %% Low RTT (20ms): threshold = max(4, min(20/8, 16)) = max(4, 2) = 4ms
    %% The threshold is clamped to the minimum of 4ms
    State = quic_cc_newreno:new(#{}),
    %% Simulate low RTT environment
    S1 = quic_cc_newreno:update_pacing_rate(State, 20),
    S2 = quic_cc_newreno:on_packet_sent(S1, 5000),
    S3 = quic_cc_newreno:on_packets_acked(S2, 5000),
    %% Should still be in slow start since we don't have enough samples
    ?assert(quic_cc_newreno:in_slow_start(S3)).

newreno_hystart_dynamic_threshold_medium_rtt_test() ->
    %% Medium RTT (80ms): threshold = max(4, min(80/8, 16)) = max(4, 10) = 10ms
    State = quic_cc_newreno:new(#{}),
    %% Simulate medium RTT environment
    S1 = quic_cc_newreno:update_pacing_rate(State, 80),
    S2 = quic_cc_newreno:on_packet_sent(S1, 5000),
    S3 = quic_cc_newreno:on_packets_acked(S2, 5000),
    ?assert(quic_cc_newreno:in_slow_start(S3)).

newreno_hystart_dynamic_threshold_high_rtt_test() ->
    %% High RTT (200ms): threshold = max(4, min(200/8, 16)) = max(4, 16) = 16ms
    %% The threshold is clamped to the maximum of 16ms
    State = quic_cc_newreno:new(#{}),
    %% Simulate high RTT environment
    S1 = quic_cc_newreno:update_pacing_rate(State, 200),
    S2 = quic_cc_newreno:on_packet_sent(S1, 5000),
    S3 = quic_cc_newreno:on_packets_acked(S2, 5000),
    ?assert(quic_cc_newreno:in_slow_start(S3)).

%%====================================================================
%% Recovery Tests
%%====================================================================

newreno_congestion_event_enters_recovery_test() ->
    State = quic_cc_newreno:new(#{}),
    ?assertNot(quic_cc_newreno:in_recovery(State)),
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc_newreno:on_congestion_event(State, Now),
    ?assert(quic_cc_newreno:in_recovery(S1)).

newreno_recovery_cwnd_reduction_test() ->
    State = quic_cc_newreno:new(#{initial_window => 100000}),
    InitialCwnd = quic_cc_newreno:cwnd(State),
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc_newreno:on_congestion_event(State, Now),
    NewCwnd = quic_cc_newreno:cwnd(S1),
    %% cwnd should be reduced by loss reduction factor (0.7)
    ?assert(NewCwnd < InitialCwnd),
    ?assertEqual(trunc(InitialCwnd * 0.7), NewCwnd).

newreno_ecn_ce_test() ->
    State = quic_cc_newreno:new(#{}),
    ?assertEqual(0, quic_cc_newreno:ecn_ce_counter(State)),
    S1 = quic_cc_newreno:on_ecn_ce(State, 5),
    ?assertEqual(5, quic_cc_newreno:ecn_ce_counter(S1)),
    ?assert(quic_cc_newreno:in_recovery(S1)).

newreno_ecn_ce_no_duplicate_test() ->
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:on_ecn_ce(State, 5),
    %% Same or lower count should not trigger again
    S2 = quic_cc_newreno:on_ecn_ce(S1, 5),
    S3 = quic_cc_newreno:on_ecn_ce(S2, 3),
    ?assertEqual(5, quic_cc_newreno:ecn_ce_counter(S3)).

%%====================================================================
%% Persistent Congestion Tests
%%====================================================================

newreno_detect_persistent_congestion_empty_test() ->
    State = quic_cc_newreno:new(#{}),
    ?assertNot(quic_cc_newreno:detect_persistent_congestion([], 100, State)).

newreno_detect_persistent_congestion_single_packet_test() ->
    State = quic_cc_newreno:new(#{}),
    LostPackets = [{1, 1000}],
    ?assertNot(quic_cc_newreno:detect_persistent_congestion(LostPackets, 100, State)).

newreno_detect_persistent_congestion_below_threshold_test() ->
    State = quic_cc_newreno:new(#{}),
    PTO = 100,
    %% Lost packets span 200ms, but threshold is PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {2, 1200}],
    ?assertNot(quic_cc_newreno:detect_persistent_congestion(LostPackets, PTO, State)).

newreno_detect_persistent_congestion_at_threshold_test() ->
    State = quic_cc_newreno:new(#{}),
    PTO = 100,
    %% Lost packets span exactly PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {2, 1300}],
    ?assert(quic_cc_newreno:detect_persistent_congestion(LostPackets, PTO, State)).

newreno_persistent_congestion_test() ->
    State = quic_cc_newreno:new(#{initial_window => 65536}),
    InitialCwnd = quic_cc_newreno:cwnd(State),
    S1 = quic_cc_newreno:on_persistent_congestion(State),
    NewCwnd = quic_cc_newreno:cwnd(S1),
    ?assert(NewCwnd < InitialCwnd),
    %% Should reset to minimum window
    ?assertEqual(2400, NewCwnd).

%%====================================================================
%% Pacing Tests
%%====================================================================

newreno_pacing_allows_test() ->
    State = quic_cc_newreno:new(#{}),
    %% Initially should allow sending
    ?assert(quic_cc_newreno:pacing_allows(State, 1200)).

newreno_pacing_delay_initial_test() ->
    State = quic_cc_newreno:new(#{}),
    %% No delay initially
    ?assertEqual(0, quic_cc_newreno:pacing_delay(State, 1200)).

newreno_update_pacing_rate_test() ->
    State = quic_cc_newreno:new(#{}),
    S1 = quic_cc_newreno:update_pacing_rate(State, 50),
    ?assert(quic_cc_newreno:pacing_allows(S1, 1200)).

%%====================================================================
%% MTU Update Tests
%%====================================================================

newreno_update_mtu_test() ->
    State = quic_cc_newreno:new(#{max_datagram_size => 1200}),
    ?assertEqual(1200, quic_cc_newreno:max_datagram_size(State)),
    S1 = quic_cc_newreno:update_mtu(State, 1400),
    ?assertEqual(1400, quic_cc_newreno:max_datagram_size(S1)).

newreno_update_mtu_no_change_test() ->
    State = quic_cc_newreno:new(#{max_datagram_size => 1200}),
    S1 = quic_cc_newreno:update_mtu(State, 1200),
    ?assertEqual(State, S1).

%%====================================================================
%% Facade Integration Tests
%%====================================================================

newreno_via_facade_basic_test() ->
    State = quic_cc:new(newreno, #{}),
    ?assertEqual(newreno, quic_cc:algorithm(State)),
    S1 = quic_cc:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc:bytes_in_flight(S1)),
    S2 = quic_cc:on_packets_acked(S1, 1200),
    ?assertEqual(0, quic_cc:bytes_in_flight(S2)).

newreno_via_facade_with_opts_test() ->
    State = quic_cc:new(#{algorithm => newreno, max_datagram_size => 1400}),
    ?assertEqual(newreno, quic_cc:algorithm(State)),
    ?assertEqual(1400, quic_cc:max_datagram_size(State)).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Simulate multiple rounds with stable RTT
simulate_stable_rounds(State, 0) ->
    State;
simulate_stable_rounds(State, N) ->
    S1 = quic_cc_newreno:on_packet_sent(State, 5000),
    S2 = quic_cc_newreno:update_pacing_rate(S1, 50),
    S3 = quic_cc_newreno:on_packets_acked(S2, 5000),
    simulate_stable_rounds(S3, N - 1).
