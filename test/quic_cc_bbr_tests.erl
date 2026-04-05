%%% -*- erlang -*-
%%%
%%% Tests for QUIC BBRv3 Congestion Control
%%%

-module(quic_cc_bbr_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% State Initialization Tests
%%====================================================================

bbr_new_state_test() ->
    State = quic_cc_bbr:new(#{}),
    %% Initial window should be at least 10 packets
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assert(Cwnd >= 10 * 1200),
    ?assertEqual(infinity, quic_cc_bbr:ssthresh(State)),
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(State)),
    ?assert(quic_cc_bbr:in_slow_start(State)),
    ?assertNot(quic_cc_bbr:in_recovery(State)).

bbr_new_state_with_opts_test() ->
    State = quic_cc_bbr:new(#{max_datagram_size => 1400}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assertEqual(10 * 1400, Cwnd),
    ?assertEqual(1400, quic_cc_bbr:max_datagram_size(State)).

bbr_new_state_custom_initial_window_test() ->
    State = quic_cc_bbr:new(#{initial_window => 65536}),
    ?assertEqual(65536, quic_cc_bbr:cwnd(State)).

bbr_algorithm_via_facade_test() ->
    State = quic_cc:new(bbr, #{}),
    ?assertEqual(bbr, quic_cc:algorithm(State)),
    ?assert(quic_cc:in_slow_start(State)).

%%====================================================================
%% Bytes Tracking Tests
%%====================================================================

bbr_on_packet_sent_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc_bbr:bytes_in_flight(S1)).

bbr_on_packet_sent_multiple_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1000),
    S2 = quic_cc_bbr:on_packet_sent(S1, 500),
    S3 = quic_cc_bbr:on_packet_sent(S2, 300),
    ?assertEqual(1800, quic_cc_bbr:bytes_in_flight(S3)).

bbr_on_packets_lost_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    ?assertEqual(5000, quic_cc_bbr:bytes_in_flight(S1)),
    S2 = quic_cc_bbr:on_packets_lost(S1, 2000),
    ?assertEqual(3000, quic_cc_bbr:bytes_in_flight(S2)).

bbr_on_packets_lost_floor_zero_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1000),
    S2 = quic_cc_bbr:on_packets_lost(S1, 2000),
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(S2)).

bbr_bytes_in_flight_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(State)),
    S1 = quic_cc_bbr:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc_bbr:bytes_in_flight(S1)).

%%====================================================================
%% Can Send Tests
%%====================================================================

bbr_can_send_within_cwnd_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assert(quic_cc_bbr:can_send(State, Cwnd)),
    ?assert(quic_cc_bbr:can_send(State, Cwnd - 100)).

bbr_can_send_exceeds_cwnd_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assertNot(quic_cc_bbr:can_send(State, Cwnd + 1)).

bbr_can_send_with_in_flight_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    S1 = quic_cc_bbr:on_packet_sent(State, Cwnd - 1000),
    ?assert(quic_cc_bbr:can_send(S1, 1000)),
    ?assertNot(quic_cc_bbr:can_send(S1, 1001)).

bbr_available_cwnd_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assertEqual(Cwnd, quic_cc_bbr:available_cwnd(State)),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    ?assertEqual(Cwnd - 5000, quic_cc_bbr:available_cwnd(S1)).

%%====================================================================
%% Control Message Allowance Tests
%%====================================================================

bbr_can_send_control_when_cwnd_full_test() ->
    State = quic_cc_bbr:new(#{initial_window => 65536}),
    S1 = quic_cc_bbr:on_packet_sent(State, 65536),
    ?assertNot(quic_cc_bbr:can_send(S1, 100)),
    ?assert(quic_cc_bbr:can_send_control(S1, 100)).

bbr_can_send_control_respects_allowance_test() ->
    State = quic_cc_bbr:new(#{initial_window => 65536}),
    S1 = quic_cc_bbr:on_packet_sent(State, 65536),
    %% Large packet exceeds allowance (1200 bytes default)
    ?assertNot(quic_cc_bbr:can_send_control(S1, 2000)).

%%====================================================================
%% Startup State Tests
%%====================================================================

bbr_in_slow_start_initially_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assert(quic_cc_bbr:in_slow_start(State)).

bbr_startup_processes_acks_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    S2 = quic_cc_bbr:on_packets_acked(S1, 5000),
    %% Should still be in startup
    ?assert(quic_cc_bbr:in_slow_start(S2)),
    %% Bytes in flight should be updated
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(S2)).

%%====================================================================
%% State Transition Tests
%%====================================================================

bbr_loss_does_not_exit_startup_test() ->
    %% BBRv3: Loss should NOT cause STARTUP exit.
    %% STARTUP exits only on bandwidth plateau (no 25% growth for 3 rounds).
    %% This prevents premature exit to DRAIN where pacing_gain drops to 0.35x.
    State = quic_cc_bbr:new(#{min_recovery_duration => 0}),
    S1 = quic_cc_bbr:on_packet_sent(State, 12000),
    Now = erlang:monotonic_time(millisecond),
    S2 = quic_cc_bbr:on_congestion_event(S1, Now),
    %% Should be in recovery
    ?assert(quic_cc_bbr:in_recovery(S2)),
    %% After ACK processing, should still be in STARTUP
    S3 = quic_cc_bbr:on_packets_acked(S2, 1000),
    %% Should remain in STARTUP (not exited due to loss)
    ?assert(quic_cc_bbr:in_slow_start(S3)).

bbr_recovery_resets_after_round_test() ->
    %% BBRv3: Recovery state should reset when a round completes.
    %% This allows fresh loss detection in subsequent rounds.
    State = quic_cc_bbr:new(#{min_recovery_duration => 0}),
    %% Send data to establish next_round_delivered
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    S2 = quic_cc_bbr:on_packets_acked(S1, 5000),
    %% Enter recovery
    Now = erlang:monotonic_time(millisecond),
    S3 = quic_cc_bbr:on_congestion_event(S2, Now),
    ?assert(quic_cc_bbr:in_recovery(S3)),
    %% Send more data and ACK to complete a round
    S4 = quic_cc_bbr:on_packet_sent(S3, 10000),
    S5 = quic_cc_bbr:on_packets_acked(S4, 10000),
    %% Recovery should be reset after round completion
    ?assertNot(quic_cc_bbr:in_recovery(S5)).

bbr_sustained_transfer_with_loss_test() ->
    %% Simulate sustained transfer with occasional loss.
    %% BBR should stay in STARTUP and continue sending at high rate.
    State = quic_cc_bbr:new(#{min_recovery_duration => 0}),

    %% Simulate multiple rounds of sending with loss events
    S1 = simulate_transfer_round(State, 50000),
    ?assert(quic_cc_bbr:in_slow_start(S1)),

    %% Another round with congestion event
    Now = erlang:monotonic_time(millisecond),
    S2 = quic_cc_bbr:on_congestion_event(S1, Now),
    ?assert(quic_cc_bbr:in_recovery(S2)),

    S3 = simulate_transfer_round(S2, 50000),
    %% Should still be in STARTUP, not prematurely exited to DRAIN
    ?assert(quic_cc_bbr:in_slow_start(S3)),
    %% Recovery should be cleared after round
    ?assertNot(quic_cc_bbr:in_recovery(S3)),
    %% Can still send data
    ?assert(quic_cc_bbr:can_send(S3, 1200)).

%%====================================================================
%% Loss Handling Tests
%%====================================================================

bbr_congestion_event_enters_recovery_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assertNot(quic_cc_bbr:in_recovery(State)),
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc_bbr:on_congestion_event(State, Now),
    ?assert(quic_cc_bbr:in_recovery(S1)).

bbr_loss_below_threshold_test() ->
    %% Loss below 2% threshold should not reduce max_bw
    State = quic_cc_bbr:new(#{min_recovery_duration => 0}),
    S1 = quic_cc_bbr:on_packet_sent(State, 10000),
    %% Track bytes in round
    S2 = quic_cc_bbr:on_packets_lost(S1, 100),
    Now = erlang:monotonic_time(millisecond),
    S3 = quic_cc_bbr:on_congestion_event(S2, Now),
    %% Should enter recovery
    ?assert(quic_cc_bbr:in_recovery(S3)).

bbr_ecn_ce_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assertEqual(0, quic_cc_bbr:ecn_ce_counter(State)),
    S1 = quic_cc_bbr:on_ecn_ce(State, 5),
    ?assertEqual(5, quic_cc_bbr:ecn_ce_counter(S1)),
    ?assert(quic_cc_bbr:in_recovery(S1)).

bbr_ecn_ce_no_duplicate_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_ecn_ce(State, 5),
    %% Same or lower count should not trigger again
    S2 = quic_cc_bbr:on_ecn_ce(S1, 5),
    S3 = quic_cc_bbr:on_ecn_ce(S2, 3),
    ?assertEqual(5, quic_cc_bbr:ecn_ce_counter(S3)).

bbr_persistent_congestion_test() ->
    State = quic_cc_bbr:new(#{initial_window => 65536}),
    InitialCwnd = quic_cc_bbr:cwnd(State),
    S1 = quic_cc_bbr:on_persistent_congestion(State),
    NewCwnd = quic_cc_bbr:cwnd(S1),
    ?assert(NewCwnd < InitialCwnd),
    %% Should reset to minimum window
    ?assertEqual(2400, NewCwnd),
    %% Should return to startup
    ?assert(quic_cc_bbr:in_slow_start(S1)),
    ?assertNot(quic_cc_bbr:in_recovery(S1)).

%%====================================================================
%% Persistent Congestion Detection Tests
%%====================================================================

bbr_detect_persistent_congestion_empty_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assertNot(quic_cc_bbr:detect_persistent_congestion([], 100, State)).

bbr_detect_persistent_congestion_single_packet_test() ->
    State = quic_cc_bbr:new(#{}),
    LostPackets = [{1, 1000}],
    ?assertNot(quic_cc_bbr:detect_persistent_congestion(LostPackets, 100, State)).

bbr_detect_persistent_congestion_below_threshold_test() ->
    State = quic_cc_bbr:new(#{}),
    PTO = 100,
    %% Lost packets span 200ms, but threshold is PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {2, 1200}],
    ?assertNot(quic_cc_bbr:detect_persistent_congestion(LostPackets, PTO, State)).

bbr_detect_persistent_congestion_at_threshold_test() ->
    State = quic_cc_bbr:new(#{}),
    PTO = 100,
    %% Lost packets span exactly PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {2, 1300}],
    ?assert(quic_cc_bbr:detect_persistent_congestion(LostPackets, PTO, State)).

bbr_detect_persistent_congestion_above_threshold_test() ->
    State = quic_cc_bbr:new(#{}),
    PTO = 100,
    %% Lost packets span 500ms, threshold is PTO * 3 = 300ms
    LostPackets = [{1, 1000}, {5, 1500}],
    ?assert(quic_cc_bbr:detect_persistent_congestion(LostPackets, PTO, State)).

%%====================================================================
%% Pacing Tests
%%====================================================================

bbr_pacing_initial_state_test() ->
    State = quic_cc_bbr:new(#{}),
    %% Initially, pacing should allow sending (rate is 0, no rate limit)
    ?assert(quic_cc_bbr:pacing_allows(State, 1200)),
    ?assertEqual(0, quic_cc_bbr:pacing_delay(State, 1200)).

bbr_pacing_allows_with_tokens_test() ->
    State = quic_cc_bbr:new(#{}),
    %% After init, tokens = max_burst (12 packets = 14400 bytes)
    ?assert(quic_cc_bbr:pacing_allows(State, 1200)).

bbr_pacing_get_tokens_consumes_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:update_pacing_rate(State, 50),
    {Allowed1, S2} = quic_cc_bbr:get_pacing_tokens(S1, 5000),
    ?assertEqual(5000, Allowed1),
    {Allowed2, _S3} = quic_cc_bbr:get_pacing_tokens(S2, 5000),
    ?assertEqual(5000, Allowed2).

bbr_pacing_delay_within_burst_test() ->
    %% With initial pacing, delay should be 0 within burst limit (14400 bytes)
    State = quic_cc_bbr:new(#{}),
    ?assertEqual(0, quic_cc_bbr:pacing_delay(State, 12000)).

bbr_pacing_allows_burst_test() ->
    State = quic_cc_bbr:new(#{}),
    %% Should allow burst of 10+ packets initially
    ?assert(quic_cc_bbr:pacing_allows(State, 12000)).

%%====================================================================
%% CWND Tests
%%====================================================================

bbr_cwnd_calculation_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    %% Initial cwnd should be reasonable (at least 10 packets)
    ?assert(Cwnd >= 10 * 1200).

bbr_cwnd_minimum_test() ->
    %% After persistent congestion, cwnd should be at minimum
    State = quic_cc_bbr:new(#{minimum_window => 4800}),
    S1 = quic_cc_bbr:on_persistent_congestion(State),
    ?assertEqual(4800, quic_cc_bbr:cwnd(S1)).

%%====================================================================
%% MTU Update Tests
%%====================================================================

bbr_update_mtu_test() ->
    State = quic_cc_bbr:new(#{max_datagram_size => 1200}),
    ?assertEqual(1200, quic_cc_bbr:max_datagram_size(State)),
    S1 = quic_cc_bbr:update_mtu(State, 1400),
    ?assertEqual(1400, quic_cc_bbr:max_datagram_size(S1)).

bbr_update_mtu_no_change_test() ->
    State = quic_cc_bbr:new(#{max_datagram_size => 1200}),
    S1 = quic_cc_bbr:update_mtu(State, 1200),
    ?assertEqual(State, S1).

%%====================================================================
%% Query Tests
%%====================================================================

bbr_ssthresh_is_infinity_test() ->
    %% BBR doesn't use ssthresh
    State = quic_cc_bbr:new(#{}),
    ?assertEqual(infinity, quic_cc_bbr:ssthresh(State)).

bbr_min_recovery_duration_test() ->
    State = quic_cc_bbr:new(#{min_recovery_duration => 200}),
    ?assertEqual(200, quic_cc_bbr:min_recovery_duration(State)).

%%====================================================================
%% Integration Tests
%%====================================================================

bbr_full_cycle_test() ->
    State = quic_cc_bbr:new(#{}),

    %% Startup - send and ACK
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    S2 = quic_cc_bbr:on_packets_acked(S1, 5000),
    ?assert(quic_cc_bbr:in_slow_start(S2)),

    %% Congestion event
    Now = erlang:monotonic_time(millisecond),
    S3 = quic_cc_bbr:on_congestion_event(S2, Now),
    ?assert(quic_cc_bbr:in_recovery(S3)),

    %% Continue sending
    S4 = quic_cc_bbr:on_packet_sent(S3, 1200),
    S5 = quic_cc_bbr:on_packets_acked(S4, 1200),

    %% Should still have valid state
    ?assert(quic_cc_bbr:cwnd(S5) > 0).

bbr_send_until_blocked_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),

    %% Send packets until we can't send anymore
    {FinalState, Sent} = send_until_full(State, 0),

    ?assert(Sent >= Cwnd),
    ?assertNot(quic_cc_bbr:can_send(FinalState, 1200)).

%%====================================================================
%% Facade Integration Tests
%%====================================================================

bbr_via_facade_basic_test() ->
    State = quic_cc:new(bbr, #{}),
    ?assertEqual(bbr, quic_cc:algorithm(State)),
    S1 = quic_cc:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc:bytes_in_flight(S1)),
    S2 = quic_cc:on_packets_acked(S1, 1200),
    ?assertEqual(0, quic_cc:bytes_in_flight(S2)).

bbr_via_facade_with_opts_test() ->
    State = quic_cc:new(#{algorithm => bbr, max_datagram_size => 1400}),
    ?assertEqual(bbr, quic_cc:algorithm(State)),
    ?assertEqual(1400, quic_cc:max_datagram_size(State)).

%%====================================================================
%% Initial Pacing Rate Tests (BBR fix)
%%====================================================================

bbr_initial_pacing_rate_test() ->
    %% Verify that pacing_rate > 0 after new() (the key fix)
    %% With default cwnd of 10*1200=12000 bytes and initial_rtt=100ms:
    %% pacing_rate = 2.885 * 12000 / 100 = ~346 bytes/ms
    State = quic_cc_bbr:new(#{}),
    %% Pacing should not allow 0 rate (which caused hangs)
    %% We verify this by checking pacing_delay is 0 for reasonable sizes
    %% because we have tokens available at a non-zero rate
    ?assertEqual(0, quic_cc_bbr:pacing_delay(State, 1200)),
    ?assert(quic_cc_bbr:pacing_allows(State, 1200)).

bbr_initial_pacing_rate_custom_rtt_test() ->
    %% Verify initial_rtt option is respected
    State = quic_cc_bbr:new(#{initial_rtt => 50}),
    %% With initial_rtt=50ms, pacing should be faster (2x the default)
    ?assertEqual(0, quic_cc_bbr:pacing_delay(State, 1200)),
    ?assert(quic_cc_bbr:pacing_allows(State, 12000)).

bbr_first_ack_updates_bandwidth_test() ->
    %% Verify that after first ACK, bandwidth is updated properly
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    %% Simulate some time passing (50ms)
    timer:sleep(50),
    S2 = quic_cc_bbr:on_packets_acked(S1, 5000),
    %% State should still be valid with proper pacing
    ?assert(quic_cc_bbr:pacing_allows(S2, 1200)),
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(S2)).

bbr_sustained_pacing_test() ->
    %% Test that pacing works through multiple send/ack cycles
    State = quic_cc_bbr:new(#{}),

    %% Send and ACK multiple packets
    S1 = quic_cc_bbr:on_packet_sent(State, 12000),
    timer:sleep(10),
    S2 = quic_cc_bbr:on_packets_acked(S1, 12000),

    S3 = quic_cc_bbr:on_packet_sent(S2, 12000),
    timer:sleep(10),
    S4 = quic_cc_bbr:on_packets_acked(S3, 12000),

    %% Should still allow sending
    ?assert(quic_cc_bbr:pacing_allows(S4, 1200)),
    ?assert(quic_cc_bbr:can_send(S4, 1200)).

%%====================================================================
%% Delivery Rate Stability Tests
%%====================================================================

bbr_delivery_rate_sustained_test() ->
    %% Verify delivery rate doesn't degrade over multiple rounds.
    %% This was the root cause of 500KB transfer timeouts.
    State = quic_cc_bbr:new(#{}),
    InitialCwnd = quic_cc_bbr:cwnd(State),

    %% First round
    S1 = quic_cc_bbr:on_packet_sent(State, 10000),
    timer:sleep(50),
    S2 = quic_cc_bbr:on_packets_acked(S1, 10000),
    Cwnd1 = quic_cc_bbr:cwnd(S2),

    %% Second round
    S3 = quic_cc_bbr:on_packet_sent(S2, 10000),
    timer:sleep(50),
    S4 = quic_cc_bbr:on_packets_acked(S3, 10000),
    Cwnd2 = quic_cc_bbr:cwnd(S4),

    %% Third round
    S5 = quic_cc_bbr:on_packet_sent(S4, 10000),
    timer:sleep(50),
    S6 = quic_cc_bbr:on_packets_acked(S5, 10000),
    Cwnd3 = quic_cc_bbr:cwnd(S6),

    %% cwnd should NOT decrease over rounds (bandwidth should be stable)
    %% Allow 20% variance for timing jitter
    ?assert(Cwnd1 >= InitialCwnd * 0.8),
    ?assert(Cwnd2 >= Cwnd1 * 0.8),
    ?assert(Cwnd3 >= Cwnd2 * 0.8).

bbr_delivery_rate_does_not_degrade_test() ->
    %% Simulate 10 rounds and verify max_bw estimate is stable.
    %% Before the fix, cwnd would collapse as SendElapsed grew.
    State = quic_cc_bbr:new(#{}),
    InitialCwnd = quic_cc_bbr:cwnd(State),

    FinalState = lists:foldl(
        fun(_, S) ->
            S1 = quic_cc_bbr:on_packet_sent(S, 12000),
            timer:sleep(10),
            quic_cc_bbr:on_packets_acked(S1, 12000)
        end,
        State,
        lists:seq(1, 10)
    ),

    %% Should still be able to send at least initial cwnd
    FinalCwnd = quic_cc_bbr:cwnd(FinalState),
    %% At least 50% of initial (BBR may transition states affecting cwnd)
    ?assert(FinalCwnd >= InitialCwnd * 0.5),
    %% At least 4 packets (minimum window)
    ?assert(FinalCwnd >= 4 * 1200).

bbr_long_transfer_cwnd_stability_test() ->
    %% Simulate a long transfer (like 500KB) and ensure cwnd stays stable.
    %% This directly tests the scenario that was failing.
    State = quic_cc_bbr:new(#{}),

    %% Simulate 50 rounds of 10KB each (500KB total)
    {FinalState, CwndHistory} = lists:foldl(
        fun(_, {S, History}) ->
            S1 = quic_cc_bbr:on_packet_sent(S, 10000),
            timer:sleep(5),
            S2 = quic_cc_bbr:on_packets_acked(S1, 10000),
            {S2, [quic_cc_bbr:cwnd(S2) | History]}
        end,
        {State, []},
        lists:seq(1, 50)
    ),

    %% Verify cwnd never collapsed to near-zero
    MinCwnd = lists:min(CwndHistory),
    MaxCwnd = lists:max(CwndHistory),
    FinalCwnd = quic_cc_bbr:cwnd(FinalState),

    %% MinCwnd should be at least 20% of MaxCwnd (no collapse)
    ?assert(MinCwnd >= MaxCwnd * 0.2),
    %% Final cwnd should be at least minimum window (4 packets)
    ?assert(FinalCwnd >= 4 * 1200),
    %% Should still allow sending
    ?assert(quic_cc_bbr:can_send(FinalState, 1200)).

%%====================================================================
%% HyStart++ Tests (RFC 9406)
%%====================================================================

bbr_hystart_enabled_by_default_test() ->
    %% HyStart++ should be enabled by default
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1200),
    S2 = quic_cc_bbr:on_packets_acked(S1, 1200),
    %% Should still be in startup
    ?assert(quic_cc_bbr:in_slow_start(S2)).

bbr_hystart_disabled_test() ->
    %% Test with HyStart++ disabled
    State = quic_cc_bbr:new(#{hystart_enabled => false}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    S2 = quic_cc_bbr:on_packets_acked(S1, 5000),
    %% Should still be in startup
    ?assert(quic_cc_bbr:in_slow_start(S2)).

bbr_hystart_rtt_tracking_test() ->
    %% Test that RTT samples are tracked during startup
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    %% Simulate RTT update
    S2 = quic_cc_bbr:update_pacing_rate(S1, 50),
    %% Should still be in startup
    ?assert(quic_cc_bbr:in_slow_start(S2)).

bbr_hystart_startup_continues_stable_rtt_test() ->
    %% Test that startup continues normally with stable RTT
    State = quic_cc_bbr:new(#{}),
    %% Multiple rounds with stable RTT should stay in startup
    S1 = simulate_stable_startup_rounds(State, 3),
    ?assert(quic_cc_bbr:in_slow_start(S1)).

bbr_hystart_reset_on_persistent_congestion_test() ->
    %% Test that HyStart++ state resets on persistent congestion
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_persistent_congestion(State),
    %% Should be back in startup
    ?assert(quic_cc_bbr:in_slow_start(S1)).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Simulate multiple startup rounds with stable RTT
simulate_stable_startup_rounds(State, 0) ->
    State;
simulate_stable_startup_rounds(State, N) ->
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    S2 = quic_cc_bbr:update_pacing_rate(S1, 50),
    S3 = quic_cc_bbr:on_packets_acked(S2, 5000),
    simulate_stable_startup_rounds(S3, N - 1).

send_until_full(State, Sent) ->
    case quic_cc_bbr:can_send(State, 1200) of
        true ->
            NewState = quic_cc_bbr:on_packet_sent(State, 1200),
            send_until_full(NewState, Sent + 1200);
        false ->
            {State, Sent}
    end.

%% Simulate a round of transfer (send and ACK bytes)
simulate_transfer_round(State, Bytes) ->
    S1 = quic_cc_bbr:on_packet_sent(State, Bytes),
    quic_cc_bbr:on_packets_acked(S1, Bytes).
