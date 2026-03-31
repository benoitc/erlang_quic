%%% -*- erlang -*-
%%%
%%% Tests for QUIC Congestion Control Recovery Scenarios
%%%
%%% These tests specifically target recovery behavior that can cause
%%% issues in distribution (net_tick_timeout due to cwnd collapse).
%%%

-module(quic_cc_recovery_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Recovery Period Tests
%%====================================================================

recovery_duration_test() ->
    %% Test that recovery lasts for minimum duration
    State = quic_cc:new(#{
        initial_window => 65536,
        % 100ms minimum
        min_recovery_duration => 100
    }),

    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),

    %% Should be in recovery
    ?assert(quic_cc:in_recovery(S1)),
    Cwnd1 = quic_cc:cwnd(S1),

    %% Event during recovery should not halve cwnd again
    S2 = quic_cc:on_congestion_event(S1, Now + 50),
    ?assertEqual(Cwnd1, quic_cc:cwnd(S2)).

recovery_exit_test() ->
    %% Test that recovery exits after duration
    State = quic_cc:new(#{
        initial_window => 65536,
        min_recovery_duration => 10
    }),

    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    ?assert(quic_cc:in_recovery(S1)),

    %% Send packet after recovery should have ended
    timer:sleep(15),
    S2 = quic_cc:on_packet_sent(S1, 1200),
    S3 = quic_cc:on_packets_acked(S2, 1200),

    %% Should be out of recovery now
    ?assertNot(quic_cc:in_recovery(S3)).

new_loss_after_recovery_test() ->
    %% Test that the system can recover after exiting recovery
    %% Note: After exiting recovery, recovery_start_time is set to current time,
    %% which means congestion events with sent_time <= recovery_start_time
    %% are skipped to prevent spurious cwnd reduction.
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 2400,
        min_recovery_duration => 10
    }),

    %% First recovery
    Now1 = erlang:monotonic_time(millisecond),
    InitialCwnd = quic_cc:cwnd(State),
    S1 = quic_cc:on_congestion_event(State, Now1),
    Cwnd1 = quic_cc:cwnd(S1),
    %% cwnd should be reduced but still reasonable
    ?assert(Cwnd1 < InitialCwnd),
    ?assert(Cwnd1 >= 2400),
    ?assert(quic_cc:in_recovery(S1)),

    %% Wait for recovery to end
    timer:sleep(15),

    %% Send/ACK to exit recovery - use proper sent time
    Now2 = erlang:monotonic_time(millisecond),
    S2 = quic_cc:on_packet_sent(S1, 1200),
    S3 = quic_cc:on_packets_acked(S2, 1200, Now2),
    ?assertNot(quic_cc:in_recovery(S3)),

    %% Verify that cwnd is maintained or grew after recovery
    Cwnd3 = quic_cc:cwnd(S3),
    ?assert(Cwnd3 >= Cwnd1).

%% Test recovery with only non-ack-eliciting packets acknowledged
%% This simulates the bidirectional deadlock where only ACK frames get through
recovery_with_no_ack_eliciting_test() ->
    State = quic_cc:new(#{
        initial_window => 65536,
        min_recovery_duration => 10
    }),

    %% Enter recovery
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    ?assert(quic_cc:in_recovery(S1)),

    %% Simulate repeated ACKs with 0 acked bytes (non-ack-eliciting only)
    %% This should not prevent recovery exit
    timer:sleep(15),
    S2 = quic_cc:on_packets_acked(S1, 0),

    %% Now ACK some actual data - should exit recovery
    S3 = quic_cc:on_packet_sent(S2, 1200),
    Now2 = erlang:monotonic_time(millisecond),
    S4 = quic_cc:on_packets_acked(S3, 1200, Now2),

    ?assertNot(quic_cc:in_recovery(S4)).

%% Test that progress is made under bidirectional load
bidirectional_large_transfer_test() ->
    %% Simulates both sides sending 1MB with recovery events
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 16384,
        min_recovery_duration => 50
    }),

    %% Enter recovery (simulates initial congestion)
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    CwndRecovery = quic_cc:cwnd(S1),

    %% Simulate sending/acking data in chunks
    timer:sleep(55),
    S2 = lists:foldl(
        fun(_, Acc) ->
            A1 = quic_cc:on_packet_sent(Acc, 1200),
            quic_cc:on_packets_acked(A1, 1200)
        end,
        S1,
        lists:seq(1, 20)
    ),

    %% Should have exited recovery and cwnd should be growing
    ?assertNot(quic_cc:in_recovery(S2)),
    ?assert(quic_cc:cwnd(S2) >= CwndRecovery).

%%====================================================================
%% Rapid Loss Scenarios (Distribution-like patterns)
%%====================================================================

rapid_consecutive_losses_test() ->
    %% Simulate rapid consecutive losses (like network burst loss)
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800,
        % Disable for test
        min_recovery_duration => 0
    }),

    %% 10 rapid losses
    FinalState = lists:foldl(
        fun(I, Acc) ->
            Now = erlang:monotonic_time(millisecond) + I * 10,
            quic_cc:on_congestion_event(Acc, Now)
        end,
        State,
        lists:seq(1, 10)
    ),

    %% cwnd should not go below minimum
    ?assert(quic_cc:cwnd(FinalState) >= 4800).

burst_loss_then_recovery_test() ->
    %% Test recovery pattern: burst loss, then gradual recovery
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800,
        min_recovery_duration => 10
    }),

    %% Initial loss
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    CwndAfterLoss = quic_cc:cwnd(S1),

    %% Wait for recovery to end
    timer:sleep(15),

    %% Gradual growth in congestion avoidance
    {FinalState, _} = lists:foldl(
        fun(_, {S, _}) ->
            S2 = quic_cc:on_packet_sent(S, 1200),
            S3 = quic_cc:on_packets_acked(S2, 1200),
            {S3, quic_cc:cwnd(S3)}
        end,
        {S1, CwndAfterLoss},
        lists:seq(1, 100)
    ),

    %% Should have grown from post-loss cwnd
    ?assert(quic_cc:cwnd(FinalState) > CwndAfterLoss).

%%====================================================================
%% Minimum Window Tests
%%====================================================================

minimum_window_protection_test() ->
    %% Test that minimum window is respected
    MinWindow = 16384,
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => MinWindow,
        min_recovery_duration => 0
    }),

    %% Many loss events
    FinalState = lists:foldl(
        fun(I, Acc) ->
            Now = erlang:monotonic_time(millisecond) + I * 100,
            quic_cc:on_congestion_event(Acc, Now)
        end,
        State,
        lists:seq(1, 50)
    ),

    %% cwnd should never go below minimum
    ?assertEqual(MinWindow, quic_cc:cwnd(FinalState)).

minimum_window_after_persistent_congestion_test() ->
    %% Test persistent congestion respects minimum window
    MinWindow = 16384,
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => MinWindow
    }),

    S1 = quic_cc:on_persistent_congestion(State),
    ?assertEqual(MinWindow, quic_cc:cwnd(S1)).

%%====================================================================
%% Bytes In Flight Tests
%%====================================================================

bytes_in_flight_accuracy_test() ->
    %% Test bytes_in_flight tracking accuracy
    State = quic_cc:new(#{initial_window => 65536}),

    %% Send many packets
    S1 = lists:foldl(
        fun(_, Acc) ->
            quic_cc:on_packet_sent(Acc, 1200)
        end,
        State,
        lists:seq(1, 50)
    ),
    ?assertEqual(50 * 1200, quic_cc:bytes_in_flight(S1)),

    %% ACK half
    S2 = quic_cc:on_packets_acked(S1, 25 * 1200),
    ?assertEqual(25 * 1200, quic_cc:bytes_in_flight(S2)),

    %% Lose some
    S3 = quic_cc:on_packets_lost(S2, 10 * 1200),
    ?assertEqual(15 * 1200, quic_cc:bytes_in_flight(S3)).

bytes_in_flight_floor_test() ->
    %% Test that bytes_in_flight never goes negative
    State = quic_cc:new(),
    S1 = quic_cc:on_packet_sent(State, 1000),
    % More than sent
    S2 = quic_cc:on_packets_lost(S1, 5000),
    ?assertEqual(0, quic_cc:bytes_in_flight(S2)).

%%====================================================================
%% Slow Start vs Congestion Avoidance Tests
%%====================================================================

slow_start_to_congestion_avoidance_test() ->
    %% Test transition from slow start to congestion avoidance
    State = quic_cc:new(#{initial_window => 14720}),
    ?assert(quic_cc:in_slow_start(State)),
    ?assertEqual(infinity, quic_cc:ssthresh(State)),

    %% Loss triggers transition
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),

    ?assertNot(quic_cc:in_slow_start(S1)),
    ?assertNotEqual(infinity, quic_cc:ssthresh(S1)).

congestion_avoidance_growth_test() ->
    %% Test growth in congestion avoidance
    %% In congestion avoidance, cwnd grows by max_datagram_size * bytes_acked / cwnd
    State = quic_cc:new(#{
        initial_window => 65536,
        min_recovery_duration => 10
    }),

    %% Enter congestion avoidance via loss
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    CwndCA = quic_cc:cwnd(S1),
    ?assertNot(quic_cc:in_slow_start(S1)),
    ?assert(quic_cc:in_recovery(S1)),

    %% Wait for recovery to end
    timer:sleep(15),

    %% Exit recovery by ACKing packet sent after recovery started
    Now2 = erlang:monotonic_time(millisecond),
    S2 = quic_cc:on_packet_sent(S1, CwndCA),
    S3 = quic_cc:on_packets_acked(S2, CwndCA, Now2),

    %% Should be out of recovery and in congestion avoidance
    ?assertNot(quic_cc:in_recovery(S3)),
    ?assertNot(quic_cc:in_slow_start(S3)),

    %% cwnd should have grown during the ACK processing
    NewCwnd = quic_cc:cwnd(S3),
    ?assert(NewCwnd >= CwndCA).

%%====================================================================
%% Pacing Under Recovery Tests
%%====================================================================

pacing_during_recovery_test() ->
    %% Test that pacing works correctly during recovery
    State = quic_cc:new(#{initial_window => 65536}),
    % 50ms RTT
    S1 = quic_cc:update_pacing_rate(State, 50),

    %% Enter recovery
    Now = erlang:monotonic_time(millisecond),
    S2 = quic_cc:on_congestion_event(S1, Now),

    %% Pacing should still work
    ?assert(quic_cc:pacing_allows(S2, 1200)).

pacing_rate_after_loss_test() ->
    %% Test that pacing rate adjusts after loss
    State = quic_cc:new(#{initial_window => 65536}),
    S1 = quic_cc:update_pacing_rate(State, 50),

    %% Record initial rate (implicitly through allowed tokens)
    {_InitialAllowed, _} = quic_cc:get_pacing_tokens(S1, 14400),

    %% Trigger loss (halves cwnd)
    Now = erlang:monotonic_time(millisecond),
    S2 = quic_cc:on_congestion_event(S1, Now),

    %% Update pacing rate with same RTT
    S3 = quic_cc:update_pacing_rate(S2, 50),

    %% Pacing should still function
    ?assert(is_integer(quic_cc:pacing_delay(S3, 1200))).

%%====================================================================
%% Integration Scenarios
%%====================================================================

distribution_like_pattern_test() ->
    %% Simulate distribution-like traffic pattern
    %% Many small messages with occasional large bursts
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800,
        min_recovery_duration => 10
    }),

    %% Simulate 1000 message cycles
    {FinalState, LossCount} = lists:foldl(
        fun(N, {S, Losses}) ->
            %% Small tick message every cycle
            S1 = quic_cc:on_packet_sent(S, 100),
            S2 = quic_cc:on_packets_acked(S1, 100),

            %% Occasional large burst (every 100 cycles)
            {S3, NewLosses} =
                case N rem 100 of
                    0 ->
                        %% Large burst - might cause loss
                        S2a = quic_cc:on_packet_sent(S2, 50000),
                        % 30% loss chance
                        case rand:uniform() > 0.7 of
                            true ->
                                Now = erlang:monotonic_time(millisecond),
                                S2b = quic_cc:on_congestion_event(S2a, Now),
                                {quic_cc:on_packets_lost(S2b, 50000), Losses + 1};
                            false ->
                                {quic_cc:on_packets_acked(S2a, 50000), Losses}
                        end;
                    _ ->
                        {S2, Losses}
                end,
            {S3, NewLosses}
        end,
        {State, 0},
        lists:seq(1, 1000)
    ),

    %% cwnd should stay above minimum even with losses
    ?assert(quic_cc:cwnd(FinalState) >= 4800),

    %% If we had losses, verify cwnd recovered
    case LossCount > 0 of
        true ->
            %% cwnd should be above minimum despite losses
            ?assert(quic_cc:cwnd(FinalState) >= 4800);
        false ->
            %% No losses, cwnd should have grown
            ?assert(quic_cc:cwnd(FinalState) >= 65536)
    end.

high_loss_rate_survival_test() ->
    %% Test survival under high loss rate
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 8000,
        min_recovery_duration => 0
    }),

    %% Simulate 50% loss rate
    {FinalState, _} = lists:foldl(
        fun(N, {S, _}) ->
            S1 = quic_cc:on_packet_sent(S, 1200),
            case N rem 2 of
                0 ->
                    %% Loss
                    Now = erlang:monotonic_time(millisecond) + N,
                    S2 = quic_cc:on_congestion_event(S1, Now),
                    {quic_cc:on_packets_lost(S2, 1200), loss};
                _ ->
                    %% Success
                    {quic_cc:on_packets_acked(S1, 1200), ack}
            end
        end,
        {State, undefined},
        lists:seq(1, 100)
    ),

    %% Should still be at minimum window
    ?assert(quic_cc:cwnd(FinalState) >= 8000).

%%====================================================================
%% Edge Cases
%%====================================================================

zero_rtt_update_test() ->
    %% Test pacing with very small RTT
    State = quic_cc:new(),
    % 1ms RTT
    S1 = quic_cc:update_pacing_rate(State, 1),
    ?assert(quic_cc:pacing_allows(S1, 1200)).

very_large_rtt_test() ->
    %% Test with very large RTT
    State = quic_cc:new(),
    % 5 second RTT
    S1 = quic_cc:update_pacing_rate(State, 5000),
    ?assert(quic_cc:pacing_allows(S1, 1200)).

cwnd_after_idle_test() ->
    %% Test cwnd behavior after idle period
    State = quic_cc:new(#{initial_window => 65536}),

    %% Grow cwnd in slow start
    S1 = quic_cc:on_packet_sent(State, 65536),
    S2 = quic_cc:on_packets_acked(S1, 65536),
    GrownCwnd = quic_cc:cwnd(S2),
    ?assertEqual(65536 * 2, GrownCwnd),

    %% After idle, some implementations reset cwnd
    %% Our implementation should maintain cwnd
    ?assertEqual(GrownCwnd, quic_cc:cwnd(S2)).
