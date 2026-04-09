%%% -*- erlang -*-
%%%
%%% Distribution Simulation Tests for QUIC
%%%
%%% These tests simulate the actual conditions causing net_tick_timeout
%%% in Docker distribution tests: large data bursts causing congestion
%%% that blocks tick messages.
%%%

-module(quic_dist_simulation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Tick Message Blocking Test
%%====================================================================

tick_blocked_by_cwnd_collapse_test() ->
    %% Simulate: Large data causes losses, cwnd collapses, ticks can't get through
    %% This is the net_tick_timeout scenario
    TickSize = 100,
    % 100KB message
    LargeMessageSize = 100000,
    % 60 seconds tick interval
    _TickInterval = 60000,
    % 240 seconds before net_tick_timeout
    _TickTimeout = 240000,

    %% Start with 64KB cwnd
    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 2400,
        min_recovery_duration => 100
    }),

    %% Send large message - this triggers losses in burst
    %% Simulate sending 100KB in 1200-byte packets (84 packets)
    PacketSize = 1200,
    NumPackets = LargeMessageSize div PacketSize,

    %% Simulate bursting all packets
    {CC1, _BytesSent} = lists:foldl(
        fun(_, {CC, Sent}) ->
            case quic_cc:can_send(CC, PacketSize) of
                true ->
                    {quic_cc:on_packet_sent(CC, PacketSize), Sent + PacketSize};
                false ->
                    {CC, Sent}
            end
        end,
        {CCState, 0},
        lists:seq(1, NumPackets)
    ),

    %% Simulate 50% packet loss - each loss triggers congestion event
    LossCount = NumPackets div 2,
    CC2 = lists:foldl(
        fun(I, CC) ->
            Now = erlang:monotonic_time(millisecond) + I * 10,
            CC_after_loss = quic_cc:on_congestion_event(CC, Now),
            quic_cc:on_packets_lost(CC_after_loss, PacketSize)
        end,
        CC1,
        lists:seq(1, LossCount)
    ),

    %% Check cwnd after losses
    FinalCwnd = quic_cc:cwnd(CC2),

    %% BUG CHECK: Is cwnd collapsed so low that even a tick can't be sent?
    %% With 100ms min_recovery_duration, cwnd shouldn't collapse too fast
    CanSendTick = quic_cc:can_send(CC2, TickSize),

    %% Assert: Even after massive losses, we should be able to send a tick
    %% If this fails, it's the bug causing net_tick_timeout
    ?assert(CanSendTick),
    ?assert(FinalCwnd >= TickSize).

%%====================================================================
%% Rapid Congestion Event Test - Simulating Docker Network
%%====================================================================

rapid_congestion_on_docker_network_test() ->
    %% Docker networks have low latency (~1-5ms) which means:
    %% - min_recovery_duration can expire quickly
    %% - Multiple recovery cycles can happen in quick succession
    %% - Each cycle halves cwnd

    InitialCwnd = 65536,
    CCState = quic_cc:new(#{
        initial_window => InitialCwnd,
        minimum_window => 2400,
        % Docker-like low latency
        min_recovery_duration => 5
    }),

    %% Simulate 10 congestion events over 100ms (10ms apart)
    %% On Docker, this is realistic due to low RTT
    FinalCC = lists:foldl(
        fun(_I, CC) ->
            % Wait for min_recovery_duration
            timer:sleep(10),
            Now = erlang:monotonic_time(millisecond),
            quic_cc:on_congestion_event(CC, Now)
        end,
        CCState,
        lists:seq(1, 10)
    ),

    FinalCwnd = quic_cc:cwnd(FinalCC),

    %% BUG CHECK: After 10 rapid losses, cwnd should still be usable
    %% 65536 / 2^10 = 64 bytes - way below minimum!
    %% minimum_window should protect us
    ?assert(FinalCwnd >= 2400).

%%====================================================================
%% Large Message Fragmentation Test
%%====================================================================

large_message_fragments_test() ->
    %% Test that large messages can be sent with proper pacing
    %% and don't cause complete cwnd collapse

    % 1MB
    MessageSize = 1024 * 1024,
    PacketSize = 1200,
    NumPackets = MessageSize div PacketSize,

    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 8000
    }),
    LossState = quic_loss:new(),

    %% Simulate sending 1MB with realistic loss pattern (1% loss)
    {FinalCC, _FinalLoss, _Acked, _Lost} = lists:foldl(
        fun(PN, {CC, Loss, A, L}) ->
            case quic_cc:can_send(CC, PacketSize) of
                true ->
                    CC1 = quic_cc:on_packet_sent(CC, PacketSize),
                    Loss1 = quic_loss:on_packet_sent(Loss, PN, PacketSize, true),

                    %% 1% random loss
                    case rand:uniform(100) of
                        1 ->
                            %% Loss
                            Now = erlang:monotonic_time(millisecond),
                            CC2 = quic_cc:on_congestion_event(CC1, Now),
                            CC3 = quic_cc:on_packets_lost(CC2, PacketSize),
                            {CC3, Loss1, A, L + 1};
                        _ ->
                            %% Success
                            CC2 = quic_cc:on_packets_acked(CC1, PacketSize),
                            {CC2, Loss1, A + 1, L}
                    end;
                false ->
                    %% Blocked - just skip (simplified)
                    {CC, Loss, A, L}
            end
        end,
        {CCState, LossState, 0, 0},
        lists:seq(0, NumPackets - 1)
    ),

    FinalCwnd = quic_cc:cwnd(FinalCC),

    %% With 1% loss rate, cwnd should still be healthy
    ?assert(FinalCwnd >= 8000).

%%====================================================================
%% Tick Priority Under Load Test
%%====================================================================

tick_priority_under_load_test() ->
    %% Test that small tick messages can be sent even when
    %% congestion window is mostly consumed by large data

    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800
    }),

    %% Send data until we're near the limit

    % 60KB in flight
    CC1 = quic_cc:on_packet_sent(CCState, 60000),

    %% Check available window
    Available = quic_cc:available_cwnd(CC1),

    %% Should still have room for tick (100 bytes)
    ?assert(Available >= 100),

    %% Verify can_send works correctly
    ?assert(quic_cc:can_send(CC1, 100)),
    ?assertNot(quic_cc:can_send(CC1, 10000)).

%%====================================================================
%% Flow Control Starvation Test
%%====================================================================

flow_control_starvation_test() ->
    %% Test that flow control doesn't starve tick messages

    FlowState = quic_flow:new(#{
        initial_max_data => 65536,
        peer_initial_max_data => 65536
    }),

    %% Send data until flow blocked
    {Result, Flow1} = quic_flow:on_data_sent(FlowState, 65536),
    ?assertEqual(blocked, Result),

    %% Should be blocked for large data
    ?assertNot(quic_flow:can_send(Flow1, 1000)),

    %% But what about after MAX_DATA update?
    %% In distribution, we need to ensure MAX_DATA is sent in time
    Flow2 = quic_flow:on_max_data_received(Flow1, 65536 * 2),

    %% Now should be able to send
    ?assert(quic_flow:can_send(Flow2, 100)).

%%====================================================================
%% High Throughput Flow Control Test
%%====================================================================

high_throughput_flow_control_test() ->
    %% Test: Rapid sending that would exceed flow control limits
    %% This reproduces the scenario fixed in commit 16478f4:
    %% - Send bursts faster than flow control allows
    %% - Verify no deadlock (old bug: offsets advanced past limits)
    %% - Verify MAX_DATA properly unblocks

    %% Small limits to trigger flow control quickly
    FlowState = quic_flow:new(#{
        % 16KB limit
        initial_max_data => 16384,
        peer_initial_max_data => 16384
    }),

    %% Each burst is 4KB - should hit limit after 4 sends
    BurstSize = 4096,

    %% Send bursts until blocked - simulates high throughput
    {Results, FinalFlow} = lists:foldl(
        fun(N, {Acc, Flow}) ->
            case quic_flow:can_send(Flow, BurstSize) of
                true ->
                    {Result, NewFlow} = quic_flow:on_data_sent(Flow, BurstSize),
                    {[{N, {sent, Result}} | Acc], NewFlow};
                false ->
                    {[{N, flow_blocked} | Acc], Flow}
            end
        end,
        {[], FlowState},
        lists:seq(1, 10)
    ),

    %% Should have sent 4 bursts (16KB), then blocked by flow control
    %% on_data_sent returns 'blocked' when hitting exactly the limit
    SentCount = length([1 || {_, {sent, _}} <- Results]),
    FlowBlockedCount = length([1 || {_, flow_blocked} <- Results]),
    ?assertEqual(4, SentCount),
    ?assertEqual(6, FlowBlockedCount),

    %% Verify final state is blocked
    ?assertNot(quic_flow:can_send(FinalFlow, BurstSize)),
    ?assert(quic_flow:send_blocked(FinalFlow)),

    %% KEY FIX VERIFICATION: MAX_DATA update properly unblocks
    %% Old bug: queue had entries with offsets > limits, never drained

    % 32KB
    UpdatedFlow = quic_flow:on_max_data_received(FinalFlow, 32768),

    %% Should be able to send again
    ?assert(quic_flow:can_send(UpdatedFlow, BurstSize)),
    ?assertNot(quic_flow:send_blocked(UpdatedFlow)),

    %% Actually send to verify no deadlock
    {ok, Flow2} = quic_flow:on_data_sent(UpdatedFlow, BurstSize),
    % 16KB + 4KB = 20KB
    ?assertEqual(20480, quic_flow:bytes_sent(Flow2)).

repeated_block_unblock_cycles_test() ->
    %% Test multiple block/unblock cycles under sustained load
    %% Verifies no state corruption accumulates over time

    FlowState = quic_flow:new(#{
        initial_max_data => 8192,
        peer_initial_max_data => 8192
    }),

    BurstSize = 2048,

    %% Run 5 cycles of: fill to limit, receive MAX_DATA, continue
    FinalFlow = lists:foldl(
        fun(Cycle, Flow) ->
            %% Send until blocked
            {_, BlockedFlow} = send_until_blocked(Flow, BurstSize),
            ?assert(quic_flow:send_blocked(BlockedFlow)),

            %% Simulate peer sending MAX_DATA (increasing limit)
            NewLimit = 8192 * (Cycle + 1),
            UnblockedFlow = quic_flow:on_max_data_received(BlockedFlow, NewLimit),

            %% Should be unblocked now
            ?assertNot(quic_flow:send_blocked(UnblockedFlow)),
            ?assert(quic_flow:can_send(UnblockedFlow, BurstSize)),

            UnblockedFlow
        end,
        FlowState,
        lists:seq(1, 5)
    ),

    %% After 5 cycles, should have sent significant data without deadlock
    BytesSent = quic_flow:bytes_sent(FinalFlow),
    ?assert(BytesSent >= 8192 * 5).

%% Helper: send until blocked
send_until_blocked(Flow, Size) ->
    send_until_blocked(Flow, Size, 0).

send_until_blocked(Flow, Size, Sent) ->
    case quic_flow:can_send(Flow, Size) of
        true ->
            {_, NewFlow} = quic_flow:on_data_sent(Flow, Size),
            send_until_blocked(NewFlow, Size, Sent + Size);
        false ->
            {Sent, Flow}
    end.

%%====================================================================
%% Combined CC + Flow + Loss Simulation
%%====================================================================

full_distribution_simulation_test() ->
    %% Full simulation of distribution-like workload:
    %% - Tick messages every cycle (small, must get through)
    %% - Occasional large messages (can wait)
    %% - Random packet loss

    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800,
        min_recovery_duration => 50
    }),
    FlowState = quic_flow:new(#{
        initial_max_data => 1024 * 1024,
        peer_initial_max_data => 1024 * 1024
    }),
    LossState = quic_loss:new(),

    %% Simulate 1000 cycles
    TickSize = 100,
    LargeMessageSize = 10000,
    % Every 50 cycles
    LargeMessageInterval = 50,

    {FinalCC, _FinalFlow, _FinalLoss, TicksSent, TicksBlocked, _LargeSent} =
        lists:foldl(
            fun(Cycle, {CC, Flow, Loss, TSent, TBlocked, LSent}) ->
                PN = Cycle * 10,

                %% Always try to send tick
                {CC1, TSent1, TBlocked1} =
                    case
                        quic_cc:can_send(CC, TickSize) andalso
                            quic_flow:can_send(Flow, TickSize)
                    of
                        true ->
                            CC_new = quic_cc:on_packet_sent(CC, TickSize),
                            CC_acked = quic_cc:on_packets_acked(CC_new, TickSize),
                            {CC_acked, TSent + 1, TBlocked};
                        false ->
                            %% Tick blocked! This is the bug condition
                            {CC, TSent, TBlocked + 1}
                    end,

                %% Occasionally send large message
                {CC2, Flow1, LSent1} =
                    case Cycle rem LargeMessageInterval of
                        0 ->
                            %% Send large message with potential loss
                            send_large_message(CC1, Flow, Loss, LargeMessageSize, PN, LSent);
                        _ ->
                            {CC1, Flow, LSent}
                    end,

                {CC2, Flow1, Loss, TSent1, TBlocked1, LSent1}
            end,
            {CCState, FlowState, LossState, 0, 0, 0},
            lists:seq(1, 1000)
        ),

    %% BUG CHECK: Ticks should NEVER be blocked
    %% If any ticks were blocked, it would cause net_tick_timeout
    ?assertEqual(0, TicksBlocked),
    ?assertEqual(1000, TicksSent),

    FinalCwnd = quic_cc:cwnd(FinalCC),
    ?assert(FinalCwnd >= 4800).

%%====================================================================
%% ACK Processing Under Load Test
%%====================================================================

ack_processing_large_ranges_test() ->
    %% Test ACK processing with many packets in flight
    %% This simulates the scenario where large data creates many packets
    %% and ACKs need to be processed quickly

    State = quic_loss:new(),
    NumPackets = 1000,

    %% Send many packets
    S1 = lists:foldl(
        fun(PN, L) ->
            quic_loss:on_packet_sent(L, PN, 1200, true)
        end,
        State,
        lists:seq(0, NumPackets - 1)
    ),

    ?assertEqual(NumPackets * 1200, quic_loss:bytes_in_flight(S1)),

    %% Process ACK for all packets (single large ACK)
    AckFrame = {ack, NumPackets - 1, 0, NumPackets - 1, []},
    Now = erlang:monotonic_time(millisecond),

    %% This should be fast even with many packets
    {S2, Acked, Lost, _Meta} = quic_loss:on_ack_received(S1, AckFrame, Now),

    ?assertEqual(NumPackets, length(Acked)),
    ?assertEqual(0, length(Lost)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S2)).

%%====================================================================
%% Min Recovery Duration Effectiveness Test
%%====================================================================

min_recovery_duration_prevents_collapse_test() ->
    %% Test that min_recovery_duration actually prevents rapid collapse

    InitialCwnd = 65536,

    %% With short recovery duration (Docker-like)
    ShortCC = quic_cc:new(#{
        initial_window => InitialCwnd,
        minimum_window => 2400,
        min_recovery_duration => 5
    }),

    %% With longer recovery duration (safer)
    LongCC = quic_cc:new(#{
        initial_window => InitialCwnd,
        minimum_window => 2400,
        min_recovery_duration => 100
    }),

    %% Simulate rapid losses over 50ms
    %% Short recovery: each 5ms loss can trigger new recovery
    %% Long recovery: only first loss triggers recovery
    Now = erlang:monotonic_time(millisecond),

    ShortFinal = simulate_rapid_losses(ShortCC, Now, 10, 5),
    LongFinal = simulate_rapid_losses(LongCC, Now, 10, 5),

    ShortCwnd = quic_cc:cwnd(ShortFinal),
    LongCwnd = quic_cc:cwnd(LongFinal),

    %% Long recovery should preserve more cwnd
    ?assert(LongCwnd >= ShortCwnd).

%%====================================================================
%% Pacing Prevents Burst Loss Test
%%====================================================================

pacing_prevents_burst_loss_test() ->
    %% Test that pacing spreads out packets and prevents burst loss

    CCState = quic_cc:new(#{initial_window => 65536}),

    %% Set up pacing with 50ms RTT
    CC1 = quic_cc:update_pacing_rate(CCState, 50),

    %% Try to send burst of 64KB
    {AllowedBurst, CC2} = quic_cc:get_pacing_tokens(CC1, 65536),

    %% Pacing should limit the burst
    %% Initial burst is ~14400 bytes (12 packets)
    ?assert(AllowedBurst =< 14400),

    %% Check that we need to wait for more tokens
    Delay = quic_cc:pacing_delay(CC2, 1200),
    ?assert(Delay >= 0).

%%====================================================================
%% Control Message Allowance - Tick Blocking Fix
%%====================================================================

tick_blocked_when_cwnd_full_test() ->
    %% This test verifies the fix for the net_tick_timeout bug.
    %% When bytes_in_flight equals cwnd, regular can_send blocks all sends,
    %% but can_send_control allows small control messages through using
    %% the control_allowance (default 1200 bytes).

    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 2400
    }),

    %% Fill the congestion window completely
    %% (simulating large data in flight)
    FullCwnd = quic_cc:cwnd(CCState),
    CC1 = quic_cc:on_packet_sent(CCState, FullCwnd),

    %% Now bytes_in_flight = cwnd
    ?assertEqual(FullCwnd, quic_cc:bytes_in_flight(CC1)),
    ?assertEqual(FullCwnd, quic_cc:cwnd(CC1)),

    %% 4-byte tick + packet overhead
    TickSize = 4 + 20,

    %% Regular can_send blocks the tick (expected - cwnd is full)
    CanSendRegular = quic_cc:can_send(CC1, TickSize),
    ?assertNot(CanSendRegular),

    %% FIX: can_send_control allows control messages through
    %% because they can exceed cwnd by up to control_allowance (1200 bytes)
    CanSendControl = quic_cc:can_send_control(CC1, TickSize),
    ?assert(CanSendControl).

tick_blocked_after_loss_burst_test() ->
    %% Simulate realistic scenario:
    %% 1. Send large data
    %% 2. Experience loss burst
    %% 3. cwnd collapses
    %% 4. bytes_in_flight still high due to unacked packets
    %% 5. Tick message can't get through

    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 2400,
        % Quick recovery for test
        min_recovery_duration => 0
    }),
    LossState = quic_loss:new(),

    %% Send many packets (simulate large message)
    NumPackets = 50,
    PacketSize = 1200,
    {CC1, _Loss1} = lists:foldl(
        fun(PN, {CC, L}) ->
            CC_new = quic_cc:on_packet_sent(CC, PacketSize),
            L_new = quic_loss:on_packet_sent(L, PN, PacketSize, true),
            {CC_new, L_new}
        end,
        {CCState, LossState},
        lists:seq(0, NumPackets - 1)
    ),

    InitialBytesInFlight = quic_cc:bytes_in_flight(CC1),
    ?assertEqual(NumPackets * PacketSize, InitialBytesInFlight),

    %% Experience loss - trigger congestion event multiple times
    CC2 = lists:foldl(
        fun(I, CC) ->
            Now = erlang:monotonic_time(millisecond) + I * 10,
            quic_cc:on_congestion_event(CC, Now)
        end,
        CC1,
        lists:seq(1, 5)
    ),

    %% cwnd has collapsed but bytes_in_flight is still high
    %% (packets are in flight until ACKed or deemed lost)
    FinalCwnd = quic_cc:cwnd(CC2),
    FinalBytesInFlight = quic_cc:bytes_in_flight(CC2),

    %% BUG CHECK: bytes_in_flight > cwnd means nothing can be sent
    case FinalBytesInFlight >= FinalCwnd of
        true ->
            %% This is the problematic state - regular can_send fails
            CanSendTick = quic_cc:can_send(CC2, 100),
            ?assertNot(CanSendTick);
        false ->
            %% Still have room
            ok
    end.

%%====================================================================
%% Helper Functions
%%====================================================================

send_large_message(CC, Flow, _Loss, Size, _PN, LSent) ->
    %% Simplified large message send
    %% In real code, this would fragment and send packets
    case quic_cc:can_send(CC, Size) andalso quic_flow:can_send(Flow, Size) of
        true ->
            CC1 = quic_cc:on_packet_sent(CC, Size),
            {_, Flow1} = quic_flow:on_data_sent(Flow, Size),

            %% 10% chance of loss
            CC2 =
                case rand:uniform(10) of
                    1 ->
                        Now = erlang:monotonic_time(millisecond),
                        quic_cc:on_congestion_event(
                            quic_cc:on_packets_lost(CC1, Size), Now
                        );
                    _ ->
                        quic_cc:on_packets_acked(CC1, Size)
                end,
            {CC2, Flow1, LSent + 1};
        false ->
            {CC, Flow, LSent}
    end.

simulate_rapid_losses(CC, StartTime, Count, IntervalMs) ->
    lists:foldl(
        fun(I, Acc) ->
            timer:sleep(IntervalMs),
            Now = StartTime + (I * IntervalMs),
            quic_cc:on_congestion_event(Acc, Now)
        end,
        CC,
        lists:seq(1, Count)
    ).
