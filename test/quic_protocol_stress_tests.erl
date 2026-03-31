%%% -*- erlang -*-
%%%
%%% Protocol Stress Tests for QUIC
%%%
%%% These tests validate protocol behavior under stress conditions
%%% similar to Erlang distribution workloads.
%%%

-module(quic_protocol_stress_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Combined Flow Control + CC + Loss Tests
%%====================================================================

flow_cc_integration_test() ->
    %% Test flow control and congestion control working together
    FlowWindow = 65536,
    CwndInitial = 65536,

    FlowState = quic_flow:new(#{
        initial_max_data => FlowWindow,
        peer_initial_max_data => FlowWindow
    }),
    CCState = quic_cc:new(#{initial_window => CwndInitial}),
    LossState = quic_loss:new(),

    %% Send data respecting both limits
    PacketSize = 1200,
    {_FinalFlow, FinalCC, FinalLoss, Sent} = send_with_limits(
        FlowState, CCState, LossState, PacketSize, 0, 50
    ),

    %% Should have sent many packets
    ?assert(Sent > 0),

    %% Verify state consistency
    ?assert(quic_cc:bytes_in_flight(FinalCC) =< quic_cc:cwnd(FinalCC)),
    ?assert(quic_loss:bytes_in_flight(FinalLoss) >= 0).

flow_cc_blocking_test() ->
    %% Test behavior when either flow or cc blocks
    FlowWindow = 10000,
    CwndInitial = 65536,

    FlowState = quic_flow:new(#{
        initial_max_data => FlowWindow,
        peer_initial_max_data => FlowWindow
    }),
    CCState = quic_cc:new(#{initial_window => CwndInitial}),

    %% Flow control should block first (smaller window)
    {Flow1, _CC1, Sent1} = send_until_blocked(FlowState, CCState, 1200),

    ?assert(Sent1 > 0),
    %% Flow window should be exhausted
    ?assert(quic_flow:send_blocked(Flow1) orelse quic_flow:send_window(Flow1) < 1200).

%%====================================================================
%% High Packet Rate Tests
%%====================================================================

high_packet_rate_ack_processing_test() ->
    %% Process many ACKs rapidly
    LossState = quic_loss:new(),

    %% Send 1000 packets
    {Loss1, _Sent} = lists:foldl(
        fun(PN, {L, S}) ->
            L1 = quic_loss:on_packet_sent(L, PN, 100, true),
            {L1, S ++ [PN]}
        end,
        {LossState, []},
        lists:seq(0, 999)
    ),

    %% Process ACKs for all packets
    AckFrame = {ack, 999, 0, 999, []},
    Now = erlang:monotonic_time(millisecond),
    {_Loss2, Acked, Lost} = quic_loss:on_ack_received(Loss1, AckFrame, Now),

    ?assertEqual(1000, length(Acked)),
    ?assertEqual(0, length(Lost)).

high_packet_rate_with_loss_test() ->
    %% Process many packets with some losses
    LossState = quic_loss:new(),

    %% Send 100 packets
    Loss1 = lists:foldl(
        fun(PN, L) ->
            quic_loss:on_packet_sent(L, PN, 100, true)
        end,
        LossState,
        lists:seq(0, 99)
    ),

    %% ACK only packets 50-99 (causing loss detection for 0-46)
    AckFrame = {ack, 99, 0, 49, []},
    Now = erlang:monotonic_time(millisecond),
    {_Loss2, Acked, Lost} = quic_loss:on_ack_received(Loss1, AckFrame, Now),

    ?assertEqual(50, length(Acked)),
    %% Loss detection by packet threshold (99 - 3 = 96, so 0-46 lost)
    ?assert(length(Lost) > 0).

%%====================================================================
%% Simulated Distribution Message Patterns
%%====================================================================

tick_messages_test() ->
    %% Simulate distribution tick messages (small, frequent)
    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800
    }),

    %% 1000 tick messages of ~100 bytes each
    FinalState = lists:foldl(
        fun(_, S) ->
            S1 = quic_cc:on_packet_sent(S, 100),
            quic_cc:on_packets_acked(S1, 100)
        end,
        CCState,
        lists:seq(1, 1000)
    ),

    %% Should have grown in slow start
    ?assert(quic_cc:cwnd(FinalState) > 65536).

large_messages_with_ticks_test() ->
    %% Simulate large messages interleaved with ticks
    CCState = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 4800,
        min_recovery_duration => 0
    }),

    {FinalState, _} = lists:foldl(
        fun(N, {S, _}) ->
            %% Tick every iteration
            S1 = quic_cc:on_packet_sent(S, 100),
            S2 = quic_cc:on_packets_acked(S1, 100),

            %% Large message every 10 iterations
            case N rem 10 of
                0 ->
                    %% Large message (10KB)
                    S3 = quic_cc:on_packet_sent(S2, 10000),
                    %% 10% chance of loss
                    case rand:uniform() > 0.9 of
                        true ->
                            Now = erlang:monotonic_time(millisecond) + N,
                            S4 = quic_cc:on_congestion_event(S3, Now),
                            {quic_cc:on_packets_lost(S4, 10000), loss};
                        false ->
                            {quic_cc:on_packets_acked(S3, 10000), ack}
                    end;
                _ ->
                    {S2, tick}
            end
        end,
        {CCState, undefined},
        lists:seq(1, 500)
    ),

    %% cwnd should be above minimum
    ?assert(quic_cc:cwnd(FinalState) >= 4800).

%%====================================================================
%% RTT Variation Tests
%%====================================================================

rtt_variation_test() ->
    %% Test RTT calculation with high jitter
    LossState = quic_loss:new(),

    %% Multiple RTT samples with variation
    RTTs = [50, 80, 30, 100, 45, 60, 90, 40, 70, 55],

    FinalState = lists:foldl(
        fun({PN, RTT}, S) ->
            S1 = quic_loss:on_packet_sent(S, PN, 100, true),
            timer:sleep(1),
            Now = erlang:monotonic_time(millisecond),
            AckFrame = {ack, PN, RTT, 0, []},
            {S2, _, _} = quic_loss:on_ack_received(S1, AckFrame, Now),
            S2
        end,
        LossState,
        lists:zip(lists:seq(0, length(RTTs) - 1), RTTs)
    ),

    %% SRTT should be reasonable
    SRTT = quic_loss:smoothed_rtt(FinalState),
    ?assert(SRTT > 0),
    ?assert(SRTT < 1000).

rtt_spike_test() ->
    %% Test behavior under RTT spike
    LossState = quic_loss:new(),

    %% Normal RTT, then spike, then normal
    S1 = quic_loss:on_packet_sent(LossState, 0, 100, true),
    S2 = quic_loss:update_rtt(S1, 50, 0),

    S3 = quic_loss:on_packet_sent(S2, 1, 100, true),
    S4 = quic_loss:update_rtt(S3, 500, 0),

    S5 = quic_loss:on_packet_sent(S4, 2, 100, true),
    S6 = quic_loss:update_rtt(S5, 60, 0),

    %% SRTT should smooth out the spike
    SRTT = quic_loss:smoothed_rtt(S6),
    ?assert(SRTT < 500),
    ?assert(SRTT > 50).

%%====================================================================
%% Stream Multiplexing Stress Tests
%%====================================================================

many_streams_test() ->
    %% Test with many concurrent streams
    NumStreams = 100,

    Streams = lists:map(
        fun(N) ->
            StreamId = N * 4,
            quic_stream:new(StreamId, client, #{
                send_max_data => 65536,
                recv_max_data => 65536
            })
        end,
        lists:seq(0, NumStreams - 1)
    ),

    %% All streams should be independent
    ?assertEqual(NumStreams, length(Streams)),
    lists:foreach(
        fun(S) ->
            ?assertEqual(open, quic_stream:state(S))
        end,
        Streams
    ).

%%====================================================================
%% PTO Backoff Tests
%%====================================================================

pto_backoff_test() ->
    %% Test PTO exponential backoff
    LossState = quic_loss:new(),
    S1 = quic_loss:update_rtt(LossState, 100, 0),

    PTO0 = quic_loss:get_pto(S1),

    %% First PTO expired
    S2 = quic_loss:on_pto_expired(S1),
    PTO1 = quic_loss:get_pto(S2),
    ?assertEqual(PTO0 * 2, PTO1),

    %% Second PTO expired
    S3 = quic_loss:on_pto_expired(S2),
    PTO2 = quic_loss:get_pto(S3),
    ?assertEqual(PTO0 * 4, PTO2),

    %% Send packet does NOT reset PTO count (per RFC 9002)
    S4 = quic_loss:on_packet_sent(S3, 0, 100, true),
    ?assertEqual(2, quic_loss:pto_count(S4)),

    %% ACK received resets PTO count
    Now = erlang:monotonic_time(millisecond) + 50,
    {S5, _, _} = quic_loss:on_ack_received(S4, {ack, 0, 0, 0, []}, Now),
    ?assertEqual(0, quic_loss:pto_count(S5)).

%%====================================================================
%% Memory Efficiency Tests
%%====================================================================

large_ack_range_memory_test() ->
    %% Test that large ACK ranges don't exhaust memory
    AckState = quic_ack:new(),

    %% Record many packets with gaps (creates many ranges)
    FinalState = lists:foldl(
        fun(N, S) ->
            %% Every 3rd packet to create gaps
            quic_ack:record_received(S, N)
        end,
        AckState,
        lists:seq(0, 30000, 3)
    ),

    %% Should be able to generate ACK
    {ok, _AckFrame} = quic_ack:generate_ack(FinalState).

%%====================================================================
%% Helper Functions
%%====================================================================

send_with_limits(FlowState, CCState, LossState, _PacketSize, PN, 0) ->
    {FlowState, CCState, LossState, PN};
send_with_limits(FlowState, CCState, LossState, PacketSize, PN, Remaining) ->
    %% Check both limits
    FlowAvail = quic_flow:send_window(FlowState),
    CanSendCC = quic_cc:can_send(CCState, quic_cc:bytes_in_flight(CCState) + PacketSize),

    case FlowAvail >= PacketSize andalso CanSendCC of
        true ->
            {_, Flow1} = quic_flow:on_data_sent(FlowState, PacketSize),
            CC1 = quic_cc:on_packet_sent(CCState, PacketSize),
            Loss1 = quic_loss:on_packet_sent(LossState, PN, PacketSize, true),
            send_with_limits(Flow1, CC1, Loss1, PacketSize, PN + 1, Remaining - 1);
        false ->
            {FlowState, CCState, LossState, PN}
    end.

send_until_blocked(FlowState, CCState, PacketSize) ->
    send_until_blocked(FlowState, CCState, PacketSize, 0).

send_until_blocked(FlowState, CCState, PacketSize, Sent) ->
    FlowAvail = quic_flow:send_window(FlowState),
    CanSendCC = quic_cc:can_send(CCState, quic_cc:bytes_in_flight(CCState) + PacketSize),

    case FlowAvail >= PacketSize andalso CanSendCC of
        true ->
            {_, Flow1} = quic_flow:on_data_sent(FlowState, PacketSize),
            CC1 = quic_cc:on_packet_sent(CCState, PacketSize),
            send_until_blocked(Flow1, CC1, PacketSize, Sent + 1);
        false ->
            {FlowState, CCState, Sent}
    end.
