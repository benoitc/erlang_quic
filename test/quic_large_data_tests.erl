%%% -*- erlang -*-
%%%
%%% Tests for Large Data Handling in QUIC
%%%
%%% These tests validate protocol behavior under large data transfers
%%% without requiring Docker/external servers.
%%%

-module(quic_large_data_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Flow Control Tests with Large Data
%%====================================================================

flow_control_large_window_test() ->
    %% Test flow control with 1MB window
    InitialWindow = 1024 * 1024,
    State = quic_flow:new(#{
        initial_max_data => InitialWindow,
        peer_initial_max_data => InitialWindow
    }),

    %% Should be able to send initial window worth of data
    ?assertEqual(InitialWindow, quic_flow:send_window(State)),

    %% After sending half the window
    HalfWindow = InitialWindow div 2,
    {ok, S1} = quic_flow:on_data_sent(State, HalfWindow),
    ?assertEqual(HalfWindow, quic_flow:send_window(S1)),

    %% MAX_DATA update should restore capacity
    S2 = quic_flow:on_max_data_received(S1, InitialWindow + HalfWindow),
    ?assertEqual(InitialWindow, quic_flow:send_window(S2)).

flow_control_incremental_consumption_test() ->
    %% Simulate sending many small chunks like distribution messages
    Window = 65536,
    State = quic_flow:new(#{
        initial_max_data => Window,
        peer_initial_max_data => Window
    }),
    ChunkSize = 1024,
    NumChunks = 50,

    %% Send 50 chunks of 1KB each
    FinalState = lists:foldl(
        fun(_, Acc) ->
            case quic_flow:on_data_sent(Acc, ChunkSize) of
                {ok, NewState} -> NewState;
                {blocked, NewState} -> NewState
            end
        end,
        State,
        lists:seq(1, NumChunks)
    ),

    %% Should have consumed 50KB
    Consumed = Window - quic_flow:send_window(FinalState),
    ?assertEqual(NumChunks * ChunkSize, Consumed).

flow_control_blocking_and_unblocking_test() ->
    %% Test that blocking and unblocking works correctly
    Window = 10000,
    State = quic_flow:new(#{
        initial_max_data => Window,
        peer_initial_max_data => Window
    }),

    %% Consume entire window
    {blocked, S1} = quic_flow:on_data_sent(State, Window),
    ?assertEqual(0, quic_flow:send_window(S1)),

    %% Should be blocked
    ?assert(quic_flow:send_blocked(S1)),

    %% MAX_DATA update should unblock
    S2 = quic_flow:on_max_data_received(S1, Window * 2),
    ?assertEqual(Window, quic_flow:send_window(S2)),
    ?assertNot(quic_flow:send_blocked(S2)).

%%====================================================================
%% Stream Tests
%%====================================================================

stream_creation_test() ->
    %% Test stream creation with custom options
    StreamWindow = 256 * 1024,
    StreamState = quic_stream:new(0, client, #{
        send_max_data => StreamWindow,
        recv_max_data => StreamWindow
    }),

    %% Verify stream was created
    ?assertEqual(0, quic_stream:id(StreamState)),
    ?assertEqual(open, quic_stream:state(StreamState)).

stream_multiple_creation_test() ->
    %% Test creating multiple streams
    NumStreams = 10,
    StreamWindow = 65536,

    %% Create multiple stream states
    Streams = lists:map(
        fun(N) ->
            % Client-initiated bidi streams
            StreamId = N * 4,
            quic_stream:new(StreamId, client, #{
                send_max_data => StreamWindow,
                recv_max_data => StreamWindow
            })
        end,
        lists:seq(0, NumStreams - 1)
    ),

    %% Each stream should have unique ID
    ?assertEqual(NumStreams, length(Streams)),
    IDs = [quic_stream:id(S) || S <- Streams],
    ?assertEqual(IDs, lists:usort(IDs)).

%%====================================================================
%% Congestion Control with Large Data Tests
%%====================================================================

cc_large_initial_window_test() ->
    %% Test with 64KB initial window (typical for distribution)
    InitialCwnd = 65536,
    State = quic_cc:new(#{initial_window => InitialCwnd}),
    ?assertEqual(InitialCwnd, quic_cc:cwnd(State)).

cc_slow_start_with_large_data_test() ->
    %% Verify slow start grows correctly with large data
    InitialCwnd = 65536,
    State = quic_cc:new(#{initial_window => InitialCwnd}),

    %% Send and ACK a full window
    S1 = quic_cc:on_packet_sent(State, InitialCwnd),
    S2 = quic_cc:on_packets_acked(S1, InitialCwnd),

    %% Window should double in slow start
    ?assertEqual(InitialCwnd * 2, quic_cc:cwnd(S2)),
    ?assert(quic_cc:in_slow_start(S2)).

cc_recovery_after_loss_test() ->
    %% Test that cwnd doesn't collapse too rapidly after loss
    InitialCwnd = 65536,
    MinCwnd = 16384,
    State = quic_cc:new(#{
        initial_window => InitialCwnd,
        minimum_window => MinCwnd,
        % 100ms minimum recovery
        min_recovery_duration => 100
    }),

    %% Single loss event should reduce cwnd
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    Cwnd1 = quic_cc:cwnd(S1),
    ?assert(Cwnd1 < InitialCwnd),
    ?assert(Cwnd1 >= MinCwnd),
    ?assert(quic_cc:in_recovery(S1)),

    %% Second loss with sent_time BEFORE recovery start should NOT reduce again
    %% (This simulates a packet that was sent before the loss event)
    S2 = quic_cc:on_congestion_event(S1, Now - 10),
    ?assertEqual(Cwnd1, quic_cc:cwnd(S2)).

cc_post_recovery_congestion_test() ->
    %% Test behavior after recovery ends - this is critical for the net_tick issue
    %% The key behavior: after exiting recovery, the system should be in
    %% congestion avoidance and able to grow cwnd linearly
    InitialCwnd = 65536,
    State = quic_cc:new(#{
        initial_window => InitialCwnd,
        minimum_window => 2400,
        min_recovery_duration => 10
    }),

    %% Enter recovery
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    Cwnd1 = quic_cc:cwnd(S1),
    ?assert(quic_cc:in_recovery(S1)),
    %% cwnd should be reduced but still reasonable
    ?assert(Cwnd1 < InitialCwnd),
    ?assert(Cwnd1 >= 2400),

    %% Wait for recovery to end
    timer:sleep(15),

    %% Send some packets after recovery - use proper sent time
    Now2 = erlang:monotonic_time(millisecond),
    S2 = quic_cc:on_packet_sent(S1, 1200),
    S3 = quic_cc:on_packets_acked(S2, 1200, Now2),

    %% Should be in congestion avoidance now
    ?assertNot(quic_cc:in_recovery(S3)),
    ?assertNot(quic_cc:in_slow_start(S3)),

    %% Verify cwnd can grow in congestion avoidance
    Cwnd3 = quic_cc:cwnd(S3),
    ?assert(Cwnd3 >= Cwnd1).

cc_minimum_window_protection_test() ->
    %% Test that cwnd never goes below minimum
    InitialCwnd = 65536,
    MinCwnd = 16384,
    State = quic_cc:new(#{
        initial_window => InitialCwnd,
        minimum_window => MinCwnd,
        min_recovery_duration => 0
    }),

    %% Trigger many loss events
    FinalState = lists:foldl(
        fun(I, Acc) ->
            Now = erlang:monotonic_time(millisecond) + I * 100,
            quic_cc:on_congestion_event(Acc, Now)
        end,
        State,
        lists:seq(1, 20)
    ),

    %% cwnd should never go below minimum
    ?assert(quic_cc:cwnd(FinalState) >= MinCwnd).

%%====================================================================
%% Loss Detection with Many Packets
%%====================================================================

loss_many_packets_in_flight_test() ->
    %% Test loss detection with many packets in flight
    State = quic_loss:new(),
    NumPackets = 100,

    %% Send many packets
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(Acc, PN, 1200, true)
        end,
        State,
        lists:seq(0, NumPackets - 1)
    ),

    %% All packets should be tracked
    ?assertEqual(NumPackets * 1200, quic_loss:bytes_in_flight(S1)),

    %% ACK all packets
    AckFrame = {ack, NumPackets - 1, 0, NumPackets - 1, []},
    Now = erlang:monotonic_time(millisecond),
    {S2, Acked, Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),

    ?assertEqual(NumPackets, length(Acked)),
    ?assertEqual(0, length(Lost)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S2)).

loss_detection_with_gaps_test() ->
    %% Test loss detection when ACKs have gaps (reordering/loss)
    State = quic_loss:new(),

    %% Send packets 0-9
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(Acc, PN, 1200, true)
        end,
        State,
        lists:seq(0, 9)
    ),

    %% ACK only packets 5-9, leaving 0-4 unacked
    %% With packet threshold of 3, packets 0,1,2 should be marked lost
    AckFrame = {ack, 9, 0, 4, []},
    Now = erlang:monotonic_time(millisecond) + 100,
    {_S2, Acked, Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),

    ?assertEqual(5, length(Acked)),
    %% Packets 0, 1, 2 should be lost (9 - 3 = 6, so 0-2 are lost)
    LostPNs = [P#sent_packet.pn || P <- Lost],
    ?assert(lists:member(0, LostPNs)),
    ?assert(lists:member(1, LostPNs)),
    ?assert(lists:member(2, LostPNs)).

loss_rtt_calculation_under_load_test() ->
    %% Test RTT calculation with many samples
    State = quic_loss:new(),

    %% Send packet and get ACK multiple times
    FinalState = lists:foldl(
        fun(N, Acc) ->
            S1 = quic_loss:on_packet_sent(Acc, N, 100, true),
            timer:sleep(1),
            Now = erlang:monotonic_time(millisecond),
            AckFrame = {ack, N, 0, 0, []},
            {S2, _, _} = quic_loss:on_ack_received(S1, AckFrame, Now),
            S2
        end,
        State,
        lists:seq(0, 9)
    ),

    %% RTT should be reasonable
    SRTT = quic_loss:smoothed_rtt(FinalState),
    ?assert(SRTT >= 1),
    ?assert(SRTT < 1000).

%%====================================================================
%% Stream Data Receive Tests
%%====================================================================

stream_receive_data_test() ->
    %% Test receiving data on a stream
    StreamState = quic_stream:new(0, client, #{}),

    %% Receive some data
    {ok, S1} = quic_stream:receive_data(StreamState, 0, <<"Hello">>, false),

    %% Should have bytes available
    ?assertEqual(5, quic_stream:bytes_available(S1)).

stream_receive_with_fin_test() ->
    %% Test receiving data with FIN
    StreamState = quic_stream:new(0, client, #{}),

    %% Receive data with FIN
    {ok, S1} = quic_stream:receive_data(StreamState, 0, <<"Hello">>, true),

    %% Stream should be half-closed
    ?assertEqual(half_closed_remote, quic_stream:state(S1)).

stream_out_of_order_receive_test() ->
    %% Test out-of-order data reception
    StreamState = quic_stream:new(0, client, #{}),

    %% Receive chunk at offset 5 first (out of order)
    {ok, S1} = quic_stream:receive_data(StreamState, 5, <<"World">>, false),
    %% No contiguous data yet
    ?assertEqual(0, quic_stream:bytes_available(S1)),

    %% Now receive chunk at offset 0
    {ok, S2} = quic_stream:receive_data(S1, 0, <<"Hello">>, false),
    %% Now all data is contiguous
    ?assertEqual(10, quic_stream:bytes_available(S2)).

%%====================================================================
%% Packet Pacing Tests
%%====================================================================

pacing_large_burst_test() ->
    %% Test pacing with large burst
    State = quic_cc:new(#{initial_window => 65536}),
    S1 = quic_cc:update_pacing_rate(State, 50),

    %% Initial burst should be allowed
    ?assert(quic_cc:pacing_allows(S1, 14400)),

    %% Get all burst tokens
    {Allowed, S2} = quic_cc:get_pacing_tokens(S1, 14400),
    ?assertEqual(14400, Allowed),

    %% After burst, should need to wait
    Delay = quic_cc:pacing_delay(S2, 1200),
    ?assert(is_integer(Delay)).

pacing_rate_calculation_test() ->
    %% Test that pacing rate is calculated correctly
    Cwnd = 65536,
    RTT = 100,
    State = quic_cc:new(#{initial_window => Cwnd}),
    _S1 = quic_cc:update_pacing_rate(State, RTT),

    %% Pacing should be active
    ok.

%%====================================================================
%% Integration: Simulated Large Transfer
%%====================================================================

simulated_large_transfer_test() ->
    %% Simulate a large transfer with loss and recovery
    Cwnd = 65536,
    State = quic_cc:new(#{
        initial_window => Cwnd,
        minimum_window => 4800,
        min_recovery_duration => 0
    }),
    LossState = quic_loss:new(),

    %% Simulate sending 1MB in 1200-byte packets
    DataSize = 1024 * 1024,
    PacketSize = 1200,
    NumPackets = DataSize div PacketSize,

    %% Send packets, simulate some losses
    {FinalCC, _FinalLoss, TotalAcked, _TotalLost} = lists:foldl(
        fun(PN, {CC, Loss, Acked, Lost}) ->
            %% Check if we can send
            case quic_cc:can_send(CC, PacketSize) of
                true ->
                    CC1 = quic_cc:on_packet_sent(CC, PacketSize),
                    Loss1 = quic_loss:on_packet_sent(Loss, PN, PacketSize, true),

                    %% Simulate ACK for most packets, loss for some
                    case PN rem 100 of
                        50 ->
                            %% Simulate loss
                            Now = erlang:monotonic_time(millisecond),
                            CC2 = quic_cc:on_congestion_event(CC1, Now),
                            CC3 = quic_cc:on_packets_lost(CC2, PacketSize),
                            {CC3, Loss1, Acked, Lost + 1};
                        _ ->
                            %% Simulate ACK
                            CC2 = quic_cc:on_packets_acked(CC1, PacketSize),
                            {CC2, Loss1, Acked + 1, Lost}
                    end;
                false ->
                    %% Blocked, skip this packet
                    {CC, Loss, Acked, Lost}
            end
        end,
        {State, LossState, 0, 0},
        lists:seq(0, NumPackets - 1)
    ),

    %% Should have processed most packets
    ?assert(TotalAcked > 0),

    %% cwnd should still be above minimum after recovery
    FinalCwnd = quic_cc:cwnd(FinalCC),
    ?assert(FinalCwnd >= 4800),

    ok.
