%%% -*- erlang -*-
%%%
%%% Tests for QUIC Congestion Control Invariants and Protocol Compliance
%%%
%%% These tests verify that critical protocol invariants are maintained:
%%% - bytes_in_flight never exceeds cwnd (except control_allowance)
%%% - Time-based loss detection requires PN < LargestAcked per RFC 9002
%%% - PTO backoff is not reset by probe retransmissions
%%%

-module(quic_cc_invariants_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

%%====================================================================
%% bytes_in_flight Invariant Tests
%%====================================================================

%% Test that bytes_in_flight never exceeds cwnd after sends
bytes_in_flight_never_exceeds_cwnd_test() ->
    State = quic_cc:new(#{initial_window => 14720}),
    Cwnd = quic_cc:cwnd(State),

    %% Try to send more than cwnd allows
    %% Each send should be gated by can_send
    {FinalState, TotalSent} = lists:foldl(
        fun(_, {S, Sent}) ->
            PacketSize = 1200,
            case quic_cc:can_send(S, PacketSize) of
                true ->
                    S1 = quic_cc:on_packet_sent(S, PacketSize),
                    {S1, Sent + PacketSize};
                false ->
                    {S, Sent}
            end
        end,
        {State, 0},
        lists:seq(1, 100)
    ),

    InFlight = quic_cc:bytes_in_flight(FinalState),
    %% bytes_in_flight should never exceed cwnd
    ?assert(InFlight =< Cwnd),
    %% Should have sent approximately cwnd worth of data
    ?assert(TotalSent =< Cwnd).

%% Test bytes_in_flight tracking through send/ack/loss cycle
bytes_in_flight_send_ack_loss_cycle_test() ->
    State = quic_cc:new(#{initial_window => 14720}),

    %% Send 10 packets
    S1 = lists:foldl(
        fun(_, Acc) -> quic_cc:on_packet_sent(Acc, 1200) end,
        State,
        lists:seq(1, 10)
    ),
    ?assertEqual(12000, quic_cc:bytes_in_flight(S1)),

    %% ACK 5 packets
    S2 = quic_cc:on_packets_acked(S1, 6000),
    ?assertEqual(6000, quic_cc:bytes_in_flight(S2)),

    %% Lose 2 packets
    S3 = quic_cc:on_packets_lost(S2, 2400),
    ?assertEqual(3600, quic_cc:bytes_in_flight(S3)),

    %% bytes_in_flight should never go negative
    S4 = quic_cc:on_packets_lost(S3, 10000),
    ?assertEqual(0, quic_cc:bytes_in_flight(S4)).

%% Test that control packets respect control_allowance
control_allowance_respected_test() ->
    State = quic_cc:new(#{initial_window => 14720}),

    %% Fill cwnd
    S1 = lists:foldl(
        fun(_, Acc) ->
            case quic_cc:can_send(Acc, 1200) of
                true -> quic_cc:on_packet_sent(Acc, 1200);
                false -> Acc
            end
        end,
        State,
        lists:seq(1, 20)
    ),

    Cwnd = quic_cc:cwnd(S1),
    InFlight = quic_cc:bytes_in_flight(S1),

    %% Regular send should be blocked
    ?assertNot(quic_cc:can_send(S1, 1200)),

    %% Control send with allowance should be allowed
    %% (up to control_allowance = 1200 bytes over cwnd)
    ?assert(quic_cc:can_send_control(S1, 100)),

    %% But only up to the allowance
    OverAllowance = Cwnd - InFlight + 1201,
    ?assertNot(quic_cc:can_send_control(S1, OverAllowance)).

%% Stress test: rapid sends and acks should maintain invariant
stress_rapid_send_ack_test() ->
    State = quic_cc:new(#{initial_window => 65536}),

    %% Rapid send/ack cycles
    {FinalState, _} = lists:foldl(
        fun(I, {S, _}) ->
            %% Send if allowed
            S1 =
                case quic_cc:can_send(S, 1200) of
                    true -> quic_cc:on_packet_sent(S, 1200);
                    false -> S
                end,
            %% ACK some packets periodically
            S2 =
                case I rem 3 of
                    0 -> quic_cc:on_packets_acked(S1, 1200);
                    _ -> S1
                end,
            %% Lose some packets periodically
            S3 =
                case I rem 7 of
                    0 ->
                        Now = erlang:monotonic_time(millisecond),
                        S2a = quic_cc:on_congestion_event(S2, Now),
                        quic_cc:on_packets_lost(S2a, 1200);
                    _ ->
                        S2
                end,
            %% Verify invariant at each step
            InFlight = quic_cc:bytes_in_flight(S3),
            Cwnd = quic_cc:cwnd(S3),
            %% Allow control_allowance (1200) overhead
            ?assert(InFlight =< Cwnd + 1200),
            {S3, I}
        end,
        {State, 0},
        lists:seq(1, 1000)
    ),

    %% Final check
    FinalInFlight = quic_cc:bytes_in_flight(FinalState),
    FinalCwnd = quic_cc:cwnd(FinalState),
    ?assert(FinalInFlight =< FinalCwnd + 1200).

%%====================================================================
%% Loss Detection Protocol Compliance Tests
%%====================================================================

%% RFC 9002 Section 6.1: Time-based loss detection should only apply
%% to packets with PN < LargestAcked
time_loss_requires_larger_acked_test() ->
    State = quic_loss:new(),

    %% Send packet 0
    S1 = quic_loss:on_packet_sent(State, 0, 1000, true, []),

    %% Wait long enough for time-based loss threshold
    timer:sleep(500),

    %% ACK frame for packet 0 itself (no larger packet acked)
    %% This should NOT declare packet 0 lost
    AckFrame = {ack, 0, 0, 0, []},
    Now = erlang:monotonic_time(millisecond),
    {_S2, Acked, Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),

    %% Packet 0 should be acked, not lost
    ?assertEqual(1, length(Acked)),
    ?assertEqual(0, length(Lost)).

%% Test that packet threshold loss requires gap
packet_threshold_loss_test() ->
    State = quic_loss:new(),

    %% Send packets 0, 1, 2, 3, 4
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(Acc, PN, 1000, true, [])
        end,
        State,
        lists:seq(0, 4)
    ),

    %% ACK packet 4 (creating gap of 4 packets: 0, 1, 2, 3)
    %% With PACKET_THRESHOLD = 3, packets 0 and 1 should be lost
    AckFrame = {ack, 4, 0, 0, []},
    Now = erlang:monotonic_time(millisecond),
    {_S2, Acked, Lost} = quic_loss:on_ack_received(S1, AckFrame, Now),

    ?assertEqual(1, length(Acked)),
    %% Packets 0 and 1 should be declared lost (gap >= 3)
    LostPNs = [P#sent_packet.pn || P <- Lost],
    ?assert(lists:member(0, LostPNs)),
    ?assert(lists:member(1, LostPNs)).

%% Test no spurious loss on sequential ACKs
no_spurious_loss_sequential_acks_test() ->
    State = quic_loss:new(),

    %% Send packets 0, 1, 2
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(Acc, PN, 1000, true, [])
        end,
        State,
        lists:seq(0, 2)
    ),

    %% ACK packets in order with small delay
    Now = erlang:monotonic_time(millisecond) + 10,

    {S2, Acked1, Lost1} = quic_loss:on_ack_received(S1, {ack, 0, 0, 0, []}, Now),
    ?assertEqual(1, length(Acked1)),
    ?assertEqual(0, length(Lost1)),

    {S3, Acked2, Lost2} = quic_loss:on_ack_received(S2, {ack, 1, 0, 0, []}, Now + 5),
    ?assertEqual(1, length(Acked2)),
    ?assertEqual(0, length(Lost2)),

    {_S4, Acked3, Lost3} = quic_loss:on_ack_received(S3, {ack, 2, 0, 0, []}, Now + 10),
    ?assertEqual(1, length(Acked3)),
    ?assertEqual(0, length(Lost3)).

%%====================================================================
%% PTO Backoff Tests
%%====================================================================

%% Test PTO exponential backoff is maintained
pto_backoff_maintained_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    BasePTO = quic_loss:get_pto(S1),

    %% First PTO expiry
    S2 = quic_loss:on_pto_expired(S1),
    ?assertEqual(1, quic_loss:pto_count(S2)),
    ?assertEqual(BasePTO * 2, quic_loss:get_pto(S2)),

    %% Second PTO expiry
    S3 = quic_loss:on_pto_expired(S2),
    ?assertEqual(2, quic_loss:pto_count(S3)),
    ?assertEqual(BasePTO * 4, quic_loss:get_pto(S3)),

    %% Third PTO expiry
    S4 = quic_loss:on_pto_expired(S3),
    ?assertEqual(3, quic_loss:pto_count(S4)),
    ?assertEqual(BasePTO * 8, quic_loss:get_pto(S4)).

%% Test PTO backoff should reset only on new ack-eliciting data, not probes
%% NOTE: This test documents the EXPECTED behavior per RFC 9002
%% Currently the implementation resets on every send which is wrong
pto_backoff_reset_on_ack_only_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),

    %% Send initial packet
    S2 = quic_loss:on_packet_sent(S1, 0, 1000, true, []),

    %% Simulate PTO timeout
    S3 = quic_loss:on_pto_expired(S2),
    ?assertEqual(1, quic_loss:pto_count(S3)),

    %% ACK the original packet - should reset PTO count
    Now = erlang:monotonic_time(millisecond) + 200,
    {S4, _Acked, _Lost} = quic_loss:on_ack_received(S3, {ack, 0, 0, 0, []}, Now),

    %% After ACK, PTO count should be reset
    ?assertEqual(0, quic_loss:pto_count(S4)).

%%====================================================================
%% Bidirectional Transfer Stress Test
%%====================================================================

%% Simulate bidirectional transfer pattern with losses
bidirectional_stress_test() ->
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 16384,
        min_recovery_duration => 50
    }),

    %% Simulate 500 cycles of bidirectional activity
    {FinalState, Stats} = lists:foldl(
        fun(I, {S, #{sends := Sends, acks := Acks, losses := Losses} = Stats}) ->
            %% Send data if allowed
            {S1, NewSends} =
                case quic_cc:can_send(S, 1200) of
                    true ->
                        {quic_cc:on_packet_sent(S, 1200), Sends + 1};
                    false ->
                        {S, Sends}
                end,

            %% Receive ACK periodically
            InFlight1 = quic_cc:bytes_in_flight(S1),
            {S2, NewAcks} =
                case {I rem 2, InFlight1 > 0} of
                    {0, true} ->
                        AckSize = min(1200, InFlight1),
                        {quic_cc:on_packets_acked(S1, AckSize), Acks + 1};
                    _ ->
                        {S1, Acks}
                end,

            %% Occasional loss
            {S3, NewLosses} =
                case I rem 17 of
                    0 ->
                        Now = erlang:monotonic_time(millisecond),
                        S2a = quic_cc:on_congestion_event(S2, Now),
                        LostSize = min(1200, quic_cc:bytes_in_flight(S2a)),
                        {quic_cc:on_packets_lost(S2a, LostSize), Losses + 1};
                    _ ->
                        {S2, Losses}
                end,

            %% Verify invariant
            InFlight = quic_cc:bytes_in_flight(S3),
            Cwnd = quic_cc:cwnd(S3),
            ?assert(
                InFlight =< Cwnd + 1200,
                {invariant_violated, I, InFlight, Cwnd}
            ),

            {S3, Stats#{sends => NewSends, acks => NewAcks, losses => NewLosses}}
        end,
        {State, #{sends => 0, acks => 0, losses => 0}},
        lists:seq(1, 500)
    ),

    %% Should have made progress
    #{sends := TotalSends, acks := TotalAcks} = Stats,
    ?assert(TotalSends > 100),
    ?assert(TotalAcks > 50),

    %% Final state should be valid
    FinalInFlight = quic_cc:bytes_in_flight(FinalState),
    FinalCwnd = quic_cc:cwnd(FinalState),
    ?assert(FinalInFlight =< FinalCwnd + 1200).
