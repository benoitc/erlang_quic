%%% -*- erlang -*-
%%%
%%% Tests for QUIC BBR Congestion Control
%%%

-module(quic_cc_bbr_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Basic State Tests
%%====================================================================

new_state_test() ->
    State = quic_cc_bbr:new(#{}),
    %% Should start in startup mode
    ?assertEqual(startup, quic_cc_bbr:mode(State)),
    %% Initial cwnd should be set
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assert(Cwnd > 0),
    %% No bandwidth estimate yet
    ?assertEqual(0, quic_cc_bbr:btl_bw(State)),
    %% No RTprop yet
    ?assertEqual(infinity, quic_cc_bbr:rt_prop(State)).

new_state_with_opts_test() ->
    State = quic_cc_bbr:new(#{initial_window => 65536, max_datagram_size => 1400}),
    ?assertEqual(65536, quic_cc_bbr:cwnd(State)).

%%====================================================================
%% Packet Sent Tests
%%====================================================================

on_packet_sent_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc_bbr:bytes_in_flight(S1)).

on_packet_sent_multiple_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1000),
    S2 = quic_cc_bbr:on_packet_sent(S1, 500),
    S3 = quic_cc_bbr:on_packet_sent(S2, 300),
    ?assertEqual(1800, quic_cc_bbr:bytes_in_flight(S3)).

%%====================================================================
%% Can Send Tests
%%====================================================================

can_send_within_cwnd_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assert(quic_cc_bbr:can_send(State, Cwnd)),
    ?assert(quic_cc_bbr:can_send(State, Cwnd - 100)).

can_send_exceeds_cwnd_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assertNot(quic_cc_bbr:can_send(State, Cwnd + 1)).

can_send_with_in_flight_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    S1 = quic_cc_bbr:on_packet_sent(State, Cwnd - 1000),
    ?assert(quic_cc_bbr:can_send(S1, 1000)),
    ?assertNot(quic_cc_bbr:can_send(S1, 1001)).

available_cwnd_test() ->
    State = quic_cc_bbr:new(#{}),
    Cwnd = quic_cc_bbr:cwnd(State),
    ?assertEqual(Cwnd, quic_cc_bbr:available_cwnd(State)),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    ?assertEqual(Cwnd - 5000, quic_cc_bbr:available_cwnd(S1)).

%%====================================================================
%% Control Message Allowance Tests
%%====================================================================

can_send_control_when_cwnd_full_test() ->
    State = quic_cc_bbr:new(#{initial_window => 65536}),
    S1 = quic_cc_bbr:on_packet_sent(State, 65536),
    ?assertNot(quic_cc_bbr:can_send(S1, 100)),
    ?assert(quic_cc_bbr:can_send_control(S1, 100)).

%%====================================================================
%% Mode Tests
%%====================================================================

in_slow_start_initially_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assert(quic_cc_bbr:in_slow_start(State)).

in_recovery_always_false_test() ->
    %% BBR doesn't use traditional recovery
    State = quic_cc_bbr:new(#{}),
    ?assertNot(quic_cc_bbr:in_recovery(State)).

startup_mode_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assertEqual(startup, quic_cc_bbr:mode(State)).

%%====================================================================
%% RTT Update Tests
%%====================================================================

rtt_update_sets_rt_prop_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_rtt_update(State, 100, 50),
    ?assertEqual(50, quic_cc_bbr:rt_prop(S1)).

rtt_update_keeps_min_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_rtt_update(State, 100, 50),
    ?assertEqual(50, quic_cc_bbr:rt_prop(S1)),
    S2 = quic_cc_bbr:on_rtt_update(S1, 200, 75),
    ?assertEqual(50, quic_cc_bbr:rt_prop(S2)),
    S3 = quic_cc_bbr:on_rtt_update(S2, 80, 25),
    ?assertEqual(25, quic_cc_bbr:rt_prop(S3)).

%%====================================================================
%% Lost Packets Tests
%%====================================================================

on_packets_lost_reduces_in_flight_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    ?assertEqual(5000, quic_cc_bbr:bytes_in_flight(S1)),
    S2 = quic_cc_bbr:on_packets_lost(S1, 2000),
    ?assertEqual(3000, quic_cc_bbr:bytes_in_flight(S2)).

on_packets_lost_floor_zero_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 1000),
    S2 = quic_cc_bbr:on_packets_lost(S1, 2000),
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(S2)).

%%====================================================================
%% Congestion Event Tests (BBR behavior)
%%====================================================================

congestion_event_no_cwnd_reduction_test() ->
    %% BBR doesn't reduce cwnd on individual loss events
    State = quic_cc_bbr:new(#{}),
    InitialCwnd = quic_cc_bbr:cwnd(State),
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc_bbr:on_congestion_event(State, Now),
    ?assertEqual(InitialCwnd, quic_cc_bbr:cwnd(S1)).

%%====================================================================
%% Persistent Congestion Tests
%%====================================================================

detect_persistent_congestion_empty_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assertNot(quic_cc_bbr:detect_persistent_congestion([], 100, State)).

detect_persistent_congestion_single_packet_test() ->
    State = quic_cc_bbr:new(#{}),
    LostPackets = [{1, 1000}],
    ?assertNot(quic_cc_bbr:detect_persistent_congestion(LostPackets, 100, State)).

detect_persistent_congestion_above_threshold_test() ->
    State = quic_cc_bbr:new(#{}),
    PTO = 100,
    LostPackets = [{1, 1000}, {5, 1500}],
    ?assert(quic_cc_bbr:detect_persistent_congestion(LostPackets, PTO, State)).

on_persistent_congestion_resets_state_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_persistent_congestion(State),
    %% Should reset to startup mode
    ?assertEqual(startup, quic_cc_bbr:mode(S1)),
    %% Cwnd should be reduced to minimum
    MinCwnd = 4 * 1200,
    ?assertEqual(MinCwnd, quic_cc_bbr:cwnd(S1)).

%%====================================================================
%% Pacing Tests
%%====================================================================

pacing_initial_state_test() ->
    State = quic_cc_bbr:new(#{}),
    %% Initially, pacing should allow sending
    ?assert(quic_cc_bbr:pacing_allows(State, 1200)),
    ?assertEqual(0, quic_cc_bbr:pacing_delay(State, 1200)).

pacing_allows_burst_test() ->
    State = quic_cc_bbr:new(#{}),
    ?assert(quic_cc_bbr:pacing_allows(State, 12000)).

pacing_get_tokens_test() ->
    State = quic_cc_bbr:new(#{}),
    {Allowed, _S1} = quic_cc_bbr:get_pacing_tokens(State, 5000),
    ?assertEqual(5000, Allowed).

%%====================================================================
%% ACK Processing Tests
%%====================================================================

on_packets_acked_updates_delivered_test() ->
    State = quic_cc_bbr:new(#{}),
    S1 = quic_cc_bbr:on_packet_sent(State, 5000),
    Now = erlang:monotonic_time(millisecond),
    RateSample = #{largest_sent_time => Now},
    S2 = quic_cc_bbr:on_packets_acked(S1, 5000, RateSample),
    %% bytes_in_flight should be reduced
    ?assertEqual(0, quic_cc_bbr:bytes_in_flight(S2)).

%%====================================================================
%% Integration via Facade Tests
%%====================================================================

facade_newreno_default_test() ->
    State = quic_cc:new(#{}),
    ?assertEqual(newreno, quic_cc:algorithm(State)).

facade_bbr_explicit_test() ->
    State = quic_cc:new(#{algorithm => bbr}),
    ?assertEqual(bbr, quic_cc:algorithm(State)).

facade_bbr_basic_operations_test() ->
    State = quic_cc:new(#{algorithm => bbr}),
    Cwnd = quic_cc:cwnd(State),
    ?assert(Cwnd > 0),
    S1 = quic_cc:on_packet_sent(State, 1200),
    ?assertEqual(1200, quic_cc:bytes_in_flight(S1)),
    ?assert(quic_cc:can_send(S1, 1000)).

facade_ssthresh_bbr_test() ->
    %% BBR doesn't use ssthresh, should return infinity
    State = quic_cc:new(#{algorithm => bbr}),
    ?assertEqual(infinity, quic_cc:ssthresh(State)).

facade_in_slow_start_bbr_test() ->
    State = quic_cc:new(#{algorithm => bbr}),
    ?assert(quic_cc:in_slow_start(State)).

facade_in_recovery_bbr_test() ->
    State = quic_cc:new(#{algorithm => bbr}),
    ?assertNot(quic_cc:in_recovery(State)).
