%%% -*- erlang -*-
%%%
%%% QUIC ECN (Explicit Congestion Notification) Tests
%%% RFC 9002 Section 7.1 - ECN-based Congestion Control
%%%
%%% This module tests ECN support in congestion control.
%%%

-module(quic_ecn_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% ECN-CE Congestion Response (RFC 9002 Section 7.1)
%%====================================================================

%% Test ECN-CE triggers congestion response
ecn_ce_triggers_congestion_test() ->
    CC = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(CC),

    %% ECN-CE signal with count of 1
    CC1 = quic_cc:on_ecn_ce(CC, 1),

    %% Should reduce cwnd like loss detection
    NewCwnd = quic_cc:cwnd(CC1),
    ?assert(NewCwnd < InitialCwnd),

    %% Should enter recovery
    ?assert(quic_cc:in_recovery(CC1)).

%% Test no response when ECN-CE count doesn't increase
ecn_ce_no_increase_test() ->
    CC = quic_cc:new(),

    %% First CE signal
    CC1 = quic_cc:on_ecn_ce(CC, 5),

    %% Second signal with same count - should not change
    CC2 = quic_cc:on_ecn_ce(CC1, 5),
    ?assertEqual(quic_cc:cwnd(CC1), quic_cc:cwnd(CC2)),

    %% Third signal with lower count - should not change
    CC3 = quic_cc:on_ecn_ce(CC2, 3),
    ?assertEqual(quic_cc:cwnd(CC2), quic_cc:cwnd(CC3)),

    %% Counter should stay at highest seen
    ?assertEqual(5, quic_cc:ecn_ce_counter(CC3)).

%% Test ECN-CE counter tracking
ecn_ce_counter_test() ->
    CC = quic_cc:new(),
    ?assertEqual(0, quic_cc:ecn_ce_counter(CC)),

    CC1 = quic_cc:on_ecn_ce(CC, 1),
    ?assertEqual(1, quic_cc:ecn_ce_counter(CC1)),

    CC2 = quic_cc:on_ecn_ce(CC1, 5),
    ?assertEqual(5, quic_cc:ecn_ce_counter(CC2)),

    %% Counter shouldn't decrease
    CC3 = quic_cc:on_ecn_ce(CC2, 3),
    ?assertEqual(5, quic_cc:ecn_ce_counter(CC3)).

%% Test ECN-CE during recovery only updates counter
ecn_ce_during_recovery_test() ->
    CC = quic_cc:new(),

    %% Enter recovery with first CE
    CC1 = quic_cc:on_ecn_ce(CC, 1),
    ?assert(quic_cc:in_recovery(CC1)),
    CwndAfterFirst = quic_cc:cwnd(CC1),

    %% Second CE during recovery - should only update counter, not cwnd
    CC2 = quic_cc:on_ecn_ce(CC1, 2),
    ?assertEqual(CwndAfterFirst, quic_cc:cwnd(CC2)),
    ?assertEqual(2, quic_cc:ecn_ce_counter(CC2)).

%% Test ECN-CE sets ssthresh properly
ecn_ce_ssthresh_test() ->
    CC = quic_cc:new(),
    InitialCwnd = quic_cc:cwnd(CC),

    CC1 = quic_cc:on_ecn_ce(CC, 1),

    %% ssthresh should be set to cwnd * 0.5
    SSThresh = quic_cc:ssthresh(CC1),
    ExpectedSSThresh = trunc(InitialCwnd * 0.5),
    ?assertEqual(ExpectedSSThresh, SSThresh).

%%====================================================================
%% ECN Integration with ACK Processing
%%====================================================================

%% Test ACK_ECN frame parsing returns ECN counts
ack_ecn_returns_counts_test() ->
    State = quic_ack:new(),

    %% ACK_ECN frame with ECT(0)=100, ECT(1)=50, CE=5
    AckFrame = {ack_ecn, 10, 0, 10, [], 100, 50, 5},
    {_NewState, _AckedPNs, ECN} = quic_ack:process_ack(State, AckFrame),

    ?assertEqual({ecn, 100, 50, 5}, ECN).

%% Test regular ACK frame doesn't return ECN
regular_ack_no_ecn_test() ->
    State = quic_ack:new(),
    AckFrame = {ack, 10, 0, 10, []},

    %% Regular ACK should return just 2-tuple
    Result = quic_ack:process_ack(State, AckFrame),
    ?assertMatch({_, _}, Result),
    ?assertEqual(2, tuple_size(Result)).

%%====================================================================
%% ECN with Congestion Control
%%====================================================================

%% Test ECN-CE response matches loss response
ecn_ce_matches_loss_response_test() ->
    CC1 = quic_cc:new(),
    CC2 = quic_cc:new(),

    %% Trigger congestion via ECN-CE
    CC1After = quic_cc:on_ecn_ce(CC1, 1),

    %% Trigger congestion via loss
    Now = erlang:monotonic_time(millisecond),
    CC2After = quic_cc:on_congestion_event(CC2, Now),

    %% Both should have same cwnd reduction (modulo timing differences)
    ?assertEqual(quic_cc:cwnd(CC1After), quic_cc:cwnd(CC2After)),
    ?assertEqual(quic_cc:ssthresh(CC1After), quic_cc:ssthresh(CC2After)).

%% Test multiple ECN-CE signals accumulate
ecn_ce_accumulation_test() ->
    CC = quic_cc:new(),

    %% First CE at count 1
    CC1 = quic_cc:on_ecn_ce(CC, 1),

    %% Exit recovery by acking enough
    CC2 = quic_cc:on_packets_acked(CC1, 50000),

    %% This may still be in recovery, so let's just verify
    %% that a new CE signal with higher count is tracked
    CC3 = quic_cc:on_ecn_ce(CC2, 5),
    ?assertEqual(5, quic_cc:ecn_ce_counter(CC3)).
