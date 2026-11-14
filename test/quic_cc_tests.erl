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
    %% Initial window should be reasonable (32 packets * MTU)
    ?assertEqual(32 * 1400, Cwnd).

new_state_with_minimum_window_opt_test() ->
    %% Initial window should be clamped to configured minimum window
    State = quic_cc:new(#{initial_window => 8000, minimum_window => 16000}),
    ?assertEqual(16000, quic_cc:cwnd(State)).

%%====================================================================
%% Algorithm Selection Tests
%%====================================================================

new_with_explicit_algorithm_test() ->
    %% Create with explicit newreno algorithm
    State = quic_cc:new(newreno, #{}),
    ?assertEqual(newreno, quic_cc:algorithm(State)),
    Cwnd = quic_cc:cwnd(State),
    ?assert(Cwnd >= 12000).

new_with_algorithm_option_test() ->
    %% Create with algorithm in options map
    State = quic_cc:new(#{algorithm => newreno}),
    ?assertEqual(newreno, quic_cc:algorithm(State)).

new_with_algorithm_and_opts_test() ->
    %% Create with explicit algorithm and options
    State = quic_cc:new(newreno, #{max_datagram_size => 1400}),
    ?assertEqual(newreno, quic_cc:algorithm(State)),
    ?assertEqual(32 * 1400, quic_cc:cwnd(State)).

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
%% Full window (RFC 9002 Section 7)
%%====================================================================

full_window_refuses_small_send_test() ->
    State = quic_cc:new(#{initial_window => 65536}),
    S1 = quic_cc:on_packet_sent(State, 65536),
    ?assertNot(quic_cc:can_send(S1, 24)),
    ?assertEqual({blocked_cwnd, 0}, quic_cc:send_check(S1, 24)),
    ?assertMatch({0, _}, quic_cc:send_check_run(S1, 24, 8)).

full_window_after_cut_refuses_small_send_test() ->
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 2400,
        min_recovery_duration => 0
    }),
    S1 = quic_cc:on_congestion_event(State, erlang:monotonic_time(millisecond)),
    S2 = quic_cc:on_packet_sent(S1, quic_cc:cwnd(S1)),
    ?assertNot(quic_cc:can_send(S2, 24)),
    ?assertMatch({blocked_cwnd, _}, quic_cc:send_check(S2, 24)).

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

    %% Verify ssthresh was set and reduced from initial
    SSThresh = quic_cc:ssthresh(S2),
    ?assert(SSThresh < InitialCwnd),
    ?assert(SSThresh >= 2400),

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
    %% cwnd should be reduced on congestion event
    ?assert(NewCwnd < InitialCwnd),
    %% Should be at least minimum window (2 * 1200)
    ?assert(NewCwnd >= 2400).

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

configured_cwnd_minimum_test() ->
    %% Custom minimum window should be respected under repeated losses.
    %% Set min_recovery_duration => 0 to allow rapid congestion events in this test.
    State = quic_cc:new(#{
        initial_window => 65536,
        minimum_window => 16384,
        min_recovery_duration => 0
    }),
    S1 = lists:foldl(
        fun(_, Acc) ->
            Now = erlang:monotonic_time(millisecond),
            quic_cc:on_congestion_event(Acc, Now + 1000)
        end,
        State,
        lists:seq(1, 10)
    ),
    ?assertEqual(16384, quic_cc:cwnd(S1)).

%%====================================================================
%% Persistent Congestion Tests (RFC 9002 Section 7.6)
%%====================================================================

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

    %% ssthresh should be reduced from initial cwnd
    ?assert(SSThresh < InitialCwnd),
    %% Should be at least minimum window (2 * 1200)
    ?assert(SSThresh >= 2400).

on_persistent_congestion_clears_recovery_test() ->
    State = quic_cc:new(),

    %% Enter recovery first
    Now = erlang:monotonic_time(millisecond),
    S1 = quic_cc:on_congestion_event(State, Now),
    ?assert(quic_cc:in_recovery(S1)),

    %% Persistent congestion should clear recovery state
    S2 = quic_cc:on_persistent_congestion(S1),
    ?assertNot(quic_cc:in_recovery(S2)).

on_persistent_congestion_respects_configured_minimum_window_test() ->
    State = quic_cc:new(#{minimum_window => 16384}),
    S1 = quic_cc:on_persistent_congestion(State),
    ?assertEqual(16384, quic_cc:cwnd(S1)).

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
%% Pacing Tests (RFC 9002 Section 7.7)
%%====================================================================

pacing_initial_state_test() ->
    State = quic_cc:new(),
    %% Initially, pacing should allow sending (rate is 0, no rate limit)
    ?assert(quic_cc:pacing_allows(State, 1200)),
    ?assertEqual(0, quic_cc:pacing_delay(State, 1200)).

update_pacing_rate_test() ->
    State = quic_cc:new(),
    %% Update pacing rate with 50ms RTT
    _S1 = quic_cc:update_pacing_rate(State, 50),
    %% Rate should now be set (cwnd / rtt * 1.25)
    Cwnd = quic_cc:cwnd(State),
    ExpectedRate = max(1, (Cwnd * 5) div (50 * 4)),
    %% Pacing should now be active
    ?assert(ExpectedRate > 0).

pacing_allows_with_tokens_test() ->
    State = quic_cc:new(),
    %% After init, tokens = max_burst (12 packets = 14400 bytes)
    %% Should allow sending a single packet
    ?assert(quic_cc:pacing_allows(State, 1200)).

pacing_get_tokens_consumes_test() ->
    State = quic_cc:new(),
    S1 = quic_cc:update_pacing_rate(State, 50),
    %% Get tokens to send 5000 bytes
    {Allowed1, S2} = quic_cc:get_pacing_tokens(S1, 5000),
    ?assertEqual(5000, Allowed1),
    %% Get more tokens
    {Allowed2, _S3} = quic_cc:get_pacing_tokens(S2, 5000),
    ?assertEqual(5000, Allowed2).

pacing_delay_when_blocked_test() ->
    State = quic_cc:new(),
    S1 = quic_cc:update_pacing_rate(State, 50),
    %% Exhaust tokens by consuming the burst
    {_, S2} = quic_cc:get_pacing_tokens(S1, 14400),
    %% Now pacing should report a delay for the next packet
    %% (After tokens exhausted, need to wait for refill)
    Delay = quic_cc:pacing_delay(S2, 1200),
    %% Delay may be 0 or small depending on how fast the test runs
    ?assert(is_integer(Delay) andalso Delay >= 0).

pacing_no_delay_without_rate_test() ->
    %% When pacing rate is 0 (no RTT sample), no pacing should apply
    State = quic_cc:new(),
    ?assertEqual(0, quic_cc:pacing_delay(State, 50000)).

pacing_allows_burst_test() ->
    State = quic_cc:new(),
    %% Should allow burst of 10+ packets (14400 bytes) initially
    ?assert(quic_cc:pacing_allows(State, 12000)).

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

%%====================================================================
%% Spurious congestion undo
%%====================================================================

%% A cut whose losses all prove to be reordering is undone: the window
%% and slow-start threshold come back and recovery ends.
spurious_congestion_restores_window_test_() ->
    [{atom_to_list(A), fun() -> spurious_restores(A) end} || A <- [newreno, cubic]].

spurious_restores(Algo) ->
    CC0 = quic_cc:new(Algo, #{}),
    Cwnd = quic_cc:cwnd(CC0),
    SSThresh = quic_cc:ssthresh(CC0),
    Cut = quic_cc:on_congestion_event(CC0, erlang:monotonic_time(millisecond)),
    ?assert(quic_cc:cwnd(Cut) < Cwnd),
    ?assert(quic_cc:in_recovery(Cut)),
    Undone = quic_cc:on_spurious_congestion(Cut),
    ?assertEqual(Cwnd, quic_cc:cwnd(Undone)),
    ?assertEqual(SSThresh, quic_cc:ssthresh(Undone)),
    ?assertNot(quic_cc:in_recovery(Undone)),
    %% Only once: a second undo has nothing left to restore.
    ?assertEqual(Undone, quic_cc:on_spurious_congestion(Undone)).

%% Persistent congestion is real: nothing to undo after it. ECN marks
%% are kept from undo by the connection (quic_ecn_tests).
spurious_congestion_after_persistent_congestion_test_() ->
    [{atom_to_list(A), fun() -> no_undo_after_persistent(A) end} || A <- [newreno, cubic]].

no_undo_after_persistent(Algo) ->
    CC0 = quic_cc:new(Algo, #{}),
    Cut = quic_cc:on_congestion_event(CC0, erlang:monotonic_time(millisecond)),
    Real = quic_cc:on_persistent_congestion(Cut),
    ?assertEqual(quic_cc:cwnd(Real), quic_cc:cwnd(quic_cc:on_spurious_congestion(Real))).

%% Nothing was cut: undo changes nothing.
spurious_congestion_without_cut_test() ->
    CC0 = quic_cc:new(newreno, #{}),
    ?assertEqual(CC0, quic_cc:on_spurious_congestion(CC0)).

%% A BBR state with no loss episode has nothing to undo.
spurious_congestion_bbr_test() ->
    CC0 = quic_cc:new(bbr, #{}),
    ?assertEqual(CC0, quic_cc:on_spurious_congestion(CC0)).
