%%% -*- erlang -*-
%%%
%%% Tests for loss-tracker handling across an active path migration
%%% (RFC 9000 §9.4).
%%%
%%% A migration invalidates the path's RTT and congestion estimates, but
%%% not the packets already in flight. Replacing the whole tracker with a
%%% fresh one orphans them: no ACK matches, loss detection never runs,
%%% and bytes_in_flight reads 0 so no PTO fires either. Their data is
%%% never retransmitted and the peer stalls on a permanent stream hole.
%%%
%%% reset_for_new_path/1 draws that line: path-derived estimates reset,
%%% the sent queue and its byte accounting survive.
%%%
%%% Covers PR #251.

-module(quic_loss_path_migration_tests).

-include_lib("eunit/include/eunit.hrl").

%% Must match quic_loss.
-define(DEFAULT_INITIAL_RTT, 100).

%%====================================================================
%% Helpers
%%====================================================================

%% A tracker mid-flight: three ack-eliciting packets outstanding and an
%% established RTT sample, i.e. what a connection looks like when a
%% migration completes under load.
in_flight_state() ->
    S0 = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(S0, 1, 1200, true, [], 1000),
    S2 = quic_loss:on_packet_sent(S1, 2, 1200, true, [], 1010),
    S3 = quic_loss:on_packet_sent(S2, 3, 1000, true, [], 1020),
    quic_loss:update_rtt(S3, 40, 0).

%%====================================================================
%% What must survive
%%====================================================================

keeps_bytes_in_flight_test() ->
    State = in_flight_state(),
    Before = quic_loss:bytes_in_flight(State),
    ?assertEqual(3400, Before),
    After = quic_loss:reset_for_new_path(State),
    %% The bytes are still on the wire; forgetting them makes the
    %% congestion controller think the path is idle.
    ?assertEqual(Before, quic_loss:bytes_in_flight(After)).

keeps_sent_packets_test() ->
    State = in_flight_state(),
    Before = quic_loss:sent_packets(State),
    After = quic_loss:reset_for_new_path(State),
    ?assertEqual(Before, quic_loss:sent_packets(After)),
    %% And they remain retransmittable rather than being dropped on the
    %% floor by the migration.
    ?assertNotEqual(undefined, quic_loss:oldest_unacked(After)).

keeps_oldest_unacked_test() ->
    State = in_flight_state(),
    ?assertEqual(
        quic_loss:oldest_unacked(State),
        quic_loss:oldest_unacked(quic_loss:reset_for_new_path(State))
    ).

%%====================================================================
%% What must reset
%%====================================================================

resets_rtt_estimates_test() ->
    State = in_flight_state(),
    ?assertEqual(40, quic_loss:latest_rtt(State)),
    ?assertEqual(40, quic_loss:smoothed_rtt(State)),
    After = quic_loss:reset_for_new_path(State),
    %% The new path has its own RTT; carrying the old one over paces the
    %% first flight against a path that no longer exists.
    ?assertEqual(0, quic_loss:latest_rtt(After)),
    ?assertEqual(?DEFAULT_INITIAL_RTT, quic_loss:smoothed_rtt(After)),
    ?assertEqual(?DEFAULT_INITIAL_RTT div 2, quic_loss:rtt_var(After)),
    ?assertEqual(infinity, quic_loss:min_rtt(After)).

resets_rtt_sample_flag_test() ->
    State = in_flight_state(),
    ?assert(quic_loss:has_rtt_sample(State)),
    %% The next sample on the new path must be taken as a first sample,
    %% not blended into the old path's EWMA.
    ?assertNot(quic_loss:has_rtt_sample(quic_loss:reset_for_new_path(State))).

resets_pto_count_test() ->
    State = quic_loss:on_pto_expired(in_flight_state()),
    ?assert(quic_loss:pto_count(State) > 0),
    ?assertEqual(0, quic_loss:pto_count(quic_loss:reset_for_new_path(State))).

first_sample_on_new_path_is_not_blended_test() ->
    After = quic_loss:reset_for_new_path(in_flight_state()),
    Sampled = quic_loss:update_rtt(After, 250, 0),
    %% A first sample sets the EWMA outright. Had the flag survived, the
    %% 250 would have been averaged against the stale 40.
    ?assertEqual(250, quic_loss:smoothed_rtt(Sampled)),
    ?assertEqual(250, quic_loss:latest_rtt(Sampled)).

%%====================================================================
%% Degenerate input
%%====================================================================

undefined_state_yields_fresh_tracker_test() ->
    State = quic_loss:reset_for_new_path(undefined),
    ?assertEqual(0, quic_loss:bytes_in_flight(State)),
    ?assertNot(quic_loss:has_rtt_sample(State)).
