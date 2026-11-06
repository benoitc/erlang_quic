%%% -*- erlang -*-
%%%
%%% The pacing rules of quic_pacing_burst_tests, held for CUBIC and BBR.
%%%
%%% Both fixes landed in NewReno only: the burst allowance scales with
%%% the pacing rate (2 ms worth, floored at 12 packets), and a smoothed
%%% RTT of 0 on a sub-millisecond link paces as 1 ms instead of freezing
%%% the rate.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cc_pacing_burst_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MDS, 1200).
-define(HUGE, (1 bsl 30)).
-define(STEP_MS, 10).
-define(MAX_WAIT_MS, 2000).

%%====================================================================
%% CUBIC
%%====================================================================

cubic_burst_scales_with_pacing_rate_test() ->
    Cwnd = 4000000,
    Expected = max(12 * ?MDS, 2 * cubic_rate(Cwnd, 10)),
    ?assert(Expected > 12 * ?MDS),
    ?assertEqual(Expected, burst_ceiling(quic_cc_cubic, cubic_paced(Cwnd, 10))).

cubic_burst_keeps_the_floor_at_low_rates_test() ->
    ?assertEqual(12 * ?MDS, burst_ceiling(quic_cc_cubic, cubic_paced(12000, 500))).

cubic_update_mtu_scales_burst_with_rate_test() ->
    Cwnd = 4000000,
    Bumped = quic_cc_cubic:update_mtu(cubic_paced(Cwnd, 10), 1400),
    ?assertEqual(max(12 * 1400, 2 * cubic_rate(Cwnd, 10)), burst_ceiling(quic_cc_cubic, Bumped)).

cubic_zero_rtt_paces_as_one_millisecond_test() ->
    Cwnd = 4000000,
    ?assertEqual(
        max(12 * ?MDS, 2 * cubic_rate(Cwnd, 1)),
        burst_ceiling(quic_cc_cubic, cubic_paced(Cwnd, 0))
    ).

%%====================================================================
%% BBR
%%====================================================================

bbr_burst_scales_with_pacing_rate_test() ->
    ?assert(burst_ceiling(quic_cc_bbr, bbr_paced(4000000)) > 12 * ?MDS).

bbr_burst_keeps_the_floor_at_low_rates_test() ->
    ?assertEqual(12 * ?MDS, burst_ceiling(quic_cc_bbr, bbr_paced(12000))).

bbr_update_mtu_scales_burst_with_rate_test() ->
    Bumped = quic_cc_bbr:update_mtu(bbr_paced(4000000), 1400),
    ?assert(burst_ceiling(quic_cc_bbr, Bumped) > 12 * 1400).

%%====================================================================
%% Helpers
%%====================================================================

%% Milli-bytes per microsecond, as quic_cc_cubic stores it.
cubic_rate(Cwnd, RttMs) ->
    max(1, (Cwnd * 1250) div (RttMs * 1000)).

cubic_paced(Cwnd, RttMs) ->
    State = quic_cc_cubic:new(#{max_datagram_size => ?MDS, initial_window => Cwnd}),
    quic_cc_cubic:update_pacing_rate(State, RttMs).

%% BBR sets its rate from its own bandwidth estimate, which starts at
%% initial_window / initial_rtt.
bbr_paced(Cwnd) ->
    quic_cc_bbr:new(#{max_datagram_size => ?MDS, initial_window => Cwnd, initial_rtt => 100}).

burst_ceiling(Mod, State) ->
    converge(Mod, State, Mod:get_pacing_tokens(State, ?HUGE), 0).

converge(_Mod, _State, {V, _}, Waited) when Waited >= ?MAX_WAIT_MS ->
    {did_not_saturate, V};
converge(Mod, State, {Prev, _}, Waited) ->
    timer:sleep(?STEP_MS),
    case Mod:get_pacing_tokens(State, ?HUGE) of
        {Prev, _} -> Prev;
        Next -> converge(Mod, State, Next, Waited + ?STEP_MS)
    end.
