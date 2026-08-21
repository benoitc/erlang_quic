%%% -*- erlang -*-
%%%
%%% Tests for the pacing burst allowance.
%%%
%%% Pacing wakeups run on send_after, which has roughly millisecond
%%% resolution. A burst bucket fixed at 12 packets therefore caps
%%% throughput at 12 packets per wakeup whenever the sender outruns the
%%% incoming ACK clock, no matter how high the paced rate is. The
%%% allowance has to scale with the rate: 2 ms worth of tokens keeps
%%% micro-bursts bounded while letting a 1 ms clock sustain the rate.
%%%
%%% pacing_max_burst has no accessor, but it is observable: the token
%%% bucket refills to min(MaxBurst, tokens + elapsed * rate) and
%%% get_pacing_tokens/2 hands back min(Size, tokens). Once enough time
%%% has passed for the bucket to saturate, asking for more than it can
%%% ever hold returns exactly MaxBurst.
%%%
%%% Covers PR #219.

-module(quic_pacing_burst_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MDS, 1200).
%% Larger than any burst under test, so the answer is bucket-limited.
-define(HUGE, (1 bsl 30)).
-define(STEP_MS, 10).
-define(MAX_WAIT_MS, 2000).

%%====================================================================
%% Helpers
%%====================================================================

%% Read back the burst ceiling.
%%
%% Every probe runs against the same input state, so each one sees a
%% longer elapsed time than the last and the refill grows monotonically
%% until it saturates at pacing_max_burst. Two consecutive equal reads
%% mean the bucket is full. Polling rather than sleeping a fixed
%% interval keeps this honest at low rates, where filling the bucket
%% takes far longer, without re-deriving the formula under test.
burst_ceiling(State) ->
    converge(State, quic_cc_newreno:get_pacing_tokens(State, ?HUGE), 0).

converge(_State, {V, _}, Waited) when Waited >= ?MAX_WAIT_MS ->
    %% Never saturated: report what we saw so the failure is legible.
    {did_not_saturate, V};
converge(State, {Prev, _}, Waited) ->
    timer:sleep(?STEP_MS),
    case quic_cc_newreno:get_pacing_tokens(State, ?HUGE) of
        {Prev, _} -> Prev;
        Next -> converge(State, Next, Waited + ?STEP_MS)
    end.

%% quic_cc_newreno stores the rate in milli-bytes per microsecond:
%% max(1, (cwnd * 1250) div (rtt_ms * 1000)).
rate(Cwnd, RttMs) ->
    max(1, (Cwnd * 1250) div (RttMs * 1000)).

paced(Cwnd, RttMs) ->
    State = quic_cc_newreno:new(#{max_datagram_size => ?MDS, initial_window => Cwnd}),
    quic_cc_newreno:update_pacing_rate(State, RttMs).

%%====================================================================
%% Baseline
%%====================================================================

unpaced_until_a_rate_exists_test() ->
    %% Straight out of new/1 there is no rate yet, so pacing does not
    %% gate anything and a send of any size is allowed through. The burst
    %% allowance only becomes observable once a rate is set.
    State = quic_cc_newreno:new(#{max_datagram_size => ?MDS}),
    ?assert(quic_cc_newreno:pacing_allows(State, ?HUGE)),
    ?assertEqual({?HUGE, State}, quic_cc_newreno:get_pacing_tokens(State, ?HUGE)).

%%====================================================================
%% The allowance scales with the rate
%%====================================================================

burst_scales_with_pacing_rate_test() ->
    %% A fat window on a short RTT: 2 ms of rate is far above the
    %% 12-packet floor, so the floor must not be what caps the bucket.
    Cwnd = 4000000,
    RttMs = 10,
    Rate = rate(Cwnd, RttMs),
    Expected = max(12 * ?MDS, 2 * Rate),
    ?assert(Expected > 12 * ?MDS),
    ?assertEqual(Expected, burst_ceiling(paced(Cwnd, RttMs))).

burst_keeps_the_floor_at_low_rates_test() ->
    %% A small window on a long RTT: 2 ms of rate is below the floor,
    %% which must still hold. Scaling the allowance must not be a way to
    %% shrink it.
    Cwnd = 12000,
    RttMs = 500,
    Rate = rate(Cwnd, RttMs),
    ?assert(2 * Rate < 12 * ?MDS),
    ?assertEqual(12 * ?MDS, burst_ceiling(paced(Cwnd, RttMs))).

burst_is_monotonic_in_rate_test() ->
    %% Same RTT, growing window: the allowance may plateau on the floor
    %% but must never move backwards as the rate rises.
    Ceilings = [burst_ceiling(paced(Cwnd, 20)) || Cwnd <- [12000, 120000, 1200000, 12000000]],
    ?assertEqual(lists:sort(Ceilings), Ceilings),
    ?assert(lists:last(Ceilings) > hd(Ceilings)).

%%====================================================================
%% MTU changes recompute the same way
%%====================================================================

update_mtu_scales_burst_with_rate_test() ->
    %% update_mtu recomputes the allowance and must apply the same rule,
    %% otherwise a PMTU probe silently reinstates the fixed bucket.
    Cwnd = 4000000,
    RttMs = 10,
    Rate = rate(Cwnd, RttMs),
    Paced = paced(Cwnd, RttMs),
    Bumped = quic_cc_newreno:update_mtu(Paced, 1400),
    ?assertEqual(1400, quic_cc_newreno:max_datagram_size(Bumped)),
    ?assertEqual(max(12 * 1400, 2 * Rate), burst_ceiling(Bumped)).

update_mtu_keeps_the_floor_at_low_rates_test() ->
    Cwnd = 12000,
    RttMs = 500,
    Paced = paced(Cwnd, RttMs),
    Bumped = quic_cc_newreno:update_mtu(Paced, 1400),
    ?assertEqual(12 * 1400, burst_ceiling(Bumped)).

%%====================================================================
%% Degenerate input
%%====================================================================

zero_rtt_paces_as_one_millisecond_test() ->
    %% RTT samples are whole milliseconds, so a sub-millisecond link
    %% reports 0. Treating that as "no RTT yet" froze the pacing rate at
    %% its handshake-time value while cwnd kept growing. The rate is
    %% computed as for a 1 ms RTT instead, so it keeps tracking cwnd.
    Small = 12000,
    Large = 4000000,
    ?assertEqual(
        max(12 * ?MDS, 2 * rate(Small, 1)),
        burst_ceiling(paced(Small, 0))
    ),
    ?assertEqual(
        max(12 * ?MDS, 2 * rate(Large, 1)),
        burst_ceiling(paced(Large, 0))
    ).
