%%% -*- erlang -*-
%%%
%%% The PTO backoff is bounded.
%%%
%%% RFC 9002 §6.2.1 doubles the PTO on each consecutive expiration, and
%%% the doubling on its own has no ceiling. On a 50 ms path that reaches
%%% roughly 90 seconds after nine expirations and about twelve minutes
%%% after twelve. A probe scheduled that far out is not a probe: the
%%% peer's idle timer, and any request deadline above it, will have
%%% fired long before. The connection is dead without being closed.
%%%
%%% Probes are a single small packet, so bounding the worst-case
%%% interval costs almost nothing and keeps recovery inside the window
%%% where anything is still listening. These tests pin the ceiling and,
%%% just as importantly, pin that the doubling below it is untouched.
%%%
%%% Covers PR #254.

-module(quic_pto_backoff_cap_tests).

-include_lib("eunit/include/eunit.hrl").

%% Must match quic_loss.
-define(MAX_PTO_MS, 5000).

%%====================================================================
%% Helpers
%%====================================================================

%% A tracker with a settled RTT, so the PTO has a definite base.
settled(RttMs) ->
    quic_loss:update_rtt(quic_loss:new(), RttMs, 0).

%% The PTO after N consecutive expirations.
pto_after(State, N) ->
    Expired = lists:foldl(
        fun(_, S) -> quic_loss:on_pto_expired(S) end,
        State,
        lists:seq(1, N)
    ),
    quic_loss:get_pto(Expired).

series(State, Upto) ->
    [pto_after(State, N) || N <- lists:seq(1, Upto)].

%%====================================================================
%% The ceiling
%%====================================================================

backoff_never_exceeds_the_cap_test() ->
    Series = series(settled(50), 12),
    ?assert(lists:all(fun(P) -> P =< ?MAX_PTO_MS end, Series)).

backoff_is_capped_even_from_a_slow_path_test() ->
    %% A long RTT reaches the ceiling in fewer steps, and must not step
    %% over it on the way.
    Series = series(settled(2000), 8),
    ?assert(lists:all(fun(P) -> P =< ?MAX_PTO_MS end, Series)).

a_long_loss_streak_stays_at_the_cap_test() ->
    %% The case that motivates this: without a ceiling, the doubling is
    %% into the minutes here.
    ?assertEqual(?MAX_PTO_MS, pto_after(settled(50), 20)),
    ?assertEqual(?MAX_PTO_MS, pto_after(settled(50), 40)).

%%====================================================================
%% Below the ceiling nothing changes (fences)
%%====================================================================

backoff_still_doubles_below_the_cap_test() ->
    State = settled(50),
    Base = quic_loss:get_pto(State),
    ?assert(Base * 2 < ?MAX_PTO_MS),
    %% Each step is exactly twice the last for as long as there is room.
    ?assertEqual(Base * 2, pto_after(State, 1)),
    ?assertEqual(Base * 4, pto_after(State, 2)),
    ?assertEqual(Base * 8, pto_after(State, 3)).

backoff_is_monotonic_test() ->
    Series = series(settled(50), 12),
    ?assertEqual(lists:sort(Series), Series).

first_expiration_is_not_clamped_on_a_fast_path_test() ->
    %% A short RTT must not be dragged up to the ceiling; the cap is an
    %% upper bound, not a floor.
    ?assert(pto_after(settled(5), 1) < ?MAX_PTO_MS).

unexpired_pto_is_untouched_test() ->
    State = settled(50),
    ?assert(quic_loss:get_pto(State) < ?MAX_PTO_MS),
    ?assertEqual(0, quic_loss:pto_count(State)).

%%====================================================================
%% Degenerate input
%%====================================================================

cap_holds_without_an_rtt_sample_test() ->
    %% Before the first sample the PTO runs off the default initial RTT.
    ?assert(pto_after(quic_loss:new(), 20) =< ?MAX_PTO_MS).
