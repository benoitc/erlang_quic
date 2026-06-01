%%% -*- erlang -*-
%%%
%%% The QUIC dist keep-alive PING must fire several times per net_ticktime
%%% window, otherwise net_kernel sees a stale connection (getstat reports QUIC
%%% packets_received) and tears it down under load. These tests pin the
%%% net_ticktime -> interval derivation.

-module(quic_dist_keepalive_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_dist.hrl").

%% Default net_ticktime (60s) -> quarter window, comfortably below 60s.
default_ticktime_test() ->
    ?assertEqual(15000, quic_dist:keep_alive_interval_for(60)).

%% The interval must stay below net_ticktime for any sane ticktime, so a
%% healthy link always refreshes liveness within the window.
below_ticktime_test() ->
    lists:foreach(
        fun(T) ->
            ?assert(quic_dist:keep_alive_interval_for(T) < (T * 1000))
        end,
        [20, 60, 120, 600]
    ).

%% Small net_ticktime clamps to the 5s floor (the connection layer's minimum).
floor_test() ->
    ?assertEqual(?QUIC_DIST_KEEP_ALIVE_MIN, quic_dist:keep_alive_interval_for(8)).

%% A longer net_ticktime scales the interval up but keeps the quarter ratio.
large_ticktime_test() ->
    ?assertEqual(30000, quic_dist:keep_alive_interval_for(120)).

%% When net_ticktime is unset or invalid, fall back to the configured default,
%% which is itself below 60s.
fallback_test() ->
    ?assertEqual(?QUIC_DIST_KEEP_ALIVE_INTERVAL, quic_dist:keep_alive_interval_for(undefined)),
    ?assert(?QUIC_DIST_KEEP_ALIVE_INTERVAL < 60000).

%% The live call must not touch the net_kernel process (it runs inside the dist
%% callback, which IS net_kernel), and must return a usable interval below 60s.
live_call_no_deadlock_test() ->
    I = quic_dist:keep_alive_interval(),
    ?assert(is_integer(I) andalso I >= ?QUIC_DIST_KEEP_ALIVE_MIN andalso I < 60000).
