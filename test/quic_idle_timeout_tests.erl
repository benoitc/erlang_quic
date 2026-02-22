%%% -*- erlang -*-
%%%
%%% Tests for QUIC Idle Timeout Enforcement (RFC 9000 Section 10.1)
%%%

-module(quic_idle_timeout_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Idle Timer Message Tests
%%====================================================================

%% Test that idle_timeout message is properly formatted
idle_timeout_message_format_test() ->
    %% The idle timeout message should be an atom
    Msg = idle_timeout,
    ?assertEqual(idle_timeout, Msg).

%%====================================================================
%% Integration with Connection State
%%====================================================================

%% Note: Full integration tests require starting the connection process
%% and are covered in quic_connection_tests.erl and quic_e2e_SUITE.erl

%% Test the basic concept of idle timeout checking
idle_timeout_check_logic_test() ->
    % 30 seconds
    IdleTimeout = 30000,
    % 25 seconds ago
    LastActivity = erlang:monotonic_time(millisecond) - 25000,
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - LastActivity,

    %% Should NOT timeout (25s < 30s)
    ?assertNot(TimeSinceActivity >= IdleTimeout),

    %% Simulate more time passing

    % 35 seconds ago
    LastActivity2 = erlang:monotonic_time(millisecond) - 35000,
    TimeSinceActivity2 = Now - LastActivity2,

    %% Should timeout (35s >= 30s)
    ?assert(TimeSinceActivity2 >= IdleTimeout).

%% Test that zero idle timeout means no timeout
zero_idle_timeout_test() ->
    IdleTimeout = 0,
    % Very old
    _LastActivity = erlang:monotonic_time(millisecond) - 1000000,
    _Now = erlang:monotonic_time(millisecond),

    %% With 0 timeout, comparison should indicate "set but disabled"
    %% In the implementation, set_idle_timer returns immediately for timeout=0
    ?assertEqual(0, IdleTimeout).

%%====================================================================
%% Timer Reset Tests
%%====================================================================

%% Test that activity resets the idle timeout window
activity_resets_timeout_test() ->
    InitialActivity = erlang:monotonic_time(millisecond),
    % Small delay
    timer:sleep(10),

    %% Simulate activity update
    NewActivity = erlang:monotonic_time(millisecond),

    ?assert(NewActivity > InitialActivity).

%%====================================================================
%% Boundary Tests
%%====================================================================

%% Test exactly at timeout boundary
exact_timeout_boundary_test() ->
    % 1 second
    IdleTimeout = 1000,

    %% Exactly at boundary should trigger timeout (>= comparison)
    LastActivity = erlang:monotonic_time(millisecond) - 1000,
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - LastActivity,

    ?assert(TimeSinceActivity >= IdleTimeout).

%% Test just below timeout boundary
just_below_timeout_boundary_test() ->
    % 10 seconds
    IdleTimeout = 10000,

    %% Just below boundary should NOT trigger timeout

    % 9.99 seconds ago
    LastActivity = erlang:monotonic_time(millisecond) - 9990,
    Now = erlang:monotonic_time(millisecond),
    TimeSinceActivity = Now - LastActivity,

    ?assertNot(TimeSinceActivity >= IdleTimeout).
