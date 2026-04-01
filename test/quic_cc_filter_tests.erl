%%% -*- erlang -*-
%%%
%%% Tests for QUIC Congestion Control Windowed Filters
%%%

-module(quic_cc_filter_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Max Filter Tests (for bandwidth estimation)
%%====================================================================

new_max_filter_test() ->
    Filter = quic_cc_filter:new_max_filter(10),
    ?assertEqual(0, quic_cc_filter:get_max(Filter)).

max_filter_single_update_test() ->
    Filter = quic_cc_filter:new_max_filter(10),
    Filter1 = quic_cc_filter:update_max(Filter, 1000, 1),
    ?assertEqual(1000, quic_cc_filter:get_max(Filter1)).

max_filter_increasing_values_test() ->
    Filter = quic_cc_filter:new_max_filter(10),
    Filter1 = quic_cc_filter:update_max(Filter, 100, 1),
    ?assertEqual(100, quic_cc_filter:get_max(Filter1)),
    Filter2 = quic_cc_filter:update_max(Filter1, 200, 2),
    ?assertEqual(200, quic_cc_filter:get_max(Filter2)),
    Filter3 = quic_cc_filter:update_max(Filter2, 300, 3),
    ?assertEqual(300, quic_cc_filter:get_max(Filter3)).

max_filter_decreasing_values_test() ->
    Filter = quic_cc_filter:new_max_filter(10),
    Filter1 = quic_cc_filter:update_max(Filter, 300, 1),
    ?assertEqual(300, quic_cc_filter:get_max(Filter1)),
    Filter2 = quic_cc_filter:update_max(Filter1, 200, 2),
    ?assertEqual(300, quic_cc_filter:get_max(Filter2)),
    Filter3 = quic_cc_filter:update_max(Filter2, 100, 3),
    ?assertEqual(300, quic_cc_filter:get_max(Filter3)).

max_filter_expiry_test() ->
    %% Window length of 10. Test that old max values expire.
    Filter = quic_cc_filter:new_max_filter(10),
    Filter1 = quic_cc_filter:update_max(Filter, 300, 0),
    ?assertEqual(300, quic_cc_filter:get_max(Filter1)),
    %% A new higher max at time 5 replaces the old
    Filter2 = quic_cc_filter:update_max(Filter1, 350, 5),
    ?assertEqual(350, quic_cc_filter:get_max(Filter2)),
    %% At time 12, the 300 at time 0 would have expired, but 350 at time 5 is still valid
    Filter3 = quic_cc_filter:update_max(Filter2, 100, 12),
    ?assertEqual(350, quic_cc_filter:get_max(Filter3)),
    %% At time 17, the 350 at time 5 has expired (17-5 > 10), new value takes over
    Filter4 = quic_cc_filter:update_max(Filter3, 200, 17),
    ?assertEqual(200, quic_cc_filter:get_max(Filter4)).

max_filter_reset_test() ->
    Filter = quic_cc_filter:new_max_filter(10),
    Filter1 = quic_cc_filter:update_max(Filter, 500, 1),
    ?assertEqual(500, quic_cc_filter:get_max(Filter1)),
    Filter2 = quic_cc_filter:reset_max(Filter1),
    ?assertEqual(0, quic_cc_filter:get_max(Filter2)).

%%====================================================================
%% Min Filter Tests (for RTT estimation)
%%====================================================================

new_min_filter_test() ->
    Filter = quic_cc_filter:new_min_filter(10000),
    ?assertEqual(infinity, quic_cc_filter:get_min(Filter)).

min_filter_single_update_test() ->
    Filter = quic_cc_filter:new_min_filter(10000),
    Filter1 = quic_cc_filter:update_min(Filter, 50, 1000),
    ?assertEqual(50, quic_cc_filter:get_min(Filter1)).

min_filter_decreasing_values_test() ->
    Filter = quic_cc_filter:new_min_filter(10000),
    Filter1 = quic_cc_filter:update_min(Filter, 100, 1000),
    ?assertEqual(100, quic_cc_filter:get_min(Filter1)),
    Filter2 = quic_cc_filter:update_min(Filter1, 50, 2000),
    ?assertEqual(50, quic_cc_filter:get_min(Filter2)),
    Filter3 = quic_cc_filter:update_min(Filter2, 25, 3000),
    ?assertEqual(25, quic_cc_filter:get_min(Filter3)).

min_filter_increasing_values_test() ->
    Filter = quic_cc_filter:new_min_filter(10000),
    Filter1 = quic_cc_filter:update_min(Filter, 25, 1000),
    ?assertEqual(25, quic_cc_filter:get_min(Filter1)),
    Filter2 = quic_cc_filter:update_min(Filter1, 50, 2000),
    ?assertEqual(25, quic_cc_filter:get_min(Filter2)),
    Filter3 = quic_cc_filter:update_min(Filter2, 100, 3000),
    ?assertEqual(25, quic_cc_filter:get_min(Filter3)).

min_filter_expiry_test() ->
    %% Window length of 10000ms. Test that old min values expire.
    Filter = quic_cc_filter:new_min_filter(10000),
    Filter1 = quic_cc_filter:update_min(Filter, 50, 0),
    ?assertEqual(50, quic_cc_filter:get_min(Filter1)),
    %% A new lower min at time 5000 replaces the old
    Filter2 = quic_cc_filter:update_min(Filter1, 25, 5000),
    ?assertEqual(25, quic_cc_filter:get_min(Filter2)),
    %% At time 12000, the 50 at time 0 would have expired, but 25 at time 5000 is still valid
    Filter3 = quic_cc_filter:update_min(Filter2, 100, 12000),
    ?assertEqual(25, quic_cc_filter:get_min(Filter3)),
    %% At time 17000, the 25 at time 5000 has expired (17000-5000 > 10000), new value takes over
    Filter4 = quic_cc_filter:update_min(Filter3, 75, 17000),
    ?assertEqual(75, quic_cc_filter:get_min(Filter4)).

min_filter_reset_test() ->
    Filter = quic_cc_filter:new_min_filter(10000),
    Filter1 = quic_cc_filter:update_min(Filter, 50, 1000),
    ?assertEqual(50, quic_cc_filter:get_min(Filter1)),
    Filter2 = quic_cc_filter:reset_min(Filter1),
    ?assertEqual(infinity, quic_cc_filter:get_min(Filter2)).

%%====================================================================
%% Edge Case Tests
%%====================================================================

max_filter_zero_window_test() ->
    %% Even with 0 window, should accept values
    Filter = quic_cc_filter:new_max_filter(0),
    Filter1 = quic_cc_filter:update_max(Filter, 100, 0),
    ?assertEqual(100, quic_cc_filter:get_max(Filter1)).

min_filter_same_time_updates_test() ->
    Filter = quic_cc_filter:new_min_filter(10000),
    Filter1 = quic_cc_filter:update_min(Filter, 100, 1000),
    Filter2 = quic_cc_filter:update_min(Filter1, 50, 1000),
    ?assertEqual(50, quic_cc_filter:get_min(Filter2)).

max_filter_same_time_updates_test() ->
    Filter = quic_cc_filter:new_max_filter(10),
    Filter1 = quic_cc_filter:update_max(Filter, 50, 1),
    Filter2 = quic_cc_filter:update_max(Filter1, 100, 1),
    ?assertEqual(100, quic_cc_filter:get_max(Filter2)).
