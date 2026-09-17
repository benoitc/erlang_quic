%%% -*- erlang -*-
%%%
%%% Tests for quic_interval, the disjoint interval list behind reclaimed
%%% stream tracking. These functions had no direct coverage while they
%%% lived inside quic_connection; the merge cases below are the ones a
%%% reader would want pinned, since an interval list that fails to merge
%%% grows without bound and one that over-merges reports a stream
%%% reclaimed that never was.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_interval_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% add/2
%%====================================================================

add_to_empty_test() ->
    ?assertEqual([{5, 5}], quic_interval:add(5, [])).

%% A point below the first range, with a gap, stays separate.
add_before_first_with_gap_test() ->
    ?assertEqual([{1, 1}, {5, 7}], quic_interval:add(1, [{5, 7}])).

%% Adjacent below extends the range down rather than adding an entry.
add_adjacent_below_test() ->
    ?assertEqual([{4, 7}], quic_interval:add(4, [{5, 7}])).

%% Adjacent above extends the range up.
add_adjacent_above_test() ->
    ?assertEqual([{5, 8}], quic_interval:add(8, [{5, 7}])).

%% A point already covered changes nothing.
add_already_present_test() ->
    ?assertEqual([{5, 7}], quic_interval:add(6, [{5, 7}])),
    ?assertEqual([{5, 7}], quic_interval:add(5, [{5, 7}])),
    ?assertEqual([{5, 7}], quic_interval:add(7, [{5, 7}])).

%% A point past the first range recurses into the tail.
add_after_first_test() ->
    ?assertEqual([{1, 2}, {5, 5}], quic_interval:add(5, [{1, 2}])).

%% The point that closes a one-element gap joins both neighbours.
add_closes_gap_merges_neighbours_test() ->
    ?assertEqual([{1, 5}], quic_interval:add(3, [{1, 2}, {4, 5}])).

%% Filling a gap wider than one leaves the ranges separate.
add_wide_gap_stays_separate_test() ->
    ?assertEqual([{1, 3}, {5, 6}], quic_interval:add(3, [{1, 2}, {5, 6}])).

%% Inserting a run of points collapses to a single range.
add_run_collapses_test() ->
    Ranges = lists:foldl(fun quic_interval:add/2, [], lists:seq(1, 20)),
    ?assertEqual([{1, 20}], Ranges).

%% Order of insertion does not change the result.
add_is_order_independent_test() ->
    Forward = lists:foldl(fun quic_interval:add/2, [], [1, 2, 3, 7, 8]),
    Backward = lists:foldl(fun quic_interval:add/2, [], [8, 7, 3, 2, 1]),
    Shuffled = lists:foldl(fun quic_interval:add/2, [], [7, 1, 8, 3, 2]),
    ?assertEqual([{1, 3}, {7, 8}], Forward),
    ?assertEqual(Forward, Backward),
    ?assertEqual(Forward, Shuffled).

%%====================================================================
%% member/2
%%====================================================================

member_of_empty_is_false_test() ->
    ?assertNot(quic_interval:member(1, [])).

member_inside_and_on_edges_test() ->
    Ranges = [{5, 7}],
    ?assert(quic_interval:member(5, Ranges)),
    ?assert(quic_interval:member(6, Ranges)),
    ?assert(quic_interval:member(7, Ranges)),
    ?assertNot(quic_interval:member(4, Ranges)),
    ?assertNot(quic_interval:member(8, Ranges)).

member_searches_later_ranges_test() ->
    Ranges = [{1, 2}, {5, 6}, {9, 10}],
    ?assert(quic_interval:member(9, Ranges)),
    ?assertNot(quic_interval:member(7, Ranges)).

%% Everything added is a member; nothing in a gap is.
member_agrees_with_add_test() ->
    Added = [1, 2, 3, 7, 8, 100],
    Ranges = lists:foldl(fun quic_interval:add/2, [], Added),
    [?assert(quic_interval:member(I, Ranges)) || I <- Added],
    [?assertNot(quic_interval:member(I, Ranges)) || I <- [0, 4, 5, 6, 9, 99, 101]].
