%%% -*- erlang -*-
%%%
%%% Tests for QUIC Flow Control
%%%

-module(quic_flow_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Basic State Tests
%%====================================================================

new_state_test() ->
    State = quic_flow:new(),
    ?assertEqual(0, quic_flow:bytes_sent(State)),
    ?assertEqual(0, quic_flow:bytes_received(State)),
    ?assert(quic_flow:send_limit(State) > 0),
    ?assert(quic_flow:recv_limit(State) > 0).

new_state_with_opts_test() ->
    State = quic_flow:new(#{
        initial_max_data => 500000,
        peer_initial_max_data => 600000
    }),
    ?assertEqual(600000, quic_flow:send_limit(State)),
    ?assertEqual(500000, quic_flow:recv_limit(State)).

%%====================================================================
%% Send Side Tests
%%====================================================================

can_send_within_limit_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 10000}),
    ?assert(quic_flow:can_send(State, 5000)),
    ?assert(quic_flow:can_send(State, 10000)),
    ?assertNot(quic_flow:can_send(State, 10001)).

on_data_sent_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 10000}),
    {ok, S1} = quic_flow:on_data_sent(State, 3000),
    ?assertEqual(3000, quic_flow:bytes_sent(S1)),
    ?assertEqual(7000, quic_flow:send_window(S1)).

on_data_sent_becomes_blocked_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 5000}),
    {ok, S1} = quic_flow:on_data_sent(State, 4000),
    ?assertNot(quic_flow:send_blocked(S1)),

    {blocked, S2} = quic_flow:on_data_sent(S1, 1000),
    ?assert(quic_flow:send_blocked(S2)),
    ?assertEqual(0, quic_flow:send_window(S2)).

send_blocked_initially_false_test() ->
    State = quic_flow:new(),
    ?assertNot(quic_flow:send_blocked(State)).

on_max_data_received_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 5000}),
    {blocked, S1} = quic_flow:on_data_sent(State, 5000),
    ?assert(quic_flow:send_blocked(S1)),
    ?assertEqual(0, quic_flow:send_window(S1)),

    %% Receive MAX_DATA from peer
    S2 = quic_flow:on_max_data_received(S1, 10000),
    ?assertNot(quic_flow:send_blocked(S2)),
    ?assertEqual(5000, quic_flow:send_window(S2)),
    ?assertEqual(10000, quic_flow:send_limit(S2)).

max_data_only_increases_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 10000}),
    % Lower
    S1 = quic_flow:on_max_data_received(State, 5000),
    ?assertEqual(10000, quic_flow:send_limit(S1)),

    % Higher
    S2 = quic_flow:on_max_data_received(S1, 15000),
    ?assertEqual(15000, quic_flow:send_limit(S2)).

%%====================================================================
%% Receive Side Tests
%%====================================================================

on_data_received_test() ->
    State = quic_flow:new(#{initial_max_data => 10000}),
    {ok, S1} = quic_flow:on_data_received(State, 3000),
    ?assertEqual(3000, quic_flow:bytes_received(S1)),
    ?assertEqual(7000, quic_flow:recv_window(S1)).

on_data_received_exceeds_limit_test() ->
    State = quic_flow:new(#{initial_max_data => 5000}),
    {ok, S1} = quic_flow:on_data_received(State, 5000),
    ?assertEqual(
        {error, flow_control_error},
        quic_flow:on_data_received(S1, 1)
    ).

on_data_received_at_limit_test() ->
    State = quic_flow:new(#{initial_max_data => 5000}),
    {ok, S1} = quic_flow:on_data_received(State, 5000),
    ?assertEqual(0, quic_flow:recv_window(S1)).

%%====================================================================
%% MAX_DATA Generation Tests
%%====================================================================

should_send_max_data_initially_false_test() ->
    State = quic_flow:new(),
    ?assertNot(quic_flow:should_send_max_data(State)).

should_send_max_data_after_threshold_test() ->
    %% With 50% threshold and initial_max_data=10000
    State = quic_flow:new(#{initial_max_data => 10000}),
    {ok, S1} = quic_flow:on_data_received(State, 4000),
    ?assertNot(quic_flow:should_send_max_data(S1)),

    % 6000 total > 50%
    {ok, S2} = quic_flow:on_data_received(S1, 2000),
    ?assert(quic_flow:should_send_max_data(S2)).

generate_max_data_test() ->
    State = quic_flow:new(#{initial_max_data => 10000}),
    {ok, S1} = quic_flow:on_data_received(State, 6000),

    {NewMax, S2} = quic_flow:generate_max_data(S1),
    %% New max should be bytes_received + initial_max_data
    ?assertEqual(16000, NewMax),
    ?assertEqual(16000, quic_flow:recv_limit(S2)),
    ?assertEqual(10000, quic_flow:recv_window(S2)).

generate_max_data_multiple_times_test() ->
    State = quic_flow:new(#{initial_max_data => 5000}),

    %% First round
    {ok, S1} = quic_flow:on_data_received(State, 4000),
    {NewMax1, S2} = quic_flow:generate_max_data(S1),
    ?assertEqual(9000, NewMax1),

    %% Receive more data
    {ok, S3} = quic_flow:on_data_received(S2, 3000),

    %% Second round
    {NewMax2, S4} = quic_flow:generate_max_data(S3),
    ?assertEqual(12000, NewMax2),
    ?assertEqual(5000, quic_flow:recv_window(S4)).

%%====================================================================
%% Window Tests
%%====================================================================

send_window_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 10000}),
    ?assertEqual(10000, quic_flow:send_window(State)),

    {ok, S1} = quic_flow:on_data_sent(State, 3000),
    ?assertEqual(7000, quic_flow:send_window(S1)),

    %% Sending exactly to the limit results in blocked
    {blocked, S2} = quic_flow:on_data_sent(S1, 7000),
    ?assertEqual(0, quic_flow:send_window(S2)).

recv_window_test() ->
    State = quic_flow:new(#{initial_max_data => 10000}),
    ?assertEqual(10000, quic_flow:recv_window(State)),

    {ok, S1} = quic_flow:on_data_received(State, 4000),
    ?assertEqual(6000, quic_flow:recv_window(S1)).

%%====================================================================
%% Integration Tests
%%====================================================================

full_send_cycle_test() ->
    State = quic_flow:new(#{peer_initial_max_data => 5000}),

    %% Send until blocked
    {ok, S1} = quic_flow:on_data_sent(State, 4000),
    ?assert(quic_flow:can_send(S1, 1000)),
    {blocked, S2} = quic_flow:on_data_sent(S1, 1000),
    ?assertNot(quic_flow:can_send(S2, 1)),

    %% Receive MAX_DATA
    S3 = quic_flow:on_max_data_received(S2, 10000),
    ?assert(quic_flow:can_send(S3, 5000)),

    %% Send more
    {ok, S4} = quic_flow:on_data_sent(S3, 3000),
    ?assertEqual(8000, quic_flow:bytes_sent(S4)).

full_recv_cycle_test() ->
    State = quic_flow:new(#{initial_max_data => 10000}),

    %% Receive some data (less than 50% threshold)
    {ok, S1} = quic_flow:on_data_received(State, 4000),
    ?assertNot(quic_flow:should_send_max_data(S1)),

    %% Receive more, triggering threshold (>50%)
    {ok, S2} = quic_flow:on_data_received(S1, 2000),
    ?assert(quic_flow:should_send_max_data(S2)),

    %% Generate MAX_DATA
    {NewMax, S3} = quic_flow:generate_max_data(S2),
    % 6000 + 10000
    ?assertEqual(16000, NewMax),
    ?assertNot(quic_flow:should_send_max_data(S3)),

    %% Can receive more now
    {ok, S4} = quic_flow:on_data_received(S3, 5000),
    ?assertEqual(11000, quic_flow:bytes_received(S4)).

bidirectional_flow_test() ->
    State = quic_flow:new(#{
        initial_max_data => 10000,
        peer_initial_max_data => 10000
    }),

    %% Send data
    {ok, S1} = quic_flow:on_data_sent(State, 5000),
    ?assertEqual(5000, quic_flow:bytes_sent(S1)),

    %% Receive data (independent of send)
    {ok, S2} = quic_flow:on_data_received(S1, 3000),
    ?assertEqual(3000, quic_flow:bytes_received(S2)),
    ?assertEqual(5000, quic_flow:bytes_sent(S2)).
