%%% -*- erlang -*-
%%%
%%% Tests for QUIC Connection State Machine
%%%

-module(quic_connection_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Connection Lifecycle Tests
%%====================================================================

start_connection_test() ->
    %% Start a connection process
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),

    %% Get state should return idle initially
    {State, _Info} = quic_connection:get_state(Pid),
    ?assertEqual(idle, State),

    %% Clean up
    quic_connection:close(Pid, normal),
    timer:sleep(100).

connect_returns_ref_test() ->
    {ok, Ref, Pid} = quic_connection:connect("127.0.0.1", 4433, #{}, self()),
    ?assert(is_reference(Ref)),
    ?assert(is_pid(Pid)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

state_info_contains_required_fields_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    ?assert(maps:is_key(scid, Info)),
    ?assert(maps:is_key(dcid, Info)),
    ?assert(maps:is_key(role, Info)),
    ?assert(maps:is_key(version, Info)),
    ?assert(maps:is_key(streams, Info)),

    %% Should be client role
    ?assertEqual(client, maps:get(role, Info)),

    %% Should be QUIC v1
    ?assertEqual(?QUIC_VERSION_1, maps:get(version, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Connection Options Tests
%%====================================================================

custom_max_data_test() ->
    Opts = #{max_data => 2000000},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

custom_max_streams_test() ->
    Opts = #{max_streams_bidi => 50, max_streams_uni => 25},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

custom_idle_timeout_test() ->
    Opts = #{idle_timeout => 60000},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

alpn_option_test() ->
    Opts = #{alpn => <<"h3">>},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Close Tests
%%====================================================================

close_normal_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    quic_connection:close(Pid, normal),
    timer:sleep(200),

    %% Process should be shutting down or dead
    %% (draining state then closed)
    ok.

%%====================================================================
%% Process and Timeout Tests
%%====================================================================

process_cast_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    %% Should not crash
    ok = quic_connection:process(Pid),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

handle_timeout_cast_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    %% Should not crash
    ok = quic_connection:handle_timeout(Pid),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Multiple Connections Test
%%====================================================================

multiple_connections_test() ->
    {ok, Pid1} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {ok, Pid2} = quic_connection:start_link("127.0.0.1", 4434, #{}, self()),

    ?assertNotEqual(Pid1, Pid2),

    {_, Info1} = quic_connection:get_state(Pid1),
    {_, Info2} = quic_connection:get_state(Pid2),

    %% SCIDs should be different
    ?assertNotEqual(maps:get(scid, Info1), maps:get(scid, Info2)),

    quic_connection:close(Pid1, normal),
    quic_connection:close(Pid2, normal),
    timer:sleep(100).

%%====================================================================
%% IP Address Format Tests
%%====================================================================

ipv4_tuple_address_test() ->
    {ok, Pid} = quic_connection:start_link({127, 0, 0, 1}, 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

string_hostname_test() ->
    {ok, Pid} = quic_connection:start_link("localhost", 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

binary_hostname_test() ->
    {ok, Pid} = quic_connection:start_link(<<"localhost">>, 4433, #{}, self()),
    ?assert(is_pid(Pid)),
    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% ACK Range Tests
%%====================================================================

%% Test that ACK ranges are maintained in descending order
ack_ranges_descending_order_test() ->
    %% Start with empty, add packets out of order
    R1 = quic_connection:add_to_ack_ranges(10, []),
    ?assertEqual([{10, 10}], R1),

    %% Add lower packet - should go after
    R2 = quic_connection:add_to_ack_ranges(5, R1),
    ?assertEqual([{10, 10}, {5, 5}], R2),

    %% Add packet in between (not adjacent) - should be inserted
    R3 = quic_connection:add_to_ack_ranges(7, R2),
    ?assertEqual([{10, 10}, {7, 7}, {5, 5}], R3).

%% Test that adjacent packets extend ranges
ack_ranges_extend_upward_test() ->
    R1 = quic_connection:add_to_ack_ranges(5, []),
    ?assertEqual([{5, 5}], R1),

    R2 = quic_connection:add_to_ack_ranges(6, R1),
    ?assertEqual([{5, 6}], R2),

    R3 = quic_connection:add_to_ack_ranges(7, R2),
    ?assertEqual([{5, 7}], R3).

%% Test that adjacent packets extend ranges downward
ack_ranges_extend_downward_test() ->
    R1 = quic_connection:add_to_ack_ranges(10, []),
    ?assertEqual([{10, 10}], R1),

    R2 = quic_connection:add_to_ack_ranges(9, R1),
    ?assertEqual([{9, 10}], R2),

    R3 = quic_connection:add_to_ack_ranges(8, R2),
    ?assertEqual([{8, 10}], R3).

%% Test duplicate packet numbers are handled
ack_ranges_duplicate_test() ->
    R1 = quic_connection:add_to_ack_ranges(5, []),
    R2 = quic_connection:add_to_ack_ranges(6, R1),
    ?assertEqual([{5, 6}], R2),

    %% Add duplicate - should not change
    R3 = quic_connection:add_to_ack_ranges(5, R2),
    ?assertEqual([{5, 6}], R3),

    R4 = quic_connection:add_to_ack_ranges(6, R3),
    ?assertEqual([{5, 6}], R4).

%% Test that ranges merge when extending downward creates adjacency
ack_ranges_merge_test() ->
    %% Create two separate ranges
    R1 = quic_connection:add_to_ack_ranges(10, []),
    R2 = quic_connection:add_to_ack_ranges(8, R1),
    ?assertEqual([{10, 10}, {8, 8}], R2),

    %% Add packet 9 which should merge the two ranges
    R3 = quic_connection:add_to_ack_ranges(9, R2),
    ?assertEqual([{8, 10}], R3).

%% Test out-of-order packet arrival that previously caused negative gaps
ack_ranges_out_of_order_no_negative_gap_test() ->
    %% This sequence caused badarg in quic_varint:encode due to negative Gap
    %% Receive packets: 10, 5, 6
    R1 = quic_connection:add_to_ack_ranges(10, []),
    ?assertEqual([{10, 10}], R1),

    R2 = quic_connection:add_to_ack_ranges(5, R1),
    ?assertEqual([{10, 10}, {5, 5}], R2),

    R3 = quic_connection:add_to_ack_ranges(6, R2),
    %% {5, 5} should extend to {5, 6}
    ?assertEqual([{10, 10}, {5, 6}], R3),

    %% Now convert to encoder format - should work without crash
    EncoderRanges = quic_connection:convert_ack_ranges_for_encode(R3),
    %% First range: LargestAcked=10, FirstRange=0 (10-10)
    %% Second range: Gap = 10 - 6 - 2 = 2, Range = 6 - 5 = 1
    ?assertEqual([{10, 0}, {2, 1}], EncoderRanges).

%% Test complex out-of-order scenario
ack_ranges_complex_out_of_order_test() ->
    %% Receive: 100, 90, 95, 92, 93, 94, 91
    R1 = quic_connection:add_to_ack_ranges(100, []),
    R2 = quic_connection:add_to_ack_ranges(90, R1),
    R3 = quic_connection:add_to_ack_ranges(95, R2),
    R4 = quic_connection:add_to_ack_ranges(92, R3),
    R5 = quic_connection:add_to_ack_ranges(93, R4),
    R6 = quic_connection:add_to_ack_ranges(94, R5),

    %% Without 91: should have {92-95} and {90} separate since 91 is missing
    ?assertEqual([{100, 100}, {92, 95}, {90, 90}], R6),

    %% Now add 91 to fill the gap - should merge to {90-95}
    R7 = quic_connection:add_to_ack_ranges(91, R6),
    ?assertEqual([{100, 100}, {90, 95}], R7),

    %% Convert to encoder format - should work
    EncoderRanges = quic_connection:convert_ack_ranges_for_encode(R7),
    %% Gap = 100 - 95 - 2 = 3, Range = 95 - 90 = 5
    ?assertEqual([{100, 0}, {3, 5}], EncoderRanges).

%% Test that single range produces valid encoder format
ack_ranges_single_range_encode_test() ->
    R = [{50, 55}],
    EncoderRanges = quic_connection:convert_ack_ranges_for_encode(R),
    ?assertEqual([{55, 5}], EncoderRanges).

%% Test convert_rest_ranges skips invalid gaps
ack_ranges_skip_invalid_gap_test() ->
    %% If somehow we get malformed ranges, they should be skipped
    %% This is a defensive test - malformed ranges shouldn't happen
    %% with correct add_to_ack_ranges, but we test the safety net
    Result = quic_connection:convert_rest_ranges(5, [{10, 20}]),
    %% Gap = 5 - 20 - 2 = -17 (negative), should be skipped
    ?assertEqual([], Result).
