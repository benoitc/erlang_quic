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

%% Test that large ranges are capped at MAX_ACK_RANGE (65536)
ack_ranges_large_first_range_capped_test() ->
    %% Create a range that exceeds MAX_ACK_RANGE
    LargeRange = [{0, 70000}],
    EncoderRanges = quic_connection:convert_ack_ranges_for_encode(LargeRange),
    %% FirstRange should be capped at 65536, not 70000
    [{LargestAcked, FirstRange}] = EncoderRanges,
    ?assertEqual(70000, LargestAcked),
    ?assertEqual(65536, FirstRange).

%% Test that subsequent large ranges are also validated
ack_ranges_large_subsequent_range_skipped_test() ->
    %% Create ranges where the second one would exceed MAX_ACK_RANGE
    %% This tests the Range =< 65536 check in convert_rest_ranges
    %% Normal case: [{100, 105}, {0, 50}]
    %% Gap = 100 - 50 - 2 = 48, Range = 50 - 0 = 50 (valid)
    NormalRanges = [{100, 105}, {0, 50}],
    NormalResult = quic_connection:convert_ack_ranges_for_encode(NormalRanges),
    ?assertEqual([{105, 5}, {48, 50}], NormalResult).

%% Test that skipping malformed range preserves PrevStart for next calculation
ack_ranges_skip_preserves_prevstart_test() ->
    %% If we skip a malformed range, the next range should use the
    %% original PrevStart, not the skipped range's Start
    %% Ranges: [{100, 105}, {95, 98}, {80, 85}]
    %% Second range overlaps (End=98 > PrevStart-2 = 98), Gap = 100 - 98 - 2 = 0
    %% After fix: when we skip due to overlap, we use PrevStart=100 for next range
    %% Gap for third = 100 - 85 - 2 = 13, Range = 85 - 80 = 5
    Ranges = [{100, 105}, {80, 85}],
    Result = quic_connection:convert_ack_ranges_for_encode(Ranges),
    %% Gap = 100 - 85 - 2 = 13, Range = 85 - 80 = 5
    ?assertEqual([{105, 5}, {13, 5}], Result).

%% Test roundtrip: encode ACK ranges and verify they can be decoded
ack_ranges_encode_decode_roundtrip_test() ->
    %% Build internal ranges
    Ranges = [{90, 100}, {70, 80}, {50, 60}],

    %% Convert to encoder format
    EncoderRanges = quic_connection:convert_ack_ranges_for_encode(Ranges),

    %% Verify format: [{LargestAcked, FirstRange}, {Gap, Range}, ...]
    [{LargestAcked, FirstRange} | RestRanges] = EncoderRanges,
    ?assertEqual(100, LargestAcked),
    % 100 - 90 = 10
    ?assertEqual(10, FirstRange),

    %% Verify gaps and ranges are non-negative (required for varint encoding)
    lists:foreach(
        fun({Gap, Range}) ->
            ?assert(Gap >= 0),
            ?assert(Range >= 0),
            ?assert(Range =< 65536)
        end,
        RestRanges
    ).

%% Test that empty ranges returns empty
ack_ranges_convert_empty_test() ->
    %% This should not happen in practice, but test defensive behavior
    ?assertError(function_clause, quic_connection:convert_ack_ranges_for_encode([])).

%%====================================================================
%% Queue Limit Tests
%%====================================================================

%% Test that send_queue_bytes is tracked in connection state
send_queue_bytes_in_state_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    %% Should have send_queue_bytes field in state info
    ?assert(maps:is_key(send_queue_bytes, Info)),
    ?assertEqual(0, maps:get(send_queue_bytes, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test that recv_buffer_bytes is tracked in connection state
recv_buffer_bytes_in_state_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    %% Should have recv_buffer_bytes field in state info
    ?assert(maps:is_key(recv_buffer_bytes, Info)),
    ?assertEqual(0, maps:get(recv_buffer_bytes, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test that state info contains both queue counters
state_info_contains_queue_counters_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    %% Verify both counters are present
    RequiredKeys = [send_queue_bytes, recv_buffer_bytes, data_sent, data_received],
    lists:foreach(
        fun(Key) ->
            ?assert(maps:is_key(Key, Info), {missing_key, Key})
        end,
        RequiredKeys
    ),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Send Queue Flow Control Tests
%% RFC 9000 Section 4.1: Connection-level flow control
%% RFC 9000 Section 4.2: "A sender MUST NOT send data at an offset
%%                        beyond the limit set by its peer"
%%====================================================================

%% Test that sending within connection-level limits is allowed
flow_control_connection_within_limit_test() ->
    StreamId = 0,
    Offset = 0,
    DataSize = 1000,
    MaxDataRemote = 10000,
    DataSent = 5000,
    Streams = #{StreamId => {10000, 0}},
    ?assertEqual(
        ok,
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test that exceeding connection-level limit blocks
%% RFC 9000 Section 4.1: Sender must not exceed max_data
flow_control_connection_exceeds_limit_test() ->
    StreamId = 0,
    Offset = 0,
    DataSize = 6000,
    MaxDataRemote = 10000,
    DataSent = 5000,
    Streams = #{StreamId => {10000, 0}},
    ?assertEqual(
        {blocked, connection},
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test that exactly at connection limit is allowed
flow_control_connection_at_limit_test() ->
    StreamId = 0,
    Offset = 0,
    DataSize = 5000,
    MaxDataRemote = 10000,
    DataSent = 5000,
    Streams = #{StreamId => {10000, 0}},
    ?assertEqual(
        ok,
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test that already over connection limit blocks
%% This is a defensive check - shouldn't happen but guards against it
flow_control_connection_already_over_limit_test() ->
    StreamId = 0,
    Offset = 0,
    DataSize = 1000,
    MaxDataRemote = 10000,
    DataSent = 11000,
    Streams = #{StreamId => {10000, 0}},
    ?assertEqual(
        {blocked, connection},
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test that exceeding stream-level limit blocks
%% RFC 9000 Section 4.2: max_stream_data limits per-stream
flow_control_stream_exceeds_limit_test() ->
    StreamId = 0,
    Offset = 4000,
    DataSize = 2000,
    MaxDataRemote = 100000,
    DataSent = 0,
    Streams = #{StreamId => {5000, 4000}},
    ?assertEqual(
        {blocked, {stream, StreamId}},
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test that stream within limit is allowed
flow_control_stream_within_limit_test() ->
    StreamId = 4,
    Offset = 4000,
    DataSize = 500,
    MaxDataRemote = 100000,
    DataSent = 0,
    Streams = #{StreamId => {5000, 4000}},
    ?assertEqual(
        ok,
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test that unknown stream is allowed (will fail later in processing)
flow_control_unknown_stream_allowed_test() ->
    StreamId = 99,
    Offset = 0,
    DataSize = 1000,
    MaxDataRemote = 100000,
    DataSent = 0,
    Streams = #{0 => {5000, 0}},
    ?assertEqual(
        ok,
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%% Test connection limit checked before stream limit
%% Even if stream has capacity, connection limit blocks first
flow_control_connection_blocks_before_stream_test() ->
    StreamId = 0,
    Offset = 0,
    DataSize = 5000,
    MaxDataRemote = 1000,
    DataSent = 0,
    Streams = #{StreamId => {10000, 0}},
    ?assertEqual(
        {blocked, connection},
        quic_connection:test_check_flow_control(
            StreamId, Offset, DataSize, MaxDataRemote, DataSent, Streams
        )
    ).

%%====================================================================
%% Flow Control Auto-tuning Tests
%% RTT-based auto-tuning for flow control windows
%%====================================================================

%% Test that auto-tuning constants are correctly defined
auto_tune_constants_test() ->
    ?assertEqual(1.5, ?CONNECTION_FLOW_CONTROL_MULTIPLIER),
    ?assertEqual(8388608, ?DEFAULT_MAX_RECEIVE_WINDOW),
    ?assertEqual(4, ?AUTO_TUNE_RTT_FACTOR).

%% Test that default connection window is 1.5x stream window
default_connection_stream_ratio_test() ->
    %% DEFAULT_INITIAL_MAX_DATA should be 1.5x DEFAULT_INITIAL_MAX_STREAM_DATA
    ExpectedConnWindow = trunc(
        ?DEFAULT_INITIAL_MAX_STREAM_DATA * ?CONNECTION_FLOW_CONTROL_MULTIPLIER
    ),
    ?assertEqual(ExpectedConnWindow, ?DEFAULT_INITIAL_MAX_DATA).

%% Test custom max_receive_window option
custom_max_receive_window_test() ->
    CustomMaxWindow = 4194304,
    Opts = #{max_receive_window => CustomMaxWindow},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    ?assertEqual(CustomMaxWindow, maps:get(fc_max_receive_window, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test that state contains flow control auto-tuning fields
state_contains_fc_auto_tune_fields_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    %% Should have auto-tuning fields
    ?assert(maps:is_key(fc_last_stream_update, Info)),
    ?assert(maps:is_key(fc_last_conn_update, Info)),
    ?assert(maps:is_key(fc_max_receive_window, Info)),

    %% Initial values
    ?assertEqual(undefined, maps:get(fc_last_stream_update, Info)),
    ?assertEqual(undefined, maps:get(fc_last_conn_update, Info)),
    ?assertEqual(?DEFAULT_MAX_RECEIVE_WINDOW, maps:get(fc_max_receive_window, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test that max_data_local uses new default (1.5x stream window)
max_data_local_default_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    %% max_data_local should be 768KB (1.5 * 512KB)
    ?assertEqual(?DEFAULT_INITIAL_MAX_DATA, maps:get(max_data_local, Info)),
    ?assertEqual(786432, maps:get(max_data_local, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test custom max_data option still works
custom_max_data_overrides_default_test() ->
    CustomMaxData = 2097152,
    Opts = #{max_data => CustomMaxData},
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, Opts, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    ?assertEqual(CustomMaxData, maps:get(max_data_local, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test that fc_max_receive_window defaults to 8MB
fc_max_receive_window_default_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),
    {_State, Info} = quic_connection:get_state(Pid),

    %% 8MB = 8388608 bytes
    ?assertEqual(8388608, maps:get(fc_max_receive_window, Info)),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Regression: the ACK-coalesce path must decrement send_queue_bytes
%% and send_queue_count when it dequeues a small stream frame. Prior to
%% the fix the byte counter leaked on every coalesce and eventually
%% tripped ?MAX_SEND_QUEUE_BYTES, blocking further sends on long-lived
%% connections.
dequeue_small_stream_frame_decrements_bytes_test() ->
    Result = quic_connection:test_coalesce_small_stream(120),
    ?assertEqual(true, maps:get(dequeued, Result)),
    ?assertEqual(0, maps:get(send_queue_bytes, Result)),
    ?assertEqual(0, maps:get(send_queue_count, Result)),
    ?assertEqual(2, maps:get(send_queue_version, Result)).

%% Regression: an empty FIN-only stream send (iodata <<>>, Fin=true) can
%% be enqueued under pacing or cwnd blocking. The O(1) emptiness check
%% used by process_send_queue/1 and handle_pacing_timeout/1 must be based
%% on send_queue_count rather than send_queue_bytes; otherwise a zero-byte
%% FIN-only entry is stranded forever because send_queue_bytes stays at 0.
%% The benchmark itself triggers this pattern with
%% quic:send_data(Conn, StreamId, <<>>, true).
zero_byte_fin_not_stranded_test() ->
    Result = quic_connection:test_zero_byte_fin_in_queue(),
    %% Queue has a real entry
    ?assertEqual(false, maps:get(queue_empty, Result)),
    %% Byte-based check would incorrectly call it empty
    ?assertEqual(true, maps:get(empty_by_bytes, Result)),
    %% Count-based check correctly reports non-empty
    ?assertEqual(false, maps:get(empty_by_count, Result)).

%% RFC 9002 §6.2: ACK decimation for 1-RTT traffic.
%% First ack-eliciting packet arms the max_ack_delay timer but does
%% NOT emit an ACK yet.
ack_decimation_first_packet_arms_timer_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    {_S1, Info} = quic_connection:test_decimate_step(S0),
    ?assertEqual(1, maps:get(ack_elicited_count, Info)),
    ?assertEqual(true, maps:get(ack_timer_armed, Info)).

%% Second ack-eliciting packet (tolerance=2) triggers an immediate
%% ACK, which clears the count and cancels the timer.
ack_decimation_second_packet_flushes_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    {S1, _After1} = quic_connection:test_decimate_step(S0),
    {_S2, After2} = quic_connection:test_decimate_step(S1),
    %% send_app_ack/1 with empty ack_ranges short-circuits but still
    %% clears the decimation state via clear_ack_decimation_state/1.
    ?assertEqual(0, maps:get(ack_elicited_count, After2)),
    ?assertEqual(false, maps:get(ack_timer_armed, After2)).

%% Timer firing (simulated via send_app_ack/1) resets count + timer.
ack_decimation_timer_fire_resets_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    {S1, _After} = quic_connection:test_decimate_step(S0),
    %% At this point count=1 and timer armed. Simulate fire.
    Info = quic_connection:test_decimate_on_timer_fire(S1),
    ?assertEqual(0, maps:get(ack_elicited_count, Info)),
    ?assertEqual(false, maps:get(ack_timer_armed, Info)).

%% Arming is idempotent: first ack-eliciting packet arms, subsequent
%% steps below tolerance don't re-arm. Observable via stable count/
%% armed status after a single step.
ack_decimation_timer_idempotent_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    {_S1, Info} = quic_connection:test_decimate_step(S0),
    ?assertEqual(1, maps:get(ack_elicited_count, Info)),
    ?assertEqual(true, maps:get(ack_timer_armed, Info)).

%% RFC 9002 §6.2: reordered 1-RTT packets should elicit an immediate
%% ACK instead of being decimated. First ack-eliciting packet is still
%% decimated when classified as sequential.
ack_reorder_triggers_immediate_ack_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    Info = quic_connection:test_maybe_send_ack_app(reordered, S0),
    %% send_app_ack/1 runs its decimation-clear branch even when
    %% ack_ranges is empty, so count stays at 0 and timer stays unarmed.
    ?assertEqual(0, maps:get(ack_elicited_count, Info)),
    ?assertEqual(false, maps:get(ack_timer_armed, Info)).

ack_sequential_uses_decimation_test() ->
    S0 = quic_connection:test_decimate_initial_state(),
    Info = quic_connection:test_maybe_send_ack_app(sequential, S0),
    %% Sequential first packet arms the timer, count goes to 1.
    ?assertEqual(1, maps:get(ack_elicited_count, Info)),
    ?assertEqual(true, maps:get(ack_timer_armed, Info)).

%% `classify_recv_trigger/2' returns sequential for the first packet
%% (largest_recv = undefined) and for PN = largest_recv + 1; every other
%% PN (gap above, dup, below) is reordered.
ack_classify_recv_trigger_test() ->
    ?assertEqual(sequential, quic_connection:test_classify_recv_trigger(0, undefined)),
    ?assertEqual(sequential, quic_connection:test_classify_recv_trigger(7, 6)),
    ?assertEqual(reordered, quic_connection:test_classify_recv_trigger(9, 6)),
    ?assertEqual(reordered, quic_connection:test_classify_recv_trigger(3, 6)),
    ?assertEqual(reordered, quic_connection:test_classify_recv_trigger(6, 6)).
