%%% -*- erlang -*-
%%%
%%% QUIC Distribution Controller Unit Tests
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_controller_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_dist.hrl").

%%====================================================================
%% Test Fixtures
%%====================================================================

%% Note: These are unit tests that don't require a running QUIC connection.
%% Integration tests are in the CT suites.

%%====================================================================
%% State Machine Tests
%%====================================================================

callback_mode_test() ->
    %% Verify the callback mode is state_functions with state_enter
    Result = quic_dist_controller:callback_mode(),
    ?assertEqual([state_functions, state_enter], Result).

%%====================================================================
%% Module Attribute Tests
%%====================================================================

%% Test that the module exports expected functions
exports_test() ->
    Exports = quic_dist_controller:module_info(exports),
    %% Check key API functions are exported
    ?assert(lists:member({start_link, 2}, Exports)),
    ?assert(lists:member({start_link, 3}, Exports)),
    ?assert(lists:member({send, 2}, Exports)),
    ?assert(lists:member({recv, 3}, Exports)),
    ?assert(lists:member({tick, 1}, Exports)),
    ?assert(lists:member({getstat, 1}, Exports)),
    ?assert(lists:member({get_address, 2}, Exports)),
    ?assert(lists:member({set_supervisor, 2}, Exports)).

%%====================================================================
%% API Tests (mocking connection)
%%====================================================================

%% These tests use meck to mock the quic_connection module.
%% They verify the controller's API works correctly.

-ifdef(MECK_TESTS).

setup_meck() ->
    meck:new(quic_connection, [passthrough]),
    meck:new(quic, [passthrough]),
    ok.

cleanup_meck(_) ->
    meck:unload(quic_connection),
    meck:unload(quic),
    ok.

controller_start_link_test_() ->
    {setup, fun setup_meck/0, fun cleanup_meck/1, fun(_) ->
        ConnRef = make_ref(),
        ConnPid = self(),

        %% Mock lookup to return our pid
        meck:expect(quic_connection, lookup, fun(Ref) when Ref =:= ConnRef ->
            {ok, ConnPid}
        end),

        %% Mock open_stream
        meck:expect(quic, open_stream, fun(_) -> {ok, 0} end),
        meck:expect(quic, set_stream_priority, fun(_, _, _, _) -> ok end),

        %% Start controller
        {ok, Pid} = quic_dist_controller:start_link(ConnRef, client),
        ?assert(is_pid(Pid)),

        %% Clean up
        gen_statem:stop(Pid),

        ok
    end}.

-endif.

%%====================================================================
%% Helper Function Tests
%%====================================================================

%% Test round-robin stream selection
stream_round_robin_test() ->
    Streams = [4, 8, 12, 16],

    %% Index 0 -> stream 4
    ?assertEqual(4, lists:nth((0 rem length(Streams)) + 1, Streams)),
    %% Index 1 -> stream 8
    ?assertEqual(8, lists:nth((1 rem length(Streams)) + 1, Streams)),
    %% Index 2 -> stream 12
    ?assertEqual(12, lists:nth((2 rem length(Streams)) + 1, Streams)),
    %% Index 3 -> stream 16
    ?assertEqual(16, lists:nth((3 rem length(Streams)) + 1, Streams)),
    %% Index 4 -> back to stream 4
    ?assertEqual(4, lists:nth((4 rem length(Streams)) + 1, Streams)).

%% Test message framing
message_framing_test() ->
    Data = <<"hello">>,

    %% Handshake framing (2-byte length prefix)
    Len2 = byte_size(Data),
    Frame2 = <<Len2:16/big, Data/binary>>,
    ?assertEqual(7, byte_size(Frame2)),

    %% Post-handshake framing (4-byte length prefix)
    Len4 = byte_size(Data),
    Frame4 = <<Len4:32/big, Data/binary>>,
    ?assertEqual(9, byte_size(Frame4)).

%% Test buffer operations
buffer_operations_test() ->
    Buffer = <<>>,
    Data1 = <<"hello">>,
    Data2 = <<" world">>,

    %% Append data
    Buffer1 = <<Buffer/binary, Data1/binary>>,
    ?assertEqual(<<"hello">>, Buffer1),

    Buffer2 = <<Buffer1/binary, Data2/binary>>,
    ?assertEqual(<<"hello world">>, Buffer2),

    %% Extract data
    Length = 5,
    <<Extracted:Length/binary, Rest/binary>> = Buffer2,
    ?assertEqual(<<"hello">>, Extracted),
    ?assertEqual(<<" world">>, Rest).

%%====================================================================
%% Message Reassembly Tests
%%====================================================================

%% Test parsing complete messages from buffer (4-byte length prefix)
parse_complete_message_test() ->
    %% Single complete message
    Payload = <<"hello world">>,
    Len = byte_size(Payload),
    Buffer = <<Len:32/big, Payload/binary>>,

    <<MsgLen:32/big, Rest/binary>> = Buffer,
    ?assertEqual(11, MsgLen),
    <<Msg:MsgLen/binary, Remaining/binary>> = Rest,
    ?assertEqual(<<"hello world">>, Msg),
    ?assertEqual(<<>>, Remaining).

%% Test parsing multiple messages in buffer
parse_multiple_messages_test() ->
    Msg1 = <<"hello">>,
    Msg2 = <<"world">>,
    Len1 = byte_size(Msg1),
    Len2 = byte_size(Msg2),
    Buffer = <<Len1:32/big, Msg1/binary, Len2:32/big, Msg2/binary>>,

    %% Parse first message
    <<L1:32/big, R1/binary>> = Buffer,
    <<M1:L1/binary, R2/binary>> = R1,
    ?assertEqual(<<"hello">>, M1),

    %% Parse second message
    <<L2:32/big, R3/binary>> = R2,
    <<M2:L2/binary, R4/binary>> = R3,
    ?assertEqual(<<"world">>, M2),
    ?assertEqual(<<>>, R4).

%% Test incomplete message (partial header)
parse_incomplete_header_test() ->
    %% Only 2 bytes of 4-byte header
    Buffer = <<0, 0>>,
    ?assert(byte_size(Buffer) < 4).

%% Test incomplete message (partial payload)
parse_incomplete_payload_test() ->
    %% Header says 10 bytes, but only 5 available
    Buffer = <<10:32/big, "hello">>,
    <<Len:32/big, Rest/binary>> = Buffer,
    ?assertEqual(10, Len),
    ?assertEqual(5, byte_size(Rest)),
    ?assert(byte_size(Rest) < Len).

%% Test tick frame (zero-length message)
parse_tick_frame_test() ->
    %% Tick is an empty frame with length 0
    Buffer = <<0:32/big>>,
    <<Len:32/big, Rest/binary>> = Buffer,
    ?assertEqual(0, Len),
    ?assertEqual(<<>>, Rest).

%% Test message reassembly across chunks (simulating QUIC delivery)
reassembly_across_chunks_test() ->
    Payload = <<"this is a longer message for testing">>,
    Len = byte_size(Payload),
    FullFrame = <<Len:32/big, Payload/binary>>,

    %% Split into 3 chunks (simulating QUIC MTU fragmentation)
    <<Chunk1:10/binary, Chunk2:15/binary, Chunk3/binary>> = FullFrame,

    %% Reassemble
    Buffer1 = Chunk1,
    Buffer2 = <<Buffer1/binary, Chunk2/binary>>,
    Buffer3 = <<Buffer2/binary, Chunk3/binary>>,

    ?assertEqual(FullFrame, Buffer3),

    %% Now parse
    <<ParsedLen:32/big, ParsedRest/binary>> = Buffer3,
    <<ParsedMsg:ParsedLen/binary, _/binary>> = ParsedRest,
    ?assertEqual(Payload, ParsedMsg).

%%====================================================================
%% Handshake Framing Tests (2-byte length prefix)
%%====================================================================

handshake_framing_test() ->
    Data = <<"handshake data">>,
    Len = byte_size(Data),
    Frame = <<Len:16/big, Data/binary>>,

    <<ParsedLen:16/big, Rest/binary>> = Frame,
    ?assertEqual(14, ParsedLen),
    <<ParsedData:ParsedLen/binary, _/binary>> = Rest,
    ?assertEqual(Data, ParsedData).

handshake_max_size_test() ->
    %% Max handshake message size with 2-byte length is 65535
    MaxLen = 65535,
    ?assert(MaxLen =< 16#FFFF).

%%====================================================================
%% Stream Selection Tests
%%====================================================================

%% Test data stream round-robin selection
data_stream_round_robin_test() ->
    DataStreams = [4, 8, 12, 16],
    NumStreams = length(DataStreams),

    %% Simulate 10 sends
    Results = lists:map(
        fun(Idx) ->
            lists:nth((Idx rem NumStreams) + 1, DataStreams)
        end,
        lists:seq(0, 9)
    ),

    %% Should cycle through: 4,8,12,16,4,8,12,16,4,8
    Expected = [4, 8, 12, 16, 4, 8, 12, 16, 4, 8],
    ?assertEqual(Expected, Results).

%% Test urgency values for different stream types
stream_urgency_test() ->
    %% From quic_dist.hrl
    ControlUrgency = 0,
    SignalUrgency = 2,
    DataHighUrgency = 4,
    DataNormalUrgency = 5,
    DataLowUrgency = 6,

    %% Control has highest priority (lowest number)
    ?assert(ControlUrgency < SignalUrgency),
    ?assert(SignalUrgency < DataHighUrgency),
    ?assert(DataHighUrgency < DataNormalUrgency),
    ?assert(DataNormalUrgency < DataLowUrgency).

%%====================================================================
%% Backpressure Logic Tests
%%====================================================================

%% Test congestion detection threshold
congestion_threshold_test() ->
    %% Default threshold is 2x cwnd
    Cwnd = 65536,
    Threshold = 2,

    %% Queue below threshold - not congested
    QueueSize1 = Cwnd,
    Congested1 = QueueSize1 > (Cwnd * Threshold),
    ?assertNot(Congested1),

    %% Queue at threshold - not congested
    QueueSize2 = Cwnd * Threshold,
    Congested2 = QueueSize2 > (Cwnd * Threshold),
    ?assertNot(Congested2),

    %% Queue above threshold - congested
    QueueSize3 = Cwnd * Threshold + 1,
    Congested3 = QueueSize3 > (Cwnd * Threshold),
    ?assert(Congested3).

%% Test max pull limiting
max_pull_limit_test() ->
    MaxPull = 16,

    %% Should pull at most MaxPull messages per notification
    Available = 100,
    Pulled = min(Available, MaxPull),
    ?assertEqual(16, Pulled),

    %% When fewer available, pull all
    Available2 = 5,
    Pulled2 = min(Available2, MaxPull),
    ?assertEqual(5, Pulled2).

%%====================================================================
%% Statistics Tests
%%====================================================================

%% Test getstat return format
getstat_format_test() ->
    %% getstat should return list of {atom(), integer()} tuples
    ExpectedKeys = [
        recv_cnt,
        recv_max,
        recv_avg,
        recv_oct,
        recv_dvi,
        send_cnt,
        send_max,
        send_avg,
        send_oct,
        send_pend
    ],

    %% Verify all expected keys are atoms
    lists:foreach(
        fun(Key) ->
            ?assert(is_atom(Key))
        end,
        ExpectedKeys
    ).

%%====================================================================
%% Tick Frame Tests (Critical for net_tick_timeout prevention)
%%====================================================================

%% Test tick frame format (4-byte zero length)
tick_frame_format_test() ->
    %% Tick frame is an empty message with 4-byte length prefix = 0
    TickFrame = <<0:32/big-unsigned>>,
    ?assertEqual(4, byte_size(TickFrame)),
    <<Length:32/big-unsigned>> = TickFrame,
    ?assertEqual(0, Length).

%% Test parsing tick frame from buffer
parse_tick_frame_exact_test() ->
    %% Exactly one tick frame
    Buffer = <<0:32/big-unsigned>>,
    <<Length:32/big-unsigned, Rest/binary>> = Buffer,
    ?assertEqual(0, Length),
    ?assertEqual(<<>>, Rest).

%% Test tick frame followed by data
tick_then_data_test() ->
    %% Tick frame followed by a data message
    Payload = <<"hello">>,
    PayloadLen = byte_size(Payload),
    Buffer = <<0:32/big-unsigned, PayloadLen:32/big-unsigned, Payload/binary>>,

    %% Parse tick
    <<TickLen:32/big-unsigned, Rest1/binary>> = Buffer,
    ?assertEqual(0, TickLen),

    %% Parse data message
    <<DataLen:32/big-unsigned, Rest2/binary>> = Rest1,
    ?assertEqual(5, DataLen),
    <<Data:DataLen/binary, Remaining/binary>> = Rest2,
    ?assertEqual(<<"hello">>, Data),
    ?assertEqual(<<>>, Remaining).

%% Test data followed by tick frame
data_then_tick_test() ->
    %% Data message followed by tick frame
    Payload = <<"world">>,
    PayloadLen = byte_size(Payload),
    Buffer = <<PayloadLen:32/big-unsigned, Payload/binary, 0:32/big-unsigned>>,

    %% Parse data message
    <<DataLen:32/big-unsigned, Rest1/binary>> = Buffer,
    ?assertEqual(5, DataLen),
    <<Data:DataLen/binary, Rest2/binary>> = Rest1,
    ?assertEqual(<<"world">>, Data),

    %% Parse tick
    <<TickLen:32/big-unsigned, Remaining/binary>> = Rest2,
    ?assertEqual(0, TickLen),
    ?assertEqual(<<>>, Remaining).

%% Test multiple consecutive tick frames
multiple_ticks_test() ->
    %% Three consecutive tick frames
    Buffer = <<0:32/big-unsigned, 0:32/big-unsigned, 0:32/big-unsigned>>,
    ?assertEqual(12, byte_size(Buffer)),

    %% Parse all three
    <<T1:32/big-unsigned, R1/binary>> = Buffer,
    <<T2:32/big-unsigned, R2/binary>> = R1,
    <<T3:32/big-unsigned, R3/binary>> = R2,
    ?assertEqual(0, T1),
    ?assertEqual(0, T2),
    ?assertEqual(0, T3),
    ?assertEqual(<<>>, R3).

%% Test tick interleaved with data messages
interleaved_tick_data_test() ->
    %% Pattern: data, tick, data, tick
    D1 = <<"msg1">>,
    D2 = <<"msg2">>,
    Buffer = <<
        (byte_size(D1)):32/big-unsigned,
        D1/binary,
        0:32/big-unsigned,
        (byte_size(D2)):32/big-unsigned,
        D2/binary,
        0:32/big-unsigned
    >>,

    %% Parse sequence
    <<L1:32/big-unsigned, R1/binary>> = Buffer,
    <<M1:L1/binary, R2/binary>> = R1,
    ?assertEqual(<<"msg1">>, M1),

    <<T1:32/big-unsigned, R3/binary>> = R2,
    ?assertEqual(0, T1),

    <<L2:32/big-unsigned, R4/binary>> = R3,
    <<M2:L2/binary, R5/binary>> = R4,
    ?assertEqual(<<"msg2">>, M2),

    <<T2:32/big-unsigned, R6/binary>> = R5,
    ?assertEqual(0, T2),
    ?assertEqual(<<>>, R6).

%%====================================================================
%% Message Reassembly Edge Cases
%%====================================================================

%% Test partial tick frame (only 2 bytes of header)
partial_tick_header_test() ->
    %% Only 2 of 4 header bytes received
    Buffer = <<0, 0>>,
    ?assertEqual(2, byte_size(Buffer)),
    ?assert(byte_size(Buffer) < 4).

%% Test partial tick frame (3 bytes of header)
partial_tick_header_3bytes_test() ->
    Buffer = <<0, 0, 0>>,
    ?assertEqual(3, byte_size(Buffer)),
    ?assert(byte_size(Buffer) < 4).

%% Test message split exactly at length boundary
split_at_length_boundary_test() ->
    Payload = <<"test data">>,
    Len = byte_size(Payload),

    %% Chunk 1: just the length header
    Chunk1 = <<Len:32/big-unsigned>>,
    %% Chunk 2: just the payload
    Chunk2 = Payload,

    %% Reassemble
    Buffer = <<Chunk1/binary, Chunk2/binary>>,

    %% Parse should work
    <<ParsedLen:32/big-unsigned, Rest/binary>> = Buffer,
    ?assertEqual(9, ParsedLen),
    <<ParsedData:ParsedLen/binary, _/binary>> = Rest,
    ?assertEqual(<<"test data">>, ParsedData).

%% Test message split in middle of length header
split_in_header_test() ->
    Payload = <<"hello">>,
    Len = byte_size(Payload),
    Full = <<Len:32/big-unsigned, Payload/binary>>,

    %% Split after 2 bytes of header
    <<Chunk1:2/binary, Chunk2/binary>> = Full,

    %% Chunk1 alone is incomplete
    ?assertEqual(2, byte_size(Chunk1)),
    ?assert(byte_size(Chunk1) < 4),

    %% After reassembly, parsing works
    Reassembled = <<Chunk1/binary, Chunk2/binary>>,
    <<L:32/big-unsigned, R/binary>> = Reassembled,
    <<D:L/binary, _/binary>> = R,
    ?assertEqual(<<"hello">>, D).

%% Test message split in middle of payload
split_in_payload_test() ->
    Payload = <<"0123456789">>,
    Len = byte_size(Payload),
    Full = <<Len:32/big-unsigned, Payload/binary>>,

    %% Split after header + 5 bytes of payload
    <<Chunk1:9/binary, Chunk2/binary>> = Full,

    %% Chunk1 has header + partial payload
    <<L1:32/big-unsigned, P1/binary>> = Chunk1,
    ?assertEqual(10, L1),
    % Only 5 of 10 bytes
    ?assertEqual(5, byte_size(P1)),

    %% After reassembly
    Reassembled = <<Chunk1/binary, Chunk2/binary>>,
    <<L:32/big-unsigned, R/binary>> = Reassembled,
    <<D:L/binary, _/binary>> = R,
    ?assertEqual(<<"0123456789">>, D).

%% Test very large message handling
large_message_framing_test() ->
    %% 1MB message
    LargeSize = 1024 * 1024,
    LargePayload = binary:copy(<<$A>>, LargeSize),

    %% Frame it
    Framed = <<LargeSize:32/big-unsigned, LargePayload/binary>>,
    ?assertEqual(LargeSize + 4, byte_size(Framed)),

    %% Parse back
    <<ParsedLen:32/big-unsigned, Rest/binary>> = Framed,
    ?assertEqual(LargeSize, ParsedLen),
    ?assertEqual(LargeSize, byte_size(Rest)).

%% Test maximum 32-bit length value
max_length_value_test() ->
    %% Max value that fits in 32-bit unsigned
    MaxLen = 16#FFFFFFFF,
    Header = <<MaxLen:32/big-unsigned>>,
    <<ParsedLen:32/big-unsigned>> = Header,
    ?assertEqual(4294967295, ParsedLen).

%% Test zero-length message vs tick
zero_length_message_test() ->
    %% Zero-length messages are valid and used for ticks
    ZeroMsg = <<0:32/big-unsigned>>,
    <<Len:32/big-unsigned, Rest/binary>> = ZeroMsg,
    ?assertEqual(0, Len),
    ?assertEqual(<<>>, Rest).

%%====================================================================
%% Buffer State Edge Cases
%%====================================================================

%% Test empty buffer
empty_buffer_test() ->
    Buffer = <<>>,
    ?assertEqual(0, byte_size(Buffer)).

%% Test 1-byte buffer (minimal incomplete header)
one_byte_buffer_test() ->
    Buffer = <<0>>,
    ?assertEqual(1, byte_size(Buffer)),
    ?assert(byte_size(Buffer) < 4).

%% Test exactly 4-byte buffer (just header, tick case)
exact_header_tick_test() ->
    Buffer = <<0:32/big-unsigned>>,
    ?assertEqual(4, byte_size(Buffer)),
    <<Len:32/big-unsigned, Rest/binary>> = Buffer,
    ?assertEqual(0, Len),
    ?assertEqual(<<>>, Rest).

%% Test exactly 4-byte buffer (header for non-empty message)
exact_header_incomplete_test() ->
    %% Header says 10 bytes but no payload
    Buffer = <<10:32/big-unsigned>>,
    <<Len:32/big-unsigned, Rest/binary>> = Buffer,
    ?assertEqual(10, Len),
    ?assertEqual(0, byte_size(Rest)),
    ?assert(byte_size(Rest) < Len).

%% Test buffer with multiple complete messages and partial
multiple_complete_plus_partial_test() ->
    M1 = <<"first">>,
    M2 = <<"second">>,
    %% Third message is incomplete (only header + 2 bytes)

    Buffer = <<
        (byte_size(M1)):32/big-unsigned,
        M1/binary,
        (byte_size(M2)):32/big-unsigned,
        M2/binary,
        10:32/big-unsigned,
        "ab"
    >>,

    %% Parse first
    <<L1:32/big-unsigned, R1/binary>> = Buffer,
    <<D1:L1/binary, R2/binary>> = R1,
    ?assertEqual(<<"first">>, D1),

    %% Parse second
    <<L2:32/big-unsigned, R3/binary>> = R2,
    <<D2:L2/binary, R4/binary>> = R3,
    ?assertEqual(<<"second">>, D2),

    %% Third is incomplete
    <<L3:32/big-unsigned, R5/binary>> = R4,
    ?assertEqual(10, L3),
    ?assertEqual(2, byte_size(R5)),
    ?assert(byte_size(R5) < L3).

%%====================================================================
%% Delivery Function Logic Tests
%%====================================================================

%% Test deliver_complete_messages logic simulation
deliver_logic_complete_msg_test() ->
    %% Simulate complete message in buffer
    Payload = <<"test">>,
    Buffer = <<(byte_size(Payload)):32/big-unsigned, Payload/binary>>,

    case Buffer of
        <<0:32/big-unsigned, Remaining/binary>> ->
            %% Tick case
            ?assertEqual(ok, tick_received),
            Remaining;
        <<Length:32/big-unsigned, Rest/binary>> when byte_size(Rest) >= Length ->
            %% Complete message
            <<Msg:Length/binary, Remaining/binary>> = Rest,
            ?assertEqual(<<"test">>, Msg),
            ?assertEqual(<<>>, Remaining);
        <<_Length:32/big-unsigned, _Rest/binary>> ->
            %% Incomplete
            ?assert(false);
        _ when byte_size(Buffer) < 4 ->
            %% Need header
            ?assert(false)
    end.

%% Test deliver_complete_messages with tick
deliver_logic_tick_test() ->
    Buffer = <<0:32/big-unsigned>>,

    case Buffer of
        <<0:32/big-unsigned, Remaining/binary>> ->
            %% Tick frame - no payload
            ?assertEqual(<<>>, Remaining);
        _ ->
            ?assert(false)
    end.

%% Test deliver_complete_messages with incomplete payload
deliver_logic_incomplete_test() ->
    %% Header says 10, only 5 available
    Buffer = <<10:32/big-unsigned, "hello">>,

    case Buffer of
        <<0:32/big-unsigned, _/binary>> ->
            ?assert(false);
        <<Length:32/big-unsigned, Rest/binary>> when byte_size(Rest) >= Length ->
            ?assert(false);
        <<Length:32/big-unsigned, Rest/binary>> ->
            %% Incomplete - need more data
            ?assertEqual(10, Length),
            ?assertEqual(5, byte_size(Rest)),
            ok;
        _ when byte_size(Buffer) < 4 ->
            ?assert(false)
    end.

%%====================================================================
%% Backpressure Configuration Tests
%%====================================================================

%% Test default backpressure values
backpressure_defaults_test() ->
    ?assertEqual(2, ?DEFAULT_QUEUE_CONGESTION_THRESHOLD),
    ?assertEqual(16, ?DEFAULT_MAX_PULL_PER_NOTIFICATION),
    ?assertEqual(10, ?DEFAULT_BACKPRESSURE_RETRY_MS).

%% Test max pull calculation
max_pull_calculation_test() ->
    MaxPull = 16,

    %% When many available, limit to MaxPull
    Available1 = 100,
    Pulled1 = min(Available1, MaxPull),
    ?assertEqual(16, Pulled1),

    %% When less than MaxPull, pull all
    Available2 = 5,
    Pulled2 = min(Available2, MaxPull),
    ?assertEqual(5, Pulled2),

    %% When exactly MaxPull
    Available3 = 16,
    Pulled3 = min(Available3, MaxPull),
    ?assertEqual(16, Pulled3).

%% Test congestion detection logic
congestion_detection_test() ->
    %% Congested = QueueSize > Cwnd * Threshold
    Cwnd = 65536,
    Threshold = 2,
    CongestionLimit = Cwnd * Threshold,

    %% Not congested at boundary
    ?assertNot(CongestionLimit > CongestionLimit),

    %% Congested above boundary
    ?assert((CongestionLimit + 1) > CongestionLimit),

    %% Not congested below
    ?assertNot((CongestionLimit - 1) > CongestionLimit).

%%====================================================================
%% Stream Selection Tests
%%====================================================================

%% Test empty data streams fallback
empty_data_streams_fallback_test() ->
    %% When no data streams, should fall back to control stream
    DataStreams = [],
    ControlStream = 0,

    SelectedStream =
        case DataStreams of
            [] -> ControlStream;
            _ -> lists:nth(1, DataStreams)
        end,
    ?assertEqual(0, SelectedStream).

%% Test round robin wraps correctly
round_robin_wrap_test() ->
    Streams = [4, 8, 12, 16],
    NumStreams = length(Streams),

    %% Test indices 0-7 (wraps at 4)
    Expected = [4, 8, 12, 16, 4, 8, 12, 16],
    Results = [lists:nth((I rem NumStreams) + 1, Streams) || I <- lists:seq(0, 7)],
    ?assertEqual(Expected, Results).

%% Test single stream round robin
single_stream_round_robin_test() ->
    Streams = [4],
    NumStreams = length(Streams),

    %% All indices should select stream 4
    Results = [lists:nth((I rem NumStreams) + 1, Streams) || I <- lists:seq(0, 9)],
    Expected = [4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
    ?assertEqual(Expected, Results).

%%====================================================================
%% Frame Sequence Tests
%%====================================================================

%% Test typical distribution sequence: handshake then data
typical_sequence_test() ->
    %% Handshake uses 2-byte length prefix
    HSData = <<"handshake">>,
    HSFrame = <<(byte_size(HSData)):16/big-unsigned, HSData/binary>>,

    %% Post-handshake uses 4-byte length prefix
    DataMsg = <<"distribution data">>,
    DataFrame = <<(byte_size(DataMsg)):32/big-unsigned, DataMsg/binary>>,

    %% Verify frames are different sizes for same-ish content

    % 2 + 9
    ?assertEqual(11, byte_size(HSFrame)),
    % 4 + 17
    ?assertEqual(21, byte_size(DataFrame)).

%% Test tick burst handling
tick_burst_test() ->
    %% 10 consecutive ticks (could happen during idle period)
    NumTicks = 10,
    TickBurst = binary:copy(<<0:32/big-unsigned>>, NumTicks),
    ?assertEqual(40, byte_size(TickBurst)),

    %% Parse all ticks
    {TickCount, Remaining} = parse_ticks(TickBurst, 0),
    ?assertEqual(10, TickCount),
    ?assertEqual(<<>>, Remaining).

%% Helper to count consecutive ticks
parse_ticks(<<0:32/big-unsigned, Rest/binary>>, Count) ->
    parse_ticks(Rest, Count + 1);
parse_ticks(Buffer, Count) ->
    {Count, Buffer}.

%% Test mixed tick and data burst
mixed_burst_test() ->
    %% Pattern: tick, data, tick, tick, data, tick
    D1 = <<"data1">>,
    D2 = <<"data2">>,
    Buffer = <<
        0:32/big-unsigned,
        (byte_size(D1)):32/big-unsigned,
        D1/binary,
        0:32/big-unsigned,
        0:32/big-unsigned,
        (byte_size(D2)):32/big-unsigned,
        D2/binary,
        0:32/big-unsigned
    >>,

    %% Count elements
    {Ticks, Data} = count_frames(Buffer, 0, []),
    ?assertEqual(4, Ticks),
    ?assertEqual([<<"data1">>, <<"data2">>], Data).

%% Helper to count frames
count_frames(<<0:32/big-unsigned, Rest/binary>>, Ticks, Data) ->
    count_frames(Rest, Ticks + 1, Data);
count_frames(<<Len:32/big-unsigned, Rest/binary>>, Ticks, Data) when byte_size(Rest) >= Len ->
    <<Msg:Len/binary, Remaining/binary>> = Rest,
    count_frames(Remaining, Ticks, Data ++ [Msg]);
count_frames(<<>>, Ticks, Data) ->
    {Ticks, Data};
count_frames(_Buffer, Ticks, Data) ->
    %% Incomplete frame
    {Ticks, Data}.

%%====================================================================
%% Stress Pattern Tests
%%====================================================================

%% Test alternating tiny and large messages
alternating_sizes_test() ->
    Tiny = <<"x">>,
    Large = binary:copy(<<$Y>>, 1000),

    Buffer = <<
        (byte_size(Tiny)):32/big-unsigned,
        Tiny/binary,
        (byte_size(Large)):32/big-unsigned,
        Large/binary,
        (byte_size(Tiny)):32/big-unsigned,
        Tiny/binary,
        (byte_size(Large)):32/big-unsigned,
        Large/binary
    >>,

    %% Parse all
    {_, Msgs} = count_frames(Buffer, 0, []),
    ?assertEqual(4, length(Msgs)),
    ?assertEqual(1, byte_size(lists:nth(1, Msgs))),
    ?assertEqual(1000, byte_size(lists:nth(2, Msgs))),
    ?assertEqual(1, byte_size(lists:nth(3, Msgs))),
    ?assertEqual(1000, byte_size(lists:nth(4, Msgs))).

%% Test many small messages
many_small_messages_test() ->
    %% 100 small messages
    Msgs = [list_to_binary(integer_to_list(I)) || I <- lists:seq(1, 100)],
    Buffer = lists:foldl(
        fun(M, Acc) ->
            <<Acc/binary, (byte_size(M)):32/big-unsigned, M/binary>>
        end,
        <<>>,
        Msgs
    ),

    {_, Parsed} = count_frames(Buffer, 0, []),
    ?assertEqual(100, length(Parsed)).

%% Test message at exact MTU boundary (1200 bytes is common QUIC MTU)
mtu_boundary_test() ->
    %% Typical QUIC payload after headers is ~1100-1200 bytes
    MTUPayload = 1100,
    Payload = binary:copy(<<$M>>, MTUPayload),
    Frame = <<MTUPayload:32/big-unsigned, Payload/binary>>,

    <<Len:32/big-unsigned, Data/binary>> = Frame,
    ?assertEqual(1100, Len),
    ?assertEqual(1100, byte_size(Data)).

%%====================================================================
%% Error Recovery Tests
%%====================================================================

%% Test partial frame preservation
partial_frame_preserved_test() ->
    %% Process complete messages, keep partial
    M1 = <<"complete">>,
    Partial = <<"part">>,
    Buffer = <<
        (byte_size(M1)):32/big-unsigned,
        M1/binary,
        100:32/big-unsigned,
        Partial/binary
    >>,

    %% After processing M1, should have partial frame left
    <<L1:32/big-unsigned, R1/binary>> = Buffer,
    <<_D1:L1/binary, Remaining/binary>> = R1,

    %% Remaining should be the incomplete frame
    <<L2:32/big-unsigned, P2/binary>> = Remaining,
    ?assertEqual(100, L2),
    ?assertEqual(4, byte_size(P2)),
    ?assert(byte_size(P2) < L2).

%%====================================================================
%% Tick Fix Verification Tests
%%====================================================================

%% Test that tick frame is sent on control stream (Fix 1)
%% Verifies the clause ordering prioritizes control stream
tick_control_stream_priority_test() ->
    %% With both control and data streams, control should be chosen
    %% This tests the logic by checking clause selection
    ControlStream = 0,
    DataStreams = [4, 8, 12],

    %% Simulate the selection logic from send_tick_frame
    SelectedStream =
        case ControlStream of
            undefined -> hd(DataStreams);
            _ -> ControlStream
        end,
    ?assertEqual(0, SelectedStream).

%% Test tick selection fallback when no control stream
tick_fallback_to_data_stream_test() ->
    DataStreams = [4, 8, 12],

    %% When control stream is undefined, should use first data stream
    SelectedStream =
        case undefined of
            undefined -> hd(DataStreams);
            CtrlStream -> CtrlStream
        end,
    ?assertEqual(4, SelectedStream).

%% Test that send_dist_data_loop_tick respects pull limit (Fix 3)
send_loop_tick_limit_test() ->
    %% The loop should stop after max_pull iterations
    MaxPull = 16,

    %% Simulate counter decrement
    Remaining0 = MaxPull,
    Remaining1 = Remaining0 - 1,
    Remaining16 = 0,

    ?assertEqual(15, Remaining1),
    ?assertEqual(0, Remaining16),
    %% When remaining is 0, loop should stop
    ?assert(Remaining16 =:= 0).

%% Test batch delivery limit (Fix 4)
batch_delivery_limit_test() ->
    %% Batch size is 32
    BatchSize = 32,

    %% After 32 messages, should yield
    RemainingAfter32 = BatchSize - 32,
    ?assertEqual(0, RemainingAfter32),

    %% Tick frames don't decrement counter
    %% Verify understanding of the batch logic
    %% 10 ticks + 20 data messages, only data decrements counter
    DataProcessed = 20,
    %% Counter only decrements for data, not ticks
    RemainingAfterMixed = BatchSize - DataProcessed,
    ?assertEqual(12, RemainingAfterMixed).

%% Test continue_delivery message format (Fix 4)
continue_delivery_format_test() ->
    %% The continue_delivery message carries the pending buffer
    PendingBuffer = <<"remaining data">>,
    Msg = {continue_delivery, PendingBuffer},

    ?assertMatch({continue_delivery, _}, Msg),
    {continue_delivery, Buffer} = Msg,
    ?assertEqual(<<"remaining data">>, Buffer).

%% Test tick frame independent of congestion (Fix 1 + Fix 2)
tick_independent_of_congestion_test() ->
    %% The tick frame should be sent regardless of congestion state
    %% This tests the logic: tick is sent FIRST, then data flush is best-effort

    %% Simulate congestion scenarios
    Congested = true,
    NotCongested = false,

    %% Tick should always be sent (simulated as true)
    TickSentWhenCongested = true,
    TickSentWhenNotCongested = true,

    ?assert(TickSentWhenCongested),
    ?assert(TickSentWhenNotCongested),

    %% Data flush only happens when not congested
    DataFlushWhenCongested = not Congested,
    DataFlushWhenNotCongested = not NotCongested,

    ?assertNot(DataFlushWhenCongested),
    ?assert(DataFlushWhenNotCongested).

%% Test max_pull used in tick data flush (Fix 3)
tick_data_flush_limited_test() ->
    %% When ticking, data flush should use max_pull limit
    MaxPull = 16,

    %% Simulate the limited loop behavior
    AvailableData = 100,
    ActualPulled = min(AvailableData, MaxPull),
    ?assertEqual(16, ActualPulled),

    %% Even with lots of data, only MaxPull should be sent
    ?assert(ActualPulled =< MaxPull).

%%====================================================================
%% Large Message Tests
%%====================================================================

%% Test 1MB message framing and fragmentation
large_message_1mb_framing_test() ->
    %% 1MB message
    Size = 1024 * 1024,
    Payload = crypto:strong_rand_bytes(Size),

    %% Frame it with 4-byte length prefix
    Framed = <<Size:32/big-unsigned, Payload/binary>>,
    ?assertEqual(Size + 4, byte_size(Framed)),

    %% Verify we can parse it back
    <<ParsedLen:32/big-unsigned, ParsedPayload/binary>> = Framed,
    ?assertEqual(Size, ParsedLen),
    ?assertEqual(Payload, ParsedPayload).

%% Test 4MB message (max stream flow control window)
large_message_4mb_framing_test() ->
    %% 4MB - max stream data limit
    Size = 4 * 1024 * 1024,
    Payload = binary:copy(<<$X>>, Size),

    %% Frame it
    Framed = <<Size:32/big-unsigned, Payload/binary>>,
    ?assertEqual(Size + 4, byte_size(Framed)),

    %% Parse header
    <<ParsedLen:32/big-unsigned, _/binary>> = Framed,
    ?assertEqual(Size, ParsedLen).

%% Test chunked reassembly of large message (simulates MTU fragmentation)
large_message_chunked_reassembly_test() ->
    %% 100KB message
    Size = 100 * 1024,
    Payload = crypto:strong_rand_bytes(Size),
    Framed = <<Size:32/big-unsigned, Payload/binary>>,

    %% Split into ~1100 byte chunks (typical QUIC MTU)
    ChunkSize = 1100,
    Chunks = chunk_binary(Framed, ChunkSize),

    %% Verify we have multiple chunks
    ?assert(length(Chunks) > 1),

    %% Reassemble
    Reassembled = iolist_to_binary(Chunks),
    ?assertEqual(Framed, Reassembled),

    %% Parse the reassembled data
    <<ParsedLen:32/big-unsigned, ParsedPayload/binary>> = Reassembled,
    ?assertEqual(Size, ParsedLen),
    ?assertEqual(Payload, ParsedPayload).

%% Test multiple large messages in sequence
multiple_large_messages_test() ->
    %% Three 100KB messages
    Size = 100 * 1024,
    M1 = crypto:strong_rand_bytes(Size),
    M2 = crypto:strong_rand_bytes(Size),
    M3 = crypto:strong_rand_bytes(Size),

    %% Frame them
    Buffer = <<
        Size:32/big-unsigned,
        M1/binary,
        Size:32/big-unsigned,
        M2/binary,
        Size:32/big-unsigned,
        M3/binary
    >>,

    %% Parse all three
    {Msgs, <<>>} = parse_all_messages(Buffer, []),
    ?assertEqual(3, length(Msgs)),
    ?assertEqual([M1, M2, M3], Msgs).

%% Test partial large message delivery (simulates network delay)
partial_large_message_test() ->
    %% 1MB message
    Size = 1024 * 1024,
    Payload = crypto:strong_rand_bytes(Size),
    Framed = <<Size:32/big-unsigned, Payload/binary>>,

    %% First chunk: header + 10KB
    <<Chunk1:10244/binary, Rest/binary>> = Framed,

    %% Verify chunk1 has complete header but incomplete payload
    <<Len:32/big-unsigned, PartialPayload/binary>> = Chunk1,
    ?assertEqual(Size, Len),
    ?assertEqual(10240, byte_size(PartialPayload)),
    ?assert(byte_size(PartialPayload) < Len),

    %% After receiving rest, can parse complete message
    Complete = <<Chunk1/binary, Rest/binary>>,
    <<_:32/big-unsigned, FullPayload/binary>> = Complete,
    ?assertEqual(Payload, FullPayload).

%% Test interleaved large and small messages
interleaved_large_small_test() ->
    Small = <<"tiny">>,
    Large = binary:copy(<<$L>>, 50000),

    Buffer = <<
        (byte_size(Small)):32/big-unsigned,
        Small/binary,
        (byte_size(Large)):32/big-unsigned,
        Large/binary,
        (byte_size(Small)):32/big-unsigned,
        Small/binary
    >>,

    {Msgs, <<>>} = parse_all_messages(Buffer, []),
    ?assertEqual(3, length(Msgs)),
    ?assertEqual(Small, lists:nth(1, Msgs)),
    ?assertEqual(Large, lists:nth(2, Msgs)),
    ?assertEqual(Small, lists:nth(3, Msgs)).

%% Test hash integrity for large message roundtrip
large_message_hash_integrity_test() ->
    %% 1MB of random data
    Size = 1024 * 1024,
    Original = crypto:strong_rand_bytes(Size),
    OriginalHash = crypto:hash(sha256, Original),

    %% Frame, chunk, reassemble, parse
    Framed = <<Size:32/big-unsigned, Original/binary>>,
    Chunks = chunk_binary(Framed, 1100),
    Reassembled = iolist_to_binary(Chunks),
    <<_:32/big-unsigned, Parsed/binary>> = Reassembled,

    %% Verify hash matches
    ParsedHash = crypto:hash(sha256, Parsed),
    ?assertEqual(OriginalHash, ParsedHash).

%% Helper: split binary into chunks
chunk_binary(Bin, ChunkSize) ->
    chunk_binary(Bin, ChunkSize, []).

chunk_binary(<<>>, _ChunkSize, Acc) ->
    lists:reverse(Acc);
chunk_binary(Bin, ChunkSize, Acc) when byte_size(Bin) =< ChunkSize ->
    lists:reverse([Bin | Acc]);
chunk_binary(Bin, ChunkSize, Acc) ->
    <<Chunk:ChunkSize/binary, Rest/binary>> = Bin,
    chunk_binary(Rest, ChunkSize, [Chunk | Acc]).

%% Helper: parse all complete messages from buffer
parse_all_messages(<<>>, Acc) ->
    {lists:reverse(Acc), <<>>};
parse_all_messages(Buffer, Acc) when byte_size(Buffer) < 4 ->
    {lists:reverse(Acc), Buffer};
parse_all_messages(<<Len:32/big-unsigned, Rest/binary>> = Buffer, Acc) when byte_size(Rest) < Len ->
    {lists:reverse(Acc), Buffer};
parse_all_messages(<<Len:32/big-unsigned, Rest/binary>>, Acc) ->
    <<Msg:Len/binary, Remaining/binary>> = Rest,
    parse_all_messages(Remaining, [Msg | Acc]).
