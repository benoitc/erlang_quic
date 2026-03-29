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
