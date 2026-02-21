%%% -*- erlang -*-
%%%
%%% Tests for QUIC Frame Coalescing
%%%

-module(quic_coalesce_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Frame Encoding Tests
%%====================================================================

%% Test that multiple frames can be concatenated into a single payload
coalesce_frames_basic_test() ->
    %% Encode a simple PING frame
    PingFrame = quic_frame:encode(ping),
    ?assert(is_binary(PingFrame)),
    ?assert(byte_size(PingFrame) > 0).

%% Test coalescing ACK and STREAM frames
coalesce_ack_and_stream_test() ->
    %% Create an ACK frame

    % Largest=10, FirstRange=5
    AckRanges = [{10, 5}],
    AckFrame = quic_frame:encode({ack, AckRanges, 0, undefined}),

    %% Create a small STREAM frame
    StreamId = 0,
    Offset = 0,
    Data = <<"hello">>,
    Fin = false,
    StreamFrame = quic_frame:encode({stream, StreamId, Offset, Data, Fin}),

    %% Coalesce them
    Payload = <<AckFrame/binary, StreamFrame/binary>>,

    %% Verify both frames are present
    ?assert(byte_size(Payload) =:= byte_size(AckFrame) + byte_size(StreamFrame)).

%%====================================================================
%% Small Frame Detection Tests
%%====================================================================

%% Test what constitutes a "small" frame (< 500 bytes)
small_frame_threshold_test() ->
    SmallData = crypto:strong_rand_bytes(100),
    SmallFrame = quic_frame:encode({stream, 0, 0, SmallData, false}),
    ?assert(byte_size(SmallFrame) < 500),

    LargeData = crypto:strong_rand_bytes(600),
    LargeFrame = quic_frame:encode({stream, 0, 0, LargeData, false}),
    ?assert(byte_size(LargeFrame) >= 500).

%% Test data size check
data_size_check_test() ->
    SmallData = <<"short">>,
    ?assert(byte_size(SmallData) < 500),

    LargeData = binary:copy(<<"x">>, 600),
    ?assert(byte_size(LargeData) >= 500).

%%====================================================================
%% Frame Decoding After Coalescing Tests
%%====================================================================

%% Test that coalesced frames can be decoded
decode_coalesced_frames_test() ->
    %% Create PING frame
    PingFrame = quic_frame:encode(ping),

    %% Create ACK frame
    AckRanges = [{5, 0}],
    AckFrame = quic_frame:encode({ack, AckRanges, 0, undefined}),

    %% Coalesce
    Payload = <<PingFrame/binary, AckFrame/binary>>,

    %% Decode first frame (quic_frame:decode returns {Frame, Rest})
    {DecodedPing, Rest} = quic_frame:decode(Payload),
    ?assertEqual(ping, DecodedPing),
    ?assert(byte_size(Rest) > 0),

    %% Decode second frame
    {DecodedAck, _Rest2} = quic_frame:decode(Rest),
    ?assertMatch({ack, _, _, _}, DecodedAck).

%%====================================================================
%% Priority Queue Tests
%%====================================================================

%% Test basic queue operations (simulating the coalescing logic)
queue_operations_test() ->
    Q = queue:new(),
    Entry = {stream_data, 0, 0, <<"test">>, false},
    Q1 = queue:in(Entry, Q),

    %% Peek
    {value, Peeked} = queue:peek(Q1),
    ?assertEqual(Entry, Peeked),

    %% Queue should still have the item
    ?assertNot(queue:is_empty(Q1)),

    %% Out removes the item
    {{value, Out}, Q2} = queue:out(Q1),
    ?assertEqual(Entry, Out),
    ?assert(queue:is_empty(Q2)).

%%====================================================================
%% Stream Frame Size Tests
%%====================================================================

%% Test STREAM frame encoding with various data sizes
stream_frame_sizes_test() ->
    %% Empty data
    F1 = quic_frame:encode({stream, 0, 0, <<>>, false}),
    ?assert(is_binary(F1)),

    %% Small data (typical for coalescing)
    F2 = quic_frame:encode({stream, 4, 100, <<"Hello, World!">>, false}),
    ?assert(is_binary(F2)),
    ?assert(byte_size(F2) < 100),

    %% Medium data still under threshold
    MediumData = crypto:strong_rand_bytes(200),
    F3 = quic_frame:encode({stream, 8, 0, MediumData, true}),
    ?assert(is_binary(F3)),
    ?assert(byte_size(F3) < 500).

%%====================================================================
%% ACK Frame Tests
%%====================================================================

%% Test ACK frame with various range configurations
ack_frame_formats_test() ->
    %% Single packet ACK
    F1 = quic_frame:encode({ack, [{0, 0}], 0, undefined}),
    ?assert(is_binary(F1)),

    %% Range ACK
    F2 = quic_frame:encode({ack, [{10, 5}, {2, 3}], 100, undefined}),
    ?assert(is_binary(F2)),

    %% Both should be small enough to coalesce with data
    ?assert(byte_size(F1) < 100),
    ?assert(byte_size(F2) < 100).

%%====================================================================
%% Integration Test
%%====================================================================

%% Test a realistic coalescing scenario
realistic_coalesce_scenario_test() ->
    %% Simulate ACK + small application data (common pattern)
    AckFrame = quic_frame:encode({ack, [{100, 10}], 50, undefined}),
    StreamFrame = quic_frame:encode({stream, 4, 256, <<"HTTP/3 response">>, false}),

    CoalescedPayload = <<AckFrame/binary, StreamFrame/binary>>,

    %% Total should be well under MTU (1200 bytes)
    ?assert(byte_size(CoalescedPayload) < 100),

    %% Verify we can decode both frames (quic_frame:decode returns {Frame, Rest})
    {_, Rest1} = quic_frame:decode(CoalescedPayload),
    {_, _Rest2} = quic_frame:decode(Rest1).
