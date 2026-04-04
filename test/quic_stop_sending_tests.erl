%%% -*- erlang -*-
%%%
%%% Tests for QUIC STOP_SENDING API
%%% RFC 9000 Section 19.5
%%%

-module(quic_stop_sending_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% API Tests
%%====================================================================

%% Test that stop_sending in idle state returns invalid_state error
stop_sending_idle_state_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),

    %% Connection is in idle state (not connected yet)
    {State, _} = quic_connection:get_state(Pid),
    ?assertEqual(idle, State),

    %% stop_sending should fail because we're not in connected state
    Result = quic_connection:stop_sending(Pid, 0, 0),
    ?assertEqual({error, {invalid_state, idle}}, Result),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%% Test that stop_sending API accepts pid
stop_sending_with_pid_test() ->
    {ok, Pid} = quic_connection:start_link("127.0.0.1", 4433, #{}, self()),

    %% Connection is in idle state
    Result = quic:stop_sending(Pid, 0, 0),
    ?assertEqual({error, {invalid_state, idle}}, Result),

    quic_connection:close(Pid, normal),
    timer:sleep(100).

%%====================================================================
%% Frame Encoding Tests
%%====================================================================

%% Verify STOP_SENDING frame encoding
stop_sending_frame_encode_test() ->
    StreamId = 4,
    ErrorCode = 256,

    Frame = {stop_sending, StreamId, ErrorCode},
    Encoded = quic_frame:encode(Frame),

    %% Frame type should be 0x05
    ?assertMatch(<<5, _/binary>>, Encoded),

    %% Should roundtrip correctly
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%% Test various stream IDs and error codes
stop_sending_frame_values_test() ->
    TestCases = [
        {0, 0},
        {1, 1},
        {100, 500},
        % Large varint values
        {16#3FFFFFFF, 16#3FFFFFFF}
    ],

    lists:foreach(
        fun({StreamId, ErrorCode}) ->
            Frame = {stop_sending, StreamId, ErrorCode},
            Encoded = quic_frame:encode(Frame),
            {Decoded, <<>>} = quic_frame:decode(Encoded),
            ?assertEqual(Frame, Decoded)
        end,
        TestCases
    ).

%%====================================================================
%% quic_stream Module Integration Tests
%%====================================================================

%% Test that quic_stream:stop_sending clears send buffer
stream_stop_sending_clears_buffer_test() ->
    Stream = quic_stream:new(0, client),
    {ok, S1} = quic_stream:send(Stream, <<"pending data">>),
    ?assert(quic_stream:bytes_to_send(S1) > 0),

    %% stop_sending should clear send buffer
    S2 = quic_stream:stop_sending(S1, 0),
    ?assertEqual(0, quic_stream:bytes_to_send(S2)).

%% Test stop_sending on empty stream
stream_stop_sending_empty_test() ->
    Stream = quic_stream:new(0, client),
    S1 = quic_stream:stop_sending(Stream, 42),
    ?assertEqual(0, quic_stream:bytes_to_send(S1)).

%% Test stop_sending with different error codes
stream_stop_sending_error_codes_test() ->
    Stream = quic_stream:new(4, server),
    {ok, S1} = quic_stream:send(Stream, <<"data">>),

    %% Various error codes should all clear the buffer
    lists:foreach(
        fun(ErrorCode) ->
            S2 = quic_stream:stop_sending(S1, ErrorCode),
            ?assertEqual(0, quic_stream:bytes_to_send(S2))
        end,
        [0, 1, 256, 16#FFFFFFFF]
    ).

%%====================================================================
%% Protocol Compliance Tests (RFC 9000 Section 19.5)
%%====================================================================

%% Verify STOP_SENDING frame type is 0x05
stop_sending_frame_type_test() ->
    Frame = {stop_sending, 0, 0},
    <<Type, _/binary>> = quic_frame:encode(Frame),
    ?assertEqual(5, Type).

%% Test that STOP_SENDING uses varint encoding for StreamId and ErrorCode
stop_sending_varint_encoding_test() ->
    %% Small values (1-byte varint, values 0-63)
    Frame1 = {stop_sending, 0, 0},
    Encoded1 = quic_frame:encode(Frame1),
    % 1 type + 1 stream_id + 1 error_code
    ?assertEqual(3, byte_size(Encoded1)),

    %% Values 0-63 fit in 1 byte
    Frame2 = {stop_sending, 63, 63},
    Encoded2 = quic_frame:encode(Frame2),
    % 1 type + 1 stream_id + 1 error_code
    ?assertEqual(3, byte_size(Encoded2)),

    %% Values 64-16383 require 2-byte varint
    Frame3 = {stop_sending, 1000, 2000},
    Encoded3 = quic_frame:encode(Frame3),
    % 1 type + 2 stream_id + 2 error_code
    ?assertEqual(5, byte_size(Encoded3)).
