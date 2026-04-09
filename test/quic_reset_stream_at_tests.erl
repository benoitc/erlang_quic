%%% -*- erlang -*-
%%%
%%% RESET_STREAM_AT Extension Tests (draft-ietf-quic-reliable-stream-reset-07)
%%%

-module(quic_reset_stream_at_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Frame Encoding/Decoding Tests
%%====================================================================

encode_decode_basic_test() ->
    Frame = {reset_stream_at, 4, 16#100, 1000, 500},
    Encoded = quic_frame:encode(Frame),
    %% Verify frame type is 0x24
    <<?FRAME_RESET_STREAM_AT, _/binary>> = Encoded,
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

encode_decode_zero_reliable_size_test() ->
    %% ReliableSize=0 is equivalent to RESET_STREAM per spec
    Frame = {reset_stream_at, 0, 0, 100, 0},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

encode_decode_reliable_equals_final_test() ->
    %% ReliableSize == FinalSize means all data must be delivered
    Frame = {reset_stream_at, 1, 0, 1000, 1000},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

encode_decode_large_values_test() ->
    %% Test with large varint values
    Frame = {reset_stream_at, 16#3FFFFFFF, 16#3FFFFFFF, 16#3FFFFFFFFFFFFFFF, 16#1FFFFFFFFFFFFFFF},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

encode_decode_roundtrip_test() ->
    %% Test various value combinations
    TestCases = [
        {reset_stream_at, 0, 0, 0, 0},
        {reset_stream_at, 1, 1, 1, 0},
        {reset_stream_at, 1, 1, 1, 1},
        {reset_stream_at, 63, 63, 16383, 8192},
        {reset_stream_at, 16383, 1073741823, 4611686018427387903, 100}
    ],
    lists:foreach(
        fun(Frame) ->
            Encoded = quic_frame:encode(Frame),
            {Decoded, <<>>} = quic_frame:decode(Encoded),
            ?assertEqual(Frame, Decoded)
        end,
        TestCases
    ).

%%====================================================================
%% Transport Parameter Tests
%%====================================================================

transport_param_encode_decode_test() ->
    Params = #{reset_stream_at => true},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(true, maps:get(reset_stream_at, Decoded)).

transport_param_with_other_params_test() ->
    Params = #{
        reset_stream_at => true,
        initial_max_data => 1048576,
        initial_max_streams_bidi => 100
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(true, maps:get(reset_stream_at, Decoded)),
    ?assertEqual(1048576, maps:get(initial_max_data, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)).

transport_param_absent_test() ->
    Params = #{initial_max_data => 1048576},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(false, maps:get(reset_stream_at, Decoded, false)).

%%====================================================================
%% Buffer Truncation Tests
%%====================================================================

truncate_buffer_test() ->
    %% Create a mock buffer with chunks at various offsets
    Buffer = [
        {0, <<"chunk0">>},
        {50, <<"chunk50">>},
        {100, <<"chunk100">>},
        {150, <<"chunk150">>}
    ],
    %% Truncate to ReliableSize=100 should keep chunks starting before 100
    Truncated = truncate_send_buffer(Buffer, 100),
    ?assertEqual(2, length(Truncated)),
    ?assert(lists:member({0, <<"chunk0">>}, Truncated)),
    ?assert(lists:member({50, <<"chunk50">>}, Truncated)).

truncate_buffer_empty_test() ->
    ?assertEqual([], truncate_send_buffer([], 100)).

truncate_buffer_all_kept_test() ->
    Buffer = [{0, <<"data">>}, {10, <<"more">>}],
    ?assertEqual(Buffer, truncate_send_buffer(Buffer, 1000)).

truncate_buffer_none_kept_test() ->
    Buffer = [{100, <<"data">>}, {200, <<"more">>}],
    ?assertEqual([], truncate_send_buffer(Buffer, 50)).

%%====================================================================
%% Helper - mirrors quic_connection:truncate_send_buffer/2
%%====================================================================

truncate_send_buffer(Buffer, ReliableSize) when is_list(Buffer) ->
    lists:filter(
        fun({Offset, _Data}) ->
            Offset < ReliableSize
        end,
        Buffer
    );
truncate_send_buffer(Buffer, _ReliableSize) ->
    Buffer.
