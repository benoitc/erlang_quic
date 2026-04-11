%%% -*- erlang -*-
%%%
%%% Unit tests for HTTP/3 frame encoding/decoding (RFC 9114)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_h3_frame_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% DATA Frame Tests
%%====================================================================

encode_decode_data_test() ->
    Payload = <<"Hello, HTTP/3!">>,
    Encoded = quic_h3_frame:encode_data(Payload),
    ?assertMatch({ok, {data, Payload}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_data_empty_test() ->
    Payload = <<>>,
    Encoded = quic_h3_frame:encode_data(Payload),
    ?assertMatch({ok, {data, <<>>}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_data_large_test() ->
    Payload = binary:copy(<<"x">>, 16384),
    Encoded = quic_h3_frame:encode_data(Payload),
    {ok, {data, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(Payload, Decoded).

%%====================================================================
%% HEADERS Frame Tests
%%====================================================================

encode_decode_headers_test() ->
    % QPACK encoded headers
    HeaderBlock = <<16#00, 16#00, 16#d1, 16#d7>>,
    Encoded = quic_h3_frame:encode_headers(HeaderBlock),
    ?assertMatch({ok, {headers, HeaderBlock}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_headers_empty_test() ->
    HeaderBlock = <<>>,
    Encoded = quic_h3_frame:encode_headers(HeaderBlock),
    ?assertMatch({ok, {headers, <<>>}, <<>>}, quic_h3_frame:decode(Encoded)).

%%====================================================================
%% SETTINGS Frame Tests
%%====================================================================

encode_decode_settings_test() ->
    Settings = #{
        qpack_max_table_capacity => 4096,
        max_field_section_size => 8192,
        qpack_blocked_streams => 100
    },
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, DecodedSettings}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, DecodedSettings)),
    ?assertEqual(8192, maps:get(max_field_section_size, DecodedSettings)),
    ?assertEqual(100, maps:get(qpack_blocked_streams, DecodedSettings)).

encode_decode_settings_empty_test() ->
    Settings = #{},
    Encoded = quic_h3_frame:encode_settings(Settings),
    ?assertMatch({ok, {settings, #{}}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_settings_connect_protocol_test() ->
    Settings = #{enable_connect_protocol => 1},
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, DecodedSettings}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(1, maps:get(enable_connect_protocol, DecodedSettings)).

default_settings_test() ->
    Settings = quic_h3_frame:default_settings(),
    ?assertEqual(0, maps:get(qpack_max_table_capacity, Settings)),
    ?assertEqual(65536, maps:get(max_field_section_size, Settings)),
    ?assertEqual(0, maps:get(qpack_blocked_streams, Settings)),
    ?assertEqual(0, maps:get(enable_connect_protocol, Settings)).

settings_payload_test() ->
    Settings = #{qpack_max_table_capacity => 1024},
    Payload = quic_h3_frame:encode_settings_payload(Settings),
    {ok, DecodedSettings} = quic_h3_frame:decode_settings_payload(Payload),
    ?assertEqual(1024, maps:get(qpack_max_table_capacity, DecodedSettings)).

%%====================================================================
%% GOAWAY Frame Tests
%%====================================================================

encode_decode_goaway_test() ->
    StreamId = 4,
    Encoded = quic_h3_frame:encode_goaway(StreamId),
    ?assertMatch({ok, {goaway, 4}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_goaway_zero_test() ->
    StreamId = 0,
    Encoded = quic_h3_frame:encode_goaway(StreamId),
    ?assertMatch({ok, {goaway, 0}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_goaway_large_test() ->
    StreamId = 16#FFFFFFFF,
    Encoded = quic_h3_frame:encode_goaway(StreamId),
    ?assertMatch({ok, {goaway, 16#FFFFFFFF}, <<>>}, quic_h3_frame:decode(Encoded)).

%%====================================================================
%% MAX_PUSH_ID Frame Tests
%%====================================================================

encode_decode_max_push_id_test() ->
    PushId = 15,
    Encoded = quic_h3_frame:encode_max_push_id(PushId),
    ?assertMatch({ok, {max_push_id, 15}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_decode_max_push_id_zero_test() ->
    PushId = 0,
    Encoded = quic_h3_frame:encode_max_push_id(PushId),
    ?assertMatch({ok, {max_push_id, 0}, <<>>}, quic_h3_frame:decode(Encoded)).

%%====================================================================
%% CANCEL_PUSH Frame Tests
%%====================================================================

encode_decode_cancel_push_test() ->
    PushId = 42,
    Encoded = quic_h3_frame:encode_cancel_push(PushId),
    ?assertMatch({ok, {cancel_push, 42}, <<>>}, quic_h3_frame:decode(Encoded)).

%%====================================================================
%% PUSH_PROMISE Frame Tests
%%====================================================================

encode_decode_push_promise_test() ->
    PushId = 7,
    HeaderBlock = <<16#00, 16#00, 16#d1>>,
    Encoded = quic_h3_frame:encode_push_promise(PushId, HeaderBlock),
    {ok, {push_promise, DecodedPushId, DecodedHeaderBlock}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(7, DecodedPushId),
    ?assertEqual(HeaderBlock, DecodedHeaderBlock).

%%====================================================================
%% Generic encode/1 Tests
%%====================================================================

encode_generic_data_test() ->
    Frame = {data, <<"test">>},
    Encoded = quic_h3_frame:encode(Frame),
    ?assertMatch({ok, {data, <<"test">>}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_generic_headers_test() ->
    Frame = {headers, <<1, 2, 3>>},
    Encoded = quic_h3_frame:encode(Frame),
    ?assertMatch({ok, {headers, <<1, 2, 3>>}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_generic_settings_test() ->
    Frame = {settings, #{qpack_blocked_streams => 50}},
    Encoded = quic_h3_frame:encode(Frame),
    {ok, {settings, Settings}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(50, maps:get(qpack_blocked_streams, Settings)).

encode_generic_goaway_test() ->
    Frame = {goaway, 100},
    Encoded = quic_h3_frame:encode(Frame),
    ?assertMatch({ok, {goaway, 100}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_generic_max_push_id_test() ->
    Frame = {max_push_id, 200},
    Encoded = quic_h3_frame:encode(Frame),
    ?assertMatch({ok, {max_push_id, 200}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_generic_cancel_push_test() ->
    Frame = {cancel_push, 5},
    Encoded = quic_h3_frame:encode(Frame),
    ?assertMatch({ok, {cancel_push, 5}, <<>>}, quic_h3_frame:decode(Encoded)).

encode_generic_push_promise_test() ->
    Frame = {push_promise, 3, <<"header_block">>},
    Encoded = quic_h3_frame:encode(Frame),
    ?assertMatch({ok, {push_promise, 3, <<"header_block">>}, <<>>}, quic_h3_frame:decode(Encoded)).

%%====================================================================
%% Unknown/Reserved Frame Tests
%%====================================================================

decode_unknown_frame_test() ->
    %% Type 0x02 is not defined in HTTP/3 (was used in HTTP/2)
    Type = 16#02,
    Payload = <<"unknown">>,
    TypeEnc = quic_varint:encode(Type),
    LenEnc = quic_varint:encode(byte_size(Payload)),
    Encoded = <<TypeEnc/binary, LenEnc/binary, Payload/binary>>,
    ?assertMatch({ok, {unknown, 16#02, <<"unknown">>}, <<>>}, quic_h3_frame:decode(Encoded)).

decode_reserved_frame_test() ->
    %% Reserved frame type: 0x1f * N + 0x21
    %% For N=0: 0x21 (33)
    Type = 16#21,
    Payload = <<"grease">>,
    TypeEnc = quic_varint:encode(Type),
    LenEnc = quic_varint:encode(byte_size(Payload)),
    Encoded = <<TypeEnc/binary, LenEnc/binary, Payload/binary>>,
    %% Reserved frames should be decoded as unknown
    ?assertMatch({ok, {unknown, 16#21, <<"grease">>}, <<>>}, quic_h3_frame:decode(Encoded)).

is_reserved_frame_type_test() ->
    %% 0x1f * N + 0x21 for N = 0, 1, 2, ...

    % N=0
    ?assert(quic_h3_frame:is_reserved_frame_type(16#21)),
    % N=1
    ?assert(quic_h3_frame:is_reserved_frame_type(16#40)),
    % N=2
    ?assert(quic_h3_frame:is_reserved_frame_type(16#5F)),
    % DATA
    ?assertNot(quic_h3_frame:is_reserved_frame_type(16#00)),
    % HEADERS
    ?assertNot(quic_h3_frame:is_reserved_frame_type(16#01)),
    % SETTINGS
    ?assertNot(quic_h3_frame:is_reserved_frame_type(16#04)).

is_reserved_setting_test() ->
    %% 0x1f * N + 0x21 for N = 0, 1, 2, ...
    ?assert(quic_h3_frame:is_reserved_setting(16#21)),
    ?assert(quic_h3_frame:is_reserved_setting(16#40)),
    % QPACK_MAX_TABLE_CAPACITY
    ?assertNot(quic_h3_frame:is_reserved_setting(16#01)),
    % MAX_FIELD_SECTION_SIZE
    ?assertNot(quic_h3_frame:is_reserved_setting(16#06)),
    % QPACK_BLOCKED_STREAMS
    ?assertNot(quic_h3_frame:is_reserved_setting(16#07)).

%%====================================================================
%% Partial Frame Tests
%%====================================================================

decode_partial_frame_test() ->
    %% Only 1 byte - need at least 2
    ?assertMatch({more, _}, quic_h3_frame:decode(<<>>)),
    ?assertMatch({more, _}, quic_h3_frame:decode(<<0>>)).

decode_partial_frame_incomplete_length_test() ->
    %% Type byte but incomplete length
    %% DATA frame type (0x00) with incomplete varint length
    ?assertMatch({more, _}, quic_h3_frame:decode(<<0, 16#C0>>)).

decode_partial_frame_incomplete_payload_test() ->
    %% Complete header but incomplete payload
    %% DATA frame with length 10 but only 3 bytes of payload
    Encoded = <<0, 10, "abc">>,
    ?assertMatch({more, 7}, quic_h3_frame:decode(Encoded)).

%%====================================================================
%% decode_all Tests
%%====================================================================

decode_all_empty_test() ->
    ?assertMatch({ok, [], <<>>}, quic_h3_frame:decode_all(<<>>)).

decode_all_single_test() ->
    Encoded = quic_h3_frame:encode_data(<<"test">>),
    {ok, [Frame], <<>>} = quic_h3_frame:decode_all(Encoded),
    ?assertMatch({data, <<"test">>}, Frame).

decode_all_multiple_test() ->
    Frame1 = quic_h3_frame:encode_data(<<"data1">>),
    Frame2 = quic_h3_frame:encode_headers(<<"headers">>),
    Frame3 = quic_h3_frame:encode_goaway(0),
    Combined = <<Frame1/binary, Frame2/binary, Frame3/binary>>,
    {ok, Frames, <<>>} = quic_h3_frame:decode_all(Combined),
    ?assertEqual(3, length(Frames)),
    ?assertMatch([{data, <<"data1">>}, {headers, <<"headers">>}, {goaway, 0}], Frames).

decode_all_with_remainder_test() ->
    Frame1 = quic_h3_frame:encode_data(<<"complete">>),
    % Incomplete DATA frame
    Partial = <<0, 10, "abc">>,
    Combined = <<Frame1/binary, Partial/binary>>,
    {ok, Frames, Remainder} = quic_h3_frame:decode_all(Combined),
    ?assertEqual(1, length(Frames)),
    ?assertMatch({data, <<"complete">>}, hd(Frames)),
    ?assertEqual(Partial, Remainder).

%%====================================================================
%% Stream Type Tests
%%====================================================================

encode_stream_type_test() ->
    ?assertEqual(<<0>>, quic_h3_frame:encode_stream_type(control)),
    ?assertEqual(<<1>>, quic_h3_frame:encode_stream_type(push)),
    ?assertEqual(<<2>>, quic_h3_frame:encode_stream_type(qpack_encoder)),
    ?assertEqual(<<3>>, quic_h3_frame:encode_stream_type(qpack_decoder)).

encode_stream_type_integer_test() ->
    %% QUIC varint uses 8-byte encoding for values >= 2^30
    ?assertEqual(
        <<192, 0, 0, 0, 255, 255, 255, 255>>,
        quic_h3_frame:encode_stream_type(16#FFFFFFFF)
    ).

decode_stream_type_test() ->
    ?assertMatch({ok, control, <<>>}, quic_h3_frame:decode_stream_type(<<0>>)),
    ?assertMatch({ok, push, <<>>}, quic_h3_frame:decode_stream_type(<<1>>)),
    ?assertMatch({ok, qpack_encoder, <<>>}, quic_h3_frame:decode_stream_type(<<2>>)),
    ?assertMatch({ok, qpack_decoder, <<>>}, quic_h3_frame:decode_stream_type(<<3>>)).

decode_stream_type_unknown_test() ->
    ?assertMatch({ok, {unknown, 16#FF}, <<>>}, quic_h3_frame:decode_stream_type(<<16#40, 16#FF>>)).

decode_stream_type_with_remainder_test() ->
    ?assertMatch({ok, control, <<"extra">>}, quic_h3_frame:decode_stream_type(<<0, "extra">>)).

decode_stream_type_empty_test() ->
    ?assertMatch({more, 1}, quic_h3_frame:decode_stream_type(<<>>)).

%%====================================================================
%% Settings Validation Tests (inspired by quiche)
%%====================================================================

%% Test single setting (like quiche settings_h3_only)
settings_single_max_field_section_test() ->
    Settings = #{max_field_section_size => 1024},
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(1024, maps:get(max_field_section_size, Decoded)).

%% Test QPACK-only settings (like quiche settings_qpack_only)
settings_qpack_only_test() ->
    Settings = #{
        qpack_max_table_capacity => 4096,
        qpack_blocked_streams => 16
    },
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, Decoded)),
    ?assertEqual(16, maps:get(qpack_blocked_streams, Decoded)).

%% Test all standard settings (like quiche settings_all_no_grease)
settings_all_standard_test() ->
    Settings = #{
        qpack_max_table_capacity => 4096,
        max_field_section_size => 16384,
        qpack_blocked_streams => 100,
        enable_connect_protocol => 1
    },
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(4096, maps:get(qpack_max_table_capacity, Decoded)),
    ?assertEqual(16384, maps:get(max_field_section_size, Decoded)),
    ?assertEqual(100, maps:get(qpack_blocked_streams, Decoded)),
    ?assertEqual(1, maps:get(enable_connect_protocol, Decoded)).

%% Test ENABLE_CONNECT_PROTOCOL with valid value (like quiche)
settings_connect_protocol_enabled_test() ->
    Settings = #{enable_connect_protocol => 1},
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(1, maps:get(enable_connect_protocol, Decoded)).

%% Test ENABLE_CONNECT_PROTOCOL disabled
settings_connect_protocol_disabled_test() ->
    Settings = #{enable_connect_protocol => 0},
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(0, maps:get(enable_connect_protocol, Decoded)).

%% Test settings with GREASE values (reserved settings should be preserved)
settings_with_grease_roundtrip_test() ->
    %% GREASE setting: 0x1f * N + 0x21
    GREASEId = 16#21,  %% N=0
    Settings = #{GREASEId => 12345},
    Encoded = quic_h3_frame:encode_settings(Settings),
    {ok, {settings, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(12345, maps:get(GREASEId, Decoded)).

%%====================================================================
%% Edge Case Tests (inspired by quiche)
%%====================================================================

%% Test DATA frame with 12-byte payload (like quiche data test)
data_12_bytes_test() ->
    Payload = <<"Hello World!">>,  %% 12 bytes
    ?assertEqual(12, byte_size(Payload)),
    Encoded = quic_h3_frame:encode_data(Payload),
    {ok, {data, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(Payload, Decoded).

%% Test HEADERS frame with 12-byte header block
headers_12_bytes_test() ->
    HeaderBlock = <<"HeaderBlock!">>,  %% 12 bytes
    ?assertEqual(12, byte_size(HeaderBlock)),
    Encoded = quic_h3_frame:encode_headers(HeaderBlock),
    {ok, {headers, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(HeaderBlock, Decoded).

%% Test GOAWAY with id=32 (like quiche goaway test)
goaway_32_test() ->
    Encoded = quic_h3_frame:encode_goaway(32),
    ?assertMatch({ok, {goaway, 32}, <<>>}, quic_h3_frame:decode(Encoded)).

%% Test MAX_PUSH_ID with push_id=128 (like quiche max_push_id test)
max_push_id_128_test() ->
    Encoded = quic_h3_frame:encode_max_push_id(128),
    ?assertMatch({ok, {max_push_id, 128}, <<>>}, quic_h3_frame:decode(Encoded)).

%% Test CANCEL_PUSH with push_id=0 (like quiche cancel_push test)
cancel_push_zero_test() ->
    Encoded = quic_h3_frame:encode_cancel_push(0),
    ?assertMatch({ok, {cancel_push, 0}, <<>>}, quic_h3_frame:decode(Encoded)).

%% Test very large varint values
goaway_max_varint_test() ->
    %% Maximum 62-bit value
    MaxStreamId = 4611686018427387903,
    Encoded = quic_h3_frame:encode_goaway(MaxStreamId),
    {ok, {goaway, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(MaxStreamId, Decoded).

%% Test multiple frames concatenated
multiple_data_frames_test() ->
    Frame1 = quic_h3_frame:encode_data(<<"first">>),
    Frame2 = quic_h3_frame:encode_data(<<"second">>),
    Frame3 = quic_h3_frame:encode_data(<<"third">>),
    Combined = <<Frame1/binary, Frame2/binary, Frame3/binary>>,
    {ok, Frames, <<>>} = quic_h3_frame:decode_all(Combined),
    ?assertEqual(3, length(Frames)),
    ?assertMatch([{data, <<"first">>}, {data, <<"second">>}, {data, <<"third">>}], Frames).

%% Test frame with maximum 1-byte length (63 bytes payload)
data_max_1byte_length_test() ->
    Payload = binary:copy(<<"x">>, 63),
    Encoded = quic_h3_frame:encode_data(Payload),
    %% Frame should be: type (1) + length (1) + payload (63) = 65 bytes
    ?assertEqual(65, byte_size(Encoded)),
    {ok, {data, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(Payload, Decoded).

%% Test frame with minimum 2-byte length (64 bytes payload)
data_min_2byte_length_test() ->
    Payload = binary:copy(<<"x">>, 64),
    Encoded = quic_h3_frame:encode_data(Payload),
    %% Frame should be: type (1) + length (2) + payload (64) = 67 bytes
    ?assertEqual(67, byte_size(Encoded)),
    {ok, {data, Decoded}, <<>>} = quic_h3_frame:decode(Encoded),
    ?assertEqual(Payload, Decoded).

%%====================================================================
%% Error Handling Tests
%%====================================================================

%% Empty input
decode_empty_test() ->
    ?assertMatch({more, _}, quic_h3_frame:decode(<<>>)).

%% Truncated varint in frame type
decode_truncated_type_test() ->
    %% 2-byte varint marker but only 1 byte
    ?assertMatch({more, _}, quic_h3_frame:decode(<<16#40>>)).

%% Truncated varint in length
decode_truncated_length_test() ->
    %% Valid type, but truncated 2-byte length
    ?assertMatch({more, _}, quic_h3_frame:decode(<<0, 16#40>>)).

%% Valid header but missing payload
decode_missing_payload_test() ->
    %% DATA frame with length 100 but no payload
    ?assertMatch({more, 100}, quic_h3_frame:decode(<<0, 16#40, 100>>)).

%%====================================================================
%% Binary Pattern Tests (Fuzzing-like)
%%====================================================================

%% Ensure various byte patterns don't crash the decoder
decode_no_crash_test_() ->
    Patterns = [
        <<>>,
        <<0>>,
        <<255>>,
        <<0, 0>>,
        <<255, 255>>,
        <<0, 0, 0, 0>>,
        <<255, 255, 255, 255>>,
        binary:copy(<<0>>, 100),
        binary:copy(<<255>>, 100),
        crypto:strong_rand_bytes(50),
        crypto:strong_rand_bytes(100),
        crypto:strong_rand_bytes(256)
    ],
    [{"Decode pattern " ++ integer_to_list(N) ++ " no crash",
      fun() ->
          Pattern = lists:nth(N, Patterns),
          %% Should not crash, may return ok, more, or error
          Result = try quic_h3_frame:decode(Pattern) of
              {ok, _, _} -> ok;
              {more, _} -> ok;
              {error, _} -> ok
          catch
              _:_ -> crashed
          end,
          ?assertNotEqual(crashed, Result)
      end} || N <- lists:seq(1, length(Patterns))].
