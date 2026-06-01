%%% -*- erlang -*-
%%%
%%% Unit tests for QPACK header compression (RFC 9204)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_qpack_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Stateless API Tests
%%====================================================================

encode_simple_headers_test() ->
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    Encoded = quic_qpack:encode(Headers),
    ?assert(is_binary(Encoded)),
    ?assert(byte_size(Encoded) > 0).

decode_simple_headers_test() ->
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

encode_decode_roundtrip_test() ->
    Headers = [
        {<<":method">>, <<"POST">>},
        {<<":scheme">>, <<"https">>},
        {<<":path">>, <<"/api/v1/resource">>},
        {<<":authority">>, <<"example.com">>},
        {<<"content-type">>, <<"application/json">>},
        {<<"accept">>, <<"*/*">>}
    ],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

encode_empty_headers_test() ->
    Headers = [],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual([], Decoded).

%%====================================================================
%% Static Table Tests
%%====================================================================

static_table_method_get_test() ->
    %% :method GET should use static table index 17
    Headers = [{<<":method">>, <<"GET">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

static_table_method_post_test() ->
    %% :method POST should use static table index 20
    Headers = [{<<":method">>, <<"POST">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

static_table_path_root_test() ->
    %% :path / should use static table index 1
    Headers = [{<<":path">>, <<"/">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

static_table_scheme_https_test() ->
    %% :scheme https should use static table index 23
    Headers = [{<<":scheme">>, <<"https">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

static_table_status_200_test() ->
    %% :status 200 should use static table index 25
    Headers = [{<<":status">>, <<"200">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

static_table_content_type_test() ->
    %% content-type with various values
    Headers = [{<<"content-type">>, <<"text/html; charset=utf-8">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

%%====================================================================
%% Byte-vector Tests (RFC 9204 wire format)
%%
%% The round-trip tests above pass even when the encoder emits a
%% malformed prefix, because the bundled decoder is lenient. These
%% assert the exact bytes a conformant peer (e.g. nghttp3) would see.
%%====================================================================

field_section_prefix_static_only_test() ->
    %% RFC 9204 Section 4.5.1: a static-only field section carries
    %% Required Insert Count 0 and Base 0, encoded as S=0, DeltaBase=0.
    %% The two-byte prefix is therefore `00 00`. A Base byte of 0x80
    %% (S=1) would mean Base = RIC - DeltaBase - 1 = -1 and is rejected
    %% as QPACK_DECOMPRESSION_FAILED.
    Encoded = quic_qpack:encode([{<<":status">>, <<"200">>}]),
    ?assertMatch(<<16#00, 16#00, _/binary>>, Encoded).

encode_status_200_bytes_test() ->
    %% Prefix `00 00` + `:status 200` as static index 25 (indexed field
    %% line `11011001` = 0xD9).
    Encoded = quic_qpack:encode([{<<":status">>, <<"200">>}]),
    ?assertEqual(<<16#00, 16#00, 16#D9>>, Encoded).

encode_response_headers_bytes_test() ->
    %% Prefix `00 00` + `:status 200` (0xD9) + `content-length 1`:
    %% literal with name reference to static index 4 (`01010100` = 0x54),
    %% value "1" as a one-byte literal string (`01` length, `31`).
    Encoded = quic_qpack:encode([
        {<<":status">>, <<"200">>},
        {<<"content-length">>, <<"1">>}
    ]),
    ?assertEqual(<<16#00, 16#00, 16#D9, 16#54, 16#01, 16#31>>, Encoded).

%%====================================================================
%% Field Section Prefix Base reconstruction (RFC 9204 Section 4.5.1.2)
%%
%%   if Sign == 0: Base = ReqInsertCount + DeltaBase
%%   else:         Base = ReqInsertCount - DeltaBase - 1
%%====================================================================

decode_base_sign_zero_test() ->
    %% S=0: Base = Required Insert Count + Delta Base.
    ?assertEqual(13, quic_qpack_prefix:decode_base(0, 10, 3)).

decode_base_sign_one_test() ->
    %% S=1: Base = Required Insert Count - Delta Base - 1.
    ?assertEqual(6, quic_qpack_prefix:decode_base(1, 10, 3)).

decode_base_static_only_test() ->
    %% Static-only prefix (00 00): RIC=0, S=0, DeltaBase=0 -> Base=0.
    ?assertEqual(0, quic_qpack_prefix:decode_base(0, 0, 0)).

decode_base_sign_one_boundary_test() ->
    %% S=1 with DeltaBase=0 -> Base = RIC - 1.
    ?assertEqual(4, quic_qpack_prefix:decode_base(1, 5, 0)).

%%====================================================================
%% Required Insert Count reconstruction (RFC 9204 Section 4.5.1.1)
%%
%%   EncInsertCount = 0 -> RIC = 0
%%   else MaxValue   = TotalInserts + MaxEntries
%%        MaxWrapped = floor(MaxValue / 2*MaxEntries) * 2*MaxEntries
%%        RIC        = MaxWrapped + EncInsertCount - 1  (wrap if > MaxValue)
%%====================================================================

decode_ric_zero_test() ->
    %% EncInsertCount 0 decodes to 0 regardless of table state.
    ?assertEqual(0, quic_qpack_prefix:decode_ric(0, 128, 1000)).

decode_ric_no_wrap_test() ->
    %% MaxEntries=128: RIC=1 encodes as (1 rem 256)+1 = 2.
    ?assertEqual(1, quic_qpack_prefix:decode_ric(2, 128, 1)).

decode_ric_no_wrap_large_test() ->
    %% RIC=100 encodes as (100 rem 256)+1 = 101.
    ?assertEqual(100, quic_qpack_prefix:decode_ric(101, 128, 100)).

decode_ric_wraparound_test() ->
    %% MaxEntries=2 (FullRange 4), TotalInserts=10: EncInsertCount 2 wraps
    %% back to RIC=9 ((9 rem 4)+1 = 2).
    ?assertEqual(9, quic_qpack_prefix:decode_ric(2, 2, 10)).

%%====================================================================
%% Literal Header Tests
%%====================================================================

encode_literal_header_test() ->
    %% Custom header not in static table
    Headers = [{<<"x-custom-header">>, <<"custom-value">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

encode_literal_header_empty_value_test() ->
    Headers = [{<<"x-empty">>, <<>>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

encode_literal_header_long_value_test() ->
    LongValue = binary:copy(<<"x">>, 1000),
    Headers = [{<<"x-long">>, LongValue}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

%%====================================================================
%% Stateful API Tests
%%====================================================================

new_state_test() ->
    State = quic_qpack:new(),
    ?assertEqual(0, quic_qpack:get_dynamic_capacity(State)),
    ?assertEqual(0, quic_qpack:get_insert_count(State)).

new_state_with_capacity_test() ->
    State = quic_qpack:new(#{max_dynamic_size => 4096}),
    ?assertEqual(4096, quic_qpack:get_dynamic_capacity(State)).

set_dynamic_capacity_under_max_test() ->
    State0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    State1 = quic_qpack:set_dynamic_capacity(2048, State0),
    ?assertEqual(2048, quic_qpack:get_dynamic_capacity(State1)).

%% RFC 9204 §4.3: the encoder's Set Dynamic Table Capacity instruction
%% MUST NOT advertise a capacity greater than the peer's maximum. The
%% API clamps so a caller can't produce a non-conformant instruction.
set_dynamic_capacity_clamps_to_max_test() ->
    State0 = quic_qpack:new(#{max_dynamic_size => 1024}),
    State1 = quic_qpack:set_dynamic_capacity(4096, State0),
    ?assertEqual(1024, quic_qpack:get_dynamic_capacity(State1)).

%% RFC 9114 §7.2.4.2: a 0-RTT client encoder must not use the dynamic
%% table before the server's SETTINGS are known. `max_allowed_capacity'
%% seeds the negotiation ceiling while leaving the table disabled, so
%% early-data requests stay static-only (no encoder-stream inserts a
%% default-capacity-0 server would reject).
new_with_allowed_capacity_starts_static_test() ->
    E0 = quic_qpack:new(#{max_allowed_capacity => 4096}),
    ?assertEqual(0, quic_qpack:get_dynamic_capacity(E0)),
    {Encoded, E1} = quic_qpack:encode([{<<"x-custom">>, <<"value">>}], 0, E0),
    ?assertEqual(<<>>, quic_qpack:get_encoder_instructions(E1)),
    %% Static-only field section prefix is 00 00 (RIC = 0, Base = 0).
    ?assertMatch(<<0, 0, _/binary>>, Encoded).

%% Once the peer's SETTINGS arrive, set_dynamic_capacity raises the table
%% up to the seeded ceiling and the encoder begins inserting entries.
allowed_capacity_enables_dynamic_after_negotiation_test() ->
    E0 = quic_qpack:new(#{max_allowed_capacity => 4096}),
    E1 = quic_qpack:set_dynamic_capacity(4096, E0),
    ?assertEqual(4096, quic_qpack:get_dynamic_capacity(E1)),
    {_Encoded, E2} = quic_qpack:encode([{<<"x-custom">>, <<"value">>}], 0, E1),
    ?assertNotEqual(<<>>, quic_qpack:get_encoder_instructions(E2)).

stateful_encode_decode_test() ->
    Encoder = quic_qpack:new(),
    Decoder = quic_qpack:new(),
    Headers = [{<<":method">>, <<"GET">>}, {<<":path">>, <<"/test">>}],

    {Encoded, _Encoder1} = quic_qpack:encode(Headers, Encoder),
    {{ok, Decoded}, _Decoder1} = quic_qpack:decode(Encoded, Decoder),
    ?assertEqual(Headers, Decoded).

%%====================================================================
%% Dynamic Table Tests
%%====================================================================

dynamic_table_capacity_test() ->
    %% Test that dynamic table capacity can be set
    State = quic_qpack:new(#{max_dynamic_size => 4096}),
    ?assertEqual(4096, quic_qpack:get_dynamic_capacity(State)),
    ?assertEqual(0, quic_qpack:get_insert_count(State)).

%%====================================================================
%% Dynamic Table round-trip (encoder stream + field section)
%%
%% Full flow: encode (insert + literal) -> feed encoder instructions to
%% the decoder -> acknowledge -> re-encode (dynamic reference) -> decode.
%%====================================================================

%% Insert one entry, acknowledge it, then reference it (RIC = insert_count).
dynamic_reference_newest_roundtrip_test() ->
    H = [{<<"x-custom">>, <<"value">>}],
    E0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    D0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    {_Literal, E1} = quic_qpack:encode(H, 0, E0),
    {ok, D1} = quic_qpack:process_encoder_instructions(
        quic_qpack:get_encoder_instructions(E1), D0
    ),
    {ok, E2} = quic_qpack:process_decoder_instructions(
        quic_qpack:encode_insert_count_increment(1), quic_qpack:clear_encoder_instructions(E1)
    ),
    {Ref, _E3} = quic_qpack:encode(H, 4, E2),
    %% The re-encode is a dynamic Indexed Field Line (10xxxxxx) after the
    %% 2-byte prefix, not another literal.
    <<_Prefix:2/binary, Tag:2, _/bitstring>> = Ref,
    ?assertEqual(2#10, Tag),
    ?assertEqual({ok, H}, element(1, quic_qpack:decode(Ref, D1))).

%% Reference a NON-newest entry (RIC < insert_count). The field section must
%% signal Base = insert_count (DeltaBase = insert_count - RIC); signalling
%% Base = RIC made the decoder resolve the wrong absolute index.
dynamic_reference_older_entry_roundtrip_test() ->
    A = {<<"a">>, <<"1">>},
    B = {<<"b">>, <<"2">>},
    E0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    D0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    {_, E1} = quic_qpack:encode([A], 0, E0),
    {ok, D1} = quic_qpack:process_encoder_instructions(
        quic_qpack:get_encoder_instructions(E1), D0
    ),
    {_, E2} = quic_qpack:encode([B], 4, quic_qpack:clear_encoder_instructions(E1)),
    {ok, D2} = quic_qpack:process_encoder_instructions(
        quic_qpack:get_encoder_instructions(E2), D1
    ),
    {ok, E3} = quic_qpack:process_decoder_instructions(
        quic_qpack:encode_insert_count_increment(2), quic_qpack:clear_encoder_instructions(E2)
    ),
    {Ref, _E4} = quic_qpack:encode([A], 8, E3),
    ?assertEqual({ok, [A]}, element(1, quic_qpack:decode(Ref, D2))).

%% A field section that arrives before its encoder-stream inserts decodes as
%% {blocked, RIC}; once the inserts are processed, the retry succeeds.
dynamic_blocked_stream_recovery_test() ->
    H = [{<<"x-custom">>, <<"value">>}],
    E0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    D0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    {_, E1} = quic_qpack:encode(H, 0, E0),
    Instr = quic_qpack:get_encoder_instructions(E1),
    {ok, E2} = quic_qpack:process_decoder_instructions(
        quic_qpack:encode_insert_count_increment(1), quic_qpack:clear_encoder_instructions(E1)
    ),
    {Ref, _E3} = quic_qpack:encode(H, 4, E2),
    ?assertMatch({blocked, 1}, element(1, quic_qpack:decode(Ref, D0))),
    {ok, D1} = quic_qpack:process_encoder_instructions(Instr, D0),
    ?assertEqual({ok, H}, element(1, quic_qpack:decode(Ref, D1))).

%% A Required Insert Count whose encoded value reaches 255 must use the
%% 8-bit prefix-integer continuation encoding (RFC 9204 Section 4.5.1.1);
%% packing it as a raw byte truncated the prefix and silently dropped the
%% section. Insert 254 entries, then reference entry 253 (RIC = 254 ->
%% encoded insert count 255).
dynamic_large_insert_count_roundtrip_test() ->
    Cap = 4096,
    E0 = quic_qpack:new(#{max_dynamic_size => Cap}),
    D0 = quic_qpack:new(#{max_dynamic_size => Cap}),
    {Ef, Df} = lists:foldl(
        fun(I, {E, D}) ->
            H = [{<<"h", (integer_to_binary(I))/binary>>, <<"v">>}],
            {_, E1} = quic_qpack:encode(H, I, E),
            {ok, D1} = quic_qpack:process_encoder_instructions(
                quic_qpack:get_encoder_instructions(E1), D
            ),
            {quic_qpack:clear_encoder_instructions(E1), D1}
        end,
        {E0, D0},
        lists:seq(0, 253)
    ),
    {ok, Eack} = quic_qpack:process_decoder_instructions(
        quic_qpack:encode_insert_count_increment(254), Ef
    ),
    H = [{<<"h253">>, <<"v">>}],
    {Ref, _E} = quic_qpack:encode(H, 999, Eack),
    ?assertEqual({ok, H}, element(1, quic_qpack:decode(Ref, Df))).

%%====================================================================
%% Huffman Encoding Tests
%%====================================================================

huffman_encode_test() ->
    Input = <<"www.example.com">>,
    Encoded = quic_qpack_huffman:encode(Input),
    ?assert(is_binary(Encoded)),
    %% Huffman encoding should be smaller
    ?assert(byte_size(Encoded) =< byte_size(Input)).

huffman_decode_test() ->
    Input = <<"www.example.com">>,
    Encoded = quic_qpack_huffman:encode(Input),
    Decoded = quic_qpack_huffman:decode(Encoded),
    ?assertEqual(Input, Decoded).

huffman_roundtrip_empty_test() ->
    Input = <<>>,
    Encoded = quic_qpack_huffman:encode(Input),
    Decoded = quic_qpack_huffman:decode(Encoded),
    ?assertEqual(Input, Decoded).

huffman_roundtrip_all_ascii_test() ->
    %% Test with various ASCII characters
    Input = <<"Hello, World! 123 @#$%">>,
    Encoded = quic_qpack_huffman:encode(Input),
    Decoded = quic_qpack_huffman:decode(Encoded),
    ?assertEqual(Input, Decoded).

huffman_encoded_size_test() ->
    Input = <<"www.example.com">>,
    Size = quic_qpack_huffman:encoded_size(Input),
    Encoded = quic_qpack_huffman:encode(Input),
    ?assertEqual(Size, byte_size(Encoded)).

huffman_decode_safe_test() ->
    Input = <<"test string">>,
    Encoded = quic_qpack_huffman:encode(Input),
    {ok, Decoded} = quic_qpack_huffman:decode_safe(Encoded),
    ?assertEqual(Input, Decoded).

%%====================================================================
%% Error Handling Tests
%%====================================================================

decode_invalid_prefix_test() ->
    %% Invalid required insert count prefix
    Invalid = <<16#FF, 16#FF>>,
    ?assertMatch({error, _}, quic_qpack:decode(Invalid)).

%%====================================================================
%% Encoder Instructions Tests
%%====================================================================

get_encoder_instructions_test() ->
    State = quic_qpack:new(),
    Instructions = quic_qpack:get_encoder_instructions(State),
    ?assertEqual(<<>>, Instructions).

clear_encoder_instructions_test() ->
    State0 = quic_qpack:new(#{max_dynamic_size => 4096}),
    %% Encode something to potentially generate instructions
    {_Encoded, State1} = quic_qpack:encode(
        [{<<"x-custom">>, <<"value">>}],
        State0
    ),
    State2 = quic_qpack:clear_encoder_instructions(State1),
    ?assertEqual(<<>>, quic_qpack:get_encoder_instructions(State2)).

%%====================================================================
%% Section Acknowledgement Tests
%%====================================================================

encode_section_ack_test() ->
    StreamId = 4,
    Ack = quic_qpack:encode_section_ack(StreamId),
    ?assert(is_binary(Ack)),
    %% Section ack format: 1xxxxxxx (7-bit prefix)
    <<First, _/binary>> = Ack,
    ?assert((First band 16#80) =:= 16#80).

encode_insert_count_increment_test() ->
    Increment = 5,
    Inc = quic_qpack:encode_insert_count_increment(Increment),
    ?assert(is_binary(Inc)),
    %% Insert count increment format: 00xxxxxx (6-bit prefix)
    <<First, _/binary>> = Inc,
    ?assert((First band 16#C0) =:= 16#00).

%%====================================================================
%% Mixed Static/Literal Headers Test
%%====================================================================

mixed_headers_test() ->
    Headers = [
        % Static table
        {<<":method">>, <<"GET">>},
        % Static table
        {<<":scheme">>, <<"https">>},
        % Name in static, value literal
        {<<":authority">>, <<"api.example.com">>},
        % Name in static, value literal
        {<<":path">>, <<"/v1/users/123">>},
        % Fully literal
        {<<"x-request-id">>, <<"abc-123-def">>},
        % Name in static
        {<<"accept">>, <<"application/json">>}
    ],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

%%====================================================================
%% Binary Header Values Test
%%====================================================================

binary_values_test() ->
    %% Headers with binary values that need proper encoding
    Headers = [
        {<<"content-length">>, <<"12345">>},
        {<<"date">>, <<"Sat, 01 Jan 2025 00:00:00 GMT">>}
    ],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

%%====================================================================
%% Multiple Encodes Test
%%====================================================================

multiple_encodes_test() ->
    State = quic_qpack:new(),

    Headers1 = [{<<":method">>, <<"GET">>}],
    {Encoded1, State1} = quic_qpack:encode(Headers1, State),

    Headers2 = [{<<":method">>, <<"POST">>}],
    {Encoded2, _State2} = quic_qpack:encode(Headers2, State1),

    ?assert(is_binary(Encoded1)),
    ?assert(is_binary(Encoded2)),
    ?assertNotEqual(Encoded1, Encoded2).

%%====================================================================
%% Huffman string encoding / EOS validation (RFC 7541 §5.2)
%%====================================================================

%% Literal values that compress should round-trip through Huffman encoding.
huffman_encoded_roundtrip_test() ->
    Headers = [
        {<<"x-long-header">>, <<"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">>}
    ],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

%% Short values should remain non-Huffman (encoded_size >= raw).
huffman_skip_for_small_value_test() ->
    Headers = [{<<"x-s">>, <<"a">>}],
    Encoded = quic_qpack:encode(Headers),
    {ok, Decoded} = quic_qpack:decode(Encoded),
    ?assertEqual(Headers, Decoded).

%% RFC 9204 §4.4.3: Insert Count Increment with value 0 is a decoder-stream
%% error.
insert_count_increment_zero_rejected_test() ->
    %% Encoded form of an Insert Count Increment with value 0: prefix 00 + 0.
    Instruction = <<0:8>>,
    State = quic_qpack:new(),
    ?assertMatch({error, _}, quic_qpack:process_decoder_instructions(Instruction, State)).

%% RFC 7541 §5.2: EOS symbol or over-long padding must be rejected on decode.
huffman_invalid_eos_rejected_test() ->
    %% Build a literal with huffman flag=1 but with an EOS-only encoded byte
    %% stream (all-ones), which contains EOS and must fail validation.
    Prefix = <<0:2, 0:6>>,
    %% Literal with literal name, huffman name = 0, name len = 1
    NameLenByte = <<0:1, 1:3, 1:4>>,
    Name = <<"x">>,
    %% Value: huffman flag=1, 4 bytes of 0xFF (will contain EOS symbol)
    ValueLenByte = <<1:1, 4:7>>,
    Value = <<16#FF, 16#FF, 16#FF, 16#FF>>,
    Header = <<NameLenByte/binary, Name/binary, ValueLenByte/binary, Value/binary>>,
    Block = <<Prefix/binary, Header/binary>>,
    ?assertMatch({error, _}, quic_qpack:decode(Block)).

%%====================================================================
%% QPACK Compliance Checks (RFC 9204)
%%====================================================================

%% RFC 9204 §4.3: a decoder that receives a Set Dynamic Table Capacity
%% instruction whose value exceeds its advertised maximum MUST treat
%% this as QPACK_ENCODER_STREAM_ERROR. `process_encoder_instructions'
%% propagates {set_capacity_exceeds_max, _, _} which the H3 connection
%% layer maps to the H3 error.
encoder_set_capacity_over_max_rejected_test() ->
    %% Build Set Dynamic Table Capacity with value 2048. Prefix 001,
    %% 5-bit value: 2048 does not fit, so first byte is 0b00111111 = 0x3F
    %% then the varint continuation for (2048 - 31) = 2017 = 0xE1 0x0F.
    Instruction = <<2#00111111, 16#E1, 16#0F>>,
    State = quic_qpack:new(#{max_dynamic_size => 1024}),
    ?assertMatch(
        {error, {set_capacity_exceeds_max, 2048, 1024}},
        quic_qpack:process_encoder_instructions(Instruction, State)
    ).

%% RFC 9204 §3.1: static-table references MUST use a valid index
%% (0..98 in the v1 table). A reference to 99+ is undefined; the
%% decoder throws and the error surfaces as a decode error.
invalid_static_index_rejected_test() ->
    %% Field section prefix is 2 bytes: Encoded RIC (8-bit prefix) + S-flag
    %% + DeltaBase (7-bit prefix). Both zero means RIC=0, Base=0 (no
    %% dynamic entries referenced).
    Prefix = <<0, 0>>,
    %% Indexed Field Line with name reference to the static table:
    %% first byte is 11xxxxxx (6-bit index prefix). For index 99:
    %%   prefix bits 11, low 6 bits = 63 (max) = 0xFF
    %%   continuation byte carrying 99 - 63 = 36
    FieldLine = <<16#FF, 36>>,
    Block = <<Prefix/binary, FieldLine/binary>>,
    ?assertMatch({error, {invalid_static_index, _}}, quic_qpack:decode(Block)).

%% RFC 7541 §5.2: an invalid Huffman-coded string in a short-length field
%% value must be rejected. 32 one-bits is not a valid encoding. This
%% exercises the short-length Huffman value path in decode_string, which
%% previously used the non-validating decoder.
short_huffman_invalid_rejected_test() ->
    %% prefix(0,0) + literal-name "x" + Huffman value (len 4) of 0xFFFFFFFF.
    Bad = <<0, 0, 16#21, "x", 16#84, 16#FF, 16#FF, 16#FF, 16#FF>>,
    ?assertMatch({error, _}, quic_qpack:decode(Bad)).
