%%% -*- erlang -*-
%%%
%%% Tests for QUIC Variable-Length Integer Encoding
%%% RFC 9000 Section 16
%%%

-module(quic_varint_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% RFC 9000 Section 16 Examples
%%====================================================================

%% The RFC provides these example encodings:
%% Value 0 -> 0x00
%% Value 63 -> 0x3f
%% Value 64 -> 0x4040
%% Value 16383 -> 0x7fff
%% Value 16384 -> 0x80004000
%% Value 1073741823 -> 0xbfffffff
%% Value 1073741824 -> 0xc0000000 40000000
%% Value 4611686018427387903 -> 0xffffffffffffffff

encode_0_test() ->
    ?assertEqual(<<16#00>>, quic_varint:encode(0)).

encode_63_test() ->
    ?assertEqual(<<16#3f>>, quic_varint:encode(63)).

encode_64_test() ->
    ?assertEqual(<<16#40, 16#40>>, quic_varint:encode(64)).

encode_16383_test() ->
    ?assertEqual(<<16#7f, 16#ff>>, quic_varint:encode(16383)).

encode_16384_test() ->
    ?assertEqual(<<16#80, 16#00, 16#40, 16#00>>, quic_varint:encode(16384)).

encode_1073741823_test() ->
    ?assertEqual(<<16#bf, 16#ff, 16#ff, 16#ff>>, quic_varint:encode(1073741823)).

encode_1073741824_test() ->
    ?assertEqual(
        <<16#c0, 16#00, 16#00, 16#00, 16#40, 16#00, 16#00, 16#00>>,
        quic_varint:encode(1073741824)
    ).

encode_max_test() ->
    Max = 4611686018427387903,
    ?assertEqual(
        <<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff>>,
        quic_varint:encode(Max)
    ).

%%====================================================================
%% Decode Tests (inverse of encode)
%%====================================================================

decode_0_test() ->
    ?assertEqual({0, <<>>}, quic_varint:decode(<<16#00>>)).

decode_63_test() ->
    ?assertEqual({63, <<>>}, quic_varint:decode(<<16#3f>>)).

decode_64_test() ->
    ?assertEqual({64, <<>>}, quic_varint:decode(<<16#40, 16#40>>)).

decode_16383_test() ->
    ?assertEqual({16383, <<>>}, quic_varint:decode(<<16#7f, 16#ff>>)).

decode_16384_test() ->
    ?assertEqual({16384, <<>>}, quic_varint:decode(<<16#80, 16#00, 16#40, 16#00>>)).

decode_1073741823_test() ->
    ?assertEqual({1073741823, <<>>}, quic_varint:decode(<<16#bf, 16#ff, 16#ff, 16#ff>>)).

decode_1073741824_test() ->
    ?assertEqual(
        {1073741824, <<>>},
        quic_varint:decode(<<16#c0, 16#00, 16#00, 16#00, 16#40, 16#00, 16#00, 16#00>>)
    ).

decode_max_test() ->
    Max = 4611686018427387903,
    ?assertEqual(
        {Max, <<>>},
        quic_varint:decode(<<16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff, 16#ff>>)
    ).

%%====================================================================
%% Decode with trailing data
%%====================================================================

decode_with_rest_test() ->
    ?assertEqual({0, <<"hello">>}, quic_varint:decode(<<16#00, "hello">>)),
    ?assertEqual({64, <<"world">>}, quic_varint:decode(<<16#40, 16#40, "world">>)).

%%====================================================================
%% encode_len tests
%%====================================================================

encode_len_1byte_test() ->
    ?assertEqual(1, quic_varint:encode_len(0)),
    ?assertEqual(1, quic_varint:encode_len(63)).

encode_len_2byte_test() ->
    ?assertEqual(2, quic_varint:encode_len(64)),
    ?assertEqual(2, quic_varint:encode_len(16383)).

encode_len_4byte_test() ->
    ?assertEqual(4, quic_varint:encode_len(16384)),
    ?assertEqual(4, quic_varint:encode_len(1073741823)).

encode_len_8byte_test() ->
    ?assertEqual(8, quic_varint:encode_len(1073741824)),
    ?assertEqual(8, quic_varint:encode_len(4611686018427387903)).

%%====================================================================
%% max_value tests
%%====================================================================

max_value_test() ->
    ?assertEqual(63, quic_varint:max_value(1)),
    ?assertEqual(16383, quic_varint:max_value(2)),
    ?assertEqual(1073741823, quic_varint:max_value(4)),
    ?assertEqual(4611686018427387903, quic_varint:max_value(8)).

%%====================================================================
%% Roundtrip tests
%%====================================================================

roundtrip_test_() ->
    Values = [
        0,
        1,
        63,
        64,
        100,
        16383,
        16384,
        100000,
        1073741823,
        1073741824,
        4611686018427387903
    ],
    [
        ?_assertEqual({V, <<>>}, quic_varint:decode(quic_varint:encode(V)))
     || V <- Values
    ].

%%====================================================================
%% Error cases
%%====================================================================

encode_negative_test() ->
    ?assertError(badarg, quic_varint:encode(-1)).

encode_too_large_test() ->
    ?assertError(badarg, quic_varint:encode(4611686018427387904)).

decode_empty_test() ->
    ?assertError(badarg, quic_varint:decode(<<>>)).

decode_incomplete_2byte_test() ->
    %% First byte says 2-byte encoding, but only 1 byte provided
    ?assertError({incomplete, 2}, quic_varint:decode(<<16#40>>)).

decode_incomplete_4byte_test() ->
    %% First byte says 4-byte encoding, but only 2 bytes provided
    ?assertError({incomplete, 4}, quic_varint:decode(<<16#80, 16#00>>)).

decode_incomplete_8byte_test() ->
    %% First byte says 8-byte encoding, but only 4 bytes provided
    ?assertError({incomplete, 8}, quic_varint:decode(<<16#c0, 16#00, 16#00, 16#00>>)).
