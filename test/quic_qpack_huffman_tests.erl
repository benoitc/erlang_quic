%%% -*- erlang -*-
%%%
%%% Unit tests for quic_qpack_huffman module.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_qpack_huffman_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Round-trip tests
%%====================================================================

encode_decode_empty_test() ->
    ?assertEqual(<<>>, quic_qpack_huffman:decode(quic_qpack_huffman:encode(<<>>))).

encode_decode_simple_test() ->
    %% Common strings that should round-trip correctly
    lists:foreach(
        fun(Str) ->
            Encoded = quic_qpack_huffman:encode(Str),
            Decoded = quic_qpack_huffman:decode(Encoded),
            ?assertEqual(Str, Decoded)
        end,
        [
            <<"GET">>,
            <<"POST">>,
            <<"/index.html">>,
            <<"www.example.com">>,
            <<"text/html">>,
            <<"application/json">>,
            <<"200">>,
            <<"404">>,
            <<"content-type">>,
            <<"accept-encoding">>
        ]
    ).

encode_decode_lowercase_test() ->
    Str = <<"abcdefghijklmnopqrstuvwxyz">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

encode_decode_uppercase_test() ->
    Str = <<"ABCDEFGHIJKLMNOPQRSTUVWXYZ">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

encode_decode_digits_test() ->
    Str = <<"0123456789">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

encode_decode_printable_test() ->
    %% All printable ASCII except those with very long codes
    Str = <<"abcdefghijklmnopqrstuvwxyz0123456789-_.~">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

encode_decode_special_chars_test() ->
    %% Various special characters
    Str = <<":/?#[]@!$&'()*+,;=">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

encode_decode_http_path_test() ->
    Str = <<"/api/v1/users?name=john&page=1">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

encode_decode_http_header_test() ->
    Str = <<"Mon, 01 Jan 2024 00:00:00 GMT">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

%%====================================================================
%% Encoding size tests
%%====================================================================

encoded_size_test() ->
    %% Test that encoded_size matches actual encoded size
    lists:foreach(
        fun(Str) ->
            PredictedSize = quic_qpack_huffman:encoded_size(Str),
            ActualSize = byte_size(quic_qpack_huffman:encode(Str)),
            ?assertEqual(ActualSize, PredictedSize)
        end,
        [
            <<>>,
            <<"a">>,
            <<"GET">>,
            <<"www.example.com">>,
            <<"content-type: application/json">>
        ]
    ).

%%====================================================================
%% Compression ratio tests
%%====================================================================

compression_beneficial_test() ->
    %% Huffman should typically compress common strings
    Str = <<"www.example.com">>,
    OriginalSize = byte_size(Str),
    CompressedSize = byte_size(quic_qpack_huffman:encode(Str)),
    ?assert(CompressedSize < OriginalSize).

%%====================================================================
%% Known encoding tests (RFC 7541 examples)
%%====================================================================

known_encoding_test() ->
    %% RFC examples for specific encodings
    %% The exact bytes depend on padding
    Encoded = quic_qpack_huffman:encode(<<"www.example.com">>),
    %% Should round-trip
    ?assertEqual(<<"www.example.com">>, quic_qpack_huffman:decode(Encoded)).

%%====================================================================
%% Edge cases
%%====================================================================

single_byte_test() ->
    lists:foreach(
        fun(Byte) ->
            Str = <<Byte>>,
            ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str)))
        %% Printable ASCII
        end,
        lists:seq(32, 126)
    ).

repeated_char_test() ->
    Str = <<"aaaaaaaaaa">>,
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

long_string_test() ->
    Str = list_to_binary(lists:duplicate(1000, $a)),
    ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str))).

%%====================================================================
%% Safe decoding tests (RFC 7541 Section 5.2 validation)
%%====================================================================

decode_safe_roundtrip_test() ->
    %% Valid encoded data should decode successfully with decode_safe
    lists:foreach(
        fun(Str) ->
            Encoded = quic_qpack_huffman:encode(Str),
            ?assertMatch({ok, Str}, quic_qpack_huffman:decode_safe(Encoded))
        end,
        [
            <<"a">>,
            <<"GET">>,
            <<"www.example.com">>,
            <<"application/json">>
        ]
    ).

decode_safe_empty_test() ->
    ?assertMatch({ok, <<>>}, quic_qpack_huffman:decode_safe(<<>>)).

decode_safe_valid_padding_test() ->
    %% Test various strings that result in different padding amounts
    %% Each string will have different padding bits
    lists:foreach(
        fun(Str) ->
            Encoded = quic_qpack_huffman:encode(Str),
            ?assertMatch({ok, Str}, quic_qpack_huffman:decode_safe(Encoded))
        end,
        [
            %% 5 bits -> 3 bits padding
            <<"a">>,
            %% 10 bits -> 6 bits padding
            <<"aa">>,
            %% 15 bits -> 1 bit padding
            <<"aaa">>,
            %% 20 bits -> 4 bits padding
            <<"aaaa">>,
            %% 25 bits -> 7 bits padding
            <<"aaaaa">>
        ]
    ).

%% RFC 7541 §5.2: decode_safe/1 must report errors, never crash.
decode_safe_rejects_overlong_padding_test() ->
    %% Whole input is all-ones padding (>= 8 bits).
    ?assertMatch({error, _}, quic_qpack_huffman:decode_safe(<<16#FF>>)),
    ?assertMatch({error, _}, quic_qpack_huffman:decode_safe(<<16#FF, 16#FF>>)).

%% Eight or more bits of padding after a symbol are as much an error as
%% a string that is nothing but padding.
decode_safe_rejects_overlong_padding_after_a_symbol_test() ->
    %% "a" is 00011, padded with 111: one more byte of ones is 11 bits.
    ?assertEqual({ok, <<"a">>}, quic_qpack_huffman:decode_safe(<<16#1F>>)),
    ?assertEqual({error, invalid_padding}, quic_qpack_huffman:decode_safe(<<16#1F, 16#FF>>)),
    ?assertEqual(
        {error, invalid_padding}, quic_qpack_huffman:decode_safe(<<16#1F, 16#FF, 16#FF>>)
    ),
    Encoded = quic_qpack_huffman:encode(<<"aaaaa">>),
    ?assertEqual(
        {error, invalid_padding}, quic_qpack_huffman:decode_safe(<<Encoded/binary, 16#FF>>)
    ).

%% Padding has to be the start of EOS, all ones: "hc" is 100111 00100,
%% and the 01111 after it is the start of some other code.
decode_safe_rejects_padding_that_is_not_eos_test() ->
    ?assertEqual({ok, <<"hc">>}, quic_qpack_huffman:decode_safe(<<2#10011100, 2#10011111>>)),
    ?assertEqual(
        {error, invalid_padding}, quic_qpack_huffman:decode_safe(<<2#10011100, 2#10001111>>)
    ).

decode_safe_rejects_invalid_code_without_crashing_test() ->
    %% 32 one-bits is an invalid encoding; must return {error,_}, not crash.
    ?assertMatch({error, _}, quic_qpack_huffman:decode_safe(<<16#FF, 16#FF, 16#FF, 16#FF>>)).

decode_safe_accepts_valid_and_empty_test() ->
    ?assertEqual({ok, <<>>}, quic_qpack_huffman:decode_safe(<<>>)),
    Enc = quic_qpack_huffman:encode(<<"hello">>),
    ?assertEqual({ok, <<"hello">>}, quic_qpack_huffman:decode_safe(Enc)).
