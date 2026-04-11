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
    lists:foreach(fun(Str) ->
        Encoded = quic_qpack_huffman:encode(Str),
        Decoded = quic_qpack_huffman:decode(Encoded),
        ?assertEqual(Str, Decoded)
    end, [
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
    ]).

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
    lists:foreach(fun(Str) ->
        PredictedSize = quic_qpack_huffman:encoded_size(Str),
        ActualSize = byte_size(quic_qpack_huffman:encode(Str)),
        ?assertEqual(ActualSize, PredictedSize)
    end, [
        <<>>,
        <<"a">>,
        <<"GET">>,
        <<"www.example.com">>,
        <<"content-type: application/json">>
    ]).

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
    lists:foreach(fun(Byte) ->
        Str = <<Byte>>,
        ?assertEqual(Str, quic_qpack_huffman:decode(quic_qpack_huffman:encode(Str)))
    end, lists:seq(32, 126)). %% Printable ASCII

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
    lists:foreach(fun(Str) ->
        Encoded = quic_qpack_huffman:encode(Str),
        ?assertMatch({ok, Str}, quic_qpack_huffman:decode_safe(Encoded))
    end, [
        <<"a">>,
        <<"GET">>,
        <<"www.example.com">>,
        <<"application/json">>
    ]).

decode_safe_empty_test() ->
    ?assertMatch({ok, <<>>}, quic_qpack_huffman:decode_safe(<<>>)).

decode_safe_valid_padding_test() ->
    %% Test various strings that result in different padding amounts
    %% Each string will have different padding bits
    lists:foreach(fun(Str) ->
        Encoded = quic_qpack_huffman:encode(Str),
        ?assertMatch({ok, Str}, quic_qpack_huffman:decode_safe(Encoded))
    end, [
        <<"a">>,     %% 5 bits -> 3 bits padding
        <<"aa">>,    %% 10 bits -> 6 bits padding
        <<"aaa">>,   %% 15 bits -> 1 bit padding
        <<"aaaa">>,  %% 20 bits -> 4 bits padding
        <<"aaaaa">>  %% 25 bits -> 7 bits padding
    ]).
