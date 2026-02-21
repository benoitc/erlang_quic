%%% -*- erlang -*-
%%%
%%% Tests for HKDF Implementation
%%% RFC 5869 Test Vectors
%%%

-module(quic_hkdf_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% RFC 5869 Test Case 1 (SHA-256)
%%====================================================================

%% Test Case 1: Basic test case with SHA-256
%%   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
%%   salt = 0x000102030405060708090a0b0c (13 octets)
%%   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 octets)
%%   L    = 42
%%
%%   PRK  = 0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
%%   OKM  = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
%%          34007208d5b887185865

rfc5869_test1_extract_test() ->
    IKM = hexstr_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    Salt = hexstr_to_bin("000102030405060708090a0b0c"),
    Expected = hexstr_to_bin("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
    PRK = quic_hkdf:extract(Salt, IKM),
    ?assertEqual(Expected, PRK).

rfc5869_test1_expand_test() ->
    PRK = hexstr_to_bin("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
    Info = hexstr_to_bin("f0f1f2f3f4f5f6f7f8f9"),
    L = 42,
    Expected = hexstr_to_bin(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ),
    OKM = quic_hkdf:expand(PRK, Info, L),
    ?assertEqual(Expected, OKM).

%%====================================================================
%% RFC 5869 Test Case 2 (SHA-256, longer inputs/outputs)
%%====================================================================

%% Test Case 2:
%%   IKM  = 0x000102...4f (80 octets)
%%   salt = 0x606162...af (80 octets)
%%   info = 0xb0b1b2...ff (80 octets)
%%   L    = 82
%%
%%   PRK  = 0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244
%%   OKM  = 0xb11e398dc80327a1c8e7f78c596a4934...

rfc5869_test2_extract_test() ->
    IKM = list_to_binary(lists:seq(16#00, 16#4f)),
    Salt = list_to_binary(lists:seq(16#60, 16#af)),
    Expected = hexstr_to_bin("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
    PRK = quic_hkdf:extract(Salt, IKM),
    ?assertEqual(Expected, PRK).

rfc5869_test2_expand_test() ->
    PRK = hexstr_to_bin("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"),
    Info = list_to_binary(lists:seq(16#b0, 16#ff)),
    L = 82,
    Expected = hexstr_to_bin(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
    ),
    OKM = quic_hkdf:expand(PRK, Info, L),
    ?assertEqual(Expected, OKM).

%%====================================================================
%% RFC 5869 Test Case 3 (SHA-256, zero-length salt and info)
%%====================================================================

%% Test Case 3:
%%   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 octets)
%%   salt = (empty)
%%   info = (empty)
%%   L    = 42
%%
%%   PRK  = 0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04
%%   OKM  = 0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d
%%          9d201395faa4b61a96c8

rfc5869_test3_extract_test() ->
    IKM = hexstr_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    Expected = hexstr_to_bin("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
    PRK = quic_hkdf:extract(<<>>, IKM),
    ?assertEqual(Expected, PRK).

rfc5869_test3_expand_test() ->
    PRK = hexstr_to_bin("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"),
    L = 42,
    Expected = hexstr_to_bin(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    ),
    OKM = quic_hkdf:expand(PRK, <<>>, L),
    ?assertEqual(Expected, OKM).

%%====================================================================
%% HKDF-Expand-Label Tests (TLS 1.3 style)
%%====================================================================

expand_label_basic_test() ->
    %% Simple test that expand_label produces consistent output
    Secret = crypto:strong_rand_bytes(32),
    Label = <<"quic key">>,
    Context = <<>>,
    Length = 16,

    Result1 = quic_hkdf:expand_label(Secret, Label, Context, Length),
    Result2 = quic_hkdf:expand_label(Secret, Label, Context, Length),

    ?assertEqual(Length, byte_size(Result1)),
    ?assertEqual(Result1, Result2).

expand_label_different_labels_test() ->
    Secret = crypto:strong_rand_bytes(32),
    Context = <<>>,
    Length = 16,

    KeyResult = quic_hkdf:expand_label(Secret, <<"quic key">>, Context, Length),
    IVResult = quic_hkdf:expand_label(Secret, <<"quic iv">>, Context, Length),

    ?assertNotEqual(KeyResult, IVResult).

expand_label_with_context_test() ->
    Secret = crypto:strong_rand_bytes(32),
    Label = <<"test">>,
    Context1 = <<"context1">>,
    Context2 = <<"context2">>,
    Length = 16,

    Result1 = quic_hkdf:expand_label(Secret, Label, Context1, Length),
    Result2 = quic_hkdf:expand_label(Secret, Label, Context2, Length),

    ?assertNotEqual(Result1, Result2).

%%====================================================================
%% Edge Cases
%%====================================================================

expand_zero_length_test() ->
    PRK = crypto:strong_rand_bytes(32),
    Result = quic_hkdf:expand(PRK, <<"info">>, 0),
    ?assertEqual(<<>>, Result).

expand_exact_hash_length_test() ->
    PRK = crypto:strong_rand_bytes(32),
    Result = quic_hkdf:expand(PRK, <<"info">>, 32),
    ?assertEqual(32, byte_size(Result)).

expand_multiple_of_hash_length_test() ->
    PRK = crypto:strong_rand_bytes(32),
    Result = quic_hkdf:expand(PRK, <<"info">>, 64),
    ?assertEqual(64, byte_size(Result)).

%%====================================================================
%% Helper Functions
%%====================================================================

hexstr_to_bin(HexStr) ->
    hexstr_to_bin(HexStr, <<>>).

hexstr_to_bin([], Acc) ->
    Acc;
hexstr_to_bin([H1, H2 | Rest], Acc) ->
    Byte = list_to_integer([H1, H2], 16),
    hexstr_to_bin(Rest, <<Acc/binary, Byte>>).
