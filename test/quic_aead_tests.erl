%%% -*- erlang -*-
%%%
%%% Tests for QUIC AEAD Packet Protection
%%% RFC 9001 Appendix A Test Vectors
%%%

-module(quic_aead_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Nonce Computation Tests
%%====================================================================

nonce_computation_basic_test() ->
    %% Simple test: IV XOR with PN
    IV = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    PN = 0,
    Expected = IV,
    ?assertEqual(Expected, quic_aead:compute_nonce(IV, PN)).

nonce_computation_with_pn_test() ->
    %% PN=1 should flip last bit
    IV = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>,
    PN = 1,
    Expected = <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>,
    ?assertEqual(Expected, quic_aead:compute_nonce(IV, PN)).

nonce_computation_large_pn_test() ->
    %% Larger packet number
    IV = <<16#fa, 16#04, 16#4b, 16#2f, 16#42, 16#a3, 16#fd, 16#3b, 16#46, 16#fb, 16#25, 16#5c>>,
    PN = 2,
    %% PN=2 in 12-byte form: 00 00 00 00 00 00 00 00 00 00 00 02
    %% XOR with IV
    Expected =
        <<16#fa, 16#04, 16#4b, 16#2f, 16#42, 16#a3, 16#fd, 16#3b, 16#46, 16#fb, 16#25, 16#5e>>,
    ?assertEqual(Expected, quic_aead:compute_nonce(IV, PN)).

%%====================================================================
%% AEAD Encryption/Decryption Tests
%%====================================================================

aead_roundtrip_aes128_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    PN = 42,
    AAD = <<"additional data">>,
    Plaintext = <<"Hello, QUIC!">>,

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),

    %% Ciphertext should be 16 bytes longer (tag)
    ?assertEqual(byte_size(Plaintext) + 16, byte_size(Ciphertext)),

    %% Decrypt should give back original
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

aead_roundtrip_aes256_test() ->
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    PN = 100,
    AAD = <<"header">>,
    Plaintext = <<"Secret message for AES-256-GCM">>,

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

aead_wrong_key_test() ->
    Key1 = crypto:strong_rand_bytes(16),
    Key2 = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    PN = 1,
    AAD = <<"aad">>,
    Plaintext = <<"data">>,

    Ciphertext = quic_aead:encrypt(Key1, IV, PN, AAD, Plaintext),
    %% Decrypting with wrong key should fail
    ?assertEqual({error, bad_tag}, quic_aead:decrypt(Key2, IV, PN, AAD, Ciphertext)).

aead_wrong_aad_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    PN = 1,
    AAD1 = <<"original aad">>,
    AAD2 = <<"modified aad">>,
    Plaintext = <<"data">>,

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD1, Plaintext),
    %% Decrypting with wrong AAD should fail
    ?assertEqual({error, bad_tag}, quic_aead:decrypt(Key, IV, PN, AAD2, Ciphertext)).

aead_wrong_pn_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    PN1 = 1,
    PN2 = 2,
    AAD = <<"aad">>,
    Plaintext = <<"data">>,

    Ciphertext = quic_aead:encrypt(Key, IV, PN1, AAD, Plaintext),
    %% Decrypting with wrong PN should fail
    ?assertEqual({error, bad_tag}, quic_aead:decrypt(Key, IV, PN2, AAD, Ciphertext)).

aead_empty_plaintext_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    PN = 0,
    AAD = <<"header">>,
    Plaintext = <<>>,

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
    %% Empty plaintext should still produce 16-byte tag
    ?assertEqual(16, byte_size(Ciphertext)),

    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
    ?assertEqual(<<>>, Decrypted).

%%====================================================================
%% RFC 9001 Appendix A.2 - Client Initial Packet Test
%%====================================================================

%% Test vector from RFC 9001 Appendix A.2
%% This tests the encryption of the client's first Initial packet

rfc9001_client_initial_encrypt_test() ->
    %% Client Initial key derived from DCID 0x8394c8f03e515708
    Key = hexstr_to_bin("1f369613dd76d5467730efcbe3b1a22d"),
    IV = hexstr_to_bin("fa044b2f42a3fd3b46fb255c"),
    PN = 2,

    %% The header (AAD) for the Initial packet
    %% This is a simplified version - full test would need complete header
    AAD = hexstr_to_bin("c000000001088394c8f03e5157080000449e00000002"),

    %% Test plaintext (CRYPTO frame + PADDING)
    Plaintext = hexstr_to_bin(
        "060040f1010000ed0303ebf8fa56f129"
        "39b9584a3896472ec40bb863cfd3e868"
        "04fe3a47f06a2b69484c000004130113"
        "02010000c000000010000e00000b6578"
        "616d706c652e636f6dff01000100000a"
        "00080006001d00170018001000070005"
        "04616c706e0005000501000000000033"
        "00260024001d00209370b2c9caa47fba"
        "baf4559fedba753de171fa71f50f1ce1"
        "5d43e994ec74d748002b000302030400"
        "0d0010000e0403050306030203080408"
        "050806002d00020101001c0002400100"
        "3900320408ffffffffffffffff050480"
        "00ffff06048000ffff07048000ffff08"
        "01100901100f088394c8f03e515708"
    ),

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),

    %% Verify we can decrypt it back
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

%%====================================================================
%% Determinism Tests
%%====================================================================

encrypt_deterministic_test() ->
    Key = hexstr_to_bin("000102030405060708090a0b0c0d0e0f"),
    IV = hexstr_to_bin("000102030405060708090a0b"),
    PN = 0,
    AAD = <<"test">>,
    Plaintext = <<"hello">>,

    Ciphertext1 = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
    Ciphertext2 = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
    ?assertEqual(Ciphertext1, Ciphertext2).

%%====================================================================
%% Header Protection Tests
%%====================================================================

header_protection_roundtrip_long_test() ->
    %% Test with a long header (Initial packet)
    HP = crypto:strong_rand_bytes(16),

    %% Long header: first byte has 0x80 bit set
    %% Format: flags (1) + version (4) + DCID len (1) + DCID (8) + SCID len (1) + SCID (8) + ...
    %% PN length is encoded in bits 0-1: 0b11 = 3, so PNLen = 3 + 1 = 4

    % Long header, Initial packet, PN len = 4 (bits 0-1 = 3)
    FirstByte = 16#c3,
    Header =
        <<FirstByte,
            % Version
            16#00, 16#00, 16#00, 16#01,
            % DCID length
            16#08,
            % DCID
            1, 2, 3, 4, 5, 6, 7, 8,
            % SCID length
            16#08,
            % SCID
            8, 7, 6, 5, 4, 3, 2, 1,
            % Token length (varint)
            16#00,
            % Length (varint)
            16#41, 16#23,
            % Packet number (4 bytes)
            16#00, 16#00, 16#00, 16#01>>,

    %% Need encrypted payload for sample (at least 20 bytes)
    EncryptedPayload = crypto:strong_rand_bytes(32),

    %% PN offset is position of PN in header

    % = 26
    PNOffset = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2,
    % = 4
    PNLen = (FirstByte band 16#03) + 1,

    Protected = quic_aead:protect_header(HP, Header, EncryptedPayload, PNOffset),

    %% Protected should be same length as original
    ?assertEqual(byte_size(Header), byte_size(Protected)),

    %% For unprotect_header, we need to split: header without PN, and PN + ciphertext
    <<ProtectedHeaderWithoutPN:PNOffset/binary, ProtectedPN:PNLen/binary>> = Protected,
    EncryptedPayloadWithPN = <<ProtectedPN/binary, EncryptedPayload/binary>>,

    %% Unprotect should recover original
    {Unprotected, UnprotPNLen} = quic_aead:unprotect_header(
        HP, ProtectedHeaderWithoutPN, EncryptedPayloadWithPN, PNOffset
    ),
    ?assertEqual(PNLen, UnprotPNLen),
    ?assertEqual(Header, Unprotected).

header_protection_roundtrip_short_test() ->
    %% Test with a short header (1-RTT packet)
    HP = crypto:strong_rand_bytes(16),

    %% Short header: first byte has 0x80 bit clear
    %% Format: flags (1) + DCID (8) + PN (1-4)

    % Short header, 1-RTT, spin bit clear, PN len = 1 (bits 0-1 = 0)
    FirstByte = 16#40,
    Header =
        <<FirstByte,
            % DCID (8 bytes)
            1, 2, 3, 4, 5, 6, 7, 8,
            % PN (1 byte)
            16#42>>,

    EncryptedPayload = crypto:strong_rand_bytes(32),
    % 1 + 8
    PNOffset = 9,
    % = 1
    PNLen = (FirstByte band 16#03) + 1,

    Protected = quic_aead:protect_header(HP, Header, EncryptedPayload, PNOffset),

    %% For unprotect_header, split header without PN, and PN + ciphertext
    <<ProtectedHeaderWithoutPN:PNOffset/binary, ProtectedPN:PNLen/binary>> = Protected,
    EncryptedPayloadWithPN = <<ProtectedPN/binary, EncryptedPayload/binary>>,

    {Unprotected, UnprotPNLen} = quic_aead:unprotect_header(
        HP, ProtectedHeaderWithoutPN, EncryptedPayloadWithPN, PNOffset
    ),
    ?assertEqual(PNLen, UnprotPNLen),
    ?assertEqual(Header, Unprotected).

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
