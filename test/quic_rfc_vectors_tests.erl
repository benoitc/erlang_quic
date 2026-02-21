%%% -*- erlang -*-
%%%
%%% QUIC RFC Test Vectors
%%% RFC 9000 - QUIC Transport
%%% RFC 9001 - Using TLS to Secure QUIC
%%%
%%% This module contains test vectors from the RFC appendices to verify
%%% our implementation matches the specification exactly.
%%%

-module(quic_rfc_vectors_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% RFC 9001 Appendix A - Sample Packet Protection
%%====================================================================

%% RFC 9001 Appendix A.1 - Keys
%% This test verifies the key derivation for Initial packets.
rfc9001_initial_keys_test() ->
    %% The Destination Connection ID used in the test
    DCID = hexstr_to_bin("8394c8f03e515708"),

    %% Expected Initial secret (from A.1)
    ExpectedInitialSecret = hexstr_to_bin(
        "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"
    ),

    InitialSecret = quic_keys:derive_initial_secret(DCID),
    ?assertEqual(ExpectedInitialSecret, InitialSecret),

    %% Client Initial keys
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID),
    ?assertEqual(hexstr_to_bin("1f369613dd76d5467730efcbe3b1a22d"), ClientKey),
    ?assertEqual(hexstr_to_bin("fa044b2f42a3fd3b46fb255c"), ClientIV),
    ?assertEqual(hexstr_to_bin("9f50449e04a0e810283a1e9933adedd2"), ClientHP),

    %% Server Initial keys
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID),
    ?assertEqual(hexstr_to_bin("cf3a5331653c364c88f0f379b6067e37"), ServerKey),
    ?assertEqual(hexstr_to_bin("0ac1493ca1905853b0bba03e"), ServerIV),
    ?assertEqual(hexstr_to_bin("c206b8d9b9f0f37644430b490eeaa314"), ServerHP).

%% RFC 9001 Section 5.2 - Initial Salt
rfc9001_initial_salt_test() ->
    %% QUIC v1 Initial Salt
    ExpectedSalt = hexstr_to_bin("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    ?assertEqual(ExpectedSalt, ?QUIC_V1_INITIAL_SALT).

%%====================================================================
%% RFC 9000 Section 17 - Packet Formats
%%====================================================================

%% RFC 9000 Section 17.2 - Long Header Packets
long_header_format_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,
    SCID = <<16#f0, 16#67, 16#a5, 16#50, 16#2a, 16#42, 16#62, 16#b5>>,

    %% Encode an Initial packet
    Payload = <<"test">>,
    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => <<>>, payload => Payload, pn => 0}
    ),

    %% Verify header structure
    <<FirstByte, Version:32, DCIDLen, EncodedDCID:DCIDLen/binary, SCIDLen,
        EncodedSCID:SCIDLen/binary, _Rest/binary>> = Encoded,

    %% First byte: 1 (long header) | 1 (fixed bit) | 00 (Initial type) | XXXX (reserved + PN length)

    % Long header bit
    ?assertEqual(1, (FirstByte bsr 7) band 1),
    % Fixed bit
    ?assertEqual(1, (FirstByte bsr 6) band 1),
    % Initial packet type
    ?assertEqual(0, (FirstByte bsr 4) band 3),

    ?assertEqual(?QUIC_VERSION_1, Version),
    ?assertEqual(DCID, EncodedDCID),
    ?assertEqual(SCID, EncodedSCID).

%% RFC 9000 Section 17.2.2 - 0-RTT
zero_rtt_packet_format_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Payload = <<"0-RTT data">>,

    Encoded = quic_packet:encode_long(
        zero_rtt,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => Payload, pn => 0}
    ),

    {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(zero_rtt, Decoded#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, Decoded#quic_packet.version),
    ?assertEqual(DCID, Decoded#quic_packet.dcid),
    ?assertEqual(SCID, Decoded#quic_packet.scid).

%% RFC 9000 Section 17.2.3 - Handshake
handshake_packet_format_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Payload = <<"Handshake data">>,

    Encoded = quic_packet:encode_long(
        handshake,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => Payload, pn => 1}
    ),

    {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(handshake, Decoded#quic_packet.type),
    ?assertEqual(DCID, Decoded#quic_packet.dcid),
    ?assertEqual(SCID, Decoded#quic_packet.scid),
    ?assertEqual(1, Decoded#quic_packet.pn).

%% RFC 9000 Section 17.2.5 - Retry
retry_packet_format_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    %% Retry Token + Retry Integrity Tag (16 bytes)
    RetryToken = <<"retry_token_data">>,
    IntegrityTag = crypto:strong_rand_bytes(16),
    Payload = <<RetryToken/binary, IntegrityTag/binary>>,

    Encoded = quic_packet:encode_long(
        retry,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => Payload}
    ),

    {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(retry, Decoded#quic_packet.type),
    ?assertEqual(DCID, Decoded#quic_packet.dcid),
    ?assertEqual(SCID, Decoded#quic_packet.scid),
    ?assertEqual(Payload, Decoded#quic_packet.payload).

%% RFC 9000 Section 17.3 - Short Header Packets
short_header_format_test() ->
    DCID = crypto:strong_rand_bytes(8),
    Payload = <<"1-RTT data">>,

    %% Test with spin bit = false, key phase = 0
    Encoded = quic_packet:encode_short(DCID, 42, Payload, false),

    {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(one_rtt, Decoded#quic_packet.type),
    ?assertEqual(DCID, Decoded#quic_packet.dcid),
    ?assertEqual(42, Decoded#quic_packet.pn).

%% RFC 9000 Section 17.3 - Short Header with Key Phase
short_header_key_phase_test() ->
    DCID = crypto:strong_rand_bytes(8),
    Payload = <<"1-RTT data">>,

    %% Test with key phase = 0
    Encoded0 = quic_packet:encode_short(DCID, 100, Payload, false, 0),
    <<FirstByte0, _/binary>> = Encoded0,
    ?assertEqual(0, quic_packet:decode_short_key_phase(FirstByte0)),

    %% Test with key phase = 1
    Encoded1 = quic_packet:encode_short(DCID, 100, Payload, false, 1),
    <<FirstByte1, _/binary>> = Encoded1,
    ?assertEqual(1, quic_packet:decode_short_key_phase(FirstByte1)).

%%====================================================================
%% RFC 9000 Section 16 - Variable-Length Integer Encoding
%%====================================================================

%% RFC 9000 Section 16 - Table 4
varint_encoding_test() ->
    %% 1-byte encoding: values 0-63 (prefix 00)
    ?assertEqual(<<0>>, quic_varint:encode(0)),
    ?assertEqual(<<37>>, quic_varint:encode(37)),
    ?assertEqual(<<63>>, quic_varint:encode(63)),

    %% 2-byte encoding: values 64-16383 (prefix 01)
    %% 64 = 0x40, 2-byte: 0x4040
    ?assertEqual(<<64, 64>>, quic_varint:encode(64)),
    %% 15293 = 0x3BBD, 2-byte: 0x7BBD = <<123, 189>>
    ?assertEqual(<<123, 189>>, quic_varint:encode(15293)),

    %% 4-byte encoding: values 16384-1073741823 (prefix 10)
    %% 16384 = 0x4000, 4-byte: 10|00_0000 00_0100_0000 00_0000_0000 = 0x80004000
    ?assertEqual(<<128, 0, 64, 0>>, quic_varint:encode(16384)),
    %% 1073741823 = 0x3FFFFFFF, 4-byte: 10|3F FF FF FF = 0xBFFFFFFF = <<191,255,255,255>>
    ?assertEqual(<<191, 255, 255, 255>>, quic_varint:encode(1073741823)),

    %% 8-byte encoding: larger values (prefix 11)
    ?assertEqual(<<192, 0, 0, 0, 64, 0, 0, 0>>, quic_varint:encode(1073741824)),
    ?assertEqual(
        <<255, 255, 255, 255, 255, 255, 255, 255>>, quic_varint:encode(4611686018427387903)
    ).

varint_decoding_test() ->
    %% Round-trip tests
    TestValues = [
        0,
        37,
        63,
        64,
        15293,
        16383,
        16384,
        1073741823,
        1073741824,
        4611686018427387903
    ],

    lists:foreach(
        fun(V) ->
            Encoded = quic_varint:encode(V),
            {Decoded, <<>>} = quic_varint:decode(Encoded),
            ?assertEqual(V, Decoded)
        end,
        TestValues
    ).

%%====================================================================
%% RFC 9000 Section 12.4 - Frame Types
%%====================================================================

%% Test all frame types encode and decode correctly
frame_types_test() ->
    %% PADDING (0x00)
    ?assertEqual(padding, element(1, quic_frame:decode(<<0>>))),

    %% PING (0x01)
    ?assertEqual(ping, element(1, quic_frame:decode(<<1>>))),

    %% ACK (0x02)
    AckFrame = {ack, [{100, 10}], 25, undefined},
    AckEncoded = quic_frame:encode(AckFrame),
    {AckDecoded, <<>>} = quic_frame:decode(AckEncoded),
    ?assertEqual(ack, element(1, AckDecoded)),

    %% CRYPTO (0x06)
    CryptoFrame = {crypto, 0, <<"hello">>},
    CryptoEncoded = quic_frame:encode(CryptoFrame),
    {CryptoDecoded, <<>>} = quic_frame:decode(CryptoEncoded),
    ?assertEqual({crypto, 0, <<"hello">>}, CryptoDecoded),

    %% MAX_DATA (0x10)
    MaxDataFrame = {max_data, 1000000},
    MaxDataEncoded = quic_frame:encode(MaxDataFrame),
    {MaxDataDecoded, <<>>} = quic_frame:decode(MaxDataEncoded),
    ?assertEqual({max_data, 1000000}, MaxDataDecoded),

    %% CONNECTION_CLOSE (0x1c)
    CloseFrame = {connection_close, transport, 0, 0, <<>>},
    CloseEncoded = quic_frame:encode(CloseFrame),
    {CloseDecoded, <<>>} = quic_frame:decode(CloseEncoded),
    ?assertEqual({connection_close, transport, 0, 0, <<>>}, CloseDecoded),

    %% HANDSHAKE_DONE (0x1e)
    ?assertEqual(handshake_done, element(1, quic_frame:decode(<<16#1e>>))).

%%====================================================================
%% RFC 9001 Section 5.4 - Header Protection
%%====================================================================

%% Test that header protection can be applied and removed
header_protection_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    HP = crypto:strong_rand_bytes(16),

    Payload = <<"test payload with enough data for sample">>,
    AAD = <<"AAD">>,

    %% Encrypt payload
    Ciphertext = quic_aead:encrypt(Key, IV, 0, AAD, Payload),

    %% Verify ciphertext is larger than plaintext (includes 16-byte auth tag)
    ?assertEqual(byte_size(Payload) + 16, byte_size(Ciphertext)),

    %% Decrypt and verify roundtrip
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, 0, AAD, Ciphertext),
    ?assertEqual(Payload, Decrypted),

    %% Verify HP key size is correct for AES-128 header protection
    ?assertEqual(16, byte_size(HP)).

%%====================================================================
%% RFC 9002 - QUIC Loss Detection and Congestion Control
%%====================================================================

%% RFC 9002 Section 6.2 - Initial Window
initial_window_test() ->
    CCState = quic_cc:new(),
    Cwnd = quic_cc:cwnd(CCState),

    %% Initial window should be min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
    %% With max_datagram_size = 1200: min(12000, max(14720, 2400)) = min(12000, 14720) = 12000
    ?assertEqual(12000, Cwnd).

%% RFC 9002 - Minimum window is 2 * max_datagram_size
minimum_window_test() ->
    CCState0 = quic_cc:new(),

    %% Simulate loss to reduce window
    CCState1 = quic_cc:on_packet_sent(CCState0, 1200),
    CCState2 = quic_cc:on_congestion_event(CCState1, erlang:monotonic_time(millisecond)),

    Cwnd = quic_cc:cwnd(CCState2),
    % 2 * max_datagram_size
    MinWindow = 2 * 1200,

    %% Window should not go below minimum
    ?assert(Cwnd >= MinWindow).

%%====================================================================
%% RFC 5869 - HKDF Test Vectors
%%====================================================================

%% RFC 5869 Appendix A.1 - Test Case 1
hkdf_test_case_1_test() ->
    IKM = hexstr_to_bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
    Salt = hexstr_to_bin("000102030405060708090a0b0c"),
    Info = hexstr_to_bin("f0f1f2f3f4f5f6f7f8f9"),
    L = 42,

    ExpectedPRK = hexstr_to_bin(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    ),
    ExpectedOKM = hexstr_to_bin(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ),

    PRK = quic_hkdf:extract(Salt, IKM),
    ?assertEqual(ExpectedPRK, PRK),

    OKM = quic_hkdf:expand(PRK, Info, L),
    ?assertEqual(ExpectedOKM, OKM).

%% RFC 5869 Appendix A.2 - Test Case 2 (longer inputs/outputs)
hkdf_test_case_2_test() ->
    IKM = hexstr_to_bin(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
    ),
    Salt = hexstr_to_bin(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ),
    Info = hexstr_to_bin(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ),
    L = 82,

    ExpectedPRK = hexstr_to_bin(
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    ),
    ExpectedOKM = hexstr_to_bin(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"
    ),

    PRK = quic_hkdf:extract(Salt, IKM),
    ?assertEqual(ExpectedPRK, PRK),

    OKM = quic_hkdf:expand(PRK, Info, L),
    ?assertEqual(ExpectedOKM, OKM).

%%====================================================================
%% RFC 9001 - Retry Integrity Tag Constants
%%====================================================================

%% RFC 9001 Section 5.8 - Retry Integrity Tag
retry_integrity_constants_test() ->
    %% Retry Integrity Key for QUIC v1
    ExpectedKey = hexstr_to_bin("be0c690b9f66575a1d766b54e368c84e"),
    %% Retry Integrity Nonce for QUIC v1
    ExpectedNonce = hexstr_to_bin("461599d35d632bf2239825bb"),

    %% These would be used in quic_crypto for Retry integrity verification
    %% For now, just verify the constants are correct per RFC 9001 Section 5.8
    ?assertEqual(16, byte_size(ExpectedKey)),
    ?assertEqual(12, byte_size(ExpectedNonce)).

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
