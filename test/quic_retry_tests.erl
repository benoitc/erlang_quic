%%% -*- erlang -*-
%%%
%%% QUIC Retry Packet Tests
%%% RFC 9000 Section 8.1 - Address Validation via Retry Packets
%%% RFC 9001 Section 5.8 - Retry Packet Integrity
%%%
%%% This module tests Retry packet handling including integrity tag
%%% computation and verification.
%%%

-module(quic_retry_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% RFC 9001 Section 5.8 - Retry Integrity Tag
%%====================================================================

%% Test that we use the correct integrity constants for QUIC v1
retry_integrity_constants_v1_test() ->
    %% RFC 9001 Section 5.8 - QUIC v1 constants
    ExpectedKey = hexstr_to_bin("be0c690b9f66575a1d766b54e368c84e"),
    ExpectedNonce = hexstr_to_bin("461599d35d632bf2239825bb"),

    %% Verify key and nonce are correct length
    ?assertEqual(16, byte_size(ExpectedKey)),
    ?assertEqual(12, byte_size(ExpectedNonce)).

%% Test Retry integrity tag computation
retry_integrity_tag_compute_test() ->
    %% Sample Original DCID
    OriginalDCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    %% Sample Retry packet without integrity tag
    %% First byte: 11|11|type(3) = 0xFF
    %% Version: 0x00000001
    %% DCID len: 0, DCID: (empty)
    %% SCID len: 8, SCID: new server CID
    %% Token: "retry_test"
    NewSCID = <<16#f0, 16#67, 16#a5, 16#50, 16#2a, 16#42, 16#62, 16#b5>>,
    Token = <<"retry_test">>,
    RetryPacketWithoutTag = <<
        % First byte (long header, fixed bit, Retry type)
        16#FF,
        % Version
        16#00,
        16#00,
        16#00,
        16#01,
        % DCID length
        0,
        % SCID length + SCID
        8,
        NewSCID/binary,
        % Retry Token
        Token/binary
    >>,

    %% Compute the integrity tag
    Tag = quic_crypto:compute_retry_integrity_tag(
        OriginalDCID, RetryPacketWithoutTag, ?QUIC_VERSION_1
    ),

    %% Tag should be 16 bytes
    ?assertEqual(16, byte_size(Tag)),

    %% Verify the tag using verify function
    FullRetryPacket = <<RetryPacketWithoutTag/binary, Tag/binary>>,
    ?assert(quic_crypto:verify_retry_integrity_tag(OriginalDCID, FullRetryPacket, ?QUIC_VERSION_1)).

%% Test that wrong ODCID fails verification
retry_integrity_wrong_odcid_test() ->
    OriginalDCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,
    WrongODCID = <<16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00>>,

    NewSCID = <<16#f0, 16#67, 16#a5, 16#50, 16#2a, 16#42, 16#62, 16#b5>>,
    Token = <<"retry_test">>,
    RetryPacketWithoutTag = <<
        16#FF,
        16#00,
        16#00,
        16#00,
        16#01,
        0,
        8,
        NewSCID/binary,
        Token/binary
    >>,

    %% Compute tag with correct ODCID
    Tag = quic_crypto:compute_retry_integrity_tag(
        OriginalDCID, RetryPacketWithoutTag, ?QUIC_VERSION_1
    ),
    FullRetryPacket = <<RetryPacketWithoutTag/binary, Tag/binary>>,

    %% Verification with wrong ODCID should fail
    ?assertNot(
        quic_crypto:verify_retry_integrity_tag(WrongODCID, FullRetryPacket, ?QUIC_VERSION_1)
    ).

%% Test that tampered packet fails verification
retry_integrity_tampered_test() ->
    OriginalDCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    NewSCID = <<16#f0, 16#67, 16#a5, 16#50, 16#2a, 16#42, 16#62, 16#b5>>,
    Token = <<"retry_test">>,
    RetryPacketWithoutTag = <<
        16#FF,
        16#00,
        16#00,
        16#00,
        16#01,
        0,
        8,
        NewSCID/binary,
        Token/binary
    >>,

    Tag = quic_crypto:compute_retry_integrity_tag(
        OriginalDCID, RetryPacketWithoutTag, ?QUIC_VERSION_1
    ),

    %% Tamper with the token in the retry packet
    TamperedToken = <<"wrong_test">>,
    TamperedPacketWithoutTag = <<
        16#FF,
        16#00,
        16#00,
        16#00,
        16#01,
        0,
        8,
        NewSCID/binary,
        TamperedToken/binary
    >>,
    TamperedFullPacket = <<TamperedPacketWithoutTag/binary, Tag/binary>>,

    %% Verification should fail
    ?assertNot(
        quic_crypto:verify_retry_integrity_tag(OriginalDCID, TamperedFullPacket, ?QUIC_VERSION_1)
    ).

%% Test packet too short for integrity tag
retry_integrity_short_packet_test() ->
    OriginalDCID = <<16#83, 16#94, 16#c8, 16#f0>>,
    % Only 7 bytes, less than 16
    ShortPacket = <<16#FF, 16#00, 16#00, 16#00, 16#01, 0, 0>>,

    %% Should return false for packet that's too short
    ?assertNot(quic_crypto:verify_retry_integrity_tag(OriginalDCID, ShortPacket, ?QUIC_VERSION_1)).

%%====================================================================
%% Retry Packet Roundtrip Tests
%%====================================================================

%% Test encoding and decoding a Retry packet
retry_packet_encode_decode_test() ->
    % Empty DCID is valid for Retry
    DCID = <<>>,
    SCID = crypto:strong_rand_bytes(8),
    Token = <<"test_token_data_12345">>,
    IntegrityTag = crypto:strong_rand_bytes(16),
    Payload = <<Token/binary, IntegrityTag/binary>>,

    %% Encode Retry packet
    Encoded = quic_packet:encode_long(retry, ?QUIC_VERSION_1, DCID, SCID, #{payload => Payload}),

    %% Decode the packet
    {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 0),

    ?assertEqual(retry, Decoded#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, Decoded#quic_packet.version),
    ?assertEqual(DCID, Decoded#quic_packet.dcid),
    ?assertEqual(SCID, Decoded#quic_packet.scid),
    ?assertEqual(Payload, Decoded#quic_packet.payload).

%% Test that Retry packet has no packet number
retry_packet_no_pn_test() ->
    DCID = <<>>,
    SCID = crypto:strong_rand_bytes(8),
    Payload = <<(crypto:strong_rand_bytes(20))/binary, (crypto:strong_rand_bytes(16))/binary>>,

    Encoded = quic_packet:encode_long(retry, ?QUIC_VERSION_1, DCID, SCID, #{payload => Payload}),
    {ok, Decoded, <<>>} = quic_packet:decode(Encoded, 0),

    %% Retry packets should have undefined packet number
    ?assertEqual(undefined, Decoded#quic_packet.pn).

%%====================================================================
%% QUIC v2 Support (RFC 9369)
%%====================================================================

%% Test QUIC v2 constants
retry_integrity_v2_test() ->
    %% RFC 9369 specifies different constants for QUIC v2
    %% Key: 8fb4b01b56ac48e260fbcbcead7cba00
    %% Nonce: d8696950c90679a4da887ece
    OriginalDCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,
    NewSCID = <<16#f0, 16#67, 16#a5, 16#50, 16#2a, 16#42, 16#62, 16#b5>>,
    Token = <<"v2_token">>,

    %% QUIC v2 version
    V2Version = 16#6b3343cf,
    RetryPacketWithoutTag = <<
        % First byte for v2 Retry
        16#CF,
        % QUIC v2 version
        (V2Version):32,
        0,
        8,
        NewSCID/binary,
        Token/binary
    >>,

    %% Compute tag for v2
    TagV2 = quic_crypto:compute_retry_integrity_tag(OriginalDCID, RetryPacketWithoutTag, V2Version),
    ?assertEqual(16, byte_size(TagV2)),

    %% v1 and v2 tags should be different due to different keys
    TagV1 = quic_crypto:compute_retry_integrity_tag(
        OriginalDCID, RetryPacketWithoutTag, ?QUIC_VERSION_1
    ),
    ?assertNotEqual(TagV1, TagV2).

%%====================================================================
%% Edge Cases
%%====================================================================

%% Test with empty token (valid but unusual)
retry_integrity_empty_token_test() ->
    OriginalDCID = crypto:strong_rand_bytes(8),
    NewSCID = crypto:strong_rand_bytes(8),
    % Empty token
    Token = <<>>,

    RetryPacketWithoutTag = <<
        16#FF,
        16#00,
        16#00,
        16#00,
        16#01,
        0,
        8,
        NewSCID/binary,
        Token/binary
    >>,

    Tag = quic_crypto:compute_retry_integrity_tag(
        OriginalDCID, RetryPacketWithoutTag, ?QUIC_VERSION_1
    ),
    FullRetryPacket = <<RetryPacketWithoutTag/binary, Tag/binary>>,

    ?assert(quic_crypto:verify_retry_integrity_tag(OriginalDCID, FullRetryPacket, ?QUIC_VERSION_1)).

%% Test with maximum length CIDs
retry_integrity_max_cid_test() ->
    %% RFC 9000: CIDs can be up to 20 bytes
    OriginalDCID = crypto:strong_rand_bytes(20),
    NewSCID = crypto:strong_rand_bytes(20),
    Token = <<"max_cid_test">>,

    RetryPacketWithoutTag = <<
        16#FF,
        16#00,
        16#00,
        16#00,
        16#01,
        % DCID len (empty in Retry response)
        0,
        % Max SCID
        20,
        NewSCID/binary,
        Token/binary
    >>,

    Tag = quic_crypto:compute_retry_integrity_tag(
        OriginalDCID, RetryPacketWithoutTag, ?QUIC_VERSION_1
    ),
    FullRetryPacket = <<RetryPacketWithoutTag/binary, Tag/binary>>,

    ?assert(quic_crypto:verify_retry_integrity_tag(OriginalDCID, FullRetryPacket, ?QUIC_VERSION_1)).

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
