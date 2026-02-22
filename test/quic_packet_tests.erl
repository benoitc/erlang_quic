%%% -*- erlang -*-
%%%
%%% Tests for QUIC Packet Encoding/Decoding
%%% RFC 9000 Section 17
%%%

-module(quic_packet_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Packet Number Encoding
%%====================================================================

pn_length_test() ->
    ?assertEqual(1, quic_packet:pn_length(0)),
    ?assertEqual(1, quic_packet:pn_length(255)),
    ?assertEqual(2, quic_packet:pn_length(256)),
    ?assertEqual(2, quic_packet:pn_length(65535)),
    ?assertEqual(3, quic_packet:pn_length(65536)),
    ?assertEqual(3, quic_packet:pn_length(16777215)),
    ?assertEqual(4, quic_packet:pn_length(16777216)).

encode_pn_test() ->
    ?assertEqual(<<0>>, quic_packet:encode_pn(0, 1)),
    ?assertEqual(<<255>>, quic_packet:encode_pn(255, 1)),
    ?assertEqual(<<1, 0>>, quic_packet:encode_pn(256, 2)),
    ?assertEqual(<<255, 255>>, quic_packet:encode_pn(65535, 2)),
    ?assertEqual(<<1, 0, 0>>, quic_packet:encode_pn(65536, 3)),
    ?assertEqual(<<1, 0, 0, 0>>, quic_packet:encode_pn(16777216, 4)).

decode_pn_test() ->
    ?assertEqual({0, <<>>}, quic_packet:decode_pn(<<0>>, 1)),
    ?assertEqual({255, <<"rest">>}, quic_packet:decode_pn(<<255, "rest">>, 1)),
    ?assertEqual({256, <<>>}, quic_packet:decode_pn(<<1, 0>>, 2)),
    ?assertEqual({65536, <<>>}, quic_packet:decode_pn(<<1, 0, 0>>, 3)),
    ?assertEqual({16777216, <<>>}, quic_packet:decode_pn(<<1, 0, 0, 0>>, 4)).

%%====================================================================
%% Initial Packet
%%====================================================================

initial_packet_roundtrip_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<10, 20, 30, 40>>,
    Token = <<"initial_token">>,
    Payload = <<"encrypted_payload">>,
    PN = 0,

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => Token, pn => PN, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(initial, Packet#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, Packet#quic_packet.version),
    ?assertEqual(DCID, Packet#quic_packet.dcid),
    ?assertEqual(SCID, Packet#quic_packet.scid),
    ?assertEqual(Token, Packet#quic_packet.token),
    ?assertEqual(PN, Packet#quic_packet.pn),
    ?assertEqual(Payload, Packet#quic_packet.payload).

initial_packet_no_token_roundtrip_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<10, 20, 30, 40>>,
    Payload = <<"encrypted_payload">>,
    PN = 1,

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{pn => PN, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(initial, Packet#quic_packet.type),
    ?assertEqual(<<>>, Packet#quic_packet.token),
    ?assertEqual(PN, Packet#quic_packet.pn),
    ?assertEqual(Payload, Packet#quic_packet.payload).

initial_packet_large_pn_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<>>,
    Payload = <<"data">>,
    % Requires 2 bytes
    PN = 300,

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{pn => PN, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(PN, Packet#quic_packet.pn).

%%====================================================================
%% Handshake Packet
%%====================================================================

handshake_packet_roundtrip_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<10, 20, 30, 40>>,
    Payload = <<"handshake_data">>,
    PN = 2,

    Encoded = quic_packet:encode_long(
        handshake,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{pn => PN, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(handshake, Packet#quic_packet.type),
    ?assertEqual(?QUIC_VERSION_1, Packet#quic_packet.version),
    ?assertEqual(DCID, Packet#quic_packet.dcid),
    ?assertEqual(SCID, Packet#quic_packet.scid),
    ?assertEqual(PN, Packet#quic_packet.pn),
    ?assertEqual(Payload, Packet#quic_packet.payload).

%%====================================================================
%% 0-RTT Packet
%%====================================================================

zero_rtt_packet_roundtrip_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<10, 20, 30, 40>>,
    Payload = <<"0rtt_data">>,
    PN = 0,

    Encoded = quic_packet:encode_long(
        zero_rtt,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{pn => PN, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(zero_rtt, Packet#quic_packet.type),
    ?assertEqual(Payload, Packet#quic_packet.payload).

%%====================================================================
%% Retry Packet
%%====================================================================

retry_packet_roundtrip_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<10, 20, 30, 40>>,
    %% Retry payload = Retry Token + 16-byte Integrity Tag
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

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(retry, Packet#quic_packet.type),
    ?assertEqual(Payload, Packet#quic_packet.payload).

%%====================================================================
%% Short Header (1-RTT) Packet
%%====================================================================

short_packet_roundtrip_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Payload = <<"encrypted_app_data">>,
    PN = 100,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, false),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(one_rtt, Packet#quic_packet.type),
    ?assertEqual(DCID, Packet#quic_packet.dcid),
    ?assertEqual(PN, Packet#quic_packet.pn).

short_packet_with_spin_bit_test() ->
    DCID = <<1, 2, 3, 4>>,
    Payload = <<"data">>,
    PN = 0,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, true),

    %% Verify first byte has spin bit set (bit 5)
    <<FirstByte, _/binary>> = Encoded,
    SpinBit = (FirstByte bsr 5) band 1,
    ?assertEqual(1, SpinBit).

short_packet_large_pn_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Payload = <<"data">>,
    % Requires 3 bytes
    PN = 1000000,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, false),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(PN, Packet#quic_packet.pn).

%%====================================================================
%% Header Form Detection
%%====================================================================

long_header_detection_test() ->
    %% Long header starts with 1 in bit 7
    LongPacket = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        <<1, 2, 3, 4>>,
        <<5, 6, 7, 8>>,
        #{pn => 0, payload => <<"data">>}
    ),
    <<FirstByte, _/binary>> = LongPacket,
    ?assertEqual(1, (FirstByte bsr 7) band 1).

short_header_detection_test() ->
    %% Short header starts with 0 in bit 7, 1 in bit 6
    ShortPacket = quic_packet:encode_short(<<1, 2, 3, 4>>, 0, <<"data">>, false),
    <<FirstByte, _/binary>> = ShortPacket,
    ?assertEqual(0, (FirstByte bsr 7) band 1),
    ?assertEqual(1, (FirstByte bsr 6) band 1).

%%====================================================================
%% Empty Connection IDs
%%====================================================================

empty_dcid_test() ->
    DCID = <<>>,
    SCID = <<1, 2, 3, 4>>,
    Payload = <<"data">>,

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{pn => 0, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 0),
    ?assertEqual(<<>>, Packet#quic_packet.dcid).

empty_scid_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    SCID = <<>>,
    Payload = <<"data">>,

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{pn => 0, payload => Payload}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(<<>>, Packet#quic_packet.scid).

%%====================================================================
%% Key Phase Tests (RFC 9001 Section 6)
%%====================================================================

%% Test encoding short header with key phase 0
encode_short_key_phase_0_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Payload = <<"data">>,
    PN = 0,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, false, 0),

    %% Verify key phase bit is 0 (bit 2)
    <<FirstByte, _/binary>> = Encoded,
    KeyPhase = quic_packet:decode_short_key_phase(FirstByte),
    ?assertEqual(0, KeyPhase).

%% Test encoding short header with key phase 1
encode_short_key_phase_1_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Payload = <<"data">>,
    PN = 0,

    Encoded = quic_packet:encode_short(DCID, PN, Payload, false, 1),

    %% Verify key phase bit is 1 (bit 2)
    <<FirstByte, _/binary>> = Encoded,
    KeyPhase = quic_packet:decode_short_key_phase(FirstByte),
    ?assertEqual(1, KeyPhase).

%% Test decode_short_key_phase extracts the correct bit
decode_short_key_phase_test() ->
    %% First byte format: 0 | 1 | S | R | R | K | P P
    %% Key phase is bit 2, so:
    %% 0100 0100 = 0x44 -> key phase 1
    %% 0100 0000 = 0x40 -> key phase 0
    ?assertEqual(0, quic_packet:decode_short_key_phase(16#40)),
    ?assertEqual(1, quic_packet:decode_short_key_phase(16#44)),
    %% With spin bit set

    % 0110 0000
    ?assertEqual(0, quic_packet:decode_short_key_phase(16#60)),
    % 0110 0100
    ?assertEqual(1, quic_packet:decode_short_key_phase(16#64)).

%% Test that 4-arity encode_short is backward compatible (uses key phase 0)
encode_short_backward_compatible_test() ->
    DCID = <<1, 2, 3, 4, 5, 6, 7, 8>>,
    Payload = <<"data">>,
    PN = 0,

    %% 4-arity should produce same result as 5-arity with key_phase=0
    Encoded4 = quic_packet:encode_short(DCID, PN, Payload, false),
    Encoded5 = quic_packet:encode_short(DCID, PN, Payload, false, 0),
    ?assertEqual(Encoded4, Encoded5).

%% Test key phase and spin bit are independent
key_phase_and_spin_bit_independent_test() ->
    DCID = <<1, 2, 3, 4>>,
    Payload = <<"data">>,
    PN = 0,

    %% Test all combinations
    Encoded00 = quic_packet:encode_short(DCID, PN, Payload, false, 0),
    Encoded01 = quic_packet:encode_short(DCID, PN, Payload, false, 1),
    Encoded10 = quic_packet:encode_short(DCID, PN, Payload, true, 0),
    Encoded11 = quic_packet:encode_short(DCID, PN, Payload, true, 1),

    %% Extract first bytes
    <<FB00, _/binary>> = Encoded00,
    <<FB01, _/binary>> = Encoded01,
    <<FB10, _/binary>> = Encoded10,
    <<FB11, _/binary>> = Encoded11,

    %% Check spin bit (bit 5)
    ?assertEqual(0, (FB00 bsr 5) band 1),
    ?assertEqual(0, (FB01 bsr 5) band 1),
    ?assertEqual(1, (FB10 bsr 5) band 1),
    ?assertEqual(1, (FB11 bsr 5) band 1),

    %% Check key phase (bit 2)
    ?assertEqual(0, quic_packet:decode_short_key_phase(FB00)),
    ?assertEqual(1, quic_packet:decode_short_key_phase(FB01)),
    ?assertEqual(0, quic_packet:decode_short_key_phase(FB10)),
    ?assertEqual(1, quic_packet:decode_short_key_phase(FB11)).

%%====================================================================
%% Error Cases
%%====================================================================

decode_empty_test() ->
    ?assertEqual({error, empty}, quic_packet:decode(<<>>, 8)).
