%%% -*- erlang -*-
%%%
%%% QUIC Version Tests
%%% RFC 9000 Section 6 - Version Negotiation
%%%
%%% Tests for QUIC version handling and related functionality.

-module(quic_version_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% RFC 9000 Section 6 - Version Negotiation Basics
%%====================================================================

%% Test that QUIC v1 version constant is correct
quic_v1_version_test() ->
    %% RFC 9000 Section 15: QUIC v1 is 0x00000001
    ?assertEqual(16#00000001, ?QUIC_VERSION_1).

%% Test that QUIC v2 version constant is correct
quic_v2_version_test() ->
    %% RFC 9369: QUIC v2 is 0x6b3343cf
    ?assertEqual(16#6b3343cf, ?QUIC_VERSION_2).

%%====================================================================
%% Version in Packet Headers
%%====================================================================

%% Initial packet contains correct version
initial_packet_version_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => <<>>, payload => <<"test">>}
    ),

    %% Parse header to verify version
    <<_FirstByte, Version:32, _Rest/binary>> = Encoded,
    ?assertEqual(?QUIC_VERSION_1, Version).

%% Handshake packet contains correct version
handshake_packet_version_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        handshake,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => <<"test">>}
    ),

    <<_FirstByte, Version:32, _Rest/binary>> = Encoded,
    ?assertEqual(?QUIC_VERSION_1, Version).

%% 0-RTT packet contains correct version
zero_rtt_packet_version_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        zero_rtt,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => <<"early data">>}
    ),

    <<_FirstByte, Version:32, _Rest/binary>> = Encoded,
    ?assertEqual(?QUIC_VERSION_1, Version).

%% Retry packet contains correct version
retry_packet_version_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Token = <<"retry_token">>,
    Tag = crypto:strong_rand_bytes(16),

    Encoded = quic_packet:encode_long(
        retry,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => <<Token/binary, Tag/binary>>}
    ),

    <<_FirstByte, Version:32, _Rest/binary>> = Encoded,
    ?assertEqual(?QUIC_VERSION_1, Version).

%%====================================================================
%% Version in Decoded Packets
%%====================================================================

%% Decode Initial packet with correct version
decode_initial_version_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => <<>>, payload => <<"test">>, pn => 0}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(?QUIC_VERSION_1, Packet#quic_packet.version),
    ?assertEqual(initial, Packet#quic_packet.type).

%% Decode Handshake packet with correct version
decode_handshake_version_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        handshake,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => <<"test">>, pn => 0}
    ),

    {ok, Packet, <<>>} = quic_packet:decode(Encoded, 8),
    ?assertEqual(?QUIC_VERSION_1, Packet#quic_packet.version).

%%====================================================================
%% Version-Specific Initial Salt (RFC 9001)
%%====================================================================

%% QUIC v1 uses specific initial salt
quic_v1_initial_salt_test() ->
    ExpectedSalt =
        <<16#38, 16#76, 16#2c, 16#f7, 16#f5, 16#59, 16#34, 16#b3, 16#4d, 16#17, 16#9a, 16#e6, 16#a4,
            16#c8, 16#0c, 16#ad, 16#cc, 16#bb, 16#7f, 16#0a>>,
    ?assertEqual(ExpectedSalt, ?QUIC_V1_INITIAL_SALT).

%% QUIC v2 uses different initial salt (RFC 9369)
%% Just verify it exists and is 20 bytes like v1
quic_v2_initial_salt_test() ->
    V2Salt = ?QUIC_V2_INITIAL_SALT,
    V1Salt = ?QUIC_V1_INITIAL_SALT,
    %% Both salts should be 20 bytes
    ?assertEqual(20, byte_size(V2Salt)),
    %% V1 and V2 salts should be different
    ?assert(V1Salt =/= V2Salt).

%%====================================================================
%% Initial Keys for Different Versions
%%====================================================================

%% Initial secret derivation works for v1
initial_secret_v1_test() ->
    DCID = crypto:strong_rand_bytes(8),
    Secret = quic_keys:derive_initial_secret(DCID),
    ?assertEqual(32, byte_size(Secret)).

%% Initial client keys derivation for v1
initial_client_keys_v1_test() ->
    DCID = crypto:strong_rand_bytes(8),
    {Key, IV, HP} = quic_keys:derive_initial_client(DCID),
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(16, byte_size(HP)).

%% Initial server keys derivation for v1
initial_server_keys_v1_test() ->
    DCID = crypto:strong_rand_bytes(8),
    {Key, IV, HP} = quic_keys:derive_initial_server(DCID),
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(16, byte_size(HP)).

%% Same DCID produces same initial secrets (deterministic)
initial_secret_deterministic_test() ->
    DCID = <<"fixed_dcid">>,
    Secret1 = quic_keys:derive_initial_secret(DCID),
    Secret2 = quic_keys:derive_initial_secret(DCID),
    ?assertEqual(Secret1, Secret2).

%% Different DCIDs produce different initial secrets
initial_secret_varies_test() ->
    DCID1 = <<"dcid_one">>,
    DCID2 = <<"dcid_two">>,
    Secret1 = quic_keys:derive_initial_secret(DCID1),
    Secret2 = quic_keys:derive_initial_secret(DCID2),
    ?assertNotEqual(Secret1, Secret2).

%%====================================================================
%% RFC 9001 Appendix A - Initial Keys Test Vector
%%====================================================================

%% RFC 9001 Appendix A.1 test vector
rfc9001_initial_keys_test() ->
    %% The Destination Connection ID used in the RFC test
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    %% Expected Initial secret
    ExpectedSecret =
        <<16#7d, 16#b5, 16#df, 16#06, 16#e7, 16#a6, 16#9e, 16#43, 16#24, 16#96, 16#ad, 16#ed, 16#b0,
            16#08, 16#51, 16#92, 16#35, 16#95, 16#22, 16#15, 16#96, 16#ae, 16#2a, 16#e9, 16#fb,
            16#81, 16#15, 16#c1, 16#e9, 16#ed, 16#0a, 16#44>>,

    Secret = quic_keys:derive_initial_secret(DCID),
    ?assertEqual(ExpectedSecret, Secret).

%% RFC 9001 Appendix A.1 - Client Initial Key
rfc9001_client_key_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    ExpectedKey =
        <<16#1f, 16#36, 16#96, 16#13, 16#dd, 16#76, 16#d5, 16#46, 16#77, 16#30, 16#ef, 16#cb, 16#e3,
            16#b1, 16#a2, 16#2d>>,

    {Key, _IV, _HP} = quic_keys:derive_initial_client(DCID),
    ?assertEqual(ExpectedKey, Key).

%% RFC 9001 Appendix A.1 - Client Initial IV
rfc9001_client_iv_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    ExpectedIV =
        <<16#fa, 16#04, 16#4b, 16#2f, 16#42, 16#a3, 16#fd, 16#3b, 16#46, 16#fb, 16#25, 16#5c>>,

    {_Key, IV, _HP} = quic_keys:derive_initial_client(DCID),
    ?assertEqual(ExpectedIV, IV).

%% RFC 9001 Appendix A.1 - Client Header Protection Key
rfc9001_client_hp_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    ExpectedHP =
        <<16#9f, 16#50, 16#44, 16#9e, 16#04, 16#a0, 16#e8, 16#10, 16#28, 16#3a, 16#1e, 16#99, 16#33,
            16#ad, 16#ed, 16#d2>>,

    {_Key, _IV, HP} = quic_keys:derive_initial_client(DCID),
    ?assertEqual(ExpectedHP, HP).

%% RFC 9001 Appendix A.1 - Server Initial Key
rfc9001_server_key_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    ExpectedKey =
        <<16#cf, 16#3a, 16#53, 16#31, 16#65, 16#3c, 16#36, 16#4c, 16#88, 16#f0, 16#f3, 16#79, 16#b6,
            16#06, 16#7e, 16#37>>,

    {Key, _IV, _HP} = quic_keys:derive_initial_server(DCID),
    ?assertEqual(ExpectedKey, Key).

%% RFC 9001 Appendix A.1 - Server Initial IV
rfc9001_server_iv_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    ExpectedIV =
        <<16#0a, 16#c1, 16#49, 16#3c, 16#a1, 16#90, 16#58, 16#53, 16#b0, 16#bb, 16#a0, 16#3e>>,

    {_Key, IV, _HP} = quic_keys:derive_initial_server(DCID),
    ?assertEqual(ExpectedIV, IV).

%% RFC 9001 Appendix A.1 - Server Header Protection Key
rfc9001_server_hp_test() ->
    DCID = <<16#83, 16#94, 16#c8, 16#f0, 16#3e, 16#51, 16#57, 16#08>>,

    ExpectedHP =
        <<16#c2, 16#06, 16#b8, 16#d9, 16#b9, 16#f0, 16#f3, 16#76, 16#44, 16#43, 16#0b, 16#49, 16#0e,
            16#ea, 16#a3, 16#14>>,

    {_Key, _IV, HP} = quic_keys:derive_initial_server(DCID),
    ?assertEqual(ExpectedHP, HP).

%%====================================================================
%% Long Header Packet Types (RFC 9000 Section 17.2)
%%====================================================================

%% Verify Initial packet type encoding (bits 00)
initial_packet_type_bits_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => <<>>, payload => <<"test">>}
    ),

    <<FirstByte, _/binary>> = Encoded,
    TypeBits = (FirstByte bsr 4) band 2#11,
    % Initial = 00
    ?assertEqual(0, TypeBits).

%% Verify 0-RTT packet type encoding (bits 01)
zero_rtt_packet_type_bits_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        zero_rtt,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => <<"test">>}
    ),

    <<FirstByte, _/binary>> = Encoded,
    TypeBits = (FirstByte bsr 4) band 2#11,
    % 0-RTT = 01
    ?assertEqual(1, TypeBits).

%% Verify Handshake packet type encoding (bits 10)
handshake_packet_type_bits_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        handshake,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => <<"test">>}
    ),

    <<FirstByte, _/binary>> = Encoded,
    TypeBits = (FirstByte bsr 4) band 2#11,
    % Handshake = 10
    ?assertEqual(2, TypeBits).

%% Verify Retry packet type encoding (bits 11)
retry_packet_type_bits_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        retry,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{payload => crypto:strong_rand_bytes(32)}
    ),

    <<FirstByte, _/binary>> = Encoded,
    TypeBits = (FirstByte bsr 4) band 2#11,
    % Retry = 11
    ?assertEqual(3, TypeBits).

%%====================================================================
%% Long Header Fixed Bit (RFC 9000 Section 17.2)
%%====================================================================

%% RFC 9000: First bit (Form) must be 1 for long header
long_header_form_bit_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => <<>>, payload => <<"test">>}
    ),

    <<FirstByte, _/binary>> = Encoded,
    FormBit = (FirstByte bsr 7) band 1,
    ?assertEqual(1, FormBit).

%% RFC 9000: Second bit (Fixed) must be 1
long_header_fixed_bit_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_long(
        initial,
        ?QUIC_VERSION_1,
        DCID,
        SCID,
        #{token => <<>>, payload => <<"test">>}
    ),

    <<FirstByte, _/binary>> = Encoded,
    FixedBit = (FirstByte bsr 6) band 1,
    ?assertEqual(1, FixedBit).

%%====================================================================
%% Short Header (RFC 9000 Section 17.3)
%%====================================================================

%% RFC 9000: First bit (Form) must be 0 for short header
short_header_form_bit_test() ->
    DCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_short(DCID, 42, <<"data">>, false),

    <<FirstByte, _/binary>> = Encoded,
    FormBit = (FirstByte bsr 7) band 1,
    ?assertEqual(0, FormBit).

%% RFC 9000: Second bit (Fixed) must be 1 for short header
short_header_fixed_bit_test() ->
    DCID = crypto:strong_rand_bytes(8),

    Encoded = quic_packet:encode_short(DCID, 42, <<"data">>, false),

    <<FirstByte, _/binary>> = Encoded,
    FixedBit = (FirstByte bsr 6) band 1,
    ?assertEqual(1, FixedBit).
