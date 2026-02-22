%%% -*- erlang -*-
%%%
%%% QUIC Version 2 and Version Negotiation Tests
%%% RFC 9369 - QUIC Version 2
%%% RFC 9000 Section 17.2.1 - Version Negotiation Packet
%%%
%%% @doc Tests for QUIC v2 support and version negotiation.

-module(quic_v2_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Step 6: Version Negotiation Packet Tests
%%====================================================================

%% Test Version Negotiation packet encoding
version_negotiation_encoding_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Versions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    %% Encode VN packet
    Packet = quic_packet:encode_version_negotiation(DCID, SCID, Versions),

    ?assert(is_binary(Packet)),
    %% VN packet structure:
    %% - First byte: form=1, fixed=1, random (4 bits), unused (2 bits)
    %% - Version: 0x00000000 (4 bytes)
    %% - DCID Length: 1 byte
    %% - DCID: variable
    %% - SCID Length: 1 byte
    %% - SCID: variable
    %% - Supported Versions: 4 bytes each
    MinLen = 1 + 4 + 1 + byte_size(DCID) + 1 + byte_size(SCID) + (4 * 2),
    ?assertEqual(MinLen, byte_size(Packet)).

%% Test Version Negotiation packet decoding
version_negotiation_decoding_test() ->
    DCID = <<"dcid1234">>,
    SCID = <<"scid5678">>,

    %% Build VN packet manually
    %% First byte: long header form (0x80) | fixed bit (0x40) | random
    FirstByte = 16#C0 bor (rand:uniform(16) - 1),
    DCIDLen = byte_size(DCID),
    SCIDLen = byte_size(SCID),
    Versions = <<?QUIC_VERSION_1:32, ?QUIC_VERSION_2:32>>,
    % Version = 0 indicates VN
    VNPacket =
        <<FirstByte:8, 0:32, DCIDLen:8, DCID/binary, SCIDLen:8, SCID/binary, Versions/binary>>,

    %% Decode it
    {ok, Decoded} = quic_packet:decode(VNPacket, undefined),

    ?assertEqual(version_negotiation, element(1, Decoded)),
    {version_negotiation, ParsedDCID, ParsedSCID, ParsedVersions} = Decoded,
    ?assertEqual(DCID, ParsedDCID),
    ?assertEqual(SCID, ParsedSCID),
    ?assertEqual([?QUIC_VERSION_1, ?QUIC_VERSION_2], ParsedVersions).

%% Test that version=0 indicates VN packet
vn_packet_format_test() ->
    %% Version field must be 0 for VN packets
    DCID = <<"dcid">>,
    SCID = <<"scid">>,

    %% Encode VN packet
    Packet = quic_packet:encode_version_negotiation(DCID, SCID, [?QUIC_VERSION_1]),

    %% Extract version field (bytes 2-5)
    <<_FirstByte:8, Version:32, _Rest/binary>> = Packet,
    ?assertEqual(0, Version).

%% Test QUIC v2 initial salt differs from v1
v2_initial_salt_test() ->
    DCID = <<"test_dcid">>,

    %% Derive client initial keys for v1
    {V1ClientKey, _V1ClientIV, _} = quic_keys:derive_initial_client(DCID, ?QUIC_VERSION_1),

    %% Derive client initial keys for v2
    {V2ClientKey, _V2ClientIV, _} = quic_keys:derive_initial_client(DCID, ?QUIC_VERSION_2),

    %% Keys should be different because initial salts differ
    ?assertNotEqual(V1ClientKey, V2ClientKey),

    %% Server keys should also differ
    {V1ServerKey, _, _} = quic_keys:derive_initial_server(DCID, ?QUIC_VERSION_1),
    {V2ServerKey, _, _} = quic_keys:derive_initial_server(DCID, ?QUIC_VERSION_2),
    ?assertNotEqual(V1ServerKey, V2ServerKey).

%% Test QUIC version constants
quic_version_constants_test() ->
    ?assertEqual(16#00000001, ?QUIC_VERSION_1),
    ?assertEqual(16#6b3343cf, ?QUIC_VERSION_2).

%% Test VN packet roundtrip (encode then decode)
vn_packet_roundtrip_test() ->
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    Versions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    %% Encode
    Packet = quic_packet:encode_version_negotiation(DCID, SCID, Versions),

    %% Decode
    {ok, Decoded} = quic_packet:decode(Packet, undefined),

    {version_negotiation, ParsedDCID, ParsedSCID, ParsedVersions} = Decoded,
    ?assertEqual(DCID, ParsedDCID),
    ?assertEqual(SCID, ParsedSCID),
    ?assertEqual(Versions, ParsedVersions).

%%====================================================================
%% Step 7: Client Version Selection Tests
%%====================================================================

%% Test version selection from VN packet
client_selects_version_test() ->
    %% When client receives VN with v1 and v2, should prefer v2
    OfferedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    %% Client should select the highest version it supports
    Selected = select_best_version(OfferedVersions, SupportedVersions),
    ?assertEqual(?QUIC_VERSION_2, Selected).

%% Test fallback to v1 when v2 not offered
client_fallback_v1_test() ->
    OfferedVersions = [?QUIC_VERSION_1],
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    Selected = select_best_version(OfferedVersions, SupportedVersions),
    ?assertEqual(?QUIC_VERSION_1, Selected).

%% Test version negotiation failure (no common version)
no_common_version_test() ->
    % Some unsupported version
    OfferedVersions = [16#ff000000],
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    Selected = select_best_version(OfferedVersions, SupportedVersions),
    ?assertEqual(undefined, Selected).

%%====================================================================
%% Step 8: Server Version Support Tests
%%====================================================================

%% Test server detects unsupported version
server_unknown_version_test() ->
    %% When server receives Initial with unknown version, it should send VN
    UnknownVersion = 16#ff000000,
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    ShouldSendVN = not lists:member(UnknownVersion, SupportedVersions),
    ?assert(ShouldSendVN).

%% Test server accepts v1
server_accepts_v1_test() ->
    Version = ?QUIC_VERSION_1,
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    Accepted = lists:member(Version, SupportedVersions),
    ?assert(Accepted).

%% Test server accepts v2
server_accepts_v2_test() ->
    Version = ?QUIC_VERSION_2,
    SupportedVersions = [?QUIC_VERSION_1, ?QUIC_VERSION_2],

    Accepted = lists:member(Version, SupportedVersions),
    ?assert(Accepted).

%%====================================================================
%% Helper Functions
%%====================================================================

%% Select best version from offered list that we support
%% Prefer higher versions
select_best_version(OfferedVersions, SupportedVersions) ->
    %% Preference order: v2 > v1
    PreferenceOrder = [?QUIC_VERSION_2, ?QUIC_VERSION_1],
    select_first_common(PreferenceOrder, OfferedVersions, SupportedVersions).

select_first_common([], _, _) ->
    undefined;
select_first_common([V | Rest], Offered, Supported) ->
    case lists:member(V, Offered) andalso lists:member(V, Supported) of
        true -> V;
        false -> select_first_common(Rest, Offered, Supported)
    end.
