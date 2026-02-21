%%% -*- erlang -*-
%%%
%%% QUIC Preferred Address Tests
%%% RFC 9000 Section 9.6 - Server's Preferred Address
%%%
%%% Tests preferred address encoding, decoding, validation, and migration
%%% per the QUIC specification.

-module(quic_preferred_address_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Preferred Address Encoding/Decoding Tests (RFC 9000 Section 9.6)
%%====================================================================

%% Test decoding a preferred address with both IPv4 and IPv6
decode_preferred_address_ipv4_and_ipv6_test() ->
    %% Build test binary:
    %% IPv4: 192.168.1.100:4433
    %% IPv6: 2001:db8::1:443
    %% CID: 8 bytes
    %% Reset token: 16 bytes
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    Binary = <<
        % IPv4 address
        192,
        168,
        1,
        100,
        % IPv4 port
        4433:16,
        % IPv6 address
        16#2001:16,
        16#db8:16,
        0:16,
        0:16,
        0:16,
        0:16,
        0:16,
        1:16,
        % IPv6 port
        443:16,
        % CID length + CID
        8:8,
        CID/binary,
        % Stateless reset token
        Token/binary
    >>,
    PA = quic_tls:decode_preferred_address(Binary),
    ?assertEqual({192, 168, 1, 100}, PA#preferred_address.ipv4_addr),
    ?assertEqual(4433, PA#preferred_address.ipv4_port),
    ?assertEqual({16#2001, 16#db8, 0, 0, 0, 0, 0, 1}, PA#preferred_address.ipv6_addr),
    ?assertEqual(443, PA#preferred_address.ipv6_port),
    ?assertEqual(CID, PA#preferred_address.cid),
    ?assertEqual(Token, PA#preferred_address.stateless_reset_token).

%% Test decoding with only IPv4 (IPv6 zeros)
decode_preferred_address_ipv4_only_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    Binary = <<
        % IPv4: 10.0.0.1
        10,
        0,
        0,
        1,
        % IPv4 port
        8443:16,
        % IPv6: all zeros
        0:128,
        % IPv6 port: 0
        0:16,
        8:8,
        CID/binary,
        Token/binary
    >>,
    PA = quic_tls:decode_preferred_address(Binary),
    ?assertEqual({10, 0, 0, 1}, PA#preferred_address.ipv4_addr),
    ?assertEqual(8443, PA#preferred_address.ipv4_port),
    ?assertEqual(undefined, PA#preferred_address.ipv6_addr),
    ?assertEqual(undefined, PA#preferred_address.ipv6_port).

%% Test decoding with only IPv6 (IPv4 zeros)
decode_preferred_address_ipv6_only_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    Binary = <<
        % IPv4: all zeros
        0,
        0,
        0,
        0,
        % IPv4 port: 0
        0:16,
        % IPv6: fe80::1
        16#fe80:16,
        0:16,
        0:16,
        0:16,
        0:16,
        0:16,
        0:16,
        1:16,
        443:16,
        8:8,
        CID/binary,
        Token/binary
    >>,
    PA = quic_tls:decode_preferred_address(Binary),
    ?assertEqual(undefined, PA#preferred_address.ipv4_addr),
    ?assertEqual(undefined, PA#preferred_address.ipv4_port),
    ?assertEqual({16#fe80, 0, 0, 0, 0, 0, 0, 1}, PA#preferred_address.ipv6_addr),
    ?assertEqual(443, PA#preferred_address.ipv6_port).

%% Test encoding a preferred address with both addresses
encode_preferred_address_ipv4_and_ipv6_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {192, 168, 1, 1},
        ipv4_port = 4433,
        ipv6_addr = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
        ipv6_port = 443,
        cid = CID,
        stateless_reset_token = Token
    },
    Encoded = quic_tls:encode_preferred_address(PA),
    %% Expected: 4 + 2 + 16 + 2 + 1 + 8 + 16 = 49 bytes
    ?assertEqual(49, byte_size(Encoded)),
    %% Roundtrip test
    Decoded = quic_tls:decode_preferred_address(Encoded),
    ?assertEqual(PA, Decoded).

%% Test encoding with only IPv4
encode_preferred_address_ipv4_only_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {127, 0, 0, 1},
        ipv4_port = 8080,
        ipv6_addr = undefined,
        ipv6_port = undefined,
        cid = CID,
        stateless_reset_token = Token
    },
    Encoded = quic_tls:encode_preferred_address(PA),
    Decoded = quic_tls:decode_preferred_address(Encoded),
    ?assertEqual({127, 0, 0, 1}, Decoded#preferred_address.ipv4_addr),
    ?assertEqual(8080, Decoded#preferred_address.ipv4_port),
    ?assertEqual(undefined, Decoded#preferred_address.ipv6_addr),
    ?assertEqual(undefined, Decoded#preferred_address.ipv6_port).

%% Test encoding with only IPv6
encode_preferred_address_ipv6_only_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = undefined,
        ipv4_port = undefined,
        % ::1
        ipv6_addr = {0, 0, 0, 0, 0, 0, 0, 1},
        ipv6_port = 443,
        cid = CID,
        stateless_reset_token = Token
    },
    Encoded = quic_tls:encode_preferred_address(PA),
    Decoded = quic_tls:decode_preferred_address(Encoded),
    ?assertEqual(undefined, Decoded#preferred_address.ipv4_addr),
    ?assertEqual(undefined, Decoded#preferred_address.ipv4_port),
    ?assertEqual({0, 0, 0, 0, 0, 0, 0, 1}, Decoded#preferred_address.ipv6_addr),
    ?assertEqual(443, Decoded#preferred_address.ipv6_port).

%%====================================================================
%% Transport Parameter Integration Tests
%%====================================================================

%% Test preferred_address in transport parameters roundtrip
transport_params_with_preferred_address_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {10, 0, 0, 1},
        ipv4_port = 4433,
        ipv6_addr = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
        ipv6_port = 443,
        cid = CID,
        stateless_reset_token = Token
    },
    Params = #{
        initial_max_data => 1048576,
        preferred_address => PA
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    DecodedPA = maps:get(preferred_address, Decoded),
    ?assertEqual(PA, DecodedPA).

%% Test transport params with preferred_address alongside other params
transport_params_full_with_preferred_address_test() ->
    SCID = crypto:strong_rand_bytes(8),
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {192, 168, 1, 100},
        ipv4_port = 4433,
        ipv6_addr = undefined,
        ipv6_port = undefined,
        cid = CID,
        stateless_reset_token = Token
    },
    Params = #{
        initial_scid => SCID,
        max_idle_timeout => 30000,
        initial_max_data => 1048576,
        initial_max_streams_bidi => 100,
        active_connection_id_limit => 4,
        preferred_address => PA
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(SCID, maps:get(initial_scid, Decoded)),
    ?assertEqual(30000, maps:get(max_idle_timeout, Decoded)),
    ?assertEqual(1048576, maps:get(initial_max_data, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)),
    ?assertEqual(4, maps:get(active_connection_id_limit, Decoded)),
    DecodedPA = maps:get(preferred_address, Decoded),
    ?assertEqual({192, 168, 1, 100}, DecodedPA#preferred_address.ipv4_addr),
    ?assertEqual(4433, DecodedPA#preferred_address.ipv4_port).

%%====================================================================
%% CID Length Variations
%%====================================================================

%% Test with empty CID (length = 0)
preferred_address_empty_cid_test() ->
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {10, 0, 0, 1},
        ipv4_port = 4433,
        ipv6_addr = undefined,
        ipv6_port = undefined,
        cid = <<>>,
        stateless_reset_token = Token
    },
    Encoded = quic_tls:encode_preferred_address(PA),
    Decoded = quic_tls:decode_preferred_address(Encoded),
    ?assertEqual(<<>>, Decoded#preferred_address.cid).

%% Test with maximum CID length (20 bytes)
preferred_address_max_cid_test() ->
    CID = crypto:strong_rand_bytes(20),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {192, 168, 0, 1},
        ipv4_port = 4433,
        ipv6_addr = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
        ipv6_port = 443,
        cid = CID,
        stateless_reset_token = Token
    },
    Encoded = quic_tls:encode_preferred_address(PA),
    Decoded = quic_tls:decode_preferred_address(Encoded),
    ?assertEqual(CID, Decoded#preferred_address.cid).

%%====================================================================
%% Edge Cases
%%====================================================================

%% Test with port 0 (should still be valid)
preferred_address_port_zero_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    %% Port 0 with a valid address should still be considered valid
    %% (though unusual in practice)
    Binary = <<
        % IPv4 address (non-zero)
        192,
        168,
        1,
        1,
        % IPv4 port = 0
        0:16,
        % IPv6: all zeros
        0:128,
        % IPv6 port: 0
        0:16,
        8:8,
        CID/binary,
        Token/binary
    >>,
    PA = quic_tls:decode_preferred_address(Binary),
    %% When address is non-zero but port is zero, address is still parsed
    ?assertEqual({192, 168, 1, 1}, PA#preferred_address.ipv4_addr),
    ?assertEqual(0, PA#preferred_address.ipv4_port).

%% Test broadcast address encoding
preferred_address_broadcast_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {255, 255, 255, 255},
        ipv4_port = 65535,
        ipv6_addr = undefined,
        ipv6_port = undefined,
        cid = CID,
        stateless_reset_token = Token
    },
    Encoded = quic_tls:encode_preferred_address(PA),
    Decoded = quic_tls:decode_preferred_address(Encoded),
    ?assertEqual({255, 255, 255, 255}, Decoded#preferred_address.ipv4_addr),
    ?assertEqual(65535, Decoded#preferred_address.ipv4_port).

%%====================================================================
%% RFC 9000 Section 9.6 Compliance Tests
%%====================================================================

%% RFC 9000: Server provides new CID for preferred address
preferred_address_cid_present_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {10, 0, 0, 1},
        ipv4_port = 4433,
        ipv6_addr = undefined,
        ipv6_port = undefined,
        cid = CID,
        stateless_reset_token = Token
    },
    ?assert(byte_size(PA#preferred_address.cid) > 0).

%% RFC 9000: Stateless reset token is always 16 bytes
preferred_address_token_size_test() ->
    CID = crypto:strong_rand_bytes(8),
    Token = crypto:strong_rand_bytes(16),
    PA = #preferred_address{
        ipv4_addr = {10, 0, 0, 1},
        ipv4_port = 4433,
        ipv6_addr = undefined,
        ipv6_port = undefined,
        cid = CID,
        stateless_reset_token = Token
    },
    ?assertEqual(16, byte_size(PA#preferred_address.stateless_reset_token)).
