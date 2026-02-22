%%% -*- erlang -*-
%%%
%%% QUIC Transport Parameters Tests
%%% RFC 9000 Section 18.2 - Transport Parameter Definitions
%%%
%%% Tests transport parameter encoding, decoding, and validation
%%% per the QUIC specification.

-module(quic_transport_params_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Transport Parameter Encoding Tests (RFC 9000 Section 18.2)
%%====================================================================

encode_original_dcid_test() ->
    %% original_destination_connection_id (0x00)
    DCID = crypto:strong_rand_bytes(8),
    Params = #{original_dcid => DCID},
    Encoded = quic_tls:encode_transport_params(Params),
    ?assert(byte_size(Encoded) > 0),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(DCID, maps:get(original_dcid, Decoded)).

encode_max_idle_timeout_test() ->
    %% max_idle_timeout (0x01)
    Params = #{max_idle_timeout => 30000},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(30000, maps:get(max_idle_timeout, Decoded)).

encode_max_udp_payload_size_test() ->
    %% max_udp_payload_size (0x03) - must be at least 1200
    Params = #{max_udp_payload_size => 1472},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(1472, maps:get(max_udp_payload_size, Decoded)).

encode_initial_max_data_test() ->
    %% initial_max_data (0x04)
    Params = #{initial_max_data => 1000000},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(1000000, maps:get(initial_max_data, Decoded)).

encode_initial_max_stream_data_bidi_local_test() ->
    %% initial_max_stream_data_bidi_local (0x05)
    Params = #{initial_max_stream_data_bidi_local => 100000},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(100000, maps:get(initial_max_stream_data_bidi_local, Decoded)).

encode_initial_max_stream_data_bidi_remote_test() ->
    %% initial_max_stream_data_bidi_remote (0x06)
    Params = #{initial_max_stream_data_bidi_remote => 100000},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(100000, maps:get(initial_max_stream_data_bidi_remote, Decoded)).

encode_initial_max_stream_data_uni_test() ->
    %% initial_max_stream_data_uni (0x07)
    Params = #{initial_max_stream_data_uni => 50000},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(50000, maps:get(initial_max_stream_data_uni, Decoded)).

encode_initial_max_streams_bidi_test() ->
    %% initial_max_streams_bidi (0x08)
    Params = #{initial_max_streams_bidi => 100},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)).

encode_initial_max_streams_uni_test() ->
    %% initial_max_streams_uni (0x09)
    Params = #{initial_max_streams_uni => 100},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(100, maps:get(initial_max_streams_uni, Decoded)).

encode_ack_delay_exponent_test() ->
    %% ack_delay_exponent (0x0a) - default is 3, max is 20
    Params = #{ack_delay_exponent => 8},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(8, maps:get(ack_delay_exponent, Decoded)).

encode_max_ack_delay_test() ->
    %% max_ack_delay (0x0b) - default is 25ms, max is 2^14ms
    Params = #{max_ack_delay => 50},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(50, maps:get(max_ack_delay, Decoded)).

encode_disable_active_migration_test() ->
    %% disable_active_migration (0x0c) - zero-length value
    Params = #{disable_active_migration => true},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(true, maps:get(disable_active_migration, Decoded)).

encode_active_connection_id_limit_test() ->
    %% active_connection_id_limit (0x0e) - default is 2, min is 2
    Params = #{active_connection_id_limit => 8},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(8, maps:get(active_connection_id_limit, Decoded)).

encode_initial_scid_test() ->
    %% initial_source_connection_id (0x0f)
    SCID = crypto:strong_rand_bytes(8),
    Params = #{initial_scid => SCID},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(SCID, maps:get(initial_scid, Decoded)).

%%====================================================================
%% Multiple Transport Parameters Tests
%%====================================================================

encode_multiple_params_test() ->
    %% Test encoding multiple parameters at once
    Params = #{
        max_idle_timeout => 60000,
        initial_max_data => 2000000,
        initial_max_streams_bidi => 100,
        initial_max_streams_uni => 100,
        ack_delay_exponent => 3,
        max_ack_delay => 25
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(60000, maps:get(max_idle_timeout, Decoded)),
    ?assertEqual(2000000, maps:get(initial_max_data, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_uni, Decoded)),
    ?assertEqual(3, maps:get(ack_delay_exponent, Decoded)),
    ?assertEqual(25, maps:get(max_ack_delay, Decoded)).

encode_full_params_test() ->
    %% Test encoding a full set of typical server parameters
    SCID = crypto:strong_rand_bytes(8),
    Params = #{
        initial_scid => SCID,
        max_idle_timeout => 30000,
        max_udp_payload_size => 1472,
        initial_max_data => 1048576,
        initial_max_stream_data_bidi_local => 262144,
        initial_max_stream_data_bidi_remote => 262144,
        initial_max_stream_data_uni => 262144,
        initial_max_streams_bidi => 100,
        initial_max_streams_uni => 100,
        ack_delay_exponent => 3,
        max_ack_delay => 25,
        active_connection_id_limit => 8
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),

    %% Verify all parameters decoded correctly
    ?assertEqual(SCID, maps:get(initial_scid, Decoded)),
    ?assertEqual(30000, maps:get(max_idle_timeout, Decoded)),
    ?assertEqual(1472, maps:get(max_udp_payload_size, Decoded)),
    ?assertEqual(1048576, maps:get(initial_max_data, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)).

%%====================================================================
%% Empty and Edge Case Tests
%%====================================================================

encode_empty_params_test() ->
    %% Empty parameters should produce empty binary
    Params = #{},
    Encoded = quic_tls:encode_transport_params(Params),
    ?assertEqual(<<>>, Encoded).

decode_empty_params_test() ->
    %% Empty binary should decode to empty map
    {ok, Decoded} = quic_tls:decode_transport_params(<<>>),
    ?assertEqual(#{}, Decoded).

encode_zero_values_test() ->
    %% Zero values should encode correctly
    Params = #{
        max_idle_timeout => 0,
        initial_max_data => 0,
        initial_max_streams_bidi => 0
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(0, maps:get(max_idle_timeout, Decoded)),
    ?assertEqual(0, maps:get(initial_max_data, Decoded)),
    ?assertEqual(0, maps:get(initial_max_streams_bidi, Decoded)).

encode_max_values_test() ->
    %% Large values should encode correctly with 8-byte varints
    Params = #{
        % Max varint value (2^62 - 1)
        initial_max_data => 4611686018427387903
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(4611686018427387903, maps:get(initial_max_data, Decoded)).

%%====================================================================
%% Connection ID Tests
%%====================================================================

encode_empty_connection_id_test() ->
    %% Empty connection ID is valid (length = 0)
    Params = #{original_dcid => <<>>},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(<<>>, maps:get(original_dcid, Decoded)).

encode_max_connection_id_test() ->
    %% RFC 9000: Connection IDs can be up to 20 bytes
    DCID = crypto:strong_rand_bytes(20),
    Params = #{original_dcid => DCID},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(DCID, maps:get(original_dcid, Decoded)).

%%====================================================================
%% RFC 9000 Section 18.2 - Transport Parameter Constraints
%%====================================================================

%% RFC 9000: max_udp_payload_size must be at least 1200
max_udp_payload_size_minimum_test() ->
    %% 1200 is the minimum required value
    Params = #{max_udp_payload_size => 1200},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(1200, maps:get(max_udp_payload_size, Decoded)).

%% RFC 9000: ack_delay_exponent must not exceed 20
ack_delay_exponent_max_valid_test() ->
    Params = #{ack_delay_exponent => 20},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(20, maps:get(ack_delay_exponent, Decoded)).

%% RFC 9000: max_ack_delay must not exceed 2^14 ms
max_ack_delay_max_valid_test() ->
    %% 2^14 = 16384 ms
    Params = #{max_ack_delay => 16384},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(16384, maps:get(max_ack_delay, Decoded)).

%% RFC 9000: active_connection_id_limit must be at least 2
active_connection_id_limit_minimum_test() ->
    Params = #{active_connection_id_limit => 2},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(2, maps:get(active_connection_id_limit, Decoded)).

%%====================================================================
%% Invalid Input Tests
%%====================================================================

decode_invalid_varint_test() ->
    %% Invalid varint encoding should fail
    InvalidData = <<255, 255, 255, 255, 255, 255, 255, 255, 255>>,
    Result = quic_tls:decode_transport_params(InvalidData),
    ?assertEqual({error, invalid_transport_params}, Result).

%%====================================================================
%% Roundtrip Tests
%%====================================================================

roundtrip_all_params_test() ->
    %% Test roundtrip for all known parameters
    DCID = crypto:strong_rand_bytes(8),
    SCID = crypto:strong_rand_bytes(8),
    AllParams = #{
        original_dcid => DCID,
        initial_scid => SCID,
        max_idle_timeout => 30000,
        max_udp_payload_size => 1472,
        initial_max_data => 1048576,
        initial_max_stream_data_bidi_local => 262144,
        initial_max_stream_data_bidi_remote => 262144,
        initial_max_stream_data_uni => 262144,
        initial_max_streams_bidi => 100,
        initial_max_streams_uni => 100,
        ack_delay_exponent => 3,
        max_ack_delay => 25,
        disable_active_migration => true,
        active_connection_id_limit => 8
    },
    Encoded = quic_tls:encode_transport_params(AllParams),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),

    %% Verify each parameter
    ?assertEqual(DCID, maps:get(original_dcid, Decoded)),
    ?assertEqual(SCID, maps:get(initial_scid, Decoded)),
    ?assertEqual(30000, maps:get(max_idle_timeout, Decoded)),
    ?assertEqual(1472, maps:get(max_udp_payload_size, Decoded)),
    ?assertEqual(1048576, maps:get(initial_max_data, Decoded)),
    ?assertEqual(262144, maps:get(initial_max_stream_data_bidi_local, Decoded)),
    ?assertEqual(262144, maps:get(initial_max_stream_data_bidi_remote, Decoded)),
    ?assertEqual(262144, maps:get(initial_max_stream_data_uni, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_uni, Decoded)),
    ?assertEqual(3, maps:get(ack_delay_exponent, Decoded)),
    ?assertEqual(25, maps:get(max_ack_delay, Decoded)),
    ?assertEqual(true, maps:get(disable_active_migration, Decoded)),
    ?assertEqual(8, maps:get(active_connection_id_limit, Decoded)).
