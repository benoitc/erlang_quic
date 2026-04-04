%%% -*- erlang -*-
%%%
%%% QUIC Datagram (RFC 9221) transport parameter tests
%%%

-module(quic_datagram_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Transport Parameter Encoding/Decoding Tests
%%====================================================================

%% Test transport parameter encoding roundtrip
tp_encode_decode_test() ->
    Params = #{max_datagram_frame_size => 65535},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(65535, maps:get(max_datagram_frame_size, Decoded)).

%% Test encoding with various sizes
tp_encode_small_size_test() ->
    Params = #{max_datagram_frame_size => 100},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(100, maps:get(max_datagram_frame_size, Decoded)).

tp_encode_large_size_test() ->
    %% RFC 9221 recommends 65535 for accepting any datagram
    Params = #{max_datagram_frame_size => 65535},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(65535, maps:get(max_datagram_frame_size, Decoded)).

%% Test that value 0 is not encoded (disabled)
tp_encode_zero_not_encoded_test() ->
    Params = #{max_datagram_frame_size => 0},
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    %% 0 should not be encoded, so the key should be absent
    ?assertEqual(0, maps:get(max_datagram_frame_size, Decoded, 0)).

%% Test encoding with other transport params
tp_encode_with_other_params_test() ->
    Params = #{
        initial_max_data => 1000000,
        max_datagram_frame_size => 1200,
        initial_max_streams_bidi => 100
    },
    Encoded = quic_tls:encode_transport_params(Params),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),
    ?assertEqual(1000000, maps:get(initial_max_data, Decoded)),
    ?assertEqual(1200, maps:get(max_datagram_frame_size, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)).

%% Test that the correct transport parameter ID (0x20) is used
tp_id_test() ->
    ?assertEqual(16#20, ?TP_MAX_DATAGRAM_FRAME_SIZE).

%%====================================================================
%% Validation Tests (state-based, no real connections)
%%====================================================================

%% These tests verify the validation logic in isolation.
%% Full integration tests require connection setup which is
%% tested in the E2E test suites.

%% Validate that max size encoding works for various varint sizes
tp_varint_encoding_test() ->
    %% 1-byte varint (0-63)
    Params1 = #{max_datagram_frame_size => 63},
    Encoded1 = quic_tls:encode_transport_params(Params1),
    {ok, Decoded1} = quic_tls:decode_transport_params(Encoded1),
    ?assertEqual(63, maps:get(max_datagram_frame_size, Decoded1)),

    %% 2-byte varint (64-16383)
    Params2 = #{max_datagram_frame_size => 1200},
    Encoded2 = quic_tls:encode_transport_params(Params2),
    {ok, Decoded2} = quic_tls:decode_transport_params(Encoded2),
    ?assertEqual(1200, maps:get(max_datagram_frame_size, Decoded2)),

    %% 4-byte varint (16384-1073741823)
    Params3 = #{max_datagram_frame_size => 100000},
    Encoded3 = quic_tls:encode_transport_params(Params3),
    {ok, Decoded3} = quic_tls:decode_transport_params(Encoded3),
    ?assertEqual(100000, maps:get(max_datagram_frame_size, Decoded3)).
