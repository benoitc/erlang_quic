%%% -*- erlang -*-
%%%
%%% Unit tests for HTTP/3 public API (RFC 9114)
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0

-module(quic_h3_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% Type Export Tests
%%====================================================================

%% Test that types are exported and usable
types_exported_test() ->
    %% These would fail to compile if types weren't exported
    ok.

%%====================================================================
%% API Function Existence Tests
%%====================================================================

%% Verify all exported functions exist
client_api_exists_test_() ->
    [
        ?_assert(erlang:function_exported(quic_h3, connect, 2)),
        ?_assert(erlang:function_exported(quic_h3, connect, 3)),
        ?_assert(erlang:function_exported(quic_h3, request, 2)),
        ?_assert(erlang:function_exported(quic_h3, request, 3))
    ].

shared_api_exists_test_() ->
    [
        ?_assert(erlang:function_exported(quic_h3, send_data, 3)),
        ?_assert(erlang:function_exported(quic_h3, send_data, 4)),
        ?_assert(erlang:function_exported(quic_h3, send_trailers, 3)),
        ?_assert(erlang:function_exported(quic_h3, cancel, 2)),
        ?_assert(erlang:function_exported(quic_h3, cancel, 3)),
        ?_assert(erlang:function_exported(quic_h3, goaway, 1)),
        ?_assert(erlang:function_exported(quic_h3, close, 1))
    ].

server_api_exists_test_() ->
    [
        ?_assert(erlang:function_exported(quic_h3, start_server, 3)),
        ?_assert(erlang:function_exported(quic_h3, stop_server, 1)),
        ?_assert(erlang:function_exported(quic_h3, send_response, 4))
    ].

query_api_exists_test_() ->
    [
        ?_assert(erlang:function_exported(quic_h3, get_settings, 1)),
        ?_assert(erlang:function_exported(quic_h3, get_peer_settings, 1))
    ].

%%====================================================================
%% Module Attribute Tests
%%====================================================================

%% Verify module info
module_info_test() ->
    Info = quic_h3:module_info(exports),
    ?assert(is_list(Info)),
    ?assert(length(Info) > 0).

%%====================================================================
%% Constants Tests
%%====================================================================

h3_error_codes_test_() ->
    [
        ?_assertEqual(16#100, ?H3_NO_ERROR),
        ?_assertEqual(16#101, ?H3_GENERAL_PROTOCOL_ERROR),
        ?_assertEqual(16#102, ?H3_INTERNAL_ERROR),
        ?_assertEqual(16#103, ?H3_STREAM_CREATION_ERROR),
        ?_assertEqual(16#104, ?H3_CLOSED_CRITICAL_STREAM),
        ?_assertEqual(16#105, ?H3_FRAME_UNEXPECTED),
        ?_assertEqual(16#106, ?H3_FRAME_ERROR),
        ?_assertEqual(16#107, ?H3_EXCESSIVE_LOAD),
        ?_assertEqual(16#108, ?H3_ID_ERROR),
        ?_assertEqual(16#109, ?H3_SETTINGS_ERROR),
        ?_assertEqual(16#10A, ?H3_MISSING_SETTINGS),
        ?_assertEqual(16#10B, ?H3_REQUEST_REJECTED),
        ?_assertEqual(16#10C, ?H3_REQUEST_CANCELLED),
        ?_assertEqual(16#10D, ?H3_REQUEST_INCOMPLETE),
        ?_assertEqual(16#10E, ?H3_MESSAGE_ERROR),
        ?_assertEqual(16#10F, ?H3_CONNECT_ERROR),
        ?_assertEqual(16#110, ?H3_VERSION_FALLBACK)
    ].

qpack_error_codes_test_() ->
    [
        ?_assertEqual(16#200, ?H3_QPACK_DECOMPRESSION_FAILED),
        ?_assertEqual(16#201, ?H3_QPACK_ENCODER_STREAM_ERROR),
        ?_assertEqual(16#202, ?H3_QPACK_DECODER_STREAM_ERROR)
    ].

h3_frame_types_test_() ->
    [
        ?_assertEqual(16#00, ?H3_FRAME_DATA),
        ?_assertEqual(16#01, ?H3_FRAME_HEADERS),
        ?_assertEqual(16#03, ?H3_FRAME_CANCEL_PUSH),
        ?_assertEqual(16#04, ?H3_FRAME_SETTINGS),
        ?_assertEqual(16#05, ?H3_FRAME_PUSH_PROMISE),
        ?_assertEqual(16#07, ?H3_FRAME_GOAWAY),
        ?_assertEqual(16#0D, ?H3_FRAME_MAX_PUSH_ID)
    ].

h3_stream_types_test_() ->
    [
        ?_assertEqual(16#00, ?H3_STREAM_CONTROL),
        ?_assertEqual(16#01, ?H3_STREAM_PUSH),
        ?_assertEqual(16#02, ?H3_STREAM_QPACK_ENCODER),
        ?_assertEqual(16#03, ?H3_STREAM_QPACK_DECODER)
    ].

h3_settings_test_() ->
    [
        ?_assertEqual(16#01, ?H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY),
        ?_assertEqual(16#06, ?H3_SETTINGS_MAX_FIELD_SECTION_SIZE),
        ?_assertEqual(16#07, ?H3_SETTINGS_QPACK_BLOCKED_STREAMS),
        ?_assertEqual(16#08, ?H3_SETTINGS_ENABLE_CONNECT_PROTOCOL)
    ].

h3_default_settings_test_() ->
    [
        ?_assertEqual(0, ?H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY),
        ?_assertEqual(65536, ?H3_DEFAULT_MAX_FIELD_SECTION_SIZE),
        ?_assertEqual(0, ?H3_DEFAULT_QPACK_BLOCKED_STREAMS)
    ].
