%%% -*- erlang -*-
%%%
%%% Unit tests for RFC 9297 HTTP Datagrams.
%%%
%%% These exercise the wire pieces (SETTINGS_H3_DATAGRAM codepoint,
%%% quarter-stream-id framing) without a real connection; the runtime
%%% send/receive path is covered by the CT suite.

-module(quic_h3_datagram_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").
-include("quic_h3.hrl").

%%====================================================================
%% SETTINGS codepoint
%%====================================================================

settings_h3_datagram_constant_test() ->
    ?assertEqual(16#33, ?H3_SETTINGS_H3_DATAGRAM).

settings_encode_decode_h3_datagram_test() ->
    Encoded = quic_h3_frame:encode_settings(#{h3_datagram => 1}),
    %% SETTINGS frame payload is prefixed by frame type (0x04) and length,
    %% so decode the whole frame to round-trip.
    {ok, {settings, Settings}, _Rest} = quic_h3_frame:decode(Encoded),
    ?assertEqual(1, maps:get(h3_datagram, Settings)).

settings_decode_zero_is_disabled_test() ->
    Encoded = quic_h3_frame:encode_settings(#{h3_datagram => 0}),
    {ok, {settings, Settings}, _Rest} = quic_h3_frame:decode(Encoded),
    ?assertEqual(0, maps:get(h3_datagram, Settings)).

%%====================================================================
%% Quarter-stream-id framing
%%====================================================================

qsid_roundtrip_test_() ->
    %% For any client-initiated bidi stream id (divisible by 4), the
    %% quarter-stream-id (StreamId bsr 2) must roundtrip to the same id
    %% after the (bsl 2) expansion on the receive side.
    [
        ?_assertEqual(StreamId, (StreamId bsr 2) bsl 2)
     || StreamId <- [0, 4, 64, 1024, 16#FFFFFFC]
    ].

qsid_varint_sizes_test_() ->
    %% Varint boundaries: 1-byte up to 63, 2-byte up to 16383,
    %% 4-byte up to 2^30-1, 8-byte beyond.
    [
        ?_assertEqual(1, byte_size(quic_varint:encode(0))),
        ?_assertEqual(1, byte_size(quic_varint:encode(63))),
        ?_assertEqual(2, byte_size(quic_varint:encode(64))),
        ?_assertEqual(2, byte_size(quic_varint:encode(16383))),
        ?_assertEqual(4, byte_size(quic_varint:encode(16384)))
    ].

%%====================================================================
%% Setting id mapping
%%====================================================================

id_to_setting_h3_datagram_test() ->
    %% h3_datagram round-trips through the id <-> atom mapping so
    %% peer SETTINGS carrying 0x33 surface on the decoded map.
    Encoded = quic_h3_frame:encode_settings_payload(#{h3_datagram => 1}),
    {ok, Decoded} = quic_h3_frame:decode_settings_payload(Encoded),
    ?assertEqual(1, maps:get(h3_datagram, Decoded)).

%%====================================================================
%% Peer SETTINGS enforcement (RFC 9297 §2.1)
%%====================================================================

%% Peer advertising SETTINGS_H3_DATAGRAM=1 without a non-zero QUIC
%% max_datagram_frame_size MUST be treated as H3_SETTINGS_ERROR.
peer_h3_datagram_without_quic_datagram_is_settings_error_test() ->
    ?assertThrow(
        {connection_error, ?H3_SETTINGS_ERROR, _},
        quic_h3_connection:validate_peer_h3_datagram_with(0)
    ).

peer_h3_datagram_with_quic_datagram_ok_test() ->
    ?assertEqual(true, quic_h3_connection:validate_peer_h3_datagram_with(1200)).
