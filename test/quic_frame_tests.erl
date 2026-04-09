%%% -*- erlang -*-
%%%
%%% Tests for QUIC Frame Encoding/Decoding
%%% RFC 9000 Section 12
%%%

-module(quic_frame_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% PADDING Frame (0x00)
%%====================================================================

padding_roundtrip_test() ->
    Frame = padding,
    Encoded = quic_frame:encode(Frame),
    ?assertEqual(<<0>>, Encoded),
    ?assertEqual({Frame, <<>>}, quic_frame:decode(Encoded)).

%%====================================================================
%% PING Frame (0x01)
%%====================================================================

ping_roundtrip_test() ->
    Frame = ping,
    Encoded = quic_frame:encode(Frame),
    ?assertEqual(<<1>>, Encoded),
    ?assertEqual({Frame, <<>>}, quic_frame:decode(Encoded)).

%%====================================================================
%% ACK Frame (0x02, 0x03)
%%====================================================================

ack_simple_roundtrip_test() ->
    Frame = {ack, [{100, 10}], 50, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_with_ranges_roundtrip_test() ->
    Frame = {ack, [{100, 10}, {5, 3}, {2, 1}], 50, undefined},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

ack_with_ecn_roundtrip_test() ->
    Frame = {ack, [{100, 10}], 50, {1000, 500, 100}},
    Encoded = quic_frame:encode(Frame),
    %% Verify starts with ECN frame type (0x03)
    ?assertMatch(<<3, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% RESET_STREAM Frame (0x04)
%%====================================================================

reset_stream_roundtrip_test() ->
    Frame = {reset_stream, 4, 256, 1024},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<4, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% RESET_STREAM_AT Frame (0x24) - draft-ietf-quic-reliable-stream-reset-07
%%====================================================================

reset_stream_at_roundtrip_test() ->
    Frame = {reset_stream_at, 4, 256, 1000, 500},
    Encoded = quic_frame:encode(Frame),
    %% Frame type should be 0x24
    ?assertMatch(<<16#24, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

reset_stream_at_zero_reliable_size_test() ->
    %% ReliableSize=0 is equivalent to RESET_STREAM per spec
    Frame = {reset_stream_at, 0, 0, 100, 0},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

reset_stream_at_max_reliable_equals_final_test() ->
    %% ReliableSize == FinalSize is valid
    Frame = {reset_stream_at, 1, 0, 1000, 1000},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

reset_stream_at_large_values_test() ->
    %% Test with 62-bit values (max varint)
    Frame =
        {reset_stream_at, 16#3FFFFFFFFFFFFFFF, 16#3FFFFFFFFFFFFFFF, 16#3FFFFFFFFFFFFFFF,
            16#1FFFFFFFFFFFFFFF},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% STOP_SENDING Frame (0x05)
%%====================================================================

stop_sending_roundtrip_test() ->
    Frame = {stop_sending, 8, 512},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<5, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% CRYPTO Frame (0x06)
%%====================================================================

crypto_roundtrip_test() ->
    Data = <<"TLS handshake data">>,
    Frame = {crypto, 0, Data},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<6, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

crypto_with_offset_roundtrip_test() ->
    Data = <<"More TLS data">>,
    Frame = {crypto, 100, Data},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% NEW_TOKEN Frame (0x07)
%%====================================================================

new_token_roundtrip_test() ->
    Token = crypto:strong_rand_bytes(32),
    Frame = {new_token, Token},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<7, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% STREAM Frame (0x08-0x0f)
%%====================================================================

stream_basic_roundtrip_test() ->
    Data = <<"Hello, QUIC!">>,
    Frame = {stream, 4, 0, Data, false},
    Encoded = quic_frame:encode(Frame),
    %% Type should be 0x0a (STREAM with LEN, no OFF, no FIN)
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

stream_with_offset_roundtrip_test() ->
    Data = <<"World">>,
    Frame = {stream, 4, 100, Data, false},
    Encoded = quic_frame:encode(Frame),
    %% Should have OFF flag set
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

stream_with_fin_roundtrip_test() ->
    Data = <<"Final data">>,
    Frame = {stream, 8, 0, Data, true},
    Encoded = quic_frame:encode(Frame),
    %% Should have FIN flag set
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

stream_full_flags_roundtrip_test() ->
    Data = <<"All flags">>,
    Frame = {stream, 12, 500, Data, true},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

stream_empty_data_roundtrip_test() ->
    Frame = {stream, 4, 0, <<>>, true},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% MAX_DATA Frame (0x10)
%%====================================================================

max_data_roundtrip_test() ->
    Frame = {max_data, 1048576},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<16, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% MAX_STREAM_DATA Frame (0x11)
%%====================================================================

max_stream_data_roundtrip_test() ->
    Frame = {max_stream_data, 4, 262144},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<17, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% MAX_STREAMS Frame (0x12, 0x13)
%%====================================================================

max_streams_bidi_roundtrip_test() ->
    Frame = {max_streams, bidi, 100},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<18, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

max_streams_uni_roundtrip_test() ->
    Frame = {max_streams, uni, 50},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<19, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% DATA_BLOCKED Frame (0x14)
%%====================================================================

data_blocked_roundtrip_test() ->
    Frame = {data_blocked, 1048576},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<20, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% STREAM_DATA_BLOCKED Frame (0x15)
%%====================================================================

stream_data_blocked_roundtrip_test() ->
    Frame = {stream_data_blocked, 4, 262144},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<21, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% STREAMS_BLOCKED Frame (0x16, 0x17)
%%====================================================================

streams_blocked_bidi_roundtrip_test() ->
    Frame = {streams_blocked, bidi, 100},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<22, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

streams_blocked_uni_roundtrip_test() ->
    Frame = {streams_blocked, uni, 50},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<23, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% NEW_CONNECTION_ID Frame (0x18)
%%====================================================================

new_connection_id_roundtrip_test() ->
    CID = crypto:strong_rand_bytes(8),
    ResetToken = crypto:strong_rand_bytes(16),
    Frame = {new_connection_id, 1, 0, CID, ResetToken},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<24, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

new_connection_id_with_retire_roundtrip_test() ->
    CID = crypto:strong_rand_bytes(16),
    ResetToken = crypto:strong_rand_bytes(16),
    Frame = {new_connection_id, 5, 3, CID, ResetToken},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% RETIRE_CONNECTION_ID Frame (0x19)
%%====================================================================

retire_connection_id_roundtrip_test() ->
    Frame = {retire_connection_id, 2},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<25, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% PATH_CHALLENGE Frame (0x1a)
%%====================================================================

path_challenge_roundtrip_test() ->
    Data = crypto:strong_rand_bytes(8),
    Frame = {path_challenge, Data},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<26, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% PATH_RESPONSE Frame (0x1b)
%%====================================================================

path_response_roundtrip_test() ->
    Data = crypto:strong_rand_bytes(8),
    Frame = {path_response, Data},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<27, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% CONNECTION_CLOSE Frame (0x1c, 0x1d)
%%====================================================================

connection_close_transport_roundtrip_test() ->
    Reason = <<"Protocol violation">>,
    Frame = {connection_close, transport, 10, 6, Reason},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<28, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

connection_close_application_roundtrip_test() ->
    Reason = <<"Application error">>,
    Frame = {connection_close, application, 256, undefined, Reason},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<29, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

connection_close_empty_reason_roundtrip_test() ->
    Frame = {connection_close, transport, 0, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% HANDSHAKE_DONE Frame (0x1e)
%%====================================================================

handshake_done_roundtrip_test() ->
    Frame = handshake_done,
    Encoded = quic_frame:encode(Frame),
    ?assertEqual(<<30>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

%%====================================================================
%% DATAGRAM Frames (0x30, 0x31) - RFC 9221
%%====================================================================

datagram_roundtrip_test() ->
    Data = <<"Hello, unreliable world!">>,
    Frame = {datagram, Data},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<16#30, _/binary>>, Encoded),
    {Decoded, Rest} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded),
    %% datagram without length consumes all remaining data
    ?assertEqual(<<>>, Rest).

datagram_empty_roundtrip_test() ->
    Frame = {datagram, <<>>},
    Encoded = quic_frame:encode(Frame),
    ?assertEqual(<<16#30>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

datagram_with_length_roundtrip_test() ->
    Data = <<"Datagram with explicit length">>,
    Frame = {datagram_with_length, Data},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<16#31, _/binary>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

datagram_with_length_empty_roundtrip_test() ->
    Frame = {datagram_with_length, <<>>},
    Encoded = quic_frame:encode(Frame),
    ?assertMatch(<<16#31, 0>>, Encoded),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

datagram_with_length_large_test() ->
    %% Test with larger data
    Data = crypto:strong_rand_bytes(1000),
    Frame = {datagram_with_length, Data},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(Frame, Decoded).

datagram_with_trailing_data_test() ->
    %% datagram_with_length should leave trailing data
    Data = <<"short">>,
    Frame = {datagram_with_length, Data},
    Encoded = <<(quic_frame:encode(Frame))/binary, "trailing">>,
    {{datagram_with_length, Data}, <<"trailing">>} = quic_frame:decode(Encoded).

%%====================================================================
%% decode_all tests
%%====================================================================

decode_all_single_test() ->
    Frame = ping,
    Encoded = quic_frame:encode(Frame),
    ?assertEqual({ok, [Frame]}, quic_frame:decode_all(Encoded)).

decode_all_multiple_test() ->
    Frames = [padding, ping, handshake_done],
    Encoded = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
    ?assertEqual({ok, Frames}, quic_frame:decode_all(Encoded)).

decode_all_empty_test() ->
    ?assertEqual({ok, []}, quic_frame:decode_all(<<>>)).

decode_all_complex_test() ->
    Frames = [
        ping,
        {max_data, 1000000},
        {stream, 4, 0, <<"test data">>, false},
        {ack, [{100, 5}], 10, undefined},
        handshake_done
    ],
    Encoded = iolist_to_binary([quic_frame:encode(F) || F <- Frames]),
    ?assertEqual({ok, Frames}, quic_frame:decode_all(Encoded)).

%%====================================================================
%% Error cases
%%====================================================================

decode_unknown_frame_test() ->
    %% Frame type 0xff is not defined
    ?assertEqual({error, {unknown_frame_type, 16#ff}}, quic_frame:decode(<<16#ff>>)).

decode_empty_test() ->
    ?assertEqual({error, empty}, quic_frame:decode(<<>>)).

%%====================================================================
%% Decode with trailing data
%%====================================================================

decode_with_trailing_test() ->
    Frame = ping,
    Encoded = <<(quic_frame:encode(Frame))/binary, "trailing data">>,
    ?assertEqual({Frame, <<"trailing data">>}, quic_frame:decode(Encoded)).
