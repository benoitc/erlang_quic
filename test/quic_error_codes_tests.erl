%%% -*- erlang -*-
%%%
%%% QUIC Error Codes Tests
%%% RFC 9000 Section 20 - Error Codes
%%%
%%% Tests for all QUIC transport error codes as defined in the specification.

-module(quic_error_codes_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% RFC 9000 Section 20.1 - Transport Error Codes
%%====================================================================

%% 0x00 - NO_ERROR
no_error_code_test() ->
    %% NO_ERROR is used when closing connection without error
    Frame = {connection_close, transport, 16#00, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#00, 0, <<>>}, Decoded).

%% 0x01 - INTERNAL_ERROR
internal_error_code_test() ->
    Frame = {connection_close, transport, 16#01, 0, <<"internal error">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#01, 0, <<"internal error">>}, Decoded).

%% 0x02 - CONNECTION_REFUSED
connection_refused_code_test() ->
    Frame = {connection_close, transport, 16#02, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#02, 0, <<>>}, Decoded).

%% 0x03 - FLOW_CONTROL_ERROR
flow_control_error_code_test() ->
    Frame = {connection_close, transport, 16#03, 0, <<"exceeded max_data">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#03, 0, <<"exceeded max_data">>}, Decoded).

%% 0x04 - STREAM_LIMIT_ERROR
stream_limit_error_code_test() ->
    Frame = {connection_close, transport, 16#04, 0, <<"too many streams">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#04, 0, <<"too many streams">>}, Decoded).

%% 0x05 - STREAM_STATE_ERROR
stream_state_error_code_test() ->
    Frame = {connection_close, transport, 16#05, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#05, 0, <<>>}, Decoded).

%% 0x06 - FINAL_SIZE_ERROR
final_size_error_code_test() ->
    Frame = {connection_close, transport, 16#06, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#06, 0, <<>>}, Decoded).

%% 0x07 - FRAME_ENCODING_ERROR
frame_encoding_error_code_test() ->
    Frame = {connection_close, transport, 16#07, 0, <<"malformed frame">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#07, 0, <<"malformed frame">>}, Decoded).

%% 0x08 - TRANSPORT_PARAMETER_ERROR
transport_parameter_error_code_test() ->
    Frame = {connection_close, transport, 16#08, 0, <<"invalid param">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#08, 0, <<"invalid param">>}, Decoded).

%% 0x09 - CONNECTION_ID_LIMIT_ERROR
connection_id_limit_error_code_test() ->
    Frame = {connection_close, transport, 16#09, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#09, 0, <<>>}, Decoded).

%% 0x0a - PROTOCOL_VIOLATION
protocol_violation_error_code_test() ->
    Frame = {connection_close, transport, 16#0a, 0, <<"protocol violation">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0a, 0, <<"protocol violation">>}, Decoded).

%% 0x0b - INVALID_TOKEN
invalid_token_error_code_test() ->
    Frame = {connection_close, transport, 16#0b, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0b, 0, <<>>}, Decoded).

%% 0x0c - APPLICATION_ERROR
application_error_code_test() ->
    Frame = {connection_close, transport, 16#0c, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0c, 0, <<>>}, Decoded).

%% 0x0d - CRYPTO_BUFFER_EXCEEDED
crypto_buffer_exceeded_error_code_test() ->
    Frame = {connection_close, transport, 16#0d, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0d, 0, <<>>}, Decoded).

%% 0x0e - KEY_UPDATE_ERROR
key_update_error_code_test() ->
    Frame = {connection_close, transport, 16#0e, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0e, 0, <<>>}, Decoded).

%% 0x0f - AEAD_LIMIT_REACHED
aead_limit_reached_error_code_test() ->
    Frame = {connection_close, transport, 16#0f, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0f, 0, <<>>}, Decoded).

%% 0x10 - NO_VIABLE_PATH
no_viable_path_error_code_test() ->
    Frame = {connection_close, transport, 16#10, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#10, 0, <<>>}, Decoded).

%%====================================================================
%% RFC 9000 Section 20.2 - Crypto Error Codes (0x0100-0x01ff)
%%====================================================================

%% TLS crypto errors use 0x0100 + TLS alert code
crypto_error_close_notify_test() ->
    %% TLS close_notify = 0
    Frame = {connection_close, transport, 16#0100, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0100, 0, <<>>}, Decoded).

crypto_error_unexpected_message_test() ->
    %% TLS unexpected_message = 10
    Frame = {connection_close, transport, 16#010a, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#010a, 0, <<>>}, Decoded).

crypto_error_bad_record_mac_test() ->
    %% TLS bad_record_mac = 20
    Frame = {connection_close, transport, 16#0114, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0114, 0, <<>>}, Decoded).

crypto_error_handshake_failure_test() ->
    %% TLS handshake_failure = 40
    Frame = {connection_close, transport, 16#0128, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0128, 0, <<>>}, Decoded).

crypto_error_certificate_required_test() ->
    %% TLS certificate_required = 116
    Frame = {connection_close, transport, 16#0174, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0174, 0, <<>>}, Decoded).

crypto_error_no_application_protocol_test() ->
    %% TLS no_application_protocol = 120
    Frame = {connection_close, transport, 16#0178, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0178, 0, <<>>}, Decoded).

%%====================================================================
%% APPLICATION_CLOSE Frame Tests
%%====================================================================

%% Application close uses a different frame type (0x1d)
%% Uses 5-tuple: {connection_close, application, ErrorCode, FrameType, Reason}
application_close_test() ->
    %% Application error codes are application-specific
    %% Note: For application close, FrameType is undefined
    Frame = {connection_close, application, 0, undefined, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, application, 0, undefined, <<>>}, Decoded).

application_close_with_reason_test() ->
    Frame = {connection_close, application, 42, undefined, <<"application shutdown">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual(
        {connection_close, application, 42, undefined, <<"application shutdown">>}, Decoded
    ).

%% H3 error codes (HTTP/3 specific)
h3_no_error_test() ->
    %% H3_NO_ERROR = 0x100
    Frame = {connection_close, application, 16#100, undefined, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, application, 16#100, undefined, <<>>}, Decoded).

h3_general_protocol_error_test() ->
    %% H3_GENERAL_PROTOCOL_ERROR = 0x101
    Frame = {connection_close, application, 16#101, undefined, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, application, 16#101, undefined, <<>>}, Decoded).

%%====================================================================
%% Error Code with Frame Type Tests
%%====================================================================

%% Transport close can include the frame type that triggered the error
error_with_frame_type_stream_test() ->
    %% STREAM frame type = 0x08-0x0f
    Frame = {connection_close, transport, 16#05, 16#08, <<"stream error">>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#05, 16#08, <<"stream error">>}, Decoded).

error_with_frame_type_crypto_test() ->
    %% CRYPTO frame type = 0x06
    Frame = {connection_close, transport, 16#0d, 16#06, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#0d, 16#06, <<>>}, Decoded).

error_with_frame_type_max_data_test() ->
    %% MAX_DATA frame type = 0x10
    Frame = {connection_close, transport, 16#03, 16#10, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#03, 16#10, <<>>}, Decoded).

%%====================================================================
%% Error Code Range Tests
%%====================================================================

%% Test that large error codes work
large_error_code_test() ->
    %% Error codes can be up to 62 bits
    Frame = {connection_close, transport, 16#1FFFFFFF, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#1FFFFFFF, 0, <<>>}, Decoded).

%% Test reserved error code range
reserved_error_code_test() ->
    %% Reserved codes can still be encoded/decoded
    Frame = {connection_close, transport, 16#FF00, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#FF00, 0, <<>>}, Decoded).

%%====================================================================
%% RESET_STREAM Error Code Tests
%%====================================================================

reset_stream_no_error_test() ->
    Frame = {reset_stream, 4, 0, 100},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({reset_stream, 4, 0, 100}, Decoded).

reset_stream_with_error_test() ->
    Frame = {reset_stream, 8, 16#42, 200},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({reset_stream, 8, 16#42, 200}, Decoded).

%%====================================================================
%% STOP_SENDING Error Code Tests
%%====================================================================

stop_sending_test() ->
    Frame = {stop_sending, 4, 0},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({stop_sending, 4, 0}, Decoded).

stop_sending_with_error_test() ->
    Frame = {stop_sending, 8, 16#42},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({stop_sending, 8, 16#42}, Decoded).

%%====================================================================
%% Empty Reason Phrase Tests
%%====================================================================

%% RFC 9000: Reason phrase is optional
empty_reason_phrase_test() ->
    Frame = {connection_close, transport, 16#01, 0, <<>>},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#01, 0, <<>>}, Decoded).

%%====================================================================
%% Long Reason Phrase Tests
%%====================================================================

long_reason_phrase_test() ->
    LongReason = list_to_binary(lists:duplicate(256, $x)),
    Frame = {connection_close, transport, 16#01, 0, LongReason},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#01, 0, LongReason}, Decoded).

%%====================================================================
%% UTF-8 Reason Phrase Tests
%%====================================================================

utf8_reason_phrase_test() ->
    %% RFC 9000: Reason phrase SHOULD be UTF-8 encoded
    Reason = <<"Error: données invalides"/utf8>>,
    Frame = {connection_close, transport, 16#01, 0, Reason},
    Encoded = quic_frame:encode(Frame),
    {Decoded, <<>>} = quic_frame:decode(Encoded),
    ?assertEqual({connection_close, transport, 16#01, 0, Reason}, Decoded).
