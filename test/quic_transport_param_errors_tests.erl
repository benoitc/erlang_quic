%%% -*- erlang -*-
%%%
%%% RFC 9000 §7.4 / §18.2: bad peer transport parameters must cause a
%%% TRANSPORT_PARAMETER_ERROR CONNECTION_CLOSE. h3spec exercises this path.

-module(quic_transport_param_errors_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

server_rejects_client_with_server_only_param_test() ->
    S0 = quic_connection:test_state_for_role(server),
    %% original_dcid is server-only; a client MUST NOT send it.
    BadParams = #{
        initial_scid => <<>>,
        original_dcid => <<1, 2, 3, 4>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

server_rejects_missing_initial_scid_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:apply_peer_transport_params(#{}, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

server_rejects_preferred_address_from_client_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        preferred_address => <<0:16/unit:8>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

server_rejects_retry_scid_from_client_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        retry_scid => <<0, 0, 0, 0>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

server_rejects_stateless_reset_token_from_client_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        stateless_reset_token => <<0:16/unit:8>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §18.2: max_udp_payload_size MUST be >= 1200.
server_rejects_max_udp_payload_size_too_small_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        max_udp_payload_size => 1199
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §18.2: ack_delay_exponent MUST be <= 20.
server_rejects_ack_delay_exponent_too_large_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        ack_delay_exponent => 21
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §18.2: max_ack_delay MUST be < 2^14 (16384).
server_rejects_max_ack_delay_too_large_test() ->
    S0 = quic_connection:test_state_for_role(server),
    BadParams = #{
        initial_scid => <<>>,
        max_ack_delay => 16384
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §12.4: a packet with zero frames is a PROTOCOL_VIOLATION.
%% Empty plaintext hitting the streaming decoder must close the connection.
empty_packet_is_protocol_violation_test() ->
    S0 = quic_connection:test_state_for_role(server),
    {ok, S1, []} = quic_connection:decode_and_process_streaming(app, <<>>, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

%% A stream-only payload (no PADDING, no other frames surrounding) is NOT
%% empty — it decodes to a single frame — so must NOT trigger the
%% no-frames guard. This guards against future refactor regressions that
%% turn the empty check into something stricter.
stream_frame_does_not_trigger_no_frames_test() ->
    S0 = quic_connection:test_state_for_role(server),
    %% PING frame is the smallest legal frame (one byte, type 0x01).
    {ok, S1, [ping]} = quic_connection:decode_and_process_streaming(app, <<16#01>>, S0),
    ?assertEqual(undefined, quic_connection:test_close_reason(S1)).

%% RFC 9000 §12.4: unknown frame type is FRAME_ENCODING_ERROR.
%% 0xff is not assigned (valid QUIC frame types occupy low codes and a few
%% draft extensions); the streaming decoder must close with 0x07.
unknown_frame_type_is_frame_encoding_error_test() ->
    S0 = quic_connection:test_state_for_role(server),
    {ok, S1, []} = quic_connection:decode_and_process_streaming(app, <<16#ff>>, S0),
    ?assertMatch(
        {transport, ?QUIC_FRAME_ENCODING_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).
