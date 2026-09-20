%%% -*- erlang -*-
%%%
%%% RFC 9000 §7.4 / §18.2: bad peer transport parameters must cause a
%%% TRANSPORT_PARAMETER_ERROR CONNECTION_CLOSE. h3spec exercises this path.

-module(quic_transport_param_errors_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% The client's SCID, which its transport parameters must echo in
%% initial_scid. The server state carries it as its DCID: without that the
%% connection-ID check rejects first and every case below passes whatever
%% else it sends.
-define(CLIENT_SCID, <<"client-scid">>).

server_rejects_client_with_server_only_param_test() ->
    S0 = server_state(),
    %% original_dcid is server-only; a client MUST NOT send it.
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        original_dcid => <<1, 2, 3, 4>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

server_rejects_missing_initial_scid_test() ->
    S0 = server_state(),
    S1 = quic_connection:apply_peer_transport_params(#{}, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

server_rejects_preferred_address_from_client_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        preferred_address => <<0:16/unit:8>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

server_rejects_retry_scid_from_client_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        retry_scid => <<0, 0, 0, 0>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

server_rejects_stateless_reset_token_from_client_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        stateless_reset_token => <<0:16/unit:8>>
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

%% RFC 9000 §18.2: active_connection_id_limit MUST be at least 2. The
%% connection's own range checks missed this one; the shared validator has
%% it.
server_rejects_active_connection_id_limit_too_small_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        active_connection_id_limit => 1
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

%% RFC 9000 §18.2: max_udp_payload_size MUST be >= 1200.
server_rejects_max_udp_payload_size_too_small_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        max_udp_payload_size => 1199
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

%% RFC 9000 §18.2: ack_delay_exponent MUST be <= 20.
server_rejects_ack_delay_exponent_too_large_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        ack_delay_exponent => 21
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

%% RFC 9000 §18.2: max_ack_delay MUST be < 2^14 (16384).
server_rejects_max_ack_delay_too_large_test() ->
    S0 = server_state(),
    BadParams = #{
        initial_scid => ?CLIENT_SCID,
        max_ack_delay => 16384
    },
    S1 = quic_connection:apply_peer_transport_params(BadParams, S0),
    ?assertMatch(
        {pending_close, transport, ?QUIC_TRANSPORT_PARAMETER_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).

%% RFC 9000 §12.4: a packet with zero frames is a PROTOCOL_VIOLATION.
%% Empty plaintext hitting the streaming decoder must close the connection.
%% The fence for everything above: the same state and a well-formed
%% parameter set must be accepted. Without this, a fixture that rejects
%% for an unrelated reason would make every case above pass regardless.
server_accepts_valid_client_params_test() ->
    S1 = quic_connection:apply_peer_transport_params(
        #{initial_scid => ?CLIENT_SCID, max_udp_payload_size => 1500}, server_state()
    ),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S1)).

server_state() ->
    quic_connection_test_support:state_set(
        quic_connection_test_support:state_for_role(server), dcid, ?CLIENT_SCID
    ).

empty_packet_is_protocol_violation_test() ->
    S0 = server_state(),
    {ok, S1, []} = quic_connection:decode_and_process_streaming(app, <<>>, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection_test_support:close_reason(S1)
    ).

%% A stream-only payload (no PADDING, no other frames surrounding) is NOT
%% empty — it decodes to a single frame — so must NOT trigger the
%% no-frames guard. This guards against future refactor regressions that
%% turn the empty check into something stricter.
stream_frame_does_not_trigger_no_frames_test() ->
    S0 = server_state(),
    %% PING frame is the smallest legal frame (one byte, type 0x01).
    {ok, S1, [ping]} = quic_connection:decode_and_process_streaming(app, <<16#01>>, S0),
    ?assertEqual(undefined, quic_connection_test_support:close_reason(S1)).

%% RFC 9000 §12.4: unknown frame type is FRAME_ENCODING_ERROR.
%% 0xff is not assigned (valid QUIC frame types occupy low codes and a few
%% draft extensions); the streaming decoder must close with 0x07.
unknown_frame_type_is_frame_encoding_error_test() ->
    S0 = server_state(),
    {ok, S1, []} = quic_connection:decode_and_process_streaming(app, <<16#ff>>, S0),
    ?assertMatch(
        {transport, ?QUIC_FRAME_ENCODING_ERROR, _},
        quic_connection_test_support:close_reason(S1)
    ).
