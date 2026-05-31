%%% -*- erlang -*-
%%%
%%% Frame-level RFC 9000 violations that must produce CONNECTION_CLOSE.
%%% Replaces the h3spec-driven checks for these cases with deterministic,
%%% in-process assertions against the server's state machine.

-module(quic_frame_violation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%% RFC 9000 §19.20: HANDSHAKE_DONE is server-to-client only. A server
%% that receives one MUST close with PROTOCOL_VIOLATION.
server_rejects_handshake_done_at_app_level_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:process_frame(app, handshake_done, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §19.20: HANDSHAKE_DONE MUST be sent in 1-RTT packets.
%% Anywhere else is PROTOCOL_VIOLATION.
handshake_done_at_handshake_level_is_protocol_violation_test() ->
    S0 = quic_connection:test_state_for_role(client),
    S1 = quic_connection:process_frame(handshake, handshake_done, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

handshake_done_at_initial_level_is_protocol_violation_test() ->
    S0 = quic_connection:test_state_for_role(client),
    S1 = quic_connection:process_frame(initial, handshake_done, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §4.6: a peer-initiated stream beyond the advertised limit is a
%% STREAM_LIMIT_ERROR. Stream 4000 is client-initiated bidi number 1000,
%% well past the default limit of 100.
server_rejects_over_limit_stream_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:process_frame(app, {stream, 4000, 0, <<"x">>, false}, S0),
    ?assertMatch(
        {transport, ?QUIC_STREAM_LIMIT_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §3.2: the peer cannot open our locally-initiated streams. STREAM
%% data for one we never opened (stream 1 is server-initiated bidi #0) is a
%% STREAM_STATE_ERROR, not a new stream.
server_rejects_data_for_unopened_local_stream_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:process_frame(app, {stream, 1, 0, <<"x">>, false}, S0),
    ?assertMatch(
        {transport, ?QUIC_STREAM_STATE_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §19.15: NEW_CONNECTION_ID with retire_prior_to greater than the
%% sequence number is a FRAME_ENCODING_ERROR.
new_connection_id_retire_prior_to_exceeds_seq_test() ->
    S0 = quic_connection:test_state_for_role(client),
    Frame = {new_connection_id, 0, 5, <<1, 2, 3, 4, 5, 6, 7, 8>>, <<0:128>>},
    S1 = quic_connection:process_frame(app, Frame, S0),
    ?assertMatch(
        {transport, ?QUIC_FRAME_ENCODING_ERROR, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §19.16: RETIRE_CONNECTION_ID for a sequence number never issued
%% is a PROTOCOL_VIOLATION (default local_cid_seq is 1, so 999 is unissued).
retire_connection_id_unissued_test() ->
    S0 = quic_connection:test_state_for_role(server),
    S1 = quic_connection:process_frame(app, {retire_connection_id, 999}, S0),
    ?assertMatch(
        {transport, ?QUIC_PROTOCOL_VIOLATION, _},
        quic_connection:test_close_reason(S1)
    ).

%% RFC 9000 §19.15: connection ID length must be 1..20 octets; otherwise the
%% frame fails to decode (caller closes with FRAME_ENCODING_ERROR).
new_connection_id_cidlen_bounds_test() ->
    Token = <<0:128>>,
    Valid = quic_frame:encode({new_connection_id, 1, 0, <<1, 2, 3, 4, 5, 6, 7, 8>>, Token}),
    ?assertMatch({{new_connection_id, 1, 0, _, _}, <<>>}, quic_frame:decode(Valid)),
    %% CIDLen = 0 (frame type, seq, retire_prior, len=0, then 16-byte token)
    ZeroLen = <<?FRAME_NEW_CONNECTION_ID, 1, 0, 0, Token/binary>>,
    ?assertEqual({error, frame_encoding_error}, quic_frame:decode(ZeroLen)),
    %% CIDLen = 21 (> 20) with 21 CID bytes + token
    BigCid = binary:copy(<<7>>, 21),
    Len21 = <<?FRAME_NEW_CONNECTION_ID, 1, 0, 21, BigCid/binary, Token/binary>>,
    ?assertEqual({error, frame_encoding_error}, quic_frame:decode(Len21)),
    %% Truncated: claims 8-byte CID but not enough bytes follow
    Trunc = <<?FRAME_NEW_CONNECTION_ID, 1, 0, 8, 1, 2, 3>>,
    ?assertEqual({error, frame_encoding_error}, quic_frame:decode(Trunc)).
