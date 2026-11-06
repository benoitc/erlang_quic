%%% -*- erlang -*-
%%%
%%% A connection that closes because of a peer error leaves the
%%% connected state (RFC 9000 Section 10.2).
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_local_close_draining_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(SID, 4).
-define(WIN, ?DEFAULT_MAX_RECEIVE_WINDOW).

data_past_the_final_size_test() ->
    S0 = recv_state(),
    S1 = quic_connection:do_process_stream_data_slow(?SID, 0, <<"first">>, true, S0),
    S2 = quic_connection:do_process_stream_data_slow(?SID, 5, <<"after">>, false, S1),
    assert_closed(?QUIC_FINAL_SIZE_ERROR, S2).

data_past_the_stream_limit_test() ->
    S = quic_connection:do_process_stream_data_slow(?SID, 2 * ?WIN, <<"x">>, false, recv_state()),
    assert_closed(?QUIC_FLOW_CONTROL_ERROR, S).

reset_stream_that_moves_the_final_size_test() ->
    S0 = recv_state(),
    S1 = quic_connection:do_process_stream_data_slow(?SID, 0, <<"first">>, true, S0),
    S2 = quic_connection:process_frame(app, {reset_stream, ?SID, 0, 100}, S1),
    assert_closed(?QUIC_FINAL_SIZE_ERROR, S2).

unexpected_datagram_test() ->
    S = quic_connection:process_frame(app, {datagram, <<"x">>}, sending_state()),
    assert_closed(?QUIC_PROTOCOL_VIOLATION, S).

max_data_outside_1rtt_test() ->
    S = quic_connection:process_frame(handshake, {max_data, 100}, sending_state()),
    assert_closed(?QUIC_PROTOCOL_VIOLATION, S).

max_stream_data_outside_1rtt_test() ->
    S = quic_connection:process_frame(handshake, {max_stream_data, ?SID, 100}, sending_state()),
    assert_closed(?QUIC_PROTOCOL_VIOLATION, S).

max_streams_outside_1rtt_test() ->
    S = quic_connection:process_frame(handshake, {max_streams, bidi, 100}, sending_state()),
    assert_closed(?QUIC_PROTOCOL_VIOLATION, S).

data_blocked_outside_1rtt_test() ->
    S = quic_connection:process_frame(handshake, {data_blocked, 100}, sending_state()),
    assert_closed(?QUIC_PROTOCOL_VIOLATION, S).

tls_alert_test() ->
    S = quic_connection:send_tls_alert(?TLS_ALERT_UNEXPECTED_MESSAGE, sending_state()),
    ?assertMatch({next_state, draining, _}, quic_connection:check_state_transition(handshaking, S)).

assert_closed(Code, State) ->
    ?assertMatch({transport, Code, _}, quic_connection_test_support:close_reason(State)),
    ?assertMatch(
        {next_state, draining, _}, quic_connection:check_state_transition(connected, State)
    ).

recv_state() ->
    quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:recv_stream_state(?SID, 0, ?WIN, 2 * ?WIN)
    ).

sending_state() ->
    quic_connection_test_support:with_keys_and_socket(
        quic_connection_test_support:state_for_role(server)
    ).
