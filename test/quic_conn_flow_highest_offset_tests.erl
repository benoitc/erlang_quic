%%% -*- erlang -*-
%%%
%%% Connection flow control counts the largest offset received on each
%%% stream (RFC 9000 Section 4.1), so data received again or filling a
%%% gap consumes no credit.

-module(quic_conn_flow_highest_offset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

duplicate_at_the_connection_limit_test() ->
    S0 = server(1000, 1000),
    S = frame(0, 500, S0),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual(1000, S#state.data_received).

straddling_frame_counts_its_new_bytes_test() ->
    S = frame(900, 200, server(1000, 2000)),
    ?assertEqual(1100, S#state.data_received).

gap_filled_after_a_later_frame_test() ->
    S1 = frame(1500, 100, server(1000, 3000)),
    ?assertEqual(1600, S1#state.data_received),
    S = frame(1000, 500, S1),
    ?assertEqual(1600, S#state.data_received).

reset_after_a_gap_test() ->
    S1 = frame(1500, 100, server(1000, 3000)),
    S = quic_connection:process_frame(app, {reset_stream, ?STREAM, 0, 2000}, S1),
    ?assertEqual(2000, S#state.data_received).

frame(Offset, Size, S) ->
    quic_connection:process_frame(
        app, {stream, ?STREAM, Offset, binary:copy(<<0>>, Size), false}, S
    ).

%% Bytes 0..Received delivered, connection limit at ConnLimit.
server(Received, ConnLimit) ->
    S = quic_connection_test_support:recv_stream_state(
        ?STREAM, Received, 100000, ConnLimit - Received
    ),
    quic_connection_test_support:with_keys_and_socket(S#state{
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{}
    }).
