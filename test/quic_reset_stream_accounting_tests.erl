%%% -*- erlang -*-
%%%
%%% A stream the peer resets counts its final size against connection
%%% flow control (RFC 9000 Section 4.5), and gives back the receive
%%% buffer its out-of-order data held.

-module(quic_reset_stream_accounting_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

counts_the_unreceived_tail_test() ->
    S = reset(1000, server(100)),
    ?assertEqual(1000, S#state.data_received).

counts_a_stream_reset_before_any_data_test() ->
    S0 = server(100),
    S = quic_connection:process_frame(app, {reset_stream, 4, 0, 1000}, S0),
    ?assertEqual(1100, S#state.data_received).

releases_buffered_data_test() ->
    S0 = quic_connection:process_frame(
        app, {stream, ?STREAM, 500, binary:copy(<<0>>, 100), false}, server(100)
    ),
    ?assertEqual(100, S0#state.recv_buffer_bytes),
    S = reset(1000, S0),
    ?assertEqual(0, S#state.recv_buffer_bytes),
    ?assertEqual(1000, S#state.data_received).

reset(FinalSize, S) ->
    quic_connection:process_frame(app, {reset_stream, ?STREAM, 0, FinalSize}, S).

server(Received) ->
    S = quic_connection_test_support:recv_stream_state(?STREAM, Received, 100000, 100000),
    quic_connection_test_support:with_keys_and_socket(S#state{
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{}
    }).
