%%% -*- erlang -*-
%%%
%%% A final size below the data already received is a FINAL_SIZE_ERROR
%%% (RFC 9000 Sections 4.5 and 20.1), and one above the stream's flow
%%% control limit a FLOW_CONTROL_ERROR (Section 4.1).

-module(quic_final_size_checks_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

reset_below_received_test() ->
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, close({reset_stream, ?STREAM, 0, 50})).

reset_below_buffered_test() ->
    S0 = frame({stream, ?STREAM, 500, binary:copy(<<0>>, 100), false}, server()),
    S = frame({reset_stream, ?STREAM, 0, 550}, S0),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_above_limit_test() ->
    ?assertMatch(
        {transport, ?QUIC_FLOW_CONTROL_ERROR, _}, close({reset_stream, ?STREAM, 0, 200000})
    ).

fin_below_received_test() ->
    ?assertMatch(
        {transport, ?QUIC_FINAL_SIZE_ERROR, _}, close({stream, ?STREAM, 40, <<"x">>, true})
    ).

reset_at_received_test() ->
    ?assertEqual(undefined, close({reset_stream, ?STREAM, 0, 100})).

close(Frame) ->
    S = frame(Frame, server()),
    S#state.close_reason.

frame(Frame, S) ->
    quic_connection:process_frame(app, Frame, S).

%% 100 bytes received on a stream with a 100000-byte limit.
server() ->
    S = quic_connection_test_support:recv_stream_state(?STREAM, 100, 99900, 1000000),
    quic_connection_test_support:with_keys_and_socket(S#state{
        max_streams_bidi_local = 100,
        max_streams_uni_local = 100,
        transport_params = #{}
    }).
