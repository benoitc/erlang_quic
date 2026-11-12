%%% -*- erlang -*-
%%%
%%% A peer that changes a stream's final size in a RESET_STREAM_AT, or in a
%%% STREAM frame after one, gets a FINAL_SIZE_ERROR
%%% (draft-ietf-quic-reliable-stream-reset-11 Section 5.2, a MUST).

-module(quic_reset_stream_at_final_size_change_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

fin_then_reset_at_with_another_size_test() ->
    S = frames([{stream, ?STREAM, 0, data(100), true}, {reset_stream_at, ?STREAM, 0, 200, 10}]),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_at_then_reset_at_with_another_size_test() ->
    S = frames([{reset_stream_at, ?STREAM, 0, 100, 10}, {reset_stream_at, ?STREAM, 0, 200, 10}]),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_then_reset_at_with_another_size_test() ->
    S = frames([{reset_stream, ?STREAM, 0, 100}, {reset_stream_at, ?STREAM, 0, 200, 0}]),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_at_then_fin_with_another_size_test() ->
    S = frames([{reset_stream_at, ?STREAM, 0, 100, 50}, {stream, ?STREAM, 80, data(40), true}]),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_at_then_fin_below_the_size_test() ->
    S = frames([{reset_stream_at, ?STREAM, 0, 100, 50}, {stream, ?STREAM, 60, data(20), true}]),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_at_then_data_past_the_size_test() ->
    S = frames([{reset_stream_at, ?STREAM, 0, 100, 50}, {stream, ?STREAM, 90, data(40), false}]),
    ?assertMatch({transport, ?QUIC_FINAL_SIZE_ERROR, _}, S#state.close_reason).

reset_at_then_same_fin_is_accepted_test() ->
    S = frames([{reset_stream_at, ?STREAM, 0, 100, 50}, {stream, ?STREAM, 0, data(100), true}]),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual(50, (maps:get(?STREAM, S#state.streams))#stream_state.recv_offset).

same_size_again_is_accepted_test() ->
    S = frames([
        {stream, ?STREAM, 0, data(100), true},
        {reset_stream_at, ?STREAM, 0, 100, 10},
        {reset_stream_at, ?STREAM, 0, 100, 10}
    ]),
    ?assertEqual(undefined, S#state.close_reason).

%%====================================================================
%% Helpers
%%====================================================================

frames(Frames) ->
    lists:foldl(fun(F, S) -> quic_connection:process_frame(app, F, S) end, server(), Frames).

%% A server that advertised reset_stream_at, with a fresh peer stream.
server() ->
    S = quic_connection_test_support:recv_stream_state(?STREAM, 0, 100000, 1000000),
    #state{cfg = Cfg} =
        S1 = quic_connection_test_support:with_keys_and_socket(S#state{
            max_streams_bidi_local = 100,
            max_streams_uni_local = 100,
            transport_params = #{}
        }),
    S1#state{cfg = Cfg#conn_cfg{reset_stream_at_enabled = true}}.

data(N) -> binary:copy(<<"x">>, N).
