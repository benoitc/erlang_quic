%%% -*- erlang -*-
%%%
%%% The peer's RESET_STREAM and RESET_STREAM_AT on one stream carry the
%%% same error code (draft-ietf-quic-reliable-stream-reset-11 Section 5.2):
%%% a change is a STREAM_STATE_ERROR. The owner hears of the reset once,
%%% whichever frames follow, and a RESET_STREAM after a RESET_STREAM_AT
%%% lowers the reliable size to 0.

-module(quic_reset_stream_at_recv_error_code_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

reset_then_reset_at_with_another_code_test() ->
    {S, _} = frames([{reset_stream, ?STREAM, 1, 100}, {reset_stream_at, ?STREAM, 2, 100, 0}]),
    ?assertMatch({transport, ?QUIC_STREAM_STATE_ERROR, _}, S#state.close_reason).

reset_at_then_reset_with_another_code_test() ->
    {S, _} = frames([{reset_stream_at, ?STREAM, 1, 100, 50}, {reset_stream, ?STREAM, 2, 100}]),
    ?assertMatch({transport, ?QUIC_STREAM_STATE_ERROR, _}, S#state.close_reason).

reset_at_then_reset_is_reported_once_test() ->
    {S, Resets} = frames([{reset_stream_at, ?STREAM, 1, 100, 50}, {reset_stream, ?STREAM, 1, 100}]),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual([{stream_reset, ?STREAM, 1}], Resets),
    #stream_state{recv_done = Done, recv_reset_at = R} = maps:get(?STREAM, S#state.streams),
    ?assertEqual({true, 0}, {Done, R}).

reset_then_reset_at_is_reported_once_test() ->
    {S, Resets} = frames([{reset_stream, ?STREAM, 1, 100}, {reset_stream_at, ?STREAM, 1, 100, 0}]),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual([{stream_reset, ?STREAM, 1}], Resets).

repeated_reset_at_is_reported_once_test() ->
    {S, Resets} = frames([
        {reset_stream_at, ?STREAM, 1, 100, 50}, {reset_stream_at, ?STREAM, 1, 100, 50}
    ]),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual([{stream_reset, ?STREAM, 1}], Resets).

lower_reliable_size_is_kept_and_reported_once_test() ->
    {S, Resets} = frames([
        {reset_stream_at, ?STREAM, 1, 100, 50},
        {reset_stream_at, ?STREAM, 1, 100, 20},
        {reset_stream_at, ?STREAM, 1, 100, 40}
    ]),
    ?assertEqual([{stream_reset, ?STREAM, 1}], Resets),
    ?assertEqual(20, (maps:get(?STREAM, S#state.streams))#stream_state.recv_reset_at).

%% After the RESET_STREAM nothing below the old reliable size is delivered.
late_data_after_reset_is_dropped_test() ->
    {S, _} = frames([
        {reset_stream_at, ?STREAM, 1, 100, 50},
        {reset_stream, ?STREAM, 1, 100},
        {stream, ?STREAM, 0, data(30), false}
    ]),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual(0, (maps:get(?STREAM, S#state.streams))#stream_state.recv_offset).

%% RFC 9000 alone does not tie RESET_STREAM error codes together.
reset_then_reset_with_another_code_is_ignored_test() ->
    {S, Resets} = frames([{reset_stream, ?STREAM, 1, 100}, {reset_stream, ?STREAM, 2, 100}]),
    ?assertEqual(undefined, S#state.close_reason),
    ?assertEqual([{stream_reset, ?STREAM, 1}], Resets).

%%====================================================================
%% Helpers
%%====================================================================

frames(Frames) ->
    flush(),
    S = lists:foldl(
        fun(F, Acc) -> quic_connection:process_frame(app, F, Acc) end, server(), Frames
    ),
    {S, flush()}.

flush() ->
    receive
        {quic, _, {stream_reset, _, _} = Reset} -> [Reset | flush()];
        {quic, _, _} -> flush()
    after 0 -> []
    end.

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
