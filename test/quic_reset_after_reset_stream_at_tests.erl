%%% -*- erlang -*-
%%%
%%% A reset that follows our RESET_STREAM_AT on the same stream, while its
%%% reliable bytes are still queued, keeps its error code and final size
%%% (draft-ietf-quic-reliable-stream-reset-11 Section 5.2): a close_stream,
%%% the answer to STOP_SENDING, or a lower reliable size.

-module(quic_reset_after_reset_stream_at_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

close_stream_keeps_code_and_final_size_test() ->
    {ok, S} = quic_connection:do_close_stream(?STREAM, 7, reset_at(undefined)),
    ?assertEqual([{reset_stream, ?STREAM, 9, 500}], plain_resets(S)),
    ?assertEqual([], queued_ranges(S)),
    ?assertEqual(#{}, S#state.pending_send_reset_at).

stop_sending_answer_keeps_code_and_final_size_test() ->
    S = stop_sending(reset_at(undefined)),
    ?assertEqual([{reset_stream, ?STREAM, 9, 500}], plain_resets(S)).

stop_sending_answer_with_reliable_size_keeps_the_code_test() ->
    S = stop_sending(reset_at(450)),
    ?assertEqual([], plain_resets(S)),
    ?assertEqual(
        [{reset_stream_at, ?STREAM, 9, 500, 500}, {reset_stream_at, ?STREAM, 9, 500, 450}],
        lists:reverse([F || {reset_stream_at, _, _, _, _} = F <- S#state.pend_frames])
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% 400 bytes sent and 600 queued, then RESET_STREAM_AT with code 9 and
%% reliable size 500, so 100 reliable bytes are still queued.
reset_at(ReliableSize) ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 400, false),
    {ok, S1} = quic_connection:queue_blocked_send(
        ?STREAM, 400, binary:copy(<<0>>, 600), false, 600, S0
    ),
    #state{streams = #{?STREAM := Stream}} = S1,
    S2 = S1#state{
        owner = self(),
        transport_params = #{reset_stream_at => true},
        streams = #{?STREAM => Stream#stream_state{reliable_size = ReliableSize}}
    },
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 9, 500, S2),
    S.

stop_sending(S) ->
    quic_connection:process_frame(app, {stop_sending, ?STREAM, 5}, S).

plain_resets(#state{pend_frames = Frames}) ->
    [F || {reset_stream, _, _, _} = F <- Frames].

queued_ranges(#state{send_queue = PQ}) ->
    [
        {Offset, Size}
     || I <- lists:seq(1, 8),
        {stream_data, ?STREAM, Offset, _, _, Size} <- queue:to_list(element(I, PQ))
    ].
