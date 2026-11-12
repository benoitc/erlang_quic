%%% -*- erlang -*-
%%%
%%% STOP_SENDING is answered with Reliable Size 0, a RESET_STREAM
%%% (draft-ietf-quic-reliable-stream-reset-11 Section 5.4), and a later
%%% RESET_STREAM_AT cannot raise it. A stream given a reliable size with
%%% quic:set_stream_reliable_size/3 is answered with RESET_STREAM_AT
%%% instead, and the bytes it keeps reliable still go out, even when they
%%% were only queued: WebTransport needs its stream header delivered
%%% (draft-ietf-webtrans-http3-17 Section 4.4).

-module(quic_stop_sending_reliable_size_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

answer_is_reset_stream_test() ->
    S = stop_sending(sent(undefined)),
    ?assertEqual([{reset_stream, ?STREAM, 9, 1000}], resets(S)).

later_reset_stream_at_cannot_raise_it_test() ->
    S1 = stop_sending(sent(undefined)),
    ?assertEqual(
        {error, cannot_increase_reliable_size},
        quic_connection:do_reset_stream_at(?STREAM, 9, 100, S1)
    ),
    ?assertEqual([{reset_stream, ?STREAM, 9, 1000}], resets(S1)).

later_reset_stream_at_after_close_stream_test() ->
    {ok, S1} = quic_connection:do_close_stream(?STREAM, 9, sent(undefined)),
    ?assertEqual(
        {error, cannot_increase_reliable_size},
        quic_connection:do_reset_stream_at(?STREAM, 9, 100, S1)
    ).

reliable_size_answer_keeps_the_queued_header_test() ->
    S = stop_sending(header_queued()),
    ?assertEqual([{reset_stream_at, ?STREAM, 9, 3, 3}], resets(S)),
    ?assertEqual([{0, 3}], queued_ranges(S)).

%%====================================================================
%% Helpers
%%====================================================================

%% 1000 bytes sent on our stream, with this reliable size, to a peer
%% that advertised reset_stream_at.
sent(ReliableSize) ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 1000, false),
    with_reliable_size(S0, ReliableSize).

%% A 3-byte stream header written but still queued, kept reliable.
header_queued() ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 0, false),
    {ok, S} = quic_connection:queue_blocked_send(?STREAM, 0, <<1, 2, 3>>, false, 3, S0),
    with_reliable_size(S, 3).

with_reliable_size(#state{streams = #{?STREAM := Stream}} = S, ReliableSize) ->
    S#state{
        owner = self(),
        transport_params = #{reset_stream_at => true},
        streams = #{?STREAM => Stream#stream_state{reliable_size = ReliableSize}}
    }.

stop_sending(S) ->
    quic_connection:process_frame(app, {stop_sending, ?STREAM, 9}, S).

resets(#state{pend_frames = Frames}) ->
    [F || F <- Frames, element(1, F) =:= reset_stream orelse element(1, F) =:= reset_stream_at].

queued_ranges(#state{send_queue = PQ}) ->
    [
        {Offset, Size}
     || I <- lists:seq(1, 8),
        {stream_data, ?STREAM, Offset, _, _, Size} <- queue:to_list(element(I, PQ))
    ].
