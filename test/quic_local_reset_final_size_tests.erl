%%% -*- erlang -*-
%%%
%%% The final size of a stream we reset is what we sent on it: data
%%% still queued, never sent, is not part of it (RFC 9000 Section 4.5).

-module(quic_local_reset_final_size_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

close_test() ->
    ?assertEqual([400], final_sizes(quic_connection:do_close_stream(?STREAM, 0, queued()))).

deadline_test() ->
    ?assertEqual(
        [400], final_sizes(quic_connection:do_close_stream_deadline(?STREAM, 0, queued()))
    ).

%% The peer's STOP_SENDING is answered with the size sent, before the
%% queued data is dropped.
stop_sending_test() ->
    S0 = (queued())#state{owner = self()},
    ?assertEqual(
        [400], final_sizes(quic_connection:process_frame(app, {stop_sending, ?STREAM, 0}, S0))
    ).

nothing_queued_test() ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 1000, false),
    ?assertEqual([1000], final_sizes(quic_connection:do_close_stream(?STREAM, 0, S0))).

%% RFC 9000 Section 13.3: a RESET_STREAM sent again does not change.
second_reset_test() ->
    {ok, S1} = quic_connection:do_close_stream(?STREAM, 0, queued()),
    {ok, S} = quic_connection:do_close_stream(?STREAM, 1, S1),
    ?assertEqual(
        [{reset_stream, ?STREAM, 0, 400}],
        [F || {reset_stream, _, _, _} = F <- S#state.pend_frames]
    ).

%% A FIN sent ahead of data still queued fixed the final size: every reset
%% carries it, or the peer closes with FINAL_SIZE_ERROR (RFC 9000 Section
%% 4.5).
fin_sent_ahead_of_queued_data_test_() ->
    S = fin_ahead(),
    [
        ?_assertEqual([1000], final_sizes(quic_connection:do_close_stream(?STREAM, 0, S))),
        ?_assertEqual([1000], final_sizes(quic_connection:do_close_stream_deadline(?STREAM, 0, S))),
        ?_assertEqual(
            [1000],
            final_sizes(
                quic_connection:process_frame(app, {stop_sending, ?STREAM, 0}, S#state{
                    owner = self()
                })
            )
        )
    ].

%% A RESET_STREAM_AT after that FIN keeps its final size too.
reset_stream_at_after_the_fin_test() ->
    S0 = (fin_ahead())#state{transport_params = #{reset_stream_at => true}},
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 9, 100, S0),
    ?assertEqual(
        [{reset_stream_at, ?STREAM, 9, 1000, 100}],
        [F || {reset_stream_at, _, _, _, _} = F <- S#state.pend_frames]
    ).

%% Without the FIN, a write sent ahead of queued data still counts: the
%% final size is at least the highest offset sent.
write_sent_ahead_of_queued_data_test() ->
    S = sent_ahead(<<"tail">>, false),
    ?assertEqual([1004], final_sizes(quic_connection:do_close_stream(?STREAM, 0, S))).

%% 400 bytes sent, then 600 held back by a full congestion window, then
%% Data and Fin sent at offset 1000, ahead of the 600 still queued. A
%% write no longer overtakes its stream's queued data, so the frame is
%% sent here directly, and the stream left as a write would leave it.
sent_ahead(Data, Fin) ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 400, false),
    Full = quic_cc:on_packet_sent(quic_cc:new(#{}), quic_cc:cwnd(quic_cc:new(#{}))),
    {ok, S1} = quic_connection:do_send_data(
        ?STREAM, binary:copy(<<0>>, 600), false, S0#state{cc_state = Full}, force
    ),
    ?assertMatch([{400, 600}], queued_ranges(S1)),
    End = 1000 + iolist_size(Data),
    {S2a, _} = quic_connection:send_stream_data_fragmented_tracked(
        ?STREAM, 1000, Data, Fin, S1#state{cc_state = quic_cc:new(#{})}
    ),
    #state{streams = #{?STREAM := Stream} = Streams} = S2a,
    S2 = quic_connection:count_sent(?STREAM, End, S2a#state{
        streams = Streams#{?STREAM := Stream#stream_state{send_offset = End, send_fin = Fin}}
    }),
    ?assertMatch([{400, 600}], queued_ranges(S2)),
    ?assert(lists:member({1000, iolist_size(Data), Fin}, sent_ranges(S2))),
    S2.

fin_ahead() ->
    sent_ahead(<<>>, true).

queued_ranges(#state{send_queue = PQ}) ->
    [
        {O, Size}
     || I <- lists:seq(1, 8),
        {stream_data, ?STREAM, O, _, _, Size} <- queue:to_list(element(I, PQ))
    ].

%% {Offset, Length, Fin} of the stream frames sent, pending ones included.
sent_ranges(#state{loss_state = L, pend_frames = Pend}) ->
    Sent = lists:append([
        F
     || #sent_packet{frames = F} <- maps:values(quic_loss:sent_packets(app, L))
    ]),
    [{O, iolist_size(D), Fin} || {stream, ?STREAM, O, D, Fin} <- Sent ++ Pend].

%% 400 bytes sent, 600 queued behind them.
queued() ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 400, false),
    {ok, S} = quic_connection:queue_blocked_send(
        ?STREAM, 400, binary:copy(<<0>>, 600), false, 600, S0
    ),
    S.

final_sizes(Result) ->
    #state{pend_frames = Frames} =
        case Result of
            {ok, S} -> S;
            #state{} = S -> S
        end,
    [F || {reset_stream, ?STREAM, _, F} <- Frames].
