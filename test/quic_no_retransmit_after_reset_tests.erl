%%% -*- erlang -*-
%%%
%%% Lost STREAM data is not retransmitted once the stream's send side is
%%% done: after we reset it (RFC 9000 Section 3.1, "Reset Sent"), or
%%% once the stream is gone.

-module(quic_no_retransmit_after_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

after_local_reset_test() ->
    {ok, S0} = quic_connection:do_close_stream(?STREAM, 0, sender()),
    ?assertEqual([], stream_frames(retransmit(S0#state{pend_frames = []}))).

after_the_stream_is_gone_test() ->
    S0 = sender(),
    ?assertEqual([], stream_frames(retransmit(S0#state{streams = #{}}))).

open_stream_is_retransmitted_test() ->
    ?assertMatch([_], stream_frames(retransmit(sender()))).

sender() ->
    quic_connection_test_support:state_with_send_stream(?STREAM, 400, false).

retransmit(S) ->
    Lost = #sent_packet{
        pn = 0,
        time_sent = 0,
        size = 1200,
        ack_eliciting = true,
        in_flight = true,
        frames = [{stream, ?STREAM, 0, binary:copy(<<0>>, 400), false}]
    },
    quic_connection:retransmit_lost_packets([Lost], S).

stream_frames(#state{pend_frames = Frames, send_queue_bytes = Queued}) ->
    [F || {stream, _, _, _, _} = F <- Frames] ++ [{queued, Queued} || Queued > 0].

probe_skips_reset_stream_data_test() ->
    {ok, S0} = quic_connection:do_close_stream(?STREAM, 0, sender()),
    Now = erlang:monotonic_time(millisecond),
    LS = quic_loss:on_packet_sent(
        app, S0#state.loss_state, 0, 1200, true, [{stream, ?STREAM, 0, <<"data">>, false}], Now
    ),
    ?assertEqual(none, quic_connection:get_oldest_unacked_frames(app, S0#state{loss_state = LS})).
