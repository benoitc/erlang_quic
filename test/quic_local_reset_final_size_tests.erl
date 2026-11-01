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

nothing_queued_test() ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 1000, false),
    ?assertEqual([1000], final_sizes(quic_connection:do_close_stream(?STREAM, 0, S0))).

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
