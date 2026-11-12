%%% -*- erlang -*-
%%%
%%% The Final Size of a RESET_STREAM_AT we send is what we sent plus the
%%% reliable bytes still queued, never more than the peer's stream and
%%% connection limits allow, and it does not change in a later frame
%%% (draft-ietf-quic-reliable-stream-reset-11 Sections 4 and 5.2).

-module(quic_reset_stream_at_final_size_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

queued_data_is_not_in_the_final_size_test() ->
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 9, 100, queued()),
    ?assertEqual([{reset_stream_at, ?STREAM, 9, 400, 100}], resets(S)).

queued_reliable_bytes_are_in_the_final_size_test() ->
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 9, 500, queued()),
    ?assertEqual([{reset_stream_at, ?STREAM, 9, 500, 500}], resets(S)),
    ?assertEqual([{400, 100}], queued_ranges(S)).

beyond_the_stream_limit_is_refused_test() ->
    S0 = with_stream(queued(), fun(St) -> St#stream_state{send_max_data = 400} end),
    ?assertEqual(
        {error, flow_control_blocked}, quic_connection:do_reset_stream_at(?STREAM, 9, 500, S0)
    ).

beyond_the_connection_limit_is_refused_test() ->
    S0 = (with_stream(queued(), fun(St) -> St#stream_state{send_highest = 400} end))#state{
        max_data_remote = 450
    },
    ?assertEqual(
        {error, flow_control_blocked}, quic_connection:do_reset_stream_at(?STREAM, 9, 500, S0)
    ),
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 9, 450, S0),
    ?assertEqual([{reset_stream_at, ?STREAM, 9, 450, 450}], resets(S)).

%% A reset quic sends on its own keeps the reliable size within the limits.
own_reset_stays_within_the_stream_limit_test() ->
    S0 = with_stream(queued(), fun(St) ->
        St#stream_state{send_max_data = 450, reliable_size = 700}
    end),
    S = quic_connection:process_frame(app, {stop_sending, ?STREAM, 9}, S0#state{owner = self()}),
    ?assertEqual([{reset_stream_at, ?STREAM, 9, 450, 450}], resets(S)).

lower_reliable_size_keeps_the_final_size_test() ->
    {ok, S1} = quic_connection:do_reset_stream_at(?STREAM, 9, 500, queued()),
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 9, 450, S1),
    ?assertEqual(
        [{reset_stream_at, ?STREAM, 9, 500, 500}, {reset_stream_at, ?STREAM, 9, 500, 450}],
        resets(S)
    ).

%%====================================================================
%% Helpers
%%====================================================================

%% 400 bytes sent and 600 queued behind them, to a peer that advertised
%% reset_stream_at.
queued() ->
    S0 = quic_connection_test_support:state_with_send_stream(?STREAM, 400, false),
    {ok, S} = quic_connection:queue_blocked_send(
        ?STREAM, 400, binary:copy(<<0>>, 600), false, 600, S0
    ),
    S#state{transport_params = #{reset_stream_at => true}}.

with_stream(#state{streams = #{?STREAM := St} = Streams} = S, F) ->
    S#state{streams = Streams#{?STREAM := F(St)}}.

resets(#state{pend_frames = Frames}) ->
    [F || F <- lists:reverse(Frames), element(1, F) =:= reset_stream_at].

queued_ranges(#state{send_queue = PQ}) ->
    [
        {Offset, Size}
     || I <- lists:seq(1, 8),
        {stream_data, ?STREAM, Offset, _, _, Size} <- queue:to_list(element(I, PQ))
    ].
