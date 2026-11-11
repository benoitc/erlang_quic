%%% -*- erlang -*-
%%%
%%% Once we have sent RESET_STREAM, no STREAM or STREAM_DATA_BLOCKED frame
%%% follows it (RFC 9000 Sections 3.3 and 4.5).

-module(quic_send_after_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(STREAM, 0).

after_reset_stream_test() ->
    {ok, S} = quic_connection:do_close_stream(?STREAM, 0, sending()),
    assert_refused(S).

after_stop_sending_test() ->
    S0 = (sending())#state{owner = self()},
    S = quic_connection:process_frame(app, {stop_sending, ?STREAM, 7}, S0),
    assert_refused(S).

after_deadline_reset_test() ->
    {ok, S} = quic_connection:do_close_stream_deadline(?STREAM, 0, sending()),
    assert_refused(S).

after_reset_stream_at_test() ->
    S0 = (sending())#state{transport_params = #{reset_stream_at => true}},
    {ok, S} = quic_connection:do_reset_stream_at(?STREAM, 0, 100, S0),
    assert_refused(S).

assert_refused(S) ->
    ?assertMatch(#{?STREAM := _}, S#state.streams),
    ?assertEqual({error, stream_closed}, send(S, check)),
    ?assertEqual({error, stream_closed}, send(S, force)).

send(S, Admission) ->
    case quic_connection:do_send_data(?STREAM, <<"late">>, false, S, Admission) of
        {ok, #state{}} -> sent;
        Other -> Other
    end.

sending() ->
    quic_connection_test_support:state_with_send_stream(?STREAM, 400, false).
