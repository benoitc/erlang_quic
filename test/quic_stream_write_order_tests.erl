%%% -*- erlang -*-
%%%
%%% A write goes behind what its stream still has in the send queue. Sent
%%% at once because the window has room for it, a small write would
%%% overtake the stream's own data: a bare FIN reaches the peer, and is
%%% acknowledged, long before the bytes it ends.

-module(quic_stream_write_order_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).

a_fin_waits_behind_the_streams_queued_data_test() ->
    S0 = ?S:queue_stream(?S:state_for_admission(0, 0, 1000000, 1000000), 0, 0, data(3000)),
    {ok, S1} = quic_connection:do_send_data(0, <<>>, true, S0, check),
    ?assertEqual([{0, 0, 3000}, {0, 3000, 0}], ?S:queued_entries(S1)),
    ?assertEqual([], ?S:app_packets_sent(S1)),
    ?assertMatch(#{0 := #stream_state{send_offset = 3000, send_fin = false}}, S1#state.streams).

data_waits_behind_the_streams_queued_data_test() ->
    S0 = ?S:queue_stream(?S:state_for_admission(0, 0, 1000000, 1000000), 0, 0, data(3000)),
    {ok, S1} = quic_connection:do_send_data(0, data(100), false, S0, check),
    ?assertEqual([{0, 0, 3000}, {0, 3000, 100}], ?S:queued_entries(S1)),
    ?assertEqual([], ?S:app_packets_sent(S1)).

%% Nothing of the stream is waiting: the write goes out as before.
a_write_with_nothing_queued_is_sent_test() ->
    S0 = ?S:state_for_admission(0, 0, 1000000, 1000000),
    {ok, S1} = quic_connection:do_send_data(0, data(100), true, S0, check),
    ?assertEqual([], ?S:queued_entries(S1)),
    ?assertMatch([{_, [{stream, 0, 0, _, true}]}], ?S:app_packets_sent(S1)).

%% Another stream's queued data does not hold a write back.
another_streams_queue_does_not_hold_a_write_test() ->
    S0 = ?S:queue_stream(?S:state_with_send_streams([0, 4]), 0, 0, data(3000)),
    {ok, S1} = quic_connection:do_send_data(4, data(100), false, S0, check),
    ?assertEqual([{0, 0, 3000}], ?S:queued_entries(S1)),
    ?assertMatch([{_, [{stream, 4, 0, _, false}]}], ?S:app_packets_sent(S1)).

data(Size) ->
    binary:copy(<<"d">>, Size).
