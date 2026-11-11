%%% -*- erlang -*-
%%%
%%% A stream that has used up its own flow-control window must not hold
%%% back the other streams queued behind it (RFC 9000 Section 4.1: a
%%% stream limit applies to that stream only). Only a connection-level
%%% limit stops the whole send queue.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_send_queue_stream_block_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").
-include_lib("quic/include/quic_qlog.hrl").
-include_lib("quic/src/quic_connection_state.hrl").

-define(S, quic_connection_test_support).
-define(WIN, 1000000).
-define(SIZE, 1000).

%%====================================================================
%% Queue drain
%%====================================================================

other_stream_is_sent_past_a_blocked_one_test() ->
    S0 = queue([{0, 0}, {4, 0}], ?S:state_with_send_windows([{0, 3, 0}, {4, 3, ?WIN}], ?WIN)),
    Sent0 = ?S:datagrams_out(S0),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual([{0, 0, ?SIZE}], ?S:queued_entries(S1)),
    ?assert(?S:datagrams_out(S1) > Sent0).

each_stream_keeps_its_order_test() ->
    Streams = [{0, 3, 0}, {4, 3, ?WIN}, {8, 3, 0}],
    S0 = queue(
        [{0, 0}, {4, 0}, {8, 0}, {0, ?SIZE}, {4, ?SIZE}, {8, ?SIZE}],
        ?S:state_with_send_windows(Streams, ?WIN)
    ),
    Left = ?S:queued_entries(quic_connection:process_send_queue(S0)),
    ?assertEqual([{0, 0, ?SIZE}, {0, ?SIZE, ?SIZE}], [E || {0, _, _} = E <- Left]),
    ?assertEqual([{8, 0, ?SIZE}, {8, ?SIZE, ?SIZE}], [E || {8, _, _} = E <- Left]),
    ?assertEqual(4, length(Left)).

less_urgent_stream_is_sent_past_a_blocked_one_test() ->
    S0 = queue([{0, 0}, {4, 0}], ?S:state_with_send_windows([{0, 1, 0}, {4, 5, ?WIN}], ?WIN)),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual([{0, 0, ?SIZE}], ?S:queued_entries(S1)).

%% The stream behind has room for part of its entry: that part goes out.
prefix_is_sent_past_a_blocked_stream_test() ->
    S0 = queue([{0, 0}, {4, 0}], ?S:state_with_send_windows([{0, 3, 0}, {4, 3, 400}], ?WIN)),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual([{0, 0, ?SIZE}, {4, 400, ?SIZE - 400}], lists:sort(?S:queued_entries(S1))).

%% The blocked stream is sent first again once it has credit.
unblocked_stream_is_sent_test() ->
    S0 = queue([{0, 0}, {4, 0}], ?S:state_with_send_windows([{0, 3, 0}, {4, 3, 0}], ?WIN)),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual([{0, 0, ?SIZE}, {4, 0, ?SIZE}], ?S:queued_entries(S1)),
    S2 = quic_connection:process_frame(app, {max_stream_data, 4, ?WIN}, S1),
    ?assertEqual([{0, 0, ?SIZE}], ?S:queued_entries(S2)).

%% Fence: the connection window is closed, so nothing may pass.
connection_block_stops_the_queue_test() ->
    S0 = queue([{0, 0}, {4, 0}], ?S:state_with_send_windows([{0, 3, 0}, {4, 3, ?WIN}], 0)),
    Sent0 = ?S:datagrams_out(S0),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual([{0, 0, ?SIZE}, {4, 0, ?SIZE}], lists:sort(?S:queued_entries(S1))),
    ?assertEqual(Sent0, ?S:datagrams_out(S1)).

%% Entries blocked by their own stream's window are visited once: a later
%% drain costs the same however many of them wait.
drain_work_does_not_grow_with_blocked_entries_test() ->
    Small = drain_work(10),
    Large = drain_work(10000),
    ?assert(Large < Small + 1000).

drain_work(Blocked) ->
    Data = binary:copy(<<"x">>, 10),
    S0 = lists:foldl(
        fun(I, S) -> ?S:queue_stream(S, 0, I * 10, Data) end,
        ?S:state_with_send_windows([{0, 3, 0}, {4, 3, ?WIN}], ?WIN),
        lists:seq(0, Blocked - 1)
    ),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual(Blocked, length(?S:parked_entries(S1))),
    S2 = ?S:queue_stream(S1, 4, 0, Data),
    true = erlang:garbage_collect(),
    {reductions, R0} = erlang:process_info(self(), reductions),
    S3 = quic_connection:process_send_queue(S2),
    {reductions, R1} = erlang:process_info(self(), reductions),
    ?assertEqual([], [E || {4, _, _} = E <- ?S:queued_entries(S3)]),
    ?assertEqual(Blocked, length(?S:parked_entries(S3))),
    R1 - R0.

%% A new limit puts back what it has room for, in offset order; the tail
%% of a split entry waits ahead of the rest, and new data waits behind.
parked_entries_keep_stream_order_test() ->
    S0 = queue([{0, 0}, {0, ?SIZE}, {0, 2 * ?SIZE}], ?S:state_with_send_windows([{0, 3, 0}], ?WIN)),
    S1 = quic_connection:process_send_queue(S0),
    ?assertEqual([{0, 0, ?SIZE}, {0, ?SIZE, ?SIZE}, {0, 2 * ?SIZE, ?SIZE}], ?S:parked_entries(S1)),
    S2 = quic_connection:process_frame(app, {max_stream_data, 0, 1500}, S1),
    ?assertEqual(1500, S2#state.data_sent),
    ?assertEqual([{0, 1500, 500}, {0, 2 * ?SIZE, ?SIZE}], ?S:queued_entries(S2)),
    S3 = quic_connection:process_send_queue(queue([{0, 3 * ?SIZE}], S2)),
    ?assertEqual(
        [{0, 1500, 500}, {0, 2 * ?SIZE, ?SIZE}, {0, 3 * ?SIZE, ?SIZE}], ?S:queued_entries(S3)
    ),
    S4 = quic_connection:process_frame(app, {max_stream_data, 0, ?WIN}, S3),
    ?assertEqual(4 * ?SIZE, S4#state.data_sent),
    ?assertEqual({[], 0, 0}, {
        ?S:queued_entries(S4), S4#state.send_queue_bytes, S4#state.send_queue_count
    }).

%% Entries put back return to their stream's urgency.
parked_entries_keep_their_urgency_test() ->
    S0 = queue([{4, 0}, {0, 0}], ?S:state_with_send_windows([{0, 1, 0}, {4, 5, 0}], ?WIN)),
    S1 = quic_connection:process_send_queue(S0),
    S2 = quic_connection:unpark_stream(0, ?WIN, quic_connection:unpark_stream(4, ?WIN, S1)),
    ?assertMatch({value, {stream_data, 0, 0, _, _, ?SIZE}}, ?S:queue_head(S2)),
    ?assertEqual([], ?S:parked_entries(S2)).

%% A FIN-only entry at the new limit fits it.
parked_fin_goes_out_at_the_limit_test() ->
    S0 = queue([{0, 0}], ?S:state_with_send_windows([{0, 3, 0}], ?WIN)),
    S1 = quic_connection:process_send_queue(
        quic_connection:queue_stream_data(0, ?SIZE, <<>>, true, S0)
    ),
    ?assertEqual([{0, 0, ?SIZE}, {0, ?SIZE, 0}], ?S:parked_entries(S1)),
    S2 = quic_connection:process_frame(app, {max_stream_data, 0, ?SIZE}, S1),
    ?assertEqual({[], 0}, {?S:queued_entries(S2), S2#state.send_queue_count}).

%% A reset drops the parked entries, and its final size covers only what
%% was sent (RFC 9000 Section 4.5).
reset_drops_parked_entries_test() ->
    S0 = queue([{0, 0}, {0, ?SIZE}], ?S:state_with_send_windows([{0, 3, 0}, {4, 3, 0}], ?WIN)),
    S1 = quic_connection:process_send_queue(queue([{4, 0}], S0)),
    #{0 := Stream} = S1#state.streams,
    ?assertEqual(0, quic_connection:reset_final_size(0, Stream, S1)),
    ?assert(quic_connection:stream_has_queued_below(0, 1, S1)),
    S2 = quic_connection:purge_stream_send_queue(0, S1),
    ?assertEqual([{4, 0, ?SIZE}], ?S:queued_entries(S2)),
    ?assertEqual({?SIZE, 1}, {S2#state.send_queue_bytes, S2#state.send_queue_count}).

queue(Entries, State) ->
    lists:foldl(
        fun({StreamId, Offset}, S) ->
            ?S:queue_stream(S, StreamId, Offset, binary:copy(<<"x">>, ?SIZE))
        end,
        State,
        Entries
    ).

%%====================================================================
%% Over a connection
%%====================================================================

%% The server never returns credit on the client's first stream. What the
%% client writes on its second stream afterwards must still all arrive.
second_stream_arrives_while_first_is_blocked_test_() ->
    {timeout, 60, fun second_stream_arrives_while_first_is_blocked/0}.

second_stream_arrives_while_first_is_blocked() ->
    Window = 65536,
    Total = 4 * Window,
    Test = self(),
    {ok, Server} = quic_test_echo_server:start(#{
        max_stream_data_bidi_remote => Window,
        max_receive_window => Window,
        connection_handler => fun(Conn, _Ref) ->
            {ok, spawn(fun() -> reader(Test, Conn, #{}) end)}
        end
    }),
    {ok, Conn} = quic:connect(
        <<"127.0.0.1">>, maps:get(port, Server), #{verify => false, alpn => [<<"echo">>]}, self()
    ),
    try
        receive
            {quic, Conn, {connected, _}} -> ok
        after 5000 -> error(not_connected)
        end,
        {ok, First} = quic:open_stream(Conn),
        {ok, Second} = quic:open_stream(Conn),
        ok = quic:send_data(Conn, First, binary:copy(<<"a">>, Total), false),
        %% The first stream has filled its window once the reader has it all.
        ?assertEqual(Window, await_received(First, Window)),
        ok = quic:send_data(Conn, Second, binary:copy(<<"b">>, Total), true),
        ?assertEqual(Total, await_received(Second, Total))
    after
        quic:close(Conn, normal),
        quic_test_echo_server:stop(Server)
    end.

await_received(StreamId, Wanted) ->
    receive
        {received, StreamId, N} when N >= Wanted -> N
    after 10000 ->
        receive
            {received, StreamId, N} -> N
        after 0 -> 0
        end
    end.

%% Never consumes on stream 0, so its window is never extended.
reader(Test, Conn, Seen) ->
    receive
        {quic, Conn, {stream_opened, 0}} ->
            ok = quic:set_stream_flow_control(Conn, 0, manual),
            reader(Test, Conn, Seen);
        {quic, Conn, {stream_data, StreamId, Data, _Fin}} ->
            N = maps:get(StreamId, Seen, 0) + byte_size(Data),
            Test ! {received, StreamId, N},
            reader(Test, Conn, Seen#{StreamId => N});
        {quic, Conn, {closed, _}} ->
            ok;
        _ ->
            reader(Test, Conn, Seen)
    end.
