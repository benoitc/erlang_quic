%% With delivery_coalescing on, consecutive same-stream deliveries of
%% one receive pass reach the owner as one message; everything else
%% about delivery (order across streams, FIN, the default) is unchanged.
-module(quic_delivery_coalescing_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(WIN, ?DEFAULT_MAX_RECEIVE_WINDOW).

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

messages() ->
    {messages, Msgs} = process_info(self(), messages),
    Msgs.

%% Streams 4 and 8 at offset 0, wide windows, inside a receive pass.
state(Coalescing) ->
    flush(),
    S0 = quic_connection:test_recv_stream_state(4, 0, ?WIN, 2 * ?WIN),
    S1 = quic_connection:test_add_recv_stream(S0, 8, ?WIN),
    quic_connection:test_state_coalescing(quic_connection:test_state_in_recv_pass(S1), Coalescing).

deliver(S, StreamId, Offset, Data, Fin) ->
    quic_connection:do_process_stream_data_buffered(StreamId, Offset, Data, Fin, S).

finish(S) ->
    {S1, _} = quic_connection:test_finish_recv_pass(S),
    S1.

data(StreamId, Msgs) ->
    [{D, F} || {quic, _, {stream_data, Id, D, F}} <- Msgs, Id =:= StreamId].

adjacent_chunks_merge_test() ->
    S0 = state(true),
    S1 = deliver(S0, 4, 0, <<"aaa">>, false),
    S2 = deliver(S1, 4, 3, <<"bbb">>, false),
    S3 = deliver(S2, 4, 6, <<"ccc">>, false),
    ?assertEqual([], messages()),
    ?assertMatch(
        {4, [<<"ccc">>, <<"bbb">>, <<"aaa">>], false}, quic_connection:test_pending_delivery(S3)
    ),
    S4 = finish(S3),
    ?assertEqual([{<<"aaabbbccc">>, false}], data(4, messages())),
    ?assertEqual(none, quic_connection:test_pending_delivery(S4)).

fin_merges_into_the_run_test() ->
    S0 = state(true),
    S1 = deliver(S0, 4, 0, <<"aaa">>, false),
    S2 = deliver(S1, 4, 3, <<"bbb">>, true),
    _ = finish(S2),
    ?assertEqual([{<<"aaabbb">>, true}], data(4, messages())).

%% Only adjacent chunks of one stream merge: another stream's delivery
%% flushes the pending run first, so arrival order is preserved.
another_stream_flushes_first_test() ->
    S0 = state(true),
    S1 = deliver(S0, 4, 0, <<"a1">>, false),
    S2 = deliver(S1, 8, 0, <<"b1">>, false),
    S3 = deliver(S2, 4, 2, <<"a2">>, false),
    _ = finish(S3),
    Msgs = [M || {quic, _, M} <- messages(), element(1, M) =:= stream_data],
    ?assertEqual(
        [
            {stream_data, 4, <<"a1">>, false},
            {stream_data, 8, <<"b1">>, false},
            {stream_data, 4, <<"a2">>, false}
        ],
        Msgs
    ).

%% Flushing a run that grew through the general path (a gap filled
%% mid-pass) still yields the bytes in order.
out_of_order_fill_test() ->
    S0 = state(true),
    S1 = deliver(S0, 4, 3, <<"bbb">>, false),
    ?assertEqual(none, quic_connection:test_pending_delivery(S1)),
    S2 = deliver(S1, 4, 0, <<"aaa">>, false),
    S3 = deliver(S2, 4, 6, <<"ccc">>, false),
    _ = finish(S3),
    ?assertEqual([{<<"aaabbbccc">>, false}], data(4, messages())).

off_by_default_delivers_per_frame_test() ->
    S0 = state(false),
    S1 = deliver(S0, 4, 0, <<"aaa">>, false),
    S2 = deliver(S1, 4, 3, <<"bbb">>, false),
    ?assertEqual([{<<"aaa">>, false}, {<<"bbb">>, false}], data(4, messages())),
    ?assertEqual(none, quic_connection:test_pending_delivery(S2)).

outside_a_pass_delivers_per_frame_test() ->
    flush(),
    S0 = quic_connection:test_recv_stream_state(4, 0, ?WIN, 2 * ?WIN),
    S = quic_connection:test_state_coalescing(S0, true),
    S1 = deliver(S, 4, 0, <<"aaa">>, false),
    _ = deliver(S1, 4, 3, <<"bbb">>, false),
    ?assertEqual([{<<"aaa">>, false}, {<<"bbb">>, false}], data(4, messages())).

%% The run flushes even when the pass initiated a close: the data
%% arrived before the close did.
flushes_when_the_pass_closes_test() ->
    S0 = state(true),
    S1 = deliver(S0, 4, 0, <<"aaa">>, false),
    S2 = quic_connection:test_state_closing(S1, {application, 0, <<>>}),
    _ = finish(S2),
    ?assertEqual([{<<"aaa">>, false}], data(4, messages())).

%% A RESET_STREAM arriving mid-pass must not overtake data the stream
%% delivered earlier in the same pass.
reset_does_not_overtake_pending_data_test() ->
    S0 = state(true),
    S1 = deliver(S0, 4, 0, <<"aaa">>, false),
    ?assertEqual([], messages()),
    S2 = quic_connection:process_frame(app, {reset_stream, 4, 7, 3}, S1),
    ?assertEqual(none, quic_connection:test_pending_delivery(S2)),
    Msgs = [M || {quic, _, M} <- messages(), element(2, M) =:= 4],
    ?assertEqual([{stream_data, 4, <<"aaa">>, false}, {stream_reset, 4, 7}], Msgs).
