%% A batch-opened run whose packets continue the receive sequence and
%% carry one stream frame each, same stream, contiguous offsets, no
%% FIN, is folded with one bookkeeping pass. The observable outcome
%% must equal the per-packet path: same delivered bytes in the same
%% order, same stream offset, same PN space, same ACK accounting.
-module(quic_stream_train_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(SID, 4).
-define(WIN, ?DEFAULT_MAX_RECEIVE_WINDOW).
-define(FB, 16#40).

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

messages() ->
    {messages, Msgs} = process_info(self(), messages),
    [M || {quic, _, M} <- Msgs].

state(Coalescing) ->
    flush(),
    S0 = quic_connection:test_recv_stream_state(?SID, 1000, ?WIN, 2 * ?WIN),
    S1 = quic_connection:test_add_recv_stream(S0, 8, ?WIN),
    S2 = quic_connection:test_state_in_recv_pass(quic_connection:test_state_with_pn_app(S1, 9)),
    quic_connection:test_state_coalescing(S2, Coalescing).

%% Packets PN0.. with one stream frame each, Sid, from Off.
train(PN0, Sid, Off, Sizes) ->
    {Pkts, _} = lists:mapfoldl(
        fun(Sz, {PN, O}) ->
            {{PN, ?FB, [{stream, Sid, O, binary:copy(<<(PN rem 256)>>, Sz), false}]}, {
                PN + 1, O + Sz
            }}
        end,
        {PN0, Off},
        Sizes
    ),
    Pkts.

%% Per-packet reference: receive bookkeeping, then the stream frame
%% through the general path, then the counters the fold adds.
reference(Results, S0) ->
    S1 = lists:foldl(
        fun({PN, FB, [{stream, Sid, Off, Data, Fin}]}, S) ->
            SA = quic_connection:record_app_recv(FB, PN, S, 0),
            quic_connection:do_process_stream_data_buffered(Sid, Off, Data, Fin, SA)
        end,
        S0,
        Results
    ),
    S1.

summary(S) ->
    M = quic_connection:test_recv_summary(S, ?SID),
    %% recv_time differs by construction; ranges/largest/offset/count matter.
    M.

contiguous_train_matches_reference_test() ->
    S0 = state(true),
    Results = train(10, ?SID, 1000, [1200, 1200, 1200, 700]),
    Fold = quic_connection:fold_opened(Results, S0),
    FoldMsgs = messages(),
    Ref0 = reference(Results, state(true)),
    RefMsgs = messages(),
    %% The reference counts packets and ack-eliciting packets itself.
    RefSum = (summary(Ref0))#{
        packets_received := 4, ack_elicited_count := 4, has_non_probing_frame := true
    },
    ?assertEqual(RefSum, summary(Fold)),
    ?assertEqual(RefMsgs, FoldMsgs),
    ?assertEqual([], FoldMsgs),
    ?assertMatch(
        #{largest_recv := 13, ack_ranges := [{0, 13}], recv_offset := 5300, packets_received := 4},
        summary(Fold)
    ),
    {?SID, Rev, false} = maps:get(pend_deliver, summary(Fold)),
    ?assertEqual(
        [
            binary:copy(<<PN>>, Sz)
         || {PN, Sz} <- lists:zip([10, 11, 12, 13], [1200, 1200, 1200, 700])
        ],
        lists:reverse(Rev)
    ).

train_without_coalescing_delivers_per_chunk_test() ->
    S0 = state(false),
    Results = train(10, ?SID, 1000, [500, 500, 500]),
    Fold = quic_connection:fold_opened(Results, S0),
    ?assertEqual(
        [{stream_data, ?SID, binary:copy(<<PN>>, 500), false} || PN <- [10, 11, 12]],
        messages()
    ),
    ?assertMatch(#{recv_offset := 2500, pend_deliver := none}, summary(Fold)).

%% Shapes the train path must hand back: an offset gap, a second
%% stream, a FIN. Each ends in the same state as the reference. (A
%% packet-number gap takes the reordered path, whose immediate ACK
%% needs a live connection; it is covered by the e2e suites.)
deviating_shapes_match_reference_test_() ->
    Gap = train(10, ?SID, 1000, [500]) ++ train(11, ?SID, 1700, [500]),
    Mixed = train(10, ?SID, 1000, [500]) ++ train(11, 8, 0, [500]) ++ train(12, ?SID, 1500, [500]),
    Fin = [{10, ?FB, [{stream, ?SID, 1000, <<"tail">>, true}]}],
    [
        {Name, fun() -> assert_shape(Results) end}
     || {Name, Results} <- [
            {"offset gap", Gap}, {"two streams", Mixed}, {"fin", Fin}
        ]
    ].

assert_shape(Results) ->
    S0 = state(true),
    Fold = quic_connection:fold_opened(Results, S0),
    FoldMsgs = messages(),
    Ref = reference(Results, state(true)),
    RefMsgs = messages(),
    Sum = fun(S) ->
        maps:without([packets_received, ack_elicited_count, has_non_probing_frame], summary(S))
    end,
    ?assertEqual(Sum(Ref), Sum(Fold)),
    ?assertEqual(RefMsgs, FoldMsgs),
    ?assertEqual(length(Results), maps:get(packets_received, summary(Fold))).
