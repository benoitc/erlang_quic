%%% -*- erlang -*-
%%%
%%% The connection's own ACK plumbing.
%%%
%%% quic_connection keeps its ACK ranges in #pn_space.ack_ranges and does
%%% its own frame encoding. Range accumulation is shared with quic_ack;
%%% the frame building and the bookkeeping below are the connection's
%%% own. These cases cover the live path, which had no direct tests for
%%% range merging, frame building, the frame-format boundary, or the ACK
%%% bookkeeping helpers.
%%%
%%% Internal ranges are descending and disjoint: [{Start, End}, ...] with
%%% the newest packet numbers first. The encoder form is the wire shape,
%%% [{LargestAcked, FirstRange} | [{Gap, Range}, ...]].
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_connection_ack_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% quic_ack:merge_ranges/1
%%
%% Reached from quic_ack:add_to_ranges/2 when a packet extends a range
%% downward far enough to touch the next one. On the connection's
%% receive path this is what keeps ACK ranges disjoint, and it was never
%% asserted directly until now.
%%====================================================================

merge_adjacent_ranges_test() ->
    %% {4,6} extended down to 4 now touches {0,3}: 3 + 1 >= 4.
    ?assertEqual([{0, 6}], quic_ack:merge_ranges([{4, 6}, {0, 3}])).

merge_overlapping_ranges_test() ->
    ?assertEqual([{0, 6}], quic_ack:merge_ranges([{3, 6}, {0, 4}])).

leaves_separated_ranges_alone_test() ->
    %% A gap of one packet (4) keeps them apart: 3 + 1 < 5.
    ?assertEqual([{5, 6}, {0, 3}], quic_ack:merge_ranges([{5, 6}, {0, 3}])).

merge_keeps_the_larger_end_test() ->
    %% The head's end wins when it reaches further than the tail's.
    ?assertEqual([{0, 9}], quic_ack:merge_ranges([{4, 9}, {0, 5}])).

merge_cascades_test() ->
    %% One merge can expose another.
    ?assertEqual([{0, 8}], quic_ack:merge_ranges([{7, 8}, {4, 6}, {0, 3}])).

merge_single_or_empty_is_identity_test() ->
    ?assertEqual([], quic_ack:merge_ranges([])),
    ?assertEqual([{1, 2}], quic_ack:merge_ranges([{1, 2}])).

%%====================================================================
%% build_ack_frame_tuple/1 and build_ack_frame/1
%%====================================================================

frame_tuple_carries_encoder_ranges_test() ->
    Ranges = [{10, 10}, {5, 6}, {0, 1}],
    ?assertEqual(
        {ack, quic_ack:convert_ack_ranges_for_encode(Ranges), 0, undefined},
        quic_ack:build_ack_frame_tuple(Ranges)
    ).

%% ACK delay is zero here: send_app_ack/1 builds the frame at send time,
%% so there is no accumulated delay to report.
frame_tuple_has_no_ack_delay_test() ->
    {ack, _Ranges, AckDelay, ECN} = quic_ack:build_ack_frame_tuple([{0, 3}]),
    ?assertEqual(0, AckDelay),
    ?assertEqual(undefined, ECN).

%% What we encode must decode back to what we built.
frame_round_trips_test() ->
    Ranges = [{10, 10}, {5, 6}, {0, 1}],
    Tuple = quic_ack:build_ack_frame_tuple(Ranges),
    Encoded = quic_ack:build_ack_frame(Ranges),
    ?assert(is_binary(Encoded)),
    ?assertEqual({Tuple, <<>>}, quic_frame:decode(Encoded)).

single_range_round_trips_test() ->
    Tuple = quic_ack:build_ack_frame_tuple([{0, 5}]),
    ?assertEqual({Tuple, <<>>}, quic_frame:decode(quic_ack:build_ack_frame([{0, 5}]))).

%% A range wider than MAX_ACK_RANGE is clamped rather than sent whole,
%% because a receiver may reject anything larger.
oversized_range_is_clamped_test() ->
    {ack, [{Largest, FirstRange} | _], _, _} =
        quic_ack:build_ack_frame_tuple([{0, 70000}]),
    ?assertEqual(70000, Largest),
    ?assertEqual(65536, FirstRange).

%%====================================================================
%% ranges_to_ack_format/1
%%
%% The boundary between the frame codec's shape and what quic_loss
%% expects: it drops the largest acked, which the caller already has.
%%====================================================================

splits_first_range_from_the_rest_test() ->
    ?assertEqual(
        {1, [{2, 1}, {2, 1}]},
        quic_ack:ranges_to_ack_format([{10, 1}, {2, 1}, {2, 1}])
    ).

single_range_leaves_an_empty_tail_test() ->
    ?assertEqual({5, []}, quic_ack:ranges_to_ack_format([{5, 5}])).

%% Decoding our own frame and converting it is the path an incoming ACK
%% actually takes, so pin the two together.
decode_then_convert_test() ->
    Encoded = quic_ack:build_ack_frame([{10, 10}, {5, 6}, {0, 1}]),
    {{ack, Ranges, _AckDelay, _ECN}, <<>>} = quic_frame:decode(Encoded),
    {FirstRange, Rest} = quic_ack:ranges_to_ack_format(Ranges),
    [{_Largest, ExpectedFirst} | ExpectedRest] = Ranges,
    ?assertEqual(ExpectedFirst, FirstRange),
    ?assertEqual(ExpectedRest, Rest).

%%====================================================================
%% Ack-eliciting classification
%%====================================================================

ack_eliciting_frames_test() ->
    ?assert(quic_ack:is_ack_eliciting_frame(ping)),
    ?assert(quic_ack:is_ack_eliciting_frame({stream, 0, 0, <<"x">>, false})),
    ?assert(quic_ack:is_ack_eliciting_frame({crypto, 0, <<"x">>})).

non_ack_eliciting_frames_test() ->
    ?assertNot(quic_ack:is_ack_eliciting_frame(padding)),
    ?assertNot(quic_ack:is_ack_eliciting_frame({ack, [], 0, undefined})),
    ?assertNot(
        quic_ack:is_ack_eliciting_frame({connection_close, transport, 0, 0, <<>>})
    ).

contains_ack_eliciting_test() ->
    ?assert(quic_ack:contains_ack_eliciting_frames([ping])),
    ?assert(quic_ack:contains_ack_eliciting_frames([padding, ping])),
    ?assertNot(quic_ack:contains_ack_eliciting_frames([])),
    ?assertNot(quic_ack:contains_ack_eliciting_frames([padding, padding])).

%% The single stream frame produced by every chunked send takes a fast
%% path rather than the list walk; it must agree with the general case.
contains_ack_eliciting_fast_path_agrees_test() ->
    Frames = [{stream, 0, 0, <<"x">>, false}],
    ?assertEqual(
        lists:any(fun quic_ack:is_ack_eliciting_frame/1, Frames),
        quic_ack:contains_ack_eliciting_frames(Frames)
    ).

%%====================================================================
%% ACK bookkeeping on #state{}
%%====================================================================

bump_ack_sent_counts_up_test() ->
    S0 = quic_connection_test_support:decimate_initial_state(),
    #{ack_sent := Before} = quic_connection_test_support:ack_counters(S0),
    S1 = quic_connection:bump_ack_sent(S0),
    S2 = quic_connection:bump_ack_sent(S1),
    #{ack_sent := After} = quic_connection_test_support:ack_counters(S2),
    ?assertEqual(Before + 2, After).

arm_ack_timer_sets_a_timer_test() ->
    S0 = quic_connection_test_support:decimate_initial_state(),
    #{ack_timer := undefined} = quic_connection_test_support:ack_counters(S0),
    S1 = quic_connection:arm_ack_timer(S0),
    #{ack_timer := Ref} = quic_connection_test_support:ack_counters(S1),
    ?assert(is_reference(Ref)),
    %% max_ack_delay is 25ms in this state, so the message lands quickly.
    receive
        {send_delayed_ack, app, Ref} -> ok
    after 2000 ->
        ct_fail_no_timer()
    end.

%% The timer runs on the delay we advertise, not the one the peer
%% advertises. max_ack_delay is an endpoint's own maximum (RFC 9000
%% Section 18.2), so a peer asking for 2000 must not stretch our timer:
%% it would hold ACKs for two seconds while that peer sizes its PTO on
%% the 25 ms it has to assume for us.
arm_ack_timer_ignores_the_peer_max_ack_delay_test() ->
    S0 = quic_connection_test_support:state_set(
        quic_connection_test_support:decimate_initial_state(),
        transport_params,
        #{max_ack_delay => 2000}
    ),
    S1 = quic_connection:arm_ack_timer(S0),
    #{ack_timer := Ref} = quic_connection_test_support:ack_counters(S1),
    receive
        {send_delayed_ack, app, Ref} -> ok
    after 500 ->
        ct_fail_no_timer()
    end.

%% Arming twice must not start a second timer: the first reference stays,
%% otherwise a stale fire would be indistinguishable from a live one.
arm_ack_timer_is_idempotent_test() ->
    S0 = quic_connection:arm_ack_timer(quic_connection_test_support:decimate_initial_state()),
    #{ack_timer := First} = quic_connection_test_support:ack_counters(S0),
    S1 = quic_connection:arm_ack_timer(S0),
    #{ack_timer := Second} = quic_connection_test_support:ack_counters(S1),
    ?assertEqual(First, Second),
    flush({send_delayed_ack, app, First}).

clear_decimation_without_a_timer_test() ->
    S0 = quic_connection_test_support:decimate_initial_state(),
    {S1, _} = quic_connection_test_support:decimate_step(S0),
    #{ack_elicited_count := Counted} = quic_connection_test_support:ack_counters(S1),
    ?assert(Counted > 0),
    S2 = quic_connection:clear_ack_decimation_state(S1),
    #{ack_elicited_count := Cleared, ack_timer := Timer} =
        quic_connection_test_support:ack_counters(S2),
    ?assertEqual(0, Cleared),
    ?assertEqual(undefined, Timer).

%% With a timer armed, clearing drops the reference as well as zeroing
%% the count. The stored reference is not the send_after reference, so a
%% pending message still arrives; what makes it harmless is that the
%% state no longer matches it, and the connected/3 clause for a
%% non-matching reference discards it.
clear_decimation_drops_the_timer_reference_test() ->
    S0 = quic_connection:arm_ack_timer(quic_connection_test_support:decimate_initial_state()),
    #{ack_timer := Ref} = quic_connection_test_support:ack_counters(S0),
    ?assert(is_reference(Ref)),
    S1 = quic_connection:clear_ack_decimation_state(S0),
    #{ack_elicited_count := Count, ack_timer := Timer} =
        quic_connection_test_support:ack_counters(S1),
    ?assertEqual(0, Count),
    ?assertEqual(undefined, Timer),
    ?assertNotEqual(Ref, Timer),
    flush({send_delayed_ack, app, Ref}).

%%====================================================================
%% Helpers
%%====================================================================

ct_fail_no_timer() ->
    ?assert(false).

%% Drop a pending timer message so it cannot reach a later test: eunit
%% runs every module in one process.
flush(Msg) ->
    receive
        Msg -> ok
    after 2000 ->
        ok
    end.
