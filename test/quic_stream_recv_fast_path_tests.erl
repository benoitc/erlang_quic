%% The receive side has lean paths for the dominant bulk shape; each
%% must be observably identical to the general path it shortcuts.
-module(quic_stream_recv_fast_path_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(SID, 4).
-define(WIN, ?DEFAULT_MAX_RECEIVE_WINDOW).

%%--------------------------------------------------------------------
%% Stream data: lean clause vs the general path
%%--------------------------------------------------------------------

flush() ->
    receive
        _ -> flush()
    after 0 -> ok
    end.

messages() ->
    {messages, Msgs} = process_info(self(), messages),
    Msgs.

%% Run both paths on the same input and return {State, Messages} each.
both(S, Offset, Data, Fin) ->
    flush(),
    Lean = quic_connection:do_process_stream_data_buffered(?SID, Offset, Data, Fin, S),
    LeanMsgs = messages(),
    flush(),
    Slow = quic_connection:do_process_stream_data_slow(?SID, Offset, Data, Fin, S),
    SlowMsgs = messages(),
    flush(),
    {{Lean, LeanMsgs}, {Slow, SlowMsgs}}.

in_order_bulk_frame_test() ->
    S = quic_connection:test_recv_stream_state(?SID, 5000, ?WIN, 2 * ?WIN),
    Data = binary:copy(<<"d">>, 1200),
    {L, R} = both(S, 5000, Data, false),
    ?assertEqual(R, L),
    {_, Msgs} = L,
    ?assertEqual([{quic, self(), {stream_data, ?SID, Data, false}}], Msgs).

%% A run of in-order frames threads identically through both paths.
in_order_run_test() ->
    S0 = quic_connection:test_recv_stream_state(?SID, 0, ?WIN, 2 * ?WIN),
    Data = binary:copy(<<"r">>, 1000),
    {Lean, Slow} = lists:foldl(
        fun(I, {L, R}) ->
            flush(),
            L1 = quic_connection:do_process_stream_data_buffered(?SID, I * 1000, Data, false, L),
            R1 = quic_connection:do_process_stream_data_slow(?SID, I * 1000, Data, false, R),
            {L1, R1}
        end,
        {S0, S0},
        lists:seq(0, 50)
    ),
    flush(),
    ?assertEqual(Slow, Lean).

%% Shapes the lean clause must hand to the general path: a gap, a
%% duplicate, a FIN, an empty frame, an unknown stream. All wide-window,
%% so the general path emits no flow-control frame either way.
out_of_order_test() ->
    S = quic_connection:test_recv_stream_state(?SID, 5000, ?WIN, 2 * ?WIN),
    {L, R} = both(S, 6200, binary:copy(<<"o">>, 1200), false),
    ?assertEqual(R, L).

duplicate_test() ->
    S = quic_connection:test_recv_stream_state(?SID, 5000, ?WIN, 2 * ?WIN),
    {L, R} = both(S, 4000, binary:copy(<<"u">>, 1000), false),
    ?assertEqual(R, L).

fin_test() ->
    S = quic_connection:test_recv_stream_state(?SID, 5000, ?WIN, 2 * ?WIN),
    {L, R} = both(S, 5000, binary:copy(<<"f">>, 100), true),
    ?assertEqual(R, L).

empty_frame_test() ->
    S = quic_connection:test_recv_stream_state(?SID, 5000, ?WIN, 2 * ?WIN),
    {L, R} = both(S, 5000, <<>>, false),
    ?assertEqual(R, L).

%%--------------------------------------------------------------------
%% PN space: sequential packets skip the ACK-range cap scan
%%--------------------------------------------------------------------

%% The pre-optimisation update: always run the cap.
reference_pn_space_recv(PN, PNSpace, Now) ->
    #pn_space{largest_recv = LargestRecv, ack_ranges = Ranges} = PNSpace,
    NewLargest =
        case LargestRecv of
            undefined -> PN;
            L when PN > L -> PN;
            L -> L
        end,
    PNSpace#pn_space{
        largest_recv = NewLargest,
        recv_time = Now,
        ack_ranges = quic_connection:cap_ack_ranges(quic_connection:add_to_ack_ranges(PN, Ranges))
    }.

empty_pn_space() ->
    #pn_space{
        next_pn = 0,
        largest_acked = undefined,
        largest_recv = undefined,
        recv_time = undefined,
        ack_ranges = [],
        ack_eliciting_in_flight = 0,
        loss_time = undefined,
        sent_packets = #{}
    }.

pn_space_matches_reference_test_() ->
    [
        {"seed " ++ integer_to_list(Seed), fun() -> pn_space_run(Seed) end}
     || Seed <- lists:seq(1, 10)
    ].

pn_space_run(Seed) ->
    rand:seed(exsplus, {Seed, Seed * 11 + 3, Seed * 17 + 5}),
    lists:foldl(
        fun(I, {New, Ref}) ->
            %% Enough gaps to overflow ?MAX_ACK_RANGES, so the cap
            %% actually bites on the reordered packets.
            PN =
                case rand:uniform(3) of
                    1 -> I * 2;
                    _ -> I * 2 + 1
                end,
            New1 = quic_connection:update_pn_space_recv(PN, New, I),
            Ref1 = reference_pn_space_recv(PN, Ref, I),
            ?assertEqual(Ref1, New1),
            {New1, Ref1}
        end,
        {empty_pn_space(), empty_pn_space()},
        lists:seq(0, 400)
    ).

%%--------------------------------------------------------------------
%% Delayed ACK: a leading stream frame never qualifies
%%--------------------------------------------------------------------

stream_frame_first_is_never_delayed_test() ->
    Stream = {stream, ?SID, 0, <<"x">>, false},
    ?assertNot(quic_connection:should_delay_ack([Stream])),
    ?assertNot(quic_connection:should_delay_ack([Stream, {datagram, <<"d">>}])).

datagram_only_is_delayed_test() ->
    ?assert(quic_connection:should_delay_ack([{datagram, <<"d">>}])),
    ?assert(quic_connection:should_delay_ack([padding, {datagram, <<"d">>}])),
    %% A stream frame after a datagram: the general clause finds it.
    ?assertNot(
        quic_connection:should_delay_ack([{datagram, <<"d">>}, {stream, ?SID, 0, <<"x">>, false}])
    ).
