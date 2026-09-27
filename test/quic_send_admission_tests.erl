%%% -*- erlang -*-
%%%
%%% The send-queue ceiling and what `{error, send_queue_full}' promises.
%%%
%%% A write refused with send_queue_full must leave nothing behind: no
%%% packet sealed, no packet number used, nothing queued, so the caller
%%% can send the same piece again. A write that was admitted must never
%%% lose part of itself to the ceiling afterwards, and neither may the
%%% queue drain.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_send_admission_tests).

-include_lib("eunit/include/eunit.hrl").

%% logger handler callback for the log test below.
-export([log/2]).

-define(SID, 0).
-define(MAX, 16777216).
%% Many packets, more than the initial congestion window lets out.
-define(PIECE, 100000).
-define(WIN, 1000000).

-define(S, quic_connection_test_support).

%%====================================================================
%% Refusal leaves nothing behind
%%====================================================================

%% Some of the piece would fit the congestion window, the rest would have
%% to be queued past the ceiling: refused before anything is sealed.
refused_write_changes_nothing_test() ->
    refused_changes_nothing(?WIN, ?WIN).

%% Stream window closed: no STREAM_DATA_BLOCKED goes out for a refused write.
refused_stream_blocked_write_sends_nothing_test() ->
    refused_changes_nothing(0, ?WIN).

%% Connection window closed: no DATA_BLOCKED goes out for a refused write.
refused_connection_blocked_write_sends_nothing_test() ->
    refused_changes_nothing(?WIN, 0).

%% Part of the piece fits the stream window: the head is not sent either.
refused_partial_window_write_sends_nothing_test() ->
    refused_changes_nothing(?PIECE div 2, ?WIN).

%% The fence for each case above: with room in the queue the same write
%% goes through and something reaches the wire.
admitted_write_is_sent_test_() ->
    [
        ?_test(admitted_sends(Stream, Conn))
     || {Stream, Conn} <- [{?WIN, ?WIN}, {0, ?WIN}, {?WIN, 0}, {?PIECE div 2, ?WIN}]
    ].

%%====================================================================
%% Admitted writes are never cut short
%%====================================================================

%% An async write has nobody to refuse to: it is queued past the ceiling.
async_write_is_admitted_past_the_ceiling_test() ->
    S0 = ?S:state_for_admission(?SID, ?MAX - ?PIECE div 2, ?WIN, ?WIN),
    Sent0 = ?S:datagrams_out(S0),
    {keep_state, S1, []} = quic_connection:coalesced_sends(
        [{async, ?SID, piece(), false}], S0
    ),
    #{send_offset := Offset, send_queue_bytes := QueueBytes} = ?S:send_snapshot(S1, ?SID),
    ?assertEqual(?PIECE, Offset),
    ?assert(QueueBytes > ?MAX),
    ?assert(?S:datagrams_out(S1) > Sent0).

%% A remainder popped off a queue that is over the ceiling goes back at
%% the head, whole, rather than being dropped.
drain_keeps_the_remainder_test() ->
    S0 = ?S:queue_stream(?S:state_for_admission(?SID, 0, ?WIN, ?WIN), ?SID, 0, piece()),
    %% Other streams' data, holding the queue over the ceiling.
    S1 = ?S:state_set(S0, send_queue_bytes, ?MAX + ?PIECE),
    S2 = quic_connection:process_send_queue(S1),
    {value, {stream_data, ?SID, Offset, Data, false, Size}} = ?S:queue_head(S2),
    ?assert(Offset > 0),
    ?assertEqual(?PIECE, Offset + Size),
    ?assertEqual(Size, byte_size(Data)),
    ?assertEqual(binary:part(piece(), Offset, Size), Data).

%%====================================================================
%% Refusals are backpressure, not faults
%%====================================================================

%% A caller retries the same piece until the queue drains: each refusal
%% is logged at debug and counted, never as a warning.
repeated_refusals_do_not_warn_test() ->
    Handler = send_queue_full_capture,
    #{level := Level} = logger:get_primary_config(),
    ok = logger:set_primary_config(level, debug),
    ok = logger:add_handler(Handler, ?MODULE, #{config => #{pid => self()}}),
    try
        S0 = ?S:state_for_admission(?SID, ?MAX - ?PIECE div 2, ?WIN, ?WIN),
        S5 = lists:foldl(fun(_, S) -> refuse(S) end, S0, lists:seq(1, 5)),
        ?assertEqual(5, ?S:send_queue_full_refusals(S5)),
        Levels = logged_levels(),
        ?assertEqual(5, length([L || L <- Levels, L =:= debug])),
        ?assertEqual([], [L || L <- Levels, L =/= debug])
    after
        _ = logger:remove_handler(Handler),
        logger:set_primary_config(level, Level)
    end.

log(#{level := Level, msg := {report, #{what := send_queue_full}}}, #{config := #{pid := Pid}}) ->
    Pid ! {send_queue_full_logged, Level};
log(_Event, _Config) ->
    ok.

refuse(S) ->
    From = {self(), make_ref()},
    {keep_state, S1, [{reply, From, {error, send_queue_full}}]} =
        quic_connection:coalesced_sends([{From, ?SID, piece(), false}], S),
    S1.

logged_levels() ->
    receive
        {send_queue_full_logged, Level} -> [Level | logged_levels()]
    after 100 -> []
    end.

%%====================================================================
%% send_ready
%%====================================================================

%% Asked for, it goes out once the queue is below half the ceiling.
send_ready_waits_for_half_the_ceiling_test() ->
    S0 = ?S:state_wanting_send_ready(?MAX div 2, true),
    S1 = quic_connection:flush_dirty_timers(S0),
    ?assertEqual([], send_ready_msgs()),
    S2 = quic_connection:flush_dirty_timers(
        quic_connection_test_support:state_set(S1, send_queue_bytes, ?MAX div 2 - 1)
    ),
    ?assertEqual([send_ready], send_ready_msgs()),
    ?assertNot(?S:send_ready_wanted(S2)),
    %% Once only: a later drain says nothing.
    _ = quic_connection:flush_dirty_timers(S2),
    ?assertEqual([], send_ready_msgs()).

%% Never asked for, it never goes out, however empty the queue.
send_ready_is_opt_in_test() ->
    _ = quic_connection:flush_dirty_timers(?S:state_wanting_send_ready(0, false)),
    ?assertEqual([], send_ready_msgs()).

send_ready_msgs() ->
    receive
        {quic, _, send_ready} -> [send_ready | send_ready_msgs()]
    after 50 -> []
    end.

%%====================================================================
%% Helpers
%%====================================================================

refused_changes_nothing(StreamWindow, ConnWindow) ->
    S0 = ?S:state_for_admission(?SID, ?MAX - ?PIECE div 2, StreamWindow, ConnWindow),
    Sent0 = ?S:datagrams_out(S0),
    From = {self(), make_ref()},
    {keep_state, S1, [{reply, From, Reply}]} = quic_connection:coalesced_sends(
        [{From, ?SID, piece(), false}], S0
    ),
    ?assertEqual({error, send_queue_full}, Reply),
    ?assertEqual(?S:send_snapshot(S0, ?SID), ?S:send_snapshot(S1, ?SID)),
    ?assertEqual(Sent0, ?S:datagrams_out(S1)).

admitted_sends(StreamWindow, ConnWindow) ->
    S0 = ?S:state_for_admission(?SID, 0, StreamWindow, ConnWindow),
    Sent0 = ?S:datagrams_out(S0),
    From = {self(), make_ref()},
    {keep_state, S1, [{reply, From, ok}]} = quic_connection:coalesced_sends(
        [{From, ?SID, piece(), false}], S0
    ),
    ?assertEqual(?PIECE, maps:get(send_offset, ?S:send_snapshot(S1, ?SID))),
    ?assert(?S:datagrams_out(S1) > Sent0).

piece() ->
    list_to_binary([I rem 256 || I <- lists:seq(1, ?PIECE)]).
