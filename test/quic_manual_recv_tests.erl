%%% -*- erlang -*-
%%%
%%% Reader-driven receive credit on a QUIC stream (used by quic_h3's
%%% `flow_control => manual').
%%%
%%% An `auto' stream grants credit as data is delivered. A `manual' one
%%% grants it only one window past the offset its reader has consumed,
%%% and its unconsumed bytes earn no connection credit either.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_manual_recv_tests).

-include_lib("eunit/include/eunit.hrl").

-define(S, quic_connection_test_support).
-define(SID, 0).
-define(W, 65536).
-define(MAX, (2 * ?W)).

%% Delivery alone moves a manual stream's limit nowhere.
manual_stream_does_not_grant_on_delivery_test() ->
    S = deliver(manual(new()), 0, 3 * ?W div 4),
    ?assertEqual(?W, maps:get(max, ?S:stream_recv(S, ?SID))).

%% The fence: the same delivery on an auto stream raises the limit.
auto_stream_grants_on_delivery_test() ->
    S = deliver(new(), 0, 3 * ?W div 4),
    ?assert(maps:get(max, ?S:stream_recv(S, ?SID)) > ?W).

%% Consuming moves the limit to one window past what was consumed.
consume_grants_one_window_past_consumed_test() ->
    S1 = deliver(manual(new()), 0, ?W),
    S2 = consumed(S1, ?W),
    ?assertEqual(2 * ?W, maps:get(max, ?S:stream_recv(S2, ?SID))).

%% Less than half a window of new credit waits for more.
small_consume_waits_for_half_a_window_test() ->
    S1 = deliver(manual(new()), 0, ?W),
    S2 = consumed(S1, ?W div 4),
    ?assertEqual(?W, maps:get(max, ?S:stream_recv(S2, ?SID))).

%% The reader cannot consume past what was delivered.
consume_is_capped_at_delivered_test() ->
    S1 = deliver(manual(new()), 0, ?W div 2),
    S2 = consumed(S1, 10 * ?W),
    ?assertEqual(?W div 2, maps:get(consumed, ?S:stream_recv(S2, ?SID))).

%% Unconsumed manual bytes earn no connection credit: the same delivery
%% raises MAX_DATA less than on an auto stream.
unconsumed_bytes_earn_no_connection_credit_test() ->
    Manual = deliver(manual(new()), 0, 3 * ?W div 4),
    Auto = deliver(new(), 0, 3 * ?W div 4),
    ?assert(?S:max_data_local(Manual) < ?S:max_data_local(Auto)).

%% Back to auto, a peer blocked on the manual window is released at once.
back_to_auto_grants_at_once_test() ->
    S1 = deliver(manual(new()), 0, ?W),
    S2 = quic_connection:set_recv_flow(?SID, auto, connected, S1),
    #{flow := Flow, max := Max} = ?S:stream_recv(S2, ?SID),
    ?assertEqual(auto, Flow),
    ?assertEqual(2 * ?W, Max).

%%====================================================================
%% Held peer streams (quic_h3 calls hold_peer_streams/1)
%%====================================================================

%% Server-initiated, as seen by the client the test state plays.
-define(PEER_BIDI, 1).
-define(PEER_UNI, 3).

%% The packet that opens a held stream earns it no MAX_STREAM_DATA.
held_stream_earns_nothing_on_its_first_packet_test() ->
    S = deliver_on(held(), ?PEER_BIDI, 0, 1000),
    ?assertMatch(#{flow := manual, max := ?W, consumed := 0}, ?S:stream_recv(S, ?PEER_BIDI)).

%% The fence: without the hold the same packet raises the limit.
peer_stream_without_hold_is_auto_test() ->
    S = deliver_on(peer(), ?PEER_BIDI, 0, 1000),
    #{flow := Flow, max := Max} = ?S:stream_recv(S, ?PEER_BIDI),
    ?assertEqual(auto, Flow),
    ?assert(Max > ?W).

%% However much it is sent, a held stream never goes past its window.
held_stream_keeps_its_initial_window_test() ->
    S = deliver_on(held(), ?PEER_BIDI, 0, ?W),
    ?assertEqual(?W, maps:get(max, ?S:stream_recv(S, ?PEER_BIDI))).

%% Until its reader is known a held stream's bytes earn connection credit
%% as delivered: bodies nobody reads cannot stall the other streams.
held_bytes_earn_connection_credit_test() ->
    Held = deliver_on(held(), ?PEER_BIDI, 0, 3 * ?W div 4),
    Auto = deliver_on(peer(), ?PEER_BIDI, 0, 3 * ?W div 4),
    ?assertEqual(?S:max_data_local(Auto), ?S:max_data_local(Held)),
    ?assertNot(?S:manual_tracked(Held, ?PEER_BIDI)).

%% Once its reader goes manual, its unconsumed bytes stop earning it.
held_stream_switched_to_manual_counts_as_manual_test() ->
    S1 = deliver_on(held(), ?PEER_BIDI, 0, 1000),
    S2 = quic_connection:set_recv_flow(?PEER_BIDI, {manual, 0}, connected, S1),
    ?assert(?S:manual_tracked(S2, ?PEER_BIDI)).

%% Framing the reader reports consumed moves the limit no further than
%% one window past it, as on any manual stream.
held_stream_reports_like_a_manual_one_test() ->
    S1 = deliver_on(held(), ?PEER_BIDI, 0, ?W),
    S2 = quic_connection:recv_consumed(?PEER_BIDI, 100, connected, S1),
    ?assertEqual(?W, maps:get(max, ?S:stream_recv(S2, ?PEER_BIDI))),
    S3 = quic_connection:set_recv_flow(?PEER_BIDI, {manual, ?W}, connected, S2),
    ?assertEqual(2 * ?W, maps:get(max, ?S:stream_recv(S3, ?PEER_BIDI))).

%% A reader in auto releases a held stream at once, one window past what
%% was delivered.
held_stream_switched_to_auto_is_released_test() ->
    S1 = deliver_on(held(), ?PEER_BIDI, 0, 1000),
    S2 = quic_connection:set_recv_flow(?PEER_BIDI, auto, connected, S1),
    ?assertMatch(#{flow := auto, max := 1000 + ?W}, ?S:stream_recv(S2, ?PEER_BIDI)),
    ?assertNot(?S:manual_tracked(S2, ?PEER_BIDI)).

%% A unidirectional stream is held as well, until quic_h3 has read its type.
uni_stream_is_held_test() ->
    S = deliver_on(held(), ?PEER_UNI, 0, ?W),
    ?assertMatch(#{flow := manual, max := ?W, consumed := 0}, ?S:stream_recv(S, ?PEER_UNI)).

%% Streams this side opened are not held.
local_stream_is_not_held_test() ->
    S = deliver(held(), 0, 1000),
    #{flow := Flow, max := Max} = ?S:stream_recv(S, ?SID),
    ?assertEqual(auto, Flow),
    ?assert(Max > ?W).

%% A held stream opened by a frame other than STREAM is held all the same.
stream_opened_by_stop_sending_is_held_test() ->
    opened_held({stop_sending, ?PEER_BIDI, 0}).

stream_opened_by_stream_data_blocked_is_held_test() ->
    opened_held({stream_data_blocked, ?PEER_BIDI, ?W}).

stream_opened_by_reset_stream_is_held_test() ->
    opened_held({reset_stream, ?PEER_BIDI, 0, 10}).

stream_opened_by_reset_stream_at_is_held_test() ->
    opened_held({reset_stream_at, ?PEER_BIDI, 0, 10, 5}).

opened_held(Frame) ->
    S = quic_connection:process_frame(app, Frame, held()),
    flush(),
    ?assertMatch(#{flow := manual, max := ?W}, ?S:stream_recv(S, ?PEER_BIDI)).

%% quic_h3:accept/2 called from an alpn_handler runs in the connection
%% process: its hold applies before the 0-RTT packets of the same datagram
%% open streams, not after them.
hold_asked_by_the_alpn_handler_applies_at_once_test() ->
    Owner = spawn(fun() ->
        receive
            stop -> ok
        end
    end),
    Accept = fun(Conn, <<"h3">>) ->
        ok = quic_connection:hold_peer_streams(Conn),
        {ok, Owner}
    end,
    try
        {ok, S0} = quic_connection:run_alpn_handler(<<"h3">>, ?S:with_alpn_handler(peer(), Accept)),
        S = deliver_on(S0, ?PEER_BIDI, 0, 1000),
        ?assertMatch(#{flow := manual, max := ?W}, ?S:stream_recv(S, ?PEER_BIDI))
    after
        Owner ! stop,
        receive
            {'$gen_cast', hold_peer_streams} -> ok
        after 0 -> ok
        end
    end.

%%====================================================================
%% Helpers
%%====================================================================

peer() ->
    ?S:state_for_peer_streams(?W, ?MAX).

held() ->
    {keep_state, S} = quic_connection:handle_common_event(
        cast, hold_peer_streams, connected, peer()
    ),
    S.

deliver_on(S, StreamId, _Offset, 0) ->
    flush(),
    _ = StreamId,
    S;
deliver_on(S, StreamId, Offset, Size) ->
    N = min(1000, Size),
    S1 = quic_connection:process_stream_data(
        StreamId, Offset, binary:copy(<<1>>, N), false, S
    ),
    deliver_on(S1, StreamId, Offset + N, Size - N).

new() ->
    ?S:state_for_manual_recv(?W, ?MAX).

manual(S) ->
    quic_connection:set_recv_flow(?SID, {manual, 0}, connected, S).

consumed(S, Offset) ->
    quic_connection:recv_consumed(?SID, Offset, connected, S).

%% Size bytes from the peer at Offset, in 1000-byte frames.
deliver(S, _Offset, 0) ->
    flush(),
    S;
deliver(S, Offset, Size) ->
    N = min(1000, Size),
    S1 = quic_connection:process_stream_data(?SID, Offset, binary:copy(<<1>>, N), false, S),
    deliver(S1, Offset + N, Size - N).

flush() ->
    receive
        {quic, _, _} -> flush()
    after 0 -> ok
    end.
