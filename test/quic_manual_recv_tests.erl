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
%% Helpers
%%====================================================================

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
