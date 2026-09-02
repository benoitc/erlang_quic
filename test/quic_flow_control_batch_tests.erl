%%% -*- erlang -*-
%%%
%%% Receive-side bookkeeping on the flow-control path: the retained ACK
%%% range cap, and that a blocked write leaves the queue in send order.

-module(quic_flow_control_batch_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MAX_ACK_RANGES, 64).

%%====================================================================
%% Retained ACK ranges (#211)
%%====================================================================

%% Every other packet lost fragments the ACK block into one range per
%% packet. Unbounded, each outgoing ACK then encodes hundreds of ranges
%% and the peer decodes them, on every packet.
alternating_loss_is_capped_test() ->
    Ranges = lists:foldl(
        fun(PN, Acc) -> cap(quic_connection:add_to_ack_ranges(PN, Acc)) end,
        [],
        [PN || PN <- lists:seq(1, 400), PN rem 2 =:= 0]
    ),
    ?assertEqual(?MAX_ACK_RANGES, length(Ranges)).

%% The cap keeps the newest ranges: the oldest are what the peer has
%% already retransmitted or given up on.
the_cap_keeps_the_highest_packet_numbers_test() ->
    Ranges = lists:foldl(
        fun(PN, Acc) -> cap(quic_connection:add_to_ack_ranges(PN, Acc)) end,
        [],
        [PN || PN <- lists:seq(1, 400), PN rem 2 =:= 0]
    ),
    [{HighStart, _} | _] = Ranges,
    ?assertEqual(400, HighStart),
    ?assert(lists:all(fun({S, E}) -> S =< E end, Ranges)).

%% Contiguous delivery is one range however long it runs, so the cap
%% never truncates an unfragmented ACK.
contiguous_delivery_stays_one_range_test() ->
    Ranges = lists:foldl(
        fun(PN, Acc) -> cap(quic_connection:add_to_ack_ranges(PN, Acc)) end,
        [],
        lists:seq(1, 500)
    ),
    ?assertEqual([{1, 500}], Ranges).

%% Ranges stay ordered and disjoint when packets arrive out of order.
out_of_order_arrival_keeps_ranges_disjoint_test() ->
    PNs = [10, 1, 7, 2, 9, 3, 8, 5],
    Ranges = lists:foldl(
        fun(PN, Acc) -> cap(quic_connection:add_to_ack_ranges(PN, Acc)) end,
        [],
        PNs
    ),
    Starts = [S || {S, _} <- Ranges],
    ?assertEqual(lists:reverse(lists:sort(Starts)), Starts),
    ?assertEqual([], [P || P <- PNs, not covered(P, Ranges)]).

cap(Ranges) ->
    quic_connection:cap_ack_ranges(Ranges).

covered(PN, Ranges) ->
    lists:any(fun({S, E}) -> PN >= S andalso PN =< E end, Ranges).

%%====================================================================
%% Blocked writes and window growth (#209, #233, #236)
%%====================================================================

large_write_test_() ->
    {timeout, 60, fun a_write_past_the_window_arrives_whole_and_in_order/0}.

%% A write several times the initial connection window blocks, queues,
%% and drains as the peer's MAX_DATA arrives. It must come back byte for
%% byte: a requeue that reorders, or a partial prefix accounted wrongly,
%% shows up here as corruption rather than a stall.
a_write_past_the_window_arrives_whole_and_in_order() ->
    {ok, Srv} = quic_test_echo_server:start(),
    try
        #{port := Port} = Srv,
        Opts = quic_test_echo_server:client_opts(),
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        try
            receive
                {quic, Conn, {connected, _}} -> ok
            after 5000 -> error(connect_timeout)
            end,
            {ok, StreamId} = quic:open_stream(Conn),
            Payload = payload(4 * 1024 * 1024),
            ok = quic:send_data(Conn, StreamId, Payload, true),
            ?assertEqual(Payload, collect(Conn, StreamId, <<>>))
        after
            quic:safe_close(Conn, normal)
        end
    after
        quic_test_echo_server:stop(Srv)
    end.

%% Position-dependent bytes, so a reordered chunk cannot compare equal.
payload(Size) ->
    iolist_to_binary([<<(N rem 251)>> || N <- lists:seq(1, Size)]).

collect(Conn, StreamId, Acc) ->
    receive
        {quic, Conn, {stream_data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic, Conn, {stream_data, StreamId, Data, false}} ->
            collect(Conn, StreamId, <<Acc/binary, Data/binary>>)
    after 30000 ->
        Acc
    end.
