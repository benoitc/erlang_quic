%%% -*- erlang -*-
%%%
%%% The #ack_state{} half encodes its ranges with the same gap arithmetic
%%% as the connection's path. Checked by round trip: decoding what
%%% generate_ack/2 produces must give back exactly the ranges it held.
%%%
%%% The oracle is quic_ack:ack_frame_to_ranges/3, the inverse quic_loss
%%% uses on every received ACK, so nothing here re-implements the encoder.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_ack_encoder_tests).

-include_lib("eunit/include/eunit.hrl").

%% Arrival orders that build several disjoint ranges.
fixed_orders_round_trip_test() ->
    Orders = [
        [0],
        [0, 1, 2, 3],
        [3, 2, 1, 0],
        [0, 2, 4, 6, 8],
        [10, 0, 5, 2, 8, 3, 7, 4, 6, 1],
        [100, 1, 50, 2, 49, 51],
        [5, 5, 5, 1, 1, 9]
    ],
    [?assertEqual(ranges_of(PNs), decoded(PNs)) || PNs <- Orders].

%% Random subsets of 0..300 in random order, seeded so a failure repeats.
random_orders_round_trip_test() ->
    rand:seed(exsss, {17, 29, 31}),
    lists:foreach(
        fun(_) ->
            PNs = [rand:uniform(301) - 1 || _ <- lists:seq(1, rand:uniform(60))],
            ?assertEqual(ranges_of(PNs), decoded(PNs))
        end,
        lists:seq(1, 500)
    ).

state_of(PNs) ->
    lists:foldl(fun(PN, S) -> quic_ack:record_received(S, PN) end, quic_ack:new(), PNs).

ranges_of(PNs) ->
    quic_ack:ack_ranges(state_of(PNs)).

decoded(PNs) ->
    {ok, {ack, Largest, _Delay, FirstRange, AckRanges}} =
        quic_ack:generate_ack(state_of(PNs), erlang:monotonic_time(millisecond)),
    quic_ack:ack_frame_to_ranges(Largest, FirstRange, AckRanges).
