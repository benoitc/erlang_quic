%%% -*- erlang -*-
%%%
%%% RFC 9002 Section 2: bytes in flight are the sizes of the packets that
%%% are ack-eliciting or carry PADDING, sent and not yet acknowledged,
%%% declared lost or discarded. Random sends of each kind, acknowledgements,
%%% timer losses and space discards run against a loss tracker; after every
%%% step its count equals that sum over the packets it still holds.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(prop_quic_in_flight).

-include_lib("proper/include/proper.hrl").
-include_lib("quic/include/quic.hrl").

prop_bytes_in_flight_is_the_sum_of_in_flight_packets() ->
    ?FORALL(
        Ops,
        list(op()),
        begin
            T0 = erlang:monotonic_time(millisecond) - 100000,
            Init = {true, quic_loss:new(), #{initial => 0, handshake => 0, app => 0}, T0},
            {Ok, _L, _Next, _T} = lists:foldl(fun step/2, Init, Ops),
            Ok
        end
    ).

op() ->
    frequency([
        {8, {send, space(), kind(), range(20, 1500)}},
        {4, {ack, space(), range(0, 100), range(0, 100)}},
        {1, {timer, space()}},
        {1, {discard, oneof([initial, handshake])}}
    ]).

space() ->
    oneof([initial, handshake, app]).

kind() ->
    oneof([ack_eliciting, padded, ack_only]).

step(_Op, {false, _, _, _} = Failed) ->
    Failed;
step(Op, {true, L0, Next0, T0}) ->
    T = T0 + 1,
    {L, Next} = run(Op, L0, Next0, T),
    {holds(L), L, Next, T}.

run({send, Space, Kind, Size}, L, Next, T) ->
    PN = maps:get(Space, Next),
    {AckEliciting, InFlight} = flags(Kind),
    {
        quic_loss:on_packet_sent(Space, L, PN, Size, AckEliciting, InFlight, [], T),
        Next#{Space := PN + 1}
    };
run({ack, Space, _A, _B}, L, #{} = Next, _T) when map_get(Space, Next) =:= 0 ->
    {L, Next};
run({ack, Space, A, B}, L, Next, T) ->
    Last = maps:get(Space, Next) - 1,
    Lo = (min(A, B) * Last) div 100,
    Hi = (max(A, B) * Last) div 100,
    {L1, _Acked, _Lost, _Meta} = quic_loss:on_ack_received(
        Space, L, {ack, Hi, 0, Hi - Lo, []}, T
    ),
    {L1, Next};
run({timer, Space}, L, Next, _T) ->
    {L1, _Lost} = quic_loss:detect_lost_packets(Space, L, quic_loss:largest_acked(L, Space)),
    {L1, Next};
run({discard, Space}, L, Next, _T) ->
    {L1, _Bytes} = quic_loss:discard_space(Space, L),
    {L1, Next}.

flags(ack_eliciting) -> {true, true};
flags(padded) -> {false, true};
flags(ack_only) -> {false, false}.

holds(L) ->
    Queued = lists:append([
        maps:values(quic_loss:sent_packets(S, L))
     || S <- [initial, handshake, app]
    ]),
    quic_loss:bytes_in_flight(L) =:=
        lists:sum([Sz || #sent_packet{in_flight = true, size = Sz} <- Queued]).
