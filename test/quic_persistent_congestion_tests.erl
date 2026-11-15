%%% -*- erlang -*-
%%%
%%% Persistent congestion (RFC 9002 Section 7.6.2): two ack-eliciting
%%% packets declared lost, sent after the first RTT sample, more than the
%%% persistent congestion duration apart, with no packet sent between them
%%% acknowledged in any packet number space.

-module(quic_persistent_congestion_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("quic/include/quic.hrl").

lost_handshake_probes_are_not_persistent_congestion_test() ->
    T0 = erlang:monotonic_time(millisecond),
    L0 = sent_at(initial, quic_loss:new(), T0, [0, 300, 900, 2100, 2200]),
    {_L, CC} = ack(initial, L0, quic_cc:new(), 4, T0 + 2250),
    ?assert(quic_cc:cwnd(CC) > minimum_window()).

%% The same blackout with packet 2 acknowledged: the two losses either
%% side of it are no run.
acknowledged_packet_between_ends_the_blackout_test() ->
    T0 = erlang:monotonic_time(millisecond),
    L0 = sent_at(app, quic_loss:new(), T0, [0]),
    {L1, CC1} = ack(app, L0, quic_cc:new(), 0, T0 + 50),
    L2 = sent_at(app, L1, T0, [100, 400, 1000, 1100], 1),
    {L, Lost, CC} = ack_ranges(app, L2, CC1, {ack, 4, 0, 0, [{0, 0}]}, T0 + 1150),
    ?assertEqual([1, 3], lists:sort([PN || #sent_packet{pn = PN} <- Lost])),
    ?assertEqual([], maps:keys(quic_loss:sent_packets(app, L))),
    ?assert(quic_cc:cwnd(CC) > minimum_window()).

blackout_after_the_first_sample_is_persistent_congestion_test() ->
    T0 = erlang:monotonic_time(millisecond),
    L0 = sent_at(app, quic_loss:new(), T0, [0]),
    {L1, CC1} = ack(app, L0, quic_cc:new(), 0, T0 + 50),
    L2 = sent_at(app, L1, T0, [100, 400, 1000, 1100], 1),
    {_L, CC} = ack(app, L2, CC1, 4, T0 + 1150),
    ?assertEqual(minimum_window(), quic_cc:cwnd(CC)).

sent_at(Space, L, T0, Offsets) ->
    sent_at(Space, L, T0, Offsets, 0).

sent_at(Space, L0, T0, Offsets, FirstPN) ->
    {L, _} = lists:foldl(
        fun(Offset, {L1, PN}) ->
            {quic_loss:on_packet_sent(Space, L1, PN, 1200, true, [ping], T0 + Offset), PN + 1}
        end,
        {L0, FirstPN},
        Offsets
    ),
    L.

ack(Space, L0, CC0, PN, Now) ->
    {L, _Lost, CC} = ack_ranges(Space, L0, CC0, {ack, PN, 0, 0, []}, Now),
    {L, CC}.

ack_ranges(Space, L0, CC0, Ack, Now) ->
    {L, _Acked, Lost, Meta} = quic_loss:on_ack_received(Space, L0, Ack, Now),
    CC1 = quic_cc:on_packets_acked(CC0, maps:get(acked_bytes, Meta), Now),
    {CC, _Persistent} = quic_connection:cc_after_loss(
        Space,
        CC1,
        maps:get(lost_bytes, Meta, 0),
        maps:get(largest_lost_sent_time, Meta, undefined),
        Lost,
        L
    ),
    {L, Lost, CC}.

minimum_window() ->
    2 * 1200.

%%====================================================================
%% quic_loss:persistent_congestion/3
%%====================================================================

no_losses_or_one_loss_is_no_persistent_congestion_test() ->
    L = sampled(),
    ?assertNot(pc([], L)),
    ?assertNot(pc([lost(1, 100)], L)).

losses_more_than_the_duration_apart_test() ->
    L = sampled(),
    D = duration(L),
    ?assertNot(pc([lost(1, 100), lost(2, 100 + D - 1)], L)),
    ?assert(pc([lost(1, 100), lost(2, 100 + D + 1)], L)).

%% The duration has to be exceeded, not reached.
losses_exactly_the_duration_apart_test() ->
    L = sampled(),
    D = duration(L),
    ?assertNot(pc([lost(1, 100), lost(2, 100 + D)], L)),
    ?assert(pc([lost(1, 100), lost(2, 100 + D + 1)], L)).

%% Packet 2 is neither lost nor still queued: it was acknowledged. Still
%% queued, it is only outstanding and the run holds.
acknowledged_packet_between_test() ->
    L = sampled(),
    D = duration(L),
    Lost = [lost(1, 100), lost(3, 100 + D + 1)],
    ?assertNot(pc(Lost, L)),
    ?assert(pc(Lost, quic_loss:on_packet_sent(app, L, 2, 1200, true, [ping], 300))).

%% A Handshake packet sent after the first loss and acknowledged ends the
%% run, even once the space is discarded; one sent before it does not.
another_space_acknowledged_after_the_first_loss_test() ->
    ?assertNot(pc_after_handshake_ack(300, keep)),
    ?assertNot(pc_after_handshake_ack(300, discard)),
    ?assert(pc_after_handshake_ack(90, keep)).

%% Both ends must be ack-eliciting (RFC 9002 Section 7.6.2); an ACK-only
%% packet between them does not break the run.
ack_only_end_test() ->
    L = sampled(),
    D = duration(L),
    ?assertNot(pc([lost(1, 100), ack_only(2, 100 + D + 1)], L)),
    ?assertNot(pc([ack_only(1, 100), lost(2, 100 + D + 1)], L)),
    ?assert(pc([lost(1, 100), ack_only(2, 300), lost(3, 100 + D + 1)], L)).

%% The first sample is at 50: a packet sent before it starts no run.
sent_before_the_first_rtt_sample_test() ->
    L = sampled(),
    D = duration(L),
    ?assertNot(pc([lost(1, 40), lost(2, 40 + D + 1)], L)),
    ?assert(pc([lost(1, 60), lost(2, 60 + D + 1)], L)),
    ?assertNot(pc([lost(1, 60), lost(2, 60 + D + 1)], quic_loss:new())).

%% RFC 9002 Section 7.6.3, one time unit being half the persistent
%% congestion PTO: packets 2 to 8 lost, 1 and 9 acknowledged, 7 units
%% apart against a duration of 6. With packet 5 acknowledged as well,
%% neither side of it spans the duration.
rfc_example_test() ->
    L = sampled(),
    PTO = quic_loss:persistent_congestion_pto(L),
    At = fun(Unit) -> 100 + (Unit * PTO) div 2 end,
    Lost = [
        lost(PN, At(Unit))
     || {PN, Unit} <- [{2, 1}, {3, 2}, {4, 3}, {5, 4}, {6, 5}, {7, 6}, {8, 8}]
    ],
    ?assert(pc(Lost, L)),
    ?assertNot(pc(lists:keydelete(5, #sent_packet.pn, Lost), L)).

%%====================================================================
%% Losses declared in separate events
%%====================================================================

%% Packets 1 to 6 are declared lost by the ACK of 9, too close together
%% for persistent congestion. 7 and 8, sent later, are still too recent
%% and follow with the ACK of 10. 1 to 8 is one period, longer than the
%% duration (RFC 9002 Section 7.6.2).
losses_declared_apart_are_one_period_test() ->
    {L1, CC1, D} = first_losses(),
    {_L, Lost, CC} = ack_ranges(
        app, sent_at(app, L1, 0, [D + 160], 10), CC1, ack_of([10]), D + 210
    ),
    ?assertEqual([7, 8], pns(Lost)),
    ?assertEqual(minimum_window(), quic_cc:cwnd(CC)).

%% Packet 7 acknowledged with 10 ends the period at 6.
acknowledged_after_the_first_losses_test() ->
    {L1, CC1, D} = first_losses(),
    {_L, Lost, CC} = ack_ranges(
        app, sent_at(app, L1, 0, [D + 160], 10), CC1, ack_of([10, 7]), D + 210
    ),
    ?assertEqual([8], pns(Lost)),
    ?assert(quic_cc:cwnd(CC) > minimum_window()).

%% Packet 6, declared lost, turns out acknowledged: 1 to 5 and 7 to 8 are
%% two periods, neither long enough.
late_acknowledged_loss_ends_the_period_test() ->
    {L1, CC1, D} = first_losses(),
    {_L, Lost, CC} = ack_ranges(
        app, sent_at(app, L1, 0, [D + 160], 10), CC1, ack_of([10, 6]), D + 210
    ),
    ?assertEqual([7, 8], pns(Lost)),
    ?assert(quic_cc:cwnd(CC) > minimum_window()).

%% Once declared, the same losses start no other period.
declared_losses_start_no_other_period_test() ->
    {L1, _CC1, D} = first_losses(),
    Later = [lost(7, 100 + D + 4), lost(8, 100 + D + 5)],
    ?assert(pc(Later, L1)),
    ?assertNot(pc(Later, quic_loss:on_persistent_congestion(L1))).

%% RFC 9002 Section 5.2: min_rtt restarts from the newest sample.
min_rtt_restarts_after_persistent_congestion_test() ->
    L0 = sent_at(app, sampled(), 0, [100], 1),
    {L, [_], [], _} = quic_loss:on_ack_received(app, L0, {ack, 1, 0, 0, []}, 300),
    ?assertEqual(50, quic_rtt:min(quic_loss:rtt(L))),
    ?assertEqual(200, quic_rtt:min(quic_loss:rtt(quic_loss:on_persistent_congestion(L)))).

%% Losses whose neighbours are both acknowledged can join no later loss,
%% so a long run of them leaves nothing behind.
isolated_losses_are_not_kept_test() ->
    ?assert(
        erts_debug:flat_size(isolated_losses(60)) - erts_debug:flat_size(isolated_losses(5)) < 100
    ).

%% N rounds of five packets, a second apart: the first is lost and the
%% others acknowledged.
isolated_losses(N) ->
    lists:foldl(
        fun(I, Acc0) ->
            Base = 5 * I,
            At = 1000 * I,
            Acc1 = sent_at(app, Acc0, 0, lists:duplicate(5, At), Base),
            {Acc, [_], _} = ack_ranges(
                app, Acc1, quic_cc:new(), {ack, Base + 4, 0, 3, []}, At + 50
            ),
            Acc
        end,
        sampled(),
        lists:seq(1, N)
    ).

%% Sampled at 50 with a 50 ms RTT, packets 1 to 6 are sent at 100 to 105,
%% 7 to 9 just past the duration D; the ACK of 9 declares 1 to 6 lost.
first_losses() ->
    L0 = sampled(),
    D = duration(L0),
    L1 = sent_at(app, L0, 0, [100, 101, 102, 103, 104, 105, D + 104, D + 105, D + 106], 1),
    {L, Lost, CC} = ack_ranges(app, L1, quic_cc:new(), ack_of([9]), D + 156),
    [1, 2, 3, 4, 5, 6] = pns(Lost),
    true = quic_cc:cwnd(CC) > minimum_window(),
    {L, CC, D}.

%% An ACK frame for the packet numbers given, newest first.
ack_of([Largest | Rest]) ->
    {ack, Largest, 0, 0, gaps(Largest, Rest)}.

gaps(_Prev, []) -> [];
gaps(Prev, [PN | Rest]) -> [{Prev - PN - 2, 0} | gaps(PN, Rest)].

pns(Packets) ->
    lists:sort([PN || #sent_packet{pn = PN} <- Packets]).

%% A first RTT sample at 50 from packet 0 of the application space.
sampled() ->
    L0 = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 1200, true, [ping], 0),
    {L, [_], [], _} = quic_loss:on_ack_received(app, L0, {ack, 0, 0, 0, []}, 50),
    L.

pc_after_handshake_ack(SentAt, Discard) ->
    L0 = quic_loss:on_packet_sent(handshake, sampled(), 0, 1200, true, [ping], SentAt),
    {L1, [_], [], _} = quic_loss:on_ack_received(handshake, L0, {ack, 0, 0, 0, []}, SentAt + 50),
    L =
        case Discard of
            keep -> L1;
            discard -> element(1, quic_loss:discard_space(handshake, L1))
        end,
    D = duration(L),
    pc([lost(1, 100), lost(2, 100 + D + 1)], L).

duration(L) ->
    3 * quic_loss:persistent_congestion_pto(L).

pc(Lost, L) ->
    quic_loss:persistent_congestion(app, Lost, L).

lost(PN, At) ->
    #sent_packet{
        pn = PN,
        time_sent = At,
        ack_eliciting = true,
        in_flight = true,
        size = 1200,
        frames = [ping]
    }.

ack_only(PN, At) ->
    #sent_packet{
        pn = PN, time_sent = At, ack_eliciting = false, in_flight = false, size = 50, frames = []
    }.
