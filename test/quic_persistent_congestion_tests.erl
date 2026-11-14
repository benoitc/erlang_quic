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
    CC = quic_connection:cc_after_loss(
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
