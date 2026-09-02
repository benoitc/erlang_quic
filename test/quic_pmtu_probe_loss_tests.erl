%%% -*- erlang -*-
%%%
%%% PMTU probes must not surface as connection loss (RFC 8899 §3,
%%% RFC 9000 §14.4).
%%%
%%% A probe sent past the path MTU is lost by design: its fate belongs
%%% to the PMTUD state machine alone. The connection sends probes
%%% tracked as non-ack-eliciting: they stay in the sent queue, which is
%%% what the PMTU ack/lost hooks fold over, but contribute nothing to
%%% bytes_in_flight, acked_bytes, lost_bytes, or the congestion-event
%%% timestamp.
%%%
%%% Before this held, a single lost 600-second raise probe kept
%%% bytes_in_flight above zero with no possible progress and the
%%% disconnect timeout declared the peer dead: every long-lived
%%% connection on an MTU-limited path died on its first periodic
%%% re-probe, both ends at once. The end-to-end consequence is covered
%%% by quic_pmtu_raise_probe_SUITE.

-module(quic_pmtu_probe_loss_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(PROBE_SIZE, 1467).
-define(DATA_SIZE, 1200).

%% An ACK frame in the shape on_ack_received/3 consumes:
%% {ack, LargestAcked, AckDelay, FirstRange, AckRanges}.
ack(Largest, FirstRange) ->
    {ack, Largest, 0, FirstRange, []}.

now_ms() ->
    erlang:monotonic_time(millisecond).

%% A probe is registered with an empty frames list, exactly as
%% send_pmtu_probe_packet does, which makes it non-ack-eliciting.
send_probe(State, PN, Now) ->
    quic_loss:on_packet_sent(State, PN, ?PROBE_SIZE, false, [], Now).

send_data(State, PN, Now) ->
    quic_loss:on_packet_sent(State, PN, ?DATA_SIZE, true, [{ping}], Now).

probe_adds_no_bytes_in_flight_test() ->
    S0 = quic_loss:new(),
    S1 = send_probe(S0, 0, now_ms()),
    ?assertEqual(0, quic_loss:bytes_in_flight(S1)).

acked_probe_is_seen_but_counts_nothing_test() ->
    Now = now_ms(),
    S0 = send_probe(quic_loss:new(), 0, Now),
    {S1, Acked, Lost, Meta} = quic_loss:on_ack_received(S0, ack(0, 0), Now + 20),
    %% The PMTU ack hook folds over the acked list, so the probe must
    %% appear there even though it elicits nothing locally.
    ?assertEqual([0], [P#sent_packet.pn || P <- Acked]),
    ?assertEqual([], Lost),
    ?assertEqual(0, maps:get(acked_bytes, Meta)),
    ?assertNot(maps:get(has_ack_eliciting, Meta)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S1)).

lost_probe_is_seen_but_is_not_a_congestion_signal_test() ->
    Now = now_ms(),
    %% Probe as pn 0, then three real packets; acking 1..3 pushes pn 0
    %% past the packet threshold (RFC 9002 §6.1.1) and declares it lost.
    S0 = send_probe(quic_loss:new(), 0, Now),
    S1 = send_data(S0, 1, Now + 1),
    S2 = send_data(S1, 2, Now + 2),
    S3 = send_data(S2, 3, Now + 3),
    {S4, Acked, Lost, Meta} = quic_loss:on_ack_received(S3, ack(3, 2), Now + 30),
    ?assertEqual([1, 2, 3], lists:sort([P#sent_packet.pn || P <- Acked])),
    %% The PMTU lost hook folds over the lost list, so the probe must
    %% appear there...
    ?assertEqual([0], [P#sent_packet.pn || P <- Lost]),
    %% ...while contributing neither lost bytes nor the timestamp that
    %% drives on_congestion_event.
    ?assertEqual(0, maps:get(lost_bytes, Meta)),
    ?assertEqual(undefined, maps:get(largest_lost_sent_time, Meta)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S4)).

%% Fence: a lost ack-eliciting packet still drives the congestion event.
lost_data_still_signals_congestion_test() ->
    Now = now_ms(),
    S0 = send_data(quic_loss:new(), 0, Now),
    S1 = send_data(S0, 1, Now + 1),
    S2 = send_data(S1, 2, Now + 2),
    S3 = send_data(S2, 3, Now + 3),
    {_S4, _Acked, Lost, Meta} = quic_loss:on_ack_received(S3, ack(3, 2), Now + 30),
    ?assertEqual([0], [P#sent_packet.pn || P <- Lost]),
    ?assertEqual(?DATA_SIZE, maps:get(lost_bytes, Meta)),
    ?assertNotEqual(undefined, maps:get(largest_lost_sent_time, Meta)).
