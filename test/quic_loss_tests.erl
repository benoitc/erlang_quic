%%% -*- erlang -*-
%%%
%%% Tests for QUIC Loss Detection
%%%

-module(quic_loss_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Basic State Tests
%%====================================================================

new_state_test() ->
    State = quic_loss:new(),
    ?assertEqual(#{}, quic_loss:sent_packets(app, State)),
    ?assertEqual(0, quic_loss:bytes_in_flight(State)),
    ?assertEqual(0, quic_loss:pto_count(State)).

new_state_with_opts_test() ->
    State = quic_loss:new(#{max_ack_delay => 50}),
    ?assertEqual(0, quic_loss:bytes_in_flight(State)).

%%====================================================================
%% Packet Tracking Tests
%%====================================================================

on_packet_sent_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 1200, true),
    ?assertEqual(1200, quic_loss:bytes_in_flight(S1)),
    Sent = quic_loss:sent_packets(app, S1),
    ?assert(maps:is_key(0, Sent)).

on_packet_sent_multiple_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 1000, true),
    S2 = quic_loss:on_packet_sent(app, S1, 1, 500, true),
    S3 = quic_loss:on_packet_sent(app, S2, 2, 300, true),
    ?assertEqual(1800, quic_loss:bytes_in_flight(S3)),
    ?assertEqual(3, maps:size(quic_loss:sent_packets(app, S3))).

non_ack_eliciting_no_bytes_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 100, false),
    ?assertEqual(0, quic_loss:bytes_in_flight(S1)).

%%====================================================================
%% RTT Tests
%%====================================================================

initial_rtt_test() ->
    State = quic_loss:new(),
    %% Default initial RTT is 100ms (more aggressive than RFC 9002's 333ms)
    ?assertEqual(100, quic_rtt:smoothed(quic_loss:rtt(State))).

first_rtt_sample_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    ?assertEqual(100, quic_rtt:smoothed(quic_loss:rtt(S1))),
    ?assertEqual(50, quic_rtt:var(quic_loss:rtt(S1))),
    ?assertEqual(100, quic_rtt:min(quic_loss:rtt(S1))),
    ?assertEqual(100, quic_rtt:latest(quic_loss:rtt(S1))).

rtt_update_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    S2 = quic_loss:update_rtt(S1, 120, 0),
    %% smoothed_rtt = 7/8 * 100 + 1/8 * 120 = 102.5 -> 102
    ?assertEqual(102, quic_rtt:smoothed(quic_loss:rtt(S2))),
    ?assertEqual(100, quic_rtt:min(quic_loss:rtt(S2))),
    ?assertEqual(120, quic_rtt:latest(quic_loss:rtt(S2))).

rtt_with_ack_delay_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    %% Second sample with ACK delay
    S2 = quic_loss:update_rtt(S1, 150, 30),
    %% adjusted_rtt = 150 - 30 = 120 (since 150 > 100 + 30)
    %% But ACK delay is capped at max_ack_delay (25ms default)
    ?assert(quic_rtt:smoothed(quic_loss:rtt(S2)) > 100).

min_rtt_updates_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    S2 = quic_loss:update_rtt(S1, 80, 0),
    ?assertEqual(80, quic_rtt:min(quic_loss:rtt(S2))),
    S3 = quic_loss:update_rtt(S2, 120, 0),
    ?assertEqual(80, quic_rtt:min(quic_loss:rtt(S3))).

%%====================================================================
%% PTO Tests
%%====================================================================

initial_pto_test() ->
    State = quic_loss:new(),
    %% Initial: smoothed_rtt=100, rtt_var=50, max_ack_delay=25.
    %% Before confirmation max_ack_delay is left out:
    %% PTO = 100 + max(4*50, 1) = 300
    ?assertEqual(300, quic_loss:get_pto(State, handshake)),
    %% After it: PTO = 100 + 200 + 25 = 325
    ?assertEqual(325, quic_loss:get_pto(quic_loss:on_handshake_confirmed(State), app)).

pto_after_rtt_sample_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 50, 0),
    %% smoothed_rtt=50, rtt_var=25, max_ack_delay=25.
    %% Before confirmation: PTO = 50 + max(4*25, 1) = 150
    ?assertEqual(150, quic_loss:get_pto(S1, handshake)),
    %% After it: PTO = 50 + 100 + 25 = 175
    ?assertEqual(175, quic_loss:get_pto(quic_loss:on_handshake_confirmed(S1), app)).

pto_exponential_backoff_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:update_rtt(State, 100, 0),
    PTO0 = quic_loss:get_pto(S1, handshake),

    S2 = quic_loss:on_pto_expired(S1),
    ?assertEqual(1, quic_loss:pto_count(S2)),
    PTO1 = quic_loss:get_pto(S2, handshake),
    ?assertEqual(PTO0 * 2, PTO1),

    S3 = quic_loss:on_pto_expired(S2),
    ?assertEqual(2, quic_loss:pto_count(S3)),
    PTO2 = quic_loss:get_pto(S3, handshake),
    ?assertEqual(PTO0 * 4, PTO2).

%% Test that PTO count is NOT reset on packet send
%% (it should only reset on ACK received per RFC 9002)
pto_not_reset_on_packet_sent_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_pto_expired(State),
    ?assertEqual(1, quic_loss:pto_count(S1)),
    %% Sending a packet should NOT reset PTO count
    S2 = quic_loss:on_packet_sent(app, S1, 0, 100, true, []),
    ?assertEqual(1, quic_loss:pto_count(S2)),
    %% PTO count should only reset on ACK
    Now = erlang:monotonic_time(millisecond) + 50,
    {S3, _, _, _} = quic_loss:on_ack_received(app, S2, {ack, 0, 0, 0, []}, Now),
    ?assertEqual(0, quic_loss:pto_count(S3)).

%%====================================================================
%% ACK Processing Tests
%%====================================================================

ack_single_packet_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 1000, true),
    AckFrame = {ack, 0, 0, 0, []},
    Now = erlang:monotonic_time(millisecond) + 50,
    {S2, Acked, Lost, _Meta} = quic_loss:on_ack_received(app, S1, AckFrame, Now),
    ?assertEqual(1, length(Acked)),
    ?assertEqual(0, length(Lost)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S2)).

ack_multiple_packets_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 500, true),
    S2 = quic_loss:on_packet_sent(app, S1, 1, 500, true),
    S3 = quic_loss:on_packet_sent(app, S2, 2, 500, true),
    % Acks 0, 1, 2
    AckFrame = {ack, 2, 0, 2, []},
    Now = erlang:monotonic_time(millisecond) + 50,
    {S4, Acked, _Lost, _Meta} = quic_loss:on_ack_received(app, S3, AckFrame, Now),
    ?assertEqual(3, length(Acked)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S4)).

ack_updates_rtt_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 500, true),
    timer:sleep(10),
    Now = erlang:monotonic_time(millisecond),
    AckFrame = {ack, 0, 0, 0, []},
    {S2, _Acked, _Lost, _Meta} = quic_loss:on_ack_received(app, S1, AckFrame, Now),
    %% RTT should be updated from the sample
    ?assert(quic_rtt:latest(quic_loss:rtt(S2)) >= 10).

%%====================================================================
%% Loss Detection Tests
%%====================================================================

loss_by_packet_threshold_test() ->
    State = quic_loss:new(),
    %% Send packets 0-5
    S1 = lists:foldl(
        fun(PN, Acc) ->
            quic_loss:on_packet_sent(app, Acc, PN, 100, true)
        end,
        State,
        lists:seq(0, 5)
    ),

    %% ACK only packet 5 (skipping 0-4)
    %% With packet threshold of 3, packets 0, 1, 2 should be lost
    AckFrame = {ack, 5, 0, 0, []},
    Now = erlang:monotonic_time(millisecond) + 1000,
    {_S2, _Acked, Lost, _Meta} = quic_loss:on_ack_received(app, S1, AckFrame, Now),

    %% Packets 0, 1, 2 should be lost (5 - 3 = 2)
    LostPNs = [P#sent_packet.pn || P <- Lost],
    ?assert(lists:member(0, LostPNs)),
    ?assert(lists:member(1, LostPNs)),
    ?assert(lists:member(2, LostPNs)).

%%====================================================================
%% Loss Time Tests
%%====================================================================

get_loss_time_no_packets_test() ->
    ?assertEqual(none, quic_loss:get_loss_time_and_space(quic_loss:new())).

%% A packet nothing has overtaken has no time-threshold deadline: until
%% an acknowledgement names a higher packet number there is no evidence
%% it was lost, and the probe timer covers it instead.
get_loss_time_needs_an_acknowledgement_test() ->
    S1 = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 100, true),
    ?assertEqual(none, quic_loss:get_loss_time_and_space(S1)).

%% Packet 0 is overtaken by the acknowledgement of packet 1, so it gets a
%% time-threshold deadline: its send time plus 9/8 of the RTT. Times are
%% pinned rather than sampled from the clock, so a stalled runner cannot
%% let the deadline pass before the assertion looks for it.
get_loss_time_with_packets_test() ->
    T0 = 1000,
    S1 = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 100, true, [], T0),
    S2 = quic_loss:on_packet_sent(app, S1, 1, 100, true, [], T0),
    {S3, _Acked, [], _Meta} = quic_loss:on_ack_received(app, S2, {ack, 1, 0, 0, []}, T0 + 10),
    %% First RTT sample: 10ms, so the loss delay is 11.25 ms, reached at 12.
    ?assertEqual({T0 + 12, app}, quic_loss:get_loss_time_and_space(S3)).

%%====================================================================
%% Integration Tests
%%====================================================================

full_cycle_test() ->
    State = quic_loss:new(),

    %% Send some packets
    S1 = quic_loss:on_packet_sent(app, State, 0, 1000, true),
    S2 = quic_loss:on_packet_sent(app, S1, 1, 1000, true),
    ?assertEqual(2000, quic_loss:bytes_in_flight(S2)),

    %% Wait and receive ACK
    timer:sleep(10),
    Now = erlang:monotonic_time(millisecond),
    AckFrame = {ack, 1, 0, 1, []},
    {S3, Acked, _Lost, _Meta} = quic_loss:on_ack_received(app, S2, AckFrame, Now),

    ?assertEqual(2, length(Acked)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S3)),
    ?assertEqual(0, quic_loss:pto_count(S3)).

%%====================================================================
%% ECN ACK Test
%%====================================================================

ack_ecn_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 500, true),
    AckFrame = {ack_ecn, 0, 0, 0, [], 10, 20, 5},
    Now = erlang:monotonic_time(millisecond) + 50,
    {S2, Acked, _Lost, _Meta} = quic_loss:on_ack_received(app, S1, AckFrame, Now),
    ?assertEqual(1, length(Acked)),
    ?assertEqual(0, quic_loss:bytes_in_flight(S2)).

%%====================================================================
%% Frame Storage Tests
%%====================================================================

on_packet_sent_with_frames_test() ->
    State = quic_loss:new(),
    Frames = [{stream, 0, 0, <<"hello">>, false}, ping],
    S1 = quic_loss:on_packet_sent(app, State, 0, 100, true, Frames),
    Sent = quic_loss:sent_packets(app, S1),
    ?assert(maps:is_key(0, Sent)),
    Packet = maps:get(0, Sent),
    ?assertEqual(Frames, Packet#sent_packet.frames).

on_packet_sent_empty_frames_test() ->
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 100, true, []),
    Sent = quic_loss:sent_packets(app, S1),
    Packet = maps:get(0, Sent),
    ?assertEqual([], Packet#sent_packet.frames).

on_packet_sent_backward_compatible_test() ->
    %% Test that on_packet_sent/4 still works (calls /5 with empty frames)
    State = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, State, 0, 100, true),
    Sent = quic_loss:sent_packets(app, S1),
    Packet = maps:get(0, Sent),
    ?assertEqual([], Packet#sent_packet.frames).

%%====================================================================
%% Retransmittable Frames Tests
%%====================================================================

retransmittable_filters_padding_test() ->
    Frames = [padding, {padding, 10}, {stream, 0, 0, <<"data">>, false}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([{stream, 0, 0, <<"data">>, false}], Result).

retransmittable_filters_ack_test() ->
    Frames = [{ack, 5, 0, 5, []}, {stream, 0, 0, <<"data">>, false}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([{stream, 0, 0, <<"data">>, false}], Result).

retransmittable_filters_ack_variants_test() ->
    Frames = [
        % 4-tuple variant
        {ack, 5, 0, 5},
        % 5-tuple variant
        {ack, 5, 0, 5, []},
        % ECN variant
        {ack_ecn, 5, 0, 5, [], 1, 2, 3},
        {stream, 0, 0, <<"data">>, false}
    ],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([{stream, 0, 0, <<"data">>, false}], Result).

retransmittable_filters_connection_close_test() ->
    Frames = [{connection_close, transport, 0, undefined, <<>>}, {max_data, 100}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([{max_data, 100}], Result).

retransmittable_keeps_stream_test() ->
    Frames = [{stream, 0, 100, <<"test data">>, true}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual(Frames, Result).

retransmittable_keeps_crypto_test() ->
    Frames = [{crypto, 0, <<"handshake data">>}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual(Frames, Result).

%% RFC 9000 Section 13.3: a lost PING needs no repair.
retransmittable_drops_ping_test() ->
    ?assertEqual([], quic_loss:retransmittable_frames([ping])).

retransmittable_keeps_max_data_test() ->
    Frames = [{max_data, 1000000}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual(Frames, Result).

retransmittable_empty_list_test() ->
    ?assertEqual([], quic_loss:retransmittable_frames([])).

retransmittable_all_filtered_test() ->
    Frames = [padding, {ack, 5, 0, 5, []}],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([], Result).

retransmittable_mixed_test() ->
    Frames = [
        padding,
        {stream, 0, 0, <<"data1">>, false},
        {ack, 5, 0, 5, []},
        {crypto, 0, <<"tls data">>},
        {connection_close, transport, 0, undefined, <<>>},
        ping
    ],
    Result = quic_loss:retransmittable_frames(Frames),
    Expected = [
        {stream, 0, 0, <<"data1">>, false},
        {crypto, 0, <<"tls data">>}
    ],
    ?assertEqual(Expected, Result).

%% DATAGRAM frames (RFC 9221) should never be retransmitted
retransmittable_filters_datagram_test() ->
    Frames = [
        {datagram, <<"unreliable data">>},
        {stream, 0, 0, <<"reliable data">>, false}
    ],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([{stream, 0, 0, <<"reliable data">>, false}], Result).

retransmittable_filters_datagram_with_length_test() ->
    Frames = [
        {datagram_with_length, <<"unreliable data">>},
        {max_data, 100}
    ],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([{max_data, 100}], Result).

retransmittable_filters_all_datagrams_test() ->
    Frames = [
        {datagram, <<"data1">>},
        {datagram_with_length, <<"data2">>}
    ],
    Result = quic_loss:retransmittable_frames(Frames),
    ?assertEqual([], Result).

%%====================================================================
%% stream_has_unacked_below/3 (RESET_STREAM_AT reliable-reclaim gate)
%%====================================================================

stream_has_unacked_below_empty_test() ->
    ?assertNot(quic_loss:stream_has_unacked_below(quic_loss:new(), 4, 100)).

stream_has_unacked_below_test() ->
    S0 = quic_loss:new(),
    %% In-flight STREAM data for stream 4 starting at offset 50.
    S1 = quic_loss:on_packet_sent(app, S0, 0, 100, true, [{stream, 4, 50, <<"a">>, false}]),
    ?assert(quic_loss:stream_has_unacked_below(S1, 4, 100)),
    ?assert(quic_loss:stream_has_unacked_below(S1, 4, 51)),
    %% Boundary at/below the frame's start offset is not "below".
    ?assertNot(quic_loss:stream_has_unacked_below(S1, 4, 50)),
    ?assertNot(quic_loss:stream_has_unacked_below(S1, 4, 10)),
    %% Different stream id never matches.
    ?assertNot(quic_loss:stream_has_unacked_below(S1, 8, 100)).

stream_has_unacked_below_ignores_non_stream_test() ->
    S0 = quic_loss:new(),
    S1 = quic_loss:on_packet_sent(app, S0, 0, 50, true, [ping, {max_data, 1000}]),
    ?assertNot(quic_loss:stream_has_unacked_below(S1, 12, 100)).

%%====================================================================
%% Reordering: spurious losses and adaptive thresholds
%%====================================================================

%% One send time for the whole burst, so its packets differ only by number.
sent(State, PNs) ->
    T = erlang:monotonic_time(millisecond),
    lists:foldl(
        fun(PN, Acc) -> quic_loss:on_packet_sent(app, Acc, PN, 1000, true, [], T) end, State, PNs
    ).

pns(Packets) -> lists:sort([P#sent_packet.pn || P <- Packets]).

%% RFC 9002 Section 6.1.2: a packet is lost by time once 9/8 of the RTT has
%% passed since it was sent. At an RTT under 8 ms that is still more than the
%% RTT, so a packet sent with the one acknowledged is not lost.
time_threshold_is_never_below_nine_eighths_test_() ->
    [
        {integer_to_list(R) ++ " ms", fun() -> ?assertEqual({[], [0]}, time_losses(R, 0)) end}
     || R <- lists:seq(1, 16)
    ].

%% The same packet sent earlier, by the RTT / 8 rounded up, is lost by time.
time_threshold_declares_past_nine_eighths_test_() ->
    [
        {integer_to_list(R) ++ " ms", fun() ->
            ?assertEqual({[0], []}, time_losses(R, (R + 7) div 8))
        end}
     || R <- lists:seq(1, 16)
    ].

%% Send 0 at T0, 1 at T0 + Gap, acknowledge 1 an RTT later; return {lost, kept} of 0.
time_losses(RTT, Gap) ->
    T0 = erlang:monotonic_time(millisecond),
    S0 = quic_loss:on_packet_sent(app, quic_loss:new(), 0, 1000, true, [], T0),
    S1 = quic_loss:on_packet_sent(app, S0, 1, 1000, true, [], T0 + Gap),
    {S2, _, Lost, _} = quic_loss:on_ack_received(app, S1, {ack, 1, 0, 0, []}, T0 + Gap + RTT),
    Kept = [PN || PN <- maps:keys(quic_loss:sent_packets(app, S2)), PN =:= 0],
    {pns(Lost), Kept}.

%% 0..2 are declared lost by the packet threshold when 5 is acked alone,
%% then acknowledged: the episode was reordering, the window cut can be
%% undone, and the packet threshold grows to the distance seen.
reordered_losses_are_spurious_test() ->
    S1 = sent(quic_loss:new(), lists:seq(0, 10)),
    Now = erlang:monotonic_time(millisecond),
    {S2, _, Lost, M1} = quic_loss:on_ack_received(app, S1, {ack, 5, 0, 0, []}, Now),
    ?assertEqual([0, 1, 2], pns(Lost)),
    ?assertMatch(#{spurious_losses := 0, spurious_congestion := false}, M1),
    {S3, _, [], M2} = quic_loss:on_ack_received(app, S2, {ack, 10, 0, 10, []}, Now),
    ?assertMatch(#{spurious_losses := 3, spurious_congestion := true}, M2),
    %% Reordering of up to 11 packets was seen: a gap of 9 is not a loss.
    S4 = sent(S3, lists:seq(11, 20)),
    {_, _, Lost2, _} = quic_loss:on_ack_received(app, S4, {ack, 20, 0, 0, []}, Now),
    ?assertEqual([], Lost2).

%% Without reordering seen, the same gap is a loss.
packet_threshold_default_test() ->
    S1 = sent(quic_loss:new(), lists:seq(11, 20)),
    Now = erlang:monotonic_time(millisecond),
    {_, _, Lost, _} = quic_loss:on_ack_received(app, S1, {ack, 20, 0, 0, []}, Now),
    ?assertEqual(lists:seq(11, 17), pns(Lost)).

%% One loss of the episode is never acknowledged: it ages out as a real
%% loss and the cut stays, even though the others were reordered.
real_loss_keeps_cut_test() ->
    S1 = sent(quic_loss:new(), lists:seq(0, 10)),
    Now = erlang:monotonic_time(millisecond),
    {S2, _, Lost, _} = quic_loss:on_ack_received(app, S1, {ack, 5, 0, 0, []}, Now),
    ?assertEqual([0, 1, 2], pns(Lost)),
    %% 1..10 acknowledged, 0 still missing.
    {S3, _, _, M1} = quic_loss:on_ack_received(app, S2, {ack, 10, 0, 9, []}, Now),
    ?assertMatch(#{spurious_losses := 2, spurious_congestion := false}, M1),
    %% Long after: 0 has aged out, so nothing is left to prove spurious.
    S4 = sent(S3, [11]),
    Later = Now + 10000,
    {_, _, _, M2} = quic_loss:on_ack_received(app, S4, {ack, 11, 0, 0, []}, Later),
    ?assertMatch(#{spurious_losses := 0, spurious_congestion := false}, M2).

%% A loss the time threshold declared, then acknowledged, moves the time
%% threshold from 9/8 to 5/4 of the RTT.
spurious_time_loss_widens_time_threshold_test() ->
    %% A 10 ms RTT sample first.
    S0 = sent(quic_loss:new(), [0]),
    #{0 := #sent_packet{time_sent = T0}} = quic_loss:sent_packets(app, S0),
    {S1, _, _, _} = quic_loss:on_ack_received(app, S0, {ack, 0, 0, 0, []}, T0 + 10),
    %% 1 goes out 60 ms before 2; 2 acked alone declares 1 lost by time,
    %% since it is only one packet behind.
    S2 = sent(S1, [1]),
    timer:sleep(60),
    S3 = sent(S2, [2]),
    #{2 := #sent_packet{time_sent = T2}} = quic_loss:sent_packets(app, S3),
    {S4, _, Lost, _} = quic_loss:on_ack_received(app, S3, {ack, 2, 0, 0, []}, T2 + 10),
    ?assertEqual([1], pns(Lost)),
    {S5, _, _, M} = quic_loss:on_ack_received(app, S4, {ack, 2, 0, 2, []}, T2 + 11),
    ?assertMatch(#{spurious_losses := 1}, M),
    S6 = sent(S5, [3, 4]),
    #{3 := #sent_packet{time_sent = T3}} = quic_loss:sent_packets(app, S6),
    {S7, _, [], _} = quic_loss:on_ack_received(app, S6, {ack, 4, 0, 0, []}, T3),
    RTT = quic_loss:rtt(S7),
    R = max(quic_rtt:smoothed(RTT), quic_rtt:latest(RTT)),
    {Deadline, app} = quic_loss:get_loss_time_and_space(S7),
    ?assertEqual(R + R div 4, Deadline - T3).
