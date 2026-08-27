%%% -*- erlang -*-
%%%
%%% Tests for the loss time threshold (RFC 9002 §6.1.2).
%%%
%%% The threshold is max(smoothed_rtt, latest_rtt), not smoothed_rtt
%%% alone. When an RTT spike outruns the EWMA the two diverge, and an
%%% EWMA-only threshold declares in-flight packets lost while their ACKs
%%% are merely late; each spurious loss both retransmits data and
%%% collapses the congestion window.
%%%
%%% The delay is observable through get_loss_time_and_space/1, which
%%% returns TimeSent + LossDelay for the oldest in-flight packet. Pinning
%%% TimeSent with on_packet_sent/6 makes LossDelay readable by
%%% subtraction, so these tests assert on the delay itself rather than
%%% re-deriving it from the formula under test.
%%%
%%% Covers PR #210.

-module(quic_loss_time_threshold_tests).

-include_lib("eunit/include/eunit.hrl").

%% Must match quic_loss.
-define(TIME_THRESHOLD, 1.125).
-define(GRANULARITY, 1).

%% Arbitrary fixed send time, in the monotonic milliseconds
%% on_packet_sent/6 expects.
-define(SENT_AT, 1000000).

%%====================================================================
%% Helpers
%%====================================================================

%% One in-flight packet sent at ?SENT_AT.
with_inflight_packet(State) ->
    quic_loss:on_packet_sent(State, 1, 1200, true, [], ?SENT_AT).

%% Feed RTT samples in order.
samples(State, Rtts) ->
    lists:foldl(fun(Rtt, S) -> quic_loss:update_rtt(S, Rtt, 0) end, State, Rtts).

%% The delay actually applied, recovered from the returned loss time.
applied_delay(State) ->
    {LossTime, _Space} = quic_loss:get_loss_time_and_space(State),
    ?assertNotEqual(undefined, LossTime),
    LossTime - ?SENT_AT.

expected_delay(Rtt) ->
    max(trunc(?TIME_THRESHOLD * Rtt), ?GRANULARITY).

%%====================================================================
%% RTT bookkeeping these tests depend on
%%====================================================================

spike_leaves_latest_above_smoothed_test() ->
    State = samples(quic_loss:new(), [20, 400]),
    ?assertEqual(400, quic_loss:latest_rtt(State)),
    %% The EWMA lags the spike, otherwise the assertions below would not
    %% distinguish the two thresholds.
    ?assert(quic_loss:smoothed_rtt(State) < 400).

decay_leaves_smoothed_above_latest_test() ->
    State = samples(quic_loss:new(), [400, 20]),
    ?assertEqual(20, quic_loss:latest_rtt(State)),
    ?assert(quic_loss:smoothed_rtt(State) > 20).

%%====================================================================
%% Loss time threshold
%%====================================================================

delay_follows_latest_rtt_when_it_exceeds_smoothed_test() ->
    State = with_inflight_packet(samples(quic_loss:new(), [20, 400])),
    SRTT = quic_loss:smoothed_rtt(State),
    Latest = quic_loss:latest_rtt(State),
    ?assertEqual(expected_delay(Latest), applied_delay(State)),
    %% Explicitly not the smoothed-only value, which is what an
    %% EWMA-only threshold would produce.
    ?assertNotEqual(expected_delay(SRTT), applied_delay(State)).

delay_follows_smoothed_rtt_when_it_exceeds_latest_test() ->
    State = with_inflight_packet(samples(quic_loss:new(), [400, 20])),
    SRTT = quic_loss:smoothed_rtt(State),
    Latest = quic_loss:latest_rtt(State),
    ?assertEqual(expected_delay(SRTT), applied_delay(State)),
    ?assertNotEqual(expected_delay(Latest), applied_delay(State)).

delay_equals_both_when_rtt_is_stable_test() ->
    %% With a flat RTT the two estimates coincide and the max() is a
    %% no-op; the threshold must not drift.
    State = with_inflight_packet(samples(quic_loss:new(), [50, 50, 50])),
    ?assertEqual(50, quic_loss:latest_rtt(State)),
    ?assertEqual(50, quic_loss:smoothed_rtt(State)),
    ?assertEqual(expected_delay(50), applied_delay(State)).

delay_floors_at_granularity_test() ->
    %% A zero RTT sample must still leave a floor of one granularity
    %% unit, otherwise loss detection fires on scheduling jitter alone.
    State = with_inflight_packet(samples(quic_loss:new(), [0])),
    ?assertEqual(?GRANULARITY, applied_delay(State)).

no_in_flight_packet_has_no_loss_time_test() ->
    State = samples(quic_loss:new(), [50]),
    ?assertEqual({undefined, initial}, quic_loss:get_loss_time_and_space(State)).

%%====================================================================
%% What the threshold is for: not declaring loss on an RTT spike
%%====================================================================

%% Two ack-eliciting packets sent SpreadMs before a third, then only the
%% third acknowledged with a sample of SampleMs.
%%
%% The packet-number threshold (RFC 9002 6.1.1, kPacketThreshold 3) is
%% deliberately kept out of it: PN 3 and 4 are within 3 of the acked PN
%% 5, so nothing declares them lost on packet number alone and the time
%% threshold is the only thing deciding.
%%
%% Their age at detection is SampleMs + SpreadMs. Choosing that to sit
%% above 1.125 * smoothed_rtt but below 1.125 * latest_rtt is what makes
%% the two thresholds disagree.
spike_scenario(SpreadMs, SampleMs) ->
    Now = erlang:monotonic_time(millisecond),
    Sent = Now - SampleMs,
    S0 = quic_loss:update_rtt(quic_loss:new(), 20, 0),
    S1 = quic_loss:on_packet_sent(S0, 3, 1200, true, [], Sent - SpreadMs),
    S2 = quic_loss:on_packet_sent(S1, 4, 1200, true, [], Sent - SpreadMs),
    S3 = quic_loss:on_packet_sent(S2, 5, 1200, true, [], Sent),
    quic_loss:on_ack_received(S3, {ack, 5, 0, 0, []}, Now).

a_spike_does_not_declare_the_earlier_flight_lost_test() ->
    %% Settled at 20 ms, then a 400 ms sample. The earlier packets are
    %% 420 ms old: past 1.125 * smoothed_rtt, inside 1.125 * latest_rtt.
    %% Their ACKs are late, not missing. Declaring them lost retransmits
    %% data that arrived and collapses the window for nothing.
    {_State, _Acked, Lost, _Meta} = spike_scenario(20, 400),
    ?assertEqual([], Lost).

a_genuinely_old_flight_is_still_declared_lost_test() ->
    %% The inverse, and the fence: far past even the spiked threshold,
    %% so taking the larger RTT must not switch loss detection off.
    {_State, _Acked, Lost, _Meta} = spike_scenario(20000, 400),
    ?assert(length(Lost) > 0).
