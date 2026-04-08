%%% -*- erlang -*-
%%%
%%% QUIC Loss Detection
%%% RFC 9002 - Loss Detection and Congestion Control
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC loss detection implementation.
%%%
%%% This module implements:
%%% - Packet loss detection using time and packet thresholds
%%% - RTT estimation (smoothed RTT, RTT variance)
%%% - Probe Timeout (PTO) calculation
%%% - Loss detection timer management
%%%
%%% == Loss Detection Methods ==
%%%
%%% 1. Packet Threshold: A packet is lost if a packet sent more than
%%%    kPacketThreshold (3) later has been acknowledged.
%%%
%%% 2. Time Threshold: A packet is lost if it was sent more than
%%%    max(kTimeThreshold * smoothed_rtt, kGranularity) ago and a
%%%    later packet has been acknowledged.
%%%

-module(quic_loss).

-include("quic.hrl").

-export([
    %% Loss detection state
    new/0,
    new/1,

    %% Packet tracking
    on_packet_sent/4,
    on_packet_sent/5,
    on_ack_received/3,

    %% Retransmission
    retransmittable_frames/1,

    %% Loss detection
    detect_lost_packets/2,
    get_loss_time_and_space/1,

    %% RTT
    update_rtt/3,
    smoothed_rtt/1,
    rtt_var/1,
    latest_rtt/1,
    min_rtt/1,

    %% PTO
    get_pto/1,
    on_pto_expired/1,

    %% Queries
    sent_packets/1,
    bytes_in_flight/1,
    pto_count/1,
    oldest_unacked/1,
    has_rtt_sample/1
]).

%% Constants from RFC 9002
-define(PACKET_THRESHOLD, 3).
% 9/8
-define(TIME_THRESHOLD, 1.125).
% 1 millisecond
-define(GRANULARITY, 1).
% RFC 9002 default is 333ms, but 100ms is more aggressive for faster ramp-up
-define(DEFAULT_INITIAL_RTT, 100).

%% Loss detection state
-record(loss_state, {
    %% Sent packets: #{PN => #sent_packet{}}
    sent_packets = #{} :: #{non_neg_integer() => #sent_packet{}},

    %% Sorted packet numbers for O(log n) range lookups
    %% Used by ACK processing to avoid O(n) map fold
    pn_set = gb_sets:new() :: gb_sets:set(non_neg_integer()),

    %% RTT estimation
    latest_rtt = 0 :: non_neg_integer(),
    smoothed_rtt = ?DEFAULT_INITIAL_RTT :: non_neg_integer(),
    rtt_var = ?DEFAULT_INITIAL_RTT div 2 :: non_neg_integer(),
    min_rtt = infinity :: non_neg_integer() | infinity,
    first_rtt_sample = false :: boolean(),

    %% Loss detection
    loss_time = undefined :: non_neg_integer() | undefined,
    time_of_last_ack = undefined :: non_neg_integer() | undefined,

    %% PTO
    pto_count = 0 :: non_neg_integer(),

    %% Bytes in flight
    bytes_in_flight = 0 :: non_neg_integer(),

    %% Cached oldest unacked packet (for O(1) PTO probe selection)
    oldest_unacked_pn = undefined :: non_neg_integer() | undefined,

    %% Configuration
    max_ack_delay = ?DEFAULT_MAX_ACK_DELAY :: non_neg_integer()
}).

-opaque loss_state() :: #loss_state{}.
-export_type([loss_state/0]).

%%====================================================================
%% Loss Detection State
%%====================================================================

%% @doc Create a new loss detection state.
-spec new() -> loss_state().
new() ->
    new(#{}).

%% @doc Create a new loss detection state with options.
%% Options:
%%   - max_ack_delay: Maximum ACK delay (default: 25ms)
%%   - initial_rtt: Initial RTT estimate in ms (default: 100ms)
-spec new(map()) -> loss_state().
new(Opts) ->
    InitialRTT = maps:get(initial_rtt, Opts, ?DEFAULT_INITIAL_RTT),
    #loss_state{
        smoothed_rtt = InitialRTT,
        rtt_var = InitialRTT div 2,
        max_ack_delay = maps:get(max_ack_delay, Opts, ?DEFAULT_MAX_ACK_DELAY)
    }.

%%====================================================================
%% Packet Tracking
%%====================================================================

%% @doc Record that a packet was sent (without frames).
-spec on_packet_sent(loss_state(), non_neg_integer(), non_neg_integer(), boolean()) ->
    loss_state().
on_packet_sent(State, PacketNumber, Size, AckEliciting) ->
    on_packet_sent(State, PacketNumber, Size, AckEliciting, []).

%% @doc Record that a packet was sent with frames.
-spec on_packet_sent(loss_state(), non_neg_integer(), non_neg_integer(), boolean(), [term()]) ->
    loss_state().
on_packet_sent(
    #loss_state{
        sent_packets = Sent,
        pn_set = PNSet,
        bytes_in_flight = InFlight,
        oldest_unacked_pn = OldestPN
    } = State,
    PacketNumber,
    Size,
    AckEliciting,
    Frames
) ->
    Now = erlang:monotonic_time(millisecond),
    SentPacket = #sent_packet{
        pn = PacketNumber,
        time_sent = Now,
        ack_eliciting = AckEliciting,
        in_flight = true,
        size = Size,
        frames = Frames
    },
    NewInFlight =
        case AckEliciting of
            true -> InFlight + Size;
            false -> InFlight
        end,
    %% Update oldest unacked packet number
    NewOldestPN =
        case OldestPN of
            undefined -> PacketNumber;
            _ when PacketNumber < OldestPN -> PacketNumber;
            _ -> OldestPN
        end,
    %% NOTE: pto_count is NOT reset here per RFC 9002.
    %% PTO count is only reset when receiving an ACK (in on_ack_received).
    %% Resetting on send would break exponential backoff for probe retransmissions.
    State#loss_state{
        sent_packets = maps:put(PacketNumber, SentPacket, Sent),
        pn_set = gb_sets:add_element(PacketNumber, PNSet),
        bytes_in_flight = NewInFlight,
        oldest_unacked_pn = NewOldestPN
    }.

%% @doc Process an ACK frame.
%% Returns {NewState, AckedPackets, LostPackets, AckMeta} or {error, ack_range_too_large}
%% AckMeta is a map containing:
%%   - acked_bytes: total bytes from ack-eliciting packets that were acknowledged
%%   - largest_ae_time: sent_time of the largest ack-eliciting packet acknowledged
-spec on_ack_received(loss_state(), term(), non_neg_integer()) ->
    {loss_state(), [#sent_packet{}], [#sent_packet{}], map()} | {error, ack_range_too_large}.
on_ack_received(State, {ack, LargestAcked, AckDelay, FirstRange, AckRanges}, Now) ->
    %% Get acknowledged ranges (more efficient than expanded list)
    case quic_ack:ack_frame_to_ranges(LargestAcked, FirstRange, AckRanges) of
        {error, _} = Error ->
            Error;
        AckedRanges ->
            %% Find packets that were acknowledged using ranges
            %% Uses pn_set for O(k log n) lookup instead of O(n) map fold
            %% MaxAckEliciting is {PN, TimeSent} for largest ack-eliciting packet
            %% RemovedBytes only counts ack-eliciting packet sizes (per RFC 9002)
            {AckedPackets, NewSent, NewPNSet, AckedBytes, MaxAckEliciting} =
                remove_acked_packets_ranges(
                    AckedRanges,
                    State#loss_state.sent_packets,
                    State#loss_state.pn_set
                ),

            %% Update RTT if we got the largest acknowledged
            NewState1 =
                case pn_in_ranges(LargestAcked, AckedRanges) of
                    true ->
                        case maps:get(LargestAcked, State#loss_state.sent_packets, undefined) of
                            #sent_packet{time_sent = TimeSent, ack_eliciting = true} ->
                                LatestRTT = Now - TimeSent,
                                AckDelayMs = ack_delay_to_ms(AckDelay, State),
                                update_rtt(State, LatestRTT, AckDelayMs);
                            _ ->
                                State
                        end;
                    false ->
                        State
                end,

            %% Detect lost packets
            {LostPackets, NewSent2, NewPNSet2, LostBytes} = detect_lost_packets(
                NewSent, NewPNSet, NewState1#loss_state.smoothed_rtt, LargestAcked, Now
            ),

            %% Update oldest unacked PN if needed
            %% Use pn_set for O(log n) lookup of smallest element
            OldOldestPN = State#loss_state.oldest_unacked_pn,
            NewOldestPN =
                case OldOldestPN of
                    undefined ->
                        find_oldest_pn_set(NewPNSet2);
                    _ ->
                        case maps:is_key(OldOldestPN, NewSent2) of
                            true -> OldOldestPN;
                            false -> find_oldest_pn_set(NewPNSet2)
                        end
                end,

            %% Update state
            NewInFlight = max(0, State#loss_state.bytes_in_flight - AckedBytes - LostBytes),
            NewState2 = NewState1#loss_state{
                sent_packets = NewSent2,
                pn_set = NewPNSet2,
                bytes_in_flight = NewInFlight,
                time_of_last_ack = Now,
                pto_count = 0,
                oldest_unacked_pn = NewOldestPN
            },

            %% Build metadata for caller (avoids redundant scanning in quic_connection)
            LargestAETime =
                case MaxAckEliciting of
                    undefined -> Now;
                    {_AckPN, AckTimeSent} -> AckTimeSent
                end,
            AckMeta = #{
                acked_bytes => AckedBytes,
                largest_ae_time => LargestAETime,
                has_ack_eliciting => MaxAckEliciting =/= undefined
            },

            {NewState2, AckedPackets, LostPackets, AckMeta}
    end;
on_ack_received(State, {ack_ecn, LargestAcked, AckDelay, FirstRange, AckRanges, _, _, _}, Now) ->
    on_ack_received(State, {ack, LargestAcked, AckDelay, FirstRange, AckRanges}, Now).

%%====================================================================
%% Loss Detection
%%====================================================================

%% @doc Detect lost packets based on time and packet thresholds.
-spec detect_lost_packets(loss_state(), non_neg_integer()) ->
    {loss_state(), [#sent_packet{}]}.
detect_lost_packets(
    #loss_state{sent_packets = Sent, pn_set = PNSet, smoothed_rtt = SRTT} = State,
    LargestAcked
) ->
    Now = erlang:monotonic_time(millisecond),
    {LostPackets, NewSent, NewPNSet, LostBytes} =
        detect_lost_packets(Sent, PNSet, SRTT, LargestAcked, Now),
    NewState = State#loss_state{
        sent_packets = NewSent,
        pn_set = NewPNSet,
        bytes_in_flight = max(0, State#loss_state.bytes_in_flight - LostBytes)
    },
    {NewState, LostPackets}.

%% Internal loss detection with pn_set
%% IMPORTANT: Only count ack-eliciting packet sizes in LostBytes since
%% bytes_in_flight only tracks ack-eliciting packets (RFC 9002).
%%
%% Uses pn_set iterator to only check packets below LossThreshold for
%% efficient O(k) loss detection where k is the number of lost packets.
detect_lost_packets(SentPackets, PNSet, SmoothedRTT, LargestAcked, Now) ->
    %% Calculate loss delay
    LossDelay = max(trunc(?TIME_THRESHOLD * SmoothedRTT), ?GRANULARITY),

    %% Packet threshold for loss detection (PN < LargestAcked - threshold)
    LossThreshold = LargestAcked - ?PACKET_THRESHOLD + 1,

    %% Iterate only packets below loss threshold for efficiency
    %% Also check time-based loss for packets below LargestAcked
    Iter = gb_sets:iterator(PNSet),
    {LostPNs, Lost, LostBytes} = detect_lost_iter(
        Iter, SentPackets, LossThreshold, LargestAcked, LossDelay, Now, [], [], 0
    ),

    %% Remove lost packets from sent map and pn_set
    Remaining = maps:without(LostPNs, SentPackets),
    %% Use foldl with delete_any for O(k * log n) instead of O(n) subtract
    NewPNSet = lists:foldl(fun gb_sets:delete_any/2, PNSet, LostPNs),

    {Lost, Remaining, NewPNSet, LostBytes}.

%% Iterator-based loss detection
detect_lost_iter(
    Iter,
    SentPackets,
    LossThreshold,
    LargestAcked,
    LossDelay,
    Now,
    PNsAcc,
    LostAcc,
    BytesAcc
) ->
    case gb_sets:next(Iter) of
        none ->
            {PNsAcc, LostAcc, BytesAcc};
        {PN, _NextIter} when PN >= LargestAcked ->
            %% No more packets can be lost (packet number >= largest acked)
            {PNsAcc, LostAcc, BytesAcc};
        {PN, NextIter} ->
            case maps:get(PN, SentPackets, undefined) of
                #sent_packet{
                    time_sent = TimeSent,
                    size = Size,
                    in_flight = true,
                    ack_eliciting = AckEliciting
                } = Packet ->
                    %% Check packet threshold (RFC 9002 Section 6.1.1)
                    PacketLost = PN < LossThreshold,
                    %% Check time threshold (RFC 9002 Section 6.1.2)
                    TimeLost = (Now - TimeSent) > LossDelay,

                    IsLost = PacketLost orelse TimeLost,
                    Ctx = {NextIter, SentPackets, LossThreshold, LargestAcked, LossDelay, Now},
                    detect_lost_maybe(
                        IsLost,
                        Ctx,
                        Packet,
                        AckEliciting,
                        Size,
                        PN,
                        PNsAcc,
                        LostAcc,
                        BytesAcc
                    );
                _ ->
                    %% Not in flight or not found, skip
                    detect_lost_iter(
                        NextIter,
                        SentPackets,
                        LossThreshold,
                        LargestAcked,
                        LossDelay,
                        Now,
                        PNsAcc,
                        LostAcc,
                        BytesAcc
                    )
            end
    end.

%% Helper to reduce nesting in detect_lost_iter
detect_lost_maybe(
    true,
    {NextIter, SentPackets, LossThreshold, LargestAcked, LossDelay, Now},
    Packet,
    AckEliciting,
    Size,
    PN,
    PNsAcc,
    LostAcc,
    BytesAcc
) ->
    NewBytes =
        case AckEliciting of
            true -> BytesAcc + Size;
            false -> BytesAcc
        end,
    detect_lost_iter(
        NextIter,
        SentPackets,
        LossThreshold,
        LargestAcked,
        LossDelay,
        Now,
        [PN | PNsAcc],
        [Packet | LostAcc],
        NewBytes
    );
detect_lost_maybe(
    false,
    {NextIter, SentPackets, LossThreshold, LargestAcked, LossDelay, Now},
    _Packet,
    _AckEliciting,
    _Size,
    _PN,
    PNsAcc,
    LostAcc,
    BytesAcc
) ->
    detect_lost_iter(
        NextIter,
        SentPackets,
        LossThreshold,
        LargestAcked,
        LossDelay,
        Now,
        PNsAcc,
        LostAcc,
        BytesAcc
    ).

%% @doc Get the loss time for setting timers.
-spec get_loss_time_and_space(loss_state()) ->
    {non_neg_integer() | undefined, atom()}.
get_loss_time_and_space(#loss_state{sent_packets = Sent, smoothed_rtt = SRTT}) ->
    LossDelay = max(trunc(?TIME_THRESHOLD * SRTT), ?GRANULARITY),

    %% Find earliest packet that might be declared lost
    case
        maps:fold(
            fun
                (_PN, #sent_packet{time_sent = TimeSent, in_flight = true}, undefined) ->
                    TimeSent + LossDelay;
                (_PN, #sent_packet{time_sent = TimeSent, in_flight = true}, Earliest) ->
                    min(TimeSent + LossDelay, Earliest);
                (_, _, Acc) ->
                    Acc
            end,
            undefined,
            Sent
        )
    of
        undefined -> {undefined, initial};
        % Simplified: always return initial space
        Time -> {Time, initial}
    end.

%%====================================================================
%% RTT Estimation (RFC 9002 Section 5)
%%====================================================================

%% @doc Update RTT estimates with a new sample.
-spec update_rtt(loss_state(), non_neg_integer(), non_neg_integer()) -> loss_state().
update_rtt(#loss_state{first_rtt_sample = false} = State, LatestRTT, _AckDelay) ->
    %% First RTT sample
    State#loss_state{
        latest_rtt = LatestRTT,
        smoothed_rtt = LatestRTT,
        rtt_var = LatestRTT div 2,
        min_rtt = LatestRTT,
        first_rtt_sample = true
    };
update_rtt(
    #loss_state{
        smoothed_rtt = SRTT,
        rtt_var = RTTVAR,
        min_rtt = MinRTT,
        max_ack_delay = MaxAckDelay
    } = State,
    LatestRTT,
    AckDelay
) ->
    %% Update min RTT
    NewMinRTT = min(MinRTT, LatestRTT),

    %% Adjust for ACK delay
    AdjustedRTT =
        case LatestRTT > NewMinRTT + AckDelay of
            true -> LatestRTT - min(AckDelay, MaxAckDelay);
            false -> LatestRTT
        end,

    %% Update smoothed RTT and variance (RFC 9002 Section 5.3)
    %% rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
    %% smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
    NewRTTVAR = (3 * RTTVAR + abs(SRTT - AdjustedRTT)) div 4,
    NewSRTT = (7 * SRTT + AdjustedRTT) div 8,

    State#loss_state{
        latest_rtt = LatestRTT,
        smoothed_rtt = NewSRTT,
        rtt_var = NewRTTVAR,
        min_rtt = NewMinRTT
    }.

%% @doc Get the smoothed RTT.
-spec smoothed_rtt(loss_state()) -> non_neg_integer().
smoothed_rtt(#loss_state{smoothed_rtt = SRTT}) -> SRTT.

%% @doc Get the RTT variance.
-spec rtt_var(loss_state()) -> non_neg_integer().
rtt_var(#loss_state{rtt_var = RTTVAR}) -> RTTVAR.

%% @doc Get the latest RTT sample.
-spec latest_rtt(loss_state()) -> non_neg_integer().
latest_rtt(#loss_state{latest_rtt = L}) -> L.

%% @doc Get the minimum RTT.
-spec min_rtt(loss_state()) -> non_neg_integer() | infinity.
min_rtt(#loss_state{min_rtt = M}) -> M.

%%====================================================================
%% Probe Timeout (RFC 9002 Section 6.2)
%%====================================================================

%% @doc Calculate the Probe Timeout.
%% PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
-spec get_pto(loss_state()) -> non_neg_integer().
get_pto(#loss_state{
    smoothed_rtt = SRTT,
    rtt_var = RTTVAR,
    max_ack_delay = MaxAckDelay,
    pto_count = PTOCount
}) ->
    PTO = SRTT + max(4 * RTTVAR, ?GRANULARITY) + MaxAckDelay,
    %% Exponential backoff
    PTO bsl PTOCount.

%% @doc Handle PTO expiration.
-spec on_pto_expired(loss_state()) -> loss_state().
on_pto_expired(#loss_state{pto_count = Count} = State) ->
    State#loss_state{pto_count = Count + 1}.

%%====================================================================
%% Queries
%%====================================================================

%% @doc Get all sent packets.
-spec sent_packets(loss_state()) -> #{non_neg_integer() => #sent_packet{}}.
sent_packets(#loss_state{sent_packets = S}) -> S.

%% @doc Get bytes currently in flight.
-spec bytes_in_flight(loss_state()) -> non_neg_integer().
bytes_in_flight(#loss_state{bytes_in_flight = B}) -> B.

%% @doc Get current PTO count.
-spec pto_count(loss_state()) -> non_neg_integer().
pto_count(#loss_state{pto_count = C}) -> C.

%% @doc Get the oldest unacked packet (for PTO probe selection).
%% Returns {ok, #sent_packet{}} or none.
-spec oldest_unacked(loss_state()) -> {ok, #sent_packet{}} | none.
oldest_unacked(#loss_state{oldest_unacked_pn = undefined}) ->
    none;
oldest_unacked(#loss_state{oldest_unacked_pn = PN, sent_packets = Sent}) ->
    case maps:get(PN, Sent, undefined) of
        undefined -> none;
        Packet -> {ok, Packet}
    end.

%% @doc Check if we have received a real RTT sample.
%% Returns false until the first ACK provides a real RTT measurement.
-spec has_rtt_sample(loss_state()) -> boolean().
has_rtt_sample(#loss_state{first_rtt_sample = HasSample}) -> HasSample.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Find the minimum packet number using pn_set.
%% O(log n) using gb_sets:smallest instead of O(n) maps:keys + lists:min.
find_oldest_pn_set(PNSet) ->
    case gb_sets:is_empty(PNSet) of
        true -> undefined;
        false -> gb_sets:smallest(PNSet)
    end.

%% Remove acknowledged packets using ranges with pn_set for O(k log n) lookup.
%% Uses the sorted pn_set to efficiently find packets in ACK ranges.
%% IMPORTANT: Only count ack-eliciting packet sizes in AccBytes since
%% bytes_in_flight only tracks ack-eliciting packets (RFC 9002).
%% Returns {AckedPackets, NewSent, NewPNSet, AckedBytes, MaxAckElicitingInfo}
%% where MaxAckElicitingInfo is {PN, TimeSent} for the largest ack-eliciting packet.
%%
%% Single range case (most common) - use iterator-based lookup
remove_acked_packets_ranges([{RangeStart, RangeEnd}], SentPackets, PNSet) ->
    %% Use pn_set iterator starting from RangeStart for efficiency
    {AckedPNs, AckedPackets, AckedBytes, MaxAckEliciting} =
        find_acked_in_range(RangeStart, RangeEnd, PNSet, SentPackets),
    NewSent = maps:without(AckedPNs, SentPackets),
    %% Use foldl with delete_any for O(k * log n) instead of O(n) subtract
    NewPNSet = lists:foldl(fun gb_sets:delete_any/2, PNSet, AckedPNs),
    {AckedPackets, NewSent, NewPNSet, AckedBytes, MaxAckEliciting};
%% Multi-range case - process each range
remove_acked_packets_ranges(AckedRanges, SentPackets, PNSet) ->
    %% Process each range and accumulate results
    {AckedPNs, AckedPackets, AckedBytes, MaxAckEliciting, _, _} =
        lists:foldl(
            fun ack_range_folder/2,
            {[], [], 0, undefined, PNSet, SentPackets},
            AckedRanges
        ),
    NewSent = maps:without(AckedPNs, SentPackets),
    %% Use foldl with delete_any for O(k * log n) instead of O(n) subtract
    NewPNSet = lists:foldl(fun gb_sets:delete_any/2, PNSet, AckedPNs),
    {AckedPackets, NewSent, NewPNSet, AckedBytes, MaxAckEliciting}.

%% Folder function for processing ACK ranges
ack_range_folder({RangeStart, RangeEnd}, {PNsAcc, PacketsAcc, BytesAcc, MaxAE, PNSet, SentPackets}) ->
    {RangePNs, RangePackets, RangeBytes, RangeMaxAE} =
        find_acked_in_range(RangeStart, RangeEnd, PNSet, SentPackets),
    NewMaxAE = merge_max_ae(MaxAE, RangeMaxAE),
    {
        RangePNs ++ PNsAcc,
        RangePackets ++ PacketsAcc,
        BytesAcc + RangeBytes,
        NewMaxAE,
        PNSet,
        SentPackets
    }.

%% Find all acked packets in a single range using pn_set iterator
find_acked_in_range(RangeStart, RangeEnd, PNSet, SentPackets) ->
    %% Get iterator starting from RangeStart
    Iter = gb_sets:iterator_from(RangeStart, PNSet),
    find_acked_iter(Iter, RangeEnd, SentPackets, [], [], 0, undefined).

find_acked_iter(Iter, RangeEnd, SentPackets, PNsAcc, PacketsAcc, BytesAcc, MaxAE) ->
    case gb_sets:next(Iter) of
        none ->
            {PNsAcc, PacketsAcc, BytesAcc, MaxAE};
        {PN, _NextIter} when PN > RangeEnd ->
            %% Past the range, done
            {PNsAcc, PacketsAcc, BytesAcc, MaxAE};
        {PN, NextIter} ->
            %% PN is in range [RangeStart, RangeEnd]
            case maps:get(PN, SentPackets, undefined) of
                #sent_packet{size = Size, ack_eliciting = AckEliciting, time_sent = TimeSent} =
                        Packet ->
                    {NewBytes, NewMaxAE} = update_acked_stats(
                        AckEliciting, Size, PN, TimeSent, BytesAcc, MaxAE
                    ),
                    find_acked_iter(
                        NextIter,
                        RangeEnd,
                        SentPackets,
                        [PN | PNsAcc],
                        [Packet | PacketsAcc],
                        NewBytes,
                        NewMaxAE
                    );
                undefined ->
                    %% PN in set but not in sent_packets (shouldn't happen, but handle it)
                    find_acked_iter(
                        NextIter,
                        RangeEnd,
                        SentPackets,
                        PNsAcc,
                        PacketsAcc,
                        BytesAcc,
                        MaxAE
                    )
            end
    end.

%% Merge max ack-eliciting info, keeping the larger PN
merge_max_ae(undefined, New) ->
    New;
merge_max_ae(Old, undefined) ->
    Old;
merge_max_ae({OldPN, _} = Old, {NewPN, _} = New) ->
    case NewPN > OldPN of
        true -> New;
        false -> Old
    end.

%% Update acked bytes and track largest ack-eliciting packet
update_acked_stats(true, Size, PN, TimeSent, BytesAcc, undefined) ->
    {BytesAcc + Size, {PN, TimeSent}};
update_acked_stats(true, Size, PN, TimeSent, BytesAcc, {OldPN, _}) when PN > OldPN ->
    {BytesAcc + Size, {PN, TimeSent}};
update_acked_stats(true, Size, _PN, _TimeSent, BytesAcc, MaxAE) ->
    {BytesAcc + Size, MaxAE};
update_acked_stats(false, _Size, _PN, _TimeSent, BytesAcc, MaxAE) ->
    {BytesAcc, MaxAE}.

%% Check if a packet number is in any of the acknowledged ranges.
%% Ranges is a list of {Start, End} tuples where Start =< End,
%% sorted in descending order (highest PN first).
pn_in_ranges(_PN, []) ->
    false;
pn_in_ranges(PN, [{Start, End} | _Rest]) when PN >= Start, PN =< End ->
    true;
pn_in_ranges(PN, [{_Start, End} | _Rest]) when PN > End ->
    %% Early exit: ranges are sorted descending, so if PN > End of current range,
    %% it can't be in any subsequent range (they all have lower End values)
    false;
pn_in_ranges(PN, [_Range | Rest]) ->
    pn_in_ranges(PN, Rest).

%% Convert encoded ACK delay to milliseconds
ack_delay_to_ms(AckDelay, #loss_state{}) ->
    %% AckDelay is in microseconds after shifting by ack_delay_exponent
    %% Using default exponent of 3
    (AckDelay bsl ?DEFAULT_ACK_DELAY_EXPONENT) div 1000.

%%====================================================================
%% Retransmission Helpers
%%====================================================================

%% @doc Filter frames to get only retransmittable ones.
%% Per RFC 9002, PADDING, ACK, and CONNECTION_CLOSE frames are not retransmitted.
-spec retransmittable_frames([term()]) -> [term()].
retransmittable_frames(Frames) ->
    lists:filter(fun is_retransmittable/1, Frames).

%% Check if a frame is retransmittable
is_retransmittable(padding) -> false;
is_retransmittable({padding, _}) -> false;
is_retransmittable({ack, _, _, _}) -> false;
is_retransmittable({ack, _, _, _, _}) -> false;
is_retransmittable({ack_ecn, _, _, _, _, _, _, _}) -> false;
is_retransmittable({connection_close, _, _, _, _}) -> false;
%% DATAGRAM frames (RFC 9221) are unreliable and never retransmitted
is_retransmittable({datagram, _}) -> false;
is_retransmittable({datagram_with_length, _}) -> false;
is_retransmittable(_) -> true.
