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
    pto_count/1
]).

%% Constants from RFC 9002
-define(PACKET_THRESHOLD, 3).
% 9/8
-define(TIME_THRESHOLD, 1.125).
% 1 millisecond
-define(GRANULARITY, 1).
% 333 milliseconds
-define(INITIAL_RTT, 333).

%% Loss detection state
-record(loss_state, {
    %% Sent packets: #{PN => #sent_packet{}}
    sent_packets = #{} :: #{non_neg_integer() => #sent_packet{}},

    %% RTT estimation
    latest_rtt = 0 :: non_neg_integer(),
    smoothed_rtt = ?INITIAL_RTT :: non_neg_integer(),
    rtt_var = ?INITIAL_RTT div 2 :: non_neg_integer(),
    min_rtt = infinity :: non_neg_integer() | infinity,
    first_rtt_sample = false :: boolean(),

    %% Loss detection
    loss_time = undefined :: non_neg_integer() | undefined,
    time_of_last_ack = undefined :: non_neg_integer() | undefined,

    %% PTO
    pto_count = 0 :: non_neg_integer(),

    %% Bytes in flight
    bytes_in_flight = 0 :: non_neg_integer(),

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
-spec new(map()) -> loss_state().
new(Opts) ->
    #loss_state{
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
    #loss_state{sent_packets = Sent, bytes_in_flight = InFlight} = State,
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
    State#loss_state{
        sent_packets = maps:put(PacketNumber, SentPacket, Sent),
        bytes_in_flight = NewInFlight,
        % Reset PTO count on new packet
        pto_count = 0
    }.

%% @doc Process an ACK frame.
%% Returns {NewState, AckedPackets, LostPackets} or {error, ack_range_too_large}
-spec on_ack_received(loss_state(), term(), non_neg_integer()) ->
    {loss_state(), [#sent_packet{}], [#sent_packet{}]} | {error, ack_range_too_large}.
on_ack_received(State, {ack, LargestAcked, AckDelay, FirstRange, AckRanges}, Now) ->
    %% Get list of acknowledged packet numbers (use quic_ack for bounds-checked version)
    case quic_ack:ack_frame_to_pn_list(LargestAcked, FirstRange, AckRanges) of
        {error, _} = Error ->
            Error;
        AckedPNs ->
            %% Find packets that were acknowledged
            {AckedPackets, NewSent, RemovedBytes} = remove_acked_packets(
                AckedPNs, State#loss_state.sent_packets
            ),

            %% Update RTT if we got the largest acknowledged
            NewState1 =
                case lists:member(LargestAcked, AckedPNs) of
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
            {LostPackets, NewSent2, LostBytes} = detect_lost_packets(
                NewSent, NewState1#loss_state.smoothed_rtt, LargestAcked, Now
            ),

            %% Update state
            NewInFlight = max(0, State#loss_state.bytes_in_flight - RemovedBytes - LostBytes),
            NewState2 = NewState1#loss_state{
                sent_packets = NewSent2,
                bytes_in_flight = NewInFlight,
                time_of_last_ack = Now,
                pto_count = 0
            },

            {NewState2, AckedPackets, LostPackets}
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
    #loss_state{sent_packets = Sent, smoothed_rtt = SRTT} = State,
    LargestAcked
) ->
    Now = erlang:monotonic_time(millisecond),
    {LostPackets, NewSent, LostBytes} = detect_lost_packets(Sent, SRTT, LargestAcked, Now),
    NewState = State#loss_state{
        sent_packets = NewSent,
        bytes_in_flight = max(0, State#loss_state.bytes_in_flight - LostBytes)
    },
    {NewState, LostPackets}.

%% Internal loss detection
detect_lost_packets(SentPackets, SmoothedRTT, LargestAcked, Now) ->
    %% Calculate loss delay
    LossDelay = max(trunc(?TIME_THRESHOLD * SmoothedRTT), ?GRANULARITY),

    %% Find lost packets
    {Lost, Remaining, LostBytes} = maps:fold(
        fun
            (
                PN,
                #sent_packet{time_sent = TimeSent, size = Size, in_flight = true} = Packet,
                {LostAcc, RemAcc, BytesAcc}
            ) ->
                %% Check packet threshold
                PacketLost = (LargestAcked - PN) >= ?PACKET_THRESHOLD,
                %% Check time threshold
                TimeLost = (Now - TimeSent) > LossDelay,

                case PacketLost orelse TimeLost of
                    true ->
                        {[Packet | LostAcc], RemAcc, BytesAcc + Size};
                    false ->
                        {LostAcc, maps:put(PN, Packet, RemAcc), BytesAcc}
                end;
            (PN, Packet, {LostAcc, RemAcc, BytesAcc}) ->
                {LostAcc, maps:put(PN, Packet, RemAcc), BytesAcc}
        end,
        {[], #{}, 0},
        SentPackets
    ),

    {Lost, Remaining, LostBytes}.

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

%%====================================================================
%% Internal Functions
%%====================================================================

%% Remove acknowledged packets from sent map
remove_acked_packets(AckedPNs, SentPackets) ->
    lists:foldl(
        fun(PN, {AccPackets, AccSent, AccBytes}) ->
            case maps:take(PN, AccSent) of
                {#sent_packet{size = Size} = Packet, NewSent} ->
                    {[Packet | AccPackets], NewSent, AccBytes + Size};
                error ->
                    {AccPackets, AccSent, AccBytes}
            end
        end,
        {[], SentPackets, 0},
        AckedPNs
    ).

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
