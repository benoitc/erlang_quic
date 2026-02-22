%%% -*- erlang -*-
%%%
%%% QUIC Congestion Control (NewReno)
%%% RFC 9002 Section 7 - Congestion Control
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC NewReno congestion control implementation.
%%%
%%% This module implements the NewReno congestion control algorithm:
%%% - Slow Start: Exponential growth until threshold or loss
%%% - Congestion Avoidance: Linear growth after threshold
%%% - Recovery: Multiplicative decrease on loss
%%% - Persistent Congestion: Reset on prolonged loss
%%%
%%% == Phases ==
%%%
%%% 1. Slow Start: cwnd += bytes_acked (exponential growth)
%%% 2. Congestion Avoidance: cwnd += max_datagram_size * bytes_acked / cwnd
%%% 3. Recovery: ssthresh = cwnd * 0.5, cwnd = max(ssthresh, min_window)
%%%

-module(quic_cc).

-export([
    %% State management
    new/0,
    new/1,

    %% Congestion control events
    on_packet_sent/2,
    on_packets_acked/2,
    on_packets_lost/2,
    on_congestion_event/2,

    %% ECN support (RFC 9002 Section 7.1)
    on_ecn_ce/2,
    ecn_ce_counter/1,

    %% Persistent congestion (RFC 9002 Section 7.6)
    detect_persistent_congestion/3,
    on_persistent_congestion/1,

    %% Queries
    cwnd/1,
    ssthresh/1,
    bytes_in_flight/1,
    can_send/2,
    available_cwnd/1,

    %% State inspection
    in_slow_start/1,
    in_recovery/1
]).

%% Constants from RFC 9002

% Minimum QUIC packet size
-define(MAX_DATAGRAM_SIZE, 1200).
% 10 * 1472 or similar
-define(INITIAL_WINDOW, 14720).
% 2 * MAX_DATAGRAM_SIZE
-define(MINIMUM_WINDOW, 2400).
-define(LOSS_REDUCTION_FACTOR, 0.5).
-define(PERSISTENT_CONGESTION_THRESHOLD, 3).

%% Congestion control state
-record(cc_state, {
    %% Congestion window
    cwnd :: non_neg_integer(),
    ssthresh :: non_neg_integer() | infinity,

    %% Bytes tracking
    bytes_in_flight = 0 :: non_neg_integer(),

    %% Recovery state
    recovery_start_time :: non_neg_integer() | undefined,
    in_recovery = false :: boolean(),

    %% Persistent congestion detection
    first_sent_time :: non_neg_integer() | undefined,

    %% ECN state (RFC 9002 Section 7.1)
    %% Tracks the highest ECN-CE count acknowledged
    ecn_ce_counter = 0 :: non_neg_integer(),

    %% Configuration
    max_datagram_size :: non_neg_integer()
}).

-opaque cc_state() :: #cc_state{}.
-export_type([cc_state/0]).

%%====================================================================
%% State Management
%%====================================================================

%% @doc Create a new congestion control state.
-spec new() -> cc_state().
new() ->
    new(#{}).

%% @doc Create a new congestion control state with options.
-spec new(map()) -> cc_state().
new(Opts) ->
    MaxDatagramSize = maps:get(max_datagram_size, Opts, ?MAX_DATAGRAM_SIZE),
    InitialWindow = initial_window(MaxDatagramSize),
    #cc_state{
        cwnd = InitialWindow,
        ssthresh = infinity,
        max_datagram_size = MaxDatagramSize
    }.

%%====================================================================
%% Congestion Control Events
%%====================================================================

%% @doc Record that a packet was sent.
-spec on_packet_sent(cc_state(), non_neg_integer()) -> cc_state().
on_packet_sent(
    #cc_state{
        bytes_in_flight = InFlight,
        first_sent_time = undefined
    } = State,
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    State#cc_state{
        bytes_in_flight = InFlight + Size,
        first_sent_time = Now
    };
on_packet_sent(#cc_state{bytes_in_flight = InFlight} = State, Size) ->
    State#cc_state{bytes_in_flight = InFlight + Size}.

%% @doc Process acknowledged packets.
%% AckedBytes is the total size of acknowledged packets.
-spec on_packets_acked(cc_state(), non_neg_integer()) -> cc_state().
on_packets_acked(
    #cc_state{bytes_in_flight = InFlight, in_recovery = true} = State,
    AckedBytes
) ->
    %% In recovery, don't increase cwnd
    State#cc_state{bytes_in_flight = max(0, InFlight - AckedBytes)};
on_packets_acked(
    #cc_state{
        cwnd = Cwnd,
        ssthresh = SSThresh,
        bytes_in_flight = InFlight,
        max_datagram_size = MaxDS
    } = State,
    AckedBytes
) ->
    NewInFlight = max(0, InFlight - AckedBytes),

    %% Increase cwnd based on phase
    NewCwnd =
        case Cwnd < SSThresh of
            true ->
                %% Slow start: increase by bytes acked
                Cwnd + AckedBytes;
            false ->
                %% Congestion avoidance: increase by ~1 MSS per RTT
                %% cwnd += max_datagram_size * acked_bytes / cwnd
                Increment = (MaxDS * AckedBytes) div max(Cwnd, 1),
                Cwnd + max(Increment, 1)
        end,

    State#cc_state{
        cwnd = NewCwnd,
        bytes_in_flight = NewInFlight
    }.

%% @doc Process lost packets.
%% LostBytes is the total size of lost packets.
-spec on_packets_lost(cc_state(), non_neg_integer()) -> cc_state().
on_packets_lost(#cc_state{bytes_in_flight = InFlight} = State, LostBytes) ->
    NewInFlight = max(0, InFlight - LostBytes),
    State#cc_state{bytes_in_flight = NewInFlight}.

%% @doc Handle a congestion event (packet loss detected).
%% SentTime is the time when the lost packet was sent.
-spec on_congestion_event(cc_state(), non_neg_integer()) -> cc_state().
on_congestion_event(
    #cc_state{
        in_recovery = true,
        recovery_start_time = RecoveryStart
    } = State,
    SentTime
) when SentTime =< RecoveryStart ->
    %% Already in recovery for this event
    State;
on_congestion_event(
    #cc_state{cwnd = Cwnd, max_datagram_size = MaxDS} = State,
    SentTime
) ->
    Now = erlang:monotonic_time(millisecond),

    %% Enter recovery
    %% ssthresh = cwnd * kLossReductionFactor
    %% cwnd = max(ssthresh, kMinimumWindow)
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), minimum_window(MaxDS)),
    NewCwnd = max(NewSSThresh, minimum_window(MaxDS)),

    State#cc_state{
        cwnd = NewCwnd,
        ssthresh = NewSSThresh,
        recovery_start_time = Now,
        in_recovery = true,
        % Track for persistent congestion
        first_sent_time = SentTime
    }.

%%====================================================================
%% ECN Support (RFC 9002 Section 7.1)
%%====================================================================

%% @doc Handle ECN-CE (Congestion Experienced) signal from ACK.
%% RFC 9002: An increase in ECN-CE count is treated as a congestion signal.
%% NewCECount is the ECN-CE count from the received ACK frame.
%% SentTime is the time when the largest acknowledged packet was sent.
-spec on_ecn_ce(cc_state(), non_neg_integer()) -> cc_state().
on_ecn_ce(#cc_state{ecn_ce_counter = OldCount} = State, NewCECount) when
    NewCECount =< OldCount
->
    %% No new CE marks, no action needed
    State;
on_ecn_ce(#cc_state{in_recovery = true, ecn_ce_counter = OldCount} = State, NewCECount) when
    NewCECount > OldCount
->
    %% Already in recovery, just update counter
    State#cc_state{ecn_ce_counter = NewCECount};
on_ecn_ce(#cc_state{cwnd = Cwnd, max_datagram_size = MaxDS} = State, NewCECount) ->
    %% RFC 9002: ECN-CE triggers the same response as packet loss
    %% Enter recovery: ssthresh = cwnd * kLossReductionFactor
    Now = erlang:monotonic_time(millisecond),
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), minimum_window(MaxDS)),
    NewCwnd = max(NewSSThresh, minimum_window(MaxDS)),

    State#cc_state{
        cwnd = NewCwnd,
        ssthresh = NewSSThresh,
        recovery_start_time = Now,
        in_recovery = true,
        ecn_ce_counter = NewCECount
    }.

%% @doc Get the current ECN-CE counter.
-spec ecn_ce_counter(cc_state()) -> non_neg_integer().
ecn_ce_counter(#cc_state{ecn_ce_counter = C}) -> C.

%%====================================================================
%% Queries
%%====================================================================

%% @doc Get the current congestion window.
-spec cwnd(cc_state()) -> non_neg_integer().
cwnd(#cc_state{cwnd = Cwnd}) -> Cwnd.

%% @doc Get the slow start threshold.
-spec ssthresh(cc_state()) -> non_neg_integer() | infinity.
ssthresh(#cc_state{ssthresh = SST}) -> SST.

%% @doc Get bytes currently in flight.
-spec bytes_in_flight(cc_state()) -> non_neg_integer().
bytes_in_flight(#cc_state{bytes_in_flight = B}) -> B.

%% @doc Check if we can send more bytes.
-spec can_send(cc_state(), non_neg_integer()) -> boolean().
can_send(#cc_state{cwnd = Cwnd, bytes_in_flight = InFlight}, Size) ->
    InFlight + Size =< Cwnd.

%% @doc Get the available congestion window (cwnd - bytes_in_flight).
-spec available_cwnd(cc_state()) -> non_neg_integer().
available_cwnd(#cc_state{cwnd = Cwnd, bytes_in_flight = InFlight}) ->
    max(0, Cwnd - InFlight).

%% @doc Check if in slow start phase.
-spec in_slow_start(cc_state()) -> boolean().
in_slow_start(#cc_state{cwnd = Cwnd, ssthresh = SSThresh}) ->
    Cwnd < SSThresh.

%% @doc Check if in recovery phase.
-spec in_recovery(cc_state()) -> boolean().
in_recovery(#cc_state{in_recovery = R}) -> R.

%%====================================================================
%% Persistent Congestion (RFC 9002 Section 7.6)
%%====================================================================

%% @doc Detect persistent congestion from lost packets.
%% Returns true if lost packets span more than PTO * kPersistentCongestionThreshold.
%% LostPackets is a list of {PacketNumber, TimeSent} tuples.
-spec detect_persistent_congestion(
    [{non_neg_integer(), non_neg_integer()}],
    non_neg_integer(),
    cc_state()
) -> boolean().
detect_persistent_congestion([], _PTO, _State) ->
    false;
detect_persistent_congestion([_], _PTO, _State) ->
    %% Need at least 2 packets to establish a time span
    false;
detect_persistent_congestion(LostPackets, PTO, _State) ->
    Times = [T || {_PN, T} <- LostPackets],
    MinTime = lists:min(Times),
    MaxTime = lists:max(Times),
    CongestionPeriod = PTO * ?PERSISTENT_CONGESTION_THRESHOLD,
    (MaxTime - MinTime) >= CongestionPeriod.

%% @doc Reset to minimum window on persistent congestion (RFC 9002 §7.6.2).
%% This is a severe response to prolonged packet loss.
-spec on_persistent_congestion(cc_state()) -> cc_state().
on_persistent_congestion(#cc_state{cwnd = Cwnd, max_datagram_size = MaxDS} = State) ->
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), ?MINIMUM_WINDOW),
    State#cc_state{
        cwnd = minimum_window(MaxDS),
        ssthresh = NewSSThresh,
        in_recovery = false,
        recovery_start_time = undefined,
        first_sent_time = undefined
    }.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Calculate initial window
%% kInitialWindow = min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
initial_window(MaxDatagramSize) ->
    min(10 * MaxDatagramSize, max(14720, 2 * MaxDatagramSize)).

%% Calculate minimum window
%% kMinimumWindow = 2 * max_datagram_size
minimum_window(MaxDatagramSize) ->
    2 * MaxDatagramSize.
