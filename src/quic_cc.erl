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

-include_lib("kernel/include/logger.hrl").
-define(QUIC_LOG_META, #{domain => [erlang_quic, congestion_control]}).

-export([
    %% State management
    new/0,
    new/1,

    %% Congestion control events
    on_packet_sent/2,
    on_packets_acked/2,
    %% With LargestAckedSentTime for proper recovery exit
    on_packets_acked/3,
    on_packets_lost/2,
    on_congestion_event/2,

    %% ECN support (RFC 9002 Section 7.1)
    on_ecn_ce/2,
    ecn_ce_counter/1,

    %% Persistent congestion (RFC 9002 Section 7.6)
    detect_persistent_congestion/3,
    on_persistent_congestion/1,

    %% Pacing (RFC 9002 Section 7.7)
    update_pacing_rate/2,
    pacing_allows/2,
    get_pacing_tokens/2,
    pacing_delay/2,

    %% Queries
    cwnd/1,
    ssthresh/1,
    bytes_in_flight/1,
    can_send/2,
    can_send_control/2,
    available_cwnd/1,

    %% State inspection
    in_slow_start/1,
    in_recovery/1,
    min_recovery_duration/1
]).

%% Constants from RFC 9002

% Minimum QUIC packet size
-define(MAX_DATAGRAM_SIZE, 1200).
% Initial cwnd: 32 packets like quic-go for better initial throughput
% RFC 9002 suggests min(10*mds, max(14720, 2*mds)) but larger is common
-define(INITIAL_WINDOW, 38400).
% Loss reduction factor: 0.7 like quic-go for less aggressive backoff
% Standard NewReno uses 0.5, but 0.7 gives better throughput recovery
-define(LOSS_REDUCTION_FACTOR, 0.7).
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
    minimum_window :: non_neg_integer(),
    max_datagram_size :: non_neg_integer(),

    %% Minimum time to stay in recovery (ms)
    %% Prevents rapid re-entry on low-latency networks
    min_recovery_duration = 100 :: non_neg_integer(),

    %% Control message allowance (bytes) - allows critical small messages
    %% to exceed cwnd by this amount to prevent blocking ticks
    control_allowance = 1200 :: non_neg_integer(),

    %% Pacing state (RFC 9002 Section 7.7)
    %% Pacing prevents bursts by spacing out packet sends

    % bytes/ms
    pacing_rate = 0 :: non_neg_integer(),
    % available tokens (bytes)
    pacing_tokens = 0 :: non_neg_integer(),
    % 12 packets burst allowance
    pacing_max_burst = 14400 :: non_neg_integer(),
    % timestamp (ms)
    last_pacing_update = 0 :: non_neg_integer()
}).

-opaque cc_state() :: #cc_state{}.
-export_type([cc_state/0]).

%% CC options type for external implementations
%% Exported for construction by callers.
-type cc_opts() :: #{
    initial_window => pos_integer(),
    minimum_window => pos_integer(),
    min_recovery_duration => non_neg_integer(),
    max_datagram_size => pos_integer()
}.
-export_type([cc_opts/0]).

%%====================================================================
%% State Management
%%====================================================================

%% @doc Create a new congestion control state.
-spec new() -> cc_state().
new() ->
    new(#{}).

%% @doc Create a new congestion control state with options.
%% Options:
%%   - max_datagram_size: Maximum datagram size (default: 1200)
%%   - initial_window: Override initial congestion window (default: RFC 9002 formula)
%%                     Higher values can improve throughput for bulk transfers.
%%                     Recommended: 32768 (32KB) or 65536 (64KB) for LAN/distribution.
%%   - minimum_window: Lower bound for cwnd after congestion events
%%                     (default: 2 * max_datagram_size per RFC 9002).
%%   - min_recovery_duration: Minimum time in recovery before exit (ms, default: 100)
%%                            Prevents rapid cwnd oscillations on low-latency networks.
-spec new(cc_opts()) -> cc_state().
new(Opts) ->
    MaxDatagramSize = maps:get(max_datagram_size, Opts, ?MAX_DATAGRAM_SIZE),
    DefaultWindow = initial_window(MaxDatagramSize),
    DefaultMinimumWindow = minimum_window(MaxDatagramSize),
    ConfiguredMinimumWindow =
        case maps:find(minimum_window, Opts) of
            {ok, Value} when is_integer(Value), Value > 0 ->
                max(Value, DefaultMinimumWindow);
            _ ->
                DefaultMinimumWindow
        end,
    InitialWindow0 = maps:get(initial_window, Opts, DefaultWindow),
    InitialWindow = max(InitialWindow0, ConfiguredMinimumWindow),
    MinRecoveryDuration = maps:get(min_recovery_duration, Opts, 100),
    %% Pacing: 10 packets burst allowance (12 with 1200 byte packets = 14400)
    PacingMaxBurst = 12 * MaxDatagramSize,
    Now = erlang:monotonic_time(millisecond),
    ?LOG_DEBUG(
        #{
            what => cc_state_initialized,
            initial_cwnd => InitialWindow,
            default_cwnd => DefaultWindow,
            minimum_window => ConfiguredMinimumWindow,
            default_minimum_window => DefaultMinimumWindow,
            max_datagram_size => MaxDatagramSize,
            min_recovery_duration => MinRecoveryDuration,
            pacing_max_burst => PacingMaxBurst
        },
        ?QUIC_LOG_META
    ),
    #cc_state{
        cwnd = InitialWindow,
        ssthresh = infinity,
        minimum_window = ConfiguredMinimumWindow,
        max_datagram_size = MaxDatagramSize,
        min_recovery_duration = MinRecoveryDuration,
        %% Initialize pacing with full burst allowance
        pacing_max_burst = PacingMaxBurst,
        pacing_tokens = PacingMaxBurst,
        last_pacing_update = Now
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
%% LargestAckedSentTime is the time when the largest acknowledged packet was sent.
%% RFC 9002: Exit recovery when the largest acked packet was sent after recovery started.
-spec on_packets_acked(cc_state(), non_neg_integer()) -> cc_state().
on_packets_acked(State, AckedBytes) ->
    %% Use current time as a proxy - ideally caller would pass largest_acked_sent_time
    Now = erlang:monotonic_time(millisecond),
    on_packets_acked(State, AckedBytes, Now).

%% @doc Process acknowledged packets.
%% RFC 9002: Exit recovery when the largest acked packet was sent after recovery started.
%% Extended: Also requires minimum recovery duration to pass before exiting.
-spec on_packets_acked(cc_state(), non_neg_integer(), non_neg_integer()) -> cc_state().
on_packets_acked(
    #cc_state{
        bytes_in_flight = InFlight,
        cwnd = OldCwnd,
        in_recovery = true,
        recovery_start_time = RecoveryStart,
        min_recovery_duration = MinDuration
    } = State,
    AckedBytes,
    LargestAckedSentTime
) ->
    NewInFlight = max(0, InFlight - AckedBytes),
    Now = erlang:monotonic_time(millisecond),
    RecoveryDuration = Now - RecoveryStart,

    %% RFC 9002 Section 7.3.2: A recovery period ends and the sender
    %% enters congestion avoidance when a packet sent during the recovery period
    %% is acknowledged. Check if the largest acked packet was sent AFTER recovery started.
    %% Extended: Also requires minimum recovery duration to pass before exiting.
    %% This prevents rapid cwnd oscillations on low-latency networks.
    case
        RecoveryDuration >= MinDuration andalso
            (LargestAckedSentTime > RecoveryStart orelse NewInFlight =:= 0)
    of
        true ->
            %% Exit recovery - packet sent after recovery started was acked
            %% and minimum recovery duration has passed
            %% Now in congestion avoidance, can increase cwnd
            #cc_state{cwnd = Cwnd, ssthresh = SSThresh, max_datagram_size = MaxDS} = State,
            NewCwnd =
                case Cwnd < SSThresh of
                    true ->
                        Cwnd + AckedBytes;
                    false ->
                        Increment = (MaxDS * AckedBytes) div max(Cwnd, 1),
                        Cwnd + max(Increment, 1)
                end,
            ?LOG_DEBUG(
                #{
                    what => cc_ack_exit_recovery,
                    acked_bytes => AckedBytes,
                    old_cwnd => OldCwnd,
                    new_cwnd => NewCwnd,
                    old_in_flight => InFlight,
                    new_in_flight => NewInFlight,
                    ssthresh => SSThresh,
                    recovery_duration => RecoveryDuration
                },
                ?QUIC_LOG_META
            ),
            %% Update recovery_start_time to current time when exiting recovery.
            %% This prevents re-entering recovery for packets sent during
            %% the recovery period that are still in flight.
            State#cc_state{
                bytes_in_flight = NewInFlight,
                in_recovery = false,
                recovery_start_time = Now,
                cwnd = NewCwnd
            };
        false ->
            %% Still in recovery, don't increase cwnd
            ?LOG_DEBUG(
                #{
                    what => cc_ack_in_recovery,
                    acked_bytes => AckedBytes,
                    cwnd => OldCwnd,
                    old_in_flight => InFlight,
                    new_in_flight => NewInFlight,
                    recovery_duration => RecoveryDuration,
                    min_duration => MinDuration
                },
                ?QUIC_LOG_META
            ),
            State#cc_state{bytes_in_flight = NewInFlight}
    end;
on_packets_acked(
    #cc_state{
        cwnd = Cwnd,
        ssthresh = SSThresh,
        bytes_in_flight = InFlight,
        max_datagram_size = MaxDS
    } = State,
    AckedBytes,
    _LargestAckedSentTime
) ->
    NewInFlight = max(0, InFlight - AckedBytes),

    %% Increase cwnd based on phase
    InSlowStart = Cwnd < SSThresh,
    NewCwnd =
        case InSlowStart of
            true ->
                %% Slow start: increase by bytes acked
                Cwnd + AckedBytes;
            false ->
                %% Congestion avoidance: increase by ~1 MSS per RTT
                %% cwnd += max_datagram_size * acked_bytes / cwnd
                Increment = (MaxDS * AckedBytes) div max(Cwnd, 1),
                Cwnd + max(Increment, 1)
        end,

    ?LOG_DEBUG(
        #{
            what => cc_ack_processed,
            acked_bytes => AckedBytes,
            old_cwnd => Cwnd,
            new_cwnd => NewCwnd,
            old_in_flight => InFlight,
            new_in_flight => NewInFlight,
            ssthresh => SSThresh,
            slow_start => InSlowStart
        },
        ?QUIC_LOG_META
    ),

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
    %% Already in recovery for this event - skip
    ?LOG_DEBUG(
        #{
            what => cc_congestion_skipped_in_recovery,
            sent_time => SentTime,
            recovery_start_time => RecoveryStart
        },
        ?QUIC_LOG_META
    ),
    State;
on_congestion_event(
    #cc_state{
        in_recovery = true,
        recovery_start_time = RecoveryStart,
        min_recovery_duration = MinDuration
    } = State,
    SentTime
) ->
    %% Already in recovery - check if min_recovery_duration has passed
    Now = erlang:monotonic_time(millisecond),
    RecoveryDuration = Now - RecoveryStart,
    case RecoveryDuration < MinDuration of
        true ->
            %% Still within protected recovery period - don't reset recovery
            ?LOG_DEBUG(
                #{
                    what => cc_congestion_skipped_protected_recovery,
                    sent_time => SentTime,
                    recovery_start_time => RecoveryStart,
                    recovery_duration => RecoveryDuration,
                    min_duration => MinDuration
                },
                ?QUIC_LOG_META
            ),
            State;
        false ->
            %% min_recovery_duration passed but packet sent after recovery started was lost
            %% Allow this to reset recovery (fall through to general clause)
            do_congestion_event(State, SentTime)
    end;
on_congestion_event(
    #cc_state{
        in_recovery = false,
        recovery_start_time = RecoveryStart
    } = State,
    SentTime
) when is_integer(RecoveryStart), SentTime =< RecoveryStart ->
    %% Packet was sent before the last recovery period ended.
    %% Don't re-enter recovery for old packets.
    ?LOG_DEBUG(
        #{
            what => cc_congestion_skipped_post_recovery,
            sent_time => SentTime,
            recovery_start_time => RecoveryStart
        },
        ?QUIC_LOG_META
    ),
    State;
on_congestion_event(State, SentTime) ->
    do_congestion_event(State, SentTime).

%% @private Helper to execute the congestion event logic.
do_congestion_event(
    #cc_state{
        cwnd = Cwnd,
        bytes_in_flight = InFlight,
        minimum_window = MinimumWindow,
        in_recovery = InRecovery,
        recovery_start_time = OldRecoveryStart
    } = State,
    SentTime
) ->
    Now = erlang:monotonic_time(millisecond),

    %% Enter recovery
    %% ssthresh = cwnd * kLossReductionFactor
    %% cwnd = max(ssthresh, kMinimumWindow)
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), MinimumWindow),
    NewCwnd = max(NewSSThresh, MinimumWindow),

    ?LOG_DEBUG(
        #{
            what => cc_congestion_event,
            old_cwnd => Cwnd,
            new_cwnd => NewCwnd,
            ssthresh => NewSSThresh,
            bytes_in_flight => InFlight,
            sent_time => SentTime,
            old_in_recovery => InRecovery,
            old_recovery_start => OldRecoveryStart,
            new_recovery_start => Now
        },
        ?QUIC_LOG_META
    ),

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
on_ecn_ce(#cc_state{cwnd = Cwnd, minimum_window = MinimumWindow} = State, NewCECount) ->
    %% RFC 9002: ECN-CE triggers the same response as packet loss
    %% Enter recovery: ssthresh = cwnd * kLossReductionFactor
    Now = erlang:monotonic_time(millisecond),
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), MinimumWindow),
    NewCwnd = max(NewSSThresh, MinimumWindow),

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

%% @doc Check if a control message can be sent.
%% Control messages (ticks, ACKs) can exceed cwnd by control_allowance
%% to prevent net_tick_timeout in distribution.
%% RFC 9002 recommends allowing at least one packet for progress.
-spec can_send_control(cc_state(), non_neg_integer()) -> boolean().
can_send_control(
    #cc_state{cwnd = Cwnd, bytes_in_flight = InFlight, control_allowance = Allowance}, Size
) ->
    InFlight + Size =< Cwnd + Allowance.

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

%% @doc Get minimum recovery duration setting.
%% External CC implementations can use this to tune recovery behavior.
-spec min_recovery_duration(cc_state()) -> non_neg_integer().
min_recovery_duration(#cc_state{min_recovery_duration = D}) -> D.

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
on_persistent_congestion(#cc_state{cwnd = Cwnd, minimum_window = MinimumWindow} = State) ->
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), MinimumWindow),
    State#cc_state{
        cwnd = MinimumWindow,
        ssthresh = NewSSThresh,
        in_recovery = false,
        recovery_start_time = undefined,
        first_sent_time = undefined
    }.

%%====================================================================
%% Pacing (RFC 9002 Section 7.7)
%%====================================================================

%% @doc Update pacing rate based on smoothed RTT and cwnd.
%% RFC 9002: pacing_rate = cwnd / smoothed_rtt
%% Called when RTT estimate is updated.
-spec update_pacing_rate(cc_state(), non_neg_integer()) -> cc_state().
update_pacing_rate(#cc_state{cwnd = Cwnd} = State, SmoothedRTT) when SmoothedRTT > 0 ->
    %% pacing_rate = cwnd / smoothed_rtt (bytes/ms)
    %% Multiply by 1.25 to allow slightly faster than cwnd/RTT for efficiency
    PacingRate = max(1, (Cwnd * 5) div (SmoothedRTT * 4)),
    State#cc_state{pacing_rate = PacingRate};
update_pacing_rate(State, _SmoothedRTT) ->
    %% No valid RTT yet, keep current state
    State.

%% @doc Check if pacing allows sending Size bytes.
%% Returns true if enough tokens are available (including burst allowance).
-spec pacing_allows(cc_state(), non_neg_integer()) -> boolean().
pacing_allows(#cc_state{pacing_rate = 0}, _Size) ->
    %% Pacing not initialized yet - allow sending
    true;
pacing_allows(
    #cc_state{
        pacing_tokens = Tokens,
        pacing_max_burst = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    },
    Size
) ->
    %% Refill tokens first, then check
    Now = erlang:monotonic_time(millisecond),
    RefreshedTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    RefreshedTokens >= Size.

%% @doc Get tokens for sending, consuming them and returning updated state.
%% Returns {AllowedBytes, UpdatedState} where AllowedBytes <= Size.
-spec get_pacing_tokens(cc_state(), non_neg_integer()) -> {non_neg_integer(), cc_state()}.
get_pacing_tokens(#cc_state{pacing_rate = 0} = State, Size) ->
    %% Pacing not initialized - allow full send
    {Size, State};
get_pacing_tokens(
    #cc_state{
        pacing_tokens = Tokens,
        pacing_max_burst = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    } = State,
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    %% Refill tokens based on elapsed time
    NewTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    %% Consume up to available tokens
    Allowed = min(Size, NewTokens),
    RemainingTokens = max(0, NewTokens - Allowed),
    NewState = State#cc_state{
        pacing_tokens = RemainingTokens,
        last_pacing_update = Now
    },
    {Allowed, NewState}.

%% @doc Calculate delay (in ms) until Size bytes can be sent.
%% Returns 0 if sending is allowed immediately.
-spec pacing_delay(cc_state(), non_neg_integer()) -> non_neg_integer().
pacing_delay(#cc_state{pacing_rate = 0}, _Size) ->
    %% Pacing not initialized - no delay
    0;
pacing_delay(
    #cc_state{
        pacing_tokens = Tokens,
        pacing_max_burst = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    },
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    %% Calculate current tokens
    CurrentTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    case CurrentTokens >= Size of
        true ->
            0;
        false ->
            %% Calculate time needed to accumulate enough tokens
            Deficit = Size - CurrentTokens,
            %% Time = bytes / (bytes/ms) = ms
            max(1, (Deficit + Rate - 1) div Rate)
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

%% Refill pacing tokens based on elapsed time
refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now) ->
    Elapsed = max(0, Now - LastUpdate),
    Added = Elapsed * Rate,
    min(MaxBurst, Tokens + Added).

%% Calculate initial window
%% Use 32 packets like quic-go for better initial throughput
%% RFC 9002 suggests min(10*mds, max(14720, 2*mds)) but larger is common in practice
initial_window(MaxDatagramSize) ->
    32 * MaxDatagramSize.

%% Calculate minimum window
%% kMinimumWindow = 2 * max_datagram_size
minimum_window(MaxDatagramSize) ->
    2 * MaxDatagramSize.
