%%% -*- erlang -*-
%%%
%%% QUIC NewReno Congestion Control Implementation
%%% RFC 9002 Section 7 - Congestion Control
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc NewReno congestion control algorithm for QUIC.
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

-module(quic_cc_newreno).
-behaviour(quic_cc).

-include_lib("kernel/include/logger.hrl").
-define(QUIC_LOG_META, #{domain => [erlang_quic, congestion_control, newreno]}).

-export([
    %% Behavior callbacks
    new/1,
    on_packet_sent/2,
    on_packets_acked/3,
    on_packets_lost/2,
    on_congestion_event/2,
    on_rtt_update/3,
    cwnd/1,
    pacing_rate/1,
    bytes_in_flight/1,
    can_send/2,

    %% Extended API (NewReno-specific)
    ssthresh/1,
    can_send_control/2,
    available_cwnd/1,
    in_slow_start/1,
    in_recovery/1,
    min_recovery_duration/1,

    %% ECN support
    on_ecn_ce/2,
    ecn_ce_counter/1,

    %% Persistent congestion
    detect_persistent_congestion/3,
    on_persistent_congestion/1,

    %% Pacing
    update_pacing_rate/2,
    pacing_allows/2,
    get_pacing_tokens/2,
    pacing_delay/2
]).

%% Constants from RFC 9002
-define(MAX_DATAGRAM_SIZE, 1200).
%% Initial cwnd: 32 packets like quic-go for better initial throughput
-define(INITIAL_WINDOW, 38400).
%% Loss reduction factor: 0.7 like quic-go for less aggressive backoff
-define(LOSS_REDUCTION_FACTOR, 0.7).
-define(PERSISTENT_CONGESTION_THRESHOLD, 3).

%% Congestion control state
-record(newreno_state, {
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

    %% ECN state
    ecn_ce_counter = 0 :: non_neg_integer(),

    %% Configuration
    minimum_window :: non_neg_integer(),
    max_datagram_size :: non_neg_integer(),
    min_recovery_duration = 100 :: non_neg_integer(),
    control_allowance = 1200 :: non_neg_integer(),

    %% Pacing state
    pacing_rate = 0 :: non_neg_integer(),
    pacing_tokens = 0 :: non_neg_integer(),
    pacing_max_burst = 14400 :: non_neg_integer(),
    last_pacing_update = 0 :: non_neg_integer()
}).

-opaque state() :: #newreno_state{}.
-export_type([state/0]).

%%====================================================================
%% Behavior Callbacks
%%====================================================================

%% @doc Create a new NewReno congestion control state.
-spec new(map()) -> state().
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
    PacingMaxBurst = 12 * MaxDatagramSize,
    Now = erlang:monotonic_time(millisecond),
    ?LOG_DEBUG(
        #{
            what => newreno_state_initialized,
            initial_cwnd => InitialWindow,
            minimum_window => ConfiguredMinimumWindow,
            max_datagram_size => MaxDatagramSize
        },
        ?QUIC_LOG_META
    ),
    #newreno_state{
        cwnd = InitialWindow,
        ssthresh = infinity,
        minimum_window = ConfiguredMinimumWindow,
        max_datagram_size = MaxDatagramSize,
        min_recovery_duration = MinRecoveryDuration,
        pacing_max_burst = PacingMaxBurst,
        pacing_tokens = PacingMaxBurst,
        last_pacing_update = Now
    }.

%% @doc Record that a packet was sent.
-spec on_packet_sent(state(), non_neg_integer()) -> state().
on_packet_sent(
    #newreno_state{
        bytes_in_flight = InFlight,
        first_sent_time = undefined
    } = State,
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    State#newreno_state{
        bytes_in_flight = InFlight + Size,
        first_sent_time = Now
    };
on_packet_sent(#newreno_state{bytes_in_flight = InFlight} = State, Size) ->
    State#newreno_state{bytes_in_flight = InFlight + Size}.

%% @doc Process acknowledged packets.
%% RateSample is ignored for NewReno (only used by BBR).
-spec on_packets_acked(state(), non_neg_integer(), map()) -> state().
on_packets_acked(
    #newreno_state{
        bytes_in_flight = InFlight,
        cwnd = OldCwnd,
        in_recovery = true,
        recovery_start_time = RecoveryStart,
        min_recovery_duration = MinDuration
    } = State,
    AckedBytes,
    #{largest_sent_time := LargestAckedSentTime}
) ->
    NewInFlight = max(0, InFlight - AckedBytes),
    Now = erlang:monotonic_time(millisecond),
    RecoveryDuration = Now - RecoveryStart,

    case
        RecoveryDuration >= MinDuration andalso
            (LargestAckedSentTime > RecoveryStart orelse NewInFlight =:= 0)
    of
        true ->
            #newreno_state{cwnd = Cwnd, ssthresh = SSThresh, max_datagram_size = MaxDS} = State,
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
                    what => newreno_ack_exit_recovery,
                    acked_bytes => AckedBytes,
                    old_cwnd => OldCwnd,
                    new_cwnd => NewCwnd,
                    recovery_duration => RecoveryDuration
                },
                ?QUIC_LOG_META
            ),
            State#newreno_state{
                bytes_in_flight = NewInFlight,
                in_recovery = false,
                recovery_start_time = Now,
                cwnd = NewCwnd
            };
        false ->
            State#newreno_state{bytes_in_flight = NewInFlight}
    end;
on_packets_acked(
    #newreno_state{
        cwnd = Cwnd,
        ssthresh = SSThresh,
        bytes_in_flight = InFlight,
        max_datagram_size = MaxDS
    } = State,
    AckedBytes,
    _RateSample
) ->
    NewInFlight = max(0, InFlight - AckedBytes),
    InSlowStart = Cwnd < SSThresh,
    NewCwnd =
        case InSlowStart of
            true ->
                Cwnd + AckedBytes;
            false ->
                Increment = (MaxDS * AckedBytes) div max(Cwnd, 1),
                Cwnd + max(Increment, 1)
        end,
    ?LOG_DEBUG(
        #{
            what => newreno_ack_processed,
            acked_bytes => AckedBytes,
            old_cwnd => Cwnd,
            new_cwnd => NewCwnd,
            slow_start => InSlowStart
        },
        ?QUIC_LOG_META
    ),
    State#newreno_state{
        cwnd = NewCwnd,
        bytes_in_flight = NewInFlight
    }.

%% @doc Process lost packets.
-spec on_packets_lost(state(), non_neg_integer()) -> state().
on_packets_lost(#newreno_state{bytes_in_flight = InFlight} = State, LostBytes) ->
    NewInFlight = max(0, InFlight - LostBytes),
    State#newreno_state{bytes_in_flight = NewInFlight}.

%% @doc Handle a congestion event.
-spec on_congestion_event(state(), non_neg_integer()) -> state().
on_congestion_event(
    #newreno_state{
        in_recovery = true,
        recovery_start_time = RecoveryStart
    } = State,
    SentTime
) when SentTime =< RecoveryStart ->
    State;
on_congestion_event(
    #newreno_state{
        in_recovery = true,
        recovery_start_time = RecoveryStart,
        min_recovery_duration = MinDuration
    } = State,
    SentTime
) ->
    Now = erlang:monotonic_time(millisecond),
    RecoveryDuration = Now - RecoveryStart,
    case RecoveryDuration < MinDuration of
        true ->
            State;
        false ->
            do_congestion_event(State, SentTime)
    end;
on_congestion_event(
    #newreno_state{
        in_recovery = false,
        recovery_start_time = RecoveryStart
    } = State,
    SentTime
) when is_integer(RecoveryStart), SentTime =< RecoveryStart ->
    State;
on_congestion_event(State, SentTime) ->
    do_congestion_event(State, SentTime).

%% @doc Handle RTT update.
-spec on_rtt_update(state(), non_neg_integer(), non_neg_integer()) -> state().
on_rtt_update(State, SmoothedRTT, _MinRTT) ->
    update_pacing_rate(State, SmoothedRTT).

%% @doc Get the current congestion window.
-spec cwnd(state()) -> non_neg_integer().
cwnd(#newreno_state{cwnd = Cwnd}) -> Cwnd.

%% @doc Get the current pacing rate.
-spec pacing_rate(state()) -> non_neg_integer().
pacing_rate(#newreno_state{pacing_rate = Rate}) -> Rate.

%% @doc Get bytes currently in flight.
-spec bytes_in_flight(state()) -> non_neg_integer().
bytes_in_flight(#newreno_state{bytes_in_flight = B}) -> B.

%% @doc Check if we can send more bytes.
-spec can_send(state(), non_neg_integer()) -> boolean().
can_send(#newreno_state{cwnd = Cwnd, bytes_in_flight = InFlight}, Size) ->
    InFlight + Size =< Cwnd.

%%====================================================================
%% Extended API (NewReno-specific)
%%====================================================================

%% @doc Get the slow start threshold.
-spec ssthresh(state()) -> non_neg_integer() | infinity.
ssthresh(#newreno_state{ssthresh = SST}) -> SST.

%% @doc Check if a control message can be sent.
-spec can_send_control(state(), non_neg_integer()) -> boolean().
can_send_control(
    #newreno_state{cwnd = Cwnd, bytes_in_flight = InFlight, control_allowance = Allowance}, Size
) ->
    InFlight + Size =< Cwnd + Allowance.

%% @doc Get the available congestion window.
-spec available_cwnd(state()) -> non_neg_integer().
available_cwnd(#newreno_state{cwnd = Cwnd, bytes_in_flight = InFlight}) ->
    max(0, Cwnd - InFlight).

%% @doc Check if in slow start phase.
-spec in_slow_start(state()) -> boolean().
in_slow_start(#newreno_state{cwnd = Cwnd, ssthresh = SSThresh}) ->
    Cwnd < SSThresh.

%% @doc Check if in recovery phase.
-spec in_recovery(state()) -> boolean().
in_recovery(#newreno_state{in_recovery = R}) -> R.

%% @doc Get minimum recovery duration.
-spec min_recovery_duration(state()) -> non_neg_integer().
min_recovery_duration(#newreno_state{min_recovery_duration = D}) -> D.

%%====================================================================
%% ECN Support
%%====================================================================

%% @doc Handle ECN-CE signal.
-spec on_ecn_ce(state(), non_neg_integer()) -> state().
on_ecn_ce(#newreno_state{ecn_ce_counter = OldCount} = State, NewCECount) when
    NewCECount =< OldCount
->
    State;
on_ecn_ce(#newreno_state{in_recovery = true, ecn_ce_counter = OldCount} = State, NewCECount) when
    NewCECount > OldCount
->
    State#newreno_state{ecn_ce_counter = NewCECount};
on_ecn_ce(#newreno_state{cwnd = Cwnd, minimum_window = MinimumWindow} = State, NewCECount) ->
    Now = erlang:monotonic_time(millisecond),
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), MinimumWindow),
    NewCwnd = max(NewSSThresh, MinimumWindow),
    State#newreno_state{
        cwnd = NewCwnd,
        ssthresh = NewSSThresh,
        recovery_start_time = Now,
        in_recovery = true,
        ecn_ce_counter = NewCECount
    }.

%% @doc Get the ECN-CE counter.
-spec ecn_ce_counter(state()) -> non_neg_integer().
ecn_ce_counter(#newreno_state{ecn_ce_counter = C}) -> C.

%%====================================================================
%% Persistent Congestion
%%====================================================================

%% @doc Detect persistent congestion.
-spec detect_persistent_congestion(
    [{non_neg_integer(), non_neg_integer()}],
    non_neg_integer(),
    state()
) -> boolean().
detect_persistent_congestion([], _PTO, _State) ->
    false;
detect_persistent_congestion([_], _PTO, _State) ->
    false;
detect_persistent_congestion(LostPackets, PTO, _State) ->
    Times = [T || {_PN, T} <- LostPackets],
    MinTime = lists:min(Times),
    MaxTime = lists:max(Times),
    CongestionPeriod = PTO * ?PERSISTENT_CONGESTION_THRESHOLD,
    (MaxTime - MinTime) >= CongestionPeriod.

%% @doc Reset on persistent congestion.
-spec on_persistent_congestion(state()) -> state().
on_persistent_congestion(#newreno_state{cwnd = Cwnd, minimum_window = MinimumWindow} = State) ->
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), MinimumWindow),
    State#newreno_state{
        cwnd = MinimumWindow,
        ssthresh = NewSSThresh,
        in_recovery = false,
        recovery_start_time = undefined,
        first_sent_time = undefined
    }.

%%====================================================================
%% Pacing
%%====================================================================

%% @doc Update pacing rate.
-spec update_pacing_rate(state(), non_neg_integer()) -> state().
update_pacing_rate(#newreno_state{cwnd = Cwnd} = State, SmoothedRTT) when SmoothedRTT > 0 ->
    PacingRate = max(1, (Cwnd * 5) div (SmoothedRTT * 4)),
    State#newreno_state{pacing_rate = PacingRate};
update_pacing_rate(State, _SmoothedRTT) ->
    State.

%% @doc Check if pacing allows sending.
-spec pacing_allows(state(), non_neg_integer()) -> boolean().
pacing_allows(#newreno_state{pacing_rate = 0}, _Size) ->
    true;
pacing_allows(
    #newreno_state{
        pacing_tokens = Tokens,
        pacing_max_burst = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    },
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    RefreshedTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    RefreshedTokens >= Size.

%% @doc Get pacing tokens.
-spec get_pacing_tokens(state(), non_neg_integer()) -> {non_neg_integer(), state()}.
get_pacing_tokens(#newreno_state{pacing_rate = 0} = State, Size) ->
    {Size, State};
get_pacing_tokens(
    #newreno_state{
        pacing_tokens = Tokens,
        pacing_max_burst = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    } = State,
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    NewTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    Allowed = min(Size, NewTokens),
    RemainingTokens = max(0, NewTokens - Allowed),
    NewState = State#newreno_state{
        pacing_tokens = RemainingTokens,
        last_pacing_update = Now
    },
    {Allowed, NewState}.

%% @doc Calculate pacing delay.
-spec pacing_delay(state(), non_neg_integer()) -> non_neg_integer().
pacing_delay(#newreno_state{pacing_rate = 0}, _Size) ->
    0;
pacing_delay(
    #newreno_state{
        pacing_tokens = Tokens,
        pacing_max_burst = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    },
    Size
) ->
    Now = erlang:monotonic_time(millisecond),
    CurrentTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    case CurrentTokens >= Size of
        true ->
            0;
        false ->
            Deficit = Size - CurrentTokens,
            max(1, (Deficit + Rate - 1) div Rate)
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

do_congestion_event(
    #newreno_state{
        cwnd = Cwnd,
        minimum_window = MinimumWindow
    } = State,
    SentTime
) ->
    Now = erlang:monotonic_time(millisecond),
    NewSSThresh = max(trunc(Cwnd * ?LOSS_REDUCTION_FACTOR), MinimumWindow),
    NewCwnd = max(NewSSThresh, MinimumWindow),
    ?LOG_DEBUG(
        #{
            what => newreno_congestion_event,
            old_cwnd => Cwnd,
            new_cwnd => NewCwnd,
            ssthresh => NewSSThresh
        },
        ?QUIC_LOG_META
    ),
    State#newreno_state{
        cwnd = NewCwnd,
        ssthresh = NewSSThresh,
        recovery_start_time = Now,
        in_recovery = true,
        first_sent_time = SentTime
    }.

refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now) ->
    Elapsed = max(0, Now - LastUpdate),
    Added = Elapsed * Rate,
    min(MaxBurst, Tokens + Added).

initial_window(MaxDatagramSize) ->
    32 * MaxDatagramSize.

minimum_window(MaxDatagramSize) ->
    2 * MaxDatagramSize.
