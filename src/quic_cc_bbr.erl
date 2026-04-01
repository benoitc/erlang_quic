%%% -*- erlang -*-
%%%
%%% QUIC BBR Congestion Control Implementation
%%% draft-cardwell-iccrg-bbr-congestion-control
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc BBR (Bottleneck Bandwidth and Round-trip propagation time) v1.
%%%
%%% BBR is a model-based congestion control algorithm that:
%%% - Estimates bottleneck bandwidth (BtlBw) using a max filter
%%% - Estimates round-trip propagation time (RTprop) using a min filter
%%% - Calculates BDP (bandwidth-delay product) = BtlBw * RTprop
%%% - Sets cwnd and pacing_rate based on BDP and current mode
%%%
%%% == Modes ==
%%%
%%% 1. STARTUP: Exponential BW probing (pacing_gain=2.89)
%%% 2. DRAIN: Drain queue filled during startup (pacing_gain=1/2.89)
%%% 3. PROBE_BW: Steady-state with 8-phase gain cycle
%%% 4. PROBE_RTT: Periodic RTprop refresh (every 10s)

-module(quic_cc_bbr).
-behaviour(quic_cc).

-include("quic.hrl").
-include_lib("kernel/include/logger.hrl").
-define(QUIC_LOG_META, #{domain => [erlang_quic, congestion_control, bbr]}).

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

    %% Extended API
    can_send_control/2,
    available_cwnd/1,
    in_slow_start/1,
    in_recovery/1,

    %% Persistent congestion
    detect_persistent_congestion/3,
    on_persistent_congestion/1,

    %% Pacing
    update_pacing_rate/2,
    pacing_allows/2,
    get_pacing_tokens/2,
    pacing_delay/2,

    %% BBR-specific queries
    mode/1,
    btl_bw/1,
    rt_prop/1
]).

%% BBR state
-record(bbr_state, {
    %% Mode: startup | drain | probe_bw | probe_rtt
    mode = startup :: startup | drain | probe_bw | probe_rtt,

    %% Bandwidth estimation
    btl_bw = 0 :: non_neg_integer(),
    btl_bw_filter :: quic_cc_filter:windowed_filter(),

    %% RTprop (minimum RTT)
    rt_prop = infinity :: non_neg_integer() | infinity,
    rt_prop_stamp = 0 :: non_neg_integer(),
    rt_prop_expired = true :: boolean(),

    %% Delivery tracking
    delivered = 0 :: non_neg_integer(),
    delivered_time = 0 :: non_neg_integer(),
    first_sent_time = 0 :: non_neg_integer(),

    %% Pacing and cwnd
    pacing_rate = 0 :: non_neg_integer(),
    pacing_gain = ?BBR_STARTUP_PACING_GAIN :: float(),
    cwnd_gain = ?BBR_STARTUP_CWND_GAIN :: float(),
    cwnd = 0 :: non_neg_integer(),

    %% PROBE_BW cycle (0..7)
    cycle_index = 0 :: non_neg_integer(),
    cycle_stamp = 0 :: non_neg_integer(),

    %% Round counting
    round_count = 0 :: non_neg_integer(),
    next_round_delivered = 0 :: non_neg_integer(),
    round_start = false :: boolean(),

    %% STARTUP exit detection
    filled_pipe = false :: boolean(),
    full_bw = 0 :: non_neg_integer(),
    full_bw_count = 0 :: non_neg_integer(),

    %% Flight tracking
    bytes_in_flight = 0 :: non_neg_integer(),
    app_limited = false :: boolean(),

    %% Prior PROBE_RTT state
    prior_cwnd = 0 :: non_neg_integer(),
    probe_rtt_done_stamp = 0 :: non_neg_integer(),
    probe_rtt_round_done = false :: boolean(),

    %% Configuration
    max_datagram_size = 1200 :: non_neg_integer(),
    min_pipe_cwnd = 4800 :: non_neg_integer(),
    initial_cwnd = 38400 :: non_neg_integer(),
    control_allowance = 1200 :: non_neg_integer(),

    %% Pacing tokens
    pacing_tokens = 0 :: non_neg_integer(),
    pacing_max_burst = 14400 :: non_neg_integer(),
    last_pacing_update = 0 :: non_neg_integer()
}).

-opaque state() :: #bbr_state{}.
-export_type([state/0]).

%%====================================================================
%% Behavior Callbacks
%%====================================================================

%% @doc Create a new BBR state.
-spec new(map()) -> state().
new(Opts) ->
    MaxDatagramSize = maps:get(max_datagram_size, Opts, 1200),
    InitialWindow = maps:get(initial_window, Opts, 32 * MaxDatagramSize),
    MinPipeCwnd = ?BBR_MIN_PIPE_CWND_PACKETS * MaxDatagramSize,
    PacingMaxBurst = 12 * MaxDatagramSize,
    Now = erlang:monotonic_time(millisecond),

    BtlBwFilter = quic_cc_filter:new_max_filter(?BBR_BTL_BW_FILTER_LEN),

    ?LOG_DEBUG(
        #{
            what => bbr_state_initialized,
            initial_cwnd => InitialWindow,
            max_datagram_size => MaxDatagramSize,
            min_pipe_cwnd => MinPipeCwnd
        },
        ?QUIC_LOG_META
    ),

    #bbr_state{
        mode = startup,
        btl_bw_filter = BtlBwFilter,
        cwnd = InitialWindow,
        initial_cwnd = InitialWindow,
        max_datagram_size = MaxDatagramSize,
        min_pipe_cwnd = MinPipeCwnd,
        pacing_gain = ?BBR_STARTUP_PACING_GAIN,
        cwnd_gain = ?BBR_STARTUP_CWND_GAIN,
        rt_prop_stamp = Now,
        pacing_max_burst = PacingMaxBurst,
        pacing_tokens = PacingMaxBurst,
        last_pacing_update = Now
    }.

%% @doc Record that a packet was sent.
-spec on_packet_sent(state(), non_neg_integer()) -> state().
on_packet_sent(#bbr_state{bytes_in_flight = InFlight, first_sent_time = 0} = State, Size) ->
    Now = erlang:monotonic_time(millisecond),
    State#bbr_state{
        bytes_in_flight = InFlight + Size,
        first_sent_time = Now
    };
on_packet_sent(#bbr_state{bytes_in_flight = InFlight} = State, Size) ->
    State#bbr_state{bytes_in_flight = InFlight + Size}.

%% @doc Process acknowledged packets.
-spec on_packets_acked(state(), non_neg_integer(), map()) -> state().
on_packets_acked(State, AckedBytes, RateSample) ->
    %% Update flight tracking
    State1 = update_flight_on_ack(State, AckedBytes),

    %% Update delivery tracking
    State2 = update_delivered(State1, AckedBytes),

    %% Check for new round
    State3 = check_round_start(State2, RateSample),

    %% Update bandwidth estimate
    State4 = update_btl_bw(State3, RateSample),

    %% Check mode transitions
    State5 = check_mode_transitions(State4),

    %% Update control parameters
    update_control_parameters(State5).

%% @doc Process lost packets.
-spec on_packets_lost(state(), non_neg_integer()) -> state().
on_packets_lost(#bbr_state{bytes_in_flight = InFlight} = State, LostBytes) ->
    NewInFlight = max(0, InFlight - LostBytes),
    State#bbr_state{bytes_in_flight = NewInFlight}.

%% @doc Handle congestion event.
%% BBR doesn't reduce cwnd on loss in the same way as loss-based algorithms.
-spec on_congestion_event(state(), non_neg_integer()) -> state().
on_congestion_event(State, _SentTime) ->
    %% BBR v1 doesn't reduce cwnd on individual loss events.
    %% Instead, it uses the bandwidth estimate which naturally decreases
    %% when delivery rate drops due to loss.
    State.

%% @doc Handle RTT update.
-spec on_rtt_update(state(), non_neg_integer(), non_neg_integer()) -> state().
on_rtt_update(State, _SmoothedRTT, MinRTT) when MinRTT > 0 ->
    update_rt_prop(State, MinRTT);
on_rtt_update(State, _SmoothedRTT, _MinRTT) ->
    State.

%% @doc Get the current congestion window.
-spec cwnd(state()) -> non_neg_integer().
cwnd(#bbr_state{cwnd = Cwnd}) -> Cwnd.

%% @doc Get the current pacing rate.
-spec pacing_rate(state()) -> non_neg_integer().
pacing_rate(#bbr_state{pacing_rate = Rate}) -> Rate.

%% @doc Get bytes in flight.
-spec bytes_in_flight(state()) -> non_neg_integer().
bytes_in_flight(#bbr_state{bytes_in_flight = B}) -> B.

%% @doc Check if can send.
-spec can_send(state(), non_neg_integer()) -> boolean().
can_send(#bbr_state{cwnd = Cwnd, bytes_in_flight = InFlight}, Size) ->
    InFlight + Size =< Cwnd.

%%====================================================================
%% Extended API
%%====================================================================

%% @doc Check if control message can be sent.
-spec can_send_control(state(), non_neg_integer()) -> boolean().
can_send_control(
    #bbr_state{cwnd = Cwnd, bytes_in_flight = InFlight, control_allowance = Allowance}, Size
) ->
    InFlight + Size =< Cwnd + Allowance.

%% @doc Get available cwnd.
-spec available_cwnd(state()) -> non_neg_integer().
available_cwnd(#bbr_state{cwnd = Cwnd, bytes_in_flight = InFlight}) ->
    max(0, Cwnd - InFlight).

%% @doc Check if in slow start (STARTUP mode).
-spec in_slow_start(state()) -> boolean().
in_slow_start(#bbr_state{mode = startup}) -> true;
in_slow_start(_) -> false.

%% @doc Check if in recovery.
%% BBR doesn't have traditional recovery; return false.
-spec in_recovery(state()) -> boolean().
in_recovery(_) -> false.

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
    CongestionPeriod = PTO * 3,
    (MaxTime - MinTime) >= CongestionPeriod.

%% @doc Reset on persistent congestion.
-spec on_persistent_congestion(state()) -> state().
on_persistent_congestion(#bbr_state{min_pipe_cwnd = MinCwnd} = State) ->
    %% Reset to minimum cwnd
    State#bbr_state{
        cwnd = MinCwnd,
        mode = startup,
        filled_pipe = false,
        full_bw = 0,
        full_bw_count = 0,
        pacing_gain = ?BBR_STARTUP_PACING_GAIN,
        cwnd_gain = ?BBR_STARTUP_CWND_GAIN
    }.

%%====================================================================
%% Pacing
%%====================================================================

%% @doc Update pacing rate (called from on_rtt_update).
-spec update_pacing_rate(state(), non_neg_integer()) -> state().
update_pacing_rate(State, _SmoothedRTT) ->
    %% BBR calculates its own pacing rate based on btl_bw and pacing_gain
    %% This is a no-op; pacing rate is updated in update_control_parameters
    State.

%% @doc Check if pacing allows sending.
-spec pacing_allows(state(), non_neg_integer()) -> boolean().
pacing_allows(#bbr_state{pacing_rate = 0}, _Size) ->
    true;
pacing_allows(
    #bbr_state{
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
get_pacing_tokens(#bbr_state{pacing_rate = 0} = State, Size) ->
    {Size, State};
get_pacing_tokens(
    #bbr_state{
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
    NewState = State#bbr_state{
        pacing_tokens = RemainingTokens,
        last_pacing_update = Now
    },
    {Allowed, NewState}.

%% @doc Calculate pacing delay.
-spec pacing_delay(state(), non_neg_integer()) -> non_neg_integer().
pacing_delay(#bbr_state{pacing_rate = 0}, _Size) ->
    0;
pacing_delay(
    #bbr_state{
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
%% BBR-Specific Queries
%%====================================================================

%% @doc Get current mode.
-spec mode(state()) -> atom().
mode(#bbr_state{mode = Mode}) -> Mode.

%% @doc Get bottleneck bandwidth estimate (bytes/ms).
-spec btl_bw(state()) -> non_neg_integer().
btl_bw(#bbr_state{btl_bw = BtlBw}) -> BtlBw.

%% @doc Get RTprop estimate (ms).
-spec rt_prop(state()) -> non_neg_integer() | infinity.
rt_prop(#bbr_state{rt_prop = RTprop}) -> RTprop.

%%====================================================================
%% Internal Functions - Delivery Tracking
%%====================================================================

update_flight_on_ack(#bbr_state{bytes_in_flight = InFlight} = State, AckedBytes) ->
    State#bbr_state{bytes_in_flight = max(0, InFlight - AckedBytes)}.

update_delivered(#bbr_state{delivered = Delivered} = State, AckedBytes) ->
    Now = erlang:monotonic_time(millisecond),
    State#bbr_state{
        delivered = Delivered + AckedBytes,
        delivered_time = Now
    }.

check_round_start(
    #bbr_state{
        delivered = Delivered,
        next_round_delivered = NextRoundDelivered,
        round_count = RoundCount
    } = State,
    _RateSample
) ->
    case Delivered >= NextRoundDelivered of
        true ->
            State#bbr_state{
                round_start = true,
                round_count = RoundCount + 1,
                next_round_delivered = Delivered
            };
        false ->
            State#bbr_state{round_start = false}
    end.

%%====================================================================
%% Internal Functions - Bandwidth Estimation
%%====================================================================

update_btl_bw(#bbr_state{app_limited = true} = State, _RateSample) ->
    %% Don't update BtlBw when app-limited
    State;
update_btl_bw(State, RateSample) ->
    DeliveryRate = calculate_delivery_rate(State, RateSample),
    update_btl_bw_filter(State, DeliveryRate).

calculate_delivery_rate(
    #bbr_state{
        delivered = Delivered,
        delivered_time = DeliveredTime
    },
    RateSample
) ->
    %% Calculate delivery rate from the rate sample
    %% DeliveryRate = (delivered_now - delivered_at_send) / (now - send_time)
    case RateSample of
        #{delivered := SentDelivered, delivered_time := SentDeliveredTime} when
            is_integer(SentDelivered), is_integer(SentDeliveredTime)
        ->
            Interval = max(1, DeliveredTime - SentDeliveredTime),
            BytesDelivered = Delivered - SentDelivered,
            BytesDelivered div Interval;
        _ ->
            %% Fallback: estimate from delivered bytes and time
            0
    end.

update_btl_bw_filter(
    #bbr_state{
        btl_bw_filter = Filter,
        round_count = RoundCount
    } = State,
    DeliveryRate
) when DeliveryRate > 0 ->
    Filter1 = quic_cc_filter:update_max(Filter, DeliveryRate, RoundCount),
    BtlBw = quic_cc_filter:get_max(Filter1),
    State#bbr_state{
        btl_bw = BtlBw,
        btl_bw_filter = Filter1
    };
update_btl_bw_filter(State, _DeliveryRate) ->
    State.

%%====================================================================
%% Internal Functions - RTprop Tracking
%%====================================================================

update_rt_prop(
    #bbr_state{
        rt_prop = OldRTprop,
        rt_prop_stamp = RTpropStamp
    } = State,
    RTT
) ->
    Now = erlang:monotonic_time(millisecond),
    NewRTprop =
        case OldRTprop of
            infinity -> RTT;
            _ -> min(OldRTprop, RTT)
        end,
    %% Check if RTprop filter window expired (10 seconds)
    RTpropExpired = (Now - RTpropStamp) > ?BBR_RT_PROP_FILTER_LEN,
    case RTT =< NewRTprop orelse RTpropExpired of
        true ->
            State#bbr_state{
                rt_prop = RTT,
                rt_prop_stamp = Now,
                rt_prop_expired = false
            };
        false ->
            State#bbr_state{
                rt_prop = NewRTprop,
                rt_prop_expired = RTpropExpired
            }
    end.

%%====================================================================
%% Internal Functions - Mode Transitions
%%====================================================================

check_mode_transitions(#bbr_state{mode = startup} = State) ->
    check_startup_exit(State);
check_mode_transitions(#bbr_state{mode = drain} = State) ->
    check_drain_exit(State);
check_mode_transitions(#bbr_state{mode = probe_bw} = State) ->
    State1 = advance_probe_bw_cycle(State),
    check_probe_rtt_needed(State1);
check_mode_transitions(#bbr_state{mode = probe_rtt} = State) ->
    check_probe_rtt_exit(State).

%% STARTUP exit: filled_pipe detection
check_startup_exit(
    #bbr_state{
        filled_pipe = true
    } = State
) ->
    enter_drain(State);
check_startup_exit(
    #bbr_state{
        round_start = true,
        btl_bw = BtlBw,
        full_bw = FullBw,
        full_bw_count = FullBwCount
    } = State
) ->
    %% Check if BW growth < 25%
    case BtlBw >= trunc(FullBw * ?BBR_FULL_BW_THRESHOLD) of
        true ->
            %% Still growing
            State#bbr_state{
                full_bw = BtlBw,
                full_bw_count = 0
            };
        false ->
            %% Not enough growth
            NewCount = FullBwCount + 1,
            case NewCount >= ?BBR_FULL_BW_COUNT of
                true ->
                    enter_drain(State#bbr_state{filled_pipe = true});
                false ->
                    State#bbr_state{full_bw_count = NewCount}
            end
    end;
check_startup_exit(State) ->
    State.

enter_drain(State) ->
    ?LOG_DEBUG(
        #{what => bbr_enter_drain, btl_bw => State#bbr_state.btl_bw},
        ?QUIC_LOG_META
    ),
    State#bbr_state{
        mode = drain,
        pacing_gain = ?BBR_DRAIN_PACING_GAIN,
        cwnd_gain = ?BBR_STARTUP_CWND_GAIN
    }.

%% DRAIN exit: inflight <= BDP
check_drain_exit(
    #bbr_state{
        bytes_in_flight = InFlight,
        btl_bw = BtlBw,
        rt_prop = RTprop
    } = State
) when RTprop =/= infinity ->
    BDP = calculate_bdp(BtlBw, RTprop),
    case InFlight =< BDP of
        true ->
            enter_probe_bw(State);
        false ->
            State
    end;
check_drain_exit(State) ->
    State.

enter_probe_bw(State) ->
    Now = erlang:monotonic_time(millisecond),
    %% Start at a random cycle index (1-7, not 0 which is probe-up)
    CycleIndex = 1 + (erlang:phash2(Now, 7)),
    Gains = list_to_tuple(?BBR_PROBE_BW_GAINS),
    PacingGain = element(CycleIndex + 1, Gains),
    ?LOG_DEBUG(
        #{what => bbr_enter_probe_bw, cycle_index => CycleIndex},
        ?QUIC_LOG_META
    ),
    State#bbr_state{
        mode = probe_bw,
        pacing_gain = PacingGain,
        cwnd_gain = ?BBR_PROBE_BW_CWND_GAIN,
        cycle_index = CycleIndex,
        cycle_stamp = Now
    }.

advance_probe_bw_cycle(
    #bbr_state{
        cycle_index = CycleIndex,
        cycle_stamp = CycleStamp,
        rt_prop = RTprop
    } = State
) when RTprop =/= infinity ->
    Now = erlang:monotonic_time(millisecond),
    %% Advance cycle every RTprop
    case (Now - CycleStamp) >= RTprop of
        true ->
            NewIndex = (CycleIndex + 1) rem ?BBR_CYCLE_LEN,
            Gains = list_to_tuple(?BBR_PROBE_BW_GAINS),
            PacingGain = element(NewIndex + 1, Gains),
            State#bbr_state{
                cycle_index = NewIndex,
                cycle_stamp = Now,
                pacing_gain = PacingGain
            };
        false ->
            State
    end;
advance_probe_bw_cycle(State) ->
    State.

check_probe_rtt_needed(
    #bbr_state{
        rt_prop_expired = true,
        mode = probe_bw
    } = State
) ->
    enter_probe_rtt(State);
check_probe_rtt_needed(State) ->
    State.

enter_probe_rtt(#bbr_state{cwnd = Cwnd, min_pipe_cwnd = MinCwnd} = State) ->
    ?LOG_DEBUG(#{what => bbr_enter_probe_rtt}, ?QUIC_LOG_META),
    State#bbr_state{
        mode = probe_rtt,
        prior_cwnd = Cwnd,
        cwnd = MinCwnd,
        pacing_gain = 1.0,
        cwnd_gain = ?BBR_PROBE_RTT_CWND_GAIN,
        probe_rtt_done_stamp = 0,
        probe_rtt_round_done = false
    }.

check_probe_rtt_exit(
    #bbr_state{
        probe_rtt_done_stamp = 0,
        bytes_in_flight = InFlight,
        min_pipe_cwnd = MinCwnd
    } = State
) ->
    %% Wait for inflight to drain to min_pipe_cwnd
    case InFlight =< MinCwnd of
        true ->
            Now = erlang:monotonic_time(millisecond),
            State#bbr_state{
                probe_rtt_done_stamp = Now,
                probe_rtt_round_done = false,
                next_round_delivered = State#bbr_state.delivered
            };
        false ->
            State
    end;
check_probe_rtt_exit(
    #bbr_state{
        probe_rtt_done_stamp = DoneStamp,
        probe_rtt_round_done = true
    } = State
) when DoneStamp > 0 ->
    Now = erlang:monotonic_time(millisecond),
    %% Exit after 200ms
    case (Now - DoneStamp) >= ?BBR_PROBE_RTT_DURATION of
        true ->
            exit_probe_rtt(State);
        false ->
            State
    end;
check_probe_rtt_exit(
    #bbr_state{
        probe_rtt_done_stamp = DoneStamp,
        round_start = true
    } = State
) when DoneStamp > 0 ->
    %% Mark round done
    State#bbr_state{probe_rtt_round_done = true};
check_probe_rtt_exit(State) ->
    State.

exit_probe_rtt(#bbr_state{prior_cwnd = PriorCwnd, filled_pipe = FilledPipe} = State) ->
    Now = erlang:monotonic_time(millisecond),
    ?LOG_DEBUG(#{what => bbr_exit_probe_rtt, filled_pipe => FilledPipe}, ?QUIC_LOG_META),
    %% Restore cwnd and return to probe_bw or startup
    State1 = State#bbr_state{
        cwnd = max(PriorCwnd, State#bbr_state.min_pipe_cwnd),
        rt_prop_stamp = Now,
        rt_prop_expired = false
    },
    case FilledPipe of
        true ->
            enter_probe_bw(State1);
        false ->
            State1#bbr_state{
                mode = startup,
                pacing_gain = ?BBR_STARTUP_PACING_GAIN,
                cwnd_gain = ?BBR_STARTUP_CWND_GAIN
            }
    end.

%%====================================================================
%% Internal Functions - Control Parameters
%%====================================================================

update_control_parameters(State) ->
    State1 = set_pacing_rate(State),
    set_cwnd(State1).

set_pacing_rate(
    #bbr_state{
        btl_bw = BtlBw,
        pacing_gain = PacingGain
    } = State
) when BtlBw > 0 ->
    %% pacing_rate = pacing_gain * btl_bw
    %% BtlBw is in bytes/ms, pacing_rate is in bytes/ms
    PacingRate = max(1, trunc(PacingGain * BtlBw)),
    State#bbr_state{pacing_rate = PacingRate};
set_pacing_rate(State) ->
    State.

set_cwnd(
    #bbr_state{
        btl_bw = BtlBw,
        rt_prop = RTprop,
        cwnd_gain = CwndGain,
        mode = Mode,
        min_pipe_cwnd = MinCwnd,
        max_datagram_size = MaxDS
    } = State
) when BtlBw > 0, RTprop =/= infinity ->
    BDP = calculate_bdp(BtlBw, RTprop),
    %% Target cwnd = cwnd_gain * BDP
    TargetCwnd = max(trunc(CwndGain * BDP), MinCwnd),
    %% In PROBE_RTT, use min_pipe_cwnd
    NewCwnd =
        case Mode of
            probe_rtt ->
                MinCwnd;
            _ ->
                %% Allow 3 extra packets for ACK aggregation
                TargetCwnd + 3 * MaxDS
        end,
    State#bbr_state{cwnd = NewCwnd};
set_cwnd(State) ->
    State.

calculate_bdp(BtlBw, RTprop) ->
    %% BDP = BtlBw (bytes/ms) * RTprop (ms) = bytes
    BtlBw * RTprop.

%%====================================================================
%% Internal Functions - Pacing Tokens
%%====================================================================

refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now) ->
    Elapsed = max(0, Now - LastUpdate),
    Added = Elapsed * Rate,
    min(MaxBurst, Tokens + Added).
