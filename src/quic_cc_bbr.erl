%%% -*- erlang -*-
%%%
%%% QUIC BBRv3 Congestion Control
%%% draft-ietf-ccwg-bbr-07
%%% RFC 9406 - HyStart++: Modified Slow Start for TCP
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc QUIC BBRv3 congestion control implementation.
%%%
%%% BBRv3 (Bottleneck Bandwidth and Round-trip propagation time) is a
%%% model-based congestion control algorithm that aims to maximize throughput
%%% while minimizing latency and packet loss.
%%%
%%% HyStart++ (RFC 9406) provides additional RTT-based startup exit detection
%%% alongside BBR's bandwidth plateau detection for earlier, safer exits.
%%%
%%% == States ==
%%%
%%% 1. Startup: Exponential bandwidth probing (2.885x pacing gain) with HyStart++ RTT monitoring
%%% 2. Drain: Reduce queue built during startup (0.347x pacing gain)
%%% 3. ProbeBW: Steady-state with cycling phases (DOWN/CRUISE/REFILL/UP)
%%% 4. ProbeRTT: Periodic RTT measurement with reduced cwnd
%%%
%%% == Units ==
%%%
%%% Volumes are bytes, times are microseconds of `erlang:monotonic_time',
%%% rates are bytes per second.
%%%
%%% == Per-packet state ==
%%%
%%% The `quic_cc' callbacks report bytes, not packets, so the delivery
%%% rate sampler (draft-ietf-ccwg-bbr-07 Section 4.1) keeps the
%%% per-packet snapshots in send order and matches acknowledged, lost and
%%% discarded bytes against the oldest outstanding ones. QUIC
%%% acknowledges and declares packets lost mostly in send order, so a
%%% reordered acknowledgment only shifts a sample to a neighbouring
%%% packet's snapshot.
%%%
%%% The `*_at' functions take the current time and are what the
%%% behaviour callbacks call with the clock; `info/1' returns the model.

-module(quic_cc_bbr).

-behaviour(quic_cc).

-include_lib("kernel/include/logger.hrl").
-define(QUIC_LOG_META, #{domain => [erlang_quic, congestion_control]}).

-export([
    on_spurious_congestion/1,
    %% Behavior callbacks
    new/1,
    on_packet_sent/2,
    on_packets_acked/2,
    on_packets_acked/3,
    on_packets_lost/2,
    on_congestion_event/2,
    on_ecn_ce/2,
    on_persistent_congestion/1,
    detect_persistent_congestion/3,
    update_pacing_rate/2,
    update_mtu/2,
    cwnd/1,
    initial_window/1,
    on_packets_discarded/2,
    reset_for_retry/1,
    ssthresh/1,
    bytes_in_flight/1,
    can_send/2,
    can_send_control/2,
    available_cwnd/1,
    in_slow_start/1,
    in_recovery/1,
    pacing_allows/2,
    get_pacing_tokens/2,
    pacing_delay/2,
    send_check/3,
    max_datagram_size/1,
    min_recovery_duration/1,
    ecn_ce_counter/1
]).

%% Application-limited marking and explicit-clock entry points
-export([
    new_at/2,
    on_app_limited/1,
    on_packet_sent_at/3,
    on_packets_acked_at/3,
    on_packets_lost_at/3,
    on_congestion_event_at/3,
    on_ecn_ce_at/3,
    on_persistent_congestion_at/2,
    info/1
]).

%%====================================================================
%% Constants (draft-ietf-ccwg-bbr-07 Section 2)
%%====================================================================

-define(STARTUP_PACING_GAIN, 2.885).
-define(DRAIN_PACING_GAIN, 0.347).
-define(DEFAULT_CWND_GAIN, 2.0).
-define(PROBE_BW_DOWN_PACING_GAIN, 0.91).
-define(PROBE_BW_CRUISE_PACING_GAIN, 1.0).
-define(PROBE_BW_REFILL_PACING_GAIN, 1.0).
-define(PROBE_BW_UP_PACING_GAIN, 1.25).
-define(PROBE_RTT_CWND_GAIN, 0.5).
-define(PACING_MARGIN_PERCENT, 1).
-define(LOSS_THRESH, 0.02).
-define(BETA, 0.7).
-define(MIN_PIPE_CWND_PKTS, 4).
-define(FULL_BW_GROWTH, 1.25).
-define(FULL_BW_ROUNDS, 3).

%% HyStart++ (RFC 9406): samples per round, RTT threshold bounds (ms)
%% and the divisor of the last round's RTT.
-define(HYSTART_MIN_SAMPLES, 8).
-define(HYSTART_MIN_RTT_THRESH, 4).
-define(HYSTART_MAX_RTT_THRESH, 16).
-define(HYSTART_MIN_RTT_DIVISOR, 8).

%% Times in microseconds.
-define(MIN_RTT_FILTER_LEN, 10000000).
-define(PROBE_RTT_DURATION, 200000).
-define(PROBE_RTT_INTERVAL, 5000000).
-define(US_PER_SEC, 1000000).

-define(MAX_DATAGRAM_SIZE, 1200).
-define(INITIAL_RTT, 100).
-define(PERSISTENT_CONGESTION_THRESHOLD, 3).

%%====================================================================
%% State
%%====================================================================

%% Per-packet delivery snapshot (Section 4.1.2.1.2).
-record(pkt, {
    size :: non_neg_integer(),
    send_time :: integer(),
    delivered :: non_neg_integer(),
    delivered_time :: integer(),
    first_send_time :: integer(),
    is_app_limited :: boolean(),
    tx_in_flight :: non_neg_integer(),
    lost :: non_neg_integer()
}).

%% Per-ACK rate sample (Sections 2.3 and 4.1.2.1.3).
-record(rs, {
    has_data = false :: boolean(),
    delivery_rate = 0 :: non_neg_integer(),
    delivered = 0 :: non_neg_integer(),
    prior_delivered = 0 :: non_neg_integer(),
    is_app_limited = false :: boolean(),
    tx_in_flight = 0 :: non_neg_integer(),
    lost = 0 :: non_neg_integer(),
    prior_lost = 0 :: non_neg_integer(),
    rtt = -1 :: integer(),
    newly_acked = 0 :: non_neg_integer(),
    send_time = 0 :: integer(),
    send_elapsed = 0 :: integer(),
    ack_elapsed = 0 :: integer()
}).

-type bbr_mode() ::
    startup
    | drain
    | probe_bw_down
    | probe_bw_cruise
    | probe_bw_refill
    | probe_bw_up
    | probe_rtt.

-type volume() :: non_neg_integer() | infinity.

-record(bbr_state, {
    %% Configuration
    max_datagram_size = ?MAX_DATAGRAM_SIZE :: pos_integer(),
    initial_window = 0 :: non_neg_integer(),
    minimum_window = 2400 :: non_neg_integer(),
    min_recovery_duration = 100 :: non_neg_integer(),
    control_allowance = 1200 :: non_neg_integer(),

    %% Connection state (Section 2.2, 4.1.2.1.1)
    cwnd = 0 :: non_neg_integer(),
    bytes_in_flight = 0 :: non_neg_integer(),
    delivered = 0 :: non_neg_integer(),
    lost = 0 :: non_neg_integer(),
    delivered_time = 0 :: integer(),
    first_send_time = 0 :: integer(),
    app_limited = 0 :: non_neg_integer(),
    lifetime_min_rtt = infinity :: non_neg_integer() | infinity,
    sent = queue:new() :: queue:queue(#pkt{}),
    rs = #rs{} :: #rs{},

    %% State machine (Section 2.7)
    mode = startup :: bbr_mode(),
    pacing_gain = ?STARTUP_PACING_GAIN :: float(),
    cwnd_gain = ?DEFAULT_CWND_GAIN :: float(),
    round_count = 0 :: non_neg_integer(),
    round_start = false :: boolean(),
    next_round_delivered = 0 :: non_neg_integer(),

    %% Bandwidth model (Sections 2.9.1, 2.11)
    max_bw = 0 :: non_neg_integer(),
    bw_hi_cur = 0 :: non_neg_integer(),
    bw_hi_prev = 0 :: non_neg_integer(),
    cycle_count = 0 :: non_neg_integer(),

    %% Volume model (Section 2.9.2)
    min_rtt = infinity :: non_neg_integer() | infinity,
    min_rtt_stamp = 0 :: integer(),

    %% Loss in the current round, and the in-flight cap it set
    loss_in_round = 0 :: non_neg_integer(),
    bytes_in_round = 0 :: non_neg_integer(),
    inflight_hi = infinity :: volume(),

    %% Startup bandwidth plateau
    full_bw = 0 :: non_neg_integer(),
    full_bw_count = 0 :: non_neg_integer(),

    %% ProbeRTT
    prior_cwnd = 0 :: non_neg_integer(),
    probe_rtt_done_stamp = 0 :: integer(),

    %% HyStart++ (RFC 9406): RTT samples this round, last and current
    %% round's minimum RTT in milliseconds
    hystart_enabled = true :: boolean(),
    hystart_rtt_sample_count = 0 :: non_neg_integer(),
    hystart_last_rtt = 0 :: non_neg_integer(),
    hystart_curr_rtt = infinity :: non_neg_integer() | infinity,

    %% Loss recovery (RFC 9002 Section 7.3.2)
    in_recovery = false :: boolean(),
    recovery_start = 0 :: integer(),

    %% ECN
    ecn_ce_counter = 0 :: non_neg_integer(),

    %% Pacing (Sections 5.6.2, 5.6.3)
    pacing_rate = 0 :: non_neg_integer(),
    send_quantum = 0 :: non_neg_integer(),
    pacing_tokens = 0 :: non_neg_integer(),
    last_pacing_update = 0 :: integer()
}).

-opaque cc_state() :: #bbr_state{}.
-export_type([cc_state/0]).

%%====================================================================
%% Initialization (Section 5.2.1)
%%====================================================================

%% @doc Create a new BBRv3 congestion control state.
-spec new(quic_cc:cc_opts()) -> cc_state().
new(Opts) ->
    new_at(Opts, now_us()).

%% @doc Create a new state at time `Now' (microseconds).
-spec new_at(quic_cc:cc_opts(), integer()) -> cc_state().
new_at(Opts, Now) ->
    MDS = maps:get(max_datagram_size, Opts, ?MAX_DATAGRAM_SIZE),
    MinimumWindow = max(maps:get(minimum_window, Opts, 2 * MDS), 2 * MDS),
    MinRecoveryDuration = maps:get(min_recovery_duration, Opts, 100) * 1000,
    InitialRtt = maps:get(initial_rtt, Opts, ?INITIAL_RTT),
    HystartEnabled = maps:get(hystart_enabled, Opts, true),
    InitialCwnd = max(maps:get(initial_window, Opts, 10 * MDS), ?MIN_PIPE_CWND_PKTS * MDS),
    S0 = #bbr_state{
        max_datagram_size = MDS,
        initial_window = InitialCwnd,
        minimum_window = MinimumWindow,
        min_recovery_duration = MinRecoveryDuration,
        cwnd = InitialCwnd,
        min_rtt_stamp = Now,
        last_pacing_update = Now,
        hystart_enabled = HystartEnabled
    },
    %% Startup gain times the initial window over initial_rtt (ms).
    Rate = max(1, trunc(?STARTUP_PACING_GAIN * ((InitialCwnd * 1000) div InitialRtt))),
    Quantum = pacing_max_burst(MDS, Rate),
    enter_startup(S0#bbr_state{pacing_rate = Rate, send_quantum = Quantum, pacing_tokens = Quantum}).

%%====================================================================
%% Per-transmit steps (Sections 4.1.2.2, 5.2.2, 5.4)
%%====================================================================

%% @doc Record that a packet was sent.
-spec on_packet_sent(cc_state(), non_neg_integer()) -> cc_state().
on_packet_sent(State, Size) ->
    on_packet_sent_at(State, Size, now_us()).

%% @doc Record that a packet was sent at time `Now' (microseconds).
-spec on_packet_sent_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_packet_sent_at(State, Size, Now) ->
    #bbr_state{
        bytes_in_flight = InFlight0,
        delivered = Delivered,
        lost = Lost,
        app_limited = AppLimited,
        sent = Sent,
        bytes_in_round = BytesInRound
    } = State,
    {DeliveredTime, FirstSendTime} =
        case InFlight0 of
            0 -> {Now, Now};
            _ -> {State#bbr_state.delivered_time, State#bbr_state.first_send_time}
        end,
    InFlight = InFlight0 + Size,
    Pkt = #pkt{
        size = Size,
        send_time = Now,
        delivered = Delivered,
        delivered_time = DeliveredTime,
        first_send_time = FirstSendTime,
        is_app_limited = (AppLimited =/= 0),
        tx_in_flight = InFlight,
        lost = Lost
    },
    State#bbr_state{
        bytes_in_flight = InFlight,
        delivered_time = DeliveredTime,
        first_send_time = FirstSendTime,
        sent = queue:in(Pkt, Sent),
        bytes_in_round = BytesInRound + Size
    }.

%% @doc The sender has no data queued: mark the connection
%% application-limited if cwnd has room (Section 4.1.2.4).
-spec on_app_limited(cc_state()) -> cc_state().
on_app_limited(#bbr_state{bytes_in_flight = InFlight, cwnd = Cwnd} = S) when InFlight < Cwnd ->
    mark_app_limited(S);
on_app_limited(S) ->
    S.

mark_app_limited(#bbr_state{delivered = Delivered, bytes_in_flight = InFlight} = S) ->
    S#bbr_state{app_limited = max(Delivered + InFlight, 1)}.

%%====================================================================
%% Per-ACK steps (Section 5.2.3)
%%====================================================================

%% @doc Process acknowledged packets.
-spec on_packets_acked(cc_state(), non_neg_integer()) -> cc_state().
on_packets_acked(State, AckedBytes) ->
    on_packets_acked_at(State, AckedBytes, now_us()).

%% @doc Process acknowledged packets. The sent time of the largest
%% acknowledged packet is not needed: the sampler keeps its own.
-spec on_packets_acked(cc_state(), non_neg_integer(), non_neg_integer()) -> cc_state().
on_packets_acked(State, AckedBytes, _LargestAckedSentTimeMs) ->
    on_packets_acked_at(State, AckedBytes, now_us()).

%% @doc Process `AckedBytes' newly acknowledged at time `Now'.
-spec on_packets_acked_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_packets_acked_at(State, 0, _Now) ->
    State;
on_packets_acked_at(State0, AckedBytes, Now) ->
    State1 = take_acked(State0, AckedBytes, Now),
    State2 = generate_rate_sample(State1),
    State3 = update_model_and_state(State2, Now),
    update_control_parameters(State3).

%% Section 4.1.2.3 UpdateRateSample, over the oldest outstanding bytes.
take_acked(#bbr_state{bytes_in_flight = InFlight} = S, AckedBytes, Now) ->
    S1 = S#bbr_state{
        bytes_in_flight = max(0, InFlight - AckedBytes),
        rs = #rs{newly_acked = AckedBytes}
    },
    S2 = ack_bytes(S1, AckedBytes, Now),
    drop_sent_when_idle(S2).

ack_bytes(S, 0, _Now) ->
    S;
ack_bytes(#bbr_state{sent = Sent, delivered = Delivered} = S, Bytes, Now) ->
    case queue:out(Sent) of
        {empty, _} ->
            S#bbr_state{delivered = Delivered + Bytes, delivered_time = Now};
        {{value, #pkt{size = Size} = P}, Rest} when Size =< Bytes ->
            S1 = ack_packet(S#bbr_state{sent = Rest}, P, Size, Now),
            ack_bytes(S1, Bytes - Size, Now);
        {{value, #pkt{size = Size} = P}, Rest} ->
            Remaining = P#pkt{size = Size - Bytes},
            ack_packet(S#bbr_state{sent = queue:in_r(Remaining, Rest)}, P, Bytes, Now)
    end.

%% The last packet taken is the newest one acknowledged.
ack_packet(#bbr_state{delivered = Delivered, lost = Lost, rs = RS} = S, P, Bytes, Now) ->
    #pkt{
        delivered = PDelivered,
        delivered_time = PDeliveredTime,
        first_send_time = PFirstSendTime,
        send_time = SendTime,
        is_app_limited = AppLimited,
        tx_in_flight = TxInFlight,
        lost = PLost
    } = P,
    RS1 = RS#rs{
        has_data = true,
        prior_delivered = PDelivered,
        is_app_limited = AppLimited,
        tx_in_flight = TxInFlight,
        prior_lost = PLost,
        lost = Lost - PLost,
        send_time = SendTime,
        rtt = Now - SendTime,
        send_elapsed = SendTime - PFirstSendTime,
        ack_elapsed = Now - PDeliveredTime
    },
    S#bbr_state{
        delivered = Delivered + Bytes,
        delivered_time = Now,
        first_send_time = SendTime,
        rs = RS1
    }.

%% Nothing in flight means nothing left to match.
drop_sent_when_idle(#bbr_state{bytes_in_flight = 0} = S) ->
    S#bbr_state{sent = queue:new()};
drop_sent_when_idle(S) ->
    S.

%% Section 4.1.2.3 GenerateRateSample.
generate_rate_sample(#bbr_state{rs = #rs{has_data = false}} = S) ->
    clear_app_limited(S);
generate_rate_sample(#bbr_state{rs = RS, lifetime_min_rtt = MinRtt0, delivered = Delivered} = S) ->
    #rs{rtt = Rtt, send_elapsed = SendElapsed, ack_elapsed = AckElapsed, prior_delivered = Prior} =
        RS,
    MinRtt = min(MinRtt0, Rtt),
    S1 = clear_app_limited(S#bbr_state{lifetime_min_rtt = MinRtt}),
    Interval = max(SendElapsed, AckElapsed),
    RSDelivered = Delivered - Prior,
    Rate =
        case (Interval < MinRtt) orelse (Interval =< 0) of
            true -> 0;
            false -> (RSDelivered * ?US_PER_SEC) div Interval
        end,
    S1#bbr_state{rs = RS#rs{delivered = RSDelivered, delivery_rate = Rate}}.

clear_app_limited(#bbr_state{app_limited = AppLimited, delivered = Delivered} = S) when
    AppLimited =/= 0, Delivered > AppLimited
->
    S#bbr_state{app_limited = 0};
clear_app_limited(S) ->
    S.

update_model_and_state(S0, Now) ->
    S1 = update_min_rtt(end_loss_round(update_max_bw(S0)), Now),
    run_state_machine(S1, Now).

update_control_parameters(S) ->
    set_pacing_rate(cap_cwnd(set_cwnd(S))).

%% A new round clears the loss count, ends recovery and starts a new
%% HyStart++ RTT round.
end_loss_round(
    #bbr_state{
        round_start = true,
        in_recovery = WasInRecovery,
        inflight_hi = Hi,
        hystart_curr_rtt = CurrRtt
    } = S
) ->
    S#bbr_state{
        hystart_last_rtt =
            case CurrRtt of
                infinity -> 0;
                _ -> CurrRtt
            end,
        hystart_curr_rtt = infinity,
        hystart_rtt_sample_count = 0,
        loss_in_round = 0,
        bytes_in_round = 0,
        in_recovery = false,
        inflight_hi =
            case WasInRecovery of
                true -> infinity;
                false -> Hi
            end
    };
end_loss_round(S) ->
    S.

%%====================================================================
%% Rounds and filters (Sections 5.5.1 - 5.5.7)
%%====================================================================

%% Section 5.5.1: a round ends on the ACK of a packet sent after it began.
update_round(
    #bbr_state{
        rs = #rs{has_data = true, prior_delivered = Prior},
        next_round_delivered = Next
    } = S
) when Prior >= Next ->
    (start_round(S))#bbr_state{round_count = S#bbr_state.round_count + 1, round_start = true};
update_round(S) ->
    S#bbr_state{round_start = false}.

start_round(#bbr_state{delivered = Delivered} = S) ->
    S#bbr_state{next_round_delivered = Delivered}.

%% Section 5.5.5: app-limited samples count only when they raise max_bw.
update_max_bw(S0) ->
    S = update_round(S0),
    #bbr_state{rs = #rs{delivery_rate = Rate, is_app_limited = AppLimited}, max_bw = MaxBw} = S,
    case (Rate > 0) andalso ((Rate >= MaxBw) orelse (not AppLimited)) of
        true ->
            Cur = max(S#bbr_state.bw_hi_cur, Rate),
            S#bbr_state{bw_hi_cur = Cur, max_bw = max(Cur, S#bbr_state.bw_hi_prev)};
        false ->
            S
    end.

%% Section 5.5.6: max of this and the last ProbeBW cycle that had samples.
advance_max_bw_filter(#bbr_state{cycle_count = Count, bw_hi_cur = 0} = S) ->
    S#bbr_state{cycle_count = Count + 1};
advance_max_bw_filter(#bbr_state{cycle_count = Count, bw_hi_cur = Cur} = S) ->
    S#bbr_state{cycle_count = Count + 1, bw_hi_prev = Cur, bw_hi_cur = 0, max_bw = Cur}.

%% Section 5.5.7: the lowest RTT sample over the last 10 seconds.
update_min_rtt(#bbr_state{min_rtt_stamp = Stamp, min_rtt = MinRtt, rs = #rs{rtt = Rtt}} = S, Now) ->
    Expired = (Now > Stamp + ?MIN_RTT_FILTER_LEN),
    case (Rtt >= 0) andalso ((Rtt < MinRtt) orelse Expired) of
        true -> S#bbr_state{min_rtt = Rtt, min_rtt_stamp = Now};
        false -> S
    end.

%%====================================================================
%% State machine
%%====================================================================

run_state_machine(#bbr_state{mode = startup} = S, _Now) ->
    run_startup(S);
run_state_machine(#bbr_state{mode = drain} = S, _Now) ->
    run_drain(S);
run_state_machine(#bbr_state{mode = probe_rtt} = S, Now) ->
    run_probe_rtt(S, Now);
run_state_machine(#bbr_state{min_rtt_stamp = Stamp} = S, Now) when
    Now - Stamp > ?PROBE_RTT_INTERVAL
->
    enter_probe_rtt(S, Now);
run_state_machine(S, _Now) ->
    advance_probe_bw_phase(S).

%% Startup ends when max_bw has not grown 25% in three ACKs, or when
%% HyStart++ sees the RTT rise.
run_startup(#bbr_state{max_bw = MaxBw, full_bw = FullBw, full_bw_count = Count} = S) ->
    {FullBw1, Count1} =
        case MaxBw >= trunc(FullBw * ?FULL_BW_GROWTH) of
            true -> {MaxBw, 0};
            false -> {FullBw, Count + 1}
        end,
    S1 = S#bbr_state{full_bw = FullBw1, full_bw_count = Count1},
    case (Count1 >= ?FULL_BW_ROUNDS) orelse hystart_should_exit(S1) of
        true -> exit_startup(S1);
        false -> S1
    end.

enter_startup(S) ->
    S#bbr_state{
        mode = startup,
        pacing_gain = ?STARTUP_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN
    }.

exit_startup(S) ->
    S#bbr_state{
        mode = drain,
        pacing_gain = ?DRAIN_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN,
        hystart_rtt_sample_count = 0,
        hystart_last_rtt = 0,
        hystart_curr_rtt = infinity
    }.

%% Drain ends once in flight is down to the BDP.
run_drain(#bbr_state{bytes_in_flight = InFlight, max_datagram_size = MDS} = S) ->
    case InFlight =< max(bdp(S), ?MIN_PIPE_CWND_PKTS * MDS) of
        true -> enter_probe_bw(S);
        false -> S
    end.

enter_probe_bw(S) ->
    S#bbr_state{
        mode = probe_bw_cruise,
        pacing_gain = ?PROBE_BW_CRUISE_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN
    }.

%% DOWN until in flight is at the BDP, CRUISE for an ACK, REFILL until
%% in flight reaches the BDP, UP for an ACK.
advance_probe_bw_phase(
    #bbr_state{mode = Mode, bytes_in_flight = InFlight, max_datagram_size = MDS} = S
) ->
    Bdp = max(bdp(S), ?MIN_PIPE_CWND_PKTS * MDS),
    case Mode of
        probe_bw_down when InFlight =< Bdp ->
            S#bbr_state{mode = probe_bw_cruise, pacing_gain = ?PROBE_BW_CRUISE_PACING_GAIN};
        probe_bw_cruise ->
            S#bbr_state{mode = probe_bw_refill, pacing_gain = ?PROBE_BW_REFILL_PACING_GAIN};
        probe_bw_refill when InFlight >= Bdp ->
            S#bbr_state{mode = probe_bw_up, pacing_gain = ?PROBE_BW_UP_PACING_GAIN};
        probe_bw_up ->
            advance_max_bw_filter(S#bbr_state{
                mode = probe_bw_down, pacing_gain = ?PROBE_BW_DOWN_PACING_GAIN
            });
        _ ->
            S
    end.

enter_probe_rtt(#bbr_state{cwnd = Cwnd} = S, Now) ->
    S#bbr_state{
        mode = probe_rtt,
        prior_cwnd = Cwnd,
        cwnd_gain = ?PROBE_RTT_CWND_GAIN,
        probe_rtt_done_stamp = Now + ?PROBE_RTT_DURATION
    }.

%% ProbeRTT lasts 200 ms and until in flight is down to the minimum
%% window, then restores cwnd.
run_probe_rtt(#bbr_state{probe_rtt_done_stamp = Done, bytes_in_flight = InFlight} = S, Now) ->
    case (Now >= Done) andalso (InFlight =< S#bbr_state.minimum_window) of
        true ->
            (enter_probe_bw(S))#bbr_state{cwnd = S#bbr_state.prior_cwnd, min_rtt_stamp = Now};
        false ->
            S
    end.

%%====================================================================
%% HyStart++ (RFC 9406)
%%====================================================================

hystart_should_exit(#bbr_state{
    hystart_enabled = true,
    hystart_rtt_sample_count = Samples,
    hystart_curr_rtt = CurrRtt,
    hystart_last_rtt = LastRtt
}) when Samples >= ?HYSTART_MIN_SAMPLES, is_integer(CurrRtt), CurrRtt > 0, LastRtt > 0 ->
    (CurrRtt - LastRtt) > rtt_threshold(LastRtt);
hystart_should_exit(_) ->
    false.

rtt_threshold(LastRtt) ->
    max(
        ?HYSTART_MIN_RTT_THRESH, min(LastRtt div ?HYSTART_MIN_RTT_DIVISOR, ?HYSTART_MAX_RTT_THRESH)
    ).

update_hystart_rtt(
    #bbr_state{
        hystart_enabled = true,
        mode = startup,
        hystart_curr_rtt = CurrRtt,
        hystart_rtt_sample_count = Count
    } = S,
    Rtt
) ->
    S#bbr_state{hystart_curr_rtt = min(CurrRtt, Rtt), hystart_rtt_sample_count = Count + 1};
update_hystart_rtt(S, _Rtt) ->
    S.

%%====================================================================
%% Loss
%%====================================================================

%% @doc Process lost packets.
-spec on_packets_lost(cc_state(), non_neg_integer()) -> cc_state().
on_packets_lost(State, LostBytes) ->
    on_packets_lost_at(State, LostBytes, now_us()).

%% @doc Process `LostBytes' declared lost at time `Now'.
-spec on_packets_lost_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_packets_lost_at(S, LostBytes, _Now) ->
    #bbr_state{bytes_in_flight = InFlight, sent = Sent, lost = Lost, loss_in_round = LossInRound} =
        S,
    drop_sent_when_idle(S#bbr_state{
        bytes_in_flight = max(0, InFlight - LostBytes),
        sent = discard_bytes(Sent, LostBytes),
        lost = Lost + LostBytes,
        loss_in_round = LossInRound + LostBytes
    }).

%% @doc Handle a congestion event (packet loss detected).
-spec on_congestion_event(cc_state(), non_neg_integer()) -> cc_state().
on_congestion_event(State, SentTimeMs) ->
    on_congestion_event_at(State, SentTimeMs, now_us()).

%% @doc Congestion event for a packet sent at `SentTimeMs', at `Now'.
-spec on_congestion_event_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_congestion_event_at(
    #bbr_state{in_recovery = true, recovery_start = Start} = S, SentTimeMs, _Now
) when
    SentTimeMs * 1000 =< Start
->
    S;
on_congestion_event_at(
    #bbr_state{in_recovery = true, recovery_start = Start, min_recovery_duration = Min} = S,
    _SentTimeMs,
    Now
) when Now - Start < Min ->
    S;
on_congestion_event_at(S, _SentTimeMs, Now) ->
    congestion_response(S, Now).

%% Loss above LossThresh in the round cuts max_bw by Beta and caps
%% in flight at its current volume.
congestion_response(S, Now) ->
    #bbr_state{
        bytes_in_round = BytesInRound,
        loss_in_round = LossInRound,
        max_bw = MaxBw,
        bytes_in_flight = InFlight,
        inflight_hi = Hi
    } = S,
    S1 =
        case (BytesInRound > 0) andalso (LossInRound / BytesInRound > ?LOSS_THRESH) of
            true -> S#bbr_state{max_bw = trunc(MaxBw * ?BETA), inflight_hi = min(Hi, InFlight)};
            false -> S
        end,
    S1#bbr_state{in_recovery = true, recovery_start = Now, loss_in_round = 0, bytes_in_round = 0}.

%% @doc Handle ECN-CE signal.
-spec on_ecn_ce(cc_state(), non_neg_integer()) -> cc_state().
on_ecn_ce(State, NewCECount) ->
    on_ecn_ce_at(State, NewCECount, now_us()).

%% @doc ECN-CE count `NewCECount' reported at time `Now'.
-spec on_ecn_ce_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_ecn_ce_at(#bbr_state{ecn_ce_counter = Old} = S, NewCECount, _Now) when NewCECount =< Old ->
    S;
on_ecn_ce_at(#bbr_state{max_bw = MaxBw} = S, NewCECount, Now) ->
    S#bbr_state{
        max_bw = trunc(MaxBw * ?BETA),
        ecn_ce_counter = NewCECount,
        in_recovery = true,
        recovery_start = Now
    }.

%% @doc BBR does not cut its model on loss, so there is nothing to undo.
-spec on_spurious_congestion(cc_state()) -> cc_state().
on_spurious_congestion(State) ->
    State.

%% @doc Handle persistent congestion: start over from Startup.
-spec on_persistent_congestion(cc_state()) -> cc_state().
on_persistent_congestion(State) ->
    on_persistent_congestion_at(State, now_us()).

%% @doc Persistent congestion declared at time `Now'.
-spec on_persistent_congestion_at(cc_state(), integer()) -> cc_state().
on_persistent_congestion_at(#bbr_state{minimum_window = MinimumWindow} = S, _Now) ->
    (enter_startup(S))#bbr_state{
        cwnd = MinimumWindow,
        max_bw = 0,
        bw_hi_cur = 0,
        bw_hi_prev = 0,
        min_rtt = infinity,
        in_recovery = false,
        recovery_start = 0,
        full_bw = 0,
        full_bw_count = 0,
        inflight_hi = infinity,
        hystart_rtt_sample_count = 0,
        hystart_last_rtt = 0,
        hystart_curr_rtt = infinity
    }.

%% @doc Detect persistent congestion from lost packets.
-spec detect_persistent_congestion(
    [{non_neg_integer(), non_neg_integer()}],
    non_neg_integer(),
    cc_state()
) -> boolean().
detect_persistent_congestion([], _PTO, _State) ->
    false;
detect_persistent_congestion([_], _PTO, _State) ->
    false;
detect_persistent_congestion(LostPackets, PTO, _State) ->
    Times = [T || {_PN, T} <- LostPackets],
    (lists:max(Times) - lists:min(Times)) >= PTO * ?PERSISTENT_CONGESTION_THRESHOLD.

%%====================================================================
%% Congestion window (Section 5.6.4)
%%====================================================================

min_pipe_cwnd(#bbr_state{max_datagram_size = MDS, minimum_window = MinWindow}) ->
    max(?MIN_PIPE_CWND_PKTS * MDS, MinWindow).

bdp(#bbr_state{min_rtt = infinity}) ->
    0;
bdp(#bbr_state{max_bw = MaxBw, min_rtt = MinRtt}) ->
    (MaxBw * MinRtt) div ?US_PER_SEC.

%% cwnd is cwnd_gain x BDP, at least four packets.
set_cwnd(#bbr_state{cwnd_gain = Gain, max_datagram_size = MDS} = S) ->
    Bdp = max(bdp(S), ?MIN_PIPE_CWND_PKTS * MDS),
    S#bbr_state{cwnd = max(trunc(Gain * Bdp), min_pipe_cwnd(S))}.

%% Loss caps cwnd at the in-flight volume it was seen at, outside
%% Startup and Drain.
cap_cwnd(#bbr_state{mode = Mode, inflight_hi = Hi, cwnd = Cwnd} = S) when
    Mode =/= startup, Mode =/= drain, Hi =/= infinity
->
    S#bbr_state{cwnd = max(min(Cwnd, Hi), min_pipe_cwnd(S))};
cap_cwnd(S) ->
    S.

%%====================================================================
%% Pacing rate and send quantum (Sections 5.6.2, 5.6.3)
%%====================================================================

%% Pacing rate is pacing_gain x max_bw less 1%; no sample, no change.
set_pacing_rate(#bbr_state{max_bw = 0} = S) ->
    S;
set_pacing_rate(#bbr_state{max_bw = Bw, pacing_gain = Gain, max_datagram_size = MDS} = S) ->
    Rate = max(1, trunc(Gain * Bw * (100 - ?PACING_MARGIN_PERCENT) / 100)),
    S#bbr_state{pacing_rate = Rate, send_quantum = pacing_max_burst(MDS, Rate)}.

%% Two milliseconds at the paced rate, floored at 12 packets.
pacing_max_burst(MDS, PacingRate) ->
    max(12 * MDS, PacingRate div 500).

%% @doc Feed the smoothed RTT (ms) to HyStart++.
-spec update_pacing_rate(cc_state(), non_neg_integer()) -> cc_state().
update_pacing_rate(State, SmoothedRTT) when SmoothedRTT > 0 ->
    update_hystart_rtt(State, SmoothedRTT);
update_pacing_rate(State, _SmoothedRTT) ->
    State.

%% @doc Check if pacing allows sending Size bytes.
-spec pacing_allows(cc_state(), non_neg_integer()) -> boolean().
pacing_allows(#bbr_state{pacing_rate = 0}, _Size) ->
    true;
pacing_allows(
    #bbr_state{
        pacing_tokens = Tokens,
        send_quantum = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    },
    Size
) ->
    refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, now_us()) >= Size.

%% @doc Get tokens for sending.
-spec get_pacing_tokens(cc_state(), non_neg_integer()) -> {non_neg_integer(), cc_state()}.
get_pacing_tokens(#bbr_state{pacing_rate = 0} = State, Size) ->
    {Size, State};
get_pacing_tokens(
    #bbr_state{
        pacing_tokens = Tokens,
        send_quantum = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    } = State,
    Size
) ->
    Now = now_us(),
    NewTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
    Allowed = min(Size, NewTokens),
    {Allowed, State#bbr_state{pacing_tokens = NewTokens - Allowed, last_pacing_update = Now}}.

%% @doc Pacing delay in milliseconds before Size bytes may be sent.
-spec pacing_delay(cc_state(), non_neg_integer()) -> non_neg_integer().
pacing_delay(#bbr_state{pacing_rate = 0}, _Size) ->
    0;
pacing_delay(
    #bbr_state{
        pacing_tokens = Tokens,
        send_quantum = MaxBurst,
        pacing_rate = Rate,
        last_pacing_update = LastUpdate
    },
    Size
) ->
    CurrentTokens = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, now_us()),
    case CurrentTokens >= Size of
        true -> 0;
        false -> delay_ms(Size - CurrentTokens, Rate)
    end.

delay_ms(Deficit, Rate) ->
    SafeRate = max(Rate, 1),
    max(1, (Deficit * 1000 + SafeRate - 1) div SafeRate).

%% @doc Fused cwnd + pacing check for the hot send path.
-spec send_check(cc_state(), non_neg_integer(), non_neg_integer()) ->
    {ok, cc_state()}
    | {blocked_cwnd, non_neg_integer()}
    | {blocked_pacing, non_neg_integer()}.
send_check(
    #bbr_state{
        cwnd = Cwnd,
        bytes_in_flight = InFlight,
        control_allowance = Allowance,
        pacing_rate = Rate
    } = State,
    Size,
    Urgency
) ->
    CwndLimit =
        case Urgency of
            0 -> Cwnd + Allowance;
            _ -> Cwnd
        end,
    case InFlight + Size =< CwndLimit of
        false ->
            {blocked_cwnd, max(0, Cwnd - InFlight)};
        true when Rate =:= 0 ->
            {ok, State};
        true ->
            #bbr_state{
                pacing_tokens = Tokens,
                send_quantum = MaxBurst,
                last_pacing_update = LastUpdate
            } = State,
            Now = now_us(),
            Refreshed = refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now),
            case Refreshed >= Size of
                true ->
                    {ok, State#bbr_state{
                        pacing_tokens = Refreshed - Size, last_pacing_update = Now
                    }};
                false ->
                    {blocked_pacing, delay_ms(Size - Refreshed, Rate)}
            end
    end.

%% Elapsed is µs, Rate is bytes/sec.
refill_tokens_at(Tokens, MaxBurst, Rate, LastUpdate, Now) ->
    Added = (max(0, Now - LastUpdate) * Rate) div ?US_PER_SEC,
    min(MaxBurst, Tokens + Added).

%%====================================================================
%% MTU, reset and queries
%%====================================================================

%% @doc Update congestion control state when MTU changes.
-spec update_mtu(cc_state(), pos_integer()) -> cc_state().
update_mtu(#bbr_state{max_datagram_size = OldMDS} = State, NewMTU) when NewMTU =:= OldMDS ->
    State;
update_mtu(#bbr_state{max_datagram_size = OldMDS, minimum_window = OldMinWin} = State, NewMTU) ->
    NewMinimumWindow = max(2 * NewMTU, (OldMinWin * NewMTU) div OldMDS),
    ?LOG_DEBUG(
        #{what => bbr_mtu_updated, old_mtu => OldMDS, new_mtu => NewMTU},
        ?QUIC_LOG_META
    ),
    State#bbr_state{
        max_datagram_size = NewMTU,
        minimum_window = NewMinimumWindow,
        send_quantum = pacing_max_burst(NewMTU, State#bbr_state.pacing_rate)
    }.

%% @doc Get the current congestion window.
-spec cwnd(cc_state()) -> non_neg_integer().
cwnd(#bbr_state{cwnd = Cwnd}) -> Cwnd.

%% @doc Drop bytes for a discarded packet number space. Not a
%% congestion event: no window or recovery change.
-spec on_packets_discarded(cc_state(), non_neg_integer()) -> cc_state().
on_packets_discarded(#bbr_state{bytes_in_flight = B, sent = Sent} = State, Bytes) ->
    drop_sent_when_idle(State#bbr_state{
        bytes_in_flight = max(0, B - Bytes),
        sent = discard_bytes(Sent, Bytes)
    }).

discard_bytes(Sent, 0) ->
    Sent;
discard_bytes(Sent, Bytes) ->
    case queue:out(Sent) of
        {empty, _} -> Sent;
        {{value, #pkt{size = Size}}, Rest} when Size =< Bytes -> discard_bytes(Rest, Bytes - Size);
        {{value, #pkt{size = Size} = P}, Rest} -> queue:in_r(P#pkt{size = Size - Bytes}, Rest)
    end.

%% @doc Start over after a Retry, keeping every configured value.
-spec reset_for_retry(cc_state()) -> cc_state().
reset_for_retry(#bbr_state{} = State) ->
    #bbr_state{
        max_datagram_size = MDS,
        initial_window = IW,
        minimum_window = MinWin,
        min_recovery_duration = MinRec
    } = State,
    new(#{
        max_datagram_size => MDS,
        initial_window => IW,
        minimum_window => MinWin,
        min_recovery_duration => MinRec div 1000
    }).

%% @doc The window this controller was configured with.
-spec initial_window(cc_state()) -> non_neg_integer().
initial_window(#bbr_state{initial_window = IW}) -> IW.

%% @doc BBR has no slow start threshold.
-spec ssthresh(cc_state()) -> non_neg_integer() | infinity.
ssthresh(_State) -> infinity.

%% @doc Get bytes currently in flight.
-spec bytes_in_flight(cc_state()) -> non_neg_integer().
bytes_in_flight(#bbr_state{bytes_in_flight = B}) -> B.

%% @doc Check if we can send more bytes.
-spec can_send(cc_state(), non_neg_integer()) -> boolean().
can_send(#bbr_state{cwnd = Cwnd, bytes_in_flight = InFlight}, Size) ->
    InFlight + Size =< Cwnd.

%% @doc Check if a control message can be sent.
-spec can_send_control(cc_state(), non_neg_integer()) -> boolean().
can_send_control(
    #bbr_state{cwnd = Cwnd, bytes_in_flight = InFlight, control_allowance = Allowance}, Size
) ->
    InFlight + Size =< Cwnd + Allowance.

%% @doc Get the available congestion window.
-spec available_cwnd(cc_state()) -> non_neg_integer().
available_cwnd(#bbr_state{cwnd = Cwnd, bytes_in_flight = InFlight}) ->
    max(0, Cwnd - InFlight).

%% @doc Startup plays the role of slow start.
-spec in_slow_start(cc_state()) -> boolean().
in_slow_start(#bbr_state{mode = startup}) -> true;
in_slow_start(_State) -> false.

%% @doc Check if in recovery phase.
-spec in_recovery(cc_state()) -> boolean().
in_recovery(#bbr_state{in_recovery = R}) -> R.

%% @doc Get the current max datagram size.
-spec max_datagram_size(cc_state()) -> pos_integer().
max_datagram_size(#bbr_state{max_datagram_size = MDS}) -> MDS.

%% @doc Minimum recovery duration setting, in milliseconds.
-spec min_recovery_duration(cc_state()) -> non_neg_integer().
min_recovery_duration(#bbr_state{min_recovery_duration = D}) -> D div 1000.

%% @doc Get the current ECN-CE counter.
-spec ecn_ce_counter(cc_state()) -> non_neg_integer().
ecn_ce_counter(#bbr_state{ecn_ce_counter = C}) -> C.

%% @doc The model and control parameters, for logging and tests.
-spec info(cc_state()) -> #{atom() => term()}.
info(#bbr_state{} = S) ->
    #{
        mode => S#bbr_state.mode,
        pacing_gain => S#bbr_state.pacing_gain,
        cwnd_gain => S#bbr_state.cwnd_gain,
        cwnd => S#bbr_state.cwnd,
        pacing_rate => S#bbr_state.pacing_rate,
        send_quantum => S#bbr_state.send_quantum,
        bytes_in_flight => S#bbr_state.bytes_in_flight,
        delivered => S#bbr_state.delivered,
        lost => S#bbr_state.lost,
        app_limited => (S#bbr_state.app_limited =/= 0),
        round_count => S#bbr_state.round_count,
        cycle_count => S#bbr_state.cycle_count,
        max_bw => S#bbr_state.max_bw,
        min_rtt => S#bbr_state.min_rtt,
        bdp => bdp(S),
        full_bw => S#bbr_state.full_bw,
        full_bw_count => S#bbr_state.full_bw_count,
        delivery_rate => (S#bbr_state.rs)#rs.delivery_rate,
        rs_app_limited => (S#bbr_state.rs)#rs.is_app_limited,
        in_recovery => S#bbr_state.in_recovery,
        prior_cwnd => S#bbr_state.prior_cwnd,
        probe_rtt_done_stamp => S#bbr_state.probe_rtt_done_stamp,
        sent_packets => queue:len(S#bbr_state.sent)
    }.

now_us() ->
    erlang:monotonic_time(microsecond).
