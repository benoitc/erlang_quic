%%% -*- erlang -*-
%%%
%%% QUIC BBRv3 Congestion Control
%%% draft-ietf-ccwg-bbr-07
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc BBRv3 congestion control, following draft-ietf-ccwg-bbr-07.
%%%
%%% BBR builds a model of the path from delivery rate and RTT samples and
%%% paces at the estimated bandwidth, bounding data in flight to a
%%% multiple of the estimated bandwidth-delay product.
%%%
%%% == States (Section 5.1) ==
%%%
%%% - Startup: pacing gain 2.77, cwnd gain 2; exits on a bandwidth
%%%   plateau or on excessive loss.
%%% - Drain: pacing gain 0.5 until in flight drops to the BDP, or after
%%%   3 rounds.
%%% - ProbeBW: DOWN (0.90), CRUISE (1.0), REFILL (1.0), UP (1.25, cwnd
%%%   gain 2.25).
%%% - ProbeRTT: cwnd gain 0.5 for 200 ms and one round when min_rtt has
%%%   not been refreshed for 10 seconds.
%%%
%%% == Units ==
%%%
%%% Volumes are bytes, times are microseconds of `erlang:monotonic_time',
%%% rates are bytes per second.
%%%
%%% == Per-packet state ==
%%%
%%% The `quic_cc' callbacks report bytes, not packets, so the delivery
%%% rate sampler (Section 4.1) keeps the per-packet snapshots in send
%%% order and matches acknowledged, lost and discarded bytes against the
%%% oldest outstanding ones. QUIC acknowledges and declares packets lost
%%% mostly in send order, so a reordered acknowledgment only shifts a
%%% sample to a neighbouring packet's snapshot.
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

-define(STARTUP_PACING_GAIN, 2.77).
-define(DRAIN_PACING_GAIN, 0.5).
-define(DEFAULT_CWND_GAIN, 2.0).
-define(PROBE_BW_DOWN_PACING_GAIN, 0.9).
-define(PROBE_BW_CRUISE_PACING_GAIN, 1.0).
-define(PROBE_BW_REFILL_PACING_GAIN, 1.0).
-define(PROBE_BW_UP_PACING_GAIN, 1.25).
-define(PROBE_BW_UP_CWND_GAIN, 2.25).
-define(PROBE_RTT_PACING_GAIN, 1.0).
-define(PROBE_RTT_CWND_GAIN, 0.5).
-define(PACING_MARGIN_PERCENT, 1).
-define(LOSS_THRESH, 0.02).
-define(BETA, 0.7).
-define(HEADROOM, 0.15).
-define(MIN_PIPE_CWND_PKTS, 4).
-define(STARTUP_FULL_LOSS_CNT, 6).
-define(FULL_BW_GROWTH, 1.25).
-define(FULL_BW_ROUNDS, 3).
-define(DRAIN_MAX_ROUNDS, 3).
-define(RENO_ROUNDS_BOUND, 63).
-define(MAX_PROBE_UP_ROUNDS, 30).

%% Times in microseconds.
-define(MIN_RTT_FILTER_LEN, 10000000).
-define(PROBE_RTT_DURATION, 200000).
-define(PROBE_WAIT_BASE, 2000000).
-define(PROBE_WAIT_RAND, 1000000).
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
    cwnd_limited_now = false :: boolean(),
    cwnd_limited_prev = false :: boolean(),
    sent = queue:new() :: queue:queue(#pkt{}),
    rs = #rs{} :: #rs{},

    %% State machine (Section 2.7)
    mode = startup :: bbr_mode(),
    pacing_gain = ?STARTUP_PACING_GAIN :: float(),
    cwnd_gain = ?DEFAULT_CWND_GAIN :: float(),
    round_count = 0 :: non_neg_integer(),
    round_start = false :: boolean(),
    next_round_delivered = 0 :: non_neg_integer(),
    idle_restart = false :: boolean(),
    drain_start_round = 0 :: non_neg_integer(),

    %% Bandwidth model (Sections 2.9.1, 2.11)
    max_bw = 0 :: non_neg_integer(),
    bw_hi_cur = 0 :: non_neg_integer(),
    bw_hi_prev = 0 :: non_neg_integer(),
    cycle_count = 0 :: non_neg_integer(),
    bw_shortterm = infinity :: volume(),
    bw = 0 :: non_neg_integer(),

    %% Volume model (Section 2.9.2)
    min_rtt = infinity :: non_neg_integer() | infinity,
    min_rtt_stamp = 0 :: integer(),
    min_rtt_expired = false :: boolean(),
    inflight_longterm = infinity :: volume(),
    inflight_shortterm = infinity :: volume(),

    %% Congestion signals (Section 2.10, 5.5.10)
    bw_latest = 0 :: non_neg_integer(),
    inflight_latest = 0 :: non_neg_integer(),
    loss_round_delivered = 0 :: non_neg_integer(),
    loss_round_start = false :: boolean(),
    is_loss_in_round = false :: boolean(),
    loss_events_in_round = 0 :: non_neg_integer(),

    %% Startup (Section 2.13)
    full_bw_reached = false :: boolean(),
    full_bw_now = false :: boolean(),
    full_bw = 0 :: non_neg_integer(),
    full_bw_count = 0 :: non_neg_integer(),

    %% ProbeBW (Section 2.14)
    is_bw_probe_stopping = false :: boolean(),
    check_probe_loss = false :: boolean(),
    bw_probe_up_acked = 0 :: non_neg_integer(),
    probe_up_acked_per_inc = infinity :: volume(),
    bw_probe_up_rounds = 0 :: non_neg_integer(),
    rounds_since_probe_up = 0 :: non_neg_integer(),
    bw_probe_wait = 0 :: non_neg_integer(),
    cycle_stamp = 0 :: integer(),
    prev_probe_too_high = false :: boolean(),
    prev_probe_precautionary = false :: boolean(),

    %% Undo (Section 2.15)
    undo_state = none :: none | startup | probe_bw_up | ce,
    undo_bw_shortterm = 0 :: volume(),
    undo_inflight_shortterm = 0 :: volume(),
    undo_inflight_longterm = 0 :: volume(),
    prior_cwnd = 0 :: non_neg_integer(),

    %% ProbeRTT (Section 2.16)
    probe_rtt_done_stamp = 0 :: integer(),
    probe_rtt_round_done = false :: boolean(),
    probe_rtt_cwnd = infinity :: volume(),

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
    InitialCwnd = max(maps:get(initial_window, Opts, 10 * MDS), ?MIN_PIPE_CWND_PKTS * MDS),
    S0 = #bbr_state{
        max_datagram_size = MDS,
        initial_window = InitialCwnd,
        minimum_window = MinimumWindow,
        min_recovery_duration = MinRecoveryDuration,
        cwnd = InitialCwnd,
        min_rtt_stamp = Now,
        last_pacing_update = Now
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
        cwnd = Cwnd,
        max_datagram_size = MDS,
        sent = Sent
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
        cwnd_limited_now = State#bbr_state.cwnd_limited_now orelse (InFlight + MDS > Cwnd),
        sent = queue:in(Pkt, Sent)
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
    %% Losses this ACK reveals come after it, so the model sees the
    %% recovery this ACK may end.
    State3 = update_model_and_state(State2, Now),
    update_control_parameters(maybe_exit_recovery(State3)).

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

%% Recovery ends on the ACK of a packet sent after it began (RFC 9002 Section 7.3.2).
maybe_exit_recovery(
    #bbr_state{in_recovery = true, recovery_start = Start, rs = #rs{has_data = true, send_time = T}} =
        S
) when T > Start ->
    restore_cwnd(S#bbr_state{in_recovery = false});
maybe_exit_recovery(S) ->
    S.

update_model_and_state(S0, Now) ->
    S1 = update_latest_delivery_signals(S0),
    S3 = update_congestion_signals(S1),
    S4 = check_full_bw_reached(S3),
    S5 = check_startup_done(S4),
    S6 = check_drain_done(S5, Now),
    S7 = update_probe_bw_cycle_phase(S6, Now),
    S8 = update_min_rtt(S7, Now),
    S9 = check_probe_rtt(S8, Now),
    S10 = advance_latest_delivery_signals(S9),
    bound_bw_for_model(S10).

update_control_parameters(S) ->
    set_pacing_rate(bound_cwnd_for_model(set_cwnd(S))).

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
    #bbr_state{
        round_count = Round,
        rounds_since_probe_up = SinceUp,
        cwnd_limited_now = LimitedNow
    } = S,
    (start_round(S))#bbr_state{
        round_count = Round + 1,
        rounds_since_probe_up = SinceUp + 1,
        round_start = true,
        cwnd_limited_prev = LimitedNow,
        cwnd_limited_now = false
    };
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

%% Section 5.3.4.3 UpdateMinRTT.
update_min_rtt(#bbr_state{min_rtt_stamp = Stamp, min_rtt = MinRtt, rs = #rs{rtt = Rtt}} = S, Now) ->
    Expired = (Now > Stamp + ?MIN_RTT_FILTER_LEN),
    S1 =
        case Expired of
            true -> S#bbr_state{probe_rtt_cwnd = bdp_multiple(S, ?PROBE_RTT_CWND_GAIN)};
            false -> S
        end,
    S2 = S1#bbr_state{min_rtt_expired = Expired},
    case (Rtt >= 0) andalso ((Rtt < MinRtt) orelse Expired) of
        true -> S2#bbr_state{min_rtt = Rtt, min_rtt_stamp = Now};
        false -> S2
    end.

%%====================================================================
%% Startup and Drain (Sections 5.3.1, 5.3.2)
%%====================================================================

enter_startup(S) ->
    S#bbr_state{
        mode = startup,
        pacing_gain = ?STARTUP_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN
    }.

reset_full_bw(S) ->
    S#bbr_state{full_bw = 0, full_bw_count = 0, full_bw_now = false}.

%% Section 5.3.1.2: three non-app-limited rounds without 25% growth.
check_full_bw_reached(#bbr_state{full_bw_now = true} = S) ->
    S;
check_full_bw_reached(#bbr_state{round_start = false} = S) ->
    S;
check_full_bw_reached(#bbr_state{rs = #rs{is_app_limited = true}} = S) ->
    S;
check_full_bw_reached(#bbr_state{rs = #rs{delivery_rate = Rate}, full_bw = FullBw} = S) when
    Rate >= FullBw * ?FULL_BW_GROWTH
->
    (reset_full_bw(S))#bbr_state{full_bw = Rate};
check_full_bw_reached(#bbr_state{full_bw_count = Count} = S) ->
    Now = (Count + 1 >= ?FULL_BW_ROUNDS),
    S#bbr_state{
        full_bw_count = Count + 1,
        full_bw_now = Now,
        full_bw_reached = S#bbr_state.full_bw_reached orelse Now
    }.

check_startup_done(S0) ->
    S = check_startup_high_loss(S0),
    case S of
        #bbr_state{mode = startup, full_bw_reached = true} -> enter_drain(S);
        _ -> S
    end.

%% Section 5.3.1.3: six loss events and LossThresh exceeded in recovery.
check_startup_high_loss(#bbr_state{full_bw_reached = true} = S) ->
    S;
check_startup_high_loss(#bbr_state{loss_round_start = false} = S) ->
    S;
check_startup_high_loss(#bbr_state{in_recovery = false} = S) ->
    S;
check_startup_high_loss(#bbr_state{loss_events_in_round = N} = S) when
    N < ?STARTUP_FULL_LOSS_CNT
->
    S;
check_startup_high_loss(#bbr_state{rs = RS, inflight_latest = Latest} = S) ->
    case is_inflight_too_high(RS) of
        true ->
            S#bbr_state{
                undo_state = startup,
                full_bw_reached = true,
                inflight_longterm = max(bdp(S), Latest)
            };
        false ->
            S
    end.

enter_drain(#bbr_state{round_count = Round} = S) ->
    S#bbr_state{
        mode = drain,
        pacing_gain = ?DRAIN_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN,
        drain_start_round = Round
    }.

check_drain_done(#bbr_state{mode = drain} = S, Now) ->
    #bbr_state{bytes_in_flight = InFlight, round_count = Round, drain_start_round = Start} = S,
    case (InFlight =< inflight(S, 1.0)) orelse (Round > Start + ?DRAIN_MAX_ROUNDS) of
        true -> enter_probe_bw(S, Now);
        false -> S
    end;
check_drain_done(S, _Now) ->
    S.

%%====================================================================
%% ProbeBW (Section 5.3.3)
%%====================================================================

enter_probe_bw(S, Now) ->
    start_probe_bw_down(S#bbr_state{cwnd_gain = ?DEFAULT_CWND_GAIN}, Now).

start_probe_bw_down(S0, Now) ->
    S = pick_probe_wait(reset_congestion_signals(S0)),
    (start_round(S))#bbr_state{
        probe_up_acked_per_inc = infinity,
        cycle_stamp = Now,
        is_bw_probe_stopping = true,
        mode = probe_bw_down,
        pacing_gain = ?PROBE_BW_DOWN_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN
    }.

start_probe_bw_cruise(S) ->
    S#bbr_state{
        mode = probe_bw_cruise,
        pacing_gain = ?PROBE_BW_CRUISE_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN
    }.

start_probe_bw_refill(S) ->
    (start_round(reset_short_term_model(S)))#bbr_state{
        bw_probe_up_rounds = 0,
        bw_probe_up_acked = 0,
        prev_probe_precautionary = false,
        is_bw_probe_stopping = false,
        mode = probe_bw_refill,
        pacing_gain = ?PROBE_BW_REFILL_PACING_GAIN,
        cwnd_gain = ?DEFAULT_CWND_GAIN
    }.

start_probe_bw_up(#bbr_state{rs = #rs{delivery_rate = Rate}} = S) ->
    S1 = (reset_full_bw(start_round(S)))#bbr_state{
        full_bw = Rate,
        mode = probe_bw_up,
        pacing_gain = ?PROBE_BW_UP_PACING_GAIN,
        cwnd_gain = ?PROBE_BW_UP_CWND_GAIN
    },
    raise_inflight_longterm_slope(S1).

is_in_probe_bw(probe_bw_down) -> true;
is_in_probe_bw(probe_bw_cruise) -> true;
is_in_probe_bw(probe_bw_refill) -> true;
is_in_probe_bw(probe_bw_up) -> true;
is_in_probe_bw(_) -> false.

is_probing_bw(startup) -> true;
is_probing_bw(probe_bw_refill) -> true;
is_probing_bw(probe_bw_up) -> true;
is_probing_bw(_) -> false.

%% Section 5.3.3.9 UpdateProbeBWCyclePhase.
update_probe_bw_cycle_phase(#bbr_state{full_bw_reached = false} = S, _Now) ->
    S;
update_probe_bw_cycle_phase(S0, Now) ->
    case adapt_long_term_model(S0) of
        {true, S} ->
            S;
        {false, #bbr_state{mode = Mode} = S} ->
            case is_in_probe_bw(Mode) of
                true -> probe_bw_phase(Mode, S, Now);
                false -> S
            end
    end.

probe_bw_phase(probe_bw_down, S, Now) ->
    case is_time_to_probe_bw(S, Now) of
        {true, S1} ->
            S1;
        false ->
            case is_time_to_cruise(S) of
                true -> start_probe_bw_cruise(S);
                false -> S
            end
    end;
probe_bw_phase(probe_bw_cruise, S, Now) ->
    case is_time_to_probe_bw(S, Now) of
        {true, S1} -> S1;
        false -> S
    end;
probe_bw_phase(probe_bw_refill, #bbr_state{round_start = true} = S, _Now) ->
    start_probe_bw_up(S#bbr_state{check_probe_loss = true});
probe_bw_phase(probe_bw_refill, S, _Now) ->
    S;
probe_bw_phase(probe_bw_up, S0, Now) ->
    case is_time_to_go_down(S0) of
        {true, S} -> start_probe_bw_down(S#bbr_state{prev_probe_too_high = false}, Now);
        {false, S} -> S
    end.

%% Section 5.3.3.8.3: after a random 2-3 s or a Reno-scale round count.
is_time_to_probe_bw(#bbr_state{cycle_stamp = Stamp, bw_probe_wait = Wait} = S, Now) ->
    case (Now > Stamp + Wait) orelse is_reno_coexistence_probe_time(S) of
        true -> {true, start_probe_bw_refill(S)};
        false -> false
    end.

pick_probe_wait(S) ->
    S#bbr_state{
        rounds_since_probe_up = rand:uniform(2) - 1,
        bw_probe_wait = ?PROBE_WAIT_BASE + rand:uniform(?PROBE_WAIT_RAND + 1) - 1
    }.

%% Target inflight in packets, the unit the round bound is counted in.
is_reno_coexistence_probe_time(
    #bbr_state{rounds_since_probe_up = Rounds, max_datagram_size = MDS} = S
) ->
    RenoRounds = target_inflight(S) div MDS,
    Rounds >= min(RenoRounds, ?RENO_ROUNDS_BOUND).

target_inflight(#bbr_state{cwnd = Cwnd} = S) ->
    min(bdp(S), Cwnd).

is_time_to_cruise(#bbr_state{bytes_in_flight = InFlight, max_bw = MaxBw} = S) ->
    (InFlight =< inflight_with_headroom(S)) andalso
        (InFlight =< quantization_budget(S, bdp_multiple(S, MaxBw, 1.0))).

%% Section 5.3.3.7: on a bandwidth plateau, or at the last loss level.
is_time_to_go_down(
    #bbr_state{prev_probe_too_high = true, bytes_in_flight = InFlight, inflight_longterm = Hi} = S
) when InFlight >= Hi ->
    {true, S#bbr_state{prev_probe_precautionary = true}};
is_time_to_go_down(#bbr_state{cwnd = Cwnd, inflight_longterm = Hi, rs = RS} = S) ->
    case is_cwnd_limited(S) andalso (Cwnd >= Hi) of
        true ->
            {false, (reset_full_bw(S))#bbr_state{full_bw = RS#rs.delivery_rate}};
        false ->
            {S#bbr_state.full_bw_now, S}
    end.

is_cwnd_limited(#bbr_state{cwnd_limited_now = Now, cwnd_limited_prev = Prev}) ->
    Now orelse Prev.

inflight_with_headroom(#bbr_state{inflight_longterm = infinity}) ->
    infinity;
inflight_with_headroom(#bbr_state{inflight_longterm = Hi, max_datagram_size = MDS} = S) ->
    Headroom = max(MDS, trunc(?HEADROOM * Hi)),
    max(Hi - Headroom, min_pipe_cwnd(S)).

raise_inflight_longterm_slope(#bbr_state{bw_probe_up_rounds = Rounds, cwnd = Cwnd} = S) ->
    Growth = 1 bsl Rounds,
    S#bbr_state{
        bw_probe_up_rounds = min(Rounds + 1, ?MAX_PROBE_UP_ROUNDS),
        probe_up_acked_per_inc = max(Cwnd div Growth, S#bbr_state.max_datagram_size)
    }.

probe_inflight_longterm_upward(#bbr_state{cwnd = Cwnd, inflight_longterm = Hi} = S) ->
    case is_cwnd_limited(S) andalso (Cwnd >= Hi) of
        false ->
            S;
        true ->
            #bbr_state{
                bw_probe_up_acked = Acked0,
                probe_up_acked_per_inc = PerInc,
                rs = #rs{newly_acked = NewlyAcked},
                max_datagram_size = MDS
            } = S,
            Acked = Acked0 + NewlyAcked,
            S1 =
                case Acked >= PerInc of
                    true ->
                        Delta = Acked div PerInc,
                        S#bbr_state{
                            bw_probe_up_acked = Acked - Delta * PerInc,
                            inflight_longterm = Hi + Delta * MDS
                        };
                    false ->
                        S#bbr_state{bw_probe_up_acked = Acked}
                end,
            case S1#bbr_state.round_start of
                true -> raise_inflight_longterm_slope(S1);
                false -> S1
            end
    end.

%% Section 5.3.3.9 AdaptLongTermModel; `{true, S}' when it changed state.
adapt_long_term_model(#bbr_state{is_bw_probe_stopping = true, round_start = true} = S0) ->
    #bbr_state{mode = Mode, rs = #rs{is_app_limited = AppLimited}} = S0,
    S1 = S0#bbr_state{check_probe_loss = false, is_bw_probe_stopping = false},
    S2 =
        case is_in_probe_bw(Mode) andalso (not AppLimited) of
            true -> advance_max_bw_filter(S1);
            false -> S1
        end,
    case
        is_in_probe_bw(Mode) andalso S2#bbr_state.prev_probe_precautionary andalso
            (not S2#bbr_state.prev_probe_too_high)
    of
        true -> {true, start_probe_bw_refill(S2)};
        false -> adapt_upper_bounds(S2)
    end;
adapt_long_term_model(S) ->
    adapt_upper_bounds(S).

adapt_upper_bounds(#bbr_state{rs = RS} = S) ->
    case is_inflight_too_high(RS) of
        true ->
            {false, S};
        false ->
            case S#bbr_state.inflight_longterm of
                infinity ->
                    {false, S};
                Hi ->
                    S1 = S#bbr_state{inflight_longterm = max(Hi, RS#rs.tx_in_flight)},
                    case S1#bbr_state.mode of
                        probe_bw_up -> {false, probe_inflight_longterm_upward(S1)};
                        _ -> {false, S1}
                    end
            end
    end.

%%====================================================================
%% ProbeRTT (Section 5.3.4)
%%====================================================================

check_probe_rtt(
    #bbr_state{mode = Mode, min_rtt_expired = true, idle_restart = false} = S0, Now
) when
    Mode =/= probe_rtt
->
    S1 = enter_probe_rtt(save_cwnd(S0)),
    S2 = (start_round(S1))#bbr_state{probe_rtt_done_stamp = 0, is_bw_probe_stopping = true},
    finish_check_probe_rtt(handle_probe_rtt(S2, Now));
check_probe_rtt(#bbr_state{mode = probe_rtt} = S, Now) ->
    finish_check_probe_rtt(handle_probe_rtt(S, Now));
check_probe_rtt(S, _Now) ->
    finish_check_probe_rtt(S).

finish_check_probe_rtt(#bbr_state{rs = #rs{delivered = D}} = S) when D > 0 ->
    S#bbr_state{idle_restart = false};
finish_check_probe_rtt(S) ->
    S.

enter_probe_rtt(S) ->
    S#bbr_state{
        mode = probe_rtt,
        pacing_gain = ?PROBE_RTT_PACING_GAIN,
        cwnd_gain = ?PROBE_RTT_CWND_GAIN
    }.

handle_probe_rtt(S0, Now) ->
    S = mark_app_limited(S0),
    #bbr_state{probe_rtt_done_stamp = Done, bytes_in_flight = InFlight} = S,
    case Done of
        0 ->
            case InFlight =< probe_rtt_cwnd(S) of
                true ->
                    (start_round(S))#bbr_state{
                        probe_rtt_done_stamp = Now + ?PROBE_RTT_DURATION,
                        probe_rtt_round_done = false
                    };
                false ->
                    S
            end;
        _ ->
            S1 =
                case S#bbr_state.round_start of
                    true -> S#bbr_state{probe_rtt_round_done = true};
                    false -> S
                end,
            case S1#bbr_state.probe_rtt_round_done of
                true -> check_probe_rtt_done(S1, Now);
                false -> S1
            end
    end.

check_probe_rtt_done(#bbr_state{probe_rtt_done_stamp = Done} = S, Now) when
    Done =/= 0, Now > Done
->
    exit_probe_rtt(restore_cwnd(S#bbr_state{min_rtt_stamp = Now}), Now);
check_probe_rtt_done(S, _Now) ->
    S.

exit_probe_rtt(S0, Now) ->
    S = reset_short_term_model(S0),
    case S#bbr_state.full_bw_reached of
        true -> start_probe_bw_cruise(start_probe_bw_down(S, Now));
        false -> enter_startup(S)
    end.

probe_rtt_cwnd(#bbr_state{probe_rtt_cwnd = Saved} = S) ->
    max(min(bdp_multiple(S, ?PROBE_RTT_CWND_GAIN), Saved), min_pipe_cwnd(S)).

%%====================================================================
%% Loss and congestion signals (Section 5.5.10)
%%====================================================================

%% @doc Process lost packets.
-spec on_packets_lost(cc_state(), non_neg_integer()) -> cc_state().
on_packets_lost(State, LostBytes) ->
    on_packets_lost_at(State, LostBytes, now_us()).

%% @doc Process `LostBytes' declared lost at time `Now'.
-spec on_packets_lost_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_packets_lost_at(#bbr_state{bytes_in_flight = InFlight} = S, LostBytes, Now) ->
    S1 = lose_bytes(S, LostBytes, Now),
    drop_sent_when_idle(S1#bbr_state{bytes_in_flight = max(0, InFlight - LostBytes)}).

lose_bytes(S, 0, _Now) ->
    S;
lose_bytes(#bbr_state{sent = Sent, lost = Lost} = S, Bytes, Now) ->
    case queue:out(Sent) of
        {empty, _} ->
            note_loss(S#bbr_state{lost = Lost + Bytes}, 1);
        {{value, #pkt{size = Size} = P}, Rest} when Size =< Bytes ->
            S1 = handle_lost_packet(S#bbr_state{sent = Rest, lost = Lost + Size}, P, Now),
            lose_bytes(S1, Bytes - Size, Now);
        {{value, #pkt{size = Size} = P}, Rest} ->
            S1 = S#bbr_state{
                sent = queue:in_r(P#pkt{size = Size - Bytes}, Rest), lost = Lost + Bytes
            },
            handle_lost_packet(S1, P#pkt{size = Bytes}, Now)
    end.

%% Section 5.5.10.2 NoteLoss, for Events lost or CE-marked packets.
note_loss(#bbr_state{is_loss_in_round = false, delivered = Delivered} = S, Events) ->
    S1 = save_state_upon_loss(S#bbr_state{loss_round_delivered = Delivered}),
    note_loss(S1#bbr_state{is_loss_in_round = true}, Events);
note_loss(#bbr_state{loss_events_in_round = N} = S, Events) ->
    S#bbr_state{loss_events_in_round = N + Events}.

%% Section 5.5.10.2 HandleLostPacket.
handle_lost_packet(S0, P, Now) ->
    S = note_loss(S0, 1),
    case S#bbr_state.check_probe_loss of
        false ->
            S;
        true ->
            #pkt{tx_in_flight = TxInFlight, lost = PLost, is_app_limited = AppLimited} = P,
            RS = (S#bbr_state.rs)#rs{
                tx_in_flight = TxInFlight,
                lost = S#bbr_state.lost - PLost,
                is_app_limited = AppLimited
            },
            case is_inflight_too_high(RS) of
                true ->
                    RS1 = RS#rs{tx_in_flight = inflight_at_loss(RS, P#pkt.size)},
                    handle_inflight_too_high(S, RS1, Now);
                false ->
                    S
            end
    end.

%% QUIC has selective acknowledgments, so only the loss rate counts.
is_inflight_too_high(#rs{lost = Lost, tx_in_flight = TxInFlight}) ->
    Lost > TxInFlight * ?LOSS_THRESH.

%% In-flight volume at which losses crossed LossThresh within P.
inflight_at_loss(#rs{tx_in_flight = TxInFlight, lost = Lost}, Size) ->
    InflightPrev = max(0, TxInFlight - Size),
    LostPrev = max(0, Lost - Size),
    LostPrefix = (?LOSS_THRESH * InflightPrev - LostPrev) / (1 - ?LOSS_THRESH),
    max(0, trunc(InflightPrev + LostPrefix)).

handle_inflight_too_high(#bbr_state{mode = Mode} = S0, RS, Now) ->
    S = S0#bbr_state{prev_probe_too_high = true, check_probe_loss = false},
    S1 =
        case RS#rs.is_app_limited of
            false ->
                Hi = max(RS#rs.tx_in_flight, trunc(target_inflight(S) * ?BETA)),
                S#bbr_state{inflight_longterm = Hi};
            true ->
                S
        end,
    case Mode of
        probe_bw_up -> start_probe_bw_down(S1#bbr_state{undo_state = probe_bw_up}, Now);
        _ -> S1
    end.

%% Near the start of ACK processing.
update_latest_delivery_signals(S) ->
    #bbr_state{
        bw_latest = BwLatest,
        inflight_latest = InflightLatest,
        loss_round_delivered = LossRoundDelivered,
        delivered = Delivered,
        rs = #rs{
            delivery_rate = Rate,
            delivered = RSDelivered,
            has_data = HasData,
            prior_delivered = Prior
        }
    } = S,
    S1 = S#bbr_state{
        loss_round_start = false,
        bw_latest = max(BwLatest, Rate),
        inflight_latest = max(InflightLatest, RSDelivered)
    },
    case HasData andalso (Prior >= LossRoundDelivered) of
        true -> S1#bbr_state{loss_round_delivered = Delivered, loss_round_start = true};
        false -> S1
    end.

%% Near the end of ACK processing.
advance_latest_delivery_signals(#bbr_state{loss_round_start = true, rs = RS} = S) ->
    S#bbr_state{
        bw_latest = RS#rs.delivery_rate,
        inflight_latest = RS#rs.delivered,
        loss_events_in_round = 0
    };
advance_latest_delivery_signals(S) ->
    S.

reset_congestion_signals(S) ->
    S#bbr_state{
        is_loss_in_round = false,
        loss_events_in_round = 0,
        bw_latest = 0,
        inflight_latest = 0
    }.

update_congestion_signals(S0) ->
    S = update_max_bw(S0),
    case S#bbr_state.loss_round_start of
        false -> S;
        true -> (adapt_lower_bounds_from_congestion(S))#bbr_state{is_loss_in_round = false}
    end.

%% Once a round outside probing, cut the short-term model by at most Beta.
adapt_lower_bounds_from_congestion(#bbr_state{mode = Mode, is_loss_in_round = Loss} = S) ->
    case (not is_probing_bw(Mode)) andalso Loss of
        true -> loss_lower_bounds(init_lower_bounds(S));
        false -> S
    end.

init_lower_bounds(#bbr_state{bw_shortterm = BwLo, inflight_shortterm = InLo} = S) ->
    S#bbr_state{
        bw_shortterm =
            case BwLo of
                infinity -> S#bbr_state.max_bw;
                _ -> BwLo
            end,
        inflight_shortterm =
            case InLo of
                infinity -> S#bbr_state.cwnd;
                _ -> InLo
            end
    }.

loss_lower_bounds(S) ->
    #bbr_state{
        bw_latest = BwLatest,
        inflight_latest = InflightLatest,
        bw_shortterm = BwLo,
        inflight_shortterm = InLo
    } = S,
    S#bbr_state{
        bw_shortterm = max(BwLatest, trunc(?BETA * BwLo)),
        inflight_shortterm = max(InflightLatest, trunc(?BETA * InLo))
    }.

reset_short_term_model(S) ->
    S#bbr_state{bw_shortterm = infinity, inflight_shortterm = infinity}.

bound_bw_for_model(#bbr_state{max_bw = MaxBw, bw_shortterm = BwLo} = S) ->
    S#bbr_state{bw = min(MaxBw, BwLo)}.

%% @doc Enter recovery when a packet sent after the current recovery
%% period started is lost (RFC 9002 Section 7.3.2).
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
on_congestion_event_at(S, _SentTimeMs, Now) ->
    enter_recovery(S, Now).

%% Section 5.6.4.4 OnEnterFastRecovery.
enter_recovery(S, Now) ->
    S1 = save_state_upon_loss(S),
    S1#bbr_state{in_recovery = true, recovery_start = Now}.

%% Section 5.5.11.1; SaveCwnd() included.
save_state_upon_loss(S0) ->
    S = save_cwnd(S0),
    S#bbr_state{
        undo_state = none,
        undo_bw_shortterm = S#bbr_state.bw_shortterm,
        undo_inflight_shortterm = S#bbr_state.inflight_shortterm,
        undo_inflight_longterm = S#bbr_state.inflight_longterm
    }.

%% @doc Treat newly CE-marked packets as lost (Section 3.7): they count
%% towards the loss rate and start a recovery period. A later spurious
%% loss signal does not undo them.
-spec on_ecn_ce(cc_state(), non_neg_integer()) -> cc_state().
on_ecn_ce(State, NewCECount) ->
    on_ecn_ce_at(State, NewCECount, now_us()).

%% @doc ECN-CE count `NewCECount' reported at time `Now'.
-spec on_ecn_ce_at(cc_state(), non_neg_integer(), integer()) -> cc_state().
on_ecn_ce_at(#bbr_state{ecn_ce_counter = Old} = S, NewCECount, _Now) when NewCECount =< Old ->
    S;
on_ecn_ce_at(
    #bbr_state{ecn_ce_counter = Old, max_datagram_size = MDS, lost = Lost} = S0, NewCECount, Now
) ->
    Marks = NewCECount - Old,
    S1 = note_loss(S0#bbr_state{ecn_ce_counter = NewCECount, lost = Lost + Marks * MDS}, Marks),
    S2 =
        case S1#bbr_state.check_probe_loss of
            true -> check_ce_probe_loss(S1, Now);
            false -> S1
        end,
    S3 =
        case S2#bbr_state.in_recovery of
            true -> S2;
            false -> enter_recovery(S2, Now)
        end,
    S3#bbr_state{undo_state = ce}.

%% CE marks while probing weigh like losses.
check_ce_probe_loss(#bbr_state{rs = #rs{has_data = true} = RS0, lost = Lost} = S, Now) ->
    RS = RS0#rs{lost = Lost - RS0#rs.prior_lost},
    case is_inflight_too_high(RS) of
        true -> handle_inflight_too_high(S, RS, Now);
        false -> S
    end;
check_ce_probe_loss(S, _Now) ->
    S.

%% @doc Undo a loss recovery episode found to be spurious (Section 5.5.11.2).
-spec on_spurious_congestion(cc_state()) -> cc_state().
on_spurious_congestion(#bbr_state{undo_state = ce} = S) ->
    S;
on_spurious_congestion(S0) ->
    S = reset_full_bw(restore_cwnd(S0)),
    #bbr_state{
        bw_shortterm = BwLo,
        inflight_shortterm = InLo,
        inflight_longterm = Hi,
        undo_bw_shortterm = UBwLo,
        undo_inflight_shortterm = UInLo,
        undo_inflight_longterm = UHi,
        undo_state = Undo,
        mode = Mode
    } = S,
    S1 = S#bbr_state{
        in_recovery = false,
        is_loss_in_round = false,
        loss_events_in_round = 0,
        bw_shortterm = max(BwLo, UBwLo),
        inflight_shortterm = max(InLo, UInLo),
        inflight_longterm = max(Hi, UHi)
    },
    S2 =
        case {Undo, Mode} of
            {startup, startup} ->
                S1;
            {startup, probe_rtt} ->
                S1#bbr_state{full_bw_reached = false};
            {startup, _} ->
                enter_startup(S1#bbr_state{full_bw_reached = false});
            {probe_bw_up, probe_bw_up} ->
                S1;
            {probe_bw_up, probe_rtt} ->
                S1;
            {probe_bw_up, _} ->
                start_probe_bw_refill(S1);
            {none, _} ->
                S1
        end,
    S2#bbr_state{undo_state = none}.

%% @doc Persistent congestion is QUIC's retransmission timeout: save the
%% model for undo and drop cwnd to the minimum window (RFC 9002 Section
%% 7.6.2, draft-ietf-ccwg-bbr-07 Section 5.6.4.4).
-spec on_persistent_congestion(cc_state()) -> cc_state().
on_persistent_congestion(State) ->
    on_persistent_congestion_at(State, now_us()).

%% @doc Persistent congestion declared at time `Now'.
-spec on_persistent_congestion_at(cc_state(), integer()) -> cc_state().
on_persistent_congestion_at(#bbr_state{minimum_window = MinimumWindow} = S, Now) ->
    S1 = save_state_upon_loss(S),
    S1#bbr_state{cwnd = MinimumWindow, in_recovery = true, recovery_start = Now}.

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
bdp(#bbr_state{bw = Bw, min_rtt = MinRtt}) ->
    (Bw * MinRtt) div ?US_PER_SEC.

bdp_multiple(#bbr_state{bw = Bw} = S, Gain) ->
    bdp_multiple(S, Bw, Gain).

bdp_multiple(#bbr_state{min_rtt = infinity, initial_window = IW}, _Bw, _Gain) ->
    IW;
bdp_multiple(#bbr_state{min_rtt = MinRtt}, Bw, Gain) ->
    trunc(Gain * ((Bw * MinRtt) div ?US_PER_SEC)).

%% Section 5.6.4.2; the QUIC offload budget is one send quantum.
quantization_budget(
    #bbr_state{send_quantum = Quantum, mode = Mode, max_datagram_size = MDS} = S, Cap
) ->
    Cap1 = max(max(Cap, Quantum), min_pipe_cwnd(S)),
    case Mode of
        probe_bw_up -> Cap1 + 2 * MDS;
        _ -> Cap1
    end.

inflight(S, Gain) ->
    quantization_budget(S, bdp_multiple(S, Gain)).

%% cwnd is cwnd_gain x BDP, at least four packets.
set_cwnd(#bbr_state{cwnd_gain = Gain, max_datagram_size = MDS} = S) ->
    Bdp = max(bdp(S), ?MIN_PIPE_CWND_PKTS * MDS),
    S#bbr_state{cwnd = max(trunc(Gain * Bdp), min_pipe_cwnd(S))}.

%% Section 5.6.4.7 BoundCwndForModel.
bound_cwnd_for_model(#bbr_state{mode = Mode, cwnd = Cwnd, inflight_shortterm = InLo} = S) ->
    Cap0 =
        case Mode of
            probe_bw_cruise ->
                inflight_with_headroom(S);
            probe_rtt ->
                inflight_with_headroom(S);
            _ ->
                case is_in_probe_bw(Mode) of
                    true -> S#bbr_state.inflight_longterm;
                    false -> infinity
                end
        end,
    Cap = max(min(Cap0, InLo), min_pipe_cwnd(S)),
    S#bbr_state{cwnd = min(Cwnd, Cap)}.

%% Section 5.6.4.4.
save_cwnd(#bbr_state{in_recovery = false, mode = Mode, cwnd = Cwnd} = S) when Mode =/= probe_rtt ->
    S#bbr_state{prior_cwnd = Cwnd};
save_cwnd(#bbr_state{prior_cwnd = Prior, cwnd = Cwnd} = S) ->
    S#bbr_state{prior_cwnd = max(Prior, Cwnd)}.

restore_cwnd(#bbr_state{prior_cwnd = Prior, cwnd = Cwnd} = S) ->
    S#bbr_state{cwnd = max(Cwnd, Prior)}.

%%====================================================================
%% Pacing rate and send quantum (Sections 5.6.2, 5.6.3)
%%====================================================================

%% Pacing rate is pacing_gain x bw less 1%; no sample, no change.
set_pacing_rate(#bbr_state{bw = 0} = S) ->
    S;
set_pacing_rate(#bbr_state{bw = Bw, pacing_gain = Gain, max_datagram_size = MDS} = S) ->
    Rate = max(1, trunc(Gain * Bw * (100 - ?PACING_MARGIN_PERCENT) / 100)),
    S#bbr_state{pacing_rate = Rate, send_quantum = pacing_max_burst(MDS, Rate)}.

%% Two milliseconds at the paced rate, floored at 12 packets.
pacing_max_burst(MDS, PacingRate) ->
    max(12 * MDS, PacingRate div 500).

%% @doc BBR paces from its own model; the smoothed RTT is not used.
-spec update_pacing_rate(cc_state(), non_neg_integer()) -> cc_state().
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
        bw => S#bbr_state.bw,
        bw_shortterm => S#bbr_state.bw_shortterm,
        min_rtt => S#bbr_state.min_rtt,
        bdp => bdp(S),
        inflight_longterm => S#bbr_state.inflight_longterm,
        inflight_shortterm => S#bbr_state.inflight_shortterm,
        full_bw_reached => S#bbr_state.full_bw_reached,
        full_bw_now => S#bbr_state.full_bw_now,
        full_bw => S#bbr_state.full_bw,
        full_bw_count => S#bbr_state.full_bw_count,
        delivery_rate => (S#bbr_state.rs)#rs.delivery_rate,
        rs_app_limited => (S#bbr_state.rs)#rs.is_app_limited,
        idle_restart => S#bbr_state.idle_restart,
        in_recovery => S#bbr_state.in_recovery,
        prior_cwnd => S#bbr_state.prior_cwnd,
        undo_state => S#bbr_state.undo_state,
        prev_probe_too_high => S#bbr_state.prev_probe_too_high,
        bw_probe_wait => S#bbr_state.bw_probe_wait,
        probe_rtt_done_stamp => S#bbr_state.probe_rtt_done_stamp,
        sent_packets => queue:len(S#bbr_state.sent)
    }.

now_us() ->
    erlang:monotonic_time(microsecond).
