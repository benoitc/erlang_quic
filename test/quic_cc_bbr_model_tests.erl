%%% -*- erlang -*-
%%%
%%% BBRv3 against draft-ietf-ccwg-bbr-07, driven over a simulated path.
%%%
%%% The path is a single bottleneck link of fixed rate and propagation
%%% delay with a drop-tail buffer. Time is simulated in microseconds and
%%% passed to the controller through its `*_at' functions, so every
%%% transition is deterministic and seconds of traffic run in
%%% milliseconds.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cc_bbr_model_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MDS, 1200).
-define(MS, 1000).
-define(SEC, 1000000).

%%====================================================================
%% Simulator
%%====================================================================

%% Options:
%%   bw        bottleneck rate, bytes/sec
%%   rtt       propagation round trip, µs
%%   buf       bottleneck buffer, bytes (infinity for none)
%%   drop      probability that the path drops a packet
%%   ce_above  queue bytes above which packets are CE-marked
%%   ack_every the receiver releases ACKs at multiples of this, µs
%%   app       infinity (bulk) | {Chunk, PeriodUs} (writes Chunk every PeriodUs)
sim(Opts) ->
    rand:seed(exsss, {7, 11, 13}),
    %% A fixed clock makes every run identical.
    T0 = 1000 * ?SEC,
    CC = quic_cc_bbr:new_at(maps:get(cc_opts, Opts, #{max_datagram_size => ?MDS}), T0),
    App =
        case maps:get(app, Opts, infinity) of
            infinity -> infinity;
            {Chunk, Period} -> #{chunk => Chunk, period => Period, next => T0, pending => 0}
        end,
    #{
        cc => CC,
        now => T0,
        t0 => T0,
        bw => maps:get(bw, Opts),
        rtt => maps:get(rtt, Opts),
        buf => maps:get(buf, Opts, infinity),
        drop => maps:get(drop, Opts, 0.0),
        ce_above => maps:get(ce_above, Opts, infinity),
        ack_every => maps:get(ack_every, Opts, 1),
        link_free => T0,
        flight => queue:new(),
        undeclared => [],
        seq => 0,
        next_send => T0,
        app => App,
        ce_count => 0,
        lost_pkts => 0,
        sent_pkts => 0,
        modes => [mode(CC)],
        last_ack => T0
    }.

mode(CC) ->
    maps:get(mode, quic_cc_bbr:info(CC)).

info(#{cc := CC}) ->
    quic_cc_bbr:info(CC).

info(Sim, Key) ->
    maps:get(Key, info(Sim)).

elapsed(#{now := Now, t0 := T0}) ->
    Now - T0.

%% Run for Duration µs of simulated time.
run(Sim, Duration) ->
    run_until(Sim, fun(_) -> false end, Duration).

%% Run until Pred holds (checked after every event) or Duration passes.
run_until(#{now := Now} = Sim, Pred, Duration) ->
    loop(Sim, Pred, Now + Duration).

loop(Sim, Pred, End) ->
    {T, Event} = next_event(Sim),
    case T > End of
        true ->
            Sim#{now := End};
        false ->
            Sim1 = record_mode(handle(Event, Sim#{now := T})),
            case Pred(Sim1) of
                true -> Sim1;
                false -> loop(Sim1, Pred, End)
            end
    end.

record_mode(#{cc := CC, modes := [Last | _] = Modes} = Sim) ->
    case mode(CC) of
        Last -> Sim;
        Mode -> Sim#{modes := [Mode | Modes]}
    end.

next_event(#{now := Now} = Sim) ->
    Candidates = [
        {next_ack(Sim), ack},
        {next_send(Sim), send},
        {next_write(Sim), write},
        {next_timeout(Sim), timeout},
        {Now + 3600 * ?SEC, idle}
    ],
    lists:min([C || {T, _} = C <- Candidates, T =/= infinity]).

%% The front of `flight' is always a delivered packet: lost ones move to
%% `undeclared' until loss detection finds them.
next_ack(#{flight := F}) ->
    case queue:peek(F) of
        empty -> infinity;
        {value, {_, _, _, AckAt, _}} -> AckAt
    end.

%% Lost packets nothing later will reveal are declared after a PTO.
next_timeout(#{flight := F, undeclared := [_ | _], rtt := Rtt, last_ack := LastAck, now := Now}) ->
    case queue:is_empty(F) of
        true -> max(Now, LastAck + 3 * Rtt);
        false -> infinity
    end;
next_timeout(_) ->
    infinity.

has_data(#{app := infinity}) -> true;
has_data(#{app := #{pending := P}}) -> P > 0.

next_send(#{cc := CC, now := Now, next_send := NextSend} = Sim) ->
    case has_data(Sim) andalso quic_cc_bbr:can_send(CC, ?MDS) of
        true -> max(Now, NextSend);
        false -> infinity
    end.

next_write(#{app := infinity}) -> infinity;
next_write(#{app := #{next := Next}}) -> Next.

handle(send, Sim) -> send_packet(Sim);
handle(ack, Sim) -> ack_packet(Sim);
handle(write, Sim) -> app_write(Sim);
handle(timeout, Sim) -> declare_all_lost(Sim);
handle(idle, Sim) -> Sim.

app_write(
    #{app := #{chunk := Chunk, period := Period, next := Next, pending := P} = App, cc := CC} = Sim
) ->
    CC1 =
        case P of
            0 -> quic_cc_bbr:on_app_limited(CC);
            _ -> CC
        end,
    Sim#{app := App#{next := Next + Period, pending := P + Chunk}, cc := CC1}.

send_packet(Sim) ->
    #{
        cc := CC,
        now := Now,
        bw := Bw,
        rtt := Rtt,
        buf := Buf,
        drop := Drop,
        ce_above := CeAbove,
        ack_every := AckEvery,
        link_free := LinkFree,
        flight := F,
        undeclared := Undeclared,
        seq := Seq,
        next_send := NextSend
    } = Sim,
    Queue = (max(0, LinkFree - Now) * Bw) div ?SEC,
    Overflow = (Buf =/= infinity) andalso (Queue + ?MDS > Buf),
    {Entry, LinkFree1} =
        case Overflow orelse (rand:uniform() < Drop) of
            true ->
                {{Seq, ?MDS, Now, lost, false}, LinkFree};
            false ->
                Depart = max(Now, LinkFree) + (?MDS * ?SEC) div Bw,
                AckAt = ceil_to(Depart + Rtt, AckEvery),
                {{Seq, ?MDS, Now, AckAt, (Queue > CeAbove)}, Depart}
        end,
    CC1 = quic_cc_bbr:on_packet_sent_at(CC, ?MDS, Now),
    Rate = max(1, maps:get(pacing_rate, quic_cc_bbr:info(CC1))),
    {F1, Undeclared1} = normalize(queue:in(Entry, F), Undeclared),
    Sim1 = Sim#{
        cc := CC1,
        link_free := LinkFree1,
        flight := F1,
        undeclared := Undeclared1,
        seq := Seq + 1,
        next_send := max(Now, NextSend) + (?MDS * ?SEC) div Rate,
        sent_pkts := maps:get(sent_pkts, Sim) + 1
    },
    consume_app(Sim1).

ceil_to(T, 1) -> T;
ceil_to(T, Step) -> ((T + Step - 1) div Step) * Step.

%% Move lost packets at the front of the flight to `undeclared'.
normalize(F, Undeclared) ->
    case queue:peek(F) of
        {value, {_, _, _, lost, _} = P} -> normalize(queue:drop(F), Undeclared ++ [P]);
        _ -> {F, Undeclared}
    end.

consume_app(#{app := infinity} = Sim) ->
    Sim;
consume_app(#{app := #{pending := P} = App} = Sim) ->
    Sim#{app := App#{pending := max(0, P - ?MDS)}}.

%% One ACK per delivered packet; lost packets three or more behind it
%% are declared lost in the same ACK, as RFC 9002 packet threshold does.
%% The controller sees the ACK in RFC 9002 Appendix A.7 order: the CE
%% mark, the losses, then the acknowledged packet.
ack_packet(#{now := Now, flight := F, undeclared := Undeclared, cc := CC0} = Sim) ->
    CC1 =
        case has_data(Sim) of
            true -> CC0;
            false -> quic_cc_bbr:on_app_limited(CC0)
        end,
    {{value, {AckSeq, Size, Sent, Now, Ce}}, F1} = queue:out(F),
    {Lost, Still} = lists:partition(fun({S, _, _, _, _}) -> S + 3 =< AckSeq end, Undeclared),
    {F2, Undeclared1} = normalize(F1, Still),
    {CC2, CeCount} =
        case Ce of
            true ->
                {
                    quic_cc_bbr:on_congestion_event_at(CC1, Sent div ?MS, Now),
                    maps:get(ce_count, Sim) + 1
                };
            false ->
                {CC1, maps:get(ce_count, Sim)}
        end,
    Sim1 = lose(Lost, Sim#{cc := CC2, ce_count := CeCount}),
    CC3 = quic_cc_bbr:on_packets_acked_at(maps:get(cc, Sim1), Size, Now),
    Sim1#{cc := CC3, flight := F2, undeclared := Undeclared1, last_ack := Now}.

lose([], Sim) ->
    Sim;
lose(Lost, #{cc := CC, now := Now, lost_pkts := N} = Sim) ->
    Bytes = lists:sum([Size || {_, Size, _, _, _} <- Lost]),
    LargestSent = lists:max([T || {_, _, T, _, _} <- Lost]),
    CC1 = quic_cc_bbr:on_packets_lost_at(CC, Bytes, Now),
    CC2 = quic_cc_bbr:on_congestion_event_at(CC1, LargestSent div ?MS, Now),
    Sim#{cc := CC2, lost_pkts := N + length(Lost)}.

declare_all_lost(#{undeclared := Lost} = Sim) ->
    lose(Lost, Sim#{undeclared := []}).

%% Change the bottleneck rate, packets already queued included.
set_bw(#{now := Now, bw := Old, rtt := Rtt, flight := F, link_free := LinkFree} = Sim, New) ->
    Stretch = fun
        (Depart) when Depart > Now -> Now + ((Depart - Now) * Old) div New;
        (Depart) -> Depart
    end,
    F1 = queue:from_list([
        {Seq, Size, Sent, Stretch(AckAt - Rtt) + Rtt, Ce}
     || {Seq, Size, Sent, AckAt, Ce} <- queue:to_list(F)
    ]),
    Sim#{bw := New, flight := F1, link_free := Stretch(LinkFree)}.

in_flight(#{flight := F, undeclared := U}) ->
    queue:len(F) + length(U).

%% Stop the application, let everything drain, then wait Idle µs.
go_idle(Sim, Idle) ->
    Sim1 = Sim#{app := #{chunk => 0, period => 3600 * ?SEC, next => infinity, pending => 0}},
    Drained = run_until(Sim1, fun(S) -> in_flight(S) =:= 0 end, 10 * ?SEC),
    Drained#{now := maps:get(now, Drained) + Idle}.

resume(#{now := Now} = Sim) ->
    Sim#{app := infinity, next_send := Now}.

app_limited(#{now := Now} = Sim, Chunk, Period) ->
    Sim#{app := #{chunk => Chunk, period => Period, next => Now, pending => 0}}.

in_mode(Mode) ->
    fun(Sim) -> info(Sim, mode) =:= Mode end.

not_in_mode(Mode) ->
    fun(Sim) -> info(Sim, mode) =/= Mode end.

visited(#{modes := Modes}) ->
    lists:reverse(Modes).

%% Run to the first ProbeBW state.
to_probe_bw(Sim) ->
    run_until(
        Sim, fun(S) -> lists:member(info(S, mode), [probe_bw_down, probe_bw_cruise]) end, 5 * ?SEC
    ).

%% A 10 MB/s, 40 ms path with a buffer of two BDPs.
bulk_path() ->
    #{bw => 10000000, rtt => 40 * ?MS, buf => 800000}.

%% The same path with a buffer of a seventh of the BDP.
shallow_path() ->
    #{bw => 10000000, rtt => 40 * ?MS, buf => 60000}.

%%====================================================================
%% Rate samples and round counting (Sections 4.1, 5.5.1)
%%====================================================================

%% A round ends on the ACK of a packet sent after the previous round
%% ended, not on every ACK.
round_ends_on_packet_sent_after_round_start_test() ->
    T = erlang:monotonic_time(microsecond),
    S0 = quic_cc_bbr:new(#{}),
    S1 = lists:foldl(fun(I, S) -> quic_cc_bbr:on_packet_sent_at(S, 1200, T + I) end, S0, [1, 2, 3]),
    S2 = quic_cc_bbr:on_packets_acked_at(S1, 1200, T + 40 * ?MS),
    ?assertEqual(1, maps:get(round_count, quic_cc_bbr:info(S2))),
    S3 = quic_cc_bbr:on_packets_acked_at(S2, 1200, T + 41 * ?MS),
    S4 = quic_cc_bbr:on_packets_acked_at(S3, 1200, T + 42 * ?MS),
    ?assertEqual(1, maps:get(round_count, quic_cc_bbr:info(S4))),
    S5 = quic_cc_bbr:on_packet_sent_at(S4, 1200, T + 43 * ?MS),
    S6 = quic_cc_bbr:on_packets_acked_at(S5, 1200, T + 83 * ?MS),
    ?assertEqual(2, maps:get(round_count, quic_cc_bbr:info(S6))).

%% The sample is taken from the newest acknowledged packet over the
%% longer of its send and ACK intervals (Section 4.1.2.3).
rate_sample_uses_longer_interval_test() ->
    T = erlang:monotonic_time(microsecond),
    S0 = quic_cc_bbr:new(#{}),
    S1 = lists:foldl(
        fun(I, S) -> quic_cc_bbr:on_packet_sent_at(S, 1200, T + I * ?MS) end, S0, lists:seq(0, 9)
    ),
    S2 = quic_cc_bbr:on_packets_acked_at(S1, 12000, T + 50 * ?MS),
    Info = quic_cc_bbr:info(S2),
    %% 12000 bytes over the 50 ms since the first send.
    ?assertEqual(240000, maps:get(delivery_rate, Info)),
    ?assertEqual(41 * ?MS, maps:get(min_rtt, Info)).

%% A round is one packet-timed round trip of the path.
rounds_are_packet_timed_test() ->
    Sim = run(sim(bulk_path()), 2 * ?SEC),
    Rounds = info(Sim, round_count),
    %% 40 ms of propagation plus queueing: at most 50 rounds in 2 s.
    ?assert(Rounds > 10),
    ?assert(Rounds =< 50).

%% min_rtt is the propagation delay seen by the newest acknowledged
%% packet, in microseconds.
min_rtt_is_propagation_delay_test() ->
    MinRtt = info(run(sim(bulk_path()), ?SEC), min_rtt),
    ?assert(MinRtt >= 40 * ?MS),
    ?assert(MinRtt < 41 * ?MS).

%% A packet sent while the sender had nothing queued gives an
%% app-limited sample; the mark clears once the data in flight when it
%% was set has been delivered (Section 4.1.2.4).
app_limited_mark_test() ->
    T = erlang:monotonic_time(microsecond),
    S1 = quic_cc_bbr:on_app_limited(quic_cc_bbr:new(#{})),
    ?assert(maps:get(app_limited, quic_cc_bbr:info(S1))),
    S2 = quic_cc_bbr:on_packet_sent_at(S1, 1200, T),
    S3 = quic_cc_bbr:on_packets_acked_at(S2, 1200, T + 40 * ?MS),
    ?assert(maps:get(rs_app_limited, quic_cc_bbr:info(S3))),
    ?assertNot(maps:get(app_limited, quic_cc_bbr:info(S3))),
    S4 = quic_cc_bbr:on_packet_sent_at(S3, 1200, T + 41 * ?MS),
    S5 = quic_cc_bbr:on_packets_acked_at(S4, 1200, T + 81 * ?MS),
    ?assertNot(maps:get(rs_app_limited, quic_cc_bbr:info(S5))).

%% A full cwnd is not an application limit.
app_limited_needs_cwnd_room_test() ->
    S0 = quic_cc_bbr:new(#{initial_window => 12000}),
    S1 = quic_cc_bbr:on_packet_sent_at(S0, 12000, erlang:monotonic_time(microsecond)),
    ?assertNot(maps:get(app_limited, quic_cc_bbr:info(quic_cc_bbr:on_app_limited(S1)))).

%% An app-limited sample below max_bw leaves it alone (Section 5.5.4).
app_limited_sample_does_not_lower_max_bw_test() ->
    Sim = run(sim(bulk_path()), 3 * ?SEC),
    MaxBw = info(Sim, max_bw),
    Slow = run(app_limited(Sim, 1200, 20 * ?MS), ?SEC),
    ?assertEqual(MaxBw, info(Slow, max_bw)).

%% One snapshot per packet in flight, none once nothing is in flight.
snapshots_are_bounded_by_flight_test() ->
    Sim = run(sim(shallow_path()), ?SEC),
    ?assertEqual(in_flight(Sim), info(Sim, sent_packets)),
    ?assertEqual(0, info(go_idle(Sim, 0), sent_packets)).

%%====================================================================
%% State machine (Sections 5.3.1 - 5.3.3)
%%====================================================================

%% max_bw tracks the bottleneck within the 2% of the draft's test A.1.
max_bw_matches_bottleneck_test() ->
    Sim = run(sim(bulk_path()), 3 * ?SEC),
    ?assert(abs(info(Sim, max_bw) - 10000000) =< 10000000 * 0.02).

%% Samples taken while the sender had nothing to send are marked
%% application-limited.
app_limited_samples_are_marked_test() ->
    Sim = run(sim(#{bw => 10000000, rtt => 20 * ?MS, app => {1200, 10 * ?MS}}), ?SEC),
    ?assert(info(Sim, rs_app_limited)).

startup_gains_test() ->
    Info = quic_cc_bbr:info(quic_cc_bbr:new(#{})),
    ?assertEqual(startup, maps:get(mode, Info)),
    ?assertEqual(2.77, maps:get(pacing_gain, Info)),
    ?assertEqual(2.0, maps:get(cwnd_gain, Info)).

%% A.1: three rounds without 25% growth end Startup.
startup_exits_on_bandwidth_plateau_test() ->
    Sim = run_until(sim(bulk_path()), not_in_mode(startup), 5 * ?SEC),
    Info = info(Sim),
    ?assertEqual(drain, maps:get(mode, Info)),
    ?assert(maps:get(full_bw_reached, Info)),
    ?assert(maps:get(full_bw_now, Info)),
    ?assertEqual(3, maps:get(full_bw_count, Info)),
    ?assertEqual(0.5, maps:get(pacing_gain, Info)),
    ?assertEqual(infinity, maps:get(inflight_longterm, Info)),
    ?assertEqual(0, maps:get(lost_pkts, Sim)).

%% A.3: Drain ends once in flight is down to the BDP.
drain_exits_on_inflight_test() ->
    Sim = run_until(sim(bulk_path()), not_in_mode(startup), 5 * ?SEC),
    Out = run_until(Sim, not_in_mode(drain), 5 * ?SEC),
    ?assertEqual(probe_bw_cruise, info(Out, mode)),
    ?assert(info(Out, bytes_in_flight) =< info(Out, bdp) + 2 * ?MDS).

%% A.4: Drain ends after three rounds even when in flight stays high,
%% here because the bottleneck halved as Drain started.
drain_exits_after_three_rounds_test() ->
    Sim = run_until(sim(bulk_path()), not_in_mode(startup), 5 * ?SEC),
    ?assertEqual(drain, info(Sim, mode)),
    Start = info(Sim, round_count),
    Out = run_until(set_bw(Sim, 5000000), not_in_mode(drain), 5 * ?SEC),
    ?assert(lists:member(info(Out, mode), [probe_bw_down, probe_bw_cruise])),
    ?assertEqual(Start + 4, info(Out, round_count)).

%% ProbeBW cycles DOWN, CRUISE, REFILL, UP with the draft's gains.
probe_bw_cycle_test() ->
    Sim = to_probe_bw(sim(bulk_path())),
    Refill = run_until(Sim, in_mode(probe_bw_refill), 5 * ?SEC),
    ?assertEqual({1.0, 2.0}, {info(Refill, pacing_gain), info(Refill, cwnd_gain)}),
    Up = run_until(Refill, in_mode(probe_bw_up), ?SEC),
    ?assertEqual({1.25, 2.25}, {info(Up, pacing_gain), info(Up, cwnd_gain)}),
    Down = run_until(Up, in_mode(probe_bw_down), 5 * ?SEC),
    ?assertEqual({0.9, 2.0}, {info(Down, pacing_gain), info(Down, cwnd_gain)}),
    Cruise = run_until(Down, in_mode(probe_bw_cruise), 5 * ?SEC),
    ?assertEqual({1.0, 2.0}, {info(Cruise, pacing_gain), info(Cruise, cwnd_gain)}),
    ?assertMatch(
        [probe_bw_refill, probe_bw_up, probe_bw_down, probe_bw_cruise | _],
        lists:dropwhile(fun(M) -> M =/= probe_bw_refill end, visited(Cruise))
    ).

%% REFILL lasts one round; UP ends on a bandwidth plateau (A.5).
probe_bw_up_exits_on_plateau_test() ->
    Sim = to_probe_bw(sim(bulk_path())),
    Refill = run_until(Sim, in_mode(probe_bw_refill), 5 * ?SEC),
    Up = run_until(Refill, in_mode(probe_bw_up), ?SEC),
    ?assertEqual(info(Refill, round_count) + 1, info(Up, round_count)),
    Down = run_until(Up, in_mode(probe_bw_down), 5 * ?SEC),
    ?assert(info(Down, full_bw_now)),
    ?assertNot(info(Down, prev_probe_too_high)).

%% The wait before the next probe is 2 to 3 seconds (Section 5.3.3.8.3).
probe_wait_is_two_to_three_seconds_test() ->
    Wait = info(to_probe_bw(sim(bulk_path())), bw_probe_wait),
    ?assert(Wait >= 2 * ?SEC),
    ?assert(Wait =< 3 * ?SEC).

%% A small BDP probes on the Reno time scale: within BDP rounds.
small_bdp_probes_on_reno_time_scale_test() ->
    Sim = to_probe_bw(sim(#{bw => 1000000, rtt => 10 * ?MS, buf => 100000})),
    Up = run_until(Sim, in_mode(probe_bw_up), 3 * ?SEC),
    ?assertEqual(probe_bw_up, info(Up, mode)),
    ?assert(elapsed(Up) - elapsed(Sim) < ?SEC).

%% A.16: max_bw forgets a faster path after two ProbeBW cycles.
max_bw_adapts_down_after_two_cycles_test() ->
    Sim = to_probe_bw(sim(bulk_path())),
    Slow = run(Sim#{bw := 5000000}, 12 * ?SEC),
    ?assert(info(Slow, cycle_count) >= info(Sim, cycle_count) + 2),
    ?assert(abs(info(Slow, max_bw) - 5000000) =< 5000000 * 0.02).

%% A.7: an application-limited flow without loss stays in Startup.
app_limited_flow_stays_in_startup_test() ->
    Sim = run(sim(#{bw => 10000000, rtt => 20 * ?MS, app => {1200, 2 * ?MS}}), 5 * ?SEC),
    ?assertEqual([startup], visited(Sim)).

%%====================================================================
%% ProbeRTT (Section 5.3.4)
%%====================================================================

%% A.10: ProbeRTT after 10 s without a lower RTT, for 200 ms and a round.
probe_rtt_after_min_rtt_expires_test() ->
    Sim = to_probe_bw(sim(bulk_path())),
    In = run_until(Sim, in_mode(probe_rtt), 15 * ?SEC),
    ?assertEqual(probe_rtt, info(In, mode)),
    ?assert(elapsed(In) >= 10 * ?SEC),
    ?assertEqual({1.0, 0.5}, {info(In, pacing_gain), info(In, cwnd_gain)}),
    Out = run_until(In, not_in_mode(probe_rtt), 2 * ?SEC),
    ?assert(elapsed(Out) - elapsed(In) >= 200 * ?MS),
    ?assertEqual(probe_bw_cruise, info(Out, mode)),
    ?assertEqual(2.0, info(Out, cwnd_gain)).

%% A.20: ProbeRTT before the pipe was filled returns to Startup.
probe_rtt_during_startup_returns_to_startup_test() ->
    Sim = sim(#{bw => 10000000, rtt => 20 * ?MS, app => {1200, 2 * ?MS}}),
    In = run_until(Sim, in_mode(probe_rtt), 12 * ?SEC),
    ?assertEqual(probe_rtt, info(In, mode)),
    Out = run_until(In, not_in_mode(probe_rtt), 2 * ?SEC),
    ?assertEqual(startup, info(Out, mode)),
    ?assertEqual([startup, probe_rtt, startup], visited(Out)).

%%====================================================================
%% Congestion window and pacing (Sections 5.4, 5.5.9, 5.6)
%%====================================================================

%% Before the first RTT sample the pacing rate is 2.77 x the initial
%% window per millisecond; the first sample replaces the millisecond.
initial_pacing_rate_test() ->
    T = erlang:monotonic_time(microsecond),
    S0 = quic_cc_bbr:new(#{initial_window => 12000}),
    ?assertEqual(trunc(2.77 * 12000 * 1000), maps:get(pacing_rate, quic_cc_bbr:info(S0))),
    S1 = quic_cc_bbr:on_packet_sent_at(S0, 1200, T),
    S2 = quic_cc_bbr:on_packets_acked_at(S1, 1200, T + 40 * ?MS),
    ?assertEqual(trunc(2.77 * 12000 * 25), maps:get(pacing_rate, quic_cc_bbr:info(S2))).

%% cwnd grows by the bytes each ACK newly acknowledges.
cwnd_grows_by_acked_bytes_test() ->
    T = erlang:monotonic_time(microsecond),
    S0 = quic_cc_bbr:new(#{initial_window => 12000}),
    S1 = quic_cc_bbr:on_packet_sent_at(quic_cc_bbr:on_packet_sent_at(S0, 1200, T), 1200, T),
    S2 = quic_cc_bbr:on_packets_acked_at(S1, 1200, T + 40 * ?MS),
    ?assertEqual(13200, quic_cc_bbr:cwnd(S2)),
    S3 = quic_cc_bbr:on_packets_acked_at(S2, 1200, T + 41 * ?MS),
    ?assertEqual(14400, quic_cc_bbr:cwnd(S3)).

%% Once the pipe is full cwnd stays within max_inflight, about two BDPs.
cwnd_bounded_by_max_inflight_test() ->
    Sim = run(to_probe_bw(sim(bulk_path())), ?SEC),
    #{cwnd := Cwnd, max_inflight := MaxInflight, bdp := Bdp} = info(Sim),
    ?assert(Cwnd =< MaxInflight),
    ?assert(Cwnd >= Bdp),
    ?assert(MaxInflight =< 2 * Bdp + info(Sim, extra_acked) + info(Sim, send_quantum)).

%% The pacing rate never drops before the pipe is full (Section 5.6.2).
pacing_rate_only_rises_in_startup_test() ->
    %% Past the first RTT sample, which sets the initial rate.
    Rates = startup_pacing_rates(run(sim(bulk_path()), 50 * ?MS), []),
    ?assert(length(Rates) > 100),
    ?assertEqual(lists:sort(Rates), lists:reverse(Rates)).

startup_pacing_rates(Sim, Acc) ->
    Next = run(Sim, ?MS),
    case info(Next, mode) of
        startup -> startup_pacing_rates(Next, [info(Next, pacing_rate) | Acc]);
        _ -> Acc
    end.

%% Nor in a ProbeRTT entered before the pipe was full, whose gain is 1.
pacing_rate_kept_in_probe_rtt_before_full_bw_test() ->
    Sim = sim(#{bw => 10000000, rtt => 20 * ?MS, app => {1200, 2 * ?MS}}),
    Before = run_until(Sim, fun(S) -> elapsed(S) >= 9 * ?SEC end, 10 * ?SEC),
    In = run_until(Before, in_mode(probe_rtt), 3 * ?SEC),
    ?assertNot(info(In, full_bw_reached)),
    ?assert(info(In, pacing_rate) >= info(Before, pacing_rate)).

%% In ProbeBW the rate is pacing_gain x bw less a 1% margin.
pacing_rate_has_one_percent_margin_test() ->
    Sim = run_until(to_probe_bw(sim(bulk_path())), in_mode(probe_bw_cruise), 5 * ?SEC),
    ?assertEqual(trunc(info(Sim, bw) * 0.99), info(Sim, pacing_rate)).

%% The send quantum is a millisecond of pacing, between two packets
%% and 64 KB.
send_quantum_test() ->
    Mid = run(to_probe_bw(sim(bulk_path())), ?SEC),
    ?assertEqual(info(Mid, pacing_rate) div 1000, info(Mid, send_quantum)),
    Fast = run(to_probe_bw(sim(#{bw => 125000000, rtt => 10 * ?MS, buf => 2500000})), ?SEC),
    ?assertEqual(65536, info(Fast, send_quantum)),
    Slow = run(to_probe_bw(sim(#{bw => 100000, rtt => 10 * ?MS, buf => 20000})), ?SEC),
    ?assertEqual(2 * ?MDS, info(Slow, send_quantum)).

%% A.14: a BDP of about one packet still keeps four packets of cwnd.
sub_packet_bdp_keeps_min_pipe_cwnd_test() ->
    Sim = run(to_probe_bw(sim(#{bw => 100000, rtt => ?MS, buf => 20000})), 2 * ?SEC),
    ?assert(info(Sim, bdp) < 2 * ?MDS),
    ?assert(info(Sim, cwnd) >= 4 * ?MDS).

%% A.12: aggregated ACKs raise extra_acked and cwnd above two BDPs.
ack_aggregation_raises_cwnd_test() ->
    Sim = run(sim((bulk_path())#{ack_every => 10 * ?MS}), 3 * ?SEC),
    #{extra_acked := Extra, max_inflight := MaxInflight, bdp := Bdp} = info(Sim),
    ?assert(Extra > 0),
    ?assert(MaxInflight > 2 * Bdp).

%% Restarting from idle in ProbeBW paces at exactly bw (Section 5.4.1).
restart_from_idle_paces_at_bw_test() ->
    Sim = run(to_probe_bw(sim(bulk_path())), ?SEC),
    Idle = go_idle(Sim, ?SEC),
    #{cc := CC, now := Now} = Idle,
    CC1 = quic_cc_bbr:on_packet_sent_at(CC, ?MDS, Now),
    Info = quic_cc_bbr:info(CC1),
    ?assert(maps:get(idle_restart, Info)),
    ?assertEqual(trunc(maps:get(bw, Info) * 0.99), maps:get(pacing_rate, Info)).

%% A.11: idling past the min_rtt window does not trigger ProbeRTT.
idle_restart_skips_probe_rtt_test() ->
    Sim = run(to_probe_bw(sim(bulk_path())), ?SEC),
    Idle = go_idle(Sim, 11 * ?SEC),
    Back = run(resume(Idle#{modes := [info(Idle, mode)]}), ?SEC),
    ?assertNot(lists:member(probe_rtt, visited(Back))),
    ?assertNot(info(Back, idle_restart)).

%% A.10: ProbeRTT holds cwnd to half the BDP.
probe_rtt_bounds_cwnd_test() ->
    In = run_until(to_probe_bw(sim(bulk_path())), in_mode(probe_rtt), 15 * ?SEC),
    Held = run(In, 100 * ?MS),
    ?assertEqual(probe_rtt, info(Held, mode)),
    ?assert(info(Held, cwnd) =< max(info(Held, bdp) div 2, 4 * ?MDS) + ?MDS).

%%====================================================================
%% Loss, ECN and undo (Sections 3.7, 5.3.1.3, 5.5.10, 5.5.11)
%%====================================================================

%% A shallow buffer ends Startup on loss, before any plateau, and sets
%% inflight_longterm.
startup_exits_on_high_loss_test() ->
    Sim = run_until(sim(shallow_path()), not_in_mode(startup), 5 * ?SEC),
    Info = info(Sim),
    ?assertEqual(drain, maps:get(mode, Info)),
    ?assert(maps:get(full_bw_reached, Info)),
    ?assertNot(maps:get(full_bw_now, Info)),
    ?assertNotEqual(infinity, maps:get(inflight_longterm, Info)),
    ?assert(maps:get(lost_pkts, Sim) > 0).

%% Recovery ends before the model sees an ACK (draft-ietf-ccwg-bbr-07
%% Section 5.6.4.4): an ACK that ends recovery does not count as a round
%% in recovery for the Startup loss exit (Section 5.3.1.3).
recovery_ended_by_this_ack_is_over_for_the_model_test() ->
    T = erlang:monotonic_time(microsecond),
    S0 = lists:foldl(
        fun(_, S) -> quic_cc_bbr:on_packet_sent_at(S, ?MDS, T) end,
        quic_cc_bbr:new_at(#{}, T),
        lists:seq(1, 20)
    ),
    S1 = quic_cc_bbr:on_congestion_event_at(S0, T div ?MS, T + 10 * ?MS),
    S2 = quic_cc_bbr:on_packets_acked_at(S1, ?MDS, T + 40 * ?MS),
    S3 = quic_cc_bbr:on_packet_sent_at(S2, ?MDS, T + 45 * ?MS),
    S4 = quic_cc_bbr:on_packets_lost_at(S3, 6 * ?MDS, T + 50 * ?MS),
    S5 = quic_cc_bbr:on_packets_acked_at(S4, 14 * ?MDS, T + 60 * ?MS),
    ?assertNot(quic_cc_bbr:in_recovery(S5)),
    ?assertEqual(startup, maps:get(mode, quic_cc_bbr:info(S5))).

%% A.2: excessive loss ends Startup even when application-limited.
startup_exits_on_loss_when_app_limited_test() ->
    Out = run_until(lossy_app_limited(), not_in_mode(startup), 5 * ?SEC),
    ?assertNotEqual(startup, info(Out, mode)),
    ?assert(info(Out, full_bw_reached)),
    ?assertNot(info(Out, full_bw_now)),
    ?assertEqual(startup, info(Out, undo_state)).

lossy_app_limited() ->
    sim(#{bw => 10000000, rtt => 20 * ?MS, drop => 0.1, app => {12000, 2 * ?MS}}).

%% A.21: loss in UP lowers inflight_longterm and goes to DOWN.
probe_bw_up_exits_on_loss_test() ->
    Sim = to_probe_bw(sim(shallow_path())),
    Up = run_until(Sim, in_mode(probe_bw_up), 5 * ?SEC),
    Hi = info(Up, inflight_longterm),
    ?assertNotEqual(infinity, Hi),
    Down = run_until(Up, not_in_mode(probe_bw_up), 5 * ?SEC),
    ?assertEqual(probe_bw_down, info(Down, mode)),
    ?assert(info(Down, prev_probe_too_high)),
    ?assertEqual(probe_bw_up, info(Down, undo_state)),
    ?assertNotEqual(infinity, info(Down, inflight_longterm)).

%% Outside bandwidth probing, a round with loss cuts the short-term
%% model by at most Beta (Section 5.5.10.3).
loss_while_cruising_cuts_short_term_model_test() ->
    Sim = run_until(to_probe_bw(sim(bulk_path())), in_mode(probe_bw_cruise), 5 * ?SEC),
    MaxBw = info(Sim, max_bw),
    Lossy = run_until(Sim#{drop := 0.05}, fun(S) -> info(S, bw_shortterm) =/= infinity end, ?SEC),
    BwLo = info(Lossy, bw_shortterm),
    ?assert(BwLo >= trunc(0.7 * MaxBw)),
    ?assert(BwLo =< MaxBw),
    ?assertEqual(BwLo, info(Lossy, bw)).

%% A CE mark is a congestion event (RFC 9002 Section 7.1): BBR enters
%% recovery, saving its model, without counting the mark as loss.
ecn_ce_enters_recovery_without_loss_test() ->
    Sim = run_until(
        sim((bulk_path())#{ce_above => 20000}),
        fun(S) -> maps:get(ce_count, S) > 0 end,
        5 * ?SEC
    ),
    ?assert(info(Sim, in_recovery)),
    ?assertEqual(0, info(Sim, lost)),
    ?assertEqual(0, maps:get(lost_pkts, Sim)).

ecn_ce_starts_recovery_test() ->
    T = erlang:monotonic_time(microsecond),
    S0 = quic_cc_bbr:on_packet_sent_at(quic_cc_bbr:new(#{}), 1200, T),
    S1 = quic_cc_bbr:on_congestion_event_at(S0, T div 1000, T + ?MS),
    ?assert(quic_cc_bbr:in_recovery(S1)),
    ?assertEqual(0, maps:get(lost, quic_cc_bbr:info(S1))),
    ?assertEqual(quic_cc_bbr:cwnd(S0), maps:get(prior_cwnd, quic_cc_bbr:info(S1))).

%% A.18: a spurious loss episode that ended Startup returns to it.
spurious_loss_returns_to_startup_test() ->
    Sim = run_until(lossy_app_limited(), not_in_mode(startup), 5 * ?SEC),
    ?assertEqual(startup, info(Sim, undo_state)),
    Undone = quic_cc_bbr:info(quic_cc_bbr:on_spurious_congestion(maps:get(cc, Sim))),
    ?assertEqual(startup, maps:get(mode, Undone)),
    ?assertNot(maps:get(full_bw_reached, Undone)),
    ?assertEqual(infinity, maps:get(inflight_longterm, Undone)),
    ?assertEqual(none, maps:get(undo_state, Undone)),
    ?assertNot(maps:get(in_recovery, Undone)).

%% A.18: a spurious loss episode that ended UP probes again from REFILL.
spurious_loss_returns_to_probe_bw_refill_test() ->
    Sim = to_probe_bw(sim(shallow_path())),
    Up = run_until(Sim, in_mode(probe_bw_up), 5 * ?SEC),
    Down = run_until(Up, not_in_mode(probe_bw_up), 5 * ?SEC),
    ?assertEqual(probe_bw_up, info(Down, undo_state)),
    Undone = quic_cc_bbr:info(quic_cc_bbr:on_spurious_congestion(maps:get(cc, Down))),
    ?assertEqual(probe_bw_refill, maps:get(mode, Undone)).

%% Persistent congestion drops cwnd to the minimum window; recovery
%% ends on the ACK of a packet sent after it and restores cwnd.
persistent_congestion_test() ->
    Sim = run(to_probe_bw(sim(bulk_path())), ?SEC),
    #{cc := CC, now := Now} = Sim,
    Before = quic_cc_bbr:cwnd(CC),
    CC1 = quic_cc_bbr:on_persistent_congestion_at(CC, Now),
    ?assertEqual(2 * ?MDS, quic_cc_bbr:cwnd(CC1)),
    ?assert(quic_cc_bbr:in_recovery(CC1)),
    ?assertEqual(Before, maps:get(prior_cwnd, quic_cc_bbr:info(CC1))),
    CC2 = quic_cc_bbr:on_packet_sent_at(CC1, ?MDS, Now + 1),
    InFlight = quic_cc_bbr:bytes_in_flight(CC2),
    CC3 = quic_cc_bbr:on_packets_acked_at(CC2, InFlight, Now + 50 * ?MS),
    ?assertNot(quic_cc_bbr:in_recovery(CC3)),
    ?assert(quic_cc_bbr:cwnd(CC3) >= 4 * ?MDS).

%% Random loss below LossThresh does not stop the flow from using the
%% path (Section 5.5.10).
low_random_loss_keeps_throughput_test() ->
    Sim = run(sim((bulk_path())#{drop => 0.01}), 10 * ?SEC),
    Delivered = info(Sim, delivered),
    ?assert(Delivered > 0.7 * 10000000 * 10).
