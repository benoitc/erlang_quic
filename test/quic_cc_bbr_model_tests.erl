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
ack_packet(#{now := Now, flight := F, undeclared := Undeclared, cc := CC0} = Sim) ->
    CC1 =
        case has_data(Sim) of
            true -> CC0;
            false -> quic_cc_bbr:on_app_limited(CC0)
        end,
    {{value, {AckSeq, Size, _, Now, Ce}}, F1} = queue:out(F),
    {Lost, Still} = lists:partition(fun({S, _, _, _, _}) -> S + 3 =< AckSeq end, Undeclared),
    {F2, Undeclared1} = normalize(F1, Still),
    CC2 = quic_cc_bbr:on_packets_acked_at(CC1, Size, Now),
    Sim1 = lose(Lost, Sim#{cc := CC2, flight := F2, undeclared := Undeclared1, last_ack := Now}),
    case Ce of
        true ->
            Count = maps:get(ce_count, Sim1) + 1,
            Sim1#{
                ce_count := Count, cc := quic_cc_bbr:on_ecn_ce_at(maps:get(cc, Sim1), Count, Now)
            };
        false ->
            Sim1
    end.

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
