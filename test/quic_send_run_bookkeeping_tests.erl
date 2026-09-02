%% The batched send-side primitives the chunk-run sender uses must
%% agree with their per-packet counterparts: send_check_run/4 with
%% sequential send_check/3 calls that account each packet as sent,
%% on_packets_sent/2 with a fold of on_packet_sent/2, and
%% on_packets_sent_run/3 with a fold of on_packet_sent/6.
-module(quic_send_run_bookkeeping_tests).

-include_lib("eunit/include/eunit.hrl").

-define(MDS, 1200).

newreno(Cwnd) ->
    quic_cc_newreno:new(#{max_datagram_size => ?MDS, initial_window => Cwnd}).

%% The honest per-packet reference: check, then account the packet as
%% sent before the next check, as the one-at-a-time send path does.
sequential_checks(_State, _Size, 0, _Urgency, K) ->
    K;
sequential_checks(State, Size, Left, Urgency, K) ->
    case quic_cc_newreno:send_check(State, Size, Urgency) of
        {ok, S1} ->
            sequential_checks(
                quic_cc_newreno:on_packet_sent(S1, Size), Size, Left - 1, Urgency, K + 1
            );
        _ ->
            K
    end.

%% Unpaced: the batch approves exactly what cwnd allows and leaves the
%% state untouched.
unpaced_run_matches_cwnd_test() ->
    S = newreno(10 * ?MDS),
    ?assertEqual({10, S}, quic_cc_newreno:send_check_run(S, ?MDS, 64, 1)),
    ?assertEqual(10, sequential_checks(S, ?MDS, 64, 1, 0)),
    ?assertEqual({4, S}, quic_cc_newreno:send_check_run(S, ?MDS, 4, 1)),
    %% Control urgency gets the allowance on top of cwnd.
    {KCtl, _} = quic_cc_newreno:send_check_run(S, ?MDS, 64, 0),
    ?assertEqual(sequential_checks(S, ?MDS, 64, 0, 0), KCtl).

nothing_fits_test() ->
    S0 = newreno(3 * ?MDS),
    S = quic_cc_newreno:on_packet_sent(S0, 3 * ?MDS),
    ?assertEqual({0, S}, quic_cc_newreno:send_check_run(S, ?MDS, 8, 1)),
    ?assertEqual(0, sequential_checks(S, ?MDS, 8, 1, 0)).

%% Paced with a saturated bucket: the batch approves what the bucket
%% holds, never more than the sequential path would.
paced_run_is_bounded_by_the_bucket_test() ->
    S0 = quic_cc_newreno:update_pacing_rate(newreno(400 * ?MDS), 50),
    %% Let the bucket fill to its burst ceiling.
    timer:sleep(50),
    {KRun, _} = quic_cc_newreno:send_check_run(S0, ?MDS, 400, 1),
    KSeq = sequential_checks(S0, ?MDS, 400, 1, 0),
    ?assert(KRun > 0),
    ?assert(KRun =< KSeq),
    %% The sequential loop refills between iterations, so it can approve
    %% a few more than the batch did; how many depends on how long the
    %% loop took on this machine. Bound it loosely: the point is that the
    %% batch tracks the bucket, not that it matches to the packet.
    ?assert(KSeq - KRun =< 32).

on_packets_sent_matches_fold_test() ->
    %% A zero-byte send stamps first_sent_time, so both paths are
    %% deterministic from here on.
    S0 = quic_cc_newreno:on_packet_sent(newreno(64 * ?MDS), 0),
    Sizes = [1200, 1200, 900, 1200],
    Fold = lists:foldl(fun(Sz, Acc) -> quic_cc_newreno:on_packet_sent(Acc, Sz) end, S0, Sizes),
    ?assertEqual(Fold, quic_cc_newreno:on_packets_sent(S0, Sizes)),
    ?assertEqual(4500, quic_cc_newreno:bytes_in_flight(Fold)),
    ?assertEqual(S0, quic_cc_newreno:on_packets_sent(S0, [])).

loss_run_matches_fold_test() ->
    L0 = quic_loss:new(),
    Now = 12345,
    Tracked = [
        {7, 1200, {stream, 4, 0, <<"a">>, false}},
        {8, 1200, {stream, 4, 1200, <<"b">>, false}}
    ],
    Fold = lists:foldl(
        fun({PN, Sz, Fr}, Acc) -> quic_loss:on_packet_sent(Acc, PN, Sz, true, [Fr], Now) end,
        L0,
        Tracked
    ),
    ?assertEqual(Fold, quic_loss:on_packets_sent_run(L0, Tracked, Now)),
    %% With bytes already outstanding, outstanding_since is kept.
    L1 = quic_loss:on_packet_sent(L0, 1, 500, true, [], 100),
    Fold1 = lists:foldl(
        fun({PN, Sz, Fr}, Acc) -> quic_loss:on_packet_sent(Acc, PN, Sz, true, [Fr], Now) end,
        L1,
        Tracked
    ),
    ?assertEqual(Fold1, quic_loss:on_packets_sent_run(L1, Tracked, Now)).
