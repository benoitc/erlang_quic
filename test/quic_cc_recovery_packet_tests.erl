%%% -*- erlang -*-
%%%
%%% RFC 9002 Section 7.3.2: "If the congestion window is reduced
%%% immediately, a single packet can be sent prior to reduction." The
%%% quic_cc wrapper lets the next packet out after a congestion event
%%% that cut the window, whatever the algorithm, and only that one.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cc_recovery_packet_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PKT, 1200).

one_packet_after_the_cut_test_() ->
    [{atom_to_list(A), fun() -> one_packet_after_the_cut(A) end} || A <- [newreno, cubic]].

one_packet_after_the_cut(Algorithm) ->
    S1 = cut(full(Algorithm)),
    ?assert(quic_cc:bytes_in_flight(S1) > quic_cc:cwnd(S1)),
    ?assert(quic_cc:can_send(S1, ?PKT)),
    ?assertMatch({ok, _}, quic_cc:send_check(S1, ?PKT)),
    S2 = quic_cc:on_packet_sent(S1, ?PKT),
    ?assertNot(quic_cc:can_send(S2, ?PKT)),
    ?assertMatch({blocked_cwnd, _}, quic_cc:send_check(S2, ?PKT)).

%% A batch of chunks gets the one packet, not a run.
one_chunk_of_a_run_test() ->
    S1 = cut(full(newreno)),
    ?assertMatch({1, _}, quic_cc:send_check_run(S1, ?PKT, 8)),
    S2 = quic_cc:on_packets_sent(S1, [?PKT]),
    ?assertMatch({0, _}, quic_cc:send_check_run(S2, ?PKT, 8)).

%% A second loss in the same recovery period does not cut, so it adds
%% nothing (Section 7.3.2: the window changes once per round trip).
no_second_packet_within_recovery_test() ->
    S1 = quic_cc:on_packet_sent(cut(full(newreno)), ?PKT),
    S2 = quic_cc:on_congestion_event(S1, erlang:monotonic_time(millisecond) - 10000),
    ?assertNot(quic_cc:can_send(S2, ?PKT)).

%% BBR does not cut the window on entering recovery, so there is no
%% packet to grant.
bbr_enters_recovery_without_a_cut_test() ->
    S0 = full(bbr),
    S1 = cut(S0),
    ?assert(quic_cc:in_recovery(S1)),
    ?assertEqual(quic_cc:cwnd(S0), quic_cc:cwnd(S1)),
    ?assertNot(quic_cc:can_send(S1, ?PKT)).

%% Undoing a spurious cut takes the packet back.
spurious_cut_takes_the_packet_back_test() ->
    S1 = quic_cc:on_spurious_congestion(cut(full(newreno))),
    ?assertNot(quic_cc:can_send(S1, quic_cc:cwnd(S1))).

%% A window with no room left for a packet.
full(Algorithm) ->
    fill(quic_cc:new(Algorithm, #{initial_window => 10 * ?PKT, min_recovery_duration => 0})).

fill(CC) ->
    case quic_cc:can_send(CC, ?PKT) of
        true -> fill(quic_cc:on_packet_sent(CC, ?PKT));
        false -> CC
    end.

cut(CC) ->
    quic_cc:on_congestion_event(CC, erlang:monotonic_time(millisecond)).
