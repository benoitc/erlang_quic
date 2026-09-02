%%% -*- erlang -*-
%%%
%%% GRO receive splitting and GSO send batching.
%%%
%%% Both features are Linux-only and need kernel support to exercise
%%% end to end, but the parts that decide what happens are pure: reading
%%% the segment size out of the UDP_GRO control message, splitting a
%%% coalesced train back into datagrams, and grouping a mixed-size send
%%% batch into runs that UDP_SEGMENT can carry. These tests reach those
%%% directly, so they run and mean something on any platform.
%%%
%%% Covers PRs #204 and #217.

-module(quic_gro_gso_batching_tests).

-include_lib("eunit/include/eunit.hrl").

%% Must match quic_socket.
-define(UDP_GRO, 104).

%%====================================================================
%% Helpers
%%====================================================================

%% The kernel hands UDP_GRO up as an int, which is 4 bytes on every
%% platform this runs on.
gro_cmsg(Size) ->
    #{level => udp, type => ?UDP_GRO, data => <<Size:32/native>>}.

other_cmsg() ->
    #{level => ip, type => 8, data => <<0, 0, 0, 0>>}.

pkt(N, Size) ->
    binary:copy(<<N>>, Size).

%%====================================================================
%% Reading the GRO segment size (#204)
%%====================================================================

reads_the_int_sized_cmsg_test() ->
    %% The whole bug in one line: the payload is an int, so a pattern
    %% that accepts only two bytes never matches and the size is never
    %% found. A missed size means the coalesced buffer goes up unsplit
    %% as one oversized datagram, and the QUIC layer drops it because
    %% short-header packets cannot be re-split.
    ?assertEqual(1200, quic_socket:extract_gro_segment_size([gro_cmsg(1200)])).

reads_it_past_other_control_messages_test() ->
    Cmsgs = [other_cmsg(), gro_cmsg(1452), other_cmsg()],
    ?assertEqual(1452, quic_socket:extract_gro_segment_size(Cmsgs)).

reads_a_full_mtu_segment_size_test() ->
    ?assertEqual(65535, quic_socket:extract_gro_segment_size([gro_cmsg(65535)])).

no_cmsgs_means_no_size_test() ->
    ?assertEqual(undefined, quic_socket:extract_gro_segment_size([])).

unrelated_cmsgs_mean_no_size_test() ->
    ?assertEqual(undefined, quic_socket:extract_gro_segment_size([other_cmsg(), other_cmsg()])).

%%====================================================================
%% Splitting a coalesced train (#204's consequence)
%%====================================================================

splits_an_exact_multiple_test() ->
    Train = binary:copy(<<"a">>, 3600),
    Parts = quic_socket:split_gro_packets(Train, 1200),
    ?assertEqual(3, length(Parts)),
    ?assert(lists:all(fun(P) -> byte_size(P) =:= 1200 end, Parts)).

splits_with_a_short_final_segment_test() ->
    %% The last datagram of a train is usually shorter, and must survive
    %% rather than being padded or dropped.
    Train = binary:copy(<<"a">>, 2500),
    Parts = quic_socket:split_gro_packets(Train, 1200),
    ?assertEqual([1200, 1200, 100], [byte_size(P) || P <- Parts]).

splits_a_single_short_datagram_test() ->
    Parts = quic_socket:split_gro_packets(binary:copy(<<"a">>, 40), 1200),
    ?assertEqual([40], [byte_size(P) || P <- Parts]).

split_preserves_the_payload_test() ->
    Train = <<(pkt(1, 1200))/binary, (pkt(2, 1200))/binary, (pkt(3, 300))/binary>>,
    Parts = quic_socket:split_gro_packets(Train, 1200),
    ?assertEqual([pkt(1, 1200), pkt(2, 1200), pkt(3, 300)], Parts),
    ?assertEqual(Train, iolist_to_binary(Parts)).

%%====================================================================
%% Grouping a send batch into GSO runs (#217)
%%====================================================================

uniform_batch_is_one_run_test() ->
    Packets = [pkt(N, 1200) || N <- lists:seq(1, 4)],
    ?assertMatch([{gso, 1200, _}], quic_socket:split_uniform_runs(Packets)).

single_packet_is_not_a_gso_run_test() ->
    %% One packet has nothing to segment, so it goes out on its own
    %% rather than through UDP_SEGMENT.
    ?assertMatch([{single, _}], quic_socket:split_uniform_runs([pkt(1, 1200)])).

empty_batch_is_empty_test() ->
    ?assertEqual([], quic_socket:split_uniform_runs([])).

a_short_trailing_packet_joins_the_run_test() ->
    %% The kernel permits a short final segment, so an ACK behind a run
    %% of full packets does not need a send of its own.
    Packets = [pkt(1, 1200), pkt(2, 1200), pkt(3, 40)],
    ?assertMatch([{gso, 1200, [_, _, _]}], quic_socket:split_uniform_runs(Packets)).

a_larger_packet_starts_a_new_run_test() ->
    %% Growing sizes cannot share one UDP_SEGMENT call: only the final
    %% segment may be short.
    Packets = [pkt(1, 40), pkt(2, 40), pkt(3, 1200)],
    Runs = quic_socket:split_uniform_runs(Packets),
    ?assert(length(Runs) >= 2).

wire_order_and_payloads_survive_test() ->
    %% The property that actually matters: whatever the grouping, every
    %% packet goes out exactly once and in the order it was queued.
    Packets = [pkt(1, 1200), pkt(2, 40), pkt(3, 1200), pkt(4, 1200), pkt(5, 300)],
    Runs = quic_socket:split_uniform_runs(Packets),
    Flat = lists:flatmap(
        fun
            ({gso, _Size, Ps}) -> Ps;
            ({single, P}) -> [P]
        end,
        Runs
    ),
    ?assertEqual(Packets, Flat).

every_run_is_gso_legal_test() ->
    %% UDP_SEGMENT requires every segment except the last to be exactly
    %% the segment size. A run that breaks that is rejected by the
    %% kernel or splits the datagrams in the wrong place.
    Packets = [pkt(1, 1200), pkt(2, 1200), pkt(3, 40), pkt(4, 800), pkt(5, 800), pkt(6, 20)],
    Runs = quic_socket:split_uniform_runs(Packets),
    [ok = assert_run_legal(R) || R <- Runs],
    ok.

assert_run_legal({single, _P}) ->
    ok;
assert_run_legal({gso, Size, Ps}) ->
    {AllButLast, [Last]} = lists:split(length(Ps) - 1, Ps),
    ?assert(lists:all(fun(P) -> byte_size(P) =:= Size end, AllButLast)),
    ?assert(byte_size(Last) =< Size),
    ok.

%%====================================================================
%% Per-write kernel limits (#200)
%%====================================================================

%% One UDP_SEGMENT write takes at most 64 segments and a payload that
%% fits a 16-bit UDP length. 64 packets of 1398 bytes is 89 KB, so a
%% full batch has to become more than one write.
a_full_batch_of_mtu_packets_splits_across_writes_test() ->
    Packets = [pkt(N rem 251, 1398) || N <- lists:seq(1, 64)],
    Runs = quic_socket:split_uniform_runs(Packets),
    ?assert(length(Runs) > 1),
    [
        begin
            ?assert(length(Ps) =< 64),
            ?assert(lists:sum([byte_size(P) || P <- Ps]) =< 65535)
        end
     || {gso, _Size, Ps} <- Runs
    ],
    ok.

%% Splitting for the write limit must not drop, duplicate or reorder
%% anything, and each piece must still be a legal segmented write.
capped_runs_keep_every_packet_in_order_test() ->
    Packets = [pkt(N rem 251, 1398) || N <- lists:seq(1, 100)],
    Runs = quic_socket:split_uniform_runs(Packets),
    Flat = lists:append([
        case R of
            {single, P} -> [P];
            {gso, _, Ps} -> Ps
        end
     || R <- Runs
    ]),
    ?assertEqual(Packets, Flat),
    [ok = assert_run_legal(R) || R <- Runs],
    ok.

%% A short final packet is the batch's last segment, so it must land in
%% the final write rather than being carried into an earlier one.
a_capped_run_keeps_the_short_packet_last_test() ->
    Packets = [pkt(1, 1398) || _ <- lists:seq(1, 64)] ++ [pkt(2, 200)],
    Runs = quic_socket:split_uniform_runs(Packets),
    {gso, _, LastPs} = lists:last(Runs),
    ?assertEqual(200, byte_size(lists:last(LastPs))),
    [ok = assert_run_legal(R) || R <- Runs],
    ok.
