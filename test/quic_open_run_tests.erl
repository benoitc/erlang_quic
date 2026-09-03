%%% Differential tests for the batched fused receive path
%%% (quic_aead_ctx:open_run/8) against the per-packet open_packet/8.
-module(quic_open_run_tests).

-include_lib("eunit/include/eunit.hrl").

-define(KEY, <<0:128>>).
-define(IV, <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>).
-define(HP, <<16#aa:8, 0:120>>).
-define(DCID, <<9, 8, 7, 6>>).

%% FirstByteBase: short header, fixed bit, phase 0 (PN-length bits clear)
-define(FB_BASE, 16#40).
%% Same with key-phase bit (bit 2) set
-define(FB_PHASE1, 16#44).

with_nif(Fun) ->
    case quic_crypto_nif:is_loaded() of
        true -> Fun();
        false -> ok
    end.

build_run(PN0, FirstByteBase, Payloads) ->
    {ok, Packets} = quic_aead_ctx:protect_run(
        aes_128_gcm, ?KEY, ?IV, ?HP, PN0, FirstByteBase, ?DCID, Payloads
    ),
    Packets.

payloads(N) ->
    [
        <<I, "payload-", (integer_to_binary(I))/binary, 0:(200 * 8)>>
     || <<I>> <= list_to_binary(lists:seq(1, N))
    ].

open_run_roundtrip_test() ->
    with_nif(fun() ->
        Payloads = payloads(8),
        Packets = build_run(0, ?FB_BASE, Payloads),
        {ok, Results} = quic_aead_ctx:open_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, undefined, 0, byte_size(?DCID), Packets
        ),
        ?assertEqual(8, length(Results)),
        ?assertEqual(
            lists:seq(0, 7),
            [PN || {PN, _FB, _P} <- Results]
        ),
        ?assertEqual(Payloads, [P || {_PN, _FB, P} <- Results])
    end).

open_run_matches_sequential_test() ->
    with_nif(fun() ->
        Payloads = payloads(6),
        Packets = build_run(100, ?FB_BASE, Payloads),
        {ok, Batch} = quic_aead_ctx:open_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, 99, 0, byte_size(?DCID), Packets
        ),
        HdrLen = 1 + byte_size(?DCID),
        {Seq, _} = lists:mapfoldl(
            fun(Pkt, Largest) ->
                <<Header:HdrLen/binary, Payload/binary>> = Pkt,
                {ok, PN, FB, Plain} = quic_aead_ctx:open_packet(
                    aes_128_gcm, ?KEY, ?IV, ?HP, Largest, 0, Header, Payload
                ),
                {{PN, FB, Plain}, max(Largest, PN)}
            end,
            99,
            Packets
        ),
        ?assertEqual(Seq, Batch)
    end).

open_run_stops_at_bad_tag_test() ->
    with_nif(fun() ->
        Packets = build_run(0, ?FB_BASE, payloads(6)),
        {Good, [Bad | Tail]} = lists:split(3, Packets),
        Sz = byte_size(Bad),
        <<Head:(Sz - 1)/binary, Last>> = Bad,
        Corrupt = <<Head/binary, (Last bxor 16#ff)>>,
        {ok, Results} = quic_aead_ctx:open_run(
            aes_128_gcm,
            ?KEY,
            ?IV,
            ?HP,
            undefined,
            0,
            byte_size(?DCID),
            Good ++ [Corrupt | Tail]
        ),
        ?assertEqual(3, length(Results)),
        ?assertEqual([0, 1, 2], [PN || {PN, _, _} <- Results])
    end).

open_run_stops_at_phase_mismatch_test() ->
    with_nif(fun() ->
        [P0, P1] = build_run(0, ?FB_BASE, payloads(2)),
        [Q0] = build_run(2, ?FB_PHASE1, payloads(1)),
        {ok, Results} = quic_aead_ctx:open_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, undefined, 0, byte_size(?DCID), [P0, P1, Q0]
        ),
        ?assertEqual(2, length(Results))
    end).

open_run_short_datagram_test() ->
    with_nif(fun() ->
        [P0] = build_run(0, ?FB_BASE, payloads(1)),
        {ok, Results} = quic_aead_ctx:open_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, undefined, 0, byte_size(?DCID), [<<1, 2, 3>>, P0]
        ),
        ?assertEqual([], Results)
    end).

open_run_empty_test() ->
    with_nif(fun() ->
        ?assertEqual(
            {ok, []},
            quic_aead_ctx:open_run(
                aes_128_gcm, ?KEY, ?IV, ?HP, undefined, 0, byte_size(?DCID), []
            )
        )
    end).

%% A run with a hole in the packet-number sequence (a lost datagram in
%% the middle of a GRO train) must still open every present packet with
%% its own packet number, carrying the largest forward across the gap.
open_run_with_pn_gap_test() ->
    with_nif(fun() ->
        [A, B] = build_run(10, ?FB_BASE, payloads(2)),
        [C, D] = build_run(13, ?FB_BASE, payloads(2)),
        {ok, Results} = quic_aead_ctx:open_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, 9, 0, byte_size(?DCID), [A, B, C, D]
        ),
        ?assertEqual([10, 11, 13, 14], [PN || {PN, _FB, _P} <- Results])
    end).

%% Reordered within a train: an older packet after newer ones.
open_run_reordered_test() ->
    with_nif(fun() ->
        [A, B, C] = build_run(20, ?FB_BASE, payloads(3)),
        {ok, Results} = quic_aead_ctx:open_run(
            aes_128_gcm, ?KEY, ?IV, ?HP, 19, 0, byte_size(?DCID), [B, C, A]
        ),
        ?assertEqual([21, 22, 20], [PN || {PN, _FB, _P} <- Results])
    end).
