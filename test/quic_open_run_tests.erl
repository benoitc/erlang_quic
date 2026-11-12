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
    %% 16#1f is not a QUIC frame type, so the in-NIF frame parser always
    %% takes the {raw, Plain} fallback for these synthetic payloads.
    [
        <<16#1f, I, "payload-", (integer_to_binary(I))/binary, 0:(199 * 8)>>
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
        %% Test payloads are not valid frame sequences, so the in-NIF
        %% frame parser falls back to {raw, Plain} for every packet.
        ?assertEqual(Payloads, [P || {_PN, _FB, {raw, P}} <- Results])
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
                {{PN, FB, {raw, Plain}}, max(Largest, PN)}
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

%% Same run shape under ChaCha20-Poly1305: the batched open must agree
%% with the per-packet open on the ChaCha header-protection mask too.
open_run_chacha_matches_sequential_test() ->
    with_nif(fun() ->
        Key = crypto:strong_rand_bytes(32),
        HP = crypto:strong_rand_bytes(32),
        Payloads = payloads(6),
        {ok, Packets} = quic_aead_ctx:protect_run(
            chacha20_poly1305, Key, ?IV, HP, 100, ?FB_BASE, ?DCID, Payloads
        ),
        {ok, Batch} = quic_aead_ctx:open_run(
            chacha20_poly1305, Key, ?IV, HP, 99, 0, byte_size(?DCID), Packets
        ),
        ?assertEqual(lists:seq(100, 105), [PN || {PN, _FB, _P} <- Batch]),
        ?assertEqual(Payloads, [P || {_PN, _FB, {raw, P}} <- Batch])
    end).

%% A 1-RTT packet with a valid tag and no plaintext: the in-NIF frame
%% parser must see zero bytes, so open_run hands back {raw, <<>>} and
%% the Erlang decoder rejects the frameless packet.
open_run_empty_payload_test_() ->
    [
        {atom_to_list(Cipher), fun() -> with_nif(fun() -> empty_payload_check(Cipher) end) end}
     || Cipher <- [aes_128_gcm, aes_256_gcm, chacha20_poly1305]
    ].

empty_payload_check(Cipher) ->
    {Key, HP} = empty_keys(Cipher),
    DCID = binary:copy(<<16#5a>>, 20),
    Packet = seal_empty(Cipher, Key, HP, DCID, 0),
    lists:foreach(
        fun(N) ->
            %% Vary what sits in the free heap past the plaintext, so a
            %% read beyond it would decode those bytes as frames.
            Junk = [list_to_binary(lists:duplicate(64, 1)) || _ <- lists:seq(1, N)],
            _ = erlang:phash2(Junk),
            ?assertEqual(
                {ok, [{0, 16#43, {raw, <<>>}}]},
                quic_aead_ctx:open_run(
                    Cipher, Key, ?IV, HP, undefined, 0, byte_size(DCID), [Packet]
                )
            ),
            <<Header:21/binary, Payload/binary>> = Packet,
            ?assertEqual(
                {ok, 0, 16#43, <<>>},
                quic_aead_ctx:open_packet(Cipher, Key, ?IV, HP, undefined, 0, Header, Payload)
            )
        end,
        lists:seq(0, 3000, 7)
    ).

empty_keys(aes_128_gcm) -> {?KEY, ?HP};
empty_keys(_) -> {<<0:256>>, <<16#aa:8, 0:248>>}.

%% Short header with a 4-byte packet number, sealed with OTP crypto
%% over an empty plaintext: the payload is the PN and the tag only.
seal_empty(Cipher, Key, HP, DCID, PN) ->
    FB = 16#43,
    Header = <<FB, DCID/binary, PN:32>>,
    <<IVHi:4/binary, IVLo:64>> = ?IV,
    Nonce = <<IVHi/binary, (IVLo bxor PN):64>>,
    {<<>>, Tag} = crypto:crypto_one_time_aead(Cipher, Key, Nonce, <<>>, Header, true),
    <<M0, M1, M2, M3, M4, _/binary>> = empty_mask(Cipher, HP, Tag),
    <<PN0, PN1, PN2, PN3>> = <<PN:32>>,
    <<
        (FB bxor (M0 band 16#1f)),
        DCID/binary,
        (PN0 bxor M1),
        (PN1 bxor M2),
        (PN2 bxor M3),
        (PN3 bxor M4),
        Tag/binary
    >>.

empty_mask(aes_128_gcm, HP, Sample) ->
    crypto:crypto_one_time(aes_128_ecb, HP, Sample, true);
empty_mask(aes_256_gcm, HP, Sample) ->
    crypto:crypto_one_time(aes_256_ecb, HP, Sample, true);
empty_mask(chacha20_poly1305, HP, Sample) ->
    crypto:crypto_one_time(chacha20, HP, Sample, <<0:40>>, true).
