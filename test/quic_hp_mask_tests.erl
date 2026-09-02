%%% -*- erlang -*-
%%%
%%% Header protection masks come from a cipher context cached per
%%% process, which is only safe because ECB blocks are independent. The
%%% mask must stay byte-identical to the one-shot call, and a rotated
%%% key must not keep using the old context.

-module(quic_hp_mask_tests).

-include_lib("eunit/include/eunit.hrl").

-define(KEY128, <<"0123456789abcdef">>).
-define(KEY256, <<"0123456789abcdef0123456789abcdef">>).
-define(SAMPLE, <<"abcdefghijklmnop">>).

%% The cached context has to produce exactly what the one-shot call did,
%% or every peer rejects our headers.
matches_the_one_shot_mask_test_() ->
    [
        {atom_to_list(Cipher), fun() ->
            {Key, Ecb} = params(Cipher),
            ?assertEqual(
                crypto:crypto_one_time(Ecb, Key, ?SAMPLE, true),
                quic_aead:compute_hp_mask(Cipher, Key, ?SAMPLE)
            )
        end}
     || Cipher <- [aes_128_gcm, aes_256_gcm]
    ].

%% Repeated use of one context must not chain state: each sample is an
%% independent block.
repeated_samples_do_not_chain_test() ->
    A = quic_aead:compute_hp_mask(aes_128_gcm, ?KEY128, ?SAMPLE),
    _ = quic_aead:compute_hp_mask(aes_128_gcm, ?KEY128, <<"different sample">>),
    B = quic_aead:compute_hp_mask(aes_128_gcm, ?KEY128, ?SAMPLE),
    ?assertEqual(A, B).

%% A key update installs a new HP key; the cache must follow it rather
%% than keep masking with the retired one.
a_rotated_key_replaces_the_context_test() ->
    Old = quic_aead:compute_hp_mask(aes_128_gcm, ?KEY128, ?SAMPLE),
    New = <<"fedcba9876543210">>,
    Got = quic_aead:compute_hp_mask(aes_128_gcm, New, ?SAMPLE),
    ?assertNotEqual(Old, Got),
    ?assertEqual(crypto:crypto_one_time(aes_128_ecb, New, ?SAMPLE, true), Got),
    %% and back again, so the swap is not one-way
    ?assertEqual(Old, quic_aead:compute_hp_mask(aes_128_gcm, ?KEY128, ?SAMPLE)).

%% The two AES sizes cache separately.
the_two_aes_sizes_do_not_share_a_context_test() ->
    M128 = quic_aead:compute_hp_mask(aes_128_gcm, ?KEY128, ?SAMPLE),
    M256 = quic_aead:compute_hp_mask(aes_256_gcm, ?KEY256, ?SAMPLE),
    ?assertEqual(crypto:crypto_one_time(aes_128_ecb, ?KEY128, ?SAMPLE, true), M128),
    ?assertEqual(crypto:crypto_one_time(aes_256_ecb, ?KEY256, ?SAMPLE, true), M256).

%% ChaCha20 keeps the one-shot path: its mask depends on the sample as
%% nonce, so there is no context to reuse.
chacha_mask_is_unchanged_test() ->
    Sample = <<1:32/little, 2:96>>,
    ?assertEqual(
        crypto:crypto_one_time(chacha20, ?KEY256, Sample, <<0, 0, 0, 0, 0>>, true),
        quic_aead:compute_hp_mask(chacha20_poly1305, ?KEY256, Sample)
    ).

params(aes_128_gcm) -> {?KEY128, aes_128_ecb};
params(aes_256_gcm) -> {?KEY256, aes_256_ecb}.
