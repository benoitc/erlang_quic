%%% -*- erlang -*-
%%%
%%% AEAD dispatch: NIF-accelerated contexts with OTP crypto fallback.
%%%
%%% QUIC seals/opens every packet as its own AEAD unit, and the OTP
%%% one-shot API re-runs the key schedule on each call. When the
%%% optional quic_crypto_nif is loaded, this module keeps an
%%% EVP context per {direction, cipher, key} in the calling process's
%%% dictionary (contexts are single-process; connection processes are
%%% the only callers) so the key schedule runs once per key. Without
%%% the NIF every function degrades to crypto:crypto_one_time_aead /
%%% crypto:crypto_one_time with identical semantics.

-module(quic_aead_ctx).

-export([
    aead_encrypt/5,
    aead_decrypt/6,
    hp_block/3
]).

-define(TAG_LEN, 16).

%% @doc Seal: returns Ciphertext||Tag.
-spec aead_encrypt(atom(), binary(), binary(), binary(), binary()) -> binary().
aead_encrypt(Cipher, Key, Nonce, Plaintext, AAD) ->
    case nif_enabled() of
        true ->
            Ctx = ctx(qc_enc, Cipher, Key),
            case quic_crypto_nif:seal(Ctx, Nonce, AAD, Plaintext) of
                Out when is_binary(Out) -> Out;
                {error, _} -> fallback_encrypt(Cipher, Key, Nonce, Plaintext, AAD)
            end;
        false ->
            fallback_encrypt(Cipher, Key, Nonce, Plaintext, AAD)
    end.

%% @doc Open: Ciphertext WITHOUT tag + Tag; returns Plaintext | error.
-spec aead_decrypt(atom(), binary(), binary(), binary(), binary(), binary()) ->
    binary() | error.
aead_decrypt(Cipher, Key, Nonce, Ciphertext, AAD, Tag) ->
    case nif_enabled() of
        true ->
            Ctx = ctx(qc_dec, Cipher, Key),
            case quic_crypto_nif:open(Ctx, Nonce, AAD, Ciphertext, Tag) of
                Out when is_binary(Out) -> Out;
                error -> error;
                {error, _} -> fallback_decrypt(Cipher, Key, Nonce, Ciphertext, AAD, Tag)
            end;
        false ->
            fallback_decrypt(Cipher, Key, Nonce, Ciphertext, AAD, Tag)
    end.

%% @doc One ECB block for AES header protection (mask source).
-spec hp_block(aes_128_ecb | aes_256_ecb, binary(), binary()) -> binary().
hp_block(Cipher, Key, Sample) ->
    case nif_enabled() of
        true ->
            Ctx = hp_ctx(Cipher, Key),
            case quic_crypto_nif:hp_block(Ctx, Sample) of
                Out when is_binary(Out) -> Out;
                {error, _} -> quic_aead:ecb_mask(Cipher, Key, Sample)
            end;
        false ->
            quic_aead:ecb_mask(Cipher, Key, Sample)
    end.

%%====================================================================
%% Internal
%%====================================================================

fallback_encrypt(Cipher, Key, Nonce, Plaintext, AAD) ->
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        Cipher, Key, Nonce, Plaintext, AAD, ?TAG_LEN, true
    ),
    <<Ciphertext/binary, Tag/binary>>.

fallback_decrypt(Cipher, Key, Nonce, Ciphertext, AAD, Tag) ->
    crypto:crypto_one_time_aead(Cipher, Key, Nonce, Ciphertext, AAD, Tag, false).

%% Cache the NIF-availability flag per process: checked on every
%% packet, and a process dictionary read beats a NIF call.
nif_enabled() ->
    case erlang:get(qc_nif) of
        undefined ->
            V = quic_crypto_nif:is_loaded(),
            erlang:put(qc_nif, V),
            V;
        V ->
            V
    end.

%% Per-process context cache. A connection holds a handful of live
%% keys (current + previous key phase per direction); stale entries
%% from key updates are few and die with the process.
ctx(Kind, Cipher, Key) ->
    PdKey = {Kind, Cipher, Key},
    case erlang:get(PdKey) of
        undefined ->
            {ok, Ctx} = quic_crypto_nif:new_aead_ctx(Cipher, Key, Kind =:= qc_enc),
            erlang:put(PdKey, Ctx),
            Ctx;
        Ctx ->
            Ctx
    end.

hp_ctx(Cipher, Key) ->
    PdKey = {qc_hp, Cipher, Key},
    case erlang:get(PdKey) of
        undefined ->
            {ok, Ctx} = quic_crypto_nif:new_hp_ctx(Cipher, Key),
            erlang:put(PdKey, Ctx),
            Ctx;
        Ctx ->
            Ctx
    end.
