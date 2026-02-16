%%% -*- erlang -*-
%%%
%%% Tests for QUIC 0-RTT (Early Data)
%%% RFC 9001 Section 4.6
%%%

-module(quic_zero_rtt_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Early Secret Tests
%%====================================================================

early_secret_with_psk_test() ->
    %% With PSK, early secret is derived from PSK
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ?assertEqual(32, byte_size(EarlySecret)).

early_secret_without_psk_test() ->
    %% Without PSK, early secret is derived from zeros
    EarlySecret = quic_crypto:derive_early_secret(),
    ?assertEqual(32, byte_size(EarlySecret)).

early_secret_deterministic_test() ->
    PSK = crypto:strong_rand_bytes(32),
    ES1 = quic_crypto:derive_early_secret(PSK),
    ES2 = quic_crypto:derive_early_secret(PSK),
    ?assertEqual(ES1, ES2).

early_secret_aes_256_test() ->
    %% AES-256-GCM uses SHA-384
    PSK = crypto:strong_rand_bytes(48),
    EarlySecret = quic_crypto:derive_early_secret(aes_256_gcm, PSK),
    ?assertEqual(48, byte_size(EarlySecret)).

%%====================================================================
%% Client Early Traffic Secret Tests
%%====================================================================

client_early_secret_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:strong_rand_bytes(32),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        EarlySecret, ClientHelloHash),
    ?assertEqual(32, byte_size(ClientEarlySecret)).

client_early_secret_cipher_aware_test() ->
    PSK = crypto:strong_rand_bytes(48),
    EarlySecret = quic_crypto:derive_early_secret(aes_256_gcm, PSK),
    ClientHelloHash = crypto:strong_rand_bytes(48),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        aes_256_gcm, EarlySecret, ClientHelloHash),
    ?assertEqual(48, byte_size(ClientEarlySecret)).

%%====================================================================
%% 0-RTT Keys Tests
%%====================================================================

zero_rtt_keys_test() ->
    %% Derive 0-RTT keys from client early traffic secret
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:strong_rand_bytes(32),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        EarlySecret, ClientHelloHash),

    %% Derive actual keys
    {Key, IV, HP} = quic_keys:derive_keys(ClientEarlySecret, aes_128_gcm),
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(16, byte_size(HP)).

zero_rtt_keys_aes_256_test() ->
    PSK = crypto:strong_rand_bytes(48),
    EarlySecret = quic_crypto:derive_early_secret(aes_256_gcm, PSK),
    ClientHelloHash = crypto:strong_rand_bytes(48),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        aes_256_gcm, EarlySecret, ClientHelloHash),

    {Key, IV, HP} = quic_keys:derive_keys(ClientEarlySecret, aes_256_gcm),
    ?assertEqual(32, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(32, byte_size(HP)).

%%====================================================================
%% PSK Binder Tests
%%====================================================================

binder_computation_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    TruncatedClientHelloHash = crypto:strong_rand_bytes(32),

    Binder = quic_crypto:compute_psk_binder(
        EarlySecret, TruncatedClientHelloHash, resumption),
    ?assertEqual(32, byte_size(Binder)).

binder_deterministic_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    TruncatedCH = crypto:strong_rand_bytes(32),

    Binder1 = quic_crypto:compute_psk_binder(EarlySecret, TruncatedCH, resumption),
    Binder2 = quic_crypto:compute_psk_binder(EarlySecret, TruncatedCH, resumption),
    ?assertEqual(Binder1, Binder2).

binder_resumption_vs_external_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    TruncatedCH = crypto:strong_rand_bytes(32),

    ResumptionBinder = quic_crypto:compute_psk_binder(EarlySecret, TruncatedCH, resumption),
    ExternalBinder = quic_crypto:compute_psk_binder(EarlySecret, TruncatedCH, external),

    %% Different binder types should produce different values
    ?assertNotEqual(ResumptionBinder, ExternalBinder).

binder_aes_256_test() ->
    PSK = crypto:strong_rand_bytes(48),
    EarlySecret = quic_crypto:derive_early_secret(aes_256_gcm, PSK),
    TruncatedCH = crypto:strong_rand_bytes(48),

    Binder = quic_crypto:compute_psk_binder(
        aes_256_gcm, EarlySecret, TruncatedCH, resumption),
    %% SHA-384 produces 48-byte output
    ?assertEqual(48, byte_size(Binder)).

%%====================================================================
%% Early Exporter Master Secret Tests
%%====================================================================

early_exporter_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:strong_rand_bytes(32),

    EarlyExporter = quic_crypto:derive_early_exporter_master_secret(
        EarlySecret, ClientHelloHash),
    ?assertEqual(32, byte_size(EarlyExporter)).

%%====================================================================
%% 0-RTT Packet Roundtrip Tests
%%====================================================================

zero_rtt_packet_encrypt_decrypt_test() ->
    %% Derive 0-RTT keys
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        EarlySecret, ClientHelloHash),
    {Key, IV, _HP} = quic_keys:derive_keys(ClientEarlySecret, aes_128_gcm),

    %% Encrypt some data
    PN = 0,
    Plaintext = <<"Hello, 0-RTT world!">>,
    AAD = <<>>,  % Simplified for test

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
    ?assert(byte_size(Ciphertext) > byte_size(Plaintext)),  % Has tag

    %% Decrypt
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

zero_rtt_multiple_packets_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        EarlySecret, ClientHelloHash),
    {Key, IV, _HP} = quic_keys:derive_keys(ClientEarlySecret, aes_128_gcm),

    %% Encrypt multiple packets with different PNs
    Packets = [
        {0, <<"First 0-RTT packet">>},
        {1, <<"Second 0-RTT packet">>},
        {2, <<"Third 0-RTT packet">>}
    ],

    Results = lists:map(
        fun({PN, Plaintext}) ->
            AAD = <<PN:32>>,
            Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
            {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
            {PN, Plaintext, Decrypted}
        end, Packets),

    %% All decrypted correctly
    lists:foreach(
        fun({_PN, Original, Decrypted}) ->
            ?assertEqual(Original, Decrypted)
        end, Results).
