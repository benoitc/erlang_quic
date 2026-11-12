%%% -*- erlang -*-
%%%
%%% Tests for QUIC TLS 1.3 Cryptographic Operations
%%% TLS 1.3 key schedule (RFC 9846 Section 7.1)
%%%

-module(quic_crypto_tests).

-include_lib("eunit/include/eunit.hrl").

%%====================================================================
%% Key Schedule Tests
%%====================================================================

early_secret_no_psk_test() ->
    %% Without PSK, early_secret = HKDF-Extract(0, 0)
    EarlySecret = quic_crypto:derive_early_secret(),
    ?assertEqual(32, byte_size(EarlySecret)).

early_secret_deterministic_test() ->
    %% Same PSK should produce same early secret
    PSK = <<"test-psk">>,
    ES1 = quic_crypto:derive_early_secret(PSK),
    ES2 = quic_crypto:derive_early_secret(PSK),
    ?assertEqual(ES1, ES2).

early_secret_different_psk_test() ->
    PSK1 = <<"psk1">>,
    PSK2 = <<"psk2">>,
    ES1 = quic_crypto:derive_early_secret(PSK1),
    ES2 = quic_crypto:derive_early_secret(PSK2),
    ?assertNotEqual(ES1, ES2).

handshake_secret_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    ?assertEqual(32, byte_size(HS)).

master_secret_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    MS = quic_crypto:derive_master_secret(HS),
    ?assertEqual(32, byte_size(MS)).

%%====================================================================
%% Traffic Secret Tests
%%====================================================================

client_handshake_secret_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    TranscriptHash = crypto:hash(sha256, <<"ClientHelloServerHello">>),
    CHS = quic_crypto:derive_client_handshake_secret(HS, TranscriptHash),
    ?assertEqual(32, byte_size(CHS)).

server_handshake_secret_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    TranscriptHash = crypto:hash(sha256, <<"ClientHelloServerHello">>),
    SHS = quic_crypto:derive_server_handshake_secret(HS, TranscriptHash),
    ?assertEqual(32, byte_size(SHS)).

client_server_handshake_different_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    TranscriptHash = crypto:hash(sha256, <<"ClientHelloServerHello">>),
    CHS = quic_crypto:derive_client_handshake_secret(HS, TranscriptHash),
    SHS = quic_crypto:derive_server_handshake_secret(HS, TranscriptHash),
    %% Client and server secrets should be different
    ?assertNotEqual(CHS, SHS).

app_secrets_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    MS = quic_crypto:derive_master_secret(HS),
    TranscriptHash = crypto:hash(sha256, <<"full_transcript">>),

    CAS = quic_crypto:derive_client_app_secret(MS, TranscriptHash),
    SAS = quic_crypto:derive_server_app_secret(MS, TranscriptHash),

    ?assertEqual(32, byte_size(CAS)),
    ?assertEqual(32, byte_size(SAS)),
    ?assertNotEqual(CAS, SAS).

%%====================================================================
%% Derive-Secret Tests
%%====================================================================

derive_secret_empty_messages_test() ->
    Secret = crypto:strong_rand_bytes(32),
    Label = <<"derived">>,
    %% Empty messages should hash to H("")
    Result = quic_crypto:derive_secret(Secret, Label, <<>>),
    ?assertEqual(32, byte_size(Result)).

derive_secret_deterministic_test() ->
    Secret = crypto:strong_rand_bytes(32),
    Label = <<"test label">>,
    Messages = <<"some messages">>,

    Result1 = quic_crypto:derive_secret(Secret, Label, Messages),
    Result2 = quic_crypto:derive_secret(Secret, Label, Messages),
    ?assertEqual(Result1, Result2).

derive_secret_pre_hashed_test() ->
    Secret = crypto:strong_rand_bytes(32),
    Label = <<"test">>,
    Messages = <<"some messages">>,
    PreHashed = crypto:hash(sha256, Messages),

    %% Both should produce same result
    Result1 = quic_crypto:derive_secret(Secret, Label, Messages),
    Result2 = quic_crypto:derive_secret(Secret, Label, PreHashed),
    ?assertEqual(Result1, Result2).

%%====================================================================
%% Finished Key and Verify Data Tests
%%====================================================================

finished_key_test() ->
    TrafficSecret = crypto:strong_rand_bytes(32),
    FinishedKey = quic_crypto:derive_finished_key(TrafficSecret),
    ?assertEqual(32, byte_size(FinishedKey)).

finished_key_deterministic_test() ->
    TrafficSecret = crypto:strong_rand_bytes(32),
    FK1 = quic_crypto:derive_finished_key(TrafficSecret),
    FK2 = quic_crypto:derive_finished_key(TrafficSecret),
    ?assertEqual(FK1, FK2).

finished_verify_test() ->
    TrafficSecret = crypto:strong_rand_bytes(32),
    FinishedKey = quic_crypto:derive_finished_key(TrafficSecret),
    TranscriptHash = crypto:hash(sha256, <<"handshake messages">>),

    VerifyData = quic_crypto:compute_finished_verify(FinishedKey, TranscriptHash),
    ?assertEqual(32, byte_size(VerifyData)).

finished_verify_deterministic_test() ->
    TrafficSecret = crypto:strong_rand_bytes(32),
    FinishedKey = quic_crypto:derive_finished_key(TrafficSecret),
    TranscriptHash = crypto:hash(sha256, <<"messages">>),

    VD1 = quic_crypto:compute_finished_verify(FinishedKey, TranscriptHash),
    VD2 = quic_crypto:compute_finished_verify(FinishedKey, TranscriptHash),
    ?assertEqual(VD1, VD2).

%%====================================================================
%% ECDHE Tests
%%====================================================================

x25519_key_generation_test() ->
    {PubKey, PrivKey} = quic_crypto:generate_key_pair(x25519),
    %% X25519 keys are 32 bytes
    ?assertEqual(32, byte_size(PubKey)),
    ?assertEqual(32, byte_size(PrivKey)).

x25519_shared_secret_test() ->
    {PubA, PrivA} = quic_crypto:generate_key_pair(x25519),
    {PubB, PrivB} = quic_crypto:generate_key_pair(x25519),

    %% Both sides should compute same shared secret
    SharedA = quic_crypto:compute_shared_secret(x25519, PrivA, PubB),
    SharedB = quic_crypto:compute_shared_secret(x25519, PrivB, PubA),
    ?assertEqual(SharedA, SharedB).

secp256r1_key_generation_test() ->
    {PubKey, PrivKey} = quic_crypto:generate_key_pair(secp256r1),
    %% P-256 public keys are 65 bytes (uncompressed: 04 || x || y)
    ?assertEqual(65, byte_size(PubKey)),
    %% Private key is 32 bytes
    ?assertEqual(32, byte_size(PrivKey)).

secp256r1_shared_secret_test() ->
    {PubA, PrivA} = quic_crypto:generate_key_pair(secp256r1),
    {PubB, PrivB} = quic_crypto:generate_key_pair(secp256r1),

    SharedA = quic_crypto:compute_shared_secret(secp256r1, PrivA, PubB),
    SharedB = quic_crypto:compute_shared_secret(secp256r1, PrivB, PubA),
    ?assertEqual(SharedA, SharedB).

%%====================================================================
%% Transcript Hash Tests
%%====================================================================

transcript_hash_empty_test() ->
    %% SHA-256 of empty string
    Expected = crypto:hash(sha256, <<>>),
    Result = quic_crypto:transcript_hash(<<>>),
    ?assertEqual(Expected, Result).

transcript_hash_test() ->
    Messages = <<"ClientHello || ServerHello">>,
    Expected = crypto:hash(sha256, Messages),
    Result = quic_crypto:transcript_hash(Messages),
    ?assertEqual(Expected, Result).

%%====================================================================
%% RFC 8448 Test Vectors
%%====================================================================

%% RFC 8448 Section 3: with no PSK the early secret is HKDF-Extract(0, 0)
%% over SHA-256.
rfc8448_early_secret_zero_psk_test() ->
    Expected = binary:decode_hex(
        <<"33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a">>
    ),
    ?assertEqual(Expected, quic_crypto:derive_early_secret()).

%%====================================================================
%% Full Key Schedule Integration Test
%%====================================================================

full_key_schedule_integration_test() ->
    %% Simulate a TLS 1.3 / QUIC key derivation flow

    %% Step 1: Early secret (no PSK)
    EarlySecret = quic_crypto:derive_early_secret(),
    ?assertEqual(32, byte_size(EarlySecret)),

    %% Step 2: ECDHE key exchange
    {ClientPub, ClientPriv} = quic_crypto:generate_key_pair(x25519),
    {ServerPub, _ServerPriv} = quic_crypto:generate_key_pair(x25519),
    SharedSecret = quic_crypto:compute_shared_secret(x25519, ClientPriv, ServerPub),
    ?assertEqual(32, byte_size(SharedSecret)),

    %% Step 3: Handshake secret
    HandshakeSecret = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    ?assertEqual(32, byte_size(HandshakeSecret)),

    %% Step 4: Handshake traffic secrets
    HSTranscript = quic_crypto:transcript_hash(<<ClientPub/binary, ServerPub/binary>>),
    ClientHS = quic_crypto:derive_client_handshake_secret(HandshakeSecret, HSTranscript),
    ServerHS = quic_crypto:derive_server_handshake_secret(HandshakeSecret, HSTranscript),
    ?assertEqual(32, byte_size(ClientHS)),
    ?assertEqual(32, byte_size(ServerHS)),

    %% Step 5: Derive keys from handshake secrets
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_traffic_keys(ClientHS),
    ?assertEqual(16, byte_size(ClientKey)),
    ?assertEqual(12, byte_size(ClientIV)),
    ?assertEqual(16, byte_size(ClientHP)),

    %% Step 6: Master secret
    MasterSecret = quic_crypto:derive_master_secret(HandshakeSecret),
    ?assertEqual(32, byte_size(MasterSecret)),

    %% Step 7: Application traffic secrets
    AppTranscript = quic_crypto:transcript_hash(<<"full transcript">>),
    ClientApp = quic_crypto:derive_client_app_secret(MasterSecret, AppTranscript),
    ServerApp = quic_crypto:derive_server_app_secret(MasterSecret, AppTranscript),
    ?assertEqual(32, byte_size(ClientApp)),
    ?assertEqual(32, byte_size(ServerApp)),

    %% Step 8: Finished key and verify data
    ServerFinishedKey = quic_crypto:derive_finished_key(ServerHS),
    ServerFinished = quic_crypto:compute_finished_verify(ServerFinishedKey, HSTranscript),
    ?assertEqual(32, byte_size(ServerFinished)).
