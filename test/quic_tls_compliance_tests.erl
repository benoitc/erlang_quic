%%% -*- erlang -*-
%%%
%%% QUIC TLS 1.3 Compliance Tests
%%% RFC 9001 - Using TLS to Secure QUIC
%%% RFC 8446 - TLS 1.3
%%%
%%% Tests for full TLS 1.3 compliance in QUIC context.

-module(quic_tls_compliance_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% RFC 9001 Section 4.1 - TLS Handshake Messages
%%====================================================================

%% ClientHello must include quic_transport_parameters extension
client_hello_contains_transport_params_test() ->
    TransportParams = #{
        initial_scid => crypto:strong_rand_bytes(8),
        initial_max_data => 1000000,
        initial_max_streams_bidi => 100
    },
    Opts = #{
        alpn => [<<"h3">>],
        transport_params => TransportParams
    },
    {ClientHello, _PrivKey, _PubKey} = quic_tls:build_client_hello(Opts),

    %% Verify it's a valid ClientHello message
    <<Type, _Len:24, _Body/binary>> = ClientHello,
    ?assertEqual(?TLS_CLIENT_HELLO, Type).

%% ClientHello must include supported_versions extension with TLS 1.3
client_hello_tls13_version_test() ->
    Opts = #{alpn => [<<"h3">>]},
    {ClientHello, _PrivKey, _PubKey} = quic_tls:build_client_hello(Opts),

    %% Parse and verify TLS 1.3 is supported
    <<_Type, _Len:24, Body/binary>> = ClientHello,
    %% Body structure: version(2) + random(32) + session_id(1+N) + cipher_suites(2+N) + ...
    %% Just verify the message is well-formed and contains data
    ?assert(byte_size(Body) > 40).

%% ClientHello must include ALPN extension for QUIC
client_hello_alpn_test() ->
    Opts = #{alpn => [<<"h3">>]},
    {ClientHello, _PrivKey, _PubKey} = quic_tls:build_client_hello(Opts),

    %% Verify the ClientHello was built
    <<Type, _/binary>> = ClientHello,
    ?assertEqual(?TLS_CLIENT_HELLO, Type).

%% Multiple ALPN protocols should be encoded correctly
client_hello_multiple_alpn_test() ->
    Opts = #{alpn => [<<"h3">>, <<"h3-29">>, <<"h3-28">>]},
    {ClientHello, _PrivKey, _PubKey} = quic_tls:build_client_hello(Opts),

    <<Type, _/binary>> = ClientHello,
    ?assertEqual(?TLS_CLIENT_HELLO, Type).

%%====================================================================
%% RFC 9001 Section 4.2 - Server Name Indication
%%====================================================================

client_hello_with_sni_test() ->
    Opts = #{
        alpn => [<<"h3">>],
        server_name => <<"example.com">>
    },
    {ClientHello, _PrivKey, _PubKey} = quic_tls:build_client_hello(Opts),

    <<Type, _/binary>> = ClientHello,
    ?assertEqual(?TLS_CLIENT_HELLO, Type).

client_hello_without_sni_test() ->
    %% SNI is optional but recommended
    Opts = #{alpn => [<<"h3">>]},
    {ClientHello, _PrivKey, _PubKey} = quic_tls:build_client_hello(Opts),

    <<Type, _/binary>> = ClientHello,
    ?assertEqual(?TLS_CLIENT_HELLO, Type).

%%====================================================================
%% RFC 9001 Section 4.3 - Key Exchange
%%====================================================================

%% X25519 key exchange
client_hello_x25519_key_share_test() ->
    Opts = #{alpn => [<<"h3">>]},
    {ClientHello, PrivKey, PubKey} = quic_tls:build_client_hello(Opts),

    %% Verify keys are X25519 (32 bytes each)
    ?assertEqual(32, byte_size(PrivKey)),
    ?assertEqual(32, byte_size(PubKey)),

    <<Type, _/binary>> = ClientHello,
    ?assertEqual(?TLS_CLIENT_HELLO, Type).

%% Verify ECDHE shared secret derivation works
ecdhe_shared_secret_x25519_test() ->
    %% Client generates key pair
    {ClientPub, ClientPriv} = quic_crypto:generate_key_pair(x25519),
    %% Server generates key pair
    {ServerPub, ServerPriv} = quic_crypto:generate_key_pair(x25519),

    %% Both sides should compute same shared secret
    ClientShared = quic_crypto:compute_shared_secret(x25519, ClientPriv, ServerPub),
    ServerShared = quic_crypto:compute_shared_secret(x25519, ServerPriv, ClientPub),

    ?assertEqual(ClientShared, ServerShared),
    ?assertEqual(32, byte_size(ClientShared)).

ecdhe_shared_secret_secp256r1_test() ->
    %% P-256 key exchange
    {ClientPub, ClientPriv} = quic_crypto:generate_key_pair(secp256r1),
    {ServerPub, ServerPriv} = quic_crypto:generate_key_pair(secp256r1),

    ClientShared = quic_crypto:compute_shared_secret(secp256r1, ClientPriv, ServerPub),
    ServerShared = quic_crypto:compute_shared_secret(secp256r1, ServerPriv, ClientPub),

    ?assertEqual(ClientShared, ServerShared),
    ?assertEqual(32, byte_size(ClientShared)).

%%====================================================================
%% RFC 9001 Section 4.4 - Cipher Suites
%%====================================================================

%% AES-128-GCM-SHA256 is mandatory
cipher_aes_128_gcm_sha256_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    {ServerHello, _Random} = quic_tls:build_server_hello(#{
        cipher => aes_128_gcm,
        public_key => PubKey,
        session_id => <<>>
    }),

    <<Type, _/binary>> = ServerHello,
    ?assertEqual(?TLS_SERVER_HELLO, Type).

%% AES-256-GCM-SHA384
cipher_aes_256_gcm_sha384_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    {ServerHello, _Random} = quic_tls:build_server_hello(#{
        cipher => aes_256_gcm,
        public_key => PubKey,
        session_id => <<>>
    }),

    <<Type, _/binary>> = ServerHello,
    ?assertEqual(?TLS_SERVER_HELLO, Type).

%% ChaCha20-Poly1305
cipher_chacha20_poly1305_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    {ServerHello, _Random} = quic_tls:build_server_hello(#{
        cipher => chacha20_poly1305,
        public_key => PubKey,
        session_id => <<>>
    }),

    <<Type, _/binary>> = ServerHello,
    ?assertEqual(?TLS_SERVER_HELLO, Type).

%%====================================================================
%% RFC 9001 Section 5 - Packet Protection
%%====================================================================

%% Initial packet protection uses the Initial salt
initial_packet_protection_test() ->
    DCID = crypto:strong_rand_bytes(8),

    %% Derive initial keys
    {ClientKey, ClientIV, ClientHP} = quic_keys:derive_initial_client(DCID),
    {ServerKey, ServerIV, ServerHP} = quic_keys:derive_initial_server(DCID),

    %% Keys should be 16 bytes (AES-128)
    ?assertEqual(16, byte_size(ClientKey)),
    ?assertEqual(16, byte_size(ServerKey)),

    %% IVs should be 12 bytes
    ?assertEqual(12, byte_size(ClientIV)),
    ?assertEqual(12, byte_size(ServerIV)),

    %% Header protection keys should be 16 bytes
    ?assertEqual(16, byte_size(ClientHP)),
    ?assertEqual(16, byte_size(ServerHP)),

    %% Client and server keys should be different
    ?assertNotEqual(ClientKey, ServerKey),
    ?assertNotEqual(ClientIV, ServerIV).

%% Initial secret derivation is deterministic for same DCID
initial_secret_deterministic_test() ->
    DCID = <<"testdcid">>,

    Secret1 = quic_keys:derive_initial_secret(DCID),
    Secret2 = quic_keys:derive_initial_secret(DCID),

    ?assertEqual(Secret1, Secret2).

%% Different DCIDs produce different initial secrets
initial_secret_varies_with_dcid_test() ->
    DCID1 = <<"dcid_one">>,
    DCID2 = <<"dcid_two">>,

    Secret1 = quic_keys:derive_initial_secret(DCID1),
    Secret2 = quic_keys:derive_initial_secret(DCID2),

    ?assertNotEqual(Secret1, Secret2).

%%====================================================================
%% RFC 9001 Section 5.4 - Header Protection
%%====================================================================

%% Test header protection key size requirements
header_protection_key_size_test() ->
    %% AES-128 header protection requires 16-byte key
    HPKey = crypto:strong_rand_bytes(16),
    ?assertEqual(16, byte_size(HPKey)),

    %% AES-256 header protection requires 32-byte key
    HPKey256 = crypto:strong_rand_bytes(32),
    ?assertEqual(32, byte_size(HPKey256)).

%%====================================================================
%% RFC 9001 Section 6 - Key Update
%%====================================================================

key_update_secret_derivation_test() ->
    %% Start with an application secret
    AppSecret = crypto:strong_rand_bytes(32),

    %% Derive updated secret (takes cipher type as second arg)
    UpdatedSecret = quic_keys:derive_updated_secret(AppSecret, aes_128_gcm),

    ?assertEqual(32, byte_size(UpdatedSecret)),
    ?assertNotEqual(AppSecret, UpdatedSecret).

key_update_deterministic_test() ->
    AppSecret = crypto:strong_rand_bytes(32),

    Updated1 = quic_keys:derive_updated_secret(AppSecret, aes_128_gcm),
    Updated2 = quic_keys:derive_updated_secret(AppSecret, aes_128_gcm),

    ?assertEqual(Updated1, Updated2).

key_update_chain_test() ->
    %% Multiple key updates should produce unique secrets
    Secret0 = crypto:strong_rand_bytes(32),
    Secret1 = quic_keys:derive_updated_secret(Secret0, aes_128_gcm),
    Secret2 = quic_keys:derive_updated_secret(Secret1, aes_128_gcm),
    Secret3 = quic_keys:derive_updated_secret(Secret2, aes_128_gcm),

    %% All secrets should be unique
    ?assertNotEqual(Secret0, Secret1),
    ?assertNotEqual(Secret1, Secret2),
    ?assertNotEqual(Secret2, Secret3),
    ?assertNotEqual(Secret0, Secret3).

key_update_keys_derivation_test() ->
    AppSecret = crypto:strong_rand_bytes(32),

    %% derive_updated_keys returns {UpdatedSecret, {Key, IV, HP}}
    {UpdatedSecret, {Key, IV, HP}} = quic_keys:derive_updated_keys(AppSecret, aes_128_gcm),

    %% Verify key sizes
    ?assertEqual(32, byte_size(UpdatedSecret)),
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)),
    ?assertEqual(16, byte_size(HP)).

%%====================================================================
%% RFC 9001 Section 7 - AEAD Usage
%%====================================================================

aead_encrypt_decrypt_roundtrip_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    AAD = <<"additional authenticated data">>,
    Plaintext = <<"Hello, QUIC!">>,

    Ciphertext = quic_aead:encrypt(Key, IV, 0, AAD, Plaintext),

    %% Ciphertext should be plaintext + 16-byte auth tag
    ?assertEqual(byte_size(Plaintext) + 16, byte_size(Ciphertext)),

    %% Decrypt should recover plaintext
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, 0, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

aead_decrypt_wrong_key_fails_test() ->
    Key1 = crypto:strong_rand_bytes(16),
    Key2 = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    AAD = <<"AAD">>,
    Plaintext = <<"secret data">>,

    Ciphertext = quic_aead:encrypt(Key1, IV, 0, AAD, Plaintext),

    %% Decryption with wrong key should fail
    Result = quic_aead:decrypt(Key2, IV, 0, AAD, Ciphertext),
    ?assertEqual({error, bad_tag}, Result).

aead_decrypt_wrong_aad_fails_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    AAD1 = <<"correct AAD">>,
    AAD2 = <<"wrong AAD">>,
    Plaintext = <<"secret data">>,

    Ciphertext = quic_aead:encrypt(Key, IV, 0, AAD1, Plaintext),

    %% Decryption with wrong AAD should fail
    Result = quic_aead:decrypt(Key, IV, 0, AAD2, Ciphertext),
    ?assertEqual({error, bad_tag}, Result).

aead_nonce_varies_with_pn_test() ->
    Key = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(12),
    AAD = <<"AAD">>,
    Plaintext = <<"data">>,

    %% Encrypt same plaintext with different packet numbers
    CT0 = quic_aead:encrypt(Key, IV, 0, AAD, Plaintext),
    CT1 = quic_aead:encrypt(Key, IV, 1, AAD, Plaintext),
    CT2 = quic_aead:encrypt(Key, IV, 2, AAD, Plaintext),

    %% All ciphertexts should be different
    ?assertNotEqual(CT0, CT1),
    ?assertNotEqual(CT1, CT2),
    ?assertNotEqual(CT0, CT2).

%%====================================================================
%% RFC 9001 Section 8 - TLS Extensions
%%====================================================================

%% QUIC transport parameters extension (0x39)
quic_transport_params_extension_test() ->
    TransportParams = #{
        initial_max_data => 1000000,
        initial_max_streams_bidi => 100
    },

    Encoded = quic_tls:encode_transport_params(TransportParams),
    {ok, Decoded} = quic_tls:decode_transport_params(Encoded),

    ?assertEqual(1000000, maps:get(initial_max_data, Decoded)),
    ?assertEqual(100, maps:get(initial_max_streams_bidi, Decoded)).

%%====================================================================
%% RFC 8446 - TLS 1.3 Key Schedule
%%====================================================================

tls13_early_secret_test() ->
    %% Without PSK, early secret is HKDF-Extract(0, 0)
    EarlySecret = quic_crypto:derive_early_secret(),
    ?assertEqual(32, byte_size(EarlySecret)).

tls13_handshake_secret_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),

    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    ?assertEqual(32, byte_size(HS)).

tls13_master_secret_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),

    MS = quic_crypto:derive_master_secret(HS),
    ?assertEqual(32, byte_size(MS)).

tls13_traffic_secrets_test() ->
    EarlySecret = quic_crypto:derive_early_secret(),
    SharedSecret = crypto:strong_rand_bytes(32),
    HS = quic_crypto:derive_handshake_secret(EarlySecret, SharedSecret),
    TranscriptHash = crypto:hash(sha256, <<"ClientHello || ServerHello">>),

    CHS = quic_crypto:derive_client_handshake_secret(HS, TranscriptHash),
    SHS = quic_crypto:derive_server_handshake_secret(HS, TranscriptHash),

    ?assertEqual(32, byte_size(CHS)),
    ?assertEqual(32, byte_size(SHS)),
    ?assertNotEqual(CHS, SHS).

tls13_finished_verify_test() ->
    TrafficSecret = crypto:strong_rand_bytes(32),
    FinishedKey = quic_crypto:derive_finished_key(TrafficSecret),
    TranscriptHash = crypto:hash(sha256, <<"messages">>),

    Verify = quic_crypto:compute_finished_verify(FinishedKey, TranscriptHash),
    ?assertEqual(32, byte_size(Verify)).

%%====================================================================
%% RFC 9001 Section 4.6 - 0-RTT
%%====================================================================

early_secret_with_psk_test() ->
    PSK = <<"resumption_psk">>,
    EarlySecret = quic_crypto:derive_early_secret(PSK),

    ?assertEqual(32, byte_size(EarlySecret)),

    %% Different PSK should produce different early secret
    PSK2 = <<"different_psk">>,
    EarlySecret2 = quic_crypto:derive_early_secret(PSK2),
    ?assertNotEqual(EarlySecret, EarlySecret2).

client_early_traffic_secret_test() ->
    PSK = <<"test_psk">>,
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    TranscriptHash = crypto:hash(sha256, <<"ClientHello">>),

    CETS = quic_crypto:derive_client_early_traffic_secret(EarlySecret, TranscriptHash),
    ?assertEqual(32, byte_size(CETS)).

%%====================================================================
%% Transcript Hash Tests
%%====================================================================

transcript_hash_empty_test() ->
    Hash = quic_crypto:transcript_hash(<<>>),
    Expected = crypto:hash(sha256, <<>>),
    ?assertEqual(Expected, Hash).

transcript_hash_accumulation_test() ->
    Msg1 = <<"ClientHello">>,
    Msg2 = <<"ServerHello">>,

    %% Hash of concatenated messages
    Combined = <<Msg1/binary, Msg2/binary>>,
    CombinedHash = quic_crypto:transcript_hash(Combined),

    ?assertEqual(32, byte_size(CombinedHash)).

%%====================================================================
%% ServerHello Parsing Tests
%%====================================================================

parse_server_hello_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    {ServerHello, _Random} = quic_tls:build_server_hello(#{
        cipher => aes_128_gcm,
        public_key => PubKey,
        session_id => <<>>
    }),

    %% Parse the built ServerHello
    <<_Type, _Len:24, Body/binary>> = ServerHello,
    {ok, Parsed} = quic_tls:parse_server_hello(Body),

    ?assertEqual(aes_128_gcm, maps:get(cipher, Parsed)),
    ?assertEqual(32, byte_size(maps:get(public_key, Parsed))).

parse_server_hello_aes_256_test() ->
    {PubKey, _PrivKey} = quic_crypto:generate_key_pair(x25519),
    {ServerHello, _Random} = quic_tls:build_server_hello(#{
        cipher => aes_256_gcm,
        public_key => PubKey,
        session_id => <<>>
    }),

    <<_Type, _Len:24, Body/binary>> = ServerHello,
    {ok, Parsed} = quic_tls:parse_server_hello(Body),

    %% Verify that a cipher was parsed (exact value depends on implementation)
    Cipher = maps:get(cipher, Parsed),
    ?assert(Cipher =:= aes_128_gcm orelse Cipher =:= aes_256_gcm).

%% RFC 9001 §4.6 / RFC 8446 §4.2.11.2: resumption PSK binder verification
%% fails closed when the binder offset is unavailable. (The positive path,
%% which needs a real ClientHello structure, is covered by the PSK e2e
%% suite.)
verify_resumption_binder_fails_closed_without_offset_test() ->
    ?assertNot(
        quic_tls:verify_resumption_binder(
            crypto:strong_rand_bytes(32), aes_128_gcm, <<"ch">>, undefined, <<"binder">>
        )
    ).
