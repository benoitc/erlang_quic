%%% -*- erlang -*-
%%%
%%% QUIC 0-RTT / Early Data Tests
%%% RFC 8446 Section 2.3 - 0-RTT Data
%%% RFC 9001 Section 4.6 - 0-RTT
%%%
%%% @doc Tests for 0-RTT early data sending and acceptance.

-module(quic_zerortt_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Step 4: 0-RTT Client-Side Tests
%%====================================================================

%% Test early secret derivation with PSK
early_secret_with_psk_test() ->
    PSK = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,

    %% Derive early secret from PSK
    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),

    %% Should be 32 bytes for SHA-256
    ?assertEqual(32, byte_size(EarlySecret)),

    %% Should be deterministic
    EarlySecret2 = quic_crypto:derive_early_secret(Cipher, PSK),
    ?assertEqual(EarlySecret, EarlySecret2),

    %% Different PSK should give different early secret
    PSK2 = crypto:strong_rand_bytes(32),
    EarlySecret3 = quic_crypto:derive_early_secret(Cipher, PSK2),
    ?assertNotEqual(EarlySecret, EarlySecret3).

%% Test client early traffic secret derivation
early_traffic_secret_test() ->
    PSK = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello data">>),

    %% Derive early secret
    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),

    %% Derive client early traffic secret
    EarlyTrafficSecret = quic_crypto:derive_client_early_traffic_secret(
        Cipher, EarlySecret, ClientHelloHash
    ),

    %% Should be 32 bytes for SHA-256
    ?assertEqual(32, byte_size(EarlyTrafficSecret)),

    %% Should be deterministic
    EarlyTrafficSecret2 = quic_crypto:derive_client_early_traffic_secret(
        Cipher, EarlySecret, ClientHelloHash
    ),
    ?assertEqual(EarlyTrafficSecret, EarlyTrafficSecret2).

%% Test 0-RTT packet type encoding
zero_rtt_packet_type_test() ->
    %% 0-RTT packet type is 0x01 in long header
    %% Long header form bit (1) | fixed bit (1) | packet type (2 bits) | reserved (2 bits) | pn len (2 bits)
    %% For 0-RTT: form=1, fixed=1, type=01, reserved=00, pn_len depends on packet
    ?assertEqual(?PACKET_TYPE_0RTT, 16#01).

%% Test early data key derivation
early_data_keys_test() ->
    PSK = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    %% Derive early secret
    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),

    %% Derive client early traffic secret
    EarlyTrafficSecret = quic_crypto:derive_client_early_traffic_secret(
        Cipher, EarlySecret, ClientHelloHash
    ),

    %% Derive traffic keys from early traffic secret
    %% Returns {Key, IV, HP} tuple
    {Key, IV, HP} = quic_keys:derive_keys(EarlyTrafficSecret, Cipher),

    %% Key should be 16 bytes for AES-128-GCM
    ?assertEqual(16, byte_size(Key)),
    %% IV should be 12 bytes
    ?assertEqual(12, byte_size(IV)),
    %% HP key should be 16 bytes
    ?assertEqual(16, byte_size(HP)).

%% Test early data encryption using AEAD
early_data_encryption_test() ->
    PSK = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    %% Derive keys
    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),
    EarlyTrafficSecret = quic_crypto:derive_client_early_traffic_secret(
        Cipher, EarlySecret, ClientHelloHash
    ),
    {Key, BaseIV, _HP} = quic_keys:derive_keys(EarlyTrafficSecret, Cipher),

    %% Encrypt some data
    Plaintext = <<"Hello, 0-RTT!">>,
    AAD = <<"additional data">>,
    PacketNumber = 0,

    %% XOR IV with packet number to get nonce
    IVLen = byte_size(BaseIV),
    PNPadded = <<0:(IVLen - 8)/unit:8, PacketNumber:64>>,
    Nonce = crypto:exor(BaseIV, PNPadded),

    %% Encrypt
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        aes_128_gcm, Key, Nonce, Plaintext, AAD, 16, true
    ),

    ?assert(is_binary(Ciphertext)),
    ?assertEqual(byte_size(Plaintext), byte_size(Ciphertext)),
    ?assertEqual(16, byte_size(Tag)),

    %% Decrypt should give back original
    Decrypted = crypto:crypto_one_time_aead(
        aes_128_gcm, Key, Nonce, Ciphertext, AAD, Tag, false
    ),
    ?assertEqual(Plaintext, Decrypted).

%%====================================================================
%% Step 5: 0-RTT Server-Side Tests
%%====================================================================

%% Test server can derive early keys from PSK in ClientHello
server_early_keys_from_psk_test() ->
    %% PSK and ClientHello for early secret derivation
    PSK = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    %% Server derives the same early keys as client
    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),
    EarlyTrafficSecret = quic_crypto:derive_client_early_traffic_secret(
        Cipher, EarlySecret, ClientHelloHash
    ),
    {Key, IV, _HP} = quic_keys:derive_keys(EarlyTrafficSecret, Cipher),

    %% Verify keys match expected format
    ?assertEqual(16, byte_size(Key)),
    ?assertEqual(12, byte_size(IV)).

%% Test early_data extension in EncryptedExtensions
early_data_indication_test() ->
    %% When server accepts early data, it includes early_data extension (type 42)
    %% in EncryptedExtensions with empty data

    % Type 42, length 0
    EarlyDataExt = <<?EXT_EARLY_DATA:16, 0:16>>,

    ?assertEqual(4, byte_size(EarlyDataExt)),
    <<?EXT_EARLY_DATA:16, 0:16>> = EarlyDataExt.

%% Test server rejecting early data (no early_data in EncryptedExtensions)
server_reject_early_data_test() ->
    %% Server can reject early data by omitting early_data extension
    %% Client must discard any 0-RTT data it sent
    %% This is just a verification that we understand the rejection mechanism
    EEWithoutEarlyData = quic_tls:build_encrypted_extensions(#{
        alpn => <<"h3">>,
        transport_params => #{}
    }),

    %% Should not contain early_data extension (type 42)
    {ok, {?TLS_ENCRYPTED_EXTENSIONS, Body}, _Rest} =
        quic_tls:decode_handshake_message(EEWithoutEarlyData),
    {ok, ExtMap} = parse_encrypted_extensions_body(Body),
    ?assertNot(maps:is_key(?EXT_EARLY_DATA, ExtMap)).

%% Test early exporter master secret derivation
early_exporter_master_secret_test() ->
    PSK = crypto:strong_rand_bytes(32),
    Cipher = aes_128_gcm,
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),
    EarlyExpMasterSecret = quic_crypto:derive_early_exporter_master_secret(
        EarlySecret, ClientHelloHash
    ),

    ?assertEqual(32, byte_size(EarlyExpMasterSecret)).

%%====================================================================
%% Additional 0-RTT Tests (merged from quic_zero_rtt_tests)
%%====================================================================

%% Test early secret derivation without PSK
early_secret_without_psk_test() ->
    %% Without PSK, early secret is derived from zeros
    EarlySecret = quic_crypto:derive_early_secret(),
    ?assertEqual(32, byte_size(EarlySecret)).

%% Test early secret determinism
early_secret_deterministic_test() ->
    PSK = crypto:strong_rand_bytes(32),
    ES1 = quic_crypto:derive_early_secret(PSK),
    ES2 = quic_crypto:derive_early_secret(PSK),
    ?assertEqual(ES1, ES2).

%% Test client early secret with AES-256-GCM cipher
client_early_secret_cipher_aware_test() ->
    PSK = crypto:strong_rand_bytes(48),
    EarlySecret = quic_crypto:derive_early_secret(aes_256_gcm, PSK),
    ClientHelloHash = crypto:strong_rand_bytes(48),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        aes_256_gcm, EarlySecret, ClientHelloHash
    ),
    ?assertEqual(48, byte_size(ClientEarlySecret)).

%% Test 0-RTT packet encrypt/decrypt roundtrip
zero_rtt_packet_encrypt_decrypt_test() ->
    %% Derive 0-RTT keys
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        EarlySecret, ClientHelloHash
    ),
    {Key, IV, _HP} = quic_keys:derive_keys(ClientEarlySecret, aes_128_gcm),

    %% Encrypt some data
    PN = 0,
    Plaintext = <<"Hello, 0-RTT world!">>,
    % Simplified for test
    AAD = <<>>,

    Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
    % Has tag
    ?assert(byte_size(Ciphertext) > byte_size(Plaintext)),

    %% Decrypt
    {ok, Decrypted} = quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext),
    ?assertEqual(Plaintext, Decrypted).

%% Test 0-RTT with multiple packets
zero_rtt_multiple_packets_test() ->
    PSK = crypto:strong_rand_bytes(32),
    EarlySecret = quic_crypto:derive_early_secret(PSK),
    ClientHelloHash = crypto:hash(sha256, <<"ClientHello">>),

    ClientEarlySecret = quic_crypto:derive_client_early_traffic_secret(
        EarlySecret, ClientHelloHash
    ),
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
        end,
        Packets
    ),

    %% All decrypted correctly
    lists:foreach(
        fun({_PN, Original, Decrypted}) ->
            ?assertEqual(Original, Decrypted)
        end,
        Results
    ).

%%====================================================================
%% Helper Functions
%%====================================================================

parse_encrypted_extensions_body(<<ExtLen:16, Extensions:ExtLen/binary, _/binary>>) ->
    parse_extensions(Extensions, #{}).

parse_extensions(<<>>, Acc) ->
    {ok, Acc};
parse_extensions(<<Type:16, Len:16, Data:Len/binary, Rest/binary>>, Acc) ->
    parse_extensions(Rest, maps:put(Type, Data, Acc));
parse_extensions(_, _) ->
    {error, invalid_extensions}.
