%%% -*- erlang -*-
%%%
%%% PropEr tests for QUIC Crypto (AEAD, HKDF, Keys)
%%%

-module(prop_quic_crypto).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Generators
%%====================================================================

%% AES-128 key (16 bytes)
aes128_key() ->
    binary(16).

%% AES-256 key (32 bytes)
aes256_key() ->
    binary(32).

%% IV (12 bytes)
iv() ->
    binary(12).

%% Packet number
packet_number() ->
    range(0, 16#FFFFFFFF).

%% AAD (additional authenticated data)
aad() ->
    ?LET(Len, range(0, 100), binary(Len)).

%% Plaintext
plaintext() ->
    ?LET(Len, range(0, 1000), binary(Len)).

%% DCID for key derivation
dcid() ->
    ?LET(Len, range(1, 20), binary(Len)).

%% Secret (32 bytes for SHA-256)
secret() ->
    binary(32).

%% Salt
salt() ->
    ?LET(Len, range(1, 32), binary(Len)).

%% Label
label() ->
    ?LET(
        Len,
        range(1, 20),
        ?LET(
            Bytes,
            vector(Len, range($a, $z)),
            list_to_binary(Bytes)
        )
    ).

%%====================================================================
%% AEAD Properties
%%====================================================================

%% AES-128-GCM encrypt/decrypt roundtrip
prop_aes128_roundtrip() ->
    ?FORALL(
        {Key, IV, PN, AAD, Plaintext},
        {aes128_key(), iv(), packet_number(), aad(), plaintext()},
        begin
            Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
            case quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext) of
                {ok, Decrypted} -> Plaintext =:= Decrypted;
                _ -> false
            end
        end
    ).

%% AES-256-GCM encrypt/decrypt roundtrip
prop_aes256_roundtrip() ->
    ?FORALL(
        {Key, IV, PN, AAD, Plaintext},
        {aes256_key(), iv(), packet_number(), aad(), plaintext()},
        begin
            Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
            case quic_aead:decrypt(Key, IV, PN, AAD, Ciphertext) of
                {ok, Decrypted} -> Plaintext =:= Decrypted;
                _ -> false
            end
        end
    ).

%% Ciphertext is longer than plaintext (by tag length)
prop_ciphertext_has_tag() ->
    ?FORALL(
        {Key, IV, PN, AAD, Plaintext},
        {aes128_key(), iv(), packet_number(), aad(), plaintext()},
        begin
            Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD, Plaintext),
            byte_size(Ciphertext) =:= byte_size(Plaintext) + 16
        end
    ).

%% Wrong key fails decryption
prop_wrong_key_fails() ->
    ?FORALL(
        {Key1, Key2, IV, PN, AAD, Plaintext},
        {aes128_key(), aes128_key(), iv(), packet_number(), aad(), plaintext()},
        ?IMPLIES(
            Key1 =/= Key2,
            begin
                Ciphertext = quic_aead:encrypt(Key1, IV, PN, AAD, Plaintext),
                quic_aead:decrypt(Key2, IV, PN, AAD, Ciphertext) =:= {error, bad_tag}
            end
        )
    ).

%% Wrong AAD fails decryption
prop_wrong_aad_fails() ->
    ?FORALL(
        {Key, IV, PN, AAD1, AAD2, Plaintext},
        {aes128_key(), iv(), packet_number(), aad(), aad(), plaintext()},
        ?IMPLIES(
            AAD1 =/= AAD2,
            begin
                Ciphertext = quic_aead:encrypt(Key, IV, PN, AAD1, Plaintext),
                quic_aead:decrypt(Key, IV, PN, AAD2, Ciphertext) =:= {error, bad_tag}
            end
        )
    ).

%% Wrong packet number fails decryption
prop_wrong_pn_fails() ->
    ?FORALL(
        {Key, IV, PN1, PN2, AAD, Plaintext},
        {aes128_key(), iv(), packet_number(), packet_number(), aad(), plaintext()},
        ?IMPLIES(
            PN1 =/= PN2,
            begin
                Ciphertext = quic_aead:encrypt(Key, IV, PN1, AAD, Plaintext),
                quic_aead:decrypt(Key, IV, PN2, AAD, Ciphertext) =:= {error, bad_tag}
            end
        )
    ).

%% Nonce computation is deterministic
prop_nonce_deterministic() ->
    ?FORALL(
        {IV, PN},
        {iv(), packet_number()},
        quic_aead:compute_nonce(IV, PN) =:= quic_aead:compute_nonce(IV, PN)
    ).

%% Nonce is 12 bytes
prop_nonce_length() ->
    ?FORALL(
        {IV, PN},
        {iv(), packet_number()},
        byte_size(quic_aead:compute_nonce(IV, PN)) =:= 12
    ).

%%====================================================================
%% HKDF Properties
%%====================================================================

%% HKDF extract produces 32-byte output for SHA-256
prop_hkdf_extract_length() ->
    ?FORALL(
        {Salt, IKM},
        {salt(), secret()},
        byte_size(quic_hkdf:extract(Salt, IKM)) =:= 32
    ).

%% HKDF expand produces requested length
prop_hkdf_expand_length() ->
    ?FORALL(
        {PRK, Info, Len},
        {secret(), aad(), range(1, 255)},
        byte_size(quic_hkdf:expand(PRK, Info, Len)) =:= Len
    ).

%% HKDF is deterministic
prop_hkdf_deterministic() ->
    ?FORALL(
        {Salt, IKM},
        {salt(), secret()},
        quic_hkdf:extract(Salt, IKM) =:= quic_hkdf:extract(Salt, IKM)
    ).

%% HKDF expand-label produces requested length
prop_expand_label_length() ->
    ?FORALL(
        {Secret, Label, Context, Len},
        {secret(), label(), aad(), range(1, 64)},
        byte_size(quic_hkdf:expand_label(Secret, Label, Context, Len)) =:= Len
    ).

%%====================================================================
%% Key Derivation Properties
%%====================================================================

%% Initial keys are deterministic for same DCID
prop_initial_keys_deterministic() ->
    ?FORALL(
        DCID,
        dcid(),
        begin
            Keys1 = quic_keys:derive_initial_client(DCID),
            Keys2 = quic_keys:derive_initial_client(DCID),
            Keys1 =:= Keys2
        end
    ).

%% Client and server initial keys are different
prop_client_server_keys_different() ->
    ?FORALL(
        DCID,
        dcid(),
        begin
            ClientKeys = quic_keys:derive_initial_client(DCID),
            ServerKeys = quic_keys:derive_initial_server(DCID),
            ClientKeys =/= ServerKeys
        end
    ).

%% Different DCIDs produce different keys
prop_different_dcid_different_keys() ->
    ?FORALL(
        {DCID1, DCID2},
        {dcid(), dcid()},
        ?IMPLIES(
            DCID1 =/= DCID2,
            begin
                Keys1 = quic_keys:derive_initial_client(DCID1),
                Keys2 = quic_keys:derive_initial_client(DCID2),
                Keys1 =/= Keys2
            end
        )
    ).

%% Initial keys have correct sizes
prop_initial_key_sizes() ->
    ?FORALL(
        DCID,
        dcid(),
        begin
            {Key, IV, HP} = quic_keys:derive_initial_client(DCID),
            byte_size(Key) =:= 16 andalso
                byte_size(IV) =:= 12 andalso
                byte_size(HP) =:= 16
        end
    ).

%%====================================================================
%% TLS Key Schedule Properties
%%====================================================================

%% Early secret is deterministic
prop_early_secret_deterministic() ->
    ?FORALL(
        PSK,
        secret(),
        quic_crypto:derive_early_secret(PSK) =:= quic_crypto:derive_early_secret(PSK)
    ).

%% Master secret derivation chain works
prop_key_schedule_chain() ->
    ?FORALL(
        SharedSecret,
        secret(),
        begin
            Early = quic_crypto:derive_early_secret(),
            Handshake = quic_crypto:derive_handshake_secret(Early, SharedSecret),
            Master = quic_crypto:derive_master_secret(Handshake),
            byte_size(Early) =:= 32 andalso
                byte_size(Handshake) =:= 32 andalso
                byte_size(Master) =:= 32
        end
    ).

%% ECDHE shared secret is symmetric
prop_ecdhe_symmetric() ->
    ?FORALL(
        _,
        exactly(true),
        begin
            {PubA, PrivA} = quic_crypto:generate_key_pair(x25519),
            {PubB, PrivB} = quic_crypto:generate_key_pair(x25519),
            SharedA = quic_crypto:compute_shared_secret(x25519, PrivA, PubB),
            SharedB = quic_crypto:compute_shared_secret(x25519, PrivB, PubA),
            SharedA =:= SharedB
        end
    ).

%%====================================================================
%% EUnit wrapper
%%====================================================================

proper_test_() ->
    {timeout, 180, [
        %% AEAD tests
        ?_assert(proper:quickcheck(prop_aes128_roundtrip(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_aes256_roundtrip(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_ciphertext_has_tag(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_wrong_key_fails(), [{numtests, 100}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_wrong_aad_fails(), [{numtests, 100}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_wrong_pn_fails(), [{numtests, 100}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_nonce_deterministic(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_nonce_length(), [{numtests, 200}, {to_file, user}])),
        %% HKDF tests
        ?_assert(proper:quickcheck(prop_hkdf_extract_length(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_hkdf_expand_length(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_hkdf_deterministic(), [{numtests, 200}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_expand_label_length(), [{numtests, 200}, {to_file, user}])),
        %% Key derivation tests
        ?_assert(
            proper:quickcheck(prop_initial_keys_deterministic(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(
            proper:quickcheck(prop_client_server_keys_different(), [
                {numtests, 100}, {to_file, user}
            ])
        ),
        ?_assert(
            proper:quickcheck(prop_different_dcid_different_keys(), [
                {numtests, 100}, {to_file, user}
            ])
        ),
        ?_assert(proper:quickcheck(prop_initial_key_sizes(), [{numtests, 100}, {to_file, user}])),
        %% TLS key schedule tests
        ?_assert(
            proper:quickcheck(prop_early_secret_deterministic(), [{numtests, 100}, {to_file, user}])
        ),
        ?_assert(proper:quickcheck(prop_key_schedule_chain(), [{numtests, 100}, {to_file, user}])),
        ?_assert(proper:quickcheck(prop_ecdhe_symmetric(), [{numtests, 50}, {to_file, user}]))
    ]}.
