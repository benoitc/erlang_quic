%%% -*- erlang -*-
%%%
%%% QUIC AEAD Packet Protection
%%% RFC 9001 Section 5 - Packet Protection
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc AEAD encryption/decryption for QUIC packet protection.
%%%
%%% QUIC uses AEAD algorithms (AES-GCM, ChaCha20-Poly1305) to protect
%%% packet payloads. Header protection is applied to hide the packet
%%% number and certain header flags.
%%%
%%% == Packet Protection ==
%%%
%%% The nonce for AEAD is computed by XORing the IV with the packet
%%% number (left-padded to 12 bytes).
%%%
%%% == Header Protection ==
%%%
%%% A sample from the encrypted payload is used to generate a mask
%%% that protects the first header byte and packet number bytes.
%%%

-module(quic_aead).

%% Suppress dialyzer warnings for cipher patterns not yet exercised
-dialyzer([no_match]).

-export([
    encrypt/5,
    encrypt/6,
    decrypt/5,
    decrypt/6,
    protect_header/4,
    unprotect_header/4,
    compute_nonce/2,
    compute_hp_mask/3
]).

-export_type([cipher/0]).

-type cipher() :: aes_128_gcm | aes_256_gcm | chacha20_poly1305.

%% Tag length for AEAD algorithms (16 bytes)
-define(TAG_LEN, 16).

%% Header protection sample offset from start of encrypted payload
-define(HP_SAMPLE_OFFSET, 4).
-define(HP_SAMPLE_LEN, 16).

%% Minimum payload size for header protection sample
-define(MIN_PAYLOAD_FOR_SAMPLE, ?HP_SAMPLE_OFFSET + ?HP_SAMPLE_LEN).

%%====================================================================
%% API
%%====================================================================

%% @doc Encrypt a QUIC packet payload using AEAD.
%%
%% Key: AEAD key
%% IV: AEAD initialization vector
%% PN: Packet number (used with IV to create nonce)
%% AAD: Additional authenticated data (unprotected header)
%% Plaintext: Payload to encrypt
%%
%% Returns: Ciphertext with authentication tag appended
-spec encrypt(binary(), binary(), non_neg_integer(), binary(), binary()) ->
    binary().
encrypt(Key, IV, PN, AAD, Plaintext) ->
    Cipher = cipher_for_key(Key),
    encrypt(Key, IV, PN, AAD, Plaintext, Cipher).

%% @doc Encrypt with explicit cipher type.
%% Useful for ChaCha20-Poly1305 which also uses 32-byte keys.
-spec encrypt(binary(), binary(), non_neg_integer(), binary(), binary(), cipher()) ->
    binary().
encrypt(Key, IV, PN, AAD, Plaintext, Cipher) ->
    Nonce = compute_nonce(IV, PN),
    {Ciphertext, Tag} = crypto:crypto_one_time_aead(
        Cipher, Key, Nonce, Plaintext, AAD, ?TAG_LEN, true),
    <<Ciphertext/binary, Tag/binary>>.

%% @doc Decrypt a QUIC packet payload using AEAD.
%%
%% Returns: {ok, Plaintext} | {error, bad_tag}
-spec decrypt(binary(), binary(), non_neg_integer(), binary(), binary()) ->
    {ok, binary()} | {error, bad_tag}.
decrypt(Key, IV, PN, AAD, CiphertextWithTag) ->
    Cipher = cipher_for_key(Key),
    decrypt(Key, IV, PN, AAD, CiphertextWithTag, Cipher).

%% @doc Decrypt with explicit cipher type.
%% Useful for ChaCha20-Poly1305 which also uses 32-byte keys.
-spec decrypt(binary(), binary(), non_neg_integer(), binary(), binary(), cipher()) ->
    {ok, binary()} | {error, bad_tag}.
decrypt(Key, IV, PN, AAD, CiphertextWithTag, Cipher) ->
    Nonce = compute_nonce(IV, PN),
    CipherLen = byte_size(CiphertextWithTag) - ?TAG_LEN,
    <<Ciphertext:CipherLen/binary, Tag:?TAG_LEN/binary>> = CiphertextWithTag,
    case crypto:crypto_one_time_aead(
            Cipher, Key, Nonce, Ciphertext, AAD, Tag, false) of
        Plaintext when is_binary(Plaintext) ->
            {ok, Plaintext};
        error ->
            {error, bad_tag}
    end.

%% @doc Apply header protection to a QUIC packet.
%%
%% HP: Header protection key
%% Header: The packet header (first byte + rest + PN)
%% EncryptedPayload: The AEAD-encrypted payload (ciphertext + tag)
%% PNOffset: Offset of packet number in the header
%%
%% The sample is taken starting 4 bytes after the start of the Packet Number.
%% Since PN is at the end of Header, and ciphertext comes after PN:
%% sample_offset = 4 - PNLen (where PNLen is encoded in the first byte)
%%
%% Returns: Protected header (first byte and PN bytes masked), or
%%          {error, payload_too_short} if payload is too small for sampling.
-spec protect_header(binary(), binary(), binary(), non_neg_integer()) ->
    binary() | {error, payload_too_short}.
protect_header(HP, Header, EncryptedPayload, PNOffset) ->
    Cipher = cipher_for_key(HP),
    <<FirstByte, _/binary>> = Header,
    PNLen = (FirstByte band 16#03) + 1,
    %% Sample starts (4 - PNLen) bytes into ciphertext
    %% This is because sample_offset = pn_offset + 4 in the full packet
    %% And ciphertext starts at pn_offset + PNLen
    SampleOffset = max(0, 4 - PNLen),
    RequiredLen = SampleOffset + ?HP_SAMPLE_LEN,
    case byte_size(EncryptedPayload) >= RequiredLen of
        true ->
            Sample = binary:part(EncryptedPayload, SampleOffset, ?HP_SAMPLE_LEN),
            Mask = compute_hp_mask(Cipher, HP, Sample),
            apply_header_mask(Header, Mask, PNOffset);
        false ->
            {error, payload_too_short}
    end.

%% @doc Remove header protection from a QUIC packet.
%%
%% HP: Header protection key
%% ProtectedHeader: The protected header bytes (up to but not including PN)
%% EncryptedPayload: PN bytes + ciphertext + tag
%% PNOffset: Offset of packet number in the full header (= byte_size(ProtectedHeader))
%%
%% The sample is taken at position 4 from the start of PN.
%% Since EncryptedPayload starts with PN, sample is at position 4.
%%
%% Returns: {UnprotectedHeader, PNLength} or {error, payload_too_short}
-spec unprotect_header(binary(), binary(), binary(), non_neg_integer()) ->
    {binary(), pos_integer()} | {error, payload_too_short}.
unprotect_header(HP, ProtectedHeader, EncryptedPayload, _PNOffset) ->
    case byte_size(EncryptedPayload) >= ?MIN_PAYLOAD_FOR_SAMPLE of
        false ->
            {error, payload_too_short};
        true ->
            Cipher = cipher_for_key(HP),
            %% Sample is at position 4 from start of PN
            %% PN is at position 0 of EncryptedPayload
            Sample = binary:part(EncryptedPayload, ?HP_SAMPLE_OFFSET, ?HP_SAMPLE_LEN),
            Mask = compute_hp_mask(Cipher, HP, Sample),

            <<ProtectedFirstByte, HeaderRest/binary>> = ProtectedHeader,
            <<MaskByte0, MaskByte1, MaskByte2, MaskByte3, MaskByte4, _/binary>> = Mask,

            %% Unmask first byte to get PN length
            IsLongHeader = (ProtectedFirstByte band 16#80) =:= 16#80,
            FirstByteMask = case IsLongHeader of
                true -> MaskByte0 band 16#0f;
                false -> MaskByte0 band 16#1f
            end,
            FirstByte = ProtectedFirstByte bxor FirstByteMask,

            %% Get PN length from unmasked first byte
            PNLen = (FirstByte band 16#03) + 1,

            %% PN is at the start of EncryptedPayload, unmask it
            <<ProtectedPN:PNLen/binary, _/binary>> = EncryptedPayload,
            PNMask = binary:part(<<MaskByte1, MaskByte2, MaskByte3, MaskByte4>>, 0, PNLen),
            PN = crypto:exor(ProtectedPN, PNMask),

            %% Return unprotected header (first byte + rest) with PN appended
            UnprotectedHeader = <<FirstByte, HeaderRest/binary, PN/binary>>,
            {UnprotectedHeader, PNLen}
    end.

%% @doc Compute the nonce for AEAD by XORing IV with packet number.
%% Packet number is left-padded to 12 bytes.
-spec compute_nonce(binary(), non_neg_integer()) -> binary().
compute_nonce(IV, PN) when byte_size(IV) =:= 12 ->
    %% Left-pad PN to 12 bytes and XOR with IV
    PNPadded = <<0:64, PN:32>>,
    crypto:exor(IV, PNPadded).

%%====================================================================
%% Internal Functions
%%====================================================================

%% Determine cipher type from key length
cipher_for_key(Key) when byte_size(Key) =:= 16 -> aes_128_gcm;
cipher_for_key(Key) when byte_size(Key) =:= 32 -> aes_256_gcm.
%% Note: ChaCha20-Poly1305 also uses 32-byte keys, but we'd need
%% additional context to distinguish it from AES-256-GCM.

%% Compute header protection mask
compute_hp_mask(aes_128_gcm, HP, Sample) ->
    %% AES-ECB encryption of sample
    crypto:crypto_one_time(aes_128_ecb, HP, Sample, true);
compute_hp_mask(aes_256_gcm, HP, Sample) ->
    %% AES-ECB encryption of sample (use first 16 bytes of 32-byte key)
    %% Actually, HP for AES-256 is 32 bytes, use aes_256_ecb
    crypto:crypto_one_time(aes_256_ecb, HP, Sample, true);
compute_hp_mask(chacha20_poly1305, HP, Sample) ->
    %% ChaCha20 with counter=0 and the sample as nonce
    %% Sample is 16 bytes: first 4 = counter, last 12 = nonce
    <<Counter:32/little, Nonce:12/binary>> = Sample,
    %% Generate 5 bytes of mask using ChaCha20
    Zeros = <<0,0,0,0,0>>,
    crypto:crypto_one_time(chacha20, HP, <<Counter:32/little, Nonce/binary>>, Zeros, true).

%% Apply mask to header (for protection)
apply_header_mask(Header, Mask, PNOffset) ->
    <<FirstByte, Rest/binary>> = Header,
    <<MaskByte0, MaskByte1, MaskByte2, MaskByte3, MaskByte4, _/binary>> = Mask,

    %% Determine PN length from first byte (bits 0-1 for short, bits 0-1 for long)
    %% The PN length is encoded in the two least significant bits + 1
    PNLen = (FirstByte band 16#03) + 1,

    %% Mask first byte: for long header, mask lower 4 bits; for short, mask lower 5 bits
    IsLongHeader = (FirstByte band 16#80) =:= 16#80,
    FirstByteMask = case IsLongHeader of
        true -> MaskByte0 band 16#0f;  % Long header: mask bits 0-3
        false -> MaskByte0 band 16#1f  % Short header: mask bits 0-4
    end,
    ProtectedFirstByte = FirstByte bxor FirstByteMask,

    %% Split header at PN offset
    BeforePNLen = PNOffset - 1,  % -1 because we already split off first byte
    <<BeforePN:BeforePNLen/binary, PN:PNLen/binary, AfterPN/binary>> = Rest,

    %% Mask PN bytes
    PNMask = binary:part(<<MaskByte1, MaskByte2, MaskByte3, MaskByte4>>, 0, PNLen),
    ProtectedPN = crypto:exor(PN, PNMask),

    <<ProtectedFirstByte, BeforePN/binary, ProtectedPN/binary, AfterPN/binary>>.
