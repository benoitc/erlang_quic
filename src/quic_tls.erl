%%% -*- erlang -*-
%%%
%%% QUIC TLS 1.3 Message Handling
%%% RFC 8446 - TLS 1.3
%%% RFC 9001 - Using TLS to Secure QUIC
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%
%%% @doc TLS 1.3 message generation and parsing for QUIC.
%%%
%%% This module handles TLS 1.3 handshake messages as they appear in
%%% QUIC CRYPTO frames. Messages are encoded without the TLS record layer.
%%%
%%% == TLS Messages in QUIC ==
%%%
%%% QUIC uses TLS 1.3 for the cryptographic handshake, but without the
%%% TLS record layer. TLS handshake messages are sent directly in
%%% CRYPTO frames.
%%%

-module(quic_tls).

-include("quic.hrl").

-export([
    %% ClientHello
    build_client_hello/1,

    %% Server message parsing (client-side)
    parse_server_hello/1,
    parse_encrypted_extensions/1,
    parse_certificate/1,
    parse_certificate_verify/1,
    parse_finished/1,

    %% Client Finished
    build_finished/1,
    verify_finished/3,
    verify_finished/4,

    %% Server-side message building
    parse_client_hello/1,
    build_server_hello/1,
    build_encrypted_extensions/1,
    build_certificate/2,
    build_certificate_verify/3,

    %% Transport parameters
    encode_transport_params/1,
    decode_transport_params/1,

    %% Preferred address (RFC 9000 Section 9.6)
    encode_preferred_address/1,
    decode_preferred_address/1,

    %% TLS message framing
    encode_handshake_message/2,
    decode_handshake_message/1
]).

%%====================================================================
%% ClientHello
%%====================================================================

%% @doc Build a TLS 1.3 ClientHello message for QUIC.
%% Options:
%%   - server_name: SNI hostname (binary)
%%   - alpn: List of ALPN protocols (list of binaries)
%%   - transport_params: QUIC transport parameters (map)
%%   - session_ticket: #session_ticket{} for resumption with PSK (optional)
%%
%% Returns: {ClientHelloMsg, PrivateKey, Random}
-spec build_client_hello(map()) -> {binary(), binary(), binary()}.
build_client_hello(Opts) ->
    %% Generate client random (32 bytes)
    Random = crypto:strong_rand_bytes(32),

    %% Generate ECDHE key pair (x25519)
    {PubKey, PrivKey} = crypto:generate_key(ecdh, x25519),

    %% Check if we have a session ticket for PSK resumption
    case maps:get(session_ticket, Opts, undefined) of
        undefined ->
            %% Standard ClientHello without PSK
            build_client_hello_standard(Random, PubKey, PrivKey, Opts);
        Ticket ->
            %% ClientHello with pre_shared_key extension for resumption
            build_client_hello_with_psk(Random, PubKey, PrivKey, Opts, Ticket)
    end.

%% Build standard ClientHello without PSK
build_client_hello_standard(Random, PubKey, PrivKey, Opts) ->
    %% Build extensions
    Extensions = build_client_hello_extensions(PubKey, Opts),

    %% Legacy session ID (empty for TLS 1.3)
    SessionId = <<>>,

    %% Cipher suites (TLS 1.3 only)
    CipherSuites = <<?TLS_AES_128_GCM_SHA256:16>>,

    %% Legacy compression methods (null only)
    CompressionMethods = <<1, 0>>,

    %% Build ClientHello body
    ClientHello = <<
        ?TLS_VERSION_1_2:16,          % legacy_version (always 0x0303)
        Random:32/binary,              % random
        (byte_size(SessionId)):8,      % legacy_session_id length
        SessionId/binary,              % legacy_session_id
        (byte_size(CipherSuites)):16,  % cipher_suites length
        CipherSuites/binary,           % cipher_suites
        CompressionMethods/binary,     % legacy_compression_methods
        (byte_size(Extensions)):16,    % extensions length
        Extensions/binary              % extensions
    >>,

    %% Wrap in handshake message
    Msg = encode_handshake_message(?TLS_CLIENT_HELLO, ClientHello),
    {Msg, PrivKey, Random}.

%% Build ClientHello with PSK for session resumption
%% RFC 8446 Section 4.2.11: pre_shared_key MUST be the last extension
%% The binder is computed over the truncated ClientHello (everything before binders)
build_client_hello_with_psk(Random, PubKey, PrivKey, Opts, Ticket) ->
    %% Build base extensions (without pre_shared_key)
    BaseExtensions = build_client_hello_extensions(PubKey, Opts),

    %% Derive PSK from resumption secret
    PSK = quic_ticket:derive_psk(Ticket#session_ticket.resumption_secret, Ticket),
    Cipher = Ticket#session_ticket.cipher,

    %% Compute obfuscated ticket age
    %% RFC 8446 4.2.11.1: obfuscated_ticket_age = (now - received_at) * 1000 + age_add
    Now = erlang:system_time(second),
    TicketAge = (Now - Ticket#session_ticket.received_at) * 1000,
    ObfuscatedAge = (TicketAge + Ticket#session_ticket.age_add) band 16#FFFFFFFF,

    %% Build pre_shared_key extension identities (without binder yet)
    TicketData = Ticket#session_ticket.ticket,
    TicketLen = byte_size(TicketData),

    %% PskIdentity: identity<1..2^16-1>, obfuscated_ticket_age
    PskIdentity = <<TicketLen:16, TicketData/binary, ObfuscatedAge:32>>,
    IdentitiesLen = byte_size(PskIdentity),
    Identities = <<IdentitiesLen:16, PskIdentity/binary>>,

    %% Binder placeholder (32 bytes for SHA-256, will be filled in)
    BinderLen = 32,
    BinderPlaceholder = <<0:BinderLen/unit:8>>,
    BindersSection = <<(BinderLen + 1):16, BinderLen:8, BinderPlaceholder/binary>>,

    %% Build pre_shared_key extension with placeholder binder
    PskExtBody = <<Identities/binary, BindersSection/binary>>,
    PskExtLen = byte_size(PskExtBody),
    PskExt = <<?EXT_PRE_SHARED_KEY:16, PskExtLen:16, PskExtBody/binary>>,

    %% Calculate total extensions length with PSK
    AllExtensions = <<BaseExtensions/binary, PskExt/binary>>,
    ExtensionsLen = byte_size(AllExtensions),

    %% Legacy session ID (empty for TLS 1.3)
    SessionId = <<>>,

    %% Cipher suites
    CipherSuites = <<?TLS_AES_128_GCM_SHA256:16>>,

    %% Legacy compression methods (null only)
    CompressionMethods = <<1, 0>>,

    %% Build full ClientHello with placeholder binder
    ClientHelloBody = <<
        ?TLS_VERSION_1_2:16,
        Random:32/binary,
        (byte_size(SessionId)):8,
        SessionId/binary,
        (byte_size(CipherSuites)):16,
        CipherSuites/binary,
        CompressionMethods/binary,
        ExtensionsLen:16,
        AllExtensions/binary
    >>,

    %% Build truncated ClientHello for binder computation
    %% Truncated = full ClientHello up to but not including the binders
    %% The binders section starts at: end - binders_len
    BindersSectionLen = byte_size(BindersSection),
    TruncatedLen = byte_size(ClientHelloBody) - BindersSectionLen,
    <<TruncatedBody:TruncatedLen/binary, _/binary>> = ClientHelloBody,

    %% Wrap truncated ClientHello for hash computation
    TruncatedMsg = encode_handshake_message(?TLS_CLIENT_HELLO, TruncatedBody),

    %% Compute PSK binder
    %% binder = HMAC(binder_key, Transcript-Hash(truncated ClientHello))
    EarlySecret = quic_crypto:derive_early_secret(Cipher, PSK),
    TruncatedHash = quic_crypto:transcript_hash(Cipher, TruncatedMsg),
    Binder = quic_crypto:compute_psk_binder(Cipher, EarlySecret, TruncatedHash, resumption),

    %% Build final binders section with real binder
    FinalBindersSection = <<(BinderLen + 1):16, BinderLen:8, Binder/binary>>,

    %% Build final ClientHello with real binder
    FinalClientHello = <<TruncatedBody/binary, FinalBindersSection/binary>>,

    %% Wrap in handshake message
    Msg = encode_handshake_message(?TLS_CLIENT_HELLO, FinalClientHello),
    {Msg, PrivKey, Random}.

%% Build ClientHello extensions
build_client_hello_extensions(PubKey, Opts) ->
    ServerName = maps:get(server_name, Opts, undefined),
    Alpn = maps:get(alpn, Opts, []),
    TransportParams = maps:get(transport_params, Opts, #{}),

    %% Supported versions (TLS 1.3 only)
    %% Length is in bytes (2 bytes per version), not version count
    SupportedVersions = encode_extension(?EXT_SUPPORTED_VERSIONS,
        <<2, ?TLS_VERSION_1_3:16>>),

    %% Supported groups (x25519)
    SupportedGroups = encode_extension(?EXT_SUPPORTED_GROUPS,
        <<2:16, ?GROUP_X25519:16>>),

    %% Signature algorithms
    SigAlgs = encode_extension(?EXT_SIGNATURE_ALGORITHMS,
        <<8:16,
          ?SIG_ECDSA_SECP256R1_SHA256:16,
          ?SIG_RSA_PSS_RSAE_SHA256:16,
          ?SIG_RSA_PKCS1_SHA256:16,
          ?SIG_ED25519:16>>),

    %% Key share (x25519 public key)
    KeyShareEntry = <<?GROUP_X25519:16, 32:16, PubKey:32/binary>>,
    KeyShare = encode_extension(?EXT_KEY_SHARE,
        <<(byte_size(KeyShareEntry)):16, KeyShareEntry/binary>>),

    %% Server Name Indication
    SNI = case ServerName of
        undefined -> <<>>;
        Name when is_binary(Name) ->
            NameLen = byte_size(Name),
            NameList = <<0, NameLen:16, Name/binary>>,
            encode_extension(?EXT_SERVER_NAME,
                <<(byte_size(NameList)):16, NameList/binary>>)
    end,

    %% ALPN
    AlpnExt = case Alpn of
        [] -> <<>>;
        Protocols ->
            ProtocolList = encode_alpn_list(Protocols),
            encode_extension(?EXT_ALPN,
                <<(byte_size(ProtocolList)):16, ProtocolList/binary>>)
    end,

    %% QUIC Transport Parameters
    TransportParamsData = encode_transport_params(TransportParams),
    TransportParamsExt = encode_extension(?EXT_QUIC_TRANSPORT_PARAMS,
        TransportParamsData),

    %% PSK Key Exchange Modes (psk_dhe_ke only)
    PskModes = encode_extension(?EXT_PSK_KEY_EXCHANGE_MODES,
        <<1, 1>>),  % psk_dhe_ke = 1

    iolist_to_binary([
        SupportedVersions,
        SupportedGroups,
        SigAlgs,
        KeyShare,
        SNI,
        AlpnExt,
        TransportParamsExt,
        PskModes
    ]).

encode_alpn_list(Protocols) ->
    iolist_to_binary([<<(byte_size(P)):8, P/binary>> || P <- Protocols]).

%%====================================================================
%% Server Message Parsing
%%====================================================================

%% @doc Parse a ServerHello message.
%% Returns server's public key and selected cipher suite.
-spec parse_server_hello(binary()) ->
    {ok, #{public_key := binary(), cipher := atom(), random := binary()}} |
    {error, term()}.
parse_server_hello(<<
    ?TLS_VERSION_1_2:16,    % legacy_version
    Random:32/binary,
    SessionIdLen:8,
    SessionId:SessionIdLen/binary,
    CipherSuite:16,
    0,                       % legacy_compression_method
    ExtensionsLen:16,
    Extensions:ExtensionsLen/binary,
    _Rest/binary
>>) ->
    %% Parse extensions to get key_share
    case parse_extensions(Extensions) of
        {ok, ExtMap} ->
            case maps:find(?EXT_KEY_SHARE, ExtMap) of
                {ok, KeyShareData} ->
                    case parse_server_key_share(KeyShareData) of
                        {ok, PubKey} ->
                            Cipher = cipher_from_suite(CipherSuite),
                            {ok, #{
                                public_key => PubKey,
                                cipher => Cipher,
                                random => Random,
                                session_id => SessionId,
                                extensions => ExtMap
                            }};
                        Error ->
                            Error
                    end;
                error ->
                    {error, missing_key_share}
            end;
        Error ->
            Error
    end;
parse_server_hello(_) ->
    {error, invalid_server_hello}.

%% @doc Parse EncryptedExtensions message.
-spec parse_encrypted_extensions(binary()) ->
    {ok, #{alpn => binary(), transport_params => map()}} |
    {error, term()}.
parse_encrypted_extensions(<<ExtensionsLen:16, Extensions:ExtensionsLen/binary, _Rest/binary>>) ->
    case parse_extensions(Extensions) of
        {ok, ExtMap} ->
            Alpn = case maps:find(?EXT_ALPN, ExtMap) of
                {ok, <<_ListLen:16, ProtoLen:8, Proto:ProtoLen/binary, _/binary>>} ->
                    Proto;
                _ ->
                    undefined
            end,
            TransportParams = case maps:find(?EXT_QUIC_TRANSPORT_PARAMS, ExtMap) of
                {ok, TPData} ->
                    case decode_transport_params(TPData) of
                        {ok, TP} -> TP;
                        _ -> #{}
                    end;
                _ ->
                    #{}
            end,
            {ok, #{alpn => Alpn, transport_params => TransportParams}};
        Error ->
            Error
    end;
parse_encrypted_extensions(_) ->
    {error, invalid_encrypted_extensions}.

%% @doc Parse Certificate message.
-spec parse_certificate(binary()) ->
    {ok, #{context := binary(), certificates := [binary()]}} |
    {error, term()}.
parse_certificate(<<ContextLen:8, Context:ContextLen/binary,
                    CertsLen:24, CertsData:CertsLen/binary, _Rest/binary>>) ->
    Certs = parse_certificate_list(CertsData),
    {ok, #{context => Context, certificates => Certs}};
parse_certificate(_) ->
    {error, invalid_certificate}.

parse_certificate_list(<<>>) ->
    [];
parse_certificate_list(<<CertLen:24, Cert:CertLen/binary,
                         ExtLen:16, _Ext:ExtLen/binary, Rest/binary>>) ->
    [Cert | parse_certificate_list(Rest)].

%% @doc Parse CertificateVerify message.
-spec parse_certificate_verify(binary()) ->
    {ok, #{algorithm := non_neg_integer(), signature := binary()}} |
    {error, term()}.
parse_certificate_verify(<<Algorithm:16, SigLen:16, Signature:SigLen/binary, _Rest/binary>>) ->
    {ok, #{algorithm => Algorithm, signature => Signature}};
parse_certificate_verify(_) ->
    {error, invalid_certificate_verify}.

%% @doc Parse Finished message.
-spec parse_finished(binary()) -> {ok, binary()} | {error, term()}.
parse_finished(VerifyData) when byte_size(VerifyData) >= 32 ->
    %% SHA-256 produces 32 bytes
    <<Data:32/binary, _/binary>> = VerifyData,
    {ok, Data};
parse_finished(_) ->
    {error, invalid_finished}.

%%====================================================================
%% Client Finished
%%====================================================================

%% @doc Build a Finished message.
%% VerifyData should be computed using quic_crypto:compute_finished_verify/2.
-spec build_finished(binary()) -> binary().
build_finished(VerifyData) ->
    encode_handshake_message(?TLS_FINISHED, VerifyData).

%% @doc Verify a Finished message (default SHA-256).
%% TrafficSecret is the sender's traffic secret.
%% TranscriptHash is the hash of all messages up to (but not including) Finished.
-spec verify_finished(binary(), binary(), binary()) -> boolean().
verify_finished(ReceivedVerifyData, TrafficSecret, TranscriptHash) ->
    FinishedKey = quic_crypto:derive_finished_key(TrafficSecret),
    ExpectedVerifyData = quic_crypto:compute_finished_verify(FinishedKey, TranscriptHash),
    crypto:hash_equals(ReceivedVerifyData, ExpectedVerifyData).

%% @doc Verify a Finished message with cipher-specific hash.
-spec verify_finished(binary(), binary(), binary(), atom()) -> boolean().
verify_finished(ReceivedVerifyData, TrafficSecret, TranscriptHash, Cipher) ->
    FinishedKey = quic_crypto:derive_finished_key(Cipher, TrafficSecret),
    ExpectedVerifyData = quic_crypto:compute_finished_verify(Cipher, FinishedKey, TranscriptHash),
    crypto:hash_equals(ReceivedVerifyData, ExpectedVerifyData).

%%====================================================================
%% Transport Parameters
%%====================================================================

%% @doc Encode QUIC transport parameters.
%% Params is a map with keys like:
%%   original_dcid, max_idle_timeout, max_udp_payload_size,
%%   initial_max_data, initial_max_stream_data_bidi_local, etc.
-spec encode_transport_params(map()) -> binary().
encode_transport_params(Params) ->
    Encoded = maps:fold(fun(Key, Value, Acc) ->
        case encode_transport_param(Key, Value) of
            <<>> -> Acc;
            Bin -> [Bin | Acc]
        end
    end, [], Params),
    iolist_to_binary(lists:reverse(Encoded)).

encode_transport_param(original_dcid, Value) ->
    encode_tp(?TP_ORIGINAL_DCID, Value);
encode_transport_param(max_idle_timeout, Value) ->
    encode_tp(?TP_MAX_IDLE_TIMEOUT, quic_varint:encode(Value));
encode_transport_param(max_udp_payload_size, Value) ->
    encode_tp(?TP_MAX_UDP_PAYLOAD_SIZE, quic_varint:encode(Value));
encode_transport_param(initial_max_data, Value) ->
    encode_tp(?TP_INITIAL_MAX_DATA, quic_varint:encode(Value));
encode_transport_param(initial_max_stream_data_bidi_local, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, quic_varint:encode(Value));
encode_transport_param(initial_max_stream_data_bidi_remote, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, quic_varint:encode(Value));
encode_transport_param(initial_max_stream_data_uni, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAM_DATA_UNI, quic_varint:encode(Value));
encode_transport_param(initial_max_streams_bidi, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAMS_BIDI, quic_varint:encode(Value));
encode_transport_param(initial_max_streams_uni, Value) ->
    encode_tp(?TP_INITIAL_MAX_STREAMS_UNI, quic_varint:encode(Value));
encode_transport_param(ack_delay_exponent, Value) ->
    encode_tp(?TP_ACK_DELAY_EXPONENT, quic_varint:encode(Value));
encode_transport_param(max_ack_delay, Value) ->
    encode_tp(?TP_MAX_ACK_DELAY, quic_varint:encode(Value));
encode_transport_param(disable_active_migration, true) ->
    encode_tp(?TP_DISABLE_ACTIVE_MIGRATION, <<>>);
encode_transport_param(active_connection_id_limit, Value) ->
    encode_tp(?TP_ACTIVE_CONNECTION_ID_LIMIT, quic_varint:encode(Value));
encode_transport_param(initial_scid, Value) ->
    encode_tp(?TP_INITIAL_SCID, Value);
encode_transport_param(preferred_address, #preferred_address{} = PA) ->
    encode_tp(?TP_PREFERRED_ADDRESS, encode_preferred_address(PA));
encode_transport_param(_, _) ->
    <<>>.

encode_tp(Id, Value) ->
    IdBin = quic_varint:encode(Id),
    LenBin = quic_varint:encode(byte_size(Value)),
    <<IdBin/binary, LenBin/binary, Value/binary>>.

%% @doc Decode QUIC transport parameters.
-spec decode_transport_params(binary()) -> {ok, map()} | {error, term()}.
decode_transport_params(Data) ->
    try
        decode_transport_params_loop(Data, #{})
    catch
        error:_ -> {error, invalid_transport_params}
    end.

decode_transport_params_loop(<<>>, Acc) ->
    {ok, Acc};
decode_transport_params_loop(Data, Acc) ->
    {Id, Rest1} = quic_varint:decode(Data),
    {Len, Rest2} = quic_varint:decode(Rest1),
    <<Value:Len/binary, Rest3/binary>> = Rest2,
    Key = tp_id_to_key(Id),
    DecodedValue = decode_tp_value(Id, Value),
    decode_transport_params_loop(Rest3, maps:put(Key, DecodedValue, Acc)).

tp_id_to_key(?TP_ORIGINAL_DCID) -> original_dcid;
tp_id_to_key(?TP_MAX_IDLE_TIMEOUT) -> max_idle_timeout;
tp_id_to_key(?TP_STATELESS_RESET_TOKEN) -> stateless_reset_token;
tp_id_to_key(?TP_MAX_UDP_PAYLOAD_SIZE) -> max_udp_payload_size;
tp_id_to_key(?TP_INITIAL_MAX_DATA) -> initial_max_data;
tp_id_to_key(?TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL) -> initial_max_stream_data_bidi_local;
tp_id_to_key(?TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE) -> initial_max_stream_data_bidi_remote;
tp_id_to_key(?TP_INITIAL_MAX_STREAM_DATA_UNI) -> initial_max_stream_data_uni;
tp_id_to_key(?TP_INITIAL_MAX_STREAMS_BIDI) -> initial_max_streams_bidi;
tp_id_to_key(?TP_INITIAL_MAX_STREAMS_UNI) -> initial_max_streams_uni;
tp_id_to_key(?TP_ACK_DELAY_EXPONENT) -> ack_delay_exponent;
tp_id_to_key(?TP_MAX_ACK_DELAY) -> max_ack_delay;
tp_id_to_key(?TP_DISABLE_ACTIVE_MIGRATION) -> disable_active_migration;
tp_id_to_key(?TP_PREFERRED_ADDRESS) -> preferred_address;
tp_id_to_key(?TP_ACTIVE_CONNECTION_ID_LIMIT) -> active_connection_id_limit;
tp_id_to_key(?TP_INITIAL_SCID) -> initial_scid;
tp_id_to_key(?TP_RETRY_SCID) -> retry_scid;
tp_id_to_key(Id) -> {unknown, Id}.

decode_tp_value(?TP_ORIGINAL_DCID, Value) -> Value;
decode_tp_value(?TP_STATELESS_RESET_TOKEN, Value) -> Value;
decode_tp_value(?TP_INITIAL_SCID, Value) -> Value;
decode_tp_value(?TP_RETRY_SCID, Value) -> Value;
decode_tp_value(?TP_DISABLE_ACTIVE_MIGRATION, <<>>) -> true;
decode_tp_value(?TP_PREFERRED_ADDRESS, Value) -> decode_preferred_address(Value);
decode_tp_value(_, Value) ->
    %% Most parameters are varints
    {Int, _} = quic_varint:decode(Value),
    Int.

%% @doc Decode preferred_address transport parameter (RFC 9000 Section 18.2).
%% Format:
%%   IPv4 address:     4 bytes
%%   IPv4 port:        2 bytes
%%   IPv6 address:    16 bytes
%%   IPv6 port:        2 bytes
%%   CID length:       1 byte
%%   Connection ID:    variable (0-20 bytes)
%%   Stateless reset: 16 bytes
-spec decode_preferred_address(binary()) -> #preferred_address{}.
decode_preferred_address(<<
    IPv4_A:8, IPv4_B:8, IPv4_C:8, IPv4_D:8,
    IPv4Port:16,
    IPv6_1:16, IPv6_2:16, IPv6_3:16, IPv6_4:16,
    IPv6_5:16, IPv6_6:16, IPv6_7:16, IPv6_8:16,
    IPv6Port:16,
    CIDLen:8, CID:CIDLen/binary,
    StatelessResetToken:16/binary,
    _Rest/binary
>>) ->
    %% Parse IPv4 - zero address means not present
    {IPv4Addr, IPv4PortVal} = case {IPv4_A, IPv4_B, IPv4_C, IPv4_D, IPv4Port} of
        {0, 0, 0, 0, 0} -> {undefined, undefined};
        _ -> {{IPv4_A, IPv4_B, IPv4_C, IPv4_D}, IPv4Port}
    end,
    %% Parse IPv6 - zero address means not present
    {IPv6Addr, IPv6PortVal} = case {IPv6_1, IPv6_2, IPv6_3, IPv6_4, IPv6_5, IPv6_6, IPv6_7, IPv6_8, IPv6Port} of
        {0, 0, 0, 0, 0, 0, 0, 0, 0} -> {undefined, undefined};
        _ -> {{IPv6_1, IPv6_2, IPv6_3, IPv6_4, IPv6_5, IPv6_6, IPv6_7, IPv6_8}, IPv6Port}
    end,
    #preferred_address{
        ipv4_addr = IPv4Addr,
        ipv4_port = IPv4PortVal,
        ipv6_addr = IPv6Addr,
        ipv6_port = IPv6PortVal,
        cid = CID,
        stateless_reset_token = StatelessResetToken
    }.

%% @doc Encode preferred_address transport parameter (RFC 9000 Section 18.2).
-spec encode_preferred_address(#preferred_address{}) -> binary().
encode_preferred_address(#preferred_address{
    ipv4_addr = IPv4Addr,
    ipv4_port = IPv4Port,
    ipv6_addr = IPv6Addr,
    ipv6_port = IPv6Port,
    cid = CID,
    stateless_reset_token = Token
}) ->
    %% Encode IPv4 (zeros if not present)
    IPv4Bin = case IPv4Addr of
        {A, B, C, D} -> <<A, B, C, D, IPv4Port:16>>;
        undefined -> <<0, 0, 0, 0, 0:16>>
    end,
    %% Encode IPv6 (zeros if not present)
    IPv6Bin = case IPv6Addr of
        {V1, V2, V3, V4, V5, V6, V7, V8} ->
            <<V1:16, V2:16, V3:16, V4:16, V5:16, V6:16, V7:16, V8:16, IPv6Port:16>>;
        undefined ->
            <<0:128, 0:16>>
    end,
    CIDLen = byte_size(CID),
    <<IPv4Bin/binary, IPv6Bin/binary, CIDLen:8, CID/binary, Token/binary>>.

%%====================================================================
%% TLS Message Framing
%%====================================================================

%% @doc Encode a TLS handshake message with type and length.
-spec encode_handshake_message(non_neg_integer(), binary()) -> binary().
encode_handshake_message(Type, Body) ->
    Length = byte_size(Body),
    <<Type:8, Length:24, Body/binary>>.

%% @doc Decode a TLS handshake message.
%% Returns {Type, Body, Rest} or {error, Reason}.
-spec decode_handshake_message(binary()) ->
    {ok, {non_neg_integer(), binary()}, binary()} |
    {error, term()}.
decode_handshake_message(<<Type:8, Length:24, Body:Length/binary, Rest/binary>>) ->
    {ok, {Type, Body}, Rest};
decode_handshake_message(<<_Type:8, Length:24, Data/binary>>) when byte_size(Data) < Length ->
    {error, incomplete};
decode_handshake_message(_) ->
    {error, invalid}.

%%====================================================================
%% Internal Functions
%%====================================================================

encode_extension(Type, Data) ->
    <<Type:16, (byte_size(Data)):16, Data/binary>>.

parse_extensions(Data) ->
    parse_extensions(Data, #{}).

parse_extensions(<<>>, Acc) ->
    {ok, Acc};
parse_extensions(<<Type:16, Len:16, Data:Len/binary, Rest/binary>>, Acc) ->
    parse_extensions(Rest, maps:put(Type, Data, Acc));
parse_extensions(<<Type:16, Len:16, Data/binary>>, _Acc) when byte_size(Data) < Len ->
    %% Extension data is truncated
    {error, {extension_truncated, Type, Len, byte_size(Data)}};
parse_extensions(Data, _Acc) when byte_size(Data) < 4 ->
    %% Not enough data for extension header (type + length)
    {error, {extension_header_incomplete, byte_size(Data)}};
parse_extensions(_, _) ->
    {error, invalid_extensions}.

parse_server_key_share(<<?GROUP_X25519:16, 32:16, PubKey:32/binary, _/binary>>) ->
    {ok, PubKey};
parse_server_key_share(<<?GROUP_SECP256R1:16, Len:16, PubKey:Len/binary, _/binary>>) ->
    {ok, PubKey};
parse_server_key_share(_) ->
    {error, unsupported_key_share}.

cipher_from_suite(?TLS_AES_128_GCM_SHA256) -> aes_128_gcm;
cipher_from_suite(?TLS_AES_256_GCM_SHA384) -> aes_256_gcm;
cipher_from_suite(?TLS_CHACHA20_POLY1305_SHA256) -> chacha20_poly1305;
cipher_from_suite(_) -> aes_128_gcm.

%%====================================================================
%% Server-side TLS Functions
%%====================================================================

%% @doc Parse a ClientHello message.
%% Returns a map with:
%%   - random: 32-byte client random
%%   - session_id: Legacy session ID
%%   - cipher_suites: List of cipher suites offered
%%   - extensions: Map of extensions
%%   - key_share: Client's public key for key exchange
%%   - server_name: SNI hostname (if present)
%%   - alpn_protocols: List of ALPN protocols (if present)
%%   - transport_params: QUIC transport parameters (if present)
-spec parse_client_hello(binary()) ->
    {ok, map()} | {error, term()}.
parse_client_hello(<<
    ?TLS_VERSION_1_2:16,  % Legacy version
    Random:32/binary,
    SessionIdLen:8, SessionId:SessionIdLen/binary,
    CipherSuitesLen:16, CipherSuites:CipherSuitesLen/binary,
    CompressionLen:8, _Compression:CompressionLen/binary,
    ExtLen:16, Extensions:ExtLen/binary,
    _Rest/binary
>>) ->
    %% Parse cipher suites
    Ciphers = parse_cipher_suites(CipherSuites),

    %% Parse extensions
    case parse_extensions(Extensions) of
        {ok, ExtMap} ->
            %% Extract key_share
            KeyShare = case maps:find(?EXT_KEY_SHARE, ExtMap) of
                {ok, KsData} -> parse_client_key_shares(KsData);
                error -> undefined
            end,

            %% Extract SNI
            ServerName = case maps:find(?EXT_SERVER_NAME, ExtMap) of
                {ok, SniData} -> parse_server_name_ext(SniData);
                error -> undefined
            end,

            %% Extract ALPN
            ALPNProtocols = case maps:find(?EXT_ALPN, ExtMap) of
                {ok, AlpnData} -> parse_alpn_ext(AlpnData);
                error -> []
            end,

            %% Extract QUIC transport parameters
            TransportParams = case maps:find(?EXT_QUIC_TRANSPORT_PARAMS, ExtMap) of
                {ok, TpData} ->
                    case decode_transport_params(TpData) of
                        {ok, TP} -> TP;
                        {error, _} -> #{}
                    end;
                error -> #{}
            end,

            %% Extract pre_shared_key extension (for resumption)
            PSK = case maps:find(?EXT_PRE_SHARED_KEY, ExtMap) of
                {ok, PskData} -> parse_pre_shared_key_ext(PskData);
                error -> undefined
            end,

            %% Extract early_data extension (client wants to send 0-RTT)
            EarlyData = maps:is_key(?EXT_EARLY_DATA, ExtMap),

            {ok, #{
                random => Random,
                session_id => SessionId,
                cipher_suites => Ciphers,
                extensions => ExtMap,
                key_share => KeyShare,
                server_name => ServerName,
                alpn_protocols => ALPNProtocols,
                transport_params => TransportParams,
                pre_shared_key => PSK,
                early_data => EarlyData
            }};
        {error, Reason} ->
            {error, Reason}
    end;
parse_client_hello(Data) when is_binary(Data) ->
    %% Provide detailed error for debugging ClientHello parsing failures
    case Data of
        <<Version:16, _/binary>> when Version =/= ?TLS_VERSION_1_2 ->
            {error, {invalid_legacy_version, Version}};
        <<_:16, _Random:32/binary, SessionIdLen:8, Rest1/binary>> when byte_size(Rest1) < SessionIdLen ->
            {error, {session_id_too_short, SessionIdLen, byte_size(Rest1)}};
        <<_:16, _:32/binary, SessionIdLen:8, _:SessionIdLen/binary,
          CipherSuitesLen:16, Rest2/binary>> when byte_size(Rest2) < CipherSuitesLen ->
            {error, {cipher_suites_too_short, CipherSuitesLen, byte_size(Rest2)}};
        _ when byte_size(Data) < 38 ->  % Minimum: 2 + 32 + 1 + 2 + 1 = 38 bytes
            {error, {client_hello_too_short, byte_size(Data)}};
        _ ->
            {error, {invalid_client_hello, byte_size(Data)}}
    end;
parse_client_hello(_) ->
    {error, invalid_client_hello_not_binary}.

%% @doc Build a ServerHello message.
%% Options:
%%   - random: Server random (32 bytes, generated if not provided)
%%   - session_id: Legacy session ID to echo
%%   - cipher_suite: Selected cipher suite
%%   - key_share: Server's public key
-spec build_server_hello(map()) -> {binary(), binary()}.
build_server_hello(Opts) ->
    %% Generate server random
    Random = maps:get(random, Opts, crypto:strong_rand_bytes(32)),

    %% Echo session ID from client
    SessionId = maps:get(session_id, Opts, <<>>),
    SessionIdLen = byte_size(SessionId),

    %% Selected cipher suite
    CipherSuite = maps:get(cipher_suite, Opts, ?TLS_AES_128_GCM_SHA256),

    %% Generate ECDHE key pair if not provided
    {PubKey, PrivKey} = case maps:find(key_pair, Opts) of
        {ok, {Pub, Priv}} -> {Pub, Priv};
        error -> crypto:generate_key(ecdh, x25519)
    end,

    %% Build extensions
    Extensions = build_server_hello_extensions(PubKey, Opts),
    ExtLen = byte_size(Extensions),

    %% Build ServerHello
    ServerHello = <<
        ?TLS_VERSION_1_2:16,  % Legacy version (TLS 1.2)
        Random:32/binary,
        SessionIdLen:8, SessionId/binary,
        CipherSuite:16,
        0:8,  % Legacy compression method (null)
        ExtLen:16, Extensions/binary
    >>,

    %% Wrap with handshake header
    Message = encode_handshake_message(?TLS_SERVER_HELLO, ServerHello),
    {Message, PrivKey}.

%% @doc Build EncryptedExtensions message.
%% Options:
%%   - alpn: Selected ALPN protocol
%%   - transport_params: QUIC transport parameters
-spec build_encrypted_extensions(map()) -> binary().
build_encrypted_extensions(Opts) ->
    Extensions = build_encrypted_extensions_list(Opts),
    ExtLen = byte_size(Extensions),
    Body = <<ExtLen:16, Extensions/binary>>,
    encode_handshake_message(?TLS_ENCRYPTED_EXTENSIONS, Body).

%% @doc Build Certificate message.
%% Certs is a list of DER-encoded certificates (server cert first).
-spec build_certificate(binary(), [binary()]) -> binary().
build_certificate(Context, Certs) ->
    CertList = build_cert_list(Certs),
    CertListLen = byte_size(CertList),
    ContextLen = byte_size(Context),
    Body = <<ContextLen:8, Context/binary, CertListLen:24, CertList/binary>>,
    encode_handshake_message(?TLS_CERTIFICATE, Body).

%% @doc Build CertificateVerify message.
%% PrivateKey is the server's private key.
%% TranscriptHash is the hash of all handshake messages up to (not including) CertificateVerify.
-spec build_certificate_verify(non_neg_integer(), crypto:key_id(), binary()) -> binary().
build_certificate_verify(SignatureAlgorithm, PrivateKey, TranscriptHash) ->
    %% Build the content to sign
    %% RFC 8446 Section 4.4.3:
    %% Content = 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + TranscriptHash
    Spaces = binary:copy(<<32>>, 64),
    ContextString = <<"TLS 1.3, server CertificateVerify">>,
    Content = <<Spaces/binary, ContextString/binary, 0, TranscriptHash/binary>>,

    %% Sign with the appropriate algorithm
    {SigAlg, HashAlg, SignOpts} = get_signature_params(SignatureAlgorithm),
    CryptoKey = convert_private_key(SigAlg, PrivateKey),
    Signature = crypto:sign(SigAlg, HashAlg, Content, CryptoKey, SignOpts),

    SigLen = byte_size(Signature),
    Body = <<SignatureAlgorithm:16, SigLen:16, Signature/binary>>,
    encode_handshake_message(?TLS_CERTIFICATE_VERIFY, Body).

%%====================================================================
%% Server-side Internal Functions
%%====================================================================

parse_cipher_suites(<<>>) ->
    [];
parse_cipher_suites(<<Suite:16, Rest/binary>>) ->
    [Suite | parse_cipher_suites(Rest)].

parse_client_key_shares(<<Len:16, Data:Len/binary, _/binary>>) ->
    parse_key_share_entries(Data);
parse_client_key_shares(_) ->
    undefined.

parse_key_share_entries(<<>>) ->
    [];
parse_key_share_entries(<<Group:16, Len:16, KeyData:Len/binary, Rest/binary>>) ->
    [{Group, KeyData} | parse_key_share_entries(Rest)];
parse_key_share_entries(_) ->
    [].

parse_server_name_ext(<<Len:16, Data:Len/binary, _/binary>>) ->
    parse_server_name_list(Data);
parse_server_name_ext(_) ->
    undefined.

parse_server_name_list(<<0:8, NameLen:16, Name:NameLen/binary, _/binary>>) ->
    Name;  % Type 0 = hostname
parse_server_name_list(_) ->
    undefined.

parse_alpn_ext(<<Len:16, Data:Len/binary, _/binary>>) ->
    parse_alpn_list(Data);
parse_alpn_ext(_) ->
    [].

parse_alpn_list(<<>>) ->
    [];
parse_alpn_list(<<Len:8, Proto:Len/binary, Rest/binary>>) ->
    [Proto | parse_alpn_list(Rest)];
parse_alpn_list(_) ->
    [].

%% Parse pre_shared_key extension from ClientHello
%% RFC 8446 Section 4.2.11
%% Returns: #{identities => [{Ticket, ObfuscatedAge}], binders => [Binder]}
parse_pre_shared_key_ext(<<IdentitiesLen:16, IdentitiesData:IdentitiesLen/binary,
                          BindersLen:16, BindersData:BindersLen/binary>>) ->
    Identities = parse_psk_identities(IdentitiesData),
    Binders = parse_psk_binders(BindersData),
    #{identities => Identities, binders => Binders};
parse_pre_shared_key_ext(_) ->
    undefined.

parse_psk_identities(<<>>) ->
    [];
parse_psk_identities(<<IdentityLen:16, Identity:IdentityLen/binary,
                       ObfuscatedAge:32, Rest/binary>>) ->
    [{Identity, ObfuscatedAge} | parse_psk_identities(Rest)];
parse_psk_identities(_) ->
    [].

parse_psk_binders(<<>>) ->
    [];
parse_psk_binders(<<BinderLen:8, Binder:BinderLen/binary, Rest/binary>>) ->
    [Binder | parse_psk_binders(Rest)];
parse_psk_binders(_) ->
    [].

build_server_hello_extensions(PubKey, _Opts) ->
    %% Supported versions extension (mandatory for TLS 1.3)
    SupportedVersions = encode_extension(?EXT_SUPPORTED_VERSIONS, <<?TLS_VERSION_1_3:16>>),

    %% Key share extension
    KeyShare = encode_extension(?EXT_KEY_SHARE,
        <<?GROUP_X25519:16, 32:16, PubKey:32/binary>>),

    <<SupportedVersions/binary, KeyShare/binary>>.

build_encrypted_extensions_list(Opts) ->
    %% ALPN extension (if ALPN was negotiated)
    ALPNExt = case maps:find(alpn, Opts) of
        {ok, ALPN} when is_binary(ALPN), byte_size(ALPN) > 0 ->
            ALPNLen = byte_size(ALPN),
            encode_extension(?EXT_ALPN, <<(ALPNLen + 1):16, ALPNLen:8, ALPN/binary>>);
        _ ->
            <<>>
    end,

    %% QUIC transport parameters
    TPExt = case maps:find(transport_params, Opts) of
        {ok, TP} when map_size(TP) > 0 ->
            TPData = encode_transport_params(TP),
            encode_extension(?EXT_QUIC_TRANSPORT_PARAMS, TPData);
        _ ->
            <<>>
    end,

    %% Early data indication (RFC 8446 Section 4.2.10)
    %% When server accepts early data, include empty early_data extension
    EarlyDataExt = case maps:get(early_data, Opts, false) of
        true ->
            encode_extension(?EXT_EARLY_DATA, <<>>);
        false ->
            <<>>
    end,

    <<ALPNExt/binary, TPExt/binary, EarlyDataExt/binary>>.

build_cert_list([]) ->
    <<>>;
build_cert_list([Cert | Rest]) ->
    CertLen = byte_size(Cert),
    RestCerts = build_cert_list(Rest),
    %% Each cert entry: cert_data<1..2^24-1> extensions<0..2^16-1>
    <<CertLen:24, Cert/binary, 0:16, RestCerts/binary>>.

get_signature_params(?SIG_RSA_PSS_RSAE_SHA256) ->
    {rsa, sha256, [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}]};
get_signature_params(?SIG_RSA_PSS_RSAE_SHA384) ->
    {rsa, sha384, [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}]};
get_signature_params(?SIG_RSA_PSS_RSAE_SHA512) ->
    {rsa, sha512, [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}]};
get_signature_params(?SIG_ECDSA_SECP256R1_SHA256) ->
    {ecdsa, sha256, []};
get_signature_params(?SIG_ECDSA_SECP384R1_SHA384) ->
    {ecdsa, sha384, []};
get_signature_params(_) ->
    {rsa, sha256, [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}]}.

%% Convert private key to format expected by crypto:sign
convert_private_key(ecdsa, {'ECPrivateKey', _, PrivKeyBin, {namedCurve, {1,2,840,10045,3,1,7}}, _, _}) ->
    %% secp256r1 / P-256
    [PrivKeyBin, secp256r1];
convert_private_key(ecdsa, {'ECPrivateKey', _, PrivKeyBin, {namedCurve, {1,3,132,0,34}}, _, _}) ->
    %% secp384r1 / P-384
    [PrivKeyBin, secp384r1];
convert_private_key(ecdsa, {'ECPrivateKey', _, PrivKeyBin, _, _, _}) ->
    %% Default EC curve
    [PrivKeyBin, secp256r1];
convert_private_key(rsa, {'RSAPrivateKey', _, N, E, D, _P, _Q, _Dp, _Dq, _Qi, _}) ->
    %% crypto:sign expects [E, N, D] list format for RSA
    [E, N, D];
convert_private_key(rsa, Key) when is_list(Key) ->
    %% Already in list format
    Key;
convert_private_key(_, Key) ->
    Key.
