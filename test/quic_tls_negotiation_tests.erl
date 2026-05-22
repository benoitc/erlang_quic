%%% -*- erlang -*-
%%%
%%% Unit tests for TLS 1.3 group + signature negotiation:
%%% multi-group ClientHello, HelloRetryRequest wire format, the
%%% synthetic message_hash transcript prefix, and the new
%%% CertificateVerify signature schemes.

-module(quic_tls_negotiation_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Multi-group ClientHello
%%====================================================================

multi_group_client_hello_test() ->
    Opts = #{
        alpn => [<<"h3">>],
        transport_params => #{initial_scid => crypto:strong_rand_bytes(8)},
        groups => [x25519, secp256r1, secp384r1]
    },
    {CH, _Priv, _Random} = quic_tls:build_client_hello(Opts),
    <<?TLS_CLIENT_HELLO, _Len:24, Body/binary>> = CH,
    {ok, Map} = quic_tls:parse_client_hello(Body),
    %% supported_groups echoes all three, in order
    ?assertEqual([x25519, secp256r1, secp384r1], maps:get(supported_groups, Map)),
    %% key_share carries exactly one entry, for the head group (x25519)
    [{Code, PubKey}] = maps:get(key_share, Map),
    ?assertEqual(?GROUP_X25519, Code),
    ?assertEqual(32, byte_size(PubKey)).

default_client_hello_single_group_test() ->
    %% No `groups' opt → wire-identical single x25519 key_share.
    Opts = #{alpn => [<<"h3">>], transport_params => #{}},
    {CH, _Priv, _Random} = quic_tls:build_client_hello(Opts),
    <<?TLS_CLIENT_HELLO, _Len:24, Body/binary>> = CH,
    {ok, Map} = quic_tls:parse_client_hello(Body),
    ?assertEqual([x25519], maps:get(supported_groups, Map)),
    [{?GROUP_X25519, _}] = maps:get(key_share, Map).

secp256r1_keyshare_head_test() ->
    %% Head group secp256r1 → 65-byte uncompressed point in key_share.
    Opts = #{
        alpn => [<<"h3">>],
        transport_params => #{},
        groups => [secp256r1, x25519]
    },
    {CH, _Priv, _Random} = quic_tls:build_client_hello(Opts),
    <<?TLS_CLIENT_HELLO, _Len:24, Body/binary>> = CH,
    {ok, Map} = quic_tls:parse_client_hello(Body),
    [{Code, PubKey}] = maps:get(key_share, Map),
    ?assertEqual(?GROUP_SECP256R1, Code),
    ?assertEqual(65, byte_size(PubKey)).

retry_random_reused_test() ->
    %% retry_random / retry_session_id are echoed verbatim into CH2.
    R = crypto:strong_rand_bytes(32),
    Opts = #{
        alpn => [<<"h3">>],
        transport_params => #{},
        groups => [x25519, secp256r1],
        key_share_group => secp256r1,
        retry_random => R,
        retry_session_id => <<>>
    },
    {CH, _Priv, Random} = quic_tls:build_client_hello(Opts),
    ?assertEqual(R, Random),
    <<?TLS_CLIENT_HELLO, _Len:24, Body/binary>> = CH,
    {ok, Map} = quic_tls:parse_client_hello(Body),
    %% supported_groups unchanged; key_share moved to secp256r1
    ?assertEqual([x25519, secp256r1], maps:get(supported_groups, Map)),
    [{?GROUP_SECP256R1, _}] = maps:get(key_share, Map).

%%====================================================================
%% Custom signature_algorithms advertisement
%%====================================================================

custom_signature_algs_test() ->
    Opts = #{
        alpn => [<<"h3">>],
        transport_params => #{},
        signature_algs => [ecdsa_secp384r1_sha384, ed25519]
    },
    {CH, _Priv, _Random} = quic_tls:build_client_hello(Opts),
    <<?TLS_CLIENT_HELLO, _Len:24, Body/binary>> = CH,
    {ok, Map} = quic_tls:parse_client_hello(Body),
    ?assertEqual(
        [?SIG_ECDSA_SECP384R1_SHA384, ?SIG_ED25519],
        maps:get(signature_algorithms, Map)
    ).

%%====================================================================
%% HelloRetryRequest wire format
%%====================================================================

hrr_roundtrip_test_() ->
    [
        {atom_to_list(G), fun() -> hrr_roundtrip(G) end}
     || G <- [x25519, secp256r1, secp384r1]
    ].

hrr_roundtrip(Group) ->
    HRR = quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, Group),
    <<?TLS_SERVER_HELLO, _Len:24, Body/binary>> = HRR,
    {hrr, Info} = quic_tls:parse_server_hello(Body),
    ?assertEqual(aes_128_gcm, maps:get(cipher, Info)),
    ?assertEqual(Group, maps:get(selected_group, Info)).

hrr_random_is_sentinel_test() ->
    HRR = quic_tls:build_hello_retry_request(<<>>, ?TLS_AES_128_GCM_SHA256, secp256r1),
    %% Body random field = bytes 3..34 (after 1B type + 3B len + 2B version)
    <<?TLS_SERVER_HELLO, _Len:24, ?TLS_VERSION_1_2:16, Random:32/binary, _/binary>> = HRR,
    ?assertEqual(?TLS_HRR_RANDOM, Random).

%%====================================================================
%% Synthetic message_hash transcript prefix (RFC 8446 §4.4.1)
%%====================================================================

hrr_transcript_prefix_sha256_test() ->
    CH1 = <<"a fake clienthello">>,
    Hash = crypto:hash(sha256, CH1),
    Prefix = quic_crypto:hrr_transcript_prefix(aes_128_gcm, Hash),
    ?assertEqual(<<254:8, 32:24, Hash/binary>>, Prefix).

hrr_transcript_prefix_sha384_test() ->
    CH1 = <<"another fake clienthello">>,
    Hash = crypto:hash(sha384, CH1),
    Prefix = quic_crypto:hrr_transcript_prefix(aes_256_gcm, Hash),
    ?assertEqual(<<254:8, 48:24, Hash/binary>>, Prefix).

%%====================================================================
%% Signature scheme sign + verify round-trips
%%====================================================================

sign_verify_ecdsa_p384_test() ->
    Key = public_key:generate_key({namedCurve, secp384r1}),
    sign_verify_roundtrip(?SIG_ECDSA_SECP384R1_SHA384, Key, ec_pubkey(Key, secp384r1)).

sign_verify_rsa_pss_384_test() ->
    Key = public_key:generate_key({rsa, 2048, 65537}),
    %% {'RSAPrivateKey', Version, Modulus, PublicExponent, ...}
    N = element(3, Key),
    E = element(4, Key),
    sign_verify_roundtrip(?SIG_RSA_PSS_RSAE_SHA384, Key, [E, N]).

sign_verify_ed25519_test() ->
    {Pub, Priv} = crypto:generate_key(eddsa, ed25519),
    Key = {ed_pri, ed25519, Pub, Priv},
    sign_verify_roundtrip(?SIG_ED25519, Key, [Pub, ed25519]).

%% Build a server CertificateVerify with `Scheme', then verify the
%% signature against `PubKey' using the same content string.
sign_verify_roundtrip(Scheme, PrivKey, PubKey) ->
    Hash = crypto:hash(sha256, <<"transcript">>),
    CV = quic_tls:build_certificate_verify(Scheme, PrivKey, Hash),
    <<?TLS_CERTIFICATE_VERIFY, _Len:24, Scheme:16, SigLen:16, Sig:SigLen/binary>> = CV,
    Spaces = binary:copy(<<32>>, 64),
    Content = <<Spaces/binary, "TLS 1.3, server CertificateVerify", 0, Hash/binary>>,
    {SigAlg, HashAlg, Opts} = sig_params(Scheme),
    ?assert(crypto:verify(SigAlg, HashAlg, Content, Sig, PubKey, Opts)).

%% Mirror quic_tls:get_signature_params/1 (it is not exported).
sig_params(?SIG_ECDSA_SECP384R1_SHA384) ->
    {ecdsa, sha384, []};
sig_params(?SIG_RSA_PSS_RSAE_SHA384) ->
    {rsa, sha384, [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, -1}]};
sig_params(?SIG_ED25519) ->
    {eddsa, none, []}.

ec_pubkey(Key, Curve) ->
    %% #'ECPrivateKey'{} tuple: {tag, ver, priv, params, pubpoint, ...}
    PubPoint = element(5, Key),
    [PubPoint, Curve].

%%====================================================================
%% Unsupported scheme fails loudly (no RSA-PSS fallback)
%%====================================================================

unsupported_scheme_errors_test() ->
    %% ed448 and a bogus code are not wired; signing must fail rather
    %% than silently using RSA-PSS.
    Key = public_key:generate_key({namedCurve, secp256r1}),
    ?assertError(
        {unsupported_signature_scheme, _},
        quic_tls:build_certificate_verify(?SIG_ED448, Key, crypto:hash(sha256, <<"x">>))
    ),
    ?assertError(
        {unsupported_signature_scheme, _},
        quic_tls:build_certificate_verify(16#FFFF, Key, crypto:hash(sha256, <<"x">>))
    ).
