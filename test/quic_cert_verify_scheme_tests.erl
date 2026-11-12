%%% -*- erlang -*-
%%%
%%% The signature scheme in a peer's CertificateVerify has to fit its
%%% certificate key (RFC 9846 Sections 4.3.3 and 4.5.2). A scheme that does
%%% not fit fails verification instead of raising.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_cert_verify_scheme_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

-define(HASH, crypto:hash(sha256, <<"transcript">>)).

rsa_pkcs1_is_refused_test() ->
    #{cert := Cert, key := Key} = root({rsa, 2048, 65537}),
    Sig = public_key:sign(content(), sha256, Key),
    ?assertNot(verify(?SIG_RSA_PKCS1_SHA256, Sig, Cert)).

unknown_scheme_with_an_rsa_key_test() ->
    #{cert := Cert, key := Key} = root({rsa, 2048, 65537}),
    Sig = public_key:sign(content(), sha256, Key),
    ?assertNot(verify(16#0a0a, Sig, Cert)).

ecdsa_scheme_for_another_curve_test() ->
    #{cert := Cert, key := Key} = root({namedCurve, secp256r1}),
    Sig = public_key:sign(content(), sha384, Key),
    ?assertNot(verify(?SIG_ECDSA_SECP384R1_SHA384, Sig, Cert)).

matching_ecdsa_scheme_still_verifies_test() ->
    #{cert := Cert, key := Key} = root({namedCurve, secp256r1}),
    Sig = public_key:sign(content(), sha256, Key),
    ?assert(verify(?SIG_ECDSA_SECP256R1_SHA256, Sig, Cert)).

verify(Scheme, Sig, Cert) ->
    Body = <<Scheme:16, (byte_size(Sig)):16, Sig/binary>>,
    quic_tls:verify_certificate_verify(Body, Cert, ?HASH, server).

content() ->
    <<(binary:copy(<<32>>, 64))/binary, "TLS 1.3, server CertificateVerify", 0, (?HASH)/binary>>.

root(KeyGen) ->
    public_key:pkix_test_root_cert("verify scheme", [{key, KeyGen}]).
