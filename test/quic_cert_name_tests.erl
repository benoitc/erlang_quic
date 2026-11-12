%%% -*- erlang -*-
%%%
%%% Server name checks in quic_cert:validate_server/4 against the
%%% subjectAltName rules of RFC 9525 Sections 6.3 and 6.4.

-module(quic_cert_name_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%%====================================================================
%% DNS-ID
%%====================================================================

exact_dns_id_test_() ->
    Ca = ca(),
    Leaf = leaf(Ca, "foo.example.com", [{dNSName, "foo.example.com"}]),
    [
        ?_assertEqual(ok, check(Ca, Leaf, <<"foo.example.com">>)),
        ?_assertEqual(ok, check(Ca, Leaf, <<"FOO.Example.COM">>)),
        ?_assertEqual(mismatch(<<"bar.example.com">>), check(Ca, Leaf, <<"bar.example.com">>)),
        ?_assertEqual(mismatch(<<"example.com">>), check(Ca, Leaf, <<"example.com">>))
    ].

wildcard_dns_id_test_() ->
    Ca = ca(),
    Leaf = leaf(Ca, "example.com", [{dNSName, "*.example.com"}]),
    [
        ?_assertEqual(ok, check(Ca, Leaf, <<"foo.example.com">>)),
        ?_assertEqual(ok, check(Ca, Leaf, <<"Foo.EXAMPLE.com">>)),
        ?_assertEqual(mismatch(<<"example.com">>), check(Ca, Leaf, <<"example.com">>)),
        ?_assertEqual(mismatch(<<"a.b.example.com">>), check(Ca, Leaf, <<"a.b.example.com">>)),
        ?_assertEqual(mismatch(<<"foo.example.org">>), check(Ca, Leaf, <<"foo.example.org">>))
    ].

partial_label_wildcard_test_() ->
    Ca = ca(),
    [
        ?_assertEqual(
            mismatch(<<"foo.example.com">>),
            check(Ca, leaf(Ca, "x", [{dNSName, "f*o.example.com"}]), <<"foo.example.com">>)
        ),
        ?_assertEqual(
            mismatch(<<"foobar.example.com">>),
            check(Ca, leaf(Ca, "x", [{dNSName, "foo*.example.com"}]), <<"foobar.example.com">>)
        ),
        ?_assertEqual(
            mismatch(<<"foo.example.com">>),
            check(Ca, leaf(Ca, "x", [{dNSName, "*oo.example.com"}]), <<"foo.example.com">>)
        )
    ].

a_label_wildcard_test() ->
    Ca = ca(),
    Leaf = leaf(Ca, "x", [{dNSName, "xn--*.example.com"}]),
    ?assertEqual(
        mismatch(<<"xn--caf-dma.example.com">>),
        check(Ca, Leaf, <<"xn--caf-dma.example.com">>)
    ).

bare_wildcard_test() ->
    Ca = ca(),
    Leaf = leaf(Ca, "x", [{dNSName, "*"}]),
    ?assertEqual(mismatch(<<"localhost">>), check(Ca, Leaf, <<"localhost">>)).

%%====================================================================
%% No DNS-ID or IP-ID: the subject CN is never used
%%====================================================================

cn_only_leaf_test_() ->
    Ca = ca(),
    [
        ?_assertEqual(
            mismatch(<<"foo.example.com">>),
            check(Ca, leaf(Ca, "foo.example.com", none), <<"foo.example.com">>)
        ),
        ?_assertEqual(
            mismatch(<<"foo.example.com">>),
            check(Ca, leaf(Ca, "*.example.com", none), <<"foo.example.com">>)
        ),
        ?_assertEqual(
            mismatch(<<"foo.example.com">>),
            check(
                Ca,
                leaf(Ca, "foo.example.com", [{rfc822Name, "admin@example.com"}]),
                <<"foo.example.com">>
            )
        )
    ].

%%====================================================================
%% IP-ID
%%====================================================================

ip_id_test_() ->
    Ca = ca(),
    Leaf = leaf(Ca, "x", [{iPAddress, [127, 0, 0, 1]}, {iPAddress, lists:duplicate(15, 0) ++ [1]}]),
    [
        ?_assertEqual(ok, check(Ca, Leaf, <<"127.0.0.1">>)),
        ?_assertEqual(ok, check(Ca, Leaf, <<"::1">>)),
        ?_assertEqual(mismatch(<<"127.0.0.2">>), check(Ca, Leaf, <<"127.0.0.2">>)),
        ?_assertEqual(mismatch(<<"::2">>), check(Ca, Leaf, <<"::2">>))
    ].

ip_id_never_by_dns_id_test_() ->
    Ca = ca(),
    [
        ?_assertEqual(
            mismatch(<<"127.0.0.1">>),
            check(Ca, leaf(Ca, "127.0.0.1", [{dNSName, "*.0.0.1"}]), <<"127.0.0.1">>)
        ),
        ?_assertEqual(
            mismatch(<<"127.0.0.1">>),
            check(Ca, leaf(Ca, "127.0.0.1", [{dNSName, "127.0.0.1"}]), <<"127.0.0.1">>)
        ),
        ?_assertEqual(
            mismatch(<<"127.0.0.1">>),
            check(Ca, leaf(Ca, "127.0.0.1", none), <<"127.0.0.1">>)
        )
    ].

%%====================================================================
%% Helpers
%%====================================================================

check(#{der := CaDer}, Leaf, Host) ->
    quic_cert:validate_server(Leaf, [], [CaDer], Host).

mismatch(Host) ->
    {error, {hostname_mismatch, Host}}.

ca() ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Exts = [
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = true}
        },
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = [keyCertSign, cRLSign, digitalSignature]
        }
    ],
    #{
        key => Key,
        name => "Name Test CA",
        der => mint("Name Test CA", "Name Test CA", Key, Key, Exts)
    }.

%% Leaf signed by `Ca' with subject CN `CN' and `San' as its
%% subjectAltName entries, or no subjectAltName extension for `none'.
leaf(#{key := CaKey, name := CaName}, CN, San) ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    Base = [
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = false}
        },
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = [digitalSignature]
        }
    ],
    Exts =
        case San of
            none ->
                Base;
            _ ->
                Base ++
                    [
                        #'Extension'{
                            extnID = ?'id-ce-subjectAltName',
                            critical = false,
                            extnValue = San
                        }
                    ]
        end,
    mint(CN, CaName, Key, CaKey, Exts).

mint(Subject, Issuer, #'ECPrivateKey'{publicKey = Pub, parameters = Params}, SignKey, Exts) ->
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = erlang:unique_integer([positive, monotonic]),
        signature = #'SignatureAlgorithm'{algorithm = ?'ecdsa-with-SHA256'},
        issuer = name(Issuer),
        validity = #'Validity'{
            notBefore = {utcTime, "200101000000Z"}, notAfter = {utcTime, "350101000000Z"}
        },
        subject = name(Subject),
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
            algorithm = #'PublicKeyAlgorithm'{algorithm = ?'id-ecPublicKey', parameters = Params},
            subjectPublicKey = #'ECPoint'{point = Pub}
        },
        extensions = Exts
    },
    public_key:pkix_sign(TBS, SignKey).

name(CN) ->
    {rdnSequence, [
        [
            #'AttributeTypeAndValue'{
                type = ?'id-at-commonName', value = {utf8String, list_to_binary(CN)}
            }
        ]
    ]}.
