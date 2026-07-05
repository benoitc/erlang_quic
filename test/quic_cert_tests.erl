%%% -*- erlang -*-
%%%
%%% Tests for server certificate validation (quic_cert) and the
%%% client-side server-authentication path in quic_connection.
%%%
%%% Regression coverage for GHSA-2r8v-p65x-3663: a QUIC client must
%%% reject a server it cannot authenticate when `verify' is enabled.

-module(quic_cert_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(CONNECT_TIMEOUT, 3000).

%%====================================================================
%% quic_cert:validate_server/4 unit tests
%%====================================================================

validate_server_test_() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Leaf, _Key} ->
            {ok, Other, _} = gen_cert("/CN=other", "subjectAltName=DNS:other"),
            [
                {"trusted self-signed leaf with matching name",
                    ?_assertEqual(ok, quic_cert:validate_server(Leaf, [], [Leaf], <<"localhost">>))},
                {"no trust anchors is rejected",
                    ?_assertEqual(
                        {error, no_trust_anchors},
                        quic_cert:validate_server(Leaf, [], [], <<"localhost">>)
                    )},
                {"untrusted anchor is rejected",
                    ?_assertEqual(
                        {error, unknown_ca},
                        quic_cert:validate_server(Leaf, [], [Other], <<"localhost">>)
                    )},
                {"hostname mismatch is rejected",
                    ?_assertMatch(
                        {error, {hostname_mismatch, _}},
                        quic_cert:validate_server(Leaf, [], [Leaf], <<"evil.example">>)
                    )},
                {"missing certificate is rejected",
                    ?_assertEqual(
                        {error, no_certificate},
                        quic_cert:validate_server(undefined, [], [Leaf], <<"localhost">>)
                    )},
                {"undefined server name skips the hostname check",
                    ?_assertEqual(ok, quic_cert:validate_server(Leaf, [], [Leaf], undefined))}
            ];
        {error, _} ->
            []
    end.

%% Regression: a server commonly sends an extra or cross-signed cert
%% above the cert that actually chains to a trust anchor (e.g.
%% cloudflare.com over Google Trust Services with the Mozilla NSS /
%% certifi bundle). The topmost-only anchor lookup used to reject these
%% chains with `unknown_ca'.
cross_signed_chain_test_() ->
    case gen_ca_files("/CN=RootA") of
        {ok, RootA} ->
            {ok, Int} = gen_signed_cert(
                "/CN=IntA", "basicConstraints=critical,CA:true", RootA
            ),
            {ok, Leaf} = gen_signed_cert(
                "/CN=leaf.test", "subjectAltName=DNS:leaf.test", Int
            ),
            {ok, Extra, _} = gen_cert("/CN=Extra", "subjectAltName=DNS:extra"),
            #{cert := RootADer} = RootA,
            #{cert := IntDer} = Int,
            #{cert := LeafDer} = Leaf,
            [
                {"extra cross-signed cert above the anchored intermediate is accepted",
                    ?_assertEqual(
                        ok,
                        quic_cert:validate_server(
                            LeafDer, [IntDer, Extra], [RootADer], <<"leaf.test">>
                        )
                    )},
                {"chain with only the unrelated root as anchor is rejected",
                    ?_assertMatch(
                        {error, _},
                        quic_cert:validate_server(
                            LeafDer, [IntDer, Extra], [Extra], <<"leaf.test">>
                        )
                    )},
                {"two-cert chain without the extra cert validates",
                    ?_assertEqual(
                        ok,
                        quic_cert:validate_server(
                            LeafDer, [IntDer], [RootADer], <<"leaf.test">>
                        )
                    )}
            ];
        {error, _} ->
            []
    end.

%% Regression: a chain anchored by an expired cross-signed root must
%% still validate when the trust store holds a still-valid root with the
%% same public key (Let's Encrypt ISRG Root X2 cross-signed by the expired
%% X1). Recovery only swaps the trust anchor: a genuinely expired leaf or
%% intermediate must still fail.
cross_signed_expired_root_test_() ->
    Kx1 = gen_key(),
    Kx2 = gen_key(),
    Ke5 = gen_key(),
    Kleaf = gen_key(),
    %% Two self-signed roots in the store; X2 shares its key with the
    %% expired cross-signed X2.
    X1self = mint("Root X1", "Root X1", Kx1, Kx1, valid, ca),
    X2self = mint("Root X2", "Root X2", Kx2, Kx2, valid, ca),
    %% X2 cross-signed by X1 (same subject + key as X2self), expired.
    X2cross = mint("Root X2", "Root X1", Kx2, Kx1, expired, ca),
    X2crossValid = mint("Root X2", "Root X1", Kx2, Kx1, valid, ca),
    E5 = mint("Int E5", "Root X2", Ke5, Kx2, valid, ca),
    E5exp = mint("Int E5", "Root X2", Ke5, Kx2, expired, ca),
    Leaf = mint("leaf.test", "Int E5", Kleaf, Ke5, valid, leaf),
    LeafExp = mint("leaf.test", "Int E5", Kleaf, Ke5, expired, leaf),
    Expired = {error, {bad_cert, cert_expired}},
    [
        {"chain anchored at the expired cross-signed root recovers via the same-key root",
            ?_assertEqual(
                ok,
                quic_cert:validate_server(Leaf, [E5, X2cross], [X1self, X2self], undefined)
            )},
        {"a genuinely expired leaf still fails",
            ?_assertEqual(
                Expired,
                quic_cert:validate_server(LeafExp, [E5, X2cross], [X1self, X2self], undefined)
            )},
        {"a genuinely expired intermediate still fails",
            ?_assertEqual(
                Expired,
                quic_cert:validate_server(Leaf, [E5exp, X2crossValid], [X1self, X2self], undefined)
            )},
        {"no still-valid same-key anchor leaves the expiry result",
            ?_assertEqual(
                Expired,
                quic_cert:validate_server(Leaf, [E5, X2cross], [X1self], undefined)
            )},
        {"a valid cross-signed root anchors on the first try",
            ?_assertEqual(
                ok,
                quic_cert:validate_server(Leaf, [E5, X2crossValid], [X1self, X2self], undefined)
            )}
    ].

%%====================================================================
%% End-to-end client behaviour
%%====================================================================

client_verification_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun(Ctx) ->
        case Ctx of
            skip ->
                [];
            #{port := Port, cert := Cert} ->
                [
                    {"verify=false connects to a self-signed server",
                        {timeout, 30, ?_assertEqual(connected, connect(Port, #{verify => false}))}},
                    {"verify=true with the right anchor and name connects",
                        {timeout, 30,
                            ?_assertEqual(
                                connected,
                                connect(Port, #{
                                    verify => true,
                                    cacerts => [Cert],
                                    server_name => <<"localhost">>
                                })
                            )}},
                    {"verify=true without a trust anchor is rejected",
                        {timeout, 30,
                            ?_assertNotEqual(
                                connected,
                                connect(Port, #{verify => true, server_name => <<"localhost">>})
                            )}},
                    {"verify=true with a name mismatch is rejected",
                        {timeout, 30,
                            ?_assertNotEqual(
                                connected,
                                connect(Port, #{
                                    verify => true,
                                    cacerts => [Cert],
                                    server_name => <<"wrong.example">>
                                })
                            )}}
                ]
        end
    end}.

setup() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Cert, Key} ->
            {ok, _} = application:ensure_all_started(quic),
            {ok, Server} = quic_test_echo_server:start(#{cert => Cert, key => Key}),
            (maps:merge(#{cert => Cert}, Server))#{server => Server};
        {error, _} ->
            skip
    end.

cleanup(skip) ->
    ok;
cleanup(#{server := Server}) ->
    quic_test_echo_server:stop(Server).

%% Run each connection in its own owner process so events from one
%% attempt never leak into the next attempt's mailbox. The `connected'
%% event is keyed on the connection pid while error notifications are
%% keyed on the connection ref, so match on any source.
connect(Port, Opts0) ->
    Parent = self(),
    {Pid, MRef} = spawn_monitor(fun() ->
        Opts = Opts0#{alpn => [<<"echo">>]},
        {ok, Conn} = quic:connect("127.0.0.1", Port, Opts, self()),
        Result =
            receive
                {quic, _, {connected, _Info}} -> connected;
                {quic, _, {closed, Reason}} -> {closed, Reason};
                {quic, _, {error, Reason}} -> {error, Reason}
            after ?CONNECT_TIMEOUT -> timeout
            end,
        quic:safe_close(Conn),
        Parent ! {result, self(), Result}
    end),
    receive
        {result, Pid, Result} ->
            erlang:demonitor(MRef, [flush]),
            Result;
        {'DOWN', MRef, process, Pid, DownReason} ->
            {crashed, DownReason}
    after ?CONNECT_TIMEOUT + 3000 ->
        erlang:demonitor(MRef, [flush]),
        exit(Pid, kill),
        timeout
    end.

%%====================================================================
%% Anti-amplification (RFC 9000 8.1): a server whose first flight
%% exceeds 3x the bytes received must defer the excess and still
%% complete the handshake once the client re-sends its Initial.
%%====================================================================

amplification_test_() ->
    {setup, fun amp_setup/0, fun cleanup/1, fun(Ctx) ->
        case Ctx of
            skip ->
                [];
            #{port := Port} ->
                [
                    %% The server defers the part of its flight that exceeds 3x
                    %% the bytes received; the handshake still completes once the
                    %% client's Handshake packet validates the address (RFC 9000
                    %% 8.1) and the deferred flight is flushed.
                    {"large server flight (> 3x) still completes the handshake",
                        {timeout, 30, ?_assertEqual(connected, connect(Port, #{verify => false}))}}
                ]
        end
    end}.

amp_setup() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Cert, Key} ->
            %% Inflate the server's first flight past 3 x 1200 bytes with a
            %% padding chain (unrelated self-signed certs; the client uses
            %% verify => false so the chain need not validate). This forces
            %% the server to defer part of the flight under the budget.
            Chain = [
                C
             || {ok, C, _} <- [
                    gen_cert("/CN=pad", "subjectAltName=DNS:pad")
                 || _ <- lists:seq(1, 4)
                ]
            ],
            {ok, _} = application:ensure_all_started(quic),
            {ok, Server} = quic_test_echo_server:start(#{
                cert => Cert, key => Key, cert_chain => Chain
            }),
            (maps:merge(#{cert => Cert}, Server))#{server => Server};
        {error, _} ->
            skip
    end.

%%====================================================================
%% Retry address validation (RFC 9000 8.1.2): with
%% address_validation => always the server sends a Retry and the
%% handshake must complete once the client echoes the token. (This used
%% to loop forever because the token's ODCID was matched against the
%% retried Initial's DCID.)
%%====================================================================

retry_address_validation_test_() ->
    {setup, fun retry_setup/0, fun cleanup/1, fun(Ctx) ->
        case Ctx of
            skip ->
                [];
            #{port := Port} ->
                [
                    {"address_validation=always completes via a Retry round-trip",
                        {timeout, 30, ?_assertEqual(connected, connect(Port, #{verify => false}))}}
                ]
        end
    end}.

retry_setup() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Cert, Key} ->
            {ok, _} = application:ensure_all_started(quic),
            {ok, Server} = quic_test_echo_server:start(#{
                cert => Cert, key => Key, address_validation => always
            }),
            (maps:merge(#{cert => Cert}, Server))#{server => Server};
        {error, _} ->
            skip
    end.

%%====================================================================
%% HTTP/3 client inherits the same verification
%%====================================================================

h3_verification_test_() ->
    {setup, fun h3_setup/0, fun h3_cleanup/1, fun(Ctx) ->
        case Ctx of
            skip ->
                [];
            #{port := Port, cert := Cert} ->
                [
                    {"h3 verify_none connects",
                        {timeout, 30,
                            ?_assertEqual(connected, h3_connect(Port, #{verify => verify_none}))}},
                    {"h3 verify_peer with the right anchor connects",
                        {timeout, 30,
                            ?_assertEqual(
                                connected,
                                h3_connect(Port, #{verify => verify_peer, cacerts => [Cert]})
                            )}},
                    {"h3 verify_peer without a trust anchor is rejected",
                        {timeout, 30,
                            ?_assertMatch(
                                {error, _}, h3_connect(Port, #{verify => verify_peer})
                            )}}
                ]
        end
    end}.

h3_setup() ->
    case gen_cert("/CN=localhost", "subjectAltName=DNS:localhost,IP:127.0.0.1") of
        {ok, Cert, Key} ->
            {ok, _} = application:ensure_all_started(quic),
            Name = list_to_atom("quic_h3_verify_" ++ suffix()),
            {ok, _} = quic_h3:start_server(Name, 0, #{cert => Cert, key => Key}),
            {ok, Port} = quic:get_server_port(Name),
            #{name => Name, port => Port, cert => Cert};
        {error, _} ->
            skip
    end.

h3_cleanup(skip) ->
    ok;
h3_cleanup(#{name := Name}) ->
    try
        quic:stop_server(Name)
    catch
        _:_ -> ok
    end,
    ok.

%% Connect over HTTP/3 to localhost and report whether the handshake
%% completed. `server_name' is set by quic_h3 to the connect host.
h3_connect(Port, Opts0) ->
    %% Connect to the IPv4 loopback directly (deterministic, no Happy Eyeballs
    %% race) while keeping the SNI/hostname as localhost for cert validation.
    Opts = Opts0#{
        sync => true,
        connect_timeout => ?CONNECT_TIMEOUT,
        quic_opts => #{server_name => <<"localhost">>}
    },
    case quic_h3:connect("127.0.0.1", Port, Opts) of
        {ok, Conn} ->
            try
                quic_h3:close(Conn)
            catch
                _:_ -> ok
            end,
            connected;
        {error, Reason} ->
            {error, Reason}
    end.

%%====================================================================
%% Helpers
%%====================================================================

%% Generate a self-signed certificate with the given subject and
%% SAN extension. Returns the leaf DER and the decoded private key,
%% or `{error, _}' when openssl is unavailable.
gen_cert(Subject, SanExt) ->
    Dir = filename:join("/tmp", "quic_cert_test_" ++ suffix()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile = filename:join(Dir, "key.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
            "-days 1 -nodes -subj '~s' -addext '~s' 2>/dev/null",
            [KeyFile, CertFile, Subject, SanExt]
        )
    ),
    _ = os:cmd(Cmd),
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertPem} = file:read_file(CertFile),
            {ok, KeyPem} = file:read_file(KeyFile),
            [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
            {ok, CertDer, decode_key(KeyPem)};
        _ ->
            {error, cert_generation_failed}
    end.

%% Make a self-signed CA cert (CA:true). Returns the DER plus the
%% openssl files so other certs can be signed by it.
gen_ca_files(Subject) ->
    Dir = filename:join("/tmp", "quic_cert_test_" ++ suffix()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    KeyFile = filename:join(Dir, "ca.key"),
    CertFile = filename:join(Dir, "ca.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
            "-days 1 -nodes -subj '~s' "
            "-addext basicConstraints=critical,CA:true 2>/dev/null",
            [KeyFile, CertFile, Subject]
        )
    ),
    _ = os:cmd(Cmd),
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertPem} = file:read_file(CertFile),
            [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
            {ok, #{cert => CertDer, cert_file => CertFile, key_file => KeyFile}};
        _ ->
            {error, cert_generation_failed}
    end.

%% CSR for `Subject', signed by `Parent's' files with `Ext' as the
%% x509v3 extensions. Returns the DER plus openssl files so further
%% intermediates can chain off it.
gen_signed_cert(Subject, Ext, #{cert_file := ParentCert, key_file := ParentKey}) ->
    Dir = filename:join("/tmp", "quic_cert_test_" ++ suffix()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    KeyFile = filename:join(Dir, "key.pem"),
    CsrFile = filename:join(Dir, "csr.pem"),
    CertFile = filename:join(Dir, "cert.pem"),
    ExtFile = filename:join(Dir, "ext.cnf"),
    ok = file:write_file(ExtFile, Ext),
    CsrCmd = lists:flatten(
        io_lib:format(
            "openssl req -newkey rsa:2048 -keyout ~s -out ~s "
            "-nodes -subj '~s' 2>/dev/null",
            [KeyFile, CsrFile, Subject]
        )
    ),
    SignCmd = lists:flatten(
        io_lib:format(
            "openssl x509 -req -in ~s -CA ~s -CAkey ~s -CAcreateserial "
            "-out ~s -days 1 -extfile ~s 2>/dev/null",
            [CsrFile, ParentCert, ParentKey, CertFile, ExtFile]
        )
    ),
    _ = os:cmd(CsrCmd),
    _ = os:cmd(SignCmd),
    case {filelib:is_file(CertFile), filelib:is_file(KeyFile)} of
        {true, true} ->
            {ok, CertPem} = file:read_file(CertFile),
            [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
            {ok, #{cert => CertDer, cert_file => CertFile, key_file => KeyFile}};
        _ ->
            {error, cert_generation_failed}
    end.

decode_key(KeyPem) ->
    case public_key:pem_decode(KeyPem) of
        [{'RSAPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('RSAPrivateKey', Der);
        [{'ECPrivateKey', Der, not_encrypted}] ->
            public_key:der_decode('ECPrivateKey', Der);
        [{'PrivateKeyInfo', Der, not_encrypted}] ->
            public_key:der_decode('PrivateKeyInfo', Der);
        [{_Type, Der, not_encrypted}] ->
            Der
    end.

suffix() ->
    integer_to_list(erlang:unique_integer([positive, monotonic])).

%%--------------------------------------------------------------------
%% In-process certificate minting. Lets a test reuse one key across two
%% roots and backdate a cert to expired, which openssl can't do
%% portably. Builds an `#'OTPTBSCertificate'{}' and signs it with
%% `public_key:pkix_sign/2'.
%%--------------------------------------------------------------------

gen_key() ->
    public_key:generate_key({rsa, 2048, 65537}).

%% DER of a cert with the given subject/issuer CNs, holding `KeyPair's
%% public key and signed by `SignKeyPair'. `Window' is `valid' or
%% `expired'; `Kind' is `ca' or `leaf'.
mint(Subject, Issuer, KeyPair, SignKeyPair, Window, Kind) ->
    TBS = #'OTPTBSCertificate'{
        version = v3,
        serialNumber = erlang:unique_integer([positive, monotonic]) + 1,
        signature = #'SignatureAlgorithm'{algorithm = ?'sha256WithRSAEncryption'},
        issuer = cert_name(Issuer),
        validity = cert_validity(Window),
        subject = cert_name(Subject),
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{
            algorithm = #'PublicKeyAlgorithm'{algorithm = ?'rsaEncryption', parameters = 'NULL'},
            subjectPublicKey = cert_pub_key(KeyPair)
        },
        extensions = cert_extensions(Kind)
    },
    public_key:pkix_sign(TBS, SignKeyPair).

cert_pub_key(#'RSAPrivateKey'{modulus = M, publicExponent = E}) ->
    #'RSAPublicKey'{modulus = M, publicExponent = E}.

cert_name(CN) ->
    {rdnSequence, [
        [#'AttributeTypeAndValue'{type = ?'id-at-commonName', value = {utf8String, CN}}]
    ]}.

cert_validity(valid) ->
    #'Validity'{notBefore = {utcTime, "200101000000Z"}, notAfter = {utcTime, "350101000000Z"}};
cert_validity(expired) ->
    #'Validity'{notBefore = {utcTime, "200101000000Z"}, notAfter = {utcTime, "210101000000Z"}}.

cert_extensions(ca) ->
    [
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
    ];
cert_extensions(leaf) ->
    [
        #'Extension'{
            extnID = ?'id-ce-basicConstraints',
            critical = true,
            extnValue = #'BasicConstraints'{cA = false}
        },
        #'Extension'{
            extnID = ?'id-ce-keyUsage',
            critical = true,
            extnValue = [digitalSignature, keyEncipherment]
        }
    ].

%%====================================================================
%% quic_cert:validate_client/3 — mutual-TLS client chain validation
%% (RFC 8446 §4.4.2.4)
%%
%% Negative coverage for the gap this change closes: previously the server
%% checked only the client's CertificateVerify signature (proof of private-key
%% possession) and never validated the chain, so a self-signed "faked" cert
%% with an attacker-chosen subject was accepted. The before/after test below
%% shows the signature check still passes for such a cert while chain
%% validation now rejects it.
%%====================================================================

validate_client_test_() ->
    case gen_ca_files("/CN=ClientRoot") of
        {ok, #{cert := RootDer} = Root} ->
            {ok, #{cert := LeafDer}} =
                gen_signed_cert("/CN=legit.client", "subjectAltName=DNS:legit.client", Root),
            %% Self-signed cert with the *same subject* as the legit one — what an
            %% attacker would forge. They hold its key, so possession is provable.
            {ok, FakeDer, _FakeKey} =
                gen_cert("/CN=legit.client", "subjectAltName=DNS:legit.client"),
            [
                {"CA-issued client cert validates against the trust anchor",
                    ?_assertEqual(ok, quic_cert:validate_client(LeafDer, [], [RootDer]))},
                {"a self-signed (faked) client cert is rejected as unknown_ca",
                    ?_assertEqual(
                        {error, unknown_ca}, quic_cert:validate_client(FakeDer, [], [RootDer])
                    )},
                {"a missing client cert is rejected",
                    ?_assertEqual(
                        {error, no_certificate}, quic_cert:validate_client(undefined, [], [RootDer])
                    )},
                {"no trust anchors rejects even a CA-issued cert",
                    ?_assertEqual(
                        {error, no_trust_anchors}, quic_cert:validate_client(LeafDer, [], [])
                    )}
            ];
        _ ->
            []
    end.

fake_client_cert_signature_vs_chain_test_() ->
    case gen_cert("/CN=evil.client", "subjectAltName=DNS:evil.client") of
        {ok, FakeDer, FakeKey} ->
            {ok, #{cert := RootDer}} = gen_ca_files("/CN=RealRoot"),
            TranscriptHash = crypto:strong_rand_bytes(32),
            %% rsa_pss_rsae_sha256 (0x0804); the openssl test certs are RSA-2048.
            SigScheme = 16#0804,
            FullMsg = quic_tls:build_certificate_verify_client(
                SigScheme, FakeKey, TranscriptHash
            ),
            %% Strip the 4-byte handshake header to get the CertificateVerify body.
            <<_Type, _Len:24, Body/binary>> = FullMsg,
            [
                {"BEFORE: the signature/possession check alone accepts the faked cert",
                    ?_assert(
                        quic_tls:verify_certificate_verify(Body, FakeDer, TranscriptHash, client)
                    )},
                {"AFTER: chain validation rejects the faked cert",
                    ?_assertEqual(
                        {error, unknown_ca}, quic_cert:validate_client(FakeDer, [], [RootDer])
                    )}
            ];
        _ ->
            []
    end.
