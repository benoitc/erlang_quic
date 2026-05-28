%%% -*- erlang -*-
%%%
%%% Tests for server certificate validation (quic_cert) and the
%%% client-side server-authentication path in quic_connection.
%%%
%%% Regression coverage for GHSA-2r8v-p65x-3663: a QUIC client must
%%% reject a server it cannot authenticate when `verify' is enabled.

-module(quic_cert_tests).

-include_lib("eunit/include/eunit.hrl").

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
        catch quic:close(Conn),
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
    catch quic:stop_server(Name),
    ok.

%% Connect over HTTP/3 to localhost and report whether the handshake
%% completed. `server_name' is set by quic_h3 to the connect host.
h3_connect(Port, Opts0) ->
    Opts = Opts0#{sync => true, connect_timeout => ?CONNECT_TIMEOUT},
    case quic_h3:connect("localhost", Port, Opts) of
        {ok, Conn} ->
            catch quic_h3:close(Conn),
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
