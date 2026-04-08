%%% -*- erlang -*-
%%%
%%% Tests for client certificate support (mutual TLS)
%%% RFC 8446 Section 4.3.2 - CertificateRequest
%%% RFC 8446 Section 4.4.2 - Client Certificate
%%%

-module(quic_client_cert_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

%%====================================================================
%% Test Setup
%%====================================================================

ensure_started() ->
    application:ensure_all_started(quic).

generate_certs() ->
    TmpDir = filename:join([
        "/tmp", "quic_client_cert_test_" ++ integer_to_list(erlang:unique_integer([positive]))
    ]),
    ok = filelib:ensure_dir(filename:join(TmpDir, "dummy")),

    %% Generate server cert
    ServerCertFile = filename:join(TmpDir, "server_cert.pem"),
    ServerKeyFile = filename:join(TmpDir, "server_key.pem"),
    ServerCmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=server' 2>/dev/null",
        [ServerKeyFile, ServerCertFile]
    ),
    os:cmd(lists:flatten(ServerCmd)),

    %% Generate client cert
    ClientCertFile = filename:join(TmpDir, "client_cert.pem"),
    ClientKeyFile = filename:join(TmpDir, "client_key.pem"),
    ClientCmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
        "-days 1 -nodes -subj '/CN=client' 2>/dev/null",
        [ClientKeyFile, ClientCertFile]
    ),
    os:cmd(lists:flatten(ClientCmd)),

    case {filelib:is_file(ServerCertFile), filelib:is_file(ClientCertFile)} of
        {true, true} ->
            {ok, ServerCertPem} = file:read_file(ServerCertFile),
            {ok, ServerKeyPem} = file:read_file(ServerKeyFile),
            {ok, ClientCertPem} = file:read_file(ClientCertFile),
            {ok, ClientKeyPem} = file:read_file(ClientKeyFile),

            [{'Certificate', ServerCertDer, _}] = public_key:pem_decode(ServerCertPem),
            ServerKeyDer = decode_key(ServerKeyPem),
            [{'Certificate', ClientCertDer, _}] = public_key:pem_decode(ClientCertPem),
            ClientKeyDer = decode_key(ClientKeyPem),

            {ok, TmpDir, ServerCertDer, ServerKeyDer, ClientCertDer, ClientKeyDer};
        _ ->
            os:cmd("rm -rf " ++ TmpDir),
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

cleanup_server_only(TmpDir, ServerName) ->
    catch quic:stop_server(ServerName),
    catch os:cmd("rm -rf " ++ TmpDir),
    ok.

%%====================================================================
%% TLS Module Unit Tests - CertificateRequest
%%====================================================================

build_certificate_request_test() ->
    %% Build CertificateRequest with empty context
    CertReq = quic_tls:build_certificate_request(<<>>),

    %% Check it's a valid TLS handshake message
    <<Type, Len:24, Body/binary>> = CertReq,
    ?assertEqual(?TLS_CERTIFICATE_REQUEST, Type),
    ?assertEqual(byte_size(Body), Len),

    %% Parse it back
    {ok, Parsed} = quic_tls:parse_certificate_request(Body),
    ?assertEqual(<<>>, maps:get(context, Parsed)).

build_certificate_request_with_context_test() ->
    Context = <<1, 2, 3, 4>>,
    CertReq = quic_tls:build_certificate_request(Context),

    <<Type, Len:24, Body/binary>> = CertReq,
    ?assertEqual(?TLS_CERTIFICATE_REQUEST, Type),
    ?assertEqual(byte_size(Body), Len),

    {ok, Parsed} = quic_tls:parse_certificate_request(Body),
    ?assertEqual(Context, maps:get(context, Parsed)).

parse_certificate_request_invalid_test() ->
    ?assertEqual({error, invalid_certificate_request}, quic_tls:parse_certificate_request(<<>>)),
    ?assertEqual(
        {error, invalid_certificate_request}, quic_tls:parse_certificate_request(<<1, 2>>)
    ).

%%====================================================================
%% TLS Module Unit Tests - Client CertificateVerify
%%====================================================================

build_certificate_verify_client_rsa_test() ->
    case generate_certs() of
        {ok, TmpDir, _ServerCert, _ServerKey, _ClientCert, ClientKey} ->
            try
                TranscriptHash = crypto:hash(sha256, <<"test transcript">>),
                SigAlg = ?SIG_RSA_PSS_RSAE_SHA256,

                CertVerifyMsg = quic_tls:build_certificate_verify_client(
                    SigAlg, ClientKey, TranscriptHash
                ),

                <<Type, Len:24, Body/binary>> = CertVerifyMsg,
                ?assertEqual(?TLS_CERTIFICATE_VERIFY, Type),
                ?assertEqual(byte_size(Body), Len),

                %% Parse it back
                {ok, Parsed} = quic_tls:parse_certificate_verify(Body),
                ?assertEqual(SigAlg, maps:get(algorithm, Parsed)),
                ?assert(byte_size(maps:get(signature, Parsed)) > 0)
            after
                os:cmd("rm -rf " ++ TmpDir)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

%%====================================================================
%% TLS Module Unit Tests - Verify CertificateVerify
%%====================================================================

verify_certificate_verify_client_test() ->
    case generate_certs() of
        {ok, TmpDir, _ServerCert, _ServerKey, ClientCert, ClientKey} ->
            try
                TranscriptHash = crypto:hash(sha256, <<"test transcript">>),
                SigAlg = ?SIG_RSA_PSS_RSAE_SHA256,

                %% Build CertificateVerify
                CertVerifyMsg = quic_tls:build_certificate_verify_client(
                    SigAlg, ClientKey, TranscriptHash
                ),

                <<_Type, _Len:24, Body/binary>> = CertVerifyMsg,

                %% Verify it
                ?assert(
                    quic_tls:verify_certificate_verify(Body, ClientCert, TranscriptHash, client)
                )
            after
                os:cmd("rm -rf " ++ TmpDir)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

verify_certificate_verify_wrong_transcript_test() ->
    case generate_certs() of
        {ok, TmpDir, _ServerCert, _ServerKey, ClientCert, ClientKey} ->
            try
                TranscriptHash = crypto:hash(sha256, <<"test transcript">>),
                WrongHash = crypto:hash(sha256, <<"wrong transcript">>),
                SigAlg = ?SIG_RSA_PSS_RSAE_SHA256,

                CertVerifyMsg = quic_tls:build_certificate_verify_client(
                    SigAlg, ClientKey, TranscriptHash
                ),

                <<_Type, _Len:24, Body/binary>> = CertVerifyMsg,

                %% Verify with wrong transcript should fail
                ?assertNot(quic_tls:verify_certificate_verify(Body, ClientCert, WrongHash, client))
            after
                os:cmd("rm -rf " ++ TmpDir)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

verify_certificate_verify_wrong_role_test() ->
    case generate_certs() of
        {ok, TmpDir, _ServerCert, _ServerKey, ClientCert, ClientKey} ->
            try
                TranscriptHash = crypto:hash(sha256, <<"test transcript">>),
                SigAlg = ?SIG_RSA_PSS_RSAE_SHA256,

                %% Build as client
                CertVerifyMsg = quic_tls:build_certificate_verify_client(
                    SigAlg, ClientKey, TranscriptHash
                ),

                <<_Type, _Len:24, Body/binary>> = CertVerifyMsg,

                %% Verify with server role should fail (different context string)
                ?assertNot(
                    quic_tls:verify_certificate_verify(Body, ClientCert, TranscriptHash, server)
                )
            after
                os:cmd("rm -rf " ++ TmpDir)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

%%====================================================================
%% Integration Tests - Mutual TLS Handshake
%%====================================================================

%% Test server with verify=true, client without cert (empty Certificate)
server_verify_client_no_cert_test() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, ServerCert, ServerKey, _ClientCert, _ClientKey} ->
            ServerName = list_to_atom(
                "verify_nocert_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                %% Start server with verify=true
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => ServerCert,
                    key => ServerKey,
                    alpn => [<<"h3">>],
                    verify => true
                }),
                {ok, Port} = quic:get_server_port(ServerName),

                %% Connect without client cert
                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"h3">>],
                        server_name => <<"server">>
                    },
                    self()
                ),

                %% Wait for connection
                receive
                    {quic, Conn, {connected, _Info}} ->
                        %% Should connect successfully (empty cert is valid)
                        %% Client peercert returns server cert (not no_peercert)
                        {ok, _ServerCert} = quic:peercert(Conn),
                        quic:close(Conn, normal)
                after 5000 ->
                    ct:fail("Connection timeout")
                end
            after
                cleanup_server_only(TmpDir, ServerName)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

%% Test server with verify=true, client with cert
server_verify_client_with_cert_test() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, ServerCert, ServerKey, ClientCert, ClientKey} ->
            ServerName = list_to_atom(
                "verify_cert_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                %% Start server with verify=true
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => ServerCert,
                    key => ServerKey,
                    alpn => [<<"h3">>],
                    verify => true
                }),
                {ok, Port} = quic:get_server_port(ServerName),

                %% Connect with client cert
                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"h3">>],
                        server_name => <<"server">>,
                        cert => ClientCert,
                        key => ClientKey
                    },
                    self()
                ),

                %% Wait for connection
                receive
                    {quic, Conn, {connected, _Info}} ->
                        %% Handshake should complete successfully
                        %% Server side would have the client cert
                        quic:close(Conn, normal)
                after 5000 ->
                    ct:fail("Connection timeout")
                end
            after
                cleanup_server_only(TmpDir, ServerName)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

%% Test server with verify=false (default), no CertificateRequest sent
server_no_verify_test() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, ServerCert, ServerKey, _ClientCert, _ClientKey} ->
            ServerName = list_to_atom(
                "noverify_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                %% Start server with verify=false (default)
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => ServerCert,
                    key => ServerKey,
                    alpn => [<<"h3">>]
                }),
                {ok, Port} = quic:get_server_port(ServerName),

                %% Connect without client cert
                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"h3">>],
                        server_name => <<"server">>
                    },
                    self()
                ),

                %% Wait for connection
                receive
                    {quic, Conn, {connected, _Info}} ->
                        %% Should connect successfully
                        quic:close(Conn, normal)
                after 5000 ->
                    ct:fail("Connection timeout")
                end
            after
                cleanup_server_only(TmpDir, ServerName)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

%% Test that peercert works on client side (gets server cert)
client_peercert_test() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, ServerCert, ServerKey, _ClientCert, _ClientKey} ->
            ServerName = list_to_atom(
                "peercert_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => ServerCert,
                    key => ServerKey,
                    alpn => [<<"h3">>]
                }),
                {ok, Port} = quic:get_server_port(ServerName),

                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"h3">>],
                        server_name => <<"server">>
                    },
                    self()
                ),

                receive
                    {quic, Conn, {connected, _Info}} ->
                        %% Client should be able to get server's cert
                        {ok, PeerCert} = quic:peercert(Conn),
                        ?assertEqual(ServerCert, PeerCert),
                        quic:close(Conn, normal)
                after 5000 ->
                    ct:fail("Connection timeout")
                end
            after
                cleanup_server_only(TmpDir, ServerName)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.

%%====================================================================
%% Test for data exchange with mutual TLS
%%====================================================================

mutual_tls_data_exchange_test() ->
    ensure_started(),
    case generate_certs() of
        {ok, TmpDir, ServerCert, ServerKey, ClientCert, ClientKey} ->
            ServerName = list_to_atom(
                "mtls_data_" ++ integer_to_list(erlang:unique_integer([positive]))
            ),
            try
                {ok, _} = quic:start_server(ServerName, 0, #{
                    cert => ServerCert,
                    key => ServerKey,
                    alpn => [<<"h3">>],
                    verify => true
                }),
                {ok, Port} = quic:get_server_port(ServerName),

                {ok, Conn} = quic:connect(
                    "127.0.0.1",
                    Port,
                    #{
                        alpn => [<<"h3">>],
                        server_name => <<"server">>,
                        cert => ClientCert,
                        key => ClientKey
                    },
                    self()
                ),

                receive
                    {quic, Conn, {connected, _Info}} ->
                        %% Open stream and send data
                        {ok, StreamId} = quic:open_stream(Conn),
                        ok = quic:send_data(Conn, StreamId, <<"hello mutual TLS">>, true),

                        %% Wait for echo or just verify stream works
                        timer:sleep(100),
                        quic:close(Conn, normal)
                after 5000 ->
                    ct:fail("Connection timeout")
                end
            after
                cleanup_server_only(TmpDir, ServerName)
            end;
        {error, cert_generation_failed} ->
            {skip, "OpenSSL not available"}
    end.
