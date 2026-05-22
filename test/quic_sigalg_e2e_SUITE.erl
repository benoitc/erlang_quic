%%% -*- erlang -*-
%%%
%%% Signature-algorithm negotiation end-to-end suite
%%% (RFC 8446 §4.2.3 / §4.4.3).
%%%
%%% One single-cert listener per key type (matches the current
%%% single-cert server API). Each test connects with a client
%%% signature_algs list compatible with that key and asserts the
%%% negotiated CertificateVerify scheme.

-module(quic_sigalg_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1
]).

-export([
    rsa_listener/1,
    ecdsa_p256_listener/1,
    ecdsa_p384_listener/1,
    ed25519_listener/1,
    incompatible_sig_alg_fails/1
]).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [
        rsa_listener,
        ecdsa_p256_listener,
        ecdsa_p384_listener,
        ed25519_listener,
        incompatible_sig_alg_fails
    ].

init_per_suite(Config) ->
    case os:find_executable("openssl") of
        false ->
            {skip, openssl_not_found};
        _ ->
            {ok, _} = application:ensure_all_started(crypto),
            {ok, _} = application:ensure_all_started(quic),
            Config
    end.

end_per_suite(_Config) ->
    ok.

%%====================================================================
%% Tests: each listener has a single cert of one key type
%%====================================================================

rsa_listener(Config) ->
    negotiates(Config, rsa, [rsa_pss_rsae_sha256], rsa_pss_rsae_sha256).

ecdsa_p256_listener(Config) ->
    negotiates(Config, p256, [ecdsa_secp256r1_sha256], ecdsa_secp256r1_sha256).

ecdsa_p384_listener(Config) ->
    negotiates(
        Config, p384, [ecdsa_secp384r1_sha384], ecdsa_secp384r1_sha384
    ).

ed25519_listener(Config) ->
    negotiates(Config, ed25519, [ed25519], ed25519).

%% RSA listener, client offers only ed25519 → no common scheme →
%% handshake fails.
incompatible_sig_alg_fails(Config) ->
    {Cert, Key} = cert_of(Config, rsa),
    {ok, Server} = quic_test_echo_server:start(#{cert => Cert, key => Key}),
    try
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            signature_algs => [ed25519]
        },
        ?assertMatch({error, _}, try_connect(Server, Opts))
    after
        quic_test_echo_server:stop(Server)
    end.

%%====================================================================
%% Helpers
%%====================================================================

negotiates(Config, KeyType, ClientSigAlgs, ExpectedScheme) ->
    {Cert, Key} = cert_of(Config, KeyType),
    {ok, Server} = quic_test_echo_server:start(#{cert => Cert, key => Key}),
    try
        Opts = #{
            verify => false,
            alpn => [<<"echo">>],
            signature_algs => ClientSigAlgs
        },
        {ok, ConnRef} = quic:connect(<<"127.0.0.1">>, port(Server), Opts, self()),
        Info = wait_connected(ConnRef),
        ?assertEqual(ExpectedScheme, maps:get(negotiated_scheme, Info)),
        ok = echo(ConnRef, <<"sig ok">>),
        quic:close(ConnRef, normal)
    after
        quic_test_echo_server:stop(Server)
    end.

port(#{port := Port}) -> Port.

wait_connected(ConnRef) ->
    receive
        {quic, ConnRef, {connected, Info}} -> Info
    after 10000 ->
        catch quic:close(ConnRef, timeout),
        ct:fail("connection timeout")
    end.

try_connect(#{port := Port}, Opts) ->
    case quic:connect(<<"127.0.0.1">>, Port, Opts, self()) of
        {error, _} = E ->
            E;
        {ok, ConnRef} ->
            receive
                {quic, ConnRef, {connected, _}} ->
                    quic:close(ConnRef, normal),
                    ok;
                {quic, ConnRef, {error, R}} ->
                    {error, R};
                {quic, ConnRef, {closed, R}} ->
                    {error, R}
            after 10000 ->
                catch quic:close(ConnRef, timeout),
                {error, timeout}
            end
    end.

echo(ConnRef, Payload) ->
    {ok, StreamId} = quic:open_stream(ConnRef),
    ok = quic:send_data(ConnRef, StreamId, Payload, true),
    receive
        {quic, ConnRef, {stream_data, StreamId, Got, true}} ->
            ?assertEqual(Payload, Got),
            ok
    after 10000 ->
        ct:fail("echo timeout")
    end.

%% Generate (once per type) a self-signed cert + key and return
%% {CertDER, KeyTerm}. KeyTerm is the pem_entry_decode form expected
%% by quic_tls:convert_private_key/2.
cert_of(Config, Type) ->
    Dir = ?config(priv_dir, Config),
    CertFile = filename:join(Dir, atom_to_list(Type) ++ "_cert.pem"),
    KeyFile = filename:join(Dir, atom_to_list(Type) ++ "_key.pem"),
    case filelib:is_file(CertFile) of
        true -> ok;
        false -> ok = gen_cert(Type, CertFile, KeyFile)
    end,
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem} = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    [KeyEntry] = public_key:pem_decode(KeyPem),
    {CertDer, public_key:pem_entry_decode(KeyEntry)}.

gen_cert(Type, CertFile, KeyFile) ->
    Newkey =
        case Type of
            rsa -> "rsa:2048";
            p256 -> "ec -pkeyopt ec_paramgen_curve:prime256v1";
            p384 -> "ec -pkeyopt ec_paramgen_curve:secp384r1";
            ed25519 -> "ed25519"
        end,
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey ~s -keyout ~s -out ~s "
            "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
            [Newkey, KeyFile, CertFile]
        )
    ),
    os:cmd(Cmd),
    case filelib:is_file(CertFile) andalso filelib:is_file(KeyFile) of
        true -> ok;
        false -> {error, openssl_failed}
    end.
