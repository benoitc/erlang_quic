%%% -*- erlang -*-
%%%
%%% An endpoint that presents a certificate has to be able to sign with
%%% its key.
%%%
%%% Presenting a certificate means signing a CertificateVerify with its
%%% key, so a key the endpoint cannot sign with, or one that belongs to
%%% another certificate, fails every such handshake. On a server that used
%%% to surface as nothing useful: the listener started, each Initial was
%%% logged as a packet that failed to decode, and the client waited out
%%% its own timeout without an answer.
%%%
%%% A configured key is now tried when the server starts or the client
%%% connects, and a key an sni_callback hands over during a handshake
%%% fails that handshake with an alert the client sees.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
-module(quic_signing_key_tests).

-include_lib("eunit/include/eunit.hrl").

%% Under eunit's own 5 s per-test limit, so a handshake that never
%% answers fails on its assertion rather than as a timeout.
-define(CONNECT_TIMEOUT, 3000).

%% TLS internal_error (RFC 8446 §6), carried as a QUIC crypto error
%% (RFC 9001 §4.8).
-define(INTERNAL_ERROR_CLOSE, 16#150).

%%====================================================================
%% At start
%%====================================================================

%% A PEM entry is how a key is stored, not a key: it has to be decoded.
a_pem_entry_is_refused_at_start_test() ->
    with_cert("/CN=pem.test", fun(Cert, _Key, KeyPem) ->
        [Entry] = public_key:pem_decode(KeyPem),
        ?assertMatch(
            {error, {invalid_server_key, _}},
            start_server(#{cert => Cert, key => Entry})
        )
    end).

%% A working key that belongs to another certificate signs fine, and the
%% client rejects the signature. Caught here instead.
a_key_for_another_certificate_is_refused_at_start_test() ->
    with_cert("/CN=one.test", fun(Cert, _Key, _) ->
        with_cert("/CN=two.test", fun(_Other, OtherKey, _) ->
            ?assertMatch(
                {error, {invalid_server_key, _}},
                start_server(#{cert => Cert, key => OtherKey})
            )
        end)
    end).

%% The fences: the key types the server signs with still start.
an_rsa_key_starts_test() ->
    with_cert("/CN=rsa.test", fun(Cert, Key, _) ->
        {ok, Name} = start_server(#{cert => Cert, key => Key}),
        stop(Name)
    end).

an_ec_key_starts_test() ->
    with_cert("/CN=ec.test", "ec -pkeyopt ec_paramgen_curve:P-256", fun(Cert, Key, _) ->
        {ok, Name} = start_server(#{cert => Cert, key => Key}),
        stop(Name)
    end).

%% A client presents its certificate for mutual TLS the same way, so the
%% same key is refused before the connection starts.
a_client_pem_entry_is_refused_at_connect_test() ->
    with_cert("/CN=client.test", fun(Cert, _Key, KeyPem) ->
        [Entry] = public_key:pem_decode(KeyPem),
        {ok, _} = application:ensure_all_started(quic),
        ?assertMatch(
            {error, {invalid_client_key, _}},
            quic:connect("127.0.0.1", 4433, #{cert => Cert, key => Entry, verify => false}, self())
        )
    end).

%% The fence: a usable client key gets as far as starting the connection.
a_usable_client_key_connects_test() ->
    with_cert("/CN=client-ok.test", fun(Cert, Key, _) ->
        {ok, _} = application:ensure_all_started(quic),
        {ok, Conn} = quic:connect(
            "127.0.0.1", 4433, #{cert => Cert, key => Key, verify => false}, self()
        ),
        close(Conn)
    end).

%%====================================================================
%% During a handshake
%%====================================================================

%% An sni_callback supplies the key after start, where nothing checked
%% it. The handshake has to fail with an alert the client sees, rather
%% than the server dropping every Initial it cannot answer.
an_unusable_key_from_sni_fails_the_handshake_visibly_test() ->
    with_cert("/CN=sni.test", fun(Cert, _Key, KeyPem) ->
        [Entry] = public_key:pem_decode(KeyPem),
        Sni = fun(_) -> {ok, #{cert => Cert, key => Entry}} end,
        {ok, Name} = start_server(#{sni_callback => Sni}),
        try
            ?assertMatch(
                {error, {peer_closed, transport, ?INTERNAL_ERROR_CLOSE, _, _}},
                connect(Name, <<"sni.test">>)
            )
        after
            stop(Name)
        end
    end).

%% The fence: a usable key from the same callback completes.
a_usable_key_from_sni_completes_test() ->
    with_cert("/CN=sni-ok.test", fun(Cert, Key, _) ->
        Sni = fun(_) -> {ok, #{cert => Cert, key => Key}} end,
        {ok, Name} = start_server(#{sni_callback => Sni}),
        try
            {ok, Conn} = connect(Name, <<"sni-ok.test">>),
            close(Conn)
        after
            stop(Name)
        end
    end).

%%====================================================================
%% Helpers
%%====================================================================

start_server(Opts) ->
    {ok, _} = application:ensure_all_started(quic),
    Name = list_to_atom("quic_key_" ++ suffix()),
    case quic:start_server(Name, 0, Opts#{alpn => [<<"h3">>]}) of
        {ok, _} -> {ok, Name};
        {error, _} = Error -> Error
    end.

stop(Name) ->
    try
        quic:stop_server(Name)
    catch
        _:_ -> ok
    end,
    ok.

connect(Name, ServerName) ->
    {ok, Port} = quic:get_server_port(Name),
    {ok, Conn} = quic:connect(
        "127.0.0.1",
        Port,
        #{
            alpn => [<<"h3">>],
            verify => false,
            server_name => ServerName,
            connect_timeout => ?CONNECT_TIMEOUT
        },
        self()
    ),
    receive
        {quic, Conn, {connected, _Info}} -> {ok, Conn};
        {quic, Conn, {closed, Reason}} -> {error, Reason};
        {quic, Conn, {error, Reason}} -> {error, Reason}
    after ?CONNECT_TIMEOUT ->
        close(Conn),
        {error, timeout}
    end.

close(Conn) ->
    try
        quic:close(Conn, normal)
    catch
        _:_ -> ok
    end.

with_cert(Subject, F) ->
    with_cert(Subject, "rsa:2048", F).

%% A self-signed certificate for Subject: its DER, its decoded key, and
%% the key's PEM as openssl wrote it.
with_cert(Subject, KeyOpt, F) ->
    Dir = filename:join("/tmp", "quic_key_test_" ++ suffix()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile = filename:join(Dir, "key.pem"),
    NewKey =
        case KeyOpt of
            "rsa:2048" -> "-newkey rsa:2048";
            "ec " ++ Params -> "-newkey ec " ++ Params
        end,
    _ = os:cmd(
        lists:flatten(
            io_lib:format(
                "openssl req -x509 ~s -keyout ~s -out ~s -days 1 -nodes -subj '~s' 2>/dev/null",
                [NewKey, KeyFile, CertFile, Subject]
            )
        )
    ),
    try
        {ok, CertPem} = file:read_file(CertFile),
        {ok, KeyPem} = file:read_file(KeyFile),
        [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
        [KeyEntry] = public_key:pem_decode(KeyPem),
        F(CertDer, public_key:pem_entry_decode(KeyEntry), KeyPem)
    after
        os:cmd("rm -rf " ++ Dir)
    end.

suffix() ->
    integer_to_list(erlang:unique_integer([positive])).
