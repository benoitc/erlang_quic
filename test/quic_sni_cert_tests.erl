%%% @doc EUnit tests for per-SNI server certificate selection.
%%%
%%% A server configured with `sni_callback' picks its cert/key from the
%%% ClientHello SNI (RFC 6066 §3). These tests prove the callback receives
%%% the SNI, the returned cert is the one presented, and that a rejected
%%% host fails the handshake.
-module(quic_sni_cert_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(CONNECT_TIMEOUT, 5000).

%%====================================================================
%% Tests
%%====================================================================

%% The callback maps two hostnames to two distinct certs; each client
%% sees the cert the callback returned for its SNI.
sni_callback_selects_cert_test() ->
    with_two_certs(fun(C1, K1, C2, K2) ->
        SniCb = sni_map_callback(#{
            <<"host1.test">> => {C1, K1},
            <<"host2.test">> => {C2, K2}
        }),
        Name = start_server(#{sni_callback => SniCb}),
        try
            ?assertEqual(C1, presented_cert(Name, <<"host1.test">>)),
            ?assertEqual(C2, presented_cert(Name, <<"host2.test">>))
        after
            stop(Name)
        end
    end).

%% An SNI the callback does not recognise aborts the handshake.
sni_callback_rejects_unknown_host_test() ->
    with_two_certs(fun(C1, K1, _C2, _K2) ->
        SniCb = sni_map_callback(#{<<"host1.test">> => {C1, K1}}),
        Name = start_server(#{sni_callback => SniCb}),
        try
            ?assertMatch({error, _}, connect(Name, <<"unknown.test">>))
        after
            stop(Name)
        end
    end).

%%====================================================================
%% Helpers
%%====================================================================

%% Build a callback that looks the SNI up in Map. Asserts it is a binary
%% so the test also covers "the callback receives the SNI".
sni_map_callback(Map) ->
    fun(ServerName) ->
        case is_binary(ServerName) andalso maps:find(ServerName, Map) of
            {ok, {Cert, Key}} -> {ok, #{cert => Cert, key => Key}};
            _ -> {error, unknown_host}
        end
    end.

start_server(Opts) ->
    {ok, _} = application:ensure_all_started(quic),
    Name = list_to_atom("quic_sni_" ++ suffix()),
    {ok, _} = quic:start_server(Name, 0, Opts#{alpn => [<<"h3">>]}),
    Name.

stop(Name) ->
    try
        quic:stop_server(Name)
    catch
        _:_ -> ok
    end,
    ok.

%% Connect with the given SNI and return the server's presented leaf cert.
presented_cert(Name, ServerName) ->
    {ok, Conn} = connect(Name, ServerName),
    try
        {ok, Cert} = quic:peercert(Conn),
        Cert
    after
        close(Conn)
    end.

connect(Name, ServerName) ->
    {ok, Port} = quic:get_server_port(Name),
    case
        quic:connect(
            "127.0.0.1",
            Port,
            #{
                alpn => [<<"h3">>],
                verify => false,
                server_name => ServerName,
                connect_timeout => ?CONNECT_TIMEOUT
            },
            self()
        )
    of
        {ok, Conn} ->
            receive
                {quic, Conn, {connected, _Info}} ->
                    {ok, Conn};
                {quic, Conn, {closed, Reason}} ->
                    {error, Reason};
                {quic, Conn, {error, Reason}} ->
                    {error, Reason}
            after ?CONNECT_TIMEOUT ->
                close(Conn),
                {error, timeout}
            end;
        {error, _} = Err ->
            Err
    end.

close(Conn) ->
    try
        quic:close(Conn, normal)
    catch
        _:_ -> ok
    end.

%% Generate two self-signed certs and run F with them, or skip when
%% openssl is unavailable.
with_two_certs(F) ->
    case {gen_cert("/CN=host1.test"), gen_cert("/CN=host2.test")} of
        {{ok, C1, K1}, {ok, C2, K2}} -> F(C1, K1, C2, K2);
        _ -> {skip, "OpenSSL not available"}
    end.

%% Self-signed leaf cert for Subject. Returns the leaf DER and decoded key.
gen_cert(Subject) ->
    Dir = filename:join("/tmp", "quic_sni_test_" ++ suffix()),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    CertFile = filename:join(Dir, "cert.pem"),
    KeyFile = filename:join(Dir, "key.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
            "-days 1 -nodes -subj '~s' 2>/dev/null",
            [KeyFile, CertFile, Subject]
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
