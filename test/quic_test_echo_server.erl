%%% -*- erlang -*-
%%%
%%% In-process QUIC echo server for the e2e test suites.
%%%
%%% Mirrors the behaviour of `docker/server/quic_server.py' — accepts
%%% connections, echoes whatever arrives on any stream back to the
%%% sender on the same stream (with fin if the incoming chunk was
%%% final). Lives entirely in the local Erlang VM so the CT suites
%%% don't need `docker compose up' to be green.

-module(quic_test_echo_server).

-export([start/0, start/1, stop/1]).

-type handle() :: #{name := atom(), port := inet:port_number()}.

-export_type([handle/0]).

%% @doc Start an echo server on an ephemeral port.
-spec start() -> {ok, handle()}.
start() ->
    start(#{}).

%% @doc Start an echo server with extra QUIC server options merged
%% over the defaults.
-spec start(map()) -> {ok, handle()}.
start(Extra) when is_map(Extra) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    {ok, Cert, Key} = load_or_generate_certs(),
    Name = list_to_atom(
        "quic_echo_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    Opts = maps:merge(
        #{
            cert => Cert,
            key => Key,
            alpn => [<<"echo">>, <<"h3">>, <<"hq-interop">>],
            connection_handler => fun(ConnPid, _ConnRef) ->
                Echo = spawn_link(fun() -> echo_loop(ConnPid) end),
                ok = quic:set_owner_sync(ConnPid, Echo),
                {ok, Echo}
            end
        },
        Extra
    ),
    {ok, _Pid} = quic:start_server(Name, 0, Opts),
    {ok, Port} = quic:get_server_port(Name),
    {ok, #{name => Name, port => Port}}.

%% @doc Stop the echo server.
-spec stop(handle()) -> ok.
stop(#{name := Name}) ->
    catch quic:stop_server(Name),
    ok.

%%====================================================================
%% Internal
%%====================================================================

%% Per-connection loop. Receives stream_data events and sends the
%% same bytes back on the same stream. Connection close ends the
%% loop.
echo_loop(Conn) ->
    receive
        {quic, Conn, {connected, _Info}} ->
            echo_loop(Conn);
        {quic, Conn, {stream_data, StreamId, Data, Fin}} ->
            case quic:send_data(Conn, StreamId, Data, Fin) of
                ok -> ok;
                {error, _} -> ok
            end,
            echo_loop(Conn);
        {quic, Conn, {stream_closed, _StreamId, _Code}} ->
            echo_loop(Conn);
        {quic, Conn, {closed, _Reason}} ->
            ok;
        {quic, Conn, _Other} ->
            echo_loop(Conn);
        {'DOWN', _, process, Conn, _} ->
            ok;
        _Unexpected ->
            echo_loop(Conn)
    end.

%% Prefer the committed certs so tests match what the Python echo
%% server uses; fall back to an on-the-fly self-signed cert.
load_or_generate_certs() ->
    CertFile = filename:join([code:lib_dir(quic), "..", "..", "certs", "cert.pem"]),
    KeyFile = filename:join([code:lib_dir(quic), "..", "..", "certs", "priv.key"]),
    case filelib:is_file(CertFile) andalso filelib:is_file(KeyFile) of
        true -> read_certs(CertFile, KeyFile);
        false -> generate_self_signed()
    end.

read_certs(CertFile, KeyFile) ->
    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem} = file:read_file(KeyFile),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    {ok, CertDer, decode_key(KeyPem)}.

generate_self_signed() ->
    Tmp = filename:join("/tmp", "quic_test_echo_" ++ random_suffix()),
    ok = filelib:ensure_dir(filename:join(Tmp, "x")),
    Cert = filename:join(Tmp, "cert.pem"),
    Key = filename:join(Tmp, "key.pem"),
    Cmd = lists:flatten(
        io_lib:format(
            "openssl req -x509 -newkey rsa:2048 -keyout ~s -out ~s "
            "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
            [Key, Cert]
        )
    ),
    os:cmd(Cmd),
    {ok, CertPem} = file:read_file(Cert),
    {ok, KeyPem} = file:read_file(Key),
    [{'Certificate', CertDer, _}] = public_key:pem_decode(CertPem),
    {ok, CertDer, decode_key(KeyPem)}.

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

random_suffix() ->
    integer_to_list(erlang:unique_integer([positive, monotonic])).
