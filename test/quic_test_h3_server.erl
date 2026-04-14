%%% -*- erlang -*-
%%%
%%% In-process HTTP/3 server for the H3 e2e test suite.
%%%
%%% Serves the handful of paths the suite exercises (`/test.txt',
%%% `/', `/large.bin', POST `/echo'). The echo path collects the
%%% request body via `quic_h3:set_stream_handler/3' from a worker
%%% process, then mirrors it back.

-module(quic_test_h3_server).

-export([start/0, start/1, stop/1]).

-type handle() :: #{name := atom(), port := inet:port_number()}.

-export_type([handle/0]).

-spec start() -> {ok, handle()}.
start() ->
    start(#{}).

-spec start(map()) -> {ok, handle()}.
start(Extra) when is_map(Extra) ->
    {ok, _} = application:ensure_all_started(crypto),
    {ok, _} = application:ensure_all_started(quic),
    {ok, Cert, Key} = load_or_generate_certs(),
    Name = list_to_atom(
        "quic_h3_test_" ++
            integer_to_list(erlang:unique_integer([positive, monotonic]))
    ),
    Opts = maps:merge(
        #{
            cert => Cert,
            key => Key,
            quic_opts => #{
                max_data => 16 * 1024 * 1024,
                max_stream_data_bidi_local => 4 * 1024 * 1024,
                max_stream_data_bidi_remote => 4 * 1024 * 1024,
                max_stream_data_uni => 4 * 1024 * 1024
            },
            handler => fun handle/5
        },
        Extra
    ),
    {ok, _Pid} = quic_h3:start_server(Name, 0, Opts),
    {ok, Port} = quic:get_server_port(Name),
    {ok, #{name => Name, port => Port}}.

-spec stop(handle()) -> ok.
stop(#{name := Name}) ->
    catch quic_h3:stop_server(Name),
    ok.

%%====================================================================
%% Request handler
%%====================================================================

handle(Conn, StreamId, <<"GET">>, <<"/test.txt">>, _Headers) ->
    Body = <<"test content\n">>,
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"text/plain">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))}
    ]),
    quic_h3:send_data(Conn, StreamId, Body, true);
handle(Conn, StreamId, <<"HEAD">>, <<"/test.txt">>, _Headers) ->
    %% No content-length on HEAD: the receiver validates inbound
    %% DATA against it and we send zero body bytes, which would
    %% trip the mismatch check.
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"text/plain">>}
    ]),
    quic_h3:send_data(Conn, StreamId, <<>>, true);
handle(Conn, StreamId, <<"GET">>, <<"/">>, _Headers) ->
    Body = <<"<html><body>OK</body></html>\n">>,
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"text/html">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))}
    ]),
    quic_h3:send_data(Conn, StreamId, Body, true);
handle(Conn, StreamId, <<"GET">>, <<"/large.bin">>, _Headers) ->
    Body = crypto:strong_rand_bytes(1024 * 1024),
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"application/octet-stream">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))}
    ]),
    quic_h3:send_data(Conn, StreamId, Body, true);
handle(Conn, StreamId, <<"POST">>, <<"/echo">>, _Headers) ->
    %% Collect the request body in a worker so this dispatch fun
    %% returns quickly.
    Parent = self(),
    spawn(fun() -> echo_worker(Conn, StreamId, Parent) end),
    ok;
handle(Conn, StreamId, _Method, _Path, _Headers) ->
    quic_h3:send_response(Conn, StreamId, 404, [
        {<<"content-type">>, <<"text/plain">>}
    ]),
    quic_h3:send_data(Conn, StreamId, <<"Not Found">>, true).

echo_worker(Conn, StreamId, _Parent) ->
    Body =
        case quic_h3:set_stream_handler(Conn, StreamId, self()) of
            ok ->
                receive_body(Conn, StreamId, <<>>);
            {ok, Buffered} ->
                Init = lists:foldl(
                    fun({Chunk, _Fin}, Acc) -> <<Acc/binary, Chunk/binary>> end,
                    <<>>,
                    Buffered
                ),
                case lists:any(fun({_, Fin}) -> Fin end, Buffered) of
                    true -> Init;
                    false -> receive_body(Conn, StreamId, Init)
                end
        end,
    quic_h3:send_response(Conn, StreamId, 200, [
        {<<"content-type">>, <<"application/octet-stream">>},
        {<<"content-length">>, integer_to_binary(byte_size(Body))}
    ]),
    quic_h3:send_data(Conn, StreamId, Body, true).

receive_body(Conn, StreamId, Acc) ->
    receive
        {quic_h3, Conn, {data, StreamId, Data, true}} ->
            <<Acc/binary, Data/binary>>;
        {quic_h3, Conn, {data, StreamId, Data, false}} ->
            receive_body(Conn, StreamId, <<Acc/binary, Data/binary>>);
        {quic_h3, Conn, {stream_end, StreamId}} ->
            Acc
    after 30000 ->
        Acc
    end.

%%====================================================================
%% Cert loading (same pattern as quic_test_echo_server)
%%====================================================================

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
    Tmp = filename:join("/tmp", "quic_test_h3_" ++ random_suffix()),
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
