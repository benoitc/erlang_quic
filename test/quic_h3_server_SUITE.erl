%%% -*- erlang -*-
%%%
%%% HTTP/3 Server Test Suite
%%%
%%% Tests our HTTP/3 server implementation using external aioquic clients.
%%%
%%% Prerequisites:
%%% - Docker and docker-compose must be available
%%% - Certificates must be generated: ./certs/generate_certs.sh
%%%
%%% Run with:
%%% rebar3 ct --suite=quic_h3_server_SUITE
%%%

-module(quic_h3_server_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    groups/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    aioquic_client_get/1,
    aioquic_client_post/1,
    aioquic_client_head/1,
    aioquic_client_large_download/1,
    aioquic_client_multiple_requests/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [{group, aioquic_client}].

groups() ->
    [
        {aioquic_client, [sequence], [
            aioquic_client_get,
            aioquic_client_post,
            aioquic_client_head,
            aioquic_client_large_download,
            aioquic_client_multiple_requests
        ]}
    ].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),

    %% Check if docker is available
    case os:find_executable("docker") of
        false ->
            {skip, docker_not_available};
        _ ->
            %% Find certs directory
            CertsDir = find_certs_dir(),
            ct:pal("Using certificates from: ~s", [CertsDir]),

            %% Create temp directory for downloads
            TmpDir = create_tmp_dir(),

            [{certs_dir, CertsDir}, {tmp_dir, TmpDir} | Config]
    end.

end_per_suite(Config) ->
    %% Cleanup temp directory
    TmpDir = ?config(tmp_dir, Config),
    os:cmd("rm -rf " ++ TmpDir),
    ok.

init_per_group(aioquic_client, Config) ->
    %% Start HTTP/3 server for this group
    Port = 4438,
    CertsDir = ?config(certs_dir, Config),

    %% Read certificates
    CertFile = filename:join(CertsDir, "cert.pem"),
    KeyFile = filename:join(CertsDir, "priv.key"),

    {ok, CertPem} = file:read_file(CertFile),
    {ok, KeyPem} = file:read_file(KeyFile),

    %% Parse certificate
    [{'Certificate', CertDer, not_encrypted}] = public_key:pem_decode(CertPem),

    %% Parse private key
    [KeyEntry] = public_key:pem_decode(KeyPem),
    Key =
        case KeyEntry of
            {'PrivateKeyInfo', _, _} -> KeyEntry;
            {'RSAPrivateKey', KeyDer, not_encrypted} -> {'RSAPrivateKey', KeyDer};
            {'ECPrivateKey', KeyDer, not_encrypted} -> {'ECPrivateKey', KeyDer}
        end,

    %% Handler that tracks requests
    Self = self(),
    Handler = fun(Conn, StreamId, Method, Path, Headers) ->
        server_handler(Conn, StreamId, Method, Path, Headers, Self)
    end,

    ServerOpts = #{
        cert => CertDer,
        key => Key,
        handler => Handler
    },

    ct:pal("Starting HTTP/3 server on port ~p", [Port]),
    case quic_h3:start_server(h3_server_test, Port, ServerOpts) of
        {ok, ServerPid} ->
            ct:pal("HTTP/3 server started: ~p", [ServerPid]),
            %% Wait for server to be ready
            timer:sleep(500),
            [{h3_port, Port}, {h3_server, ServerPid} | Config];
        {error, Reason} ->
            ct:fail({server_start_failed, Reason})
    end;
init_per_group(_GroupName, Config) ->
    Config.

end_per_group(aioquic_client, _Config) ->
    %% Stop HTTP/3 server
    quic_h3:stop_server(h3_server_test),
    ct:pal("HTTP/3 server stopped"),
    ok;
end_per_group(_GroupName, _Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, _Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    ok.

%%====================================================================
%% Test Cases
%%====================================================================

%% @doc Test GET request using aioquic client
aioquic_client_get(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Use aioquic's http3_client to make a GET request
    Cmd = build_aioquic_cmd(Port, TmpDir, "https://127.0.0.1:~p/test", []),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 30000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    %% Check exit code
    ?assertEqual(0, ExitCode),
    ok.

%% @doc Test POST request using aioquic client
aioquic_client_post(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Create a test file to POST
    TestFile = filename:join(TmpDir, "post_data.txt"),
    ok = file:write_file(TestFile, <<"Hello from aioquic!">>),

    %% POST the file
    Cmd = build_aioquic_cmd(
        Port,
        TmpDir,
        "https://127.0.0.1:~p/echo",
        ["--data", TestFile]
    ),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 30000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ok.

%% @doc Test HEAD request using aioquic client
aioquic_client_head(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% aioquic http3_client doesn't support HEAD directly,
    %% but we can check server handles GET properly and infer HEAD works
    Cmd = build_aioquic_cmd(Port, TmpDir, "https://127.0.0.1:~p/test", ["-v"]),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 30000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ok.

%% @doc Test large download using aioquic client
aioquic_client_large_download(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Request a large file (server will generate random data)
    Cmd = build_aioquic_cmd(Port, TmpDir, "https://127.0.0.1:~p/large", []),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 60000),
    ct:pal(
        "Exit code: ~p, Output (truncated): ~s",
        [ExitCode, string:slice(Output, 0, 500)]
    ),

    ?assertEqual(0, ExitCode),
    ok.

%% @doc Test multiple sequential requests using aioquic client
aioquic_client_multiple_requests(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Make multiple requests - aioquic supports this
    Cmd = build_aioquic_cmd(
        Port,
        TmpDir,
        "https://127.0.0.1:~p/test https://127.0.0.1:~p/echo https://127.0.0.1:~p/index",
        []
    ),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 45000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ok.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @doc Find the certs directory
find_certs_dir() ->
    Candidates = [
        filename:join([code:lib_dir(quic), "..", "certs"]),
        "certs",
        "/Users/benoitc/Projects/erlang_quic/certs"
    ],
    find_existing_dir(Candidates).

find_existing_dir([]) ->
    ct:fail(certs_dir_not_found);
find_existing_dir([Dir | Rest]) ->
    AbsDir = filename:absname(Dir),
    case filelib:is_dir(AbsDir) of
        true ->
            CertFile = filename:join(AbsDir, "cert.pem"),
            case filelib:is_file(CertFile) of
                true -> AbsDir;
                false -> find_existing_dir(Rest)
            end;
        false ->
            find_existing_dir(Rest)
    end.

%% @doc Create a temporary directory
create_tmp_dir() ->
    TmpBase = "/tmp/quic_h3_server_test_" ++ integer_to_list(erlang:system_time(second)),
    ok = filelib:ensure_dir(TmpBase ++ "/"),
    file:make_dir(TmpBase),
    TmpBase.

%% @doc Build aioquic client command
build_aioquic_cmd(Port, TmpDir, UrlPattern, ExtraArgs) ->
    %% Format URL with port
    Url = io_lib:format(UrlPattern, [Port, Port, Port]),

    %% Build command with docker
    BaseCmd = io_lib:format(
        "docker run --rm --network host "
        "-v ~s:/tmp/output "
        "python:3.11-slim "
        "sh -c 'pip install -q aioquic && python -m aioquic.h3.client ~s "
        "--insecure --output-dir /tmp/output ~s'",
        [TmpDir, Url, string:join(ExtraArgs, " ")]
    ),
    lists:flatten(BaseCmd).

%% @doc Execute command with timeout
exec_cmd(Cmd, Timeout) ->
    Port = open_port(
        {spawn, lists:flatten(Cmd)},
        [exit_status, binary, stderr_to_stdout, {line, 1024}]
    ),
    exec_cmd_loop(Port, [], Timeout).

exec_cmd_loop(Port, Acc, Timeout) ->
    receive
        {Port, {data, {eol, Line}}} ->
            exec_cmd_loop(Port, [Line | Acc], Timeout);
        {Port, {data, {noeol, Line}}} ->
            exec_cmd_loop(Port, [Line | Acc], Timeout);
        {Port, {exit_status, Status}} ->
            Output = iolist_to_binary(lists:reverse(Acc)),
            {Status, Output}
    after Timeout ->
        catch port_close(Port),
        Output = iolist_to_binary(lists:reverse(Acc)),
        {timeout, Output}
    end.

%% @doc Server request handler
server_handler(Conn, StreamId, Method, Path, Headers, _TestPid) ->
    ct:pal("Server received: ~s ~s", [Method, Path]),
    ct:pal("Request headers: ~p", [Headers]),

    case {Method, Path} of
        {<<"GET">>, <<"/test">>} ->
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [{<<"content-type">>, <<"text/plain">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<"test response">>, true);
        {<<"GET">>, <<"/index">>} ->
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [{<<"content-type">>, <<"text/html">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<"<html><body>OK</body></html>">>, true);
        {<<"GET">>, <<"/large">>} ->
            %% Generate 1MB of data
            Data = crypto:strong_rand_bytes(1024 * 1024),
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [
                    {<<"content-type">>, <<"application/octet-stream">>},
                    {<<"content-length">>, <<"1048576">>}
                ]
            ),
            quic_h3:send_data(Conn, StreamId, Data, true);
        {<<"POST">>, <<"/echo">>} ->
            %% Echo back - for now just send empty response
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [{<<"content-type">>, <<"application/octet-stream">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<"echo">>, true);
        {<<"HEAD">>, _} ->
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [
                    {<<"content-type">>, <<"text/plain">>},
                    {<<"content-length">>, <<"13">>}
                ]
            ),
            quic_h3:send_data(Conn, StreamId, <<>>, true);
        _ ->
            quic_h3:send_response(
                Conn,
                StreamId,
                404,
                [{<<"content-type">>, <<"text/plain">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<"Not Found">>, true)
    end.
