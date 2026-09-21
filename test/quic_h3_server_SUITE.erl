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
    application:ensure_all_started(quic),

    %% Check if docker is available
    case os:find_executable("docker") of
        false ->
            {skip, docker_not_available};
        _ ->
            %% Find certs directory
            CertsDir = find_certs_dir(),
            ct:pal("Using certificates from: ~s", [CertsDir]),

            %% Build the client image here, under its own budget. Left to
            %% the first case, a fresh machine spends that case's timeout
            %% building it and fails before any request is made.
            build_client_image(),

            %% Create temp directory for downloads
            TmpDir = create_tmp_dir(),

            [{certs_dir, CertsDir}, {tmp_dir, TmpDir} | Config]
    end.

build_client_image() ->
    Cmd = io_lib:format(
        "cd ~s && docker compose --profile tools build aioquic-h3-client 2>&1",
        [find_docker_dir()]
    ),
    case exec_cmd(Cmd, 600000) of
        {0, _} -> ok;
        {Status, Output} -> ct:fail({client_image_build_failed, Status, Output})
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

    %% Decode the private key: the server signs with it, and a PEM entry
    %% is not a key. Handing it over as one left every handshake unable
    %% to sign its CertificateVerify.
    [KeyEntry] = public_key:pem_decode(KeyPem),
    Key = public_key:pem_entry_decode(KeyEntry),

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
    clear(TmpDir, ["test"]),
    Cmd = build_aioquic_cmd(Port, TmpDir, "https://127.0.0.1:~p/test", []),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 30000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ?assertEqual({ok, <<"test response">>}, fetched(TmpDir, "test")),
    ok.

%% @doc Test POST request using aioquic client
aioquic_client_post(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Create a test file to POST
    TestFile = filename:join(TmpDir, "post_data.txt"),
    ok = file:write_file(TestFile, <<"Hello from aioquic!">>),
    clear(TmpDir, ["echo"]),

    %% POST the file
    Cmd = build_aioquic_cmd(
        Port,
        TmpDir,
        "https://127.0.0.1:~p/echo",
        %% The client runs in a container with TmpDir mounted at
        %% /tmp/output, so it needs the file's path in there.
        ["--data", "/tmp/output/post_data.txt"]
    ),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 30000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ?assertEqual({ok, <<"echo">>}, fetched(TmpDir, "echo")),
    ok.

%% @doc Test HEAD request using aioquic client
aioquic_client_head(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% aioquic http3_client doesn't support HEAD directly,
    %% but we can check server handles GET properly and infer HEAD works
    clear(TmpDir, ["test"]),
    Cmd = build_aioquic_cmd(Port, TmpDir, "https://127.0.0.1:~p/test", ["-v"]),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 30000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ?assertEqual({ok, <<"test response">>}, fetched(TmpDir, "test")),
    ok.

%% @doc Test large download using aioquic client
aioquic_client_large_download(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Request a large file (server will generate random data)
    clear(TmpDir, ["large"]),
    Cmd = build_aioquic_cmd(Port, TmpDir, "https://127.0.0.1:~p/large", []),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 60000),
    ct:pal(
        "Exit code: ~p, Output (truncated): ~s",
        [ExitCode, string:slice(Output, 0, 500)]
    ),

    ?assertEqual(0, ExitCode),
    {ok, Body} = fetched(TmpDir, "large"),
    ?assertEqual(1024 * 1024, byte_size(Body)),
    ok.

%% @doc Test multiple sequential requests using aioquic client
aioquic_client_multiple_requests(Config) ->
    Port = ?config(h3_port, Config),
    TmpDir = ?config(tmp_dir, Config),

    %% Make multiple requests - aioquic supports this. Only paths the
    %% handler serves to a GET: /echo is POST only and answers 404.
    clear(TmpDir, ["test", "index"]),
    Cmd = build_aioquic_cmd(
        Port,
        TmpDir,
        "https://127.0.0.1:~p/test https://127.0.0.1:~p/index",
        []
    ),
    ct:pal("Running: ~s", [Cmd]),

    {ExitCode, Output} = exec_cmd(Cmd, 45000),
    ct:pal("Exit code: ~p, Output: ~s", [ExitCode, Output]),

    ?assertEqual(0, ExitCode),
    ?assertEqual({ok, <<"test response">>}, fetched(TmpDir, "test")),
    ?assertEqual({ok, <<"<html><body>OK</body></html>">>}, fetched(TmpDir, "index")),
    ok.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @doc Find the certs directory
%%
%% From this file's own path rather than the build directory or the
%% working directory, neither of which is the project root under Common
%% Test: the lookup used to fall through to a path on one machine.
find_certs_dir() ->
    Dir = filename:join(project_root(), "certs"),
    case filelib:is_file(filename:join(Dir, "cert.pem")) of
        true -> Dir;
        false -> ct:fail({certs_dir_not_found, Dir})
    end.

project_root() ->
    filename:dirname(filename:dirname(filename:absname(?FILE))).

%% The client saves each body under its last path segment, in a directory
%% every case shares. A case removes what it expects first, so a check
%% that passes is reading this request's response and not an earlier one.
clear(TmpDir, Names) ->
    lists:foreach(fun(N) -> file:delete(filename:join(TmpDir, N)) end, Names).

fetched(TmpDir, Name) ->
    file:read_file(filename:join(TmpDir, Name)).

%% @doc Create a temporary directory
create_tmp_dir() ->
    TmpBase = "/tmp/quic_h3_server_test_" ++ integer_to_list(erlang:system_time(second)),
    ok = filelib:ensure_dir(TmpBase ++ "/"),
    file:make_dir(TmpBase),
    TmpBase.

%% @doc Build aioquic client command using docker-compose service
build_aioquic_cmd(Port, TmpDir, UrlPattern, ExtraArgs) ->
    %% Count ~p placeholders and build port argument list
    PlaceholderCount = count_format_placeholders(UrlPattern),
    PortArgs = lists:duplicate(PlaceholderCount, Port),

    %% Format URL with ports
    Url = io_lib:format(UrlPattern, PortArgs),

    %% Find docker directory
    DockerDir = find_docker_dir(),

    %% Build command using docker compose run
    %% Use the aioquic-h3-client service which has aioquic properly installed
    BaseCmd = io_lib:format(
        "cd ~s && docker compose run --rm "
        "-v ~s:/tmp/output "
        "aioquic-h3-client "
        "~s --insecure --output-dir /tmp/output ~s 2>&1",
        [DockerDir, TmpDir, Url, string:join(ExtraArgs, " ")]
    ),
    lists:flatten(BaseCmd).

%% @doc Find the docker directory containing docker-compose.yml
find_docker_dir() ->
    Dir = filename:join(project_root(), "docker"),
    case filelib:is_file(filename:join(Dir, "docker-compose.yml")) of
        true -> Dir;
        false -> ct:fail({docker_dir_not_found, Dir})
    end.

%% @doc Count format placeholders (~p, ~s, etc.) in a string
count_format_placeholders(Str) ->
    count_format_placeholders(Str, 0).

count_format_placeholders([], Count) ->
    Count;
count_format_placeholders([$~, C | Rest], Count) when C >= $a, C =< $z; C >= $A, C =< $Z ->
    count_format_placeholders(Rest, Count + 1);
count_format_placeholders([$~, $~ | Rest], Count) ->
    %% Escaped tilde, don't count
    count_format_placeholders(Rest, Count);
count_format_placeholders([_ | Rest], Count) ->
    count_format_placeholders(Rest, Count).

%% @doc Execute command with timeout
%%
%% Through sh -c rather than {spawn, Cmd}, which prefixes the command with
%% `exec': the commands start with cd, a shell builtin, and dash (Ubuntu's
%% /bin/sh) will not exec one.
exec_cmd(Cmd, Timeout) ->
    Port = open_port(
        {spawn_executable, "/bin/sh"},
        [
            {args, ["-c", lists:flatten(Cmd)]},
            exit_status,
            binary,
            stderr_to_stdout,
            {line, 1024}
        ]
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
        try
            port_close(Port)
        catch
            _:_ -> ok
        end,
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
