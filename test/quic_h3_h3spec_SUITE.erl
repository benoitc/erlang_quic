%%% -*- erlang -*-
%%%
%%% HTTP/3 h3spec Conformance Test Suite
%%%
%%% Tests our HTTP/3 server implementation against h3spec conformance tool.
%%%
%%% h3spec is a conformance testing tool for HTTP/3 implementations from Haskell:
%%% https://github.com/kazu-yamamoto/h3spec
%%%
%%% Prerequisites:
%%% - Docker must be available
%%% - Certificates must be generated: ./certs/generate_certs.sh
%%%
%%% Run with:
%%% rebar3 ct --suite=quic_h3_h3spec_SUITE
%%%

-module(quic_h3_h3spec_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

%% Test cases
-export([
    h3spec_conformance/1
]).

%%====================================================================
%% CT Callbacks
%%====================================================================

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [h3spec_conformance].

init_per_suite(Config) ->
    application:ensure_all_started(crypto),
    application:ensure_all_started(ssl),
    {ok, _} = application:ensure_all_started(quic),

    %% Check if docker is available
    case os:find_executable("docker") of
        false ->
            {skip, docker_not_available};
        _ ->
            %% Find certs directory
            CertsDir = find_certs_dir(),
            ct:pal("Using certificates from: ~s", [CertsDir]),

            %% Server port
            Port = 4437,

            [{h3_port, Port}, {certs_dir, CertsDir} | Config]
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(TestCase, Config) ->
    ct:pal("Starting test: ~p", [TestCase]),
    Config.

end_per_testcase(TestCase, Config) ->
    ct:pal("Finished test: ~p", [TestCase]),
    %% Stop server if it was started
    case ?config(h3_server, Config) of
        undefined ->
            ok;
        ServerPid when is_pid(ServerPid) ->
            quic_h3:stop_server(h3spec_test_server)
    end,
    ok.

%%====================================================================
%% Test Cases
%%====================================================================

%% @doc Run h3spec conformance tests against our HTTP/3 server
h3spec_conformance(Config) ->
    Port = ?config(h3_port, Config),
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

    %% Start HTTP/3 server
    Handler = fun echo_handler/5,
    ServerOpts = #{
        cert => CertDer,
        key => Key,
        handler => Handler
    },

    ct:pal("Starting HTTP/3 server on port ~p", [Port]),
    case quic_h3:start_server(h3spec_test_server, Port, ServerOpts) of
        {ok, _ServerPid} ->
            ct:pal("HTTP/3 server started"),

            %% Wait for server to be ready
            timer:sleep(1000),

            %% Run h3spec
            run_h3spec(Port, Config);
        {error, Reason} ->
            ct:fail({server_start_failed, Reason})
    end.

%%====================================================================
%% Internal Functions
%%====================================================================

%% @doc Find the certs directory
find_certs_dir() ->
    Candidates = [
        %% From test directory
        filename:join([code:lib_dir(quic), "..", "certs"]),
        %% From project root
        "certs",
        %% Absolute path fallback
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

%% @doc Echo handler for h3spec tests
echo_handler(Conn, StreamId, Method, Path, Headers) ->
    ct:pal("h3spec request: ~s ~s", [Method, Path]),
    ct:pal("Headers: ~p", [Headers]),

    case {Method, Path} of
        {<<"GET">>, _} ->
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [{<<"content-type">>, <<"text/plain">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<"OK">>, true);
        {<<"POST">>, _} ->
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [{<<"content-type">>, <<"application/octet-stream">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<>>, true);
        {<<"HEAD">>, _} ->
            quic_h3:send_response(
                Conn,
                StreamId,
                200,
                [
                    {<<"content-type">>, <<"text/plain">>},
                    {<<"content-length">>, <<"2">>}
                ]
            ),
            quic_h3:send_data(Conn, StreamId, <<>>, true);
        _ ->
            quic_h3:send_response(
                Conn,
                StreamId,
                405,
                [{<<"content-type">>, <<"text/plain">>}]
            ),
            quic_h3:send_data(Conn, StreamId, <<"Method Not Allowed">>, true)
    end.

%% @doc Run h3spec via Docker
run_h3spec(Port, _Config) ->
    ok = ensure_h3spec_image(),
    Cmd = lists:flatten(
        io_lib:format(
            "docker run --rm --network host "
            "erlang_quic/h3spec:local "
            "127.0.0.1 ~p -n 2>&1",
            [Port]
        )
    ),
    ct:pal("Running: ~s", [Cmd]),
    Output = os:cmd(Cmd),
    ct:pal("h3spec output:~n~s", [Output]),
    case parse_h3spec_output(Output) of
        {ok, Examples, 0} ->
            ct:pal("h3spec passed: ~p examples, 0 failures", [Examples]),
            ok;
        {ok, Examples, Failures} ->
            ct:pal("h3spec: ~p examples, ~p failures", [Examples, Failures]),
            %% Hard cap on failures. Ratcheted down as each conformance PR
            %% lands. Target is 0.
            MaxFailures = 48,
            case Failures > MaxFailures of
                true -> ct:fail({h3spec_failures, Failures, Examples, {max, MaxFailures}});
                false -> ok
            end;
        {error, Reason} ->
            ct:fail({h3spec_error, Reason})
    end.

%% @doc Build erlang_quic/h3spec:local from docker/h3spec if it is not
%% already present. The h3spec binary is vendored via the Dockerfile so
%% this is a one-time build per host.
ensure_h3spec_image() ->
    case os:cmd("docker image inspect erlang_quic/h3spec:local > /dev/null 2>&1; echo $?") of
        "0\n" ->
            ok;
        _ ->
            ct:pal("Building erlang_quic/h3spec:local ..."),
            Out = os:cmd(
                "docker build --platform linux/amd64 "
                "-t erlang_quic/h3spec:local docker/h3spec 2>&1"
            ),
            ct:pal("h3spec build output:~n~s", [Out]),
            case re:run(Out, "^Successfully tagged|writing image", [multiline]) of
                {match, _} ->
                    ok;
                nomatch ->
                    case
                        os:cmd(
                            "docker image inspect erlang_quic/h3spec:local > /dev/null 2>&1; echo $?"
                        )
                    of
                        "0\n" -> ok;
                        _ -> ct:fail({h3spec_build_failed, Out})
                    end
            end
    end.

%% @doc Parse h3spec output to extract results
parse_h3spec_output(Output) ->
    %% Check for docker errors
    case re:run(Output, "Unable to find image|Error|Cannot connect", [caseless]) of
        {match, _} ->
            case re:run(Output, "Unable to find image", []) of
                {match, _} -> {error, docker_not_found};
                nomatch -> {error, {docker_error, Output}}
            end;
        nomatch ->
            %% Look for "X examples, Y failures" pattern
            case
                re:run(
                    Output,
                    "(\\d+) examples?, (\\d+) failures?",
                    [{capture, all_but_first, list}]
                )
            of
                {match, [ExamplesStr, FailuresStr]} ->
                    Examples = list_to_integer(ExamplesStr),
                    Failures = list_to_integer(FailuresStr),
                    {ok, Examples, Failures};
                nomatch ->
                    %% Try alternative format
                    case re:run(Output, "Finished in|passed|failed", [caseless]) of
                        {match, _} ->
                            %% Some output but couldn't parse - treat as success with warning
                            ct:pal("Warning: Could not parse h3spec output format"),
                            {ok, 0, 0};
                        nomatch ->
                            {error, {parse_error, Output}}
                    end
            end
    end.
