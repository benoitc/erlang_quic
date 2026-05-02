%%% -*- erlang -*-
%%%
%%% E2E coverage for priv/bin/quic_call.sh against a live quic_dist target.
%%%
%%% Copyright (c) 2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_call_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([
    all/0,
    suite/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    rpc_help/1,
    rpc_node/1,
    rpc_with_args/1,
    rpc_badrpc/1,
    rpc_bad_cookie/1,
    rpc_hidden/1
]).

-define(TARGET_PORT, 14530).

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [{group, script}].

groups() ->
    [
        {script, [sequence], [
            rpc_help,
            rpc_node,
            rpc_with_args,
            rpc_badrpc,
            rpc_hidden,
            rpc_bad_cookie
        ]}
    ].

%%====================================================================
%% Suite setup
%%====================================================================

init_per_suite(Config) ->
    case locate_script() of
        {error, Reason} ->
            {skip, Reason};
        {ok, Script} ->
            case code:which(peer) of
                non_existing ->
                    {skip, peer_not_available};
                _ ->
                    case os:find_executable("bash") of
                        false ->
                            {skip, bash_not_found};
                        _ ->
                            case generate_certs(Config) of
                                {ok, CertDir} ->
                                    [{script, Script}, {cert_dir, CertDir} | Config];
                                {error, R} ->
                                    {skip, {cert_generation_failed, R}}
                            end
                    end
            end
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(script, Config) ->
    case start_target(Config) of
        {ok, Port, Node, Cookie, ProbeConfig} ->
            [
                {target_port_handle, Port},
                {target_node, Node},
                {cookie, Cookie},
                {probe_config, ProbeConfig}
                | Config
            ];
        {error, Reason} ->
            {skip, {target_start_failed, Reason}}
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(script, Config) ->
    case ?config(target_port_handle, Config) of
        undefined -> ok;
        Port -> stop_port(Port)
    end,
    ok;
end_per_group(_Group, _Config) ->
    ok.

stop_port(Port) ->
    case erlang:port_info(Port, os_pid) of
        {os_pid, OsPid} ->
            os:cmd("kill " ++ integer_to_list(OsPid)),
            timer:sleep(200),
            os:cmd("kill -9 " ++ integer_to_list(OsPid) ++ " 2>/dev/null"),
            catch erlang:port_close(Port),
            ok;
        _ ->
            catch erlang:port_close(Port),
            ok
    end.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%%====================================================================
%% Test cases
%%====================================================================

rpc_help(Config) ->
    Script = ?config(script, Config),
    {Stdout, _Stderr, Exit} = run(Script ++ " -h"),
    ?assertEqual(0, Exit),
    ?assertNotEqual(nomatch, string:find(Stdout, "Usage:")),
    ok.

rpc_node(Config) ->
    {Stdout, _Stderr, Exit} = run_call(Config, "erlang node '[]'"),
    ?assertEqual(0, Exit),
    NodeStr = atom_to_list(?config(target_node, Config)),
    ?assertNotEqual(nomatch, string:find(Stdout, NodeStr)),
    ok.

rpc_with_args(Config) ->
    {Stdout, _Stderr, Exit} = run_call(Config, "erlang '+' '[2,3]'"),
    ?assertEqual(0, Exit),
    ?assertEqual("5", string:trim(Stdout)),
    ok.

rpc_badrpc(Config) ->
    {_Stdout, Stderr, Exit} = run_call(Config, "erlang nope_function '[]'"),
    ?assertNotEqual(0, Exit),
    ?assertNotEqual(nomatch, string:find(Stderr, "badrpc")),
    ok.

rpc_bad_cookie(Config) ->
    Script = ?config(script, Config),
    Probe = ?config(probe_config, Config),
    Node = atom_to_list(?config(target_node, Config)),
    Cmd = lists:flatten(
        io_lib:format(
            "~s -c wrong_cookie_value -C ~s ~s erlang node '[]'",
            [Script, Probe, Node]
        )
    ),
    %% A wrong cookie causes the target to reject at challenge-reply time;
    %% the probe's net_kernel may take a while to give up. We just need to
    %% see a non-zero exit (or a forced kill) to confirm it didn't succeed.
    {_Stdout, _Stderr, Exit} = run(Cmd, 30000),
    ?assertNotEqual(0, Exit),
    ok.

rpc_hidden(Config) ->
    %% From the target's POV during the call, the probe must appear in
    %% nodes(hidden) but NOT in nodes().
    {Visible, _, Exit0} = run_call(Config, "erlang nodes '[]'"),
    ?assertEqual(0, Exit0),
    ?assertEqual(nomatch, string:find(Visible, "quic_call_")),

    {Hidden, _, Exit1} = run_call(Config, "erlang nodes '[hidden]'"),
    ?assertEqual(0, Exit1),
    ?assertNotEqual(nomatch, string:find(Hidden, "quic_call_")),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

locate_script() ->
    case code:priv_dir(quic) of
        {error, _} = E ->
            E;
        Priv ->
            Path = filename:join([Priv, "bin", "quic_call.sh"]),
            case filelib:is_regular(Path) of
                true -> {ok, Path};
                false -> {error, {script_missing, Path}}
            end
    end.

generate_certs(Config) ->
    PrivDir = ?config(priv_dir, Config),
    CertDir = filename:join(PrivDir, "certs"),
    ok = filelib:ensure_dir(filename:join(CertDir, "dummy")),
    Cmd = io_lib:format(
        "openssl req -x509 -newkey rsa:2048 -keyout ~s/key.pem -out ~s/cert.pem "
        "-days 1 -nodes -subj '/CN=localhost' 2>/dev/null",
        [CertDir, CertDir]
    ),
    os:cmd(lists:flatten(Cmd)),
    case
        {
            filelib:is_file(filename:join(CertDir, "cert.pem")),
            filelib:is_file(filename:join(CertDir, "key.pem"))
        }
    of
        {true, true} -> {ok, CertDir};
        _ -> {error, openssl_failed}
    end.

start_target(Config) ->
    CertDir = ?config(cert_dir, Config),
    PrivDir = ?config(priv_dir, Config),
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "key.pem"),
    Cookie = "quiccall_" ++ integer_to_list(erlang:unique_integer([positive])),
    Suffix = integer_to_list(erlang:unique_integer([positive])),
    Host = "127.0.0.1",
    Node = list_to_atom("quic_call_target_" ++ Suffix ++ "@" ++ Host),
    ReadyFile = filename:join(PrivDir, "target.ready"),

    EbinDir =
        case code:lib_dir(quic) of
            {error, _} ->
                filename:absname(filename:dirname(code:which(quic_dist)));
            LibDir ->
                filename:join(LibDir, "ebin")
        end,

    Eval = lists:flatten(
        io_lib:format(
            "{ok,_}=application:ensure_all_started(quic),"
            "Nodes=[{'~s',{\"~s\",~b}}],"
            "application:set_env(quic,dist,"
            "[{cert_file,\"~s\"},{key_file,\"~s\"},{verify,verify_none},"
            "{discovery_module,quic_discovery_static},{nodes,Nodes}]),"
            "{ok,_}=quic_discovery_static:init([{nodes,Nodes}]),"
            "ok=file:write_file(\"~s\",<<\"ok\">>),"
            "receive _ -> ok end.",
            [atom_to_list(Node), Host, ?TARGET_PORT, CertFile, KeyFile, ReadyFile]
        )
    ),
    Args = [
        "-name",
        atom_to_list(Node),
        "-setcookie",
        Cookie,
        "-proto_dist",
        "quic",
        "-epmd_module",
        "quic_epmd",
        "-start_epmd",
        "false",
        "-quic_dist_port",
        integer_to_list(?TARGET_PORT),
        "-quic_dist_cert",
        CertFile,
        "-quic_dist_key",
        KeyFile,
        "-quic_dist_verify",
        "verify_none",
        "-pa",
        EbinDir,
        "-noinput",
        "-eval",
        Eval
    ],
    ErlExe = os:find_executable("erl"),
    Port = erlang:open_port({spawn_executable, ErlExe}, [
        {args, Args},
        binary,
        exit_status,
        stderr_to_stdout
    ]),

    case wait_for_ready(ReadyFile, 60) of
        ok ->
            ProbeConfig = write_dist_config(
                filename:join(PrivDir, "probe.config"),
                CertDir,
                [{Node, {Host, ?TARGET_PORT}}]
            ),
            {ok, Port, Node, Cookie, ProbeConfig};
        timeout ->
            Log = drain_port(Port, []),
            stop_port(Port),
            ct:log("target failed to become ready. output:~n~s", [Log]),
            {error, target_not_ready}
    end.

drain_port(Port, Acc) ->
    receive
        {Port, {data, Bin}} -> drain_port(Port, [Bin | Acc])
    after 100 ->
        lists:reverse(Acc)
    end.

wait_for_ready(_File, 0) ->
    timeout;
wait_for_ready(File, N) ->
    case filelib:is_regular(File) of
        true ->
            ok;
        false ->
            timer:sleep(500),
            wait_for_ready(File, N - 1)
    end.

write_dist_config(Path, CertDir, Nodes) ->
    NodesIO = [
        io_lib:format("{'~s', {\"~s\", ~b}}", [atom_to_list(N), Host, Port])
     || {N, {Host, Port}} <- Nodes
    ],
    NodesStr = lists:join(", ", NodesIO),
    Body = io_lib:format(
        "[{quic, [{dist, [{cert_file, \"~s\"},"
        " {key_file, \"~s\"},"
        " {verify, verify_none},"
        " {discovery_module, quic_discovery_static},"
        " {nodes, [~s]}]}]}].~n",
        [
            filename:join(CertDir, "cert.pem"),
            filename:join(CertDir, "key.pem"),
            NodesStr
        ]
    ),
    ok = file:write_file(Path, iolist_to_binary(Body)),
    Path.

run_call(Config, MFAStr) ->
    Script = ?config(script, Config),
    Probe = ?config(probe_config, Config),
    Cookie = ?config(cookie, Config),
    Node = atom_to_list(?config(target_node, Config)),
    Cmd = lists:flatten(
        io_lib:format(
            "~s -c ~s -C ~s ~s ~s",
            [Script, Cookie, Probe, Node, MFAStr]
        )
    ),
    run(Cmd).

run(Cmd) ->
    run(Cmd, 20000).

run(Cmd, TimeoutMs) ->
    StderrFile =
        "/tmp/quic_call_stderr_" ++ integer_to_list(erlang:unique_integer([positive])),
    Bash = os:find_executable("bash"),
    Wrapped = lists:flatten(io_lib:format("exec ~s 2>~s", [Cmd, StderrFile])),
    Port = erlang:open_port(
        {spawn_executable, Bash},
        [{args, ["-c", Wrapped]}, exit_status, binary, stream]
    ),
    {Stdout, Exit} = collect(Port, [], TimeoutMs),
    Stderr =
        case file:read_file(StderrFile) of
            {ok, Bin} -> binary_to_list(Bin);
            _ -> ""
        end,
    file:delete(StderrFile),
    ct:log("cmd: ~s~nstdout:~n~s~nstderr:~n~s~nexit: ~p", [Cmd, Stdout, Stderr, Exit]),
    {Stdout, Stderr, Exit}.

collect(Port, Acc, TimeoutMs) ->
    receive
        {Port, {data, Bin}} ->
            collect(Port, [Bin | Acc], TimeoutMs);
        {Port, {exit_status, Status}} ->
            {binary_to_list(iolist_to_binary(lists:reverse(Acc))), Status}
    after TimeoutMs ->
        case erlang:port_info(Port, os_pid) of
            {os_pid, OsPid} ->
                os:cmd("kill -9 " ++ integer_to_list(OsPid));
            _ ->
                ok
        end,
        catch erlang:port_close(Port),
        {binary_to_list(iolist_to_binary(lists:reverse(Acc))), 124}
    end.
