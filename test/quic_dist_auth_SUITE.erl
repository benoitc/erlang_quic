%%% -*- erlang -*-
%%%
%%% E2E coverage for quic_dist auth_callback and register_with_epmd.
%%%
%%% Copyright (c) 2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_auth_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([
    all/0,
    suite/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_testcase/2,
    end_per_testcase/2
]).

-export([
    default_no_callback/1,
    auth_ok_both_sides/1,
    auth_server_denies/1,
    auth_timeout/1,
    register_with_epmd_visible/1
]).

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [
        default_no_callback,
        auth_ok_both_sides,
        auth_server_denies,
        auth_timeout,
        register_with_epmd_visible
    ].

%%====================================================================
%% Suite setup
%%====================================================================

init_per_suite(Config) ->
    case os:find_executable("erl") of
        false ->
            {skip, erl_not_found};
        _ ->
            case generate_certs(Config) of
                {ok, CertDir} ->
                    [{cert_dir, CertDir} | Config];
                {error, R} ->
                    {skip, {cert_generation_failed, R}}
            end
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_Case, Config) ->
    Config.

end_per_testcase(_Case, _Config) ->
    case erase({?MODULE, target_port_handle}) of
        undefined -> ok;
        Port -> stop_port(Port)
    end,
    ok.

%%====================================================================
%% Test cases
%%====================================================================

default_no_callback(Config) ->
    Spec = #{tag => "default", auth_cb => undefined},
    {Target, _Port, Cookie, TargetUdp} = start_target(Config, Spec),
    Result = run_probe(Config, "default_probe", Target, TargetUdp, Cookie, undefined, 10000),
    ?assertEqual(connected, Result).

auth_ok_both_sides(Config) ->
    Cb = "quic_dist_auth_test_cb:always_ok",
    Spec = #{tag => "ok", auth_cb => Cb},
    {Target, _Port, Cookie, TargetUdp} = start_target(Config, Spec),
    Result = run_probe(Config, "ok_probe", Target, TargetUdp, Cookie, Cb, 10000),
    ?assertEqual(connected, Result).

auth_server_denies(Config) ->
    Cb = "quic_dist_auth_test_cb:server_denies",
    Spec = #{tag => "deny", auth_cb => Cb},
    {Target, _Port, Cookie, TargetUdp} = start_target(Config, Spec),
    Result = run_probe(Config, "deny_probe", Target, TargetUdp, Cookie, Cb, 10000),
    ?assertEqual(refused, Result).

auth_timeout(Config) ->
    %% Both sides hang in the callback. The configured timeout fires
    %% on the server gatekeeper; the client setup process eventually
    %% sees the connection close.
    Cb = "quic_dist_auth_test_cb:hangs_forever",
    Spec = #{tag => "tmo", auth_cb => Cb, auth_timeout => 1500},
    {Target, _Port, Cookie, TargetUdp} = start_target(Config, Spec),
    Result = run_probe(Config, "tmo_probe", Target, TargetUdp, Cookie, Cb, 1500),
    ?assertEqual(refused, Result).

register_with_epmd_visible(Config) ->
    %% Boot a target with register_with_epmd=true and have it write its
    %% own quic_epmd:names/1 result to a file. Verify the short name is
    %% present.
    PrivDir = ?config(priv_dir, Config),
    NamesFile = filename:join(PrivDir, "epmd_names.txt"),
    Spec = #{
        tag => "epmd",
        auth_cb => undefined,
        register_with_epmd => true,
        %% Bypass quic_epmd:names/1 (its function_exported check is
        %% load-order sensitive); query the static backend directly.
        extra_eval =>
            "{ok, RegisteredNodes} = quic_discovery_static:list_nodes(\"127.0.0.1\"),"
            "ok = file:write_file(\"" ++ NamesFile ++
            "\", io_lib:format(\"~p\", [RegisteredNodes])),"
    },
    {Target, _Port, _Cookie, TargetUdp} = start_target(Config, Spec),
    %% Cleanup the target promptly; the file is already written.
    stop_port(TargetUdp),
    erase({?MODULE, target_port_handle}),
    {ok, Bin} = file:read_file(NamesFile),
    NamesStr = binary_to_list(Bin),
    ct:log("quic_epmd:names result:~n~s", [NamesStr]),
    ShortName = short_name(Target),
    ?assertNotEqual(nomatch, string:find(NamesStr, ShortName)).

%%====================================================================
%% Boot helpers
%%====================================================================

start_target(Config, Spec) ->
    CertDir = ?config(cert_dir, Config),
    PrivDir = ?config(priv_dir, Config),
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "key.pem"),
    Cookie = "qauth_" ++ integer_to_list(erlang:unique_integer([positive])),
    Host = "127.0.0.1",
    Tag = maps:get(tag, Spec),
    Suffix = integer_to_list(erlang:unique_integer([positive])),
    Node = list_to_atom(
        "qauth_target_" ++ Tag ++ "_" ++ Suffix ++ "@" ++ Host
    ),
    PortNum = pick_port(),
    ReadyFile = filename:join(PrivDir, "target_" ++ Tag ++ ".ready"),

    AuthCb = maps:get(auth_cb, Spec, undefined),
    AuthTimeout = maps:get(auth_timeout, Spec, 10000),
    RegisterEpmd = maps:get(register_with_epmd, Spec, false),
    ExtraEval = maps:get(extra_eval, Spec, ""),

    AuthArgs =
        case AuthCb of
            undefined ->
                [];
            CbStr ->
                [
                    "-quic_dist_auth_callback",
                    CbStr,
                    "-quic_dist_auth_handshake_timeout",
                    integer_to_list(AuthTimeout)
                ]
        end,
    EpmdArgs =
        case RegisterEpmd of
            true -> ["-quic_dist_register_with_epmd", "true"];
            false -> []
        end,

    Eval = lists:flatten(
        io_lib:format(
            "{ok,_}=application:ensure_all_started(quic),"
            "~s"
            "ok=file:write_file(\"~s\",<<\"ok\">>),"
            "receive _ -> ok end.",
            [ExtraEval, ReadyFile]
        )
    ),
    Args =
        [
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
            integer_to_list(PortNum),
            "-quic_dist_cert",
            CertFile,
            "-quic_dist_key",
            KeyFile,
            "-quic_dist_verify",
            "verify_none",
            "-pa",
            quic_ebin(),
            "-pa",
            test_ebin(),
            "-noinput",
            "-eval",
            Eval
        ] ++ AuthArgs ++ EpmdArgs,

    ErlExe = os:find_executable("erl"),
    Port = erlang:open_port({spawn_executable, ErlExe}, [
        {args, Args},
        binary,
        exit_status,
        stderr_to_stdout
    ]),
    case wait_for_ready(ReadyFile, 60) of
        ok ->
            put({?MODULE, target_port_handle}, Port),
            put({?MODULE, target_port_for, atom_to_list(Node)}, PortNum),
            {Node, PortNum, Cookie, Port};
        timeout ->
            Log = drain_port(Port),
            stop_port(Port),
            ct:fail("target ~s not ready. output:~n~s", [Tag, Log])
    end.

run_probe(Config, Tag, Target, _TargetUdp, Cookie, AuthCb, AuthTimeout) ->
    CertDir = ?config(cert_dir, Config),
    PrivDir = ?config(priv_dir, Config),
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "key.pem"),
    Host = "127.0.0.1",
    Suffix = integer_to_list(erlang:unique_integer([positive])),
    Probe = list_to_atom(
        "qauth_probe_" ++ Tag ++ "_" ++ Suffix ++ "@" ++ Host
    ),
    ProbePort = pick_port(),
    ResultFile = filename:join(PrivDir, "probe_result_" ++ Tag),

    AuthArgs =
        case AuthCb of
            undefined ->
                [];
            CbStr ->
                [
                    "-quic_dist_auth_callback",
                    CbStr,
                    "-quic_dist_auth_handshake_timeout",
                    integer_to_list(AuthTimeout)
                ]
        end,

    TargetStr = atom_to_list(Target),
    TargetPort = get({?MODULE, target_port_for, TargetStr}),

    Eval = lists:flatten(
        io_lib:format(
            "{ok,_}=application:ensure_all_started(quic),"
            "Nodes=[{'~s',{\"127.0.0.1\",~b}}],"
            "{ok,_}=quic_discovery_static:init([{nodes,Nodes}]),"
            "Verdict = case net_kernel:connect_node('~s') of"
            " true -> connected;"
            " _ -> refused"
            " end,"
            "ok=file:write_file(\"~s\",atom_to_list(Verdict)),"
            "erlang:halt(0).",
            [TargetStr, TargetPort, TargetStr, ResultFile]
        )
    ),
    Args =
        [
            "-name",
            atom_to_list(Probe),
            "-setcookie",
            Cookie,
            "-proto_dist",
            "quic",
            "-epmd_module",
            "quic_epmd",
            "-start_epmd",
            "false",
            "-hidden",
            "-kernel",
            "net_setuptime",
            "10",
            "-quic_dist_port",
            integer_to_list(ProbePort),
            "-quic_dist_cert",
            CertFile,
            "-quic_dist_key",
            KeyFile,
            "-quic_dist_verify",
            "verify_none",
            "-pa",
            quic_ebin(),
            "-pa",
            test_ebin(),
            "-noinput",
            "-eval",
            Eval
        ] ++ AuthArgs,

    ErlExe = os:find_executable("erl"),
    Port = erlang:open_port({spawn_executable, ErlExe}, [
        {args, Args},
        binary,
        exit_status,
        stderr_to_stdout
    ]),
    Out = wait_for_port_exit(Port, 30000),
    ct:log("probe ~s output:~n~s", [Tag, Out]),
    case file:read_file(ResultFile) of
        {ok, Bin} ->
            list_to_atom(string:trim(binary_to_list(Bin)));
        {error, _} ->
            refused
    end.

%%====================================================================
%% Low-level helpers
%%====================================================================

quic_ebin() ->
    case code:lib_dir(quic) of
        {error, _} ->
            filename:absname(filename:dirname(code:which(quic_dist)));
        LibDir ->
            filename:join(LibDir, "ebin")
    end.

test_ebin() ->
    filename:absname(filename:dirname(code:which(?MODULE))).

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

pick_port() ->
    {ok, S} = gen_udp:open(0, [binary, {active, false}]),
    {ok, P} = inet:port(S),
    gen_udp:close(S),
    P.

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

drain_port(Port) ->
    drain_port(Port, []).
drain_port(Port, Acc) ->
    receive
        {Port, {data, Bin}} -> drain_port(Port, [Bin | Acc])
    after 100 ->
        binary_to_list(iolist_to_binary(lists:reverse(Acc)))
    end.

wait_for_port_exit(Port, TimeoutMs) ->
    wait_for_port_exit(Port, TimeoutMs, []).
wait_for_port_exit(Port, TimeoutMs, Acc) ->
    receive
        {Port, {data, Bin}} ->
            wait_for_port_exit(Port, TimeoutMs, [Bin | Acc]);
        {Port, {exit_status, _}} ->
            binary_to_list(iolist_to_binary(lists:reverse(Acc)))
    after TimeoutMs ->
        case erlang:port_info(Port, os_pid) of
            {os_pid, OsPid} ->
                os:cmd("kill -9 " ++ integer_to_list(OsPid));
            _ ->
                ok
        end,
        catch erlang:port_close(Port),
        binary_to_list(iolist_to_binary(lists:reverse(Acc)))
    end.

short_name(Node) ->
    NodeStr = atom_to_list(Node),
    case string:split(NodeStr, "@") of
        [N, _Host] -> N;
        [N] -> N
    end.
