%%% -*- erlang -*-
%%%
%%% Distribution over QUIC authenticated by TLS 1.3 external PSK
%%% (RFC 8446 §4.2.11). No X.509 certs configured on either side;
%%% both peers share the same PSK callback module + identity.
%%%
%%% Boots two real erl VMs via open_port (mirrors
%%% quic_dist_auth_SUITE). The peer module's boot tries to bring
%%% distribution up too eagerly to thread non-string PSK data
%%% through.

-module(quic_dist_psk_SUITE).

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
    psk_only_mesh/1
]).

-define(PSK_CALLBACK, "quic_dist_psk_test_cb:cluster").

suite() ->
    [{timetrap, {minutes, 3}}].

all() ->
    [psk_only_mesh].

init_per_suite(Config) ->
    case os:find_executable("erl") of
        false -> {skip, erl_not_found};
        _ -> Config
    end.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, _Config) ->
    case erase({?MODULE, target_port_handle}) of
        undefined -> ok;
        Port -> stop_port(Port)
    end,
    ok.

%%====================================================================
%% Target listens with psk_callback; probe connects with the same
%% callback module + a runtime external_psk override (the offer
%% can't ride a flat boot arg, so set_connect_options/2 attaches
%% it just before the dial).
%%====================================================================

psk_only_mesh(Config) ->
    {Target, TargetPort, Cookie, TargetUdp} = start_target(Config),
    Result = run_probe(Config, Target, TargetPort, Cookie),
    stop_port(TargetUdp),
    erase({?MODULE, target_port_handle}),
    ?assertEqual(connected, Result).

%%====================================================================
%% Target boot
%%====================================================================

start_target(Config) ->
    PrivDir = ?config(priv_dir, Config),
    Cookie = "qpsk_" ++ integer_to_list(erlang:unique_integer([positive])),
    Host = "127.0.0.1",
    Suffix = integer_to_list(erlang:unique_integer([positive])),
    Node = list_to_atom("qpsk_target_" ++ Suffix ++ "@" ++ Host),
    PortNum = pick_port(),
    ReadyFile = filename:join(PrivDir, "psk_target_" ++ Suffix ++ ".ready"),

    Eval = lists:flatten(
        io_lib:format(
            "{ok,_}=application:ensure_all_started(quic),"
            "ok=file:write_file(\"~s\",<<\"ok\">>),"
            "receive _ -> ok end.",
            [ReadyFile]
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
        integer_to_list(PortNum),
        "-quic_dist_psk_callback",
        ?PSK_CALLBACK,
        "-pa",
        quic_ebin(),
        "-pa",
        test_ebin(),
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
            put({?MODULE, target_port_handle}, Port),
            {Node, PortNum, Cookie, Port};
        timeout ->
            Log = drain_port(Port),
            stop_port(Port),
            ct:fail("target not ready. output:~n~s", [Log])
    end.

%%====================================================================
%% Probe: brings its own psk_callback up at boot so load_credentials
%% succeeds, then registers an external_psk override on the target
%% via set_connect_options/2 before connecting.
%%====================================================================

run_probe(Config, Target, TargetPort, Cookie) ->
    PrivDir = ?config(priv_dir, Config),
    Host = "127.0.0.1",
    Suffix = integer_to_list(erlang:unique_integer([positive])),
    Probe = list_to_atom("qpsk_probe_" ++ Suffix ++ "@" ++ Host),
    ProbePort = pick_port(),
    ResultFile = filename:join(PrivDir, "psk_probe_" ++ Suffix ++ ".result"),

    TargetStr = atom_to_list(Target),
    Eval = lists:flatten(
        io_lib:format(
            "{ok,_}=application:ensure_all_started(quic),"
            "Nodes=[{'~s',{\"127.0.0.1\",~b}}],"
            "{ok,_}=quic_discovery_static:init([{nodes,Nodes}]),"
            %% Runtime override: client side offers external_psk.
            "ok=quic_dist:set_connect_options('~s',"
            "#{external_psk => {<<\"cluster\">>,"
            "<<\"shared-cluster-psk-32-bytes!!!!!\">>}}),"
            "Verdict = case net_kernel:connect_node('~s') of"
            " true -> connected;"
            " _ -> refused"
            " end,"
            "ok=file:write_file(\"~s\",atom_to_list(Verdict)),"
            "erlang:halt(0).",
            [TargetStr, TargetPort, TargetStr, TargetStr, ResultFile]
        )
    ),
    Args = [
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
        "-quic_dist_psk_callback",
        ?PSK_CALLBACK,
        "-pa",
        quic_ebin(),
        "-pa",
        test_ebin(),
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
    Out = wait_for_port_exit(Port, 30000),
    ct:log("probe output:~n~s", [Out]),
    case file:read_file(ResultFile) of
        {ok, Bin} -> list_to_atom(string:trim(binary_to_list(Bin)));
        {error, _} -> refused
    end.

%%====================================================================
%% Low-level helpers (mirror quic_dist_auth_SUITE)
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
