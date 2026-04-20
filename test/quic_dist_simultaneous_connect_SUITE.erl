%%% -*- erlang -*-
%%%
%%% QUIC Distribution Simultaneous-Connect Regression Suite
%%%
%%% Reproduces the race where two peer nodes call
%%% net_kernel:connect_node/1 on each other within a small time
%%% window. Stock Erlang dist resolves this via dist_util + net_kernel
%%% name-comparison arbitration. If our accept path reaches mark_pending
%%% too late, the outbound recv_status starves and net_kernel:connect_node
%%% hangs indefinitely.
%%%
%%% Copyright (c) 2024-2026 Benoit Chesneau
%%% Apache License 2.0
%%%

-module(quic_dist_simultaneous_connect_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([
    all/0,
    suite/0,
    groups/0,
    init_per_suite/1,
    end_per_suite/1,
    init_per_group/2,
    end_per_group/2
]).

-export([
    simultaneous_connect_test/1
]).

-define(DIAL_TIMEOUT, 10000).
-define(COLLECT_TIMEOUT, 15000).
-define(DISCONNECT_TIMEOUT, 5000).
-define(POLL_INTERVAL, 20).

suite() ->
    [{timetrap, {minutes, 5}}].

all() ->
    [{group, two_node}].

groups() ->
    [{two_node, [sequence], [simultaneous_connect_test]}].

init_per_suite(Config) ->
    {ok, CertDir} = generate_test_certs(Config),
    [{cert_dir, CertDir} | Config].

end_per_suite(Config) ->
    CertDir = ?config(cert_dir, Config),
    os:cmd("rm -rf " ++ CertDir),
    ok.

init_per_group(two_node, Config) ->
    case code:which(peer) of
        non_existing ->
            {skip, peer_module_not_available};
        _ ->
            CertDir = ?config(cert_dir, Config),
            case start_peer_nodes(CertDir) of
                {ok, Node1, Peer1, Node2, Peer2} ->
                    [
                        {node1, Node1},
                        {peer1, Peer1},
                        {node2, Node2},
                        {peer2, Peer2}
                        | Config
                    ];
                {error, Reason} ->
                    {skip, {peer_start_failed, Reason}}
            end
    end;
init_per_group(_Group, Config) ->
    Config.

end_per_group(two_node, Config) ->
    catch peer:stop(?config(peer1, Config)),
    catch peer:stop(?config(peer2, Config)),
    ok;
end_per_group(_Group, _Config) ->
    ok.

%%====================================================================
%% Test Cases
%%====================================================================

simultaneous_connect_test(Config) ->
    Node1 = ?config(node1, Config),
    Node2 = ?config(node2, Config),
    Peer1 = ?config(peer1, Config),
    Peer2 = ?config(peer2, Config),

    %% Sanity: verify non-racing one-way connect works first.
    ok = ensure_disconnected(Peer1, Node1, Peer2, Node2),
    R0 = safe_peer_call(Peer1, net_kernel, connect_node, [Node2], ?DIAL_TIMEOUT),
    ?assertEqual(true, R0, one_way_sanity),
    ok = ensure_disconnected(Peer1, Node1, Peer2, Node2),

    %% Race both sides. On the current accept-path fix the dial
    %% resolves within the dial timeout; before the fix both sides
    %% hang indefinitely.
    {R1, R2} = race_dial(Peer1, Node1, Peer2, Node2),
    ?assertEqual({true, true}, {R1, R2}),
    ok = ensure_disconnected(Peer1, Node1, Peer2, Node2),
    ok.

%%====================================================================
%% Helpers
%%====================================================================

race_dial(Peer1, Node1, Peer2, Node2) ->
    Parent = self(),
    spawn_link(fun() ->
        Parent ! {dial1, safe_peer_call(Peer1, net_kernel, connect_node, [Node2], ?DIAL_TIMEOUT)}
    end),
    %% Tiny stagger so the two dials don't hit net_kernel in the same µs.
    timer:sleep(1),
    spawn_link(fun() ->
        Parent ! {dial2, safe_peer_call(Peer2, net_kernel, connect_node, [Node1], ?DIAL_TIMEOUT)}
    end),
    R1 =
        receive
            {dial1, V1} -> V1
        after ?COLLECT_TIMEOUT -> timeout
        end,
    R2 =
        receive
            {dial2, V2} -> V2
        after ?COLLECT_TIMEOUT -> timeout
        end,
    {R1, R2}.

safe_peer_call(Peer, Mod, Fun, Args, Timeout) ->
    try
        peer:call(Peer, Mod, Fun, Args, Timeout)
    catch
        _:Reason -> {error, Reason}
    end.

ensure_disconnected(Peer1, Node1, Peer2, Node2) ->
    _ = safe_peer_call(Peer1, erlang, disconnect_node, [Node2], 5000),
    _ = safe_peer_call(Peer2, erlang, disconnect_node, [Node1], 5000),
    wait_until(
        fun() ->
            safe_peer_call(Peer1, erlang, nodes, [], 5000) =:= [] andalso
                safe_peer_call(Peer2, erlang, nodes, [], 5000) =:= []
        end,
        ?DISCONNECT_TIMEOUT
    ).

wait_until(F, Timeout) ->
    wait_until(F, Timeout, erlang:monotonic_time(millisecond)).

wait_until(F, Timeout, Start) ->
    case F() of
        true ->
            ok;
        false ->
            case erlang:monotonic_time(millisecond) - Start > Timeout of
                true ->
                    {error, timeout};
                false ->
                    timer:sleep(?POLL_INTERVAL),
                    wait_until(F, Timeout, Start)
            end
    end.

generate_test_certs(Config) ->
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
        _ -> {error, cert_generation_failed}
    end.

start_peer_nodes(CertDir) ->
    CertFile = filename:join(CertDir, "cert.pem"),
    KeyFile = filename:join(CertDir, "key.pem"),

    Node1Name = list_to_atom(
        "quic_sc_node1_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),
    Node2Name = list_to_atom(
        "quic_sc_node2_" ++ integer_to_list(erlang:unique_integer([positive]))
    ),

    CodePath = code:get_path(),
    PeerOpts = fun(Name, Port) ->
        #{
            name => Name,
            host => "127.0.0.1",
            longnames => true,
            args =>
                [
                    "-proto_dist",
                    "quic",
                    "-epmd_module",
                    "quic_epmd",
                    "-start_epmd",
                    "false",
                    "-quic_dist_port",
                    integer_to_list(Port),
                    "-quic_dist_cert",
                    CertFile,
                    "-quic_dist_key",
                    KeyFile,
                    "-setcookie",
                    atom_to_list(erlang:get_cookie())
                ] ++ lists:append([["-pa", P] || P <- CodePath]),
            connection => standard_io
        }
    end,

    try
        {ok, Peer1, Node1} = peer:start(PeerOpts(Node1Name, 14433)),
        {ok, Peer2, Node2} = peer:start(PeerOpts(Node2Name, 14434)),

        Nodes = [
            {Node1, {"127.0.0.1", 14433}},
            {Node2, {"127.0.0.1", 14434}}
        ],
        DistConfig = [
            {cert_file, CertFile},
            {key_file, KeyFile},
            {verify, verify_none},
            {discovery_module, quic_discovery_static},
            {nodes, Nodes}
        ],

        ok = peer:call(Peer1, application, set_env, [quic, dist, DistConfig]),
        ok = peer:call(Peer2, application, set_env, [quic, dist, DistConfig]),

        {ok, _} = peer:call(Peer1, application, ensure_all_started, [quic]),
        {ok, _} = peer:call(Peer2, application, ensure_all_started, [quic]),

        {ok, _} = peer:call(Peer1, quic_discovery_static, init, [[{nodes, Nodes}]]),
        {ok, _} = peer:call(Peer2, quic_discovery_static, init, [[{nodes, Nodes}]]),

        {ok, Node1, Peer1, Node2, Peer2}
    catch
        _:Reason -> {error, Reason}
    end.
